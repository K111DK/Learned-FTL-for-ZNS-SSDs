//
// Created by root on 4/13/24.
//
#include "dm-zftl.h"
#define DM_ZFTL_SFTL_L2P_FRAME_LENGTH (1024)
#define DM_ZFTL_LEAFTL_L2P_FRAME_LENGTH (256)
#define DM_ZFTL_MAX_L2P_SIZE ((unsigned int) 100 * 4 * 1024) // in bytes 2GB
unsigned int dm_zftl_sftl_get_size(struct dm_zftl_mapping_table * mapping_table){
    unsigned int curr_ppn = 0;
    unsigned int i;
    unsigned int pre_ppn = 0;
    unsigned int head_count = 0;
    for(i = 0; i < mapping_table->l2p_table_sz; ++i){
        if(mapping_table->l2p_table[i] != DM_ZFTL_UNMAPPED_PPA){
            curr_ppn = mapping_table->l2p_table[i];
            if(curr_ppn != pre_ppn + 1){
                head_count++;
            }
            pre_ppn = curr_ppn;
        }
    }
    return head_count * 8 + mapping_table->nr_l2p_lock_slice * 2 / 8;
}

unsigned int dm_zftl_dftl_get_size(struct dm_zftl_mapping_table * mapping_table){
    unsigned int vaild_lpn = 0;
    unsigned int i;
    for(i = 0; i < mapping_table->l2p_table_sz; ++i){
        if(mapping_table->l2p_table[i] != DM_ZFTL_UNMAPPED_PPA){
            vaild_lpn++;
        }
    }
    return vaild_lpn * 8;
}

void dm_zftl_l2p_set_init(struct dm_zftl_target * dm_zftl){
    dm_zftl->l2p_mem_pool = MALLOC(sizeof (struct dm_zftl_l2p_mem_pool));
    struct dm_zftl_l2p_mem_pool * l2p_mem_pool = dm_zftl->l2p_mem_pool;
    int _blocks = dmz_sect2blk(dm_zftl->capacity_nr_sectors);

    mutex_init(&l2p_mem_pool->mutex_lock);
    l2p_mem_pool->lbns_in_frame = DM_ZFTL_SFTL_L2P_FRAME_LENGTH;
    l2p_mem_pool->max_frame = _blocks / l2p_mem_pool->lbns_in_frame;

    l2p_mem_pool->l2f_table = MALLOC_ARRAY(
            l2p_mem_pool->max_frame
    , sizeof(struct dm_zftl_l2p_frame *)
    );
    l2p_mem_pool->maxium_l2p_size = DM_ZFTL_MAX_L2P_SIZE;

    l2p_mem_pool->GTD = MALLOC_ARRAY(
            l2p_mem_pool->max_frame
    , sizeof(unsigned int)
    );

    l2p_mem_pool->frame_access_cnt = MALLOC_ARRAY(
            l2p_mem_pool->max_frame
    ,sizeof(uint8_t));


    dm_zftl->mapping_table->l2p_cache = l2p_mem_pool;

    unsigned int i;
    for(i = 0; i < l2p_mem_pool->max_frame; ++i){
        l2p_mem_pool->l2f_table[i] = dm_zftl_create_new_frame(i);
#if DM_ZFTL_USING_LEA_FTL
        l2p_mem_pool->GTD[i] = 0;
#else
        l2p_mem_pool->GTD[i] = 1024;
        l2p_mem_pool->frame_access_cnt[i] = 0;
#endif
    }

    l2p_mem_pool->current_size = 0;
    spin_lock_init(&l2p_mem_pool->_lock);
    TAILQ_INIT(&l2p_mem_pool->_frame_list);
}

struct l2p_pin_work * dm_zftl_init_pin_ctx(struct dm_zftl_target * dm_zftl, struct io_job * io_job){
    struct l2p_pin_work * pin_work_ctx = kvmalloc(sizeof(struct l2p_pin_work), GFP_KERNEL);
    TAILQ_INIT(&pin_work_ctx->_deferred_pin_list);
    TAILQ_INIT(&pin_work_ctx->_pinned_list);
    pin_work_ctx->io_job = io_job;
    pin_work_ctx->wanted_free_space = 0;
    pin_work_ctx->total_l2p_page = 0;
    pin_work_ctx->dm_zftl = dm_zftl;
    atomic_set(&pin_work_ctx->pinned_cnt, 0);
    atomic_set(&pin_work_ctx->deferred_cnt, 0);
    pin_work_ctx->deferred_count = 0;
    pin_work_ctx->pinned_count = 0;
    return pin_work_ctx;
}

void dm_zftl_try_l2p_pin(struct work_struct * work){
    BUG_ON(!work);
    struct try_l2p_pin * try_pin = container_of(work, struct try_l2p_pin, work);
    BUG_ON(!try_pin);
    struct dm_zftl_target * dm_zftl = try_pin->dm_zftl;
    BUG_ON(!dm_zftl);
    struct io_job * io_job = try_pin->io_job;
    BUG_ON(!io_job);

    unsigned long flags;
    int block_l2p_pin = 0;
//    spin_lock_irqsave(&dm_zftl->l2p_mem_pool->_lock, flags);
//    block_l2p_pin = dm_zftl->l2p_mem_pool->current_size >= dm_zftl->l2p_mem_pool->maxium_l2p_size;
//    spin_unlock_irqrestore(&dm_zftl->l2p_mem_pool->_lock, flags);
//    if(block_l2p_pin) {
//        dm_zftl_try_evict(dm_zftl, dm_zftl->l2p_mem_pool);
//        INIT_WORK(&try_pin->work, dm_zftl_try_l2p_pin);
//        queue_work(dm_zftl->l2p_try_pin_wq, &try_pin->work);
//        return;
//    }

    struct l2p_pin_work * pin_work_ctx = dm_zftl_init_pin_ctx(dm_zftl, io_job);
    BUG_ON(!pin_work_ctx);
    if(io_job->flags == IO_WORK){
        struct dm_zftl_io_work * io_work = io_job->io_work;
        struct dm_zftl_l2p_mem_pool * l2p_cache = io_work->target->l2p_mem_pool;
        io_work->pin_work_ctx = pin_work_ctx;
        struct bio * bio = io_work->bio_ctx;

        unsigned int nr_blocks = dmz_bio_blocks(bio);

        unsigned int start_l2p_page = dmz_bio_block(bio) / l2p_cache->lbns_in_frame;
        unsigned int end_l2p_page = (dmz_bio_block(bio) + nr_blocks) / l2p_cache->lbns_in_frame;
        unsigned int l2p_page_no;

        for(l2p_page_no = start_l2p_page; l2p_page_no <= end_l2p_page; ++l2p_page_no){
            struct dm_zftl_l2p_frame * frame = l2p_cache->l2f_table[l2p_page_no];
            struct frame_no_node * frame_node = kvmalloc(sizeof(struct frame_no_node), GFP_KERNEL);
            frame_node->frame_no = frame->frame_no;

            spin_lock_irqsave(&frame->_lock, flags);
            dm_zftl_pin_frame(l2p_cache, l2p_cache->l2f_table[frame->frame_no]);
            if(frame->state == ON_DRAM){

                spin_unlock_irqrestore(&frame->_lock, flags);
                TAILQ_INSERT_HEAD(&pin_work_ctx->_pinned_list, frame_node, list_entry);
                atomic_inc(&pin_work_ctx->pinned_cnt);
                pin_work_ctx->pinned_count++;

            }else{

                spin_unlock_irqrestore(&frame->_lock, flags);
                TAILQ_INSERT_HEAD(&pin_work_ctx->_deferred_pin_list, frame_node, list_entry);
                atomic_inc(&pin_work_ctx->deferred_cnt);
                pin_work_ctx->deferred_count++;

            }

            pin_work_ctx->total_l2p_page++;
        }
    }
    else if(io_job->flags == CP_JOB){
        //dm_zftl_try_l2p_pin+0x4a1/0x1410
        struct copy_job * cp_job = io_job->cp_job;
        struct dm_zftl_l2p_mem_pool * l2p_cache = cp_job->dm_zftl->l2p_mem_pool;
        cp_job->pin_work_ctx = pin_work_ctx;

        unsigned int i;
        unsigned int pre_frame, curr_frame;
        unsigned int lpn;
        pre_frame = -1;
        for(i = 0; i < cp_job->nr_blocks; ++i){
            lpn = cp_job->copy_buffer->lpn_buffer[i].lpn;
            if(lpn == DM_ZFTL_UNMAPPED_LPA)
                continue;
            curr_frame = lpn / l2p_cache->lbns_in_frame;
            if(curr_frame != pre_frame){
                struct dm_zftl_l2p_frame * frame = l2p_cache->l2f_table[curr_frame];
                struct frame_no_node * frame_node = kvmalloc(sizeof(struct frame_no_node), GFP_KERNEL);
                frame_node->frame_no = frame->frame_no;

                spin_lock_irqsave(&frame->_lock, flags);
                dm_zftl_pin_frame(l2p_cache, l2p_cache->l2f_table[frame->frame_no]);
                if(frame->state == ON_DRAM){
                    spin_unlock_irqrestore(&frame->_lock, flags);

                    TAILQ_INSERT_HEAD(&pin_work_ctx->_pinned_list, frame_node, list_entry);
                    atomic_inc(&pin_work_ctx->pinned_cnt);
                    pin_work_ctx->pinned_count++;

                }else{
                    spin_unlock_irqrestore(&frame->_lock, flags);

                    TAILQ_INSERT_HEAD(&pin_work_ctx->_deferred_pin_list, frame_node, list_entry);
                    atomic_inc(&pin_work_ctx->deferred_cnt);
                    pin_work_ctx->deferred_count++;

                }


                pin_work_ctx->total_l2p_page++;
            }
            pre_frame = curr_frame;
        }
    }else{

        return;

    }

#if DM_ZFTL_PIN_DEBUG
    printk(KERN_EMERG "[PIN] pinned:%d deferred pinned:%d", atomic_read(&pin_work_ctx->pinned_cnt),
                                                            atomic_read(&pin_work_ctx->deferred_cnt));
#endif

    if(dm_zftl_is_pin_complete(pin_work_ctx)){
        // kick off normal io
        struct l2p_pin_complete_work * work = kvmalloc(sizeof (struct l2p_pin_complete_work), GFP_KERNEL);
        work->pin_work_ctx = pin_work_ctx;
        INIT_WORK(&work->work, dm_zftl_l2p_pin_complete);
        queue_work(pin_work_ctx->dm_zftl->io_kick_off_wq, &work->work);
    }else{
        // queue page in/ page out io
        dm_zftl_queue_l2p_pin_io(pin_work_ctx);
    }
}

void dm_zftl_unpin(struct l2p_pin_work * pin_work_ctx){

    struct dm_zftl_l2p_mem_pool * l2p_cache = pin_work_ctx->dm_zftl->l2p_mem_pool;
    struct frame_no_node * frame_no;
    TAILQ_FOREACH(frame_no, &pin_work_ctx->_pinned_list, list_entry){
        dm_zftl_unpin_frame(l2p_cache, l2p_cache->l2f_table[frame_no->frame_no]);
    }
}

struct dm_zftl_l2p_frame * dm_zftl_create_new_frame(unsigned int frame_no){
    struct dm_zftl_l2p_frame * frame = kvmalloc(sizeof(struct dm_zftl_l2p_frame), GFP_NOIO);
    spin_lock_init(&frame->_lock);
    frame->frame_no = frame_no;
    atomic_set(&frame->on_lru_list, 0);
    frame->state = ON_DISK;
    atomic_set(&frame->ref_count, 0);
    return frame;
}

int dm_zftl_queue_l2p_pin_io(struct l2p_pin_work *pin_work_ctx){
    struct frame_no_node * frame_node;
    struct dm_zftl_l2p_mem_pool * l2p_cache = pin_work_ctx->dm_zftl->l2p_mem_pool;
    int deferred = 0;
    TAILQ_FOREACH(frame_node, &pin_work_ctx->_deferred_pin_list, list_entry){
        deferred++;
        struct l2p_page_in_work * page_in_work = kvmalloc(sizeof(struct l2p_page_in_work), GFP_KERNEL | __GFP_ZERO);
        page_in_work->pin_work =  pin_work_ctx;
        page_in_work->frame = l2p_cache->l2f_table[frame_node->frame_no];
        INIT_WORK(&page_in_work->work, dm_zftl_do_l2p_pin_io);
        queue_work(pin_work_ctx->dm_zftl->l2p_pin_wq, &page_in_work->work);
    }
//    printk("Err: deferred:%u wanted:%u", deferred, pin_work_ctx->deferred_count);
//    BUG_ON(deferred != pin_work_ctx->deferred_count);
    return 0;
}

void dm_zftl_do_l2p_pin_io(struct work_struct * work){
    struct l2p_page_in_work * page_in_work = container_of(work, struct l2p_page_in_work, work);
    struct dm_zftl_l2p_mem_pool * l2p_cache = page_in_work->pin_work->dm_zftl->l2p_mem_pool;
    struct dm_io_region * where = kvmalloc(sizeof(struct dm_io_region), GFP_NOIO);
    struct dm_io_request iorq;
    unsigned long flags;
    spin_lock_irqsave(&page_in_work->frame->_lock, flags);
    if(page_in_work->frame->state == ON_DRAM) {
        spin_unlock_irqrestore(&page_in_work->frame->_lock, flags);
        goto FINISH;

    } else if(page_in_work->frame->state == IN_PROC){
        spin_unlock_irqrestore(&page_in_work->frame->_lock, flags);
        goto REQUEUE;

    } else if(page_in_work->frame->state == ON_DISK){//ON_DISK
        page_in_work->frame->state = IN_PROC;
        spin_unlock_irqrestore(&page_in_work->frame->_lock, flags);
        goto KICK_OFF_PIN_IO;

    } else{

        spin_unlock_irqrestore(&page_in_work->frame->_lock, flags);
        BUG_ON(1);

    }

    FINISH:
    dm_zftl_l2p_pin_io_cb(0, page_in_work);
    return;

    REQUEUE:
    INIT_WORK(&page_in_work->work, dm_zftl_do_l2p_pin_io);
    queue_work(page_in_work->pin_work->dm_zftl->l2p_pin_wq, &page_in_work->work);
    return;


    KICK_OFF_PIN_IO:

    spin_lock_irqsave(&l2p_cache->_lock, flags);
    l2p_cache->current_size += l2p_cache->GTD[page_in_work->frame->frame_no];
    spin_unlock_irqrestore(&l2p_cache->_lock, flags);

    where->bdev = page_in_work->pin_work->dm_zftl->cache_device->bdev;
    where->sector = 0;//TODO: Currently we only read first 4k block of cache device to stimulate page in io
    where->count = dmz_blk2sect(1);

    iorq.bi_op = REQ_OP_READ;
    iorq.bi_op_flags = 0;
    iorq.mem.type = DM_IO_VMA;
    iorq.mem.ptr.vma = page_in_work->pin_work->dm_zftl->dummy_l2p_buffer;
    iorq.notify.fn = dm_zftl_l2p_pin_io_cb;
    iorq.notify.context = page_in_work;
    iorq.client = page_in_work->pin_work->dm_zftl->io_client;
    dm_io(&iorq, 1, where, NULL);
    return;
}

void dm_zftl_l2p_pin_io_cb(unsigned long error, void * context){
    struct l2p_page_in_work * page_in_work = (struct l2p_page_in_work *)context;
    int kick_off = 0;
    unsigned long flags;

    spin_lock_irqsave(&page_in_work->frame->_lock, flags);
    page_in_work->frame->state = ON_DRAM;
    spin_unlock_irqrestore(&page_in_work->frame->_lock, flags);

    atomic_inc(&page_in_work->pin_work->pinned_cnt);
    if(atomic_dec_and_test(&page_in_work->pin_work->deferred_cnt)){
        kick_off = 1;
    }


    if(kick_off){
        struct l2p_pin_complete_work * work = kvmalloc(sizeof (struct l2p_pin_complete_work), GFP_KERNEL);
        work->pin_work_ctx = page_in_work->pin_work;
        INIT_WORK(&work->work, dm_zftl_l2p_pin_complete);
        queue_work(page_in_work->pin_work->dm_zftl->io_kick_off_wq, &work->work);
    }
}

void dm_zftl_l2p_pin_complete(struct work_struct * work){
    struct l2p_pin_complete_work * complete_work = container_of(work, struct l2p_pin_complete_work, work);
    struct l2p_pin_work * pin_work =  complete_work->pin_work_ctx;
    struct dm_zftl_l2p_mem_pool * l2p_cache = pin_work->dm_zftl->l2p_mem_pool;

    struct frame_no_node * frame_node;
    unsigned long flags;
    int deferred = 0;
    while(!TAILQ_EMPTY(&pin_work->_deferred_pin_list)){
        frame_node = TAILQ_FIRST(&pin_work->_deferred_pin_list);
        TAILQ_REMOVE(&pin_work->_deferred_pin_list, frame_node, list_entry);
        TAILQ_INSERT_HEAD(&pin_work->_pinned_list, frame_node, list_entry);
        deferred++;
        //dm_zftl_pin_frame(l2p_cache, l2p_cache->l2f_table[frame_node->frame_no]);
    }
    if(deferred != pin_work->deferred_count){
        printk(KERN_EMERG "Deferred err => true:%d, wanted:%d", deferred, pin_work->deferred_count);
        BUG_ON(1);
    }

    int pin_cnt = 0;
    TAILQ_FOREACH(frame_node, &pin_work->_pinned_list, list_entry){
        pin_cnt++;
    }
    if(pin_cnt != pin_work->total_l2p_page){
        printk(KERN_EMERG "Pin err");
        BUG_ON(1);
    }

    if(pin_work->io_job->flags == IO_WORK){
        struct dm_zftl_io_work * io_work = pin_work->io_job->io_work;
        io_work->pin_cb_ctx = (void *)io_work;
        io_work->pin_cb_fn(io_work->pin_cb_ctx);
    }else{
        struct copy_job * cp_job = pin_work->io_job->cp_job;
        cp_job->pin_cb_ctx = (void *)cp_job;
        cp_job->pin_cb_fn(cp_job->pin_cb_ctx);
    }
}

void dm_zftl_del_from_lru(struct dm_zftl_l2p_mem_pool * l2p_cache, struct dm_zftl_l2p_frame * frame){
    BUG_ON(!frame);
    unsigned long flags1;
    int remove = 0;
    spin_lock_irqsave(&l2p_cache->_lock, flags1);
    if(atomic_read(&frame->on_lru_list)){
        atomic_set(&frame->on_lru_list, 0);
        TAILQ_REMOVE(&l2p_cache->_frame_list, frame, list_entry);
    }
    spin_unlock_irqrestore(&l2p_cache->_lock, flags1);

}
void dm_zftl_add_to_lru(struct dm_zftl_l2p_mem_pool * l2p_cache, struct dm_zftl_l2p_frame * frame){
    BUG_ON(!frame);
    unsigned long flags1;
    int add = 0;
    spin_lock_irqsave(&l2p_cache->_lock, flags1);
    if(!atomic_read(&frame->on_lru_list)){
        atomic_set(&frame->on_lru_list, 1);
        TAILQ_INSERT_HEAD(&l2p_cache->_frame_list, frame, list_entry);
    }
    spin_unlock_irqrestore(&l2p_cache->_lock, flags1);
}


void dm_zftl_pin_frame(struct dm_zftl_l2p_mem_pool *l2p_cache, struct dm_zftl_l2p_frame * frame){
    //return;
    atomic_inc(&frame->ref_count);
    dm_zftl_del_from_lru(l2p_cache, frame);
    return;
}

void dm_zftl_unpin_frame(struct dm_zftl_l2p_mem_pool *l2p_cache, struct dm_zftl_l2p_frame * frame){
    BUG_ON(!frame);
    //BUG_ON(!l2p_cache->l2f_table[frame->frame_no]);
    if(atomic_dec_and_test(&frame->ref_count)) {
        dm_zftl_add_to_lru(l2p_cache, frame);
    }
}

int dm_zftl_is_pin_complete(struct l2p_pin_work * pin_ctx){
    return pin_ctx->total_l2p_page == (atomic_read(&pin_ctx->pinned_cnt));
}

void dm_zftl_l2p_promote(struct dm_zftl_l2p_mem_pool * l2p_cache, struct dm_zftl_l2p_frame * frame){

    if(!atomic_read(&frame->on_lru_list))
        return;
    //TODO:dose this useful???
}

struct dm_zftl_l2p_frame * dm_zftl_l2p_evict(struct dm_zftl_l2p_mem_pool * l2p_cache){

    struct dm_zftl_l2p_frame * frame = dm_zftl_l2p_coldest(l2p_cache);//?
    if(!frame)
        return NULL;
    unsigned int flags;
    spin_lock_irqsave(&frame->_lock, flags);

    if(!atomic_read(&frame->on_lru_list)){
        spin_unlock_irqrestore(&frame->_lock, flags);
        return NULL;
    }
    dm_zftl_del_from_lru(l2p_cache, frame);
    frame->state = ON_DISK;
    spin_unlock_irqrestore(&frame->_lock, flags);

    return frame;
}

void dm_zftl_l2p_put(struct dm_zftl_l2p_mem_pool * l2p_cache, struct dm_zftl_l2p_frame * frame){
    BUG_ON(!frame);
    BUG_ON(!l2p_cache);
    l2p_cache->l2f_table[frame->frame_no] = frame;
}

struct dm_zftl_l2p_frame * dm_zftl_l2p_coldest(struct dm_zftl_l2p_mem_pool * l2p_cache){
    return TAILQ_LAST(&l2p_cache->_frame_list, _frame_list);
}

int dm_zftl_need_evict(struct dm_zftl_l2p_mem_pool * l2p_cache){
    unsigned long flags;
    int is_overflow = 0;
    spin_lock_irqsave(&l2p_cache->_lock, flags);
    is_overflow = 10 * l2p_cache->current_size >= l2p_cache->maxium_l2p_size * 9;
    spin_unlock_irqrestore(&l2p_cache->_lock, flags);
    return is_overflow;
}

void dm_zftl_try_evict(struct dm_zftl_target * dm_zftl, struct dm_zftl_l2p_mem_pool * l2p_cache){
    if(dm_zftl_need_evict(l2p_cache)){
        struct dm_zftl_l2p_frame * frame = dm_zftl_l2p_evict(l2p_cache);
        if(frame) {
            unsigned long flags;
            spin_lock_irqsave(&l2p_cache->_lock, flags);
            l2p_cache->current_size -= l2p_cache->GTD[frame->frame_no];
            spin_unlock_irqrestore(&l2p_cache->_lock, flags);

            struct l2p_page_out_work * page_out = MALLOC(sizeof (struct l2p_page_out_work));
            page_out->page_out_cnt = 1;
            page_out->l2p_cache = l2p_cache;
            page_out->frame = frame;
            page_out->dm_zftl = dm_zftl;
            INIT_WORK(&page_out->work, dm_zftl_do_evict);
            queue_work(dm_zftl->l2p_page_out_wq, &page_out->work);
        }
    }
}

void dm_zftl_do_evict(struct work_struct *work){
    struct l2p_page_out_work * page_out_work = container_of(work, struct l2p_page_out_work, work);
    struct dm_io_region * where = MALLOC(sizeof (struct dm_io_region));
    where->bdev = page_out_work->dm_zftl->cache_device->bdev;
    where->sector = page_out_work->frame->frame_no;//TODO: Currently we only read first 4k block of cache device to stimulate page in io
    where->count = dmz_blk2sect(1);

    struct dm_io_request iorq;
    iorq.bi_op = REQ_OP_READ;
    iorq.bi_op_flags = 0;
    iorq.mem.type = DM_IO_VMA;
    iorq.mem.ptr.vma = page_out_work->dm_zftl->dummy_l2p_buffer;
    iorq.notify.fn = dm_zftl_l2p_evict_cb;
    iorq.notify.context = page_out_work;
    iorq.client = page_out_work->dm_zftl->io_client;
    dm_io(&iorq, 1, where, NULL);
}

void dm_zftl_l2p_evict_cb(unsigned long error, void * context){
    struct l2p_page_out_work * page_out_work = (struct l2p_page_out_work *)context;
    struct dm_zftl_l2p_mem_pool * l2p_cache = page_out_work->l2p_cache;
    struct dm_zftl_target * dm_zftl = page_out_work->dm_zftl;
    dm_zftl_try_evict(dm_zftl, l2p_cache);
}

void dm_zftl_lsm_tree_try_compact(struct dm_zftl_target * dm_zftl){
    if((dm_zftl->last_compact_traffic_ >= DM_ZFTL_COMPACT_INTERVAL) && DM_ZFTL_COMPACT_ENABLE){

#if DM_ZFTL_COMPACT_DEBUG
        printk(KERN_EMERG "[Compact] Trigger Compact");
#endif

        dm_zftl->last_compact_traffic_ = 0;
        struct dm_zftl_compact_work * _work = kvmalloc(sizeof(struct dm_zftl_compact_work), GFP_KERNEL);
        _work->target = dm_zftl;
        INIT_WORK(&_work->work, dm_zftl_compact_work);
        queue_work(dm_zftl->lsm_tree_compact_wq, &_work->work);
    }

}

void dm_zftl_compact_work(struct work_struct *work){
    struct dm_zftl_compact_work * _work = container_of(work, struct dm_zftl_compact_work, work);
    struct dm_zftl_target * dm_zftl = _work->target;
    unsigned int i;
    for(i = 0; i < dm_zftl->mapping_table->lsm_tree->nr_frame ; ++i) {
        mutex_lock(&dm_zftl->mapping_table->l2p_lock_array[i]);
        lsm_tree_frame_compact__(&dm_zftl->mapping_table->lsm_tree->frame[i]);
#if DM_ZFTL_COMPACT_WITH_PROMOTE
        lsm_tree_frame_promote__(&dm_zftl->mapping_table->lsm_tree->frame[i]);
#endif
        mutex_unlock(&dm_zftl->mapping_table->l2p_lock_array[i]);
    }
    kvfree(_work);
}

//EXPORT_SYMBOL(dm_zftl_try_l2p_pin);
//EXPORT_SYMBOL(dm_zftl_get);
//EXPORT_SYMBOL(dm_zftl_unpin_frame);
//EXPORT_SYMBOL(dm_zftl_init_mapping_table);
//EXPORT_SYMBOL(dm_zftl_ppn_is_valid);
//EXPORT_SYMBOL(dm_zftl_l2p_set_init);
//EXPORT_SYMBOL(dm_zftl_get_lpn_frame);
//EXPORT_SYMBOL(dm_zftl_update_mapping_by_lpn_array);
//EXPORT_SYMBOL(dm_zftl_update_mapping_cache);
