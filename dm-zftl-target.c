//
// Created by root on 3/3/24.
//
#include "dm-zftl.h"
#include <linux/sort.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/dm-io.h>
#include <linux/bio.h>
#include <linux/dm-ioctl.h>
#include <linux/spinlock.h>
#define DM_ZFTL_SFTL_L2P_FRAME_LENGTH (1024)
#define DM_ZFTL_LEAFTL_L2P_FRAME_LENGTH (256)
#define DM_ZFTL_MAX_L2P_SIZE ((unsigned int) 100 * 4 * 1024) // in bytes 2GB

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
    struct l2p_pin_work * pin_work_ctx = kvmalloc(sizeof(struct l2p_pin_work), GFP_NOIO);
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
    struct try_l2p_pin * try_pin = container_of(work, struct try_l2p_pin, work);
    struct dm_zftl_target * dm_zftl = try_pin->dm_zftl;
    struct io_job * io_job = try_pin->io_job;


    unsigned long flags;
    int block_l2p_pin = 0;
    spin_lock_irqsave(&dm_zftl->l2p_mem_pool->_lock, flags);
    block_l2p_pin = dm_zftl->l2p_mem_pool->current_size >= dm_zftl->l2p_mem_pool->maxium_l2p_size;
    spin_unlock_irqrestore(&dm_zftl->l2p_mem_pool->_lock, flags);
    if(block_l2p_pin) {

        dm_zftl_try_evict(dm_zftl, dm_zftl->l2p_mem_pool);
        INIT_WORK(&try_pin->work, dm_zftl_try_l2p_pin);
        queue_work(dm_zftl->l2p_try_pin_wq, &try_pin->work);
        return;
    }

    struct l2p_pin_work * pin_work_ctx = dm_zftl_init_pin_ctx(dm_zftl, io_job);
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
    }else if(io_job->flags == CP_JOB){
        struct copy_job * cp_job = io_job->cp_job;
        struct dm_zftl_l2p_mem_pool * l2p_cache = cp_job->dm_zftl->l2p_mem_pool;
        cp_job->pin_work_ctx = pin_work_ctx;

        unsigned int i;
        unsigned int pre_frame, curr_frame;
        pre_frame = -1;
        for(i = cp_job->lpn_start_idx; i < cp_job->lpn_start_idx + cp_job->nr_read_io; ++i){
            curr_frame = cp_job->cp_lpn_array[i] / l2p_cache->lbns_in_frame;
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
    BUG_ON(deferred != pin_work_ctx->deferred_count);
    return 0;
}

void dm_zftl_do_l2p_pin_io(struct work_struct * work){
    struct l2p_page_in_work * page_in_work = container_of(work, struct l2p_page_in_work, work);
    struct dm_zftl_l2p_mem_pool * l2p_cache = page_in_work->pin_work->dm_zftl->l2p_mem_pool;
    struct dm_io_region *where = kvmalloc(sizeof(struct dm_io_region), GFP_NOIO);
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

int dm_zftl_init_mapping_table(struct dm_zftl_target * dm_zftl){



    dm_zftl->mapping_table = (struct dm_zftl_mapping_table *)vmalloc(sizeof(struct dm_zftl_mapping_table));
    mutex_init(&dm_zftl->mapping_table->l2p_lock);
    dm_zftl->mapping_table->dm_zftl = dm_zftl;

    dm_zftl->mapping_table->l2p_table_sz = dmz_sect2blk(dm_zftl->capacity_nr_sectors);
    dm_zftl->mapping_table->l2p_table = kvmalloc_array(dm_zftl->mapping_table->l2p_table_sz,
                                                       sizeof(uint32_t), GFP_KERNEL | __GFP_ZERO);
    dm_zftl->mapping_table->p2l_table = kvmalloc_array(dm_zftl->mapping_table->l2p_table_sz,
                                                       sizeof(uint32_t), GFP_KERNEL | __GFP_ZERO);
    dm_zftl->mapping_table->device_bitmap = kvmalloc_array( (dm_zftl->mapping_table->l2p_table_sz) / 8 + 1 ,
                                                            sizeof(uint8_t), GFP_KERNEL | __GFP_ZERO);
    dm_zftl->mapping_table->validate_bitmap = kvmalloc_array( (dm_zftl->mapping_table->l2p_table_sz) / 8 + 1 ,
                                                              sizeof(uint8_t), GFP_KERNEL | __GFP_ZERO);
    dm_zftl->mapping_table->lsm_tree = lsm_tree_init(dm_zftl->mapping_table->l2p_table_sz);
    unsigned int ppn, lpn, i;
    for(ppn = 0; ppn < dm_zftl->mapping_table->l2p_table_sz; ppn++){
        lpn = ppn;
        dm_zftl->mapping_table->l2p_table[lpn] = DM_ZFTL_UNMAPPED_PPA;
        dm_zftl->mapping_table->p2l_table[ppn] = DM_ZFTL_UNMAPPED_LPA;
        dm_zftl_invalidate_ppn(dm_zftl->mapping_table, ppn);
        dm_zftl_lpn_set_dev(dm_zftl->mapping_table, lpn, DM_ZFTL_CACHE);
    }
    return 0;
}

sector_t dm_zftl_get(struct dm_zftl_mapping_table * mapping_table, sector_t lba){
    sector_t ppa;
    if((unsigned int)lba > mapping_table->l2p_table_sz){
        ppa = DM_ZFTL_UNMAPPED_PPA;
    }
    unsigned int lpn = dmz_sect2blk(lba);
    unsigned int ppn = dm_zftl_l2p_get(mapping_table, lpn);
    return dmz_blk2sect(ppn);
}

int dm_zftl_set_by_bn(struct dm_zftl_mapping_table * mapping_table, sector_t lpn, sector_t ppn){
    sector_t original_ppn;
    original_ppn = mapping_table->l2p_table[lpn];
    mapping_table->l2p_table[lpn] = ppn;
    mapping_table->p2l_table[ppn] = lpn;

    dm_zftl_invalidate_ppn(mapping_table, original_ppn);
    dm_zftl_validate_ppn(mapping_table, ppn);
    return 0;
}

int dm_zftl_set(struct dm_zftl_mapping_table * mapping_table, sector_t lba, sector_t ppa){
    sector_t lpn, ppn, original_ppn;
    lpn = dmz_sect2blk(lba);
    original_ppn = mapping_table->l2p_table[lpn];
    ppn = dmz_sect2blk(ppa);
    mapping_table->l2p_table[lpn] = ppn;
    mapping_table->p2l_table[ppn] = lpn;
    dm_zftl_invalidate_ppn(mapping_table, original_ppn);
    dm_zftl_validate_ppn(mapping_table, ppn);
    return 0;
}

int dm_zftl_update_mapping_by_lpn_array(struct dm_zftl_mapping_table * mapping_table,
                                        unsigned int * lpn_array,
                                        sector_t ppn,
                                        unsigned int nr_block){
    unsigned int i = 0;
#if DM_ZFTL_MAPPING_DEBUG
    printk(KERN_EMERG "L2P Update: LPN:%llu ==> PPN:%llu [%llu blocks]",
            lpn_array[0],
            ppn,
            nr_block);
#endif
    //Change dev
    for(i = 0; i < nr_block; ++i){
        dm_zftl_lpn_set_dev(mapping_table, lpn_array[i], DM_ZFTL_BACKEND);
        dm_zftl_set_by_bn(mapping_table, lpn_array[i], ppn + i);
        BUG_ON(mapping_table->p2l_table[ppn + i] != lpn_array[i]);
        BUG_ON(mapping_table->l2p_table[lpn_array[i]] != ppn + i);
    }
#if DM_ZFTL_USING_LEA_FTL
    lsm_tree_update_by_lpn_array(mapping_table->lsm_tree,
                    lpn_array,
                    nr_block,
                    ppn);
#endif

    return 0;
}

int dm_zftl_update_mapping_cache(struct dm_zftl_mapping_table * mapping_table, sector_t lba, sector_t ppa, sector_t nr_blocks){
    mutex_lock(&mapping_table->l2p_lock);
#if DM_ZFTL_USING_LEA_FTL
    lsm_tree_update_seq(mapping_table->lsm_tree, dmz_sect2blk(lba), nr_blocks, dmz_sect2blk(ppa));
#endif
    int i;
    for(i = 0; i < nr_blocks; ++i){
        dm_zftl_lpn_set_dev(mapping_table, dmz_sect2blk(lba) + i, DM_ZFTL_CACHE);
        dm_zftl_set(mapping_table, lba + (sector_t)i * dmz_blk2sect(1) , ppa + (sector_t)i * dmz_blk2sect(1));
        BUG_ON(mapping_table->p2l_table[dmz_sect2blk(ppa) + i] != dmz_sect2blk(lba) + i);
        BUG_ON(mapping_table->l2p_table[dmz_sect2blk(lba) + i] != dmz_sect2blk(ppa) + i);
    }
#if DM_ZFTL_MAPPING_DEBUG
    printk(KERN_EMERG "L2P Update: LPN:%llu ==> PPN:%llu [%llu blocks]",
           dmz_sect2blk(lba),
           dmz_sect2blk(ppa),
           nr_blocks);
#endif


    mutex_unlock(&mapping_table->l2p_lock);

    struct dm_zftl_target * dm_zftl = mapping_table->dm_zftl;

    unsigned long flags;
    spin_lock_irqsave(&dm_zftl->record_lock_, flags);
    dm_zftl->cache_2_zns_reclaim_write_traffic_ += nr_blocks;
    dm_zftl->last_compact_traffic_ += nr_blocks;
    spin_unlock_irqrestore(&dm_zftl->record_lock_, flags);
    dm_zftl_lsm_tree_try_compact(dm_zftl);

    return 0;
}

unsigned int dm_zftl_l2p_get(struct dm_zftl_mapping_table * mapping_table, unsigned int lpn){
    unsigned int ppn, origin_ppn;
    mutex_lock(&mapping_table->l2p_lock);


#if DM_ZFTL_USING_LEA_FTL
    origin_ppn = lsm_tree_get_ppn(mapping_table->lsm_tree,
                                        lpn);
    ppn = origin_ppn;
    if(ppn != DM_ZFTL_UNMAPPED_PPA){
        ppn = lsm_tree_predict_correct(mapping_table->p2l_table, lpn, ppn);
    }
    if(ppn != mapping_table->l2p_table[lpn]) {
        printk(KERN_EMERG
        "[Get] lpn:%llu predict err! =>dev:%s cal:%llu got:%llu wanted:%llu", lpn, dm_zftl_lpn_is_in_cache(mapping_table, lpn) ? "Cache":"ZNS", origin_ppn , ppn, mapping_table->l2p_table[lpn]);
        unsigned int i=0;
        for(i = origin_ppn - ERROR_BOUND; i <= origin_ppn + ERROR_BOUND; ++i)
            printk(KERN_EMERG "P2L:(PPN:%llu => LPN:%llu) L2P:(LPN:%llu => PPN:%llu)", i, mapping_table->p2l_table[i], mapping_table->p2l_table[i], mapping_table->l2p_table[mapping_table->p2l_table[i]]);
        BUG_ON(1);
    }
#else
    ppn = mapping_table->l2p_table[lpn];
#endif

    mutex_unlock(&mapping_table->l2p_lock);
    return ppn;

}


int dm_zftl_lpn_is_in_cache(struct dm_zftl_mapping_table * mapping_table, sector_t lpn){
    if((mapping_table->device_bitmap[lpn / 8] & ((uint8_t) 1 << (lpn % 8))) == (uint8_t)0)
        return 1;
    return 0;
}

void dm_zftl_lpn_set_dev(struct dm_zftl_mapping_table * mapping_table, unsigned int lpn, int dev){
    if(lpn >= mapping_table->l2p_table_sz)
        return;
    if(dev == DM_ZFTL_CACHE) {
        mapping_table->device_bitmap[lpn / 8] &= (~((uint8_t) 1 << (lpn % 8)));
        BUG_ON(!dm_zftl_lpn_is_in_cache(mapping_table, lpn));
    }
    else{
        mapping_table->device_bitmap[lpn / 8] |= ((uint8_t) 1 << (lpn % 8));
        BUG_ON(dm_zftl_lpn_is_in_cache(mapping_table, lpn));
    }
}

void dm_zftl_invalidate_ppn(struct dm_zftl_mapping_table * mapping_table, sector_t ppn){
    mapping_table->validate_bitmap[ppn / 8] &=  (~((uint8_t) 1 << (ppn % 8)));
}

void dm_zftl_validate_ppn(struct dm_zftl_mapping_table * mapping_table, sector_t ppn){
    mapping_table->validate_bitmap[ppn / 8] |=  ((uint8_t) 1 << (ppn % 8));
}

int dm_zftl_ppn_is_valid(struct dm_zftl_mapping_table * mapping_table, sector_t ppn){
    if((mapping_table->validate_bitmap[ppn / 8] & ((uint8_t) 1 << (ppn % 8))) == (uint8_t)0)
        return 0;
    return 1;
}

unsigned int dm_zftl_get_ppa_zone_id(struct dm_zftl_target * dm_zftl, sector_t ppa){
    struct zoned_dev *dev = dm_zftl_get_ppa_dev(dm_zftl, ppa);
    return ppa / dev->zone_nr_sectors;
}


struct zoned_dev * dm_zftl_get_ppa_dev(struct dm_zftl_target * dm_zftl, sector_t ppa){
    if(ppa >= dm_zftl->cache_device->capacity_nr_sectors){
        return dm_zftl->zone_device;
    }
    return dm_zftl->cache_device;
}

sector_t dm_zftl_get_dev_addr(struct dm_zftl_target * dm_zftl, sector_t ppa){
    struct zoned_dev * dev = dm_zftl_get_ppa_dev(dm_zftl, ppa);
    return ppa - dev->zoned_metadata->addr_offset;
}

void dm_zftl_bio_endio(struct bio *bio, blk_status_t status)
{
    unsigned long flags;
    struct dm_zftl_io_work *bioctx = dm_per_bio_data(bio, sizeof(struct dm_zftl_io_work));

    spin_lock_irqsave(&bioctx->lock_, flags);

    if (status != BLK_STS_OK && bio->bi_status == BLK_STS_OK)
        bio->bi_status = status;

//    if (bioctx->dev && bio->bi_status != BLK_STS_OK)
//        bioctx->dev->flags |= DMZ_CHECK_BDEV;

    if (bioctx->io_complete == DM_ZFTL_IO_COMPLETE) {
        bio_endio(bio);
    }

    spin_unlock_irqrestore(&bioctx->lock_, flags);
}

void dm_zftl_io_complete(struct bio* bio){
    unsigned long flags;
    struct dm_zftl_io_work *context = dm_per_bio_data(bio, sizeof(struct dm_zftl_io_work));
    spin_lock_irqsave(&context->lock_, flags);
    context->io_complete = DM_ZFTL_IO_COMPLETE;
    spin_unlock_irqrestore(&context->lock_, flags);


#if DM_ZFTL_L2P_PIN

#endif
}

int dm_zftl_iterate_devices(struct dm_target *ti,
                        iterate_devices_callout_fn fn, void *data)
{
    struct dm_zftl_target *dm_zftl = ti->private;
    unsigned int zone_nr_sectors = dm_zftl->zone_device->zone_nr_sectors;
    sector_t capacity;

    int i, r;
    capacity = dm_zftl->cache_device->capacity_nr_sectors;
    r = fn(ti, dm_zftl->zone_device->dmdev, 0, ti->len, data);
    //printk(KERN_EMERG "Func: %pS at address: %px Return: %d\n", fn, fn, r);
    return r;
}

sector_t dm_zftl_get_seq_wp(struct zoned_dev * dev, sector_t len){

    sector_t wp;
    unsigned long flags;
    int ret;
    struct zone_info * opened_zone = dev->zoned_metadata->opened_zoned;
    if(!opened_zone){
        printk(KERN_EMERG "Error: Dev:%s no remaining free zone",
                dm_zftl_is_cache(dev) == DM_ZFTL_CACHE ? "Cache":"ZNS");
        return DM_ZFTL_UNMAPPED_PPA;
    }

    try_get_wp:



    if(opened_zone->wp + len <= (unsigned int)dev->zone_nr_sectors){
        wp = opened_zone->wp + opened_zone->id * dev->zone_nr_sectors + dev->zoned_metadata->addr_offset;

        return wp;
    }


    dm_zftl_zone_close(dev, opened_zone->id);
    ret = dm_zftl_open_new_zone(dev);
    if(ret){
        printk(KERN_EMERG "Error: Dev:%s can't alloc free zone",
               dm_zftl_is_cache(dev) == DM_ZFTL_CACHE ? "Cache":"ZNS");
        return DM_ZFTL_UNMAPPED_PPA;
    }
    opened_zone = dev->zoned_metadata->opened_zoned;
    goto try_get_wp;

}
/*
 * Initialize the bio context
 */
static inline void dm_zftl_init_bioctx(struct dm_zftl_target *dm_zftl,
                                     struct bio *bio)
{
    struct dm_zftl_io_work *bioctx = dm_per_bio_data(bio, sizeof(struct dm_zftl_io_work));
    bioctx->target = dm_zftl;
    bioctx->user_sec = bio->bi_iter.bi_sector;
    bioctx->bio_ctx = bio;
    bioctx->io_complete = DM_ZFTL_IO_IN_PROG;
    refcount_set(&bioctx->ref, 1);
    spin_lock_init(&bioctx->lock_);
}

void dm_zftl_dm_io_read_cb(unsigned long error, void * context){
    struct bio * bio =(struct bio *) context;
    bio_endio(bio);
}

#if DM_ZFTL_READ_SPLIT
void dm_zftl_read_split_cb(unsigned long error, void * context){
    struct dm_zftl_read_io * read_io = (struct dm_zftl_read_io * )context;
    unsigned long flags;
    spin_lock_irqsave(&read_io->lock_, flags);

    read_io->complete_io += 1;
    if(read_io->complete_io == read_io->nr_io){
        bio_endio(read_io->bio);
    }

    spin_unlock_irqrestore(&read_io->lock_, flags);
}
#endif


int dm_zftl_dm_io_read(struct dm_zftl_target *dm_zftl,struct bio *bio){
    //
    struct zoned_dev * dev;

    unsigned long flags;
    unsigned int nr_blocks = dmz_bio_blocks(bio);
    struct dm_io_region * where = kvmalloc_array(nr_blocks,
                                              sizeof(struct dm_io_region), GFP_KERNEL | __GFP_ZERO);
    int i, ret;
    sector_t start_sec = bio->bi_iter.bi_sector;
    sector_t ppa;
    sector_t original_ppa = dm_zftl_get(dm_zftl->mapping_table, start_sec);

    struct dm_zftl_read_io * read_io = (struct dm_zftl_read_io *)vmalloc(sizeof( struct dm_zftl_read_io));
    read_io->bio = bio;
    read_io->nr_io = nr_blocks;
    read_io->complete_io = 0;
    spin_lock_init(&read_io->lock_);


    for(i = 0; i < nr_blocks; ++i){


        ppa = dm_zftl_get(dm_zftl->mapping_table, start_sec + dmz_blk2sect(i));
        dev = dm_zftl_get_ppa_dev(dm_zftl, ppa);
        where[i].bdev = dev->bdev;
        where[i].sector = dm_zftl_get_dev_addr(dm_zftl, ppa);
        where[i].count = dmz_blk2sect(1);

#if DM_ZFTL_DEBUG
        printk(KERN_EMERG "Bio:READ [%llu, %llu](sec) ==> [Sub READ{%llu/%llu}] Dev:%s Zone ID:%llu Range[%llu, %llu](sec)",
           start_sec + dmz_blk2sect(i),
           start_sec + dmz_blk2sect(i) + where[i].count,
           i + 1,
           nr_blocks,
           dm_zftl_is_cache(dev) ? "CACHE":"ZNS",
           dev->zoned_metadata->opened_zoned->id,
           dm_zftl_get_ppa_dev(dm_zftl, ppa),
           dm_zftl_get_ppa_dev(dm_zftl, ppa) + where[i].count
           );
#endif

        struct dm_io_request iorq;
        iorq.bi_op = REQ_OP_READ;
        iorq.bi_op_flags = 0;
        iorq.mem.type = DM_IO_BIO;
        iorq.mem.ptr.bio = bio;
        //iorq.notify.fn = dm_zftl_read_split_cb;
        iorq.notify.fn = NULL;
        iorq.notify.context = read_io;
        iorq.client = dm_zftl->io_client;

        dm_io(&iorq, 1, &where[i], NULL);
        bio_advance(bio, 1 << DMZ_BLOCK_SHIFT);
    }
    dm_zftl_io_complete(bio);
    dm_zftl_bio_endio(bio, errno_to_blk_status(0));
    return DM_MAPIO_SUBMITTED;
}

void dm_zftl_dm_io_write_cb(unsigned long error, void * context){
    struct dm_zftl_io_work * io_work =(struct dm_zftl_io_work *) context;
    struct bio * bio = io_work->bio_ctx;
    struct dm_zftl_target * dm_zftl = io_work->target;
    dm_zftl_io_complete(bio);
    dm_zftl_bio_endio(bio, errno_to_blk_status(0));
}

int dm_zftl_dm_io_write(struct dm_zftl_target *dm_zftl, struct bio *bio){
    struct dm_zftl_io_work *context = dm_per_bio_data(bio, sizeof(struct dm_zftl_io_work));
    struct zoned_dev * dev = dm_zftl_get_foregound_io_dev(dm_zftl);
    struct dm_io_region * where = kvmalloc_array(1, sizeof(struct dm_io_region), GFP_KERNEL | __GFP_ZERO);
    int i, ret;

    context->target = dm_zftl;
    context->bio_ctx = bio;

    sector_t start_sec = bio->bi_iter.bi_sector;
    sector_t ppa;

    mutex_lock(&dm_zftl->mapping_table->l2p_lock);
    sector_t start_ppa = dm_zftl_get_seq_wp(dev, bio_sectors(bio));
    dev->zoned_metadata->opened_zoned->wp += dmz_blk2sect(dmz_bio_blocks(bio));
    mutex_unlock(&dm_zftl->mapping_table->l2p_lock);
    sector_t desire, addr1, addr2;
    desire = bio->bi_iter.bi_sector;


    if(start_ppa == DM_ZFTL_UNMAPPED_PPA){
        ret = -EIO;
        printk(KERN_EMERG "[Write Error] ZNS free: %llu Cache free: %llu In proc reclaiming: %llu"
                    ,atomic_read(&dm_zftl->zone_device->zoned_metadata->nr_free_zone)
                    ,atomic_read(&dm_zftl->cache_device->zoned_metadata->nr_free_zone)
                    ,atomic_read(&dm_zftl->nr_reclaim_work));
        goto FINISH;
    }

    ppa = start_ppa;
    where->sector = dm_zftl_get_dev_addr(dm_zftl, ppa);
    where->bdev = dev->bdev;
    where->count = dmz_blk2sect(dmz_bio_blocks(bio));


    if(atomic_read(&dm_zftl->nr_reclaim_work))
        io_schedule();


    dm_zftl_update_mapping_cache(dm_zftl->mapping_table,
                           start_sec,
                           start_ppa,
                           dmz_bio_blocks(bio));

    addr1 = start_ppa;

#if DM_ZFTL_DEBUG
    printk(KERN_EMERG "Bio:WRITE [%llu, %llu](sec) ==> Dev:%s Zone ID:%llu Range[%llu, %llu](sec)",
           start_sec,
           start_sec + where->count,
           dm_zftl_is_cache(dev) ? "CACHE":"ZNS",
           dev->zoned_metadata->opened_zoned->id,
           dm_zftl_get_dev_addr(dm_zftl, ppa),
           dm_zftl_get_dev_addr(dm_zftl, ppa) + where->count
           );
#endif

    struct dm_io_request iorq;
    iorq.bi_op = REQ_OP_WRITE;
    iorq.bi_op_flags = 0;
    iorq.mem.type = DM_IO_BIO;
    iorq.mem.ptr.bio = bio;
    iorq.notify.fn = dm_zftl_dm_io_write_cb;
    iorq.notify.context = context;
    iorq.client = dm_zftl->io_client;


    //return dm_io(&iorq, 1, where, NULL);
    dm_io(&iorq, 1, where, NULL);
    ret = DM_MAPIO_SUBMITTED;




    return ret;

    FINISH:
    ret = DM_MAPIO_SUBMITTED;
    dm_zftl_io_complete(bio);
    return ret;
}

/*
 * Handle IO
 * */
void dm_zftl_handle_bio(struct dm_zftl_target *dm_zftl,
                     struct dm_zftl_io_work *io, struct bio *bio){
    int ret;


    if (!bio_sectors(bio)) {
        dm_zftl_io_complete(bio);
        dm_zftl_bio_endio(bio, errno_to_blk_status(0));
        return;
    }

    /*
     * Write may trigger a zone allocation. So make sure the
     * allocation can succeed.
     */
    //TODO:Write traffic Record
    if (bio_op(bio) == REQ_OP_WRITE){
        dm_zftl->total_write_traffic_sec_ += bio_sectors(bio);
        dm_zftl->last_write_traffic_ += bio_sectors(bio);
        dm_zftl_cache_try_reclaim(dm_zftl);
    }

#if DM_ZFTL_DEBUG
    const char * op = "UNKNOWN";
    switch (bio_op(bio)) {
        case REQ_OP_READ:
            op = "READ";
            break;
        case REQ_OP_WRITE:
            op = "WRITE";
            break;
        case REQ_OP_DISCARD:
            op = "DISCARD";
            break;
        case REQ_OP_WRITE_ZEROES:
            op = "WRITE ZERO";
            break;
        default:
            op = "UNKNOWN";
    }
    printk(KERN_EMERG "Bio:%s [%llu, %llu](sec) [%llu, %llu](blocks)",
            op,
            bio->bi_iter.bi_sector,
            bio->bi_iter.bi_sector + bio_sectors(bio),
            dmz_bio_block(bio),
            dmz_bio_block(bio) + dmz_bio_blocks(bio)
            );
#endif
    switch (bio_op(bio)) {
        case REQ_OP_READ:
            ret = dm_zftl_dm_io_read(dm_zftl, bio);
#if DM_ZFTL_L2P_PIN
            dm_zftl_unpin(io->pin_work_ctx);
#endif
            break;
        case REQ_OP_WRITE:
            ret = dm_zftl_dm_io_write(dm_zftl, bio);
#if DM_ZFTL_L2P_PIN
            dm_zftl_unpin(io->pin_work_ctx);
#endif
            break;
        case REQ_OP_DISCARD:
        case REQ_OP_WRITE_ZEROES:
            dm_zftl_io_complete(bio);
            dm_zftl_bio_endio(bio, errno_to_blk_status(0));
            break;
        default:
            dm_zftl_io_complete(bio);
            dm_zftl_bio_endio(bio, errno_to_blk_status(0));
            printk(KERN_EMERG "Ignoring unsupported BIO operation 0x%x",
                        bio_op(bio));
            ret = -EIO;
    }


    unsigned long flags;
    spin_lock_irqsave(&dm_zftl->record_lock_, flags);
    switch (bio_op(bio)) {
        case REQ_OP_READ:
            dm_zftl->foreground_read_traffic_ += dmz_bio_blocks(bio);
            break;
        case REQ_OP_WRITE:
            dm_zftl->foreground_write_traffic_ += dmz_bio_blocks(bio);
            break;
    }
    spin_unlock_irqrestore(&dm_zftl->record_lock_, flags);


}
/*
 *
 * IO work fn
 *
 * */
static void dm_zftl_io_work_(struct work_struct *work){
    struct dm_zftl_io_work * io_work = container_of(work, struct dm_zftl_io_work, work);
    struct bio * io = io_work->bio_ctx;
    dm_zftl_handle_bio(io_work->target, io_work, io);
}
/*
 *
 * Queue io
 *
 * */
struct dm_zftl_io_work * dm_zftl_get_io_work(struct dm_zftl_target *dm_zftl, struct bio *bio){
    struct dm_zftl_io_work * io_work = kvmalloc(sizeof(struct dm_zftl_io_work), GFP_NOIO);
    INIT_WORK(&io_work->work, dm_zftl_io_work_);
    io_work->bio_ctx = bio;
    io_work->target = dm_zftl;
    return io_work;
}


void dm_zftl_queue_io(void * context){
    struct dm_zftl_io_work * io_work = context;
    queue_work(io_work->target->io_wq, &io_work->work);
}


void lsm_tree_frame_status_check(struct lsm_tree * tree, status_type_t type,
                                 unsigned int status_flags, char *result,
                                 unsigned int maxlen) {

}


/*
 * Process a new BIO.
 */
static int dm_zftl_map(struct dm_target *ti, struct bio *bio)
{
    struct dm_zftl_target *dm_zftl = ti->private;
    struct zoned_dev *dev = dm_zftl->zone_device;
    sector_t sector = bio->bi_iter.bi_sector;
    unsigned int nr_sectors = bio_sectors(bio);
    sector_t zone_sector;
    int ret;

    //if (dmzap_bdev_is_dying(dmzap->dev))
    //    return DM_MAPIO_KILL;

    if (!nr_sectors && bio_op(bio) != REQ_OP_WRITE)
        return DM_MAPIO_REMAPPED;

    if(!dmz_bio_blocks(bio))
        return DM_MAPIO_SUBMITTED;


    /* The BIO should be block aligned */
    if ((nr_sectors & DMZ_BLOCK_SECTORS_MASK) || (sector & DMZ_BLOCK_SECTORS_MASK)){
        printk(KERN_EMERG "Unaligned bio [%llu, %llu]",sector , sector + nr_sectors);
        return DM_MAPIO_KILL;
    }


    /* Initialize the BIO context */
    dm_zftl_init_bioctx(dm_zftl,bio);

    /* Split zone BIOs to fit entirely into a zone */
    zone_sector = sector & (dev->zone_nr_sectors - 1);
    if (zone_sector + nr_sectors > dev->zone_nr_sectors) {
#if DM_ZFTL_DEBUG
        printk(KERN_EMERG "Bio Split  Bio op %s  sector:[%llu,   %llu]",
                bio_op(bio) == READ ? "READ":"WRITE",
                (unsigned long long)sector,
                (unsigned long long)(sector + nr_sectors));
#endif
        dm_accept_partial_bio(bio, dev->zone_nr_sectors - zone_sector);
    }

    struct dm_zftl_io_work * io_work = dm_zftl_get_io_work(dm_zftl, bio);
    io_work->pin_cb_fn = dm_zftl_queue_io;
    io_work->pin_cb_ctx = (void *) io_work;
    struct io_job * io_job = kvmalloc(sizeof(struct io_job), GFP_NOIO);
    io_job->flags = IO_WORK;
    io_job->io_work = io_work;

    if(bio_op(bio) != REQ_OP_READ && bio_op(bio) != REQ_OP_WRITE){
        return DM_MAPIO_SUBMITTED;
    }

    if(!dmz_bio_blocks(bio))
        return DM_MAPIO_SUBMITTED;

    /* Now ready to handle this BIO */
#if DM_ZFTL_L2P_PIN
    struct try_l2p_pin * try_pin = kvmalloc(sizeof(struct try_l2p_pin), GFP_KERNEL);
    try_pin->dm_zftl = dm_zftl;
    try_pin->io_job = io_job;
    INIT_WORK(&try_pin->work, dm_zftl_try_l2p_pin);
    queue_work(dm_zftl->l2p_try_pin_wq, &try_pin->work);
#else
    dm_zftl_queue_io(io_job->io_work);
#endif

    return DM_MAPIO_SUBMITTED;
}





static int dm_zftl_load_device(struct dm_target *ti, char **argv){
    struct block_device *bdev;
    struct dm_dev *ddev;
    struct dm_zftl_target * dmz = ti->private;
    int ret;

    /* Get the zoned device */
    ret = dm_get_device(ti, argv[1], dm_table_get_mode(ti->table), &ddev);
    if (ret) {
        ti->error = "Get target device failed";
        return ret;
    }
    bdev = ddev->bdev;
    dmz->zone_device->bdev = bdev;
    dmz->zone_device->capacity_nr_sectors = i_size_read(bdev->bd_inode) >> SECTOR_SHIFT;
    dmz->zone_device->dmdev = ddev;
    dmz->zone_device->flags = DM_ZFTL_BACKEND;


    struct request_queue *q;
    sector_t zone_nr_sectors = 0;

    q = bdev_get_queue(dmz->zone_device->bdev);
    zone_nr_sectors = blk_queue_zone_sectors(q);
    dmz->zone_device->zone_nr_sectors = zone_nr_sectors;
    dmz->zone_device->zone_nr_blocks = dmz_sect2blk(zone_nr_sectors);
    dmz->zone_device->nr_zones = blkdev_nr_zones(dmz->zone_device->bdev->bd_disk);

#if DM_ZFTL_DEBUG
    printk(KERN_EMERG "ZNS Device:   Total zones:%d   Blocks per zone:%d   Sectors per zone:%d   Total Size(sectors):%d",
                                                dmz->zone_device->nr_zones,
                                                dmz->zone_device->zone_nr_blocks,
                                                zone_nr_sectors,
                                                dmz->zone_device->capacity_nr_sectors);
#endif


    /* Get the regular device */
    ret = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &ddev);
    if (ret) {
        ti->error = "Get target device failed";
        return ret;
    }
    dmz->cache_device->dmdev = ddev;
    dmz->cache_device->flags = DM_ZFTL_CACHE;
    bdev = ddev->bdev;
    dmz->cache_device->bdev = bdev;

    dmz->cache_device->capacity_nr_sectors = i_size_read(bdev->bd_inode) >> SECTOR_SHIFT;

    dmz->cache_device->zone_nr_sectors = zone_nr_sectors;
    dmz->cache_device->zone_nr_blocks = dmz_sect2blk(zone_nr_sectors);
    dmz->cache_device->nr_zones = dmz->cache_device->capacity_nr_sectors / dmz->cache_device->zone_nr_sectors;
    dmz->cache_device->capacity_nr_sectors = dmz->cache_device->nr_zones * zone_nr_sectors;

    dmz->capacity_nr_sectors = dmz->cache_device->capacity_nr_sectors + dmz->zone_device->capacity_nr_sectors;


#if DM_ZFTL_DEBUG
    printk(KERN_EMERG "Cache Device: Total zones:%d   Blocks per zone:%d   Sectors per zone:%d   Total Size(sectors):%d",
            dmz->cache_device->nr_zones,
            dmz->cache_device->zone_nr_blocks,
            zone_nr_sectors,
            dmz->cache_device->capacity_nr_sectors);
#endif


    return 0;
}

/*
 * Cleanup target.
 */
static void dm_zftl_dtr(struct dm_target *ti)
{
    struct dmz_target *dmz = ti->private;
}


/*
 * Initialize zone metadata and layout
 * */
static int dm_zftl_geometry_init(struct dm_target *ti)
{
    struct dm_zftl_target *zftl = ti->private;
    int i,r;
    zftl->zone_device->zoned_metadata = (struct dev_metadata *)vmalloc(sizeof (struct dev_metadata));
    struct dev_metadata * zoned_device_metadata = zftl->zone_device->zoned_metadata;
    zoned_device_metadata->zones = kvmalloc_array(zftl->zone_device->nr_zones,
                                                  sizeof(struct zone_info), GFP_KERNEL | __GFP_ZERO);
    if (!zoned_device_metadata->zones) {
        printk(KERN_EMERG "Unable to alloc memory");
    }

    struct zone_link_entry * zone_link;
    INIT_LIST_HEAD(&zoned_device_metadata->free_zoned);
    INIT_LIST_HEAD(&zoned_device_metadata->full_zoned);
    INIT_LIST_HEAD(&zoned_device_metadata->open_zoned);
    atomic_set(&zoned_device_metadata->nr_free_zone, (int)zftl->zone_device->nr_zones);
    atomic_set(&zoned_device_metadata->nr_full_zone, 0);



    for(i = 0; i < zftl->zone_device->nr_zones; ++i){
        zoned_device_metadata->zones[i].dev = zftl->zone_device;
        atomic_set(&zoned_device_metadata->zones[i].refcount, 0);
        zoned_device_metadata->zones[i].wp = 0;
        zoned_device_metadata->zones[i].id = i;
        spin_lock_init(&zoned_device_metadata->zones[i].lock_);
        zone_link = (struct zone_link_entry *)vmalloc(sizeof (struct zone_link_entry));
        zone_link->id = i;
        list_add(&zone_link->link, &zoned_device_metadata->free_zoned);
    }

    zftl->cache_device->zoned_metadata = (struct dev_metadata *)vmalloc(sizeof (struct dev_metadata));
    struct dev_metadata * cache_device_metadata = zftl->cache_device->zoned_metadata;
    cache_device_metadata->zones = kvmalloc_array(zftl->cache_device->nr_zones,
                                                  sizeof(struct zone_info), GFP_KERNEL | __GFP_ZERO);
    if(!cache_device_metadata->zones){
        ti->error = "metadata create fail";
        return 1;
    }
    INIT_LIST_HEAD(&cache_device_metadata->free_zoned);
    INIT_LIST_HEAD(&cache_device_metadata->full_zoned);
    INIT_LIST_HEAD(&cache_device_metadata->open_zoned);
    atomic_set(&cache_device_metadata->nr_free_zone, (int)zftl->cache_device->nr_zones - 1);
    atomic_set(&cache_device_metadata->nr_full_zone, 0);


    for(i = 1; i < zftl->cache_device->nr_zones; ++i){
        cache_device_metadata->zones[i].dev = zftl->cache_device;
        atomic_set(&cache_device_metadata->zones[i].refcount, 0);
        cache_device_metadata->zones[i].wp = 0;
        cache_device_metadata->zones[i].id = i;
        spin_lock_init(&cache_device_metadata->zones[i].lock_);
        zone_link = (struct zone_link_entry *)vmalloc(sizeof (struct zone_link_entry));
        zone_link->id = i;
        list_add(&zone_link->link, &cache_device_metadata->free_zoned);
    }

    cache_device_metadata->addr_offset = 0;
    zoned_device_metadata->addr_offset = zftl->cache_device->capacity_nr_sectors;

    spin_lock_init(&zoned_device_metadata->lock_);
    spin_lock_init(&cache_device_metadata->lock_);
    return 0;
}


/*
 * Setup target request queue limits.
 */
static void dm_zftl_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
    struct dm_zftl_target *dm_zftl = ti->private;
    unsigned int zone_sectors = dm_zftl->zone_device->zone_nr_sectors;

    limits->logical_block_size = DMZ_BLOCK_SIZE;
    limits->physical_block_size = DMZ_BLOCK_SIZE;

    blk_limits_io_min(limits, DMZ_BLOCK_SIZE);
    blk_limits_io_opt(limits, DMZ_BLOCK_SIZE);

    limits->discard_alignment = DMZ_BLOCK_SIZE;
    limits->discard_granularity = DMZ_BLOCK_SIZE;

    limits->max_discard_sectors = zone_sectors;
    limits->max_hw_discard_sectors = zone_sectors;
    limits->max_write_zeroes_sectors = zone_sectors;

    /* FS hint to try to align to the device zone size */
    limits->chunk_sectors = zone_sectors;
    limits->max_sectors = zone_sectors;

    /* We are exposing a drive-managed zoned block device */
    limits->zoned = DM_ZFTL_EXPOSE_TYPE;
}
/*
 * Setup target.
 */
static int dm_zftl_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    struct dm_zftl_target *dmz;
    int ret, i;

    /* Check arguments */
    if (argc < 1) {
        ti->error = "Invalid argument count";
        return -EINVAL;
    }

    /* Allocate and initialize the target descriptor */
    dmz = kzalloc(sizeof(struct dm_zftl_target), GFP_KERNEL);
    if (!dmz) {
        ti->error = "Unable to allocate the ZFTL target descriptor";
        return -ENOMEM;
    }

    dmz->zone_device = kcalloc(argc, sizeof(struct zoned_dev), GFP_KERNEL);
    if (!dmz->zone_device) {
        ti->error = "Unable to allocate the zoned device descriptors";
        kfree(dmz);
        return -ENOMEM;
    }

    dmz->cache_device = kcalloc(argc, sizeof(struct zoned_dev), GFP_KERNEL);
    if (!dmz->cache_device) {
        ti->error = "Unable to allocate the cache device descriptors";
        return -ENOMEM;
    }

    ret = bioset_init(&dmz->bio_set, DM_ZFTL_MIN_BIOS, 0, 0);
    if (ret) {
        ti->error = "create bio set failed";
        goto err_map;
    }
    ti->private = dmz;

    ret = dm_zftl_load_device(ti, argv);
    ret = dm_zftl_geometry_init(ti);
    ret = dm_zftl_reset_all(dmz->zone_device);
    ret = dm_zftl_open_new_zone(dmz->cache_device);
    ret = dm_zftl_open_new_zone(dmz->zone_device);
    ret = dm_zftl_init_mapping_table(dmz);
    ret = dm_zftl_init_copy_buffer(dmz);


    //make sure init after mapping table init
    dm_zftl_l2p_set_init(dmz);
    dmz->io_client = dm_io_client_create();
    dmz->record_buffer = NULL;


    ret = kfifo_alloc(&dmz->cache_device->write_fifo, sizeof(struct zone_link_entry) * dmz->cache_device->nr_zones, GFP_KERNEL);
    if (ret) {
        ti->error = "kfifo_alloc fail\n";
        ret = -ENOMEM;
        goto err_dev;
    }

    dmz->io_wq = alloc_workqueue("dm_zftl_foreground_io_wq", WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
    if (!dmz->io_wq) {
        ti->error = "Create io workqueue failed";
        ret = -ENOMEM;
        goto err_dev;
    }

    dmz->reclaim_write_wq = alloc_workqueue("dm_zftl_reclaim_write_wq", WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
    if (!dmz->reclaim_write_wq) {
        ti->error = "Create io workqueue failed";
        ret = -ENOMEM;
        goto err_dev;
    }

    dmz->lsm_tree_compact_wq = alloc_workqueue("dm_zftl_lsm_compact_wq", WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
    if (!dmz->lsm_tree_compact_wq) {
        ti->error = "Create io workqueue failed";
        ret = -ENOMEM;
        goto err_dev;
    }

    atomic_set(&dmz->nr_reclaim_work, 0);
    atomic_set(&dmz->max_reclaim_read_work, DM_ZFTL_RECLAIM_MAX_READ_NUM_DEFAULT);



    dmz->reclaim_read_wq = alloc_ordered_workqueue("dmz_zftl_rec", WQ_MEM_RECLAIM, 0);
    if (!dmz->reclaim_read_wq) {
        ti->error = "Create reclaim workqueue failed";
        ret = -ENOMEM;
        goto err_dev;
    }

    dmz->l2p_pin_wq = alloc_ordered_workqueue("dmz_zftl_pin", WQ_MEM_RECLAIM, 0);
    if (!dmz->l2p_pin_wq) {
        ti->error = "Create pin io workqueue failed";
        ret = -ENOMEM;
        goto err_dev;
    }

    dmz->l2p_page_out_wq = alloc_ordered_workqueue("dmz_zftl_page_out", WQ_MEM_RECLAIM, 0);
    if (!dmz->l2p_page_out_wq) {
        ti->error = "Create page out io workqueue failed";
        ret = -ENOMEM;
        goto err_dev;
    }

    dmz->io_kick_off_wq = alloc_ordered_workqueue("dmz_zftl_io_kick_off", WQ_MEM_RECLAIM, 0);
    if (!dmz->io_kick_off_wq) {
        ti->error = "Create kick off io workqueue failed";
        ret = -ENOMEM;
        goto err_dev;
    }

    dmz->l2p_try_pin_wq = alloc_ordered_workqueue("dmz_zftl_l2p_try_pin", WQ_MEM_RECLAIM, 0);
    if (!dmz->l2p_try_pin_wq) {
        ti->error = "Create try pin workqueue failed";
        ret = -ENOMEM;
        goto err_dev;
    }

    //dmz->reclaim_work = vmalloc(sizeof(struct dm_zftl_reclaim_read_work));
    //dmz->reclaim_work->target = dmz;
    //INIT_DELAYED_WORK(&dmz->reclaim_work->work, dm_zftl_reclaim_read_work);
    //mod_delayed_work(dmz->reclaim_read_wq, &dmz->reclaim_work->work, DM_ZFTL_RECLAIM_PERIOD);

    spin_lock_init(&dmz->record_lock_);
    dmz->cache_2_zns_reclaim_write_traffic_ = 0;
    dmz->cache_2_zns_reclaim_read_traffic_ = 0;
    dmz->zns_write_traffic_ = 0;
    dmz->cache_write_traffic_ = 0;
    dmz->foreground_read_traffic_ = 0;
    dmz->foreground_write_traffic_ = 0;
    dmz->foreground_reclaim_cnt_ = 0;
    dmz->background_reclaim_cnt_ = 0;
    dmz->total_write_traffic_sec_ = 0;
    dmz->last_write_traffic_ = 0;
    dmz->last_compact_traffic_ = 0;


    dmz->dummy_l2p_buffer = vmalloc(8192);
    if(!dmz->dummy_l2p_buffer)
        goto err_dev;

    clear_bit_unlock(DMZAP_WR_OUTSTANDING, &dmz->zone_device->write_bitmap);



    ti->max_io_len = dmz->zone_device->zone_nr_sectors;
    ti->num_flush_bios = 1;
    ti->num_discard_bios = 1;
    ti->num_write_zeroes_bios = 1;
    ti->per_io_data_size = sizeof(struct dm_zftl_io_work);
    ti->flush_supported = true;
    ti->discards_supported = false;
    /* The exposed capacity is the zone device capicity*/
    ti->len = dmz->zone_device->capacity_nr_sectors;

    return 0;
    err_map:
    err_meta:
    err_dev:
    return -1;
}

/*
 * Pass on ioctl to the backend device.
 */
static int dm_zftl_prepare_ioctl(struct dm_target *ti, struct block_device **bdev)
{
    struct dm_zftl_target * dm_zftl = ti->private;
    *bdev = dm_zftl->zone_device->bdev;
    return 0;
}

static void dm_zftl_status(struct dm_target *ti, status_type_t type,
                       unsigned int status_flags, char *result,
                       unsigned int maxlen){
    struct dm_zftl_target * dm_zftl = ti->private;
    int sz=0;
    DMEMIT("<Dm-zftl>: status.......\n");
#if DM_ZFTL_USING_LEA_FTL
    struct dm_zftl_compact_work * _work = kmalloc(sizeof(struct dm_zftl_compact_work), GFP_NOIO);
    _work->target = dm_zftl;
    dm_zftl_compact_work((struct work_struct *)_work);

    //lsm_tree_frame_status_check(dm_zftl->mapping_table->lsm_tree, type, status_flags, result, maxlen);
    int level_sum = 0;
    int acc_count = 0;
    int appro_count = 0;
    int crb_count = 0;
    unsigned int frame_no = 0;
    struct lsm_tree * tree = dm_zftl->mapping_table->lsm_tree;

    if(!dm_zftl->record_buffer){
        dm_zftl->record_buffer = vmalloc(sizeof (unsigned int) * tree->nr_frame);
        if(dm_zftl->record_buffer == NULL){
            vfree(dm_zftl->record_buffer);
            printk(KERN_EMERG "Can't alloc record buffer\n");
            return;
        }
    }


    DMEMIT("Mapping table leaftl size:%u B\n", lsm_tree_get_size(tree));

    for(frame_no = 0; frame_no < tree->nr_frame ; frame_no++) {

        struct lsm_tree_frame * frame = &tree->frame[frame_no];

        if(dm_zftl->record_buffer) {
            if(!frame)
                dm_zftl->record_buffer[frame_no] = 0;
            else
                dm_zftl->record_buffer[frame_no] = (unsigned int)(atomic_read(&frame->nr_level));
        }

        if(!frame)
            continue;
        struct lsm_tree_level * level = frame->level;
        if(!level)
            continue;

        level_sum += atomic_read(&frame->nr_level);

        while(level) {
            struct segment * segs = level->seg;
            while(segs) {
                if(segs->is_acc_seg)
                    acc_count += 1;
                else {
                    appro_count += 1;
                }
                if(!segs->is_seq_seg){
                    crb_count += (int)segs->CRB->buffer_len;
                }
                segs = segs->next;
            }
            level = level->next_level;
        }
    }

    DMEMIT("Accurate segments: %d \n"
           "Approximate segments: %d \n"
           "Total segments: %d \n"
           "CRB lpns: %d \n"
            ,acc_count
            ,appro_count
            ,appro_count + acc_count
            ,crb_count);

    unsigned int avg_level;
    unsigned int p50_level;
    unsigned int p99_level;
    unsigned int max_level;
    DMEMIT("Avg level: %u / %u \n", level_sum, tree->nr_frame);
    if(dm_zftl->record_buffer){
        // ascend
        sort(dm_zftl->record_buffer,
             tree->nr_frame,
             sizeof(unsigned int),
             dm_zftl_cmp_,
             NULL);
        max_level = dm_zftl->record_buffer[ tree->nr_frame - 1 ];
        p99_level = dm_zftl->record_buffer[ 99 * (tree->nr_frame - 1) / 100 ];
        p50_level = dm_zftl->record_buffer[ 50 * (tree->nr_frame - 1) / 100 ];
        DMEMIT("Max level: %u\n"
               "P99 level: %u\n"
               "P50 level: %u\n",
               max_level,
               p99_level,
               p50_level);
    }


#else

#endif
    DMEMIT("Mapping table dftl/sftl size:%u B\n", dm_zftl_sftl_get_size(dm_zftl->mapping_table));
    struct dm_zftl_l2p_mem_pool * l2p_cache = dm_zftl->l2p_mem_pool;
    unsigned int i = 0;
    unsigned int pinned_frame_cnt = 0;
    unsigned int unpinned_frame_cnt = 0;
    unsigned int on_drame_frame_cnt = 0;
    unsigned int on_lru_frame_cnt = 0;
    unsigned int current_eta_l2p_size = 0;
    struct dm_zftl_l2p_frame * frame;

    unsigned long flags;
    for(i = 0; i < l2p_cache->max_frame; ++i){
        frame = l2p_cache->l2f_table[i];
        spin_lock_irqsave(&frame->_lock, flags);
        if(frame->state == ON_DRAM){
            on_drame_frame_cnt++;
            if(atomic_read(&frame->ref_count)){
                pinned_frame_cnt++;
            }else{
                unpinned_frame_cnt++;
            }
        }
        spin_unlock_irqrestore(&frame->_lock, flags);
    }

    TAILQ_FOREACH(frame, &l2p_cache->_frame_list, list_entry){
        on_lru_frame_cnt++;
    }
    DMEMIT("Total l2p frame on dram: %u\n", on_drame_frame_cnt);
    DMEMIT("Total pinned frame: %u\n", pinned_frame_cnt);
    DMEMIT("Total unpinned frame: %u\n", unpinned_frame_cnt);
    DMEMIT("Total on lru frame: %u\n", on_lru_frame_cnt);
    return;
}

unsigned int dm_zftl_sftl_get_size(struct dm_zftl_mapping_table * mapping_table){
    unsigned int vaild_lpn = 0;
    unsigned int vaild_lpn_frame = 0;
    unsigned int i;
    unsigned int pre_frame = 0;
    for(i = 0; i < mapping_table->l2p_table_sz; ++i){
        if(mapping_table->l2p_table[i] != DM_ZFTL_UNMAPPED_PPA){
            vaild_lpn++;
            if(i / DM_ZFTL_SFTL_L2P_FRAME_LENGTH != pre_frame){
                pre_frame = i / DM_ZFTL_SFTL_L2P_FRAME_LENGTH;
                vaild_lpn_frame++;
            }
        }
    }
    return vaild_lpn_frame * 1024 * 4;
}

static struct target_type dm_zftl_type = {
        .name		 = "zftl",
        .version	 = {1, 0, 0},
        .features	 = DM_TARGET_ZONED_HM,
        .module		 = THIS_MODULE,
        .ctr		 = dm_zftl_ctr,
        .dtr		 = dm_zftl_dtr,
        .map		 = dm_zftl_map,
        .io_hints	 = dm_zftl_io_hints,
        .prepare_ioctl	 = dm_zftl_prepare_ioctl,
        .iterate_devices = dm_zftl_iterate_devices,
        .status = dm_zftl_status,
};




struct zoned_dev * dm_zftl_get_foregound_io_dev(struct dm_zftl_target * dm_zftl){
    /* Do we need this ? */
//    if(atomic_read(&dm_zftl->cache_device->zoned_metadata->nr_free_zone) <= DM_ZFTL_FULL_THRESHOLD){
//        printk(KERN_EMERG "Cache dev full. Now foregound io switch to ZNS");
//        return dm_zftl->zone_device;
//    }
    return dm_zftl->cache_device;
}

int dm_zftl_open_new_zone(struct zoned_dev * dev){

    if(atomic_read(&dev->zoned_metadata->nr_free_zone) == 0)
        return 1;

    struct zone_link_entry *zone_link = NULL;
    list_for_each_entry(zone_link, &dev->zoned_metadata->free_zoned, link){
        if(zone_link)
            goto FOUND;

    }
    return 1;

    FOUND:
    list_del(&zone_link->link);
    atomic_dec(&dev->zoned_metadata->nr_free_zone);
    dev->zoned_metadata->opened_zoned = &dev->zoned_metadata->zones[zone_link->id];
#if DM_ZFTL_DEBUG
    printk(KERN_EMERG "Open new zone => Device:%s Id:%llu Range: [%llu, %llu](blocks)"
            , dm_zftl_is_cache(dev) ? "Cache" : "ZNS"
            , zone_link->id
            , zone_link->id * dev->zone_nr_blocks
            , (zone_link->id + 1) * dev->zone_nr_blocks);
    printk(KERN_EMERG "Remaing free zone:%d", atomic_read(&dev->zoned_metadata->nr_free_zone));
#endif
    return 0;
}

int dm_zftl_reset_all(struct zoned_dev * dev){
    int ret;
    ret = blkdev_zone_mgmt(dev->bdev, REQ_OP_ZONE_RESET,
                           0,
                           dev->capacity_nr_sectors,
                           GFP_NOIO);
    if (ret) {
        printk(KERN_EMERG "Reset All zone failed");
        return ret;
    }

#if DM_ZFTL_DEBUG
    printk(KERN_EMERG "Reset All zone complete!");
#endif
    return 0;
}
/*
 *
 * Reset a zone write pointer.
 */
int dm_zftl_reset_zone(struct zoned_dev * dev, struct zone_info *zone)
{

    struct zone_link_entry * zone_link = (struct zone_link_entry *)vmalloc(sizeof (struct zone_link_entry));
    zone_link->id = zone->id;
    list_add(&zone_link->link, &dev->zoned_metadata->free_zoned);
    atomic_inc(&dev->zoned_metadata->nr_free_zone);

    if(dm_zftl_is_zns(dev)){//TODO: Make sure init zone_dev flag before try to reset any zone
        int ret;
        ret = blkdev_zone_mgmt(dev->bdev, REQ_OP_ZONE_RESET,
                           zone->id * dev->zone_nr_sectors,
                           dev->zone_nr_sectors,
                           GFP_NOIO);
        if (ret) {
            printk(KERN_EMERG "Reset zone %u failed %d",
                    zone->id, ret);
            return ret;
        }
        zone->wp=0;
    }else{

        zone->wp=0;
    }
#if DM_ZFTL_DEBUG
    printk(KERN_EMERG "Reset zone => Device:%s Id:%llu Range: [%llu, %llu](blocks)"
                                , dm_zftl_is_cache(dev) ? "cache" : "backend"
                                , zone->id
                                , zone->id * dev->zone_nr_blocks
                                , (zone->id + 1) * dev->zone_nr_blocks);
#endif
    return 0;
}

void dm_zftl_zone_close(struct zoned_dev * dev, unsigned int zone_id){
    struct zone_link_entry *zone_link = kzalloc(sizeof(struct  zone_link_entry), GFP_KERNEL);
    int ret;
    zone_link->id = zone_id;
    list_add(&zone_link->link, &dev->zoned_metadata->full_zoned);
    dev->zoned_metadata->opened_zoned = NULL;
    atomic_inc(&dev->zoned_metadata->nr_full_zone);

    if(dm_zftl_is_cache(dev)){
        ret = kfifo_in(&dev->write_fifo, zone_link, sizeof(struct zone_link_entry));
        if (!ret) {
            printk(KERN_ERR "[ZONE CLOSE]: fifo is full\n");
        }
    }
}

static int __init dm_zftl_init(void)
{
    return dm_register_target(&dm_zftl_type);
}

static void __exit dm_zftl_exit(void)
{
    dm_unregister_target(&dm_zftl_type);
}
module_init(dm_zftl_init);
module_exit(dm_zftl_exit);

MODULE_DESCRIPTION(DM_NAME " an host-based ftl for zoned block device");
MODULE_AUTHOR("Xin Huang <hx2002@mail.ustc.edu.cn>");
MODULE_LICENSE("GPL");


