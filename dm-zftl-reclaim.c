//
// Created by root on 3/14/24.
//
#include "dm-zftl.h"
#include <linux/sort.h>
#define BLOCK_4K_SIZE 4096
#define COPY_BUFFER_SIZE 65536
//  Reclaim:
//  Reclaim include foreground reclaim (Cache => ZNS) and background reclaim (ZNS => ZNS)
//  I.      Get Reclaim Zone id
//  II.     Kick-off read io, read zone data to pre-alloc buffer. ( i => zone_start_ppn + i => lpn )(need to construct L2P mapping?)
//  III.    Zone data ( contain P2L mapping ) => Sort all lpn
//  IV.     Pin all lpn
//  V.      (Mapping-lock) Check l2p and vaild-bitmap, keep vaild lpn to lpn buffer and sort, update mapping
//  VI.     Construct Page-list Kick-off write back io

void * dm_zftl_init_copy_buffer(struct dm_zftl_target * dm_zftl){
    int ret;
    ret = kfifo_alloc(&dm_zftl->fg_reclaim_buffer_fifo, sizeof(struct copy_buffer) * DM_ZFTL_MAX_RECLAIM_BUFFER, GFP_KERNEL);
    if(ret){
        printk(KERN_EMERG "[Reclaim] fifo alloc fail!");
        BUG_ON(1);
    }
    ret = kfifo_alloc(&dm_zftl->bg_reclaim_buffer_fifo, sizeof(struct copy_buffer) * DM_ZFTL_MAX_RECLAIM_BUFFER, GFP_KERNEL);
    if(ret){
        printk(KERN_EMERG "[Reclaim] fifo alloc fail!");
        BUG_ON(1);
    }
    unsigned int i = 0;
    for(i = 0; i < DM_ZFTL_MAX_RECLAIM_BUFFER; ++i){
        struct copy_buffer * buffer = kvmalloc(sizeof(struct copy_buffer), GFP_KERNEL);
        buffer->nr_blocks = dm_zftl->zone_device->zone_nr_blocks;
        buffer->buffer = vmalloc(BLOCK_4K_SIZE * dm_zftl->zone_device->zone_nr_blocks);
        if(buffer->buffer == NULL){
            vfree(buffer->buffer);
            printk(KERN_EMERG "Can't alloc copy buffer");
            BUG_ON(1);
        }
        buffer->lpn_buffer = kvmalloc_array(buffer->nr_blocks, sizeof(struct dm_zftl_p2l_info), GFP_KERNEL);
        if(buffer->lpn_buffer == NULL){
            vfree(buffer->lpn_buffer);
            printk(KERN_EMERG "Can't alloc lpn buffer");
            BUG_ON(1);
        }
        buffer->nr_valid_blocks = 0;
        buffer->sorted_lpn_array = kvmalloc_array(buffer->nr_blocks, sizeof(unsigned int), GFP_KERNEL);
        if(buffer->sorted_lpn_array == NULL){
            vfree(buffer->sorted_lpn_array);
            printk(KERN_EMERG "Can't alloc sorted lpn buffer");
            BUG_ON(1);
        }
        kfifo_in(&dm_zftl->fg_reclaim_buffer_fifo, buffer, sizeof(struct copy_buffer));
    }

    for(i = 0; i < DM_ZFTL_MAX_RECLAIM_BUFFER; ++i){
        struct copy_buffer * buffer = kvmalloc(sizeof(struct copy_buffer), GFP_KERNEL);
        buffer->nr_blocks = dm_zftl->zone_device->zone_nr_blocks;
        buffer->buffer = vmalloc(BLOCK_4K_SIZE * dm_zftl->zone_device->zone_nr_blocks);
        if(buffer->buffer == NULL){
            vfree(buffer->buffer);
            printk(KERN_EMERG "Can't alloc copy buffer");
            BUG_ON(1);
        }
        buffer->lpn_buffer = kvmalloc_array(buffer->nr_blocks, sizeof(struct dm_zftl_p2l_info), GFP_KERNEL);
        if(buffer->lpn_buffer == NULL){
            vfree(buffer->lpn_buffer);
            printk(KERN_EMERG "Can't alloc lpn buffer");
            BUG_ON(1);
        }
        buffer->sorted_lpn_array = kvmalloc_array(buffer->nr_blocks, sizeof(unsigned int), GFP_KERNEL);
        if(buffer->sorted_lpn_array == NULL){
            vfree(buffer->sorted_lpn_array);
            printk(KERN_EMERG "Can't alloc sorted lpn buffer");
            BUG_ON(1);
        }
        kfifo_in(&dm_zftl->bg_reclaim_buffer_fifo, buffer, sizeof(struct copy_buffer));
    }
    return 0;
}

void dm_zftl_zns_try_gc(struct dm_zftl_target * dm_zftl){
    if(dm_zftl_need_gc(dm_zftl)){
        atomic_inc(&dm_zftl->nr_bg_reclaim);
        struct copy_job * copy_job = kmalloc(sizeof(struct copy_job), GFP_NOIO);
        INIT_WORK(&copy_job->work, dm_zftl_do_background_reclaim);
        copy_job->dm_zftl = dm_zftl;
        queue_work(dm_zftl->reclaim_read_wq, &copy_job->work);
    }
}

int dm_zftl_need_gc(struct dm_zftl_target * dm_zftl){
    if(!DM_ZFTL_ZNS_GC_ENABLE)
        return 0;
    if(atomic_read(&dm_zftl->nr_bg_reclaim) >= atomic_read(&dm_zftl->max_reclaim_read_work))
        return 0;
    if(atomic_read(&dm_zftl->zone_device->zoned_metadata->nr_full_zone) >= atomic_read(&dm_zftl->zone_device->zoned_metadata->nr_free_zone)){
        return 1;
    }
    return 0;
}

void dm_zftl_do_background_reclaim(struct work_struct *work){
    struct copy_job * copy_job = container_of(work, struct copy_job, work);
    struct dm_zftl_target * dm_zftl = copy_job->dm_zftl;
    dm_zftl_do_reclaim_read(work, dm_zftl->zone_device
            , dm_zftl->zone_device);
}

int dm_zftl_need_reclaim(struct dm_zftl_target * dm_zftl){
    if(atomic_read(&dm_zftl->nr_fg_reclaim) >= atomic_read(&dm_zftl->max_reclaim_read_work))
        return 0;
    if(     (
                    dm_zftl->last_write_traffic_ >= DM_ZFTL_RECLAIM_INTERVAL ||
                    atomic_read(&dm_zftl->cache_device->zoned_metadata->nr_free_zone) <= DM_ZFTL_RECLAIM_THRESHOLD
            )
            && DM_ZFTL_RECLAIM_ENABLE){
        dm_zftl->last_write_traffic_ = 0;
        return 1;
    }
    return 0;
}

void dm_zftl_cache_try_reclaim(struct dm_zftl_target * dm_zftl){
    if(dm_zftl_need_reclaim(dm_zftl)){
        atomic_inc(&dm_zftl->nr_fg_reclaim);
        struct copy_job * read_work = kmalloc(sizeof(struct copy_job), GFP_NOIO);
        INIT_WORK(&read_work->work, dm_zftl_do_foreground_reclaim);
        read_work->dm_zftl = dm_zftl;
        queue_work(dm_zftl->reclaim_read_wq, &read_work->work);
    }
}
// Get free zone id and free buffer, if fail then retry. o.w kick-off read
void dm_zftl_do_foreground_reclaim(struct work_struct *work){
    struct copy_job * copy_job = container_of(work, struct copy_job, work);
    struct dm_zftl_target * dm_zftl = copy_job->dm_zftl;
    dm_zftl_do_reclaim_read(work, dm_zftl->cache_device
                            , dm_zftl->zone_device);
}

void dm_zftl_do_reclaim_read(struct work_struct *work, struct zoned_dev *reclaim_from, struct zoned_dev *copy_to){
    struct copy_job * cp_job = container_of(work, struct copy_job, work);
    struct dm_zftl_target * dm_zftl = cp_job->dm_zftl;
    struct kfifo * fifo;
    struct copy_buffer * copy_buffer = NULL;
    int ret;

    if(dm_zftl_is_cache(reclaim_from)){
        fifo = &dm_zftl->fg_reclaim_buffer_fifo;
    }else{
        fifo = &dm_zftl->bg_reclaim_buffer_fifo;
    }
    ret = kfifo_out(fifo, copy_buffer, sizeof(struct copy_buffer));
    if (!ret){
        goto REQUEUE;
    }

    cp_job->fifo = fifo;
    cp_job->copy_buffer = copy_buffer;
    cp_job->copy_buffer->nr_valid_blocks = 0;
    cp_job->copy_buffer->nr_blocks = reclaim_from->zone_nr_blocks;
    cp_job->dm_zftl = dm_zftl;
    cp_job->copy_from = reclaim_from;
    cp_job->writeback_to = copy_to;
    spin_lock_init(&cp_job->lock_);

    unsigned int reclaim_zone_id = dm_zftl_get_reclaim_zone(cp_job->copy_from, dm_zftl->mapping_table);
    cp_job->reclaim_zone_id = reclaim_zone_id;
    if(!reclaim_zone_id) {
        goto REQUEUE;
    }

    unsigned int reclaim_zone_start_ppn = dm_zftl_get_zone_start_vppn(cp_job->copy_from, reclaim_zone_id);
    cp_job->reclaim_zone_start_ppn = reclaim_zone_start_ppn;

    struct dm_io_region * where = kvmalloc(sizeof(struct dm_io_region), GFP_KERNEL | __GFP_ZERO);

    where->bdev = cp_job->copy_from->bdev;
    where->sector = dm_zftl_get_dev_addr(cp_job->dm_zftl
                                        , dmz_blk2sect(reclaim_zone_start_ppn));
    where->count = dmz_blk2sect(cp_job->copy_from->zone_nr_blocks);

    struct dm_io_request iorq;
    iorq.bi_op = REQ_OP_READ;
    iorq.bi_op_flags = 0;
    iorq.mem.type = DM_IO_VMA;
    iorq.mem.ptr.vma = cp_job->copy_buffer->buffer;
    iorq.notify.fn = dm_zftl_reclaim_read_cb;
    iorq.notify.context = cp_job;
    iorq.client = cp_job->dm_zftl->io_client;
    unsigned long error_bits;
    ret = dm_io(&iorq, 1, where, error_bits);
    return;

    REQUEUE:
    queue_work(dm_zftl->reclaim_read_wq, &cp_job->work);
    return;
}

void dm_zftl_reclaim_read_cb(unsigned long error, void * context){
    struct copy_job * copy_job =(struct copy_job *) context;
    struct dm_zftl_target * dm_zftl = copy_job->dm_zftl;
    //sort lpn buffer (don't need lock, only p2l is being used)
    unsigned int start_ppn = copy_job->reclaim_zone_start_ppn;
    unsigned int ppn;
    for(ppn = start_ppn; ppn < start_ppn + copy_job->nr_blocks; ++ppn){
        copy_job->copy_buffer->lpn_buffer[ppn - start_ppn].ppn = ppn;
        copy_job->copy_buffer->lpn_buffer[ppn - start_ppn].lpn = dm_zftl->mapping_table->p2l_table[ppn];
        copy_job->copy_buffer->lpn_buffer[ppn - start_ppn].vma_idx = ppn - start_ppn;
    }

    sort(copy_job->copy_buffer->lpn_buffer,
         copy_job->copy_buffer->nr_blocks,
         sizeof(struct dm_zftl_p2l_info),
         dm_zftl_p2l_cmp_,
         NULL);

#if DM_ZFTL_L2P_PIN
    //kick-off pin work
    copy_job->pin_cb_fn = dm_zftl_valid_data_writeback;
    copy_job->pin_cb_ctx = (struct work_struct *)&copy_job->work;
    struct io_job * io_job = kmalloc(sizeof(struct io_job), GFP_NOIO);
    io_job->copy_job = cp_job;
    io_job->flags = CP_JOB;
    struct try_l2p_pin * try_pin = kvmalloc(sizeof(struct try_l2p_pin), GFP_KERNEL);
    try_pin->dm_zftl = dm_zftl;
    try_pin->io_job = io_job;
    INIT_WORK(&try_pin->work, dm_zftl_try_l2p_pin);
    queue_work(dm_zftl->l2p_try_pin_wq, &try_pin->work);
#else
    //kick-off write-back
    INIT_WORK(&copy_job->work, dm_zftl_valid_data_writeback);
    queue_work(copy_job->dm_zftl->reclaim_write_wq, &copy_job->work);
#endif
}

struct page_list * dm_zftl_construct_wb_page_list(struct copy_buffer * copy_buffer){
    struct page_list * write_back_page_list = NULL;
    struct page_list * curr = NULL;
    unsigned int i = 0;
    char * vma_start = (char *)copy_buffer->buffer;
    unsigned int vma_idx;
    void * vma;
    for(i = 0; i < copy_buffer->nr_valid_blocks; ++i){

        vma_idx = copy_buffer->lpn_buffer[i].vma_idx;
        vma = (void *)(vma_start + BLOCK_4K_SIZE * vma_idx);

        struct page * cp_page = virt_to_page(vma);
        struct page_list * cp_page_list = kvmalloc(sizeof(struct page_list), GFP_KERNEL);
        cp_page_list->page = cp_page;
        cp_page_list->next = NULL;

        if(curr) {
            curr->next = cp_page_list;
            curr = cp_page_list;
        }else{
            curr = cp_page_list;
            write_back_page_list = cp_page_list;
        }

    }
    return write_back_page_list;
}

void dm_zftl_valid_data_writeback(struct work_struct *work){
    struct copy_job * copy_job = container_of(work, struct copy_job, work);
    struct dm_zftl_target * dm_zftl = copy_job->dm_zftl;
    unsigned int i = 0;
    unsigned int ppn = 0;
    unsigned int next_valid_idx = 0;

    struct zoned_dev * wb_dev = copy_job->writeback_to;
    sector_t nr_sectors = dmz_blk2sect(copy_job->copy_buffer->nr_valid_blocks);
    struct dm_io_region * where = (struct dm_io_region *)vmalloc(sizeof (struct dm_io_region));
    sector_t start_ppa = dm_zftl_get_seq_wp(wb_dev, nr_sectors);
    unsigned long flags;
    spin_lock_irqsave(&copy_job->writeback_to->zoned_metadata->opened_zoned->lock_, flags);
    copy_job->writeback_to->zoned_metadata->opened_zoned->wp += nr_sectors;
    spin_unlock_irqrestore(&copy_job->writeback_to->zoned_metadata->opened_zoned->lock_, flags);


    mutex_lock(&dm_zftl->mapping_table->l2p_lock);
    for(i = 0; i < copy_job->nr_blocks; ++i){
        ppn = copy_job->copy_buffer->lpn_buffer[i].ppn;
        if(dm_zftl_ppn_is_valid(copy_job->dm_zftl->mapping_table, ppn)){
            copy_job->copy_buffer->lpn_buffer[next_valid_idx] = copy_job->copy_buffer->lpn_buffer[i];
            copy_job->copy_buffer->sorted_lpn_array[next_valid_idx] = copy_job->copy_buffer->lpn_buffer[i].lpn;
            next_valid_idx++;
        }
    }

    copy_job->copy_buffer->nr_valid_blocks = next_valid_idx;

    struct page_list * wb_pg_list = dm_zftl_construct_wb_page_list(copy_job->copy_buffer);

    dm_zftl_update_mapping_by_lpn_array(dm_zftl->mapping_table,
                                        copy_job->copy_buffer->sorted_lpn_array,
                                        dmz_sect2blk(start_ppa),
                                        copy_job->copy_buffer->nr_valid_blocks);
    mutex_unlock(&dm_zftl->mapping_table->l2p_lock);


    /* We can only have one outstanding write at a time */
    while(test_and_set_bit_lock(DMZAP_WR_OUTSTANDING,
                                &dm_zftl->zone_device->write_bitmap))
        io_schedule();

    if(start_ppa == DM_ZFTL_UNMAPPED_PPA){
        printk(KERN_EMERG "[Reclaim] Fatal: no free space for wriite back valid data");
        BUG_ON(1);
    }

#if DM_ZFTL_RECLAIM_DEBUG
    printk(KERN_EMERG "[Reclaim][Write back] dev:%s zone:%llu ==> dev:%s zone:%llu wp:%llu",
            DM_ZFTL_DEV_STR(copy_job->copy_from),
            copy_job->reclaim_zone_id,
            DM_ZFTL_DEV_STR(dm_zftl_get_ppa_dev(dm_zftl, start_ppa)),
            dev->zoned_metadata->opened_zoned->id,
            dev->zoned_metadata->opened_zoned->wp
    );
#endif
    where->sector = dm_zftl_get_dev_addr(dm_zftl, start_ppa);
    where->bdev = wb_dev->bdev;
    where->count = nr_sectors;

    int ret;
    unsigned long error_bits;
    struct dm_io_request iorq;

    iorq.bi_op = REQ_OP_WRITE;
    iorq.bi_op_flags = 0;
    iorq.mem.type = DM_IO_PAGE_LIST;
    iorq.mem.ptr.pl = wb_pg_list;
    iorq.mem.offset = 0;
    iorq.notify.fn = dm_zftl_valid_data_writeback_cb;
    iorq.notify.context = copy_job;
    iorq.client = dm_zftl->io_client;
    ret = dm_io(&iorq, 1, where, error_bits);
    return;
}

void dm_zftl_valid_data_writeback_cb(unsigned long error, void * context){
    struct copy_job * copy_job = context;
    struct dm_zftl_target * dm_zftl = copy_job->dm_zftl;
    unsigned long flags;
    #if DM_ZFTL_RECLAIM_DEBUG
    printk(KERN_EMERG "[Reclaim Done] dev:%s zone:%llu",DM_ZFTL_DEV_STR(job->copy_from), job->reclaim_zone_id);
#endif

    //TODO:Fix metadata update and zone reset
    clear_bit_unlock(DMZAP_WR_OUTSTANDING, &dm_zftl->zone_device->write_bitmap);
    dm_zftl_reset_zone(copy_job->copy_from,
                       &copy_job->copy_from->zoned_metadata->zones[copy_job->reclaim_zone_id]);

    if(dm_zftl_is_cache(copy_job->copy_from))
        atomic_dec(&dm_zftl->nr_fg_reclaim);
    else
        atomic_dec(&dm_zftl->nr_bg_reclaim);

    int ret;
    ret = kfifo_in(copy_job->fifo, copy_job, sizeof(struct copy_job));
    if (!ret) {
        printk(KERN_ERR "[COPY FIFO]: fifo is full\n");
        BUG_ON(1);
    }

    spin_lock_irqsave(&dm_zftl->record_lock_, flags);
    dm_zftl->cache_2_zns_reclaim_write_traffic_ += copy_job->copy_buffer->nr_valid_blocks;
    dm_zftl->total_write_traffic_sec_ += dmz_blk2sect(copy_job->copy_buffer->nr_valid_blocks);
    dm_zftl->last_compact_traffic_ += copy_job->copy_buffer->nr_valid_blocks;
    spin_unlock_irqrestore(&dm_zftl->record_lock_, flags);

    dm_zftl_zns_try_gc(dm_zftl);
    dm_zftl_cache_try_reclaim(dm_zftl);
    dm_zftl_lsm_tree_try_compact(dm_zftl);
#if DM_ZFTL_L2P_PIN
    dm_zftl_unpin(cp_job->pin_work_ctx);
#endif

}

unsigned int dm_zftl_get_victim_greedy(struct zoned_dev * dev, struct dm_zftl_mapping_table * mapping_table){
    if(atomic_read(&dev->zoned_metadata->nr_full_zone) == 0)
        return 0;

    struct zone_link_entry * zone_link = NULL;
    struct zone_link_entry * selected_zone_link = NULL;

    int found = 0;
    int victim_id = 0;
    unsigned int min_victim_valid = dev->zone_nr_blocks;
    list_for_each_entry(zone_link, &dev->zoned_metadata->full_zoned, link){
        if(zone_link){
            found = 1;
            unsigned int valid_cnt = dm_zftl_zone_vaild_count(dev, zone_link->id, mapping_table);
            if(valid_cnt < min_victim_valid){
                selected_zone_link = zone_link;
                victim_id = zone_link->id;
                min_victim_valid = valid_cnt;
            }
        }
    }

    if(found){
        list_del(&selected_zone_link->link);
        atomic_dec(&dev->zoned_metadata->nr_full_zone);
    }

    return victim_id;
}

unsigned int dm_zftl_get_reclaim_zone(struct zoned_dev * dev, struct dm_zftl_mapping_table * mappping_table){
    int ret;
    unsigned int reclaim_zone_id = 0;
    if(dm_zftl_is_cache(dev)){

        struct zone_link_entry reclaim_zone;
        reclaim_zone_id = 0;
        int ret;
        ret = kfifo_out(&dev->write_fifo, &reclaim_zone, sizeof(struct zone_link_entry));
        if (!ret){
            reclaim_zone_id = 0;
            return 0;
        }

        reclaim_zone_id = reclaim_zone.id;
        atomic_dec(&dev->zoned_metadata->nr_full_zone);


    }else{

        reclaim_zone_id = dm_zftl_get_victim_greedy(dev, mappping_table);
        if(reclaim_zone_id)
            return reclaim_zone_id;

    }

#if DM_ZFTL_RECLAIM_DEBUG
    if(reclaim_zone_id){
        printk(KERN_EMERG "Reclaim zone => Device:%s Id:%llu Range: [%llu, %llu](blocks)"
                , dm_zftl_is_cache(dev) ? "Cache" : "ZNS"
                , reclaim_zone_id
                , reclaim_zone_id * dev->zone_nr_blocks
                , (reclaim_zone_id + 1) * dev->zone_nr_blocks);
        printk(KERN_EMERG "Remaing full zone:%d Remaing free zone:%d", atomic_read(&dev->zoned_metadata->nr_full_zone),
                                                                        atomic_read(&dev->zoned_metadata->nr_free_zone));
    }
#endif

    return reclaim_zone_id;
}

unsigned int dm_zftl_u8_count(uint8_t bitmap){
    unsigned int cnt = 0;
    while(bitmap){
        cnt++;
        bitmap &= (bitmap - 1);
    }
    return cnt;
}

unsigned int dm_zftl_zone_vaild_count(struct zoned_dev * dev, unsigned int zone_id, struct dm_zftl_mapping_table * mapping_table){
    unsigned int start_bm = dm_zftl_get_zone_start_vppn(dev, zone_id) / 8;
    unsigned int end_bm = start_bm + dev->zone_nr_blocks / 8;
    unsigned int i, cnt = 0;
    for(i = start_bm; i < end_bm; ++i){
        cnt += dm_zftl_u8_count(mapping_table->validate_bitmap[i]);
    }
    return cnt;
}
//自定义排序函数  从小到大排序
int dm_zftl_cmp_(const void *a,const void *b)
{
    unsigned int *da1 = (unsigned int *)a;
    unsigned int *da2 = (unsigned int *)b;
    if(*da1 > *da2)
        return 1;
    else if(*da1 < *da2)
        return -1;
    else
        return 0;
}

//自定义排序函数lpn  从小到大排序
int dm_zftl_p2l_cmp_(const void *a,const void *b)
{
    struct dm_zftl_p2l_info *da1 = (struct dm_zftl_p2l_info *)a;
    struct dm_zftl_p2l_info *da2 = (struct dm_zftl_p2l_info *)b;
    if(da1->lpn > da2->lpn)
        return 1;
    else if(da1->lpn < da2->lpn)
        return -1;
    else
        return 0;
}

sector_t dm_zftl_get_zone_start_vppn(struct zoned_dev * dev, unsigned int zone_id){
    if(zone_id > dev->nr_zones){
        printk(KERN_EMERG "Invalid zone id: Dev:%s Id:%llu",
                DM_ZFTL_DEV_STR(dev),
                zone_id);
        return DM_ZFTL_UNMAPPED_PPA;
    }
    return dmz_sect2blk((sector_t)dev->zoned_metadata->addr_offset + zone_id * dev->zone_nr_sectors);
}