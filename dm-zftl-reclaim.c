//
// Created by root on 3/14/24.
//
#include "dm-zftl.h"
#include <linux/sort.h>
#define BLOCK_4K_SIZE 4096
#define COPY_BUFFER_SIZE 65536


void dm_zftl_lsm_tree_try_compact(struct dm_zftl_target * dm_zftl){
    if((dm_zftl->last_compact_traffic_ >= DM_ZFTL_COMPACT_INTERVAL) && DM_ZFTL_COMPACT_ENABLE){

#if DM_ZFTL_COMPACT_DEBUG
        printk(KERN_EMERG "[Compact] Trigger Compact");
#endif

        dm_zftl->last_compact_traffic_ = 0;
        struct dm_zftl_compact_work * _work = kmalloc(sizeof(struct dm_zftl_compact_work), GFP_NOIO);
        _work->target = dm_zftl;
        INIT_WORK(&_work->work, dm_zftl_compact_work);
        queue_work(dm_zftl->lsm_tree_compact_wq, &_work->work);
    }

}

void dm_zftl_compact_work(struct work_struct *work){
    struct dm_zftl_compact_work * _work = container_of(work, struct dm_zftl_compact_work, work);
    struct dm_zftl_target * dm_zftl = _work->target;
    lsm_tree_compact(dm_zftl->mapping_table->lsm_tree);
}

void dm_zftl_zns_try_gc(struct dm_zftl_target * dm_zftl){
    if(dm_zftl_need_gc(dm_zftl)){
        atomic_inc(&dm_zftl->nr_reclaim_work);
        struct dm_zftl_reclaim_read_work * read_work = kmalloc(sizeof(struct dm_zftl_reclaim_read_work), GFP_NOIO);
        INIT_WORK(&read_work->work, dm_zftl_do_background_reclaim);
        read_work->target = dm_zftl;
        queue_work(dm_zftl->reclaim_read_wq, &read_work->work);
    }
}

int dm_zftl_need_gc(struct dm_zftl_target * dm_zftl){
    if(atomic_read(&dm_zftl->nr_reclaim_work) >= atomic_read(&dm_zftl->max_reclaim_read_work))
        return 0;
    if(atomic_read(&dm_zftl->zone_device->zoned_metadata->nr_full_zone) * DM_ZFTL_ZNS_GC_WATERMARK_PERCENTILE >=
            atomic_read(&dm_zftl->zone_device->zoned_metadata->nr_free_zone) * (100 - DM_ZFTL_ZNS_GC_WATERMARK_PERCENTILE)){
        return 1;
    }
    return 0;
}

void dm_zftl_cache_try_reclaim(struct dm_zftl_target * dm_zftl){
    if(dm_zftl_need_reclaim(dm_zftl)){
        dm_zftl_foreground_reclaim(dm_zftl);
    }
}

void dm_zftl_foreground_reclaim(struct dm_zftl_target * dm_zftl){
    //printk(KERN_EMERG "Trigger reclaim");
    atomic_inc(&dm_zftl->nr_reclaim_work);

    struct dm_zftl_reclaim_read_work * read_work = kmalloc(sizeof(struct dm_zftl_reclaim_read_work), GFP_NOIO);
    INIT_WORK(&read_work->work, dm_zftl_do_foreground_reclaim);
    read_work->target = dm_zftl;
    queue_work(dm_zftl->reclaim_read_wq, &read_work->work);
}

int dm_zftl_need_reclaim(struct dm_zftl_target * dm_zftl){
    if(atomic_read(&dm_zftl->nr_reclaim_work) >= atomic_read(&dm_zftl->max_reclaim_read_work))
        return 0;
    if(     (
                dm_zftl->last_write_traffic_ >= DM_ZFTL_RECLAIM_INTERVAL ||
                atomic_read(&dm_zftl->cache_device->zoned_metadata->nr_free_zone) <= 5
            )
            && DM_ZFTL_RECLAIM_ENABLE){
        dm_zftl->last_write_traffic_ = 0;
        return 1;
    }
    return 0;
}

void dm_zftl_do_background_reclaim(struct work_struct *work){
    struct dm_zftl_reclaim_read_work * read_work = container_of(work, struct dm_zftl_reclaim_read_work, work);
    struct dm_zftl_target * dm_zftl = read_work->target;
    dm_zftl_do_reclaim(work, dm_zftl->zone_device, dm_zftl->zone_device);
}

void dm_zftl_do_foreground_reclaim(struct work_struct *work){
    struct dm_zftl_reclaim_read_work * read_work = container_of(work, struct dm_zftl_reclaim_read_work, work);
    struct dm_zftl_target * dm_zftl = read_work->target;
    dm_zftl_do_reclaim(work, dm_zftl->cache_device, dm_zftl->zone_device);
}

int dm_zftl_get_sorted_vaild_lpn(struct copy_job * cp_job){
    struct dm_zftl_target * dm_zftl = cp_job->dm_zftl;
    unsigned int zone_id = cp_job->reclaim_zone_id;
    struct zoned_dev * dev = cp_job->copy_from;
    unsigned int start_ppn = dm_zftl_get_zone_start_vppn(dev, zone_id);
    struct dm_zftl_mapping_table * mapping_table = dm_zftl->mapping_table;
    if(start_ppn == DM_ZFTL_UNMAPPED_PPA){
        printk(KERN_EMERG "Unable to reclaim invalid zone id");
        return 1;
    }
    unsigned int end_ppn = start_ppn + dev->zone_nr_blocks;
    unsigned int i;
    unsigned int current_lpn_buffer_idx = 0;
    unsigned int lp;

    //Find all vaild blocks in reclaim zone
    for(i = start_ppn; i < end_ppn; ++i){

        if(dm_zftl_ppn_is_valid(mapping_table, i)){
            lp = mapping_table->p2l_table[i];
            if(lp == DM_ZFTL_UNMAPPED_LPA){
                printk(KERN_EMERG "Unmapped LPA");
                return 1;
            }

            dm_zftl->buffer->lpn_buffer[current_lpn_buffer_idx] = lp;
            current_lpn_buffer_idx++;
        }

    }

    //no vaild blocks TODO:?
    if(current_lpn_buffer_idx == 0)
        return 0;

    // sort lpn ascend order
    sort(dm_zftl->buffer->lpn_buffer,
         current_lpn_buffer_idx,
         sizeof(unsigned int),
         dm_zftl_cmp_,
         NULL);


    //Maybe error? Check lpn order & corresponding ppn correct
    int pre_lpn = -1;
    for(i = 0; i < current_lpn_buffer_idx; ++i){
        if(((int)dm_zftl->buffer->lpn_buffer[i] > pre_lpn) &&
           mapping_table->l2p_table[dm_zftl->buffer->lpn_buffer[i]] < end_ppn &&
           mapping_table->l2p_table[dm_zftl->buffer->lpn_buffer[i]] >= start_ppn
                ){
            pre_lpn = (int)dm_zftl->buffer->lpn_buffer[i];
        }else{
            goto SORT_ERROR;
        }
    }


    cp_job->nr_blocks = current_lpn_buffer_idx;
    cp_job->nr_read_complete = 0;
    cp_job->read_complete = 0;
    cp_job->lpn_start_idx = 0;
    cp_job->nr_read_io = current_lpn_buffer_idx;
    cp_job->cp_lpn_array = dm_zftl->buffer->lpn_buffer;
#if DM_ZFTL_RECLAIM_DEBUG
    printk(KERN_EMERG "[Reclaim] sort done!");
#endif

    return 0;

    SORT_ERROR:
    return 1;
}

void dm_zftl_do_reclaim(struct work_struct *work, struct zoned_dev *reclaim_from, struct zoned_dev *copy_to){

    struct dm_zftl_reclaim_read_work * read_work = container_of(work, struct dm_zftl_reclaim_read_work, work);
    struct dm_zftl_target * dm_zftl = read_work->target;

    struct copy_job * cp_job = vmalloc(sizeof (struct copy_job));
    cp_job->dm_zftl = dm_zftl;
    cp_job->copy_from = reclaim_from;
    cp_job->writeback_to = copy_to;


    spin_lock_init(&cp_job->lock_);
    mutex_lock(&dm_zftl->mapping_table->l2p_lock);

    unsigned int reclaim_zone_id = dm_zftl_get_reclaim_zone(cp_job->copy_from, dm_zftl->mapping_table);
    cp_job->reclaim_zone_id = reclaim_zone_id;

    if(!reclaim_zone_id)
        goto ERR_OUT;

    if(dm_zftl_get_sorted_vaild_lpn(cp_job))
        goto ERR_OUT;



    cp_job->pin_cb_fn = dm_zftl_read_valid_zone_data_to_buffer;
    cp_job->pin_cb_ctx = (void *)cp_job;
    struct io_job * io_job = kmalloc(sizeof(struct io_job), GFP_NOIO);
    io_job->cp_job = cp_job;
    io_job->flags = CP_JOB;

#if DM_ZFTL_L2P_PIN
    dm_zftl_try_l2p_pin(dm_zftl, io_job);
#else
    cp_job->pin_cb_fn(cp_job->pin_cb_ctx);
#endif

    return;

    ERR_OUT:
    printk(KERN_EMERG "Reclaim fail!");
    return;
}

struct zoned_dev * dm_zftl_get_background_io_dev(struct dm_zftl_target * dm_zftl){
    return dm_zftl->zone_device;
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

void * dm_zftl_init_copy_buffer(struct dm_zftl_target * dm_zftl){
    dm_zftl->buffer = (struct copy_buffer *)vmalloc(sizeof (struct copy_buffer));
    dm_zftl->buffer->buffer = vmalloc(BLOCK_4K_SIZE * COPY_BUFFER_SIZE);

    if(dm_zftl->buffer->buffer == NULL){
        kfree(dm_zftl->buffer->buffer);
        printk(KERN_EMERG "Can't alloc copy buffer");
        return 1;
    }

    dm_zftl->buffer->lpn_buffer = vmalloc(sizeof (unsigned int) * COPY_BUFFER_SIZE);
    if(dm_zftl->buffer->lpn_buffer == NULL){
        kfree(dm_zftl->buffer->lpn_buffer);
        printk(KERN_EMERG "Can't alloc lpn buffer");
        return 1;
    }

    dm_zftl->buffer->nr_blocks = COPY_BUFFER_SIZE;
    return 0;
}

void * dm_zftl_get_buffer_block_addr(struct dm_zftl_target * dm_zftl, unsigned int idx){
    unsigned int max = dm_zftl->buffer->nr_blocks;
    char * p = (char *)dm_zftl->buffer->buffer;
    if(idx < max){
        return (void *)(p + BLOCK_4K_SIZE * idx);
    }
    return NULL;
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

void dm_zftl_copy_read_cb(unsigned long error, void * context){
    struct copy_job * job =(struct copy_job *) context;
    unsigned int flag;

    spin_lock_irqsave(&job->lock_, flag);

    job->nr_read_complete += 1;
    if(job->nr_read_complete == job->nr_blocks){
        job->read_complete = 1;
    }

    spin_unlock_irqrestore(&job->lock_, flag);

    if(job->read_complete){
        // Trigger write
#if DM_ZFTL_RECLAIM_DEBUG
        printk(KERN_EMERG "[Reclaim][Read complete] dev:%s zone:%llu,start write back",
            DM_ZFTL_DEV_STR(job->copy_from),
            job->reclaim_zone_id
        );
#endif

        INIT_WORK(&job->work, dm_zftl_write_back_);
        //once all vaild block read to VMA, kick off write
        queue_work(job->dm_zftl->reclaim_write_wq, &job->work);
    }
}

void dm_zftl_write_back_(struct work_struct *work){
    struct copy_job * job = container_of(work, struct copy_job, work);
    dm_zftl_valid_data_writeback(job->dm_zftl, job);
}


void dm_zftl_valid_data_writeback_cb(unsigned long error, void * context){
    struct copy_job * cp_job = context;
    struct dm_zftl_target * dm_zftl = cp_job->dm_zftl;
    clear_bit_unlock(DMZAP_WR_OUTSTANDING, &dm_zftl->zone_device->write_bitmap);
    mutex_unlock(&dm_zftl->mapping_table->l2p_lock);
#if DM_ZFTL_L2P_PIN
    dm_zftl_unpin(cp_job->pin_work_ctx);
#endif

}


int dm_zftl_valid_data_writeback(struct dm_zftl_target * dm_zftl, struct copy_job * job){
    unsigned int nr_blocks = job->nr_blocks;
    struct zoned_dev * dev = job->writeback_to;
    sector_t nr_sectors = dmz_blk2sect(job->nr_blocks);
    struct dm_io_region * where = (struct dm_io_region *)vmalloc(sizeof (struct dm_io_region));
    sector_t start_ppa = dm_zftl_get_seq_wp(dev, nr_sectors);

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
            DM_ZFTL_DEV_STR(job->copy_from),
            job->reclaim_zone_id,
            DM_ZFTL_DEV_STR(dm_zftl_get_ppa_dev(dm_zftl, start_ppa)),
            dev->zoned_metadata->opened_zoned->id,
            dev->zoned_metadata->opened_zoned->wp
    );

#endif

    struct zone_info * reclaim_zone = &job->copy_from->zoned_metadata->zones[job->reclaim_zone_id];

    sector_t ppa;
    ppa = start_ppa;
    where->sector = dm_zftl_get_dev_addr(dm_zftl, ppa);
    where->bdev = dev->bdev;
    where->count = nr_sectors;


    //TODO:change mapping
    dm_zftl_update_mapping_by_lpn_array(dm_zftl->mapping_table,
                                        dm_zftl->buffer->lpn_buffer,
                                        dmz_sect2blk(start_ppa),
                                        job->nr_blocks);

    //we can do unpin now



#if DM_ZFTL_RECLAIM_DEBUG
    printk(KERN_EMERG "[Reclaim][Write back] mapping update done");
#endif

    int ret;
    unsigned long error_bits;
    struct dm_io_request iorq;

    iorq.bi_op = REQ_OP_WRITE;
    iorq.bi_op_flags = 0;
    iorq.mem.type = DM_IO_VMA;
    iorq.mem.ptr.vma = dm_zftl_get_buffer_block_addr(dm_zftl, 0);
    iorq.notify.fn = dm_zftl_valid_data_writeback_cb;
    iorq.notify.context = job;
    iorq.client = dm_zftl->io_client;

    ret = dm_io(&iorq, 1, where, error_bits);


    unsigned int i;
    for(i = 0; i < nr_blocks ; ++i){
        dm_zftl->buffer->lpn_buffer[i] = 0;
    }

#if DM_ZFTL_RECLAIM_DEBUG
    printk(KERN_EMERG "[Reclaim Done] dev:%s zone:%llu",DM_ZFTL_DEV_STR(job->copy_from), job->reclaim_zone_id);
#endif

    //TODO:Fix metadata update and zone reset
    dm_zftl_reset_zone(job->copy_from, reclaim_zone);

    unsigned long flags;

    spin_lock_irqsave(&job->writeback_to->zoned_metadata->opened_zoned->lock_, flags);
    job->writeback_to->zoned_metadata->opened_zoned->wp += nr_sectors;
    spin_unlock_irqrestore(&job->writeback_to->zoned_metadata->opened_zoned->lock_, flags);


    atomic_dec(&dm_zftl->nr_reclaim_work);

    spin_lock_irqsave(&dm_zftl->record_lock_, flags);
    dm_zftl->cache_2_zns_reclaim_write_traffic_ += job->nr_blocks;
    dm_zftl->last_compact_traffic_ += job->nr_blocks;
    spin_unlock_irqrestore(&dm_zftl->record_lock_, flags);

    dm_zftl_lsm_tree_try_compact(dm_zftl);

    return 1;
}


void dm_zftl_read_valid_zone_data_to_buffer(void * context){


    struct copy_job * cp_job = context;

#if DM_ZFTL_RECLAIM_DEBUG
    printk(KERN_EMERG "[Reclaim][Read] dev:%s zone:%llu, Validate [ %llu / %llu ]",
            DM_ZFTL_DEV_STR(cp_job->copy_from),
            cp_job->reclaim_zone_id,
            cp_job->nr_read_io,
            cp_job->copy_from->zone_nr_blocks);
#endif

    struct dm_io_region * where = kvmalloc_array(cp_job->nr_read_io,
                                                 sizeof(struct dm_io_region), GFP_KERNEL | __GFP_ZERO);


    unsigned int nr_read_io = cp_job->nr_read_io;
    unsigned int lpn, error_bits;
    int ret;
    unsigned int i;

    for(i = cp_job->lpn_start_idx; i < cp_job->lpn_start_idx + nr_read_io; ++i) {

        lpn = cp_job->cp_lpn_array[i];

        where[i].bdev = cp_job->copy_from->bdev;
        where[i].sector = dm_zftl_get_dev_addr(cp_job->dm_zftl,
                                               dmz_blk2sect(cp_job->dm_zftl->mapping_table->l2p_table[lpn]));
        where[i].count = dmz_blk2sect(1);


        struct dm_io_request iorq;
        iorq.bi_op = REQ_OP_READ;
        iorq.bi_op_flags = 0;
        iorq.mem.type = DM_IO_VMA;
        iorq.mem.ptr.vma = dm_zftl_get_buffer_block_addr(cp_job->dm_zftl, i);
        iorq.notify.fn = dm_zftl_copy_read_cb;
        iorq.notify.context = cp_job;
        iorq.client = cp_job->dm_zftl->io_client;

        ret = dm_io(&iorq, 1, &where[i], error_bits);
    }

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

unsigned int dm_zftl_get_victim_greedy(struct zoned_dev * dev, struct dm_zftl_mapping_table * mapping_table){
    if(atomic_read(&dev->zoned_metadata->nr_full_zone) == 0)
        return 0;

    struct zone_link_entry *zone_link = NULL;

    int found = 0;
    int victim_id = 0;
    unsigned int min_victim_valid = dev->zone_nr_blocks;
    list_for_each_entry(zone_link, &dev->zoned_metadata->full_zoned, link){
        if(zone_link){
            found = 1;
            unsigned int valid_cnt = dm_zftl_zone_vaild_count(dev, zone_link->id, mapping_table);
            if(valid_cnt < min_victim_valid){
                victim_id = zone_link->id;
                min_victim_valid = valid_cnt;
            }
        }
    }

    if(found){
        list_del(&zone_link->link);
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