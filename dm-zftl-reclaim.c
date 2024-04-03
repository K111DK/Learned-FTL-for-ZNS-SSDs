//
// Created by root on 3/14/24.
//
#include "dm-zftl.h"
#include <linux/sort.h>
#define BLOCK_4K_SIZE 4096
#define COPY_BUFFER_SIZE 65536


void dm_zftl_try_reclaim(struct dm_zftl_target * dm_zftl){
    if(dm_zftl_need_reclaim(dm_zftl)){

        printk(KERN_EMERG "Trigger reclaim");
        atomic_inc(&dm_zftl->nr_reclaim_work);

        struct dm_zftl_reclaim_read_work * read_work = kmalloc(sizeof(struct dm_zftl_reclaim_read_work), GFP_NOIO);
        INIT_WORK(&read_work->work, dm_zftl_do_foreground_reclaim);
        read_work->target = dm_zftl;
        queue_work(dm_zftl->reclaim_read_wq, &read_work->work);

    }
}

int dm_zftl_need_reclaim(struct dm_zftl_target * dm_zftl){
    if(atomic_read(&dm_zftl->nr_reclaim_work) >= atomic_read(&dm_zftl->max_reclaim_read_work))
        return 0;

    if(dm_zftl->last_write_traffic_ >= DM_ZFTL_RECLAIM_INTERVAL
        && DM_ZFTL_RECLAIM_ENABLE){
        dm_zftl->last_write_traffic_ = 0;
        return 1;
    }

    return 0;
}


void dm_zftl_do_foreground_reclaim(struct work_struct *work){
    struct dm_zftl_reclaim_read_work * read_work = container_of(work, struct dm_zftl_reclaim_read_work, work);
    struct dm_zftl_target * dm_zftl = read_work->target;

    struct copy_job * cp_job = vmalloc(sizeof (struct copy_job));
    cp_job->dm_zftl = dm_zftl;
    cp_job->copy_from = dm_zftl->cache_device;
    cp_job->writeback_to = dm_zftl->zone_device;
    spin_lock_init(&cp_job->lock_);

    mutex_lock(&dm_zftl->mapping_table->l2p_lock);
    int ret;
    unsigned int reclaim_zone_id = dm_zftl_get_reclaim_zone(cp_job->copy_from);

    cp_job->reclaim_zone_id = reclaim_zone_id;

    if(!reclaim_zone_id){
        goto OUT;
    }
    ret = dm_zftl_read_valid_zone_data_to_buffer(
            dm_zftl,
            cp_job,
            reclaim_zone_id
    );

    if(ret){
        printk(KERN_EMERG "Reclaim fail!");
        goto OUT;
    }
    return;

    OUT:
    mutex_unlock(&dm_zftl->mapping_table->l2p_lock);
}


struct zoned_dev * dm_zftl_get_background_io_dev(struct dm_zftl_target * dm_zftl){
    return dm_zftl->zone_device;
}


//自定义排序函数  从小到大排序
static int dm_zftl_cmp_(const void *a,const void *b)
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
    struct dm_zftl_target* dm_zftl = (struct dm_zftl_target *)context;
    mutex_unlock(&dm_zftl->mapping_table->l2p_lock);
}


int dm_zftl_valid_data_writeback(struct dm_zftl_target * dm_zftl, struct copy_job * job){
    unsigned int nr_blocks = job->nr_blocks;
    struct zoned_dev * dev = job->writeback_to;
    sector_t nr_sectors = dmz_blk2sect(job->nr_blocks);
    struct dm_io_region * where = (struct dm_io_region *)vmalloc(sizeof (struct dm_io_region));
    sector_t start_ppa = dm_zftl_get_seq_wp(dev, nr_sectors);

    //    if(start_ppa == DM_ZFTL_UNMAPPED_PPA){
    //        ret = -EIO;
    //        goto FINISH;
    //    }

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


    dm_zftl_update_mapping_by_lpn_array(dm_zftl->mapping_table,
                                        dm_zftl->buffer->lpn_buffer,
                                        dmz_sect2blk(start_ppa),
                                        job->nr_blocks);

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
    iorq.notify.fn = NULL;
    iorq.notify.context = NULL;
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
    //dm_zftl_reset_zone(job->copy_from, reclaim_zone);
    job->writeback_to->zoned_metadata->opened_zoned->wp += nr_sectors;
    job->copy_from->zoned_metadata->zones[reclaim_zone->id].wp = 0;

    struct zone_link_entry * zone_link = (struct zone_link_entry *)vmalloc(sizeof (struct zone_link_entry));
    zone_link->id = reclaim_zone->id;
    list_add(&zone_link->link, &dev->zoned_metadata->free_zoned);
    atomic_inc(&dev->zoned_metadata->nr_free_zone);

    atomic_dec(&dm_zftl->nr_reclaim_work);

    dm_zftl_valid_data_writeback_cb(0, (void *)dm_zftl);
    return 1;
}


int dm_zftl_read_valid_zone_data_to_buffer(struct dm_zftl_target * dm_zftl, struct copy_job * cp_job, unsigned int zone_id){

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


#if DM_ZFTL_RECLAIM_DEBUG
    printk(KERN_EMERG "[Reclaim][Read] dev:%s zone:%llu, Validate [ %llu / %llu ]",
            DM_ZFTL_DEV_STR(cp_job->copy_from),
            cp_job->reclaim_zone_id,
            current_lpn_buffer_idx,
            cp_job->copy_from->zone_nr_blocks);
#endif


    struct dm_io_region * where = kvmalloc_array(current_lpn_buffer_idx,
                                                 sizeof(struct dm_io_region), GFP_KERNEL | __GFP_ZERO);


    unsigned int nr_read_io = current_lpn_buffer_idx;
    unsigned int lpn, error_bits;
    int ret;

    for(i = 0; i < nr_read_io; ++i) {

        lpn = dm_zftl->buffer->lpn_buffer[i];

        where[i].bdev = dev->bdev;
        where[i].sector = dm_zftl_get_dev_addr(dm_zftl, dmz_blk2sect(mapping_table->l2p_table[lpn]));
        where[i].count = dmz_blk2sect(1);


        struct dm_io_request iorq;
        iorq.bi_op = REQ_OP_READ;
        iorq.bi_op_flags = 0;
        iorq.mem.type = DM_IO_VMA;
        iorq.mem.ptr.vma = dm_zftl_get_buffer_block_addr(dm_zftl, i);
        iorq.notify.fn = dm_zftl_copy_read_cb;
        iorq.notify.context = cp_job;
        iorq.client = dm_zftl->io_client;

        ret = dm_io(&iorq, 1, &where[i], error_bits);
    }



    DONE:
    return 0;

    SORT_ERROR:
    printk(KERN_EMERG "Sort error");
    return 1;
}

unsigned int dm_zftl_get_reclaim_zone(struct zoned_dev * dev){
    if(dm_zftl_is_cache(dev)){
        struct zone_link_entry reclaim_zone;
        unsigned int reclaim_zone_id = 0;
        int ret;
        ret = kfifo_out(dev->write_fifo, &reclaim_zone, sizeof(struct zone_link_entry));
        if (!ret){
#if DM_ZFTL_DEBUG
            printk(KERN_EMERG "Device:%s have not full zone"
            , dm_zftl_is_cache(dev) ? "Cache" : "ZNS");
#endif
            reclaim_zone_id = 0;
            return 0;
        }

        reclaim_zone_id = reclaim_zone.id;
        atomic_dec(&dev->zoned_metadata->nr_full_zone);
#if DM_ZFTL_RECLAIM_DEBUG
        printk(KERN_EMERG "Reclaim zone => Device:%s Id:%llu Range: [%llu, %llu](blocks)"
            , dm_zftl_is_cache(dev) ? "Cache" : "ZNS"
            , reclaim_zone_id
            , reclaim_zone_id * dev->zone_nr_blocks
            , (reclaim_zone_id + 1) * dev->zone_nr_blocks);
    printk(KERN_EMERG "Remaing full zone:%d", atomic_read(&dev->zoned_metadata->nr_full_zone));
#endif
        return reclaim_zone_id;
    }

//    if(atomic_read(&dev->zoned_metadata->nr_full_zone) == 0) {
//#if DM_ZFTL_DEBUG
//        printk(KERN_EMERG "Device:%s have not full zone"
//            , dm_zftl_is_cache(dev) ? "Cache" : "ZNS");
//#endif
//        return 0;
//    }
//    struct zone_link_entry *zone_link = NULL;
//    list_for_each_entry(zone_link, &dev->zoned_metadata->full_zoned, link){
//        if(zone_link)
//            goto FOUND;
//
//    }
//    return 0;
//
//    FOUND:
//    list_del(&zone_link->link);
//    atomic_dec(&dev->zoned_metadata->nr_full_zone);
//    //TODO:Is this neccesary?
//    dev->zoned_metadata->opened_zoned = &dev->zoned_metadata->zones[zone_link->id];
//#if DM_ZFTL_DEBUG
//    printk(KERN_EMERG "Reclaim zone => Device:%s Id:%llu Range: [%llu, %llu](blocks)"
//            , dm_zftl_is_cache(dev) ? "Cache" : "ZNS"
//            , zone_link->id
//            , zone_link->id * dev->zone_nr_blocks
//            , (zone_link->id + 1) * dev->zone_nr_blocks);
//    printk(KERN_EMERG "Remaing full zone:%d", atomic_read(&dev->zoned_metadata->nr_full_zone));
//#endif
//    return zone_link->id;
    return 0;
}