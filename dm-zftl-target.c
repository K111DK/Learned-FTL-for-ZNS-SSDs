//
// Created by root on 3/3/24.
//
#include "dm-zftl.h"
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/dm-io.h>
#include <linux/bio.h>
#include <linux/dm-ioctl.h>

int dm_zftl_init_mapping_table(struct dm_zftl_target * dm_zftl){
    dm_zftl->mapping_table = (struct dm_zftl_mapping_table *)vmalloc(sizeof(struct dm_zftl_mapping_table));
    mutex_init(&dm_zftl->mapping_table->l2p_lock);
    dm_zftl->mapping_table->l2p_table_sz = dmz_sect2blk(dm_zftl->capacity_nr_sectors);
    dm_zftl->mapping_table->l2p_table  = kvmalloc_array(dm_zftl->mapping_table->l2p_table_sz + 1000,
                                                        sizeof(uint32_t), GFP_KERNEL | __GFP_ZERO);
    dm_zftl->mapping_table->device_bitmap = kvmalloc_array( (dm_zftl->mapping_table->l2p_table_sz + 1000) / 8 + 1 ,
                                                            sizeof(uint8_t), GFP_KERNEL | __GFP_ZERO);
    int i;
#if DM_ZFTL_MAPPING_DEBUG
    printk(KERN_EMERG "Mapping table has %llu entrys (max sec: %llu)", dm_zftl->mapping_table->l2p_table_sz, dmz_blk2sect(dm_zftl->mapping_table->l2p_table_sz));
#endif
    for(i = 0; i < dm_zftl->mapping_table->l2p_table_sz + 1000; ++i){
        dm_zftl->mapping_table->l2p_table[i] = 0;
        dm_zftl->mapping_table->device_bitmap[ i / 8 ] &= ((uint8_t)(1) << (i % 8));
    }
    return 0;
}

sector_t dm_zftl_get(struct dm_zftl_mapping_table * mapping_table, sector_t lba){
    sector_t ppa;
//  TODO:buggy
//    if((unsigned int)lba > mapping_table->l2p_table_sz){
//        ppa = 0;
//    }
    int is_backend = mapping_table->device_bitmap[lba / 8] & ((uint8_t)(1) << (lba % 8));
    ppa = mapping_table->l2p_table[dmz_sect2blk(lba)];
    return dmz_blk2sect(ppa);
}


int dm_zftl_set(struct dm_zftl_mapping_table * mapping_table, sector_t lba, sector_t ppa){
    mapping_table->l2p_table[dmz_sect2blk(lba)] = dmz_sect2blk(ppa);
    return 0;
}


int dm_zftl_update_mapping(struct dm_zftl_mapping_table * mapping_table, sector_t lba, sector_t ppa, sector_t nr_blocks){
    int i;
#if DM_ZFTL_MAPPING_DEBUG
    printk(KERN_EMERG "Write: sec:(%llu => %llu) blk:(%llu => %llu)", lba, ppa, dmz_sect2blk(lba), dmz_sect2blk(ppa));
#endif
    for(i = 0; i < nr_blocks; ++i){
        dm_zftl_set(mapping_table, lba + (sector_t)i * dmz_blk2sect(1) , ppa + (sector_t)i * dmz_blk2sect(1));
    }
#if DM_ZFTL_MAPPING_DEBUG
    printk(KERN_EMERG "L2P Update: LPN:%llu ==> PPN:%llu [%llu blocks]",
           dmz_sect2blk(lba),
           dmz_sect2blk(ppa),
           nr_blocks);
#endif
    return 0;
}
sector_t dm_zftl_get_seq_wp_direct(struct zoned_dev * dev){
    struct zone_info * opened_zone = dev->zoned_metadata->opened_zoned;
    return opened_zone->wp + opened_zone->id * dev->zone_nr_sectors ;
}

sector_t dm_zftl_get_seq_wp(struct zoned_dev * dev, struct bio * bio){
    sector_t wp;
    int ret;
    unsigned int bio_len = bio_sectors(bio);
    struct zone_info * opened_zone = dev->zoned_metadata->opened_zoned;

    try_get_wp:

    if(opened_zone->wp + bio_len <= (unsigned int)dev->zone_nr_sectors){
        wp = opened_zone->wp + opened_zone->id * dev->zone_nr_sectors ;
        return wp;
    }

    dm_zftl_zone_close(dev, opened_zone->id);
    ret = dm_zftl_open_new_zone(dev);
    printk(KERN_EMERG "Get new zone of wp:%lld", dev->zoned_metadata->opened_zoned->wp);
    if(ret){
        printk(KERN_EMERG "Error: can't alloc free zone");
        return -1;
    }
    opened_zone = dev->zoned_metadata->opened_zoned;
    goto try_get_wp;

}


//*
// * Initialize the bio context
// */
//static inline void dm_zftl_init_bioctx(struct dm_zftl_target *dm_zftl,
//                                     struct bio *bio)
//{
//    struct dm_zftl_io_work *bioctx = dm_per_bio_data(bio, sizeof(struct dm_zftl_io_work));
//    bioctx->target = dm_zftl;
//    bioctx->user_sec = bio->bi_iter.bi_sector;
//    bioctx->bio_ctx = bio;
//    refcount_set(&bioctx->ref, 1);
//}

///*
// * Target BIO completion.
// */
//inline void dm_zftl_bio_endio(struct bio *bio, blk_status_t status)
//{
//    struct dm_zftl_io_work *bioctx = dm_per_bio_data(bio, sizeof(struct dm_zftl_io_work));
//    if (status != BLK_STS_OK && bio->bi_status == BLK_STS_OK)
//        bio->bi_status = status;
//    if (refcount_dec_and_test(&bioctx->ref)) {
//        bio_endio(bio);
//    }
//}




///*
// * Completion callback for an internally cloned target BIO. This terminates the
// * target BIO when there are no more references to its context.
// */
//static void dm_zftl_clone_endio(struct bio *bio)
//{
//    struct dm_zftl_io_work *bioctx = bio->bi_private;
//    blk_status_t status = bio->bi_status;
//
//    if (status != BLK_STS_OK && bio->bi_status == BLK_STS_OK)
//        bio->bi_status = status;
//
//    if (bio_data_dir(bio) == WRITE) {
//        struct zone_info * opened_zone = bioctx->target->cache_device->zoned_metadata->opened_zoned;
//        unsigned int bio_len = bio_sectors(bio);
//        dm_zftl_update_mapping(bioctx->target->mapping_table,
//                               bioctx->user_sec,//LPA
//                               dm_zftl_get_seq_wp(bioctx->target->cache_device, bio),
//                               dmz_bio_blocks(bio));
//#if DM_ZFTL_DEBUG_WRITE
//        printk(KERN_EMERG "Wp update from %llu to %llu", opened_zone->wp, opened_zone->wp + bio_len);
//#endif
//        opened_zone->wp += bio_len;
//    }
//    bio_endio(bio);
//}

//*
// * Issue a clone of a target BIO. The clone may only partially process the
// * original target BIO.
// */
//static int dm_zftl_submit_bio(struct dm_zftl_target *dm_zftl,
//                            sector_t sector, struct bio *bio)
//{
//    struct dm_zftl_io_work *bioctx = dm_per_bio_data(bio, sizeof(struct dm_zftl_io_work));
//    //All foreground write send to cache device
//    bio_set_dev(bio, dm_zftl->cache_device->bdev);
//
//#if DM_ZFTL_MAPPING_DEBUG
//    if(bio_op(bio) == WRITE)
//        printk(KERN_EMERG "%s: bio submit [%llu, %llu]", bio_op(bio) == WRITE ? "Write" : "Read" ,sector, sector + bio_sectors(bio));
//#endif
//
//    bio->bi_iter.bi_sector = sector;
//    bio->bi_end_io = dm_zftl_clone_endio;
//    bio->bi_private = bioctx;
//
//    submit_bio_noacct(bio);
//    return 0;
//}

void dm_zftl_dm_io_read_cb(unsigned long error, void * context){
    struct bio * bio =(struct bio *) context;
#if DM_ZFTL_MAPPING_DEBUG
    printk(KERN_EMERG "Read call back ");
#endif
    bio_endio(bio);
}

int dm_zftl_dm_io_read(struct dm_zftl_target *dm_zftl,struct bio *bio){
#if DM_ZFTL_NO_MAPPING_TEST
    zero_fill_bio(bio);
    bio_endio(bio);
    return DM_MAPIO_SUBMITTED;
#endif
    unsigned int nr_blocks = dmz_bio_blocks(bio);
    struct dm_io_region * where = kvmalloc_array(nr_blocks,
                                              sizeof(struct dm_io_region), GFP_KERNEL | __GFP_ZERO);
    int i, ret;
    sector_t start_sec = bio->bi_iter.bi_sector;
    sector_t ppa;
    sector_t original_ppa = dm_zftl_get(dm_zftl->mapping_table, start_sec);
    for(i = 0; i < nr_blocks; ++i){
        ppa = dm_zftl_get(dm_zftl->mapping_table, start_sec + dmz_blk2sect(i));
        where[i].bdev = dm_zftl->zone_device->bdev;
        where[i].sector = ppa;
        where[i].count = dmz_blk2sect(1);
        if(ppa == (sector_t) 0){
            //printk(KERN_EMERG "Unmapped IO %llu (%llu secs)", start_sec, dmz_bio_blocks(bio) * 8);
            goto RETURN_ZERO;
        }
    }

#if DM_ZFTL_MAPPING_DEBUG
    printk(KERN_EMERG "Submit read to bdev [%llu, %llu]", original_ppa, original_ppa + dmz_blk2sect(nr_blocks));
#endif

    struct dm_io_request iorq;

    iorq.bi_op = REQ_OP_READ;
    iorq.bi_op_flags = REQ_SYNC;
    iorq.mem.type = DM_IO_BIO;
    iorq.mem.ptr.bio = bio;
    iorq.notify.fn = dm_zftl_dm_io_read_cb;
    iorq.notify.context = bio;
    iorq.client = dm_zftl->io_client;

    return dm_io(&iorq, nr_blocks, where, NULL);


    RETURN_ZERO:
    zero_fill_bio(bio);
    bio_endio(bio);
    return DM_MAPIO_SUBMITTED;
}

void dm_zftl_dm_io_write_cb(unsigned long error, void * context){
    struct dm_zftl_io_work * io_work =(struct dm_zftl_io_work *) context;
    struct bio * bio = io_work->bio_ctx;
    struct dm_zftl_target * dm_zftl = io_work->target;
#if DM_ZFTL_MAPPING_DEBUG
    printk(KERN_EMERG "Write call back ");
#endif
    bio_endio(bio);
//    clear_bit_unlock(DMZAP_WR_OUTSTANDING, &dm_zftl->zone_device->write_bitmap);
}

int dm_zftl_dm_io_write(struct dm_zftl_target *dm_zftl, struct bio *bio){
//    while(test_and_set_bit_lock(DMZAP_WR_OUTSTANDING,
//                                &dm_zftl->zone_device->write_bitmap))
//        io_schedule();
    struct dm_io_region * where = kvmalloc_array(1, sizeof(struct dm_io_region), GFP_KERNEL | __GFP_ZERO);
    int i, ret;
    sector_t start_sec = bio->bi_iter.bi_sector;
    sector_t ppa;
    sector_t start_ppa = dm_zftl_get_seq_wp(dm_zftl->zone_device, bio);

    ppa = start_ppa;
    where->sector = ppa;
    where->bdev = dm_zftl->zone_device->bdev;
    where->count = dmz_blk2sect(dmz_bio_blocks(bio));
    dm_zftl_update_mapping(dm_zftl->mapping_table,
                           start_sec,
                           start_ppa,
                           dmz_bio_blocks(bio));

#if DM_ZFTL_MAPPING_DEBUG
    printk(KERN_EMERG "Submit write to bdev [%llu, %llu]", start_ppa, start_ppa + where->count);
#endif

    struct dm_io_request iorq;
    struct dm_zftl_io_work * context = (struct dm_zftl_io_work *)vmalloc(sizeof(struct dm_zftl_io_work));
    context->bio_ctx = bio;
    context->target = dm_zftl;
    iorq.bi_op = REQ_OP_WRITE;
    iorq.bi_op_flags = REQ_SYNC;
    iorq.mem.type = DM_IO_BIO;
    iorq.mem.ptr.bio = bio;
    iorq.notify.fn = dm_zftl_dm_io_write_cb;
    iorq.notify.context = context;
    iorq.client = dm_zftl->io_client;

    dm_zftl->zone_device->zoned_metadata->opened_zoned->wp += dmz_blk2sect(dmz_bio_blocks(bio));

    return dm_io(&iorq, 1, where, NULL);


    RETURN_ZERO:
    zero_fill_bio(bio);
    bio_endio(bio);
    return DM_MAPIO_SUBMITTED;


}


//int dm_zftl_read(struct dm_zftl_target *dm_zftl,struct bio *bio){
//    sector_t user = bio->bi_iter.bi_sector;
//    unsigned int size;
//    sector_t backing;
//    int mapped;
//    sector_t left = dmz_bio_blocks(bio);
//    int ret;
//#if DM_ZFTL_MAPPING_DEBUG
//    printk(KERN_EMERG "Handle read: [%llu, %llu]",user  ,user+left*8);
//#endif
//
//
//#if DM_ZFTL_NO_MAPPING_TEST
//        #if DM_ZFTL_DEBUG
//                printk(KERN_EMERG "Read: return dummy data");
//        #endif
//        zero_fill_bio(bio);
//#else
//
//    sector_t ppa;
//    while (left) {
//        ppa = dm_zftl_get(dm_zftl->mapping_table, bio->bi_iter.bi_sector);
//        size = 1 << DMZ_BLOCK_SHIFT;
//        if (ppa == 0){//UNMAPEED
//            swap(bio->bi_iter.bi_size, size);
//            zero_fill_bio(bio);
//            swap(bio->bi_iter.bi_size, size);
//        }else{
//            ret = dm_zftl_submit_bio(dm_zftl, ppa, bio);
//            if (ret)
//                return DM_MAPIO_KILL;
//        }
//        bio_advance(bio, size);
//        left -= 1;
//    }
//#endif
//
//    return DM_MAPIO_SUBMITTED;
//}



//int dm_zftl_write(struct dm_zftl_target *dm_zftl, struct bio *bio){
//    int ret;
//    /* We can only have one outstanding write at a time */
//    while(test_and_set_bit_lock(DMZAP_WR_OUTSTANDING,
//                                &dm_zftl->zone_device->write_bitmap))
//        io_schedule();
//    ret = dm_zftl_submit_bio(dm_zftl, dm_zftl_get_seq_wp(dm_zftl->cache_device, bio), bio);
//    if (ret) {
//        /* Out of memory, try again later */
//        clear_bit_unlock(DMZAP_WR_OUTSTANDING, &dm_zftl->zone_device->write_bitmap);
//        return ret;
//    }
//    return DM_MAPIO_SUBMITTED;
//}

/*
 * Handle IO
 * */
int dm_zftl_handle_bio(struct dm_zftl_target *dm_zftl,
                     struct dm_zftl_io_work *io, struct bio *bio){
    int ret;

//    if (dmzap->dev->flags & DMZ_BDEV_DYING) {
//        ret = -EIO;
//        goto out;
//    }

    if (!bio_sectors(bio)) {
        ret = DM_MAPIO_SUBMITTED;
        bio_endio(bio);
        goto out;
    }

    /*
     * Write may trigger a zone allocation. So make sure the
     * allocation can succeed.
     */
//    if (bio_op(bio) == REQ_OP_WRITE){
//        mutex_lock(&dmzap->reclaim_lock);
//        dmzap_schedule_reclaim(dmzap);
//        mutex_unlock(&dmzap->reclaim_lock);
//        dmzap->nr_user_written_sec += bio_sectors(bio);
//    }

    switch (bio_op(bio)) {
        case REQ_OP_READ:
            mutex_lock(&dm_zftl->mapping_table->l2p_lock);
            ret = dm_zftl_dm_io_read(dm_zftl, bio);
            mutex_unlock(&dm_zftl->mapping_table->l2p_lock);
            break;
        case REQ_OP_WRITE:
            mutex_lock(&dm_zftl->mapping_table->l2p_lock);
            ret = dm_zftl_dm_io_write(dm_zftl, bio);
            mutex_unlock(&dm_zftl->mapping_table->l2p_lock);
            break;
        case REQ_OP_DISCARD:
        case REQ_OP_WRITE_ZEROES:
            printk(KERN_EMERG "Discard operation triggered");
            ret = DM_MAPIO_SUBMITTED;
            break;
        default:
            printk(KERN_EMERG "Ignoring unsupported BIO operation 0x%x",
                        bio_op(bio));
            ret = -EIO;
    }

    out:
    return ret;
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
static int dm_zftl_queue_io(struct dm_zftl_target *dm_zftl, struct bio *bio){
//TODO:Queue io
/* Create a new chunk work */
    struct dm_zftl_io_work * io_work = kmalloc(sizeof(struct dm_zftl_io_work), GFP_NOIO);
    INIT_WORK(&io_work->work, dm_zftl_io_work_);
    io_work->bio_ctx = bio;
    io_work->target = dm_zftl;
    queue_work(dm_zftl->io_wq, &io_work->work);
    return 0;
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

#if DM_ZFTL_DEBUG
        printk(KERN_EMERG "Bio op:%s  Sector: [%llu,   %llu]    Block: [%llu,   %llu]",
            bio_op(bio) == READ ? "read" : "write",
            (unsigned long long)sector,
            (unsigned long long)(sector + nr_sectors),
            (unsigned long long)dmz_bio_block(bio),
            (unsigned long long)dmz_bio_blocks(bio) + dmz_bio_block(bio));
#endif

    if (!nr_sectors && bio_op(bio) != REQ_OP_WRITE)
        return DM_MAPIO_REMAPPED;


    /* The BIO should be block aligned */
    if ((nr_sectors & DMZ_BLOCK_SECTORS_MASK) || (sector & DMZ_BLOCK_SECTORS_MASK))
        return DM_MAPIO_KILL;

    /* Initialize the BIO context */
//    dm_zftl_init_bioctx(dm_zftl,bio);

//    /* Set the BIO pending in the flush list */
//    if (!nr_sectors && bio_op(bio) == REQ_OP_WRITE) {
//        spin_lock(&dmzap->flush_lock);
//        bio_list_add(&dmzap->flush_list, bio);
//        spin_unlock(&dmzap->flush_lock);
//        mod_delayed_work(dmzap->flush_wq, &dmzap->flush_work, 0);
//        return DM_MAPIO_SUBMITTED;
//    }

    /* Split zone BIOs to fit entirely into a zone TODO:Do we need this?? */
    zone_sector = sector & (dev->zone_nr_sectors - 1);
    if (zone_sector + nr_sectors > dev->zone_nr_sectors) {
#if DM_ZFTL_DEBUG
        printk(KERN_EMERG "Bio op %d    sector: [%llu,   %llu]    Bio Split!",
                bio_op(bio), (unsigned long long)sector, (unsigned long long)(sector + nr_sectors));
#endif
        dm_accept_partial_bio(bio, dev->zone_nr_sectors - zone_sector);
    }

    /* Now ready to handle this BIO */
    ret = dm_zftl_queue_io(dm_zftl, bio);
    ret = 0;
    if (ret) {
        printk(KERN_EMERG
                      "BIO op %d sector %llu + %u can't process\n",
                      bio_op(bio), (unsigned long long)sector, nr_sectors);
        return DM_MAPIO_REQUEUE;
    }

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


    struct request_queue *q;
    sector_t zone_nr_sectors = 0;

    q = bdev_get_queue(dmz->zone_device->bdev);
    zone_nr_sectors = blk_queue_zone_sectors(q);
    dmz->zone_device->zone_nr_sectors = zone_nr_sectors;
    dmz->zone_device->zone_nr_blocks = dmz_sect2blk(zone_nr_sectors);
    dmz->zone_device->nr_zones = blkdev_nr_zones(dmz->zone_device->bdev->bd_disk);

#if DM_ZFTL_DEBUG
    printk(KERN_EMERG "ZNS Device: Total zones:%d    Blocks per zone:%d    Sectors per zone:%d    Total Size(sectors):%d",
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
    bdev = ddev->bdev;
    dmz->cache_device->bdev = bdev;
    dmz->cache_device->capacity_nr_sectors = i_size_read(bdev->bd_inode) >> SECTOR_SHIFT;
    dmz->cache_device->zone_nr_sectors = zone_nr_sectors;
    dmz->cache_device->zone_nr_blocks = dmz_sect2blk(zone_nr_sectors);
    dmz->cache_device->nr_zones = dmz->cache_device->capacity_nr_sectors / dmz->cache_device->zone_nr_sectors;
    dmz->capacity_nr_sectors = dmz->zone_device->nr_zones * zone_nr_sectors;


#if DM_ZFTL_DEBUG
    printk(KERN_EMERG "Cache Device: Total zones:%d    Blocks per zone:%d    Sectors per zone:%d    Total Size(sectors):%d",
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
    printk(KERN_EMERG "Total size: %d", zftl->zone_device->nr_zones * sizeof(struct zone_info));
    zoned_device_metadata->zones = kvmalloc_array(zftl->zone_device->nr_zones,
                                                  sizeof(struct zone_info), GFP_KERNEL | __GFP_ZERO);
    if (!zoned_device_metadata->zones) {
        printk(KERN_EMERG "Unable to alloc memory");
    }

    struct zone_link_entry * zone_link;
    INIT_LIST_HEAD(&zoned_device_metadata->free_zoned);
    INIT_LIST_HEAD(&zoned_device_metadata->full_zoned);
    INIT_LIST_HEAD(&zoned_device_metadata->open_zoned);
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
    //TODO: first zone of cache device is metadata zone, which is't vaild for mapping
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

    limits->logical_block_size = DMZ_BLOCK_SIZE;
    limits->physical_block_size = DMZ_BLOCK_SIZE;

    blk_limits_io_min(limits, DMZ_BLOCK_SIZE);
    blk_limits_io_opt(limits, DMZ_BLOCK_SIZE);

    limits->discard_alignment = DMZ_BLOCK_SIZE;
    limits->discard_granularity = DMZ_BLOCK_SIZE;
    limits->max_discard_sectors = dm_zftl->zone_device->zone_nr_sectors;
    limits->max_hw_discard_sectors = dm_zftl->zone_device->zone_nr_sectors;
    limits->max_write_zeroes_sectors = dm_zftl->zone_device->zone_nr_sectors;

    /* FS hint to try to align to the device zone size */
    limits->chunk_sectors = dm_zftl->zone_device->zone_nr_sectors;
    limits->max_sectors = dm_zftl->zone_device->zone_nr_sectors;

    /* We are exposing a drive-managed zoned block device */
    limits->zoned = BLK_ZONED_NONE;
}

void dm_zftl_mapping_table_test(struct dm_zftl_target *dm_zftl){
    printk(KERN_EMERG "Start mapping test....");
    struct dm_zftl_mapping_table * l2p = dm_zftl->mapping_table;
    sector_t l2p_sz = l2p->l2p_table_sz;
    sector_t start_sec = 0;
    unsigned int nr_blocks = 1000;
    dm_zftl_update_mapping(l2p, start_sec, dm_zftl_get_seq_wp_direct(dm_zftl->cache_device), nr_blocks);
    printk(KERN_EMERG "start_sec:%llu  wp:%llu  secs:%llu",start_sec ,dm_zftl_get_seq_wp_direct(dm_zftl->cache_device), dmz_blk2sect(nr_blocks));
    unsigned int i;
    sector_t ret;
    for(i = 0; i < nr_blocks; ++i ){
        ret = dm_zftl_get(l2p, start_sec + i * dmz_blk2sect(i));
        printk(KERN_EMERG "sec:%llu => sec:%llu",start_sec + i * dmz_blk2sect(i), ret);
    }
    printk(KERN_EMERG "End mapping test....");
    return;
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
    dmz->io_client = dm_io_client_create();

    dmz->io_wq = alloc_workqueue("dm_zftl_wq", WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
    if (!dmz->io_wq) {
        ti->error = "Create io workqueue failed";
        ret = -ENOMEM;
        goto err_dev;
    }

    /* Set target (no write same support) */
    ti->max_io_len = DM_ZFTL_SPLIT_IO_NR_SECTORS;
    ti->num_flush_bios = 1;
    ti->num_discard_bios = 1;
    ti->num_write_zeroes_bios = 1;
    ti->per_io_data_size = sizeof(struct dm_zftl_io_work);
    ti->flush_supported = true;
    ti->discards_supported = false;
    /* The exposed capacity is the number of chunks that can be mapped */
    ti->len = dmz->capacity_nr_sectors;

    printk(KERN_EMERG "last block(4k) %llu", dmz_sect2blk(dmz->capacity_nr_sectors) - 1);

    //dm_zftl_mapping_table_test(dmz);


    return 0;
    err_map:
    err_meta:
    err_dev:
    return -1;
}



static struct target_type dm_zftl_type = {
        .name		 = "zftl",
        .version	 = {1, 0, 0},
        .features	 = DM_TARGET_SINGLETON | DM_TARGET_MIXED_ZONED_MODEL,
        .module		 = THIS_MODULE,
        .ctr		 = dm_zftl_ctr,
        .dtr		 = dm_zftl_dtr,
        .map		 = dm_zftl_map,
        .io_hints	 = dm_zftl_io_hints,

};

static int __init dm_zftl_init(void)
{
    return dm_register_target(&dm_zftl_type);
}

static void __exit dm_zftl_exit(void)
{
    dm_unregister_target(&dm_zftl_type);
}


//static inline void dm_zftl_bio_end_wr(struct bio *bio,
//                                      blk_status_t status)
//{
//    struct dm_zftl_io_work *bioctx = dm_per_bio_data(bio, sizeof(struct dm_zftl_io_work));
//    struct dm_zftl_target *dm_zftl = bioctx->target;
//
//    if (bio->bi_status != BLK_STS_OK) {
//        /* TODO: stop writing to zone
//         *  (or writing altogether) on
//         *  failed writes
//         */
//        printk(KERN_EMERG "Write failed! bi_status %d", bio->bi_status);
//
//    } else {
//        int ret;
//
////TODO: mapping update
//
//        dm_zftl_update_seq_wp(dm_zftl, bio_sectors(bio));
//    }
//
//    clear_bit_unlock(DMZAP_WR_OUTSTANDING, &dm_zftl->zone_device->write_bitmap);
//}




int dm_zftl_open_new_zone(struct zoned_dev * dev){
    struct zone_link_entry *zone_link;
    list_for_each_entry(zone_link, &dev->zoned_metadata->free_zoned, link){
        if(zone_link)
            break;
    }
    if(!zone_link)
        return 1;
    list_del(&zone_link->link);
    atomic_dec(&dev->zoned_metadata->nr_free_zone);
    dev->zoned_metadata->opened_zoned = &dev->zoned_metadata->zones[zone_link->id];
#if DM_ZFTL_DEBUG_WRITE
    printk(KERN_EMERG "Open new zone");
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
#if DM_ZFTL_DEBUG
    printk(KERN_EMERG "Reset zone %u complete!",
            zone->id);
#endif
    return 0;
}

void dm_zftl_zone_close(struct zoned_dev * dev, unsigned int zone_id){
    struct zone_link_entry *zone_link = kzalloc(sizeof(struct  zone_link_entry), GFP_KERNEL);
    zone_link->id = zone_id;
    list_add(&zone_link->link, &dev->zoned_metadata->full_zoned);
    dev->zoned_metadata->opened_zoned = NULL;
}





module_init(dm_zftl_init);
module_exit(dm_zftl_exit);

MODULE_DESCRIPTION(DM_NAME " an host-based ftl for zoned block device");
MODULE_AUTHOR("Xin Huang <hx2002@mail.ustc.edu.cn>");
MODULE_LICENSE("GPL");


