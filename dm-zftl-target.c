//
// Created by root on 3/3/24.
//
#include "dm-zftl.h"
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
/*
 * Process a new BIO.
 */
static int dm_zftl_map(struct dm_target *ti, struct bio *bio)
{
    return DM_MAPIO_KILL;
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
    printk(KERN_EMERG "ZNS Device: Total zones:%d    Blocks per zone:%d    Sectors per zone:%d    Total Size(sectors):%d",
                                                dmz->zone_device->nr_zones,
                                                dmz->zone_device->zone_nr_blocks,
                                                zone_nr_sectors,
                                                dmz->zone_device->capacity_nr_sectors);



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
    dmz->capacity_nr_sectors = (dmz->cache_device->nr_zones + dmz->zone_device->nr_zones) * zone_nr_sectors;
    printk(KERN_EMERG "Cache Device: Total zones:%d    Blocks per zone:%d    Sectors per zone:%d    Total Size(sectors):%d",
            dmz->cache_device->nr_zones,
            dmz->cache_device->zone_nr_blocks,
            zone_nr_sectors,
            dmz->cache_device->capacity_nr_sectors);


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
        zoned_device_metadata->zones[i].wp_block = 0;
        zoned_device_metadata->zones[i].id = i;
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
    for(i = 0; i < zftl->cache_device->nr_zones; ++i){
        cache_device_metadata->zones[i].dev = zftl->cache_device;
        atomic_set(&cache_device_metadata->zones[i].refcount, 0);
        cache_device_metadata->zones[i].wp_block = 0;
        cache_device_metadata->zones[i].id = i;
        zone_link = (struct zone_link_entry *)vmalloc(sizeof (struct zone_link_entry));
        zone_link->id = i;
        list_add(&zone_link->link, &cache_device_metadata->free_zoned);
    }
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
    limits->max_discard_sectors = dm_zftl->capacity_nr_sectors;
    limits->max_hw_discard_sectors = dm_zftl->capacity_nr_sectors;
    limits->max_write_zeroes_sectors = dm_zftl->capacity_nr_sectors;

    /* FS hint to try to align to the device zone size */
    limits->chunk_sectors = dm_zftl->capacity_nr_sectors;
    limits->max_sectors = dm_zftl->capacity_nr_sectors;

    /* We are exposing a drive-managed zoned block device */
    limits->zoned = BLK_ZONED_NONE;
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

    ti->private = dmz;

    ret = dm_zftl_load_device(ti, argv);
    ret = dm_zftl_geometry_init(ti);

    /* Set target (no write same support) */
    ti->max_io_len = DMZ_BLOCK_SIZE;
    ti->num_flush_bios = 1;
    ti->num_discard_bios = 1;
    ti->num_write_zeroes_bios = 1;
    ti->per_io_data_size = DMZ_BLOCK_SIZE;
    ti->flush_supported = true;
    ti->discards_supported = true;
    /* The exposed capacity is the number of chunks that can be mapped */
    ti->len = dmz->capacity_nr_sectors;


    return 0;
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

module_init(dm_zftl_init);
module_exit(dm_zftl_exit);

MODULE_DESCRIPTION(DM_NAME " an host-based ftl for zoned block device");
MODULE_AUTHOR("Xin Huang <hx2002@mail.ustc.edu.cn>");
MODULE_LICENSE("GPL");


