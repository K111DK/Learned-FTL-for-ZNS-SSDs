//
// Created by root on 3/4/24.
//

#ifndef DM_ZFTL_DM_ZFTL_H
#define DM_ZFTL_DM_ZFTL_H

#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/device-mapper.h>
#include <linux/dm-kcopyd.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>
#include <linux/radix-tree.h>
#include <linux/shrinker.h>


#define BDEVNAME_SIZE 256
/*
 * Creates block devices with 4KB blocks, always.
 * copy from dm-zoned
 */
#define DMZ_BLOCK_SHIFT		12
#define DMZ_BLOCK_SIZE		(1 << DMZ_BLOCK_SHIFT)
#define DMZ_BLOCK_MASK		(DMZ_BLOCK_SIZE - 1)

#define DMZ_BLOCK_SHIFT_BITS	(DMZ_BLOCK_SHIFT + 3)
#define DMZ_BLOCK_SIZE_BITS	(1 << DMZ_BLOCK_SHIFT_BITS)
#define DMZ_BLOCK_MASK_BITS	(DMZ_BLOCK_SIZE_BITS - 1)

#define DMZ_BLOCK_SECTORS_SHIFT	(DMZ_BLOCK_SHIFT - SECTOR_SHIFT)
#define DMZ_BLOCK_SECTORS	(DMZ_BLOCK_SIZE >> SECTOR_SHIFT)
#define DMZ_BLOCK_SECTORS_MASK	(DMZ_BLOCK_SECTORS - 1)

/*
 * 4KB block <-> 512B sector conversion.
 */
#define dmz_blk2sect(b)		((sector_t)(b) << DMZ_BLOCK_SECTORS_SHIFT)
#define dmz_sect2blk(s)		((sector_t)(s) >> DMZ_BLOCK_SECTORS_SHIFT)

#define dmz_bio_block(bio)	dmz_sect2blk((bio)->bi_iter.bi_sector)
#define dmz_bio_blocks(bio)	dmz_sect2blk(bio_sectors(bio))

struct dm_zftl_target {
    struct zoned_dev *cache_device;
    struct zoned_dev *zone_device;
    sector_t capacity_nr_sectors;
};

struct zoned_dev {

    struct block_device	*bdev;
    struct dev_metadata *zoned_metadata;

    char			name[BDEVNAME_SIZE];
    uuid_t			uuid;
    unsigned int	flags;

    sector_t		capacity_nr_sectors; // sector
    unsigned int	nr_zones;
    sector_t		zone_nr_sectors;
    unsigned int    zone_nr_blocks;
};

struct dev_metadata {
    /* Zone information array */
    struct zone_info * zones;
    atomic_t nr_open_zone;
    struct list_head open_zoned;
    atomic_t nr_free_zone;
    struct list_head free_zoned;
    atomic_t nr_full_zone;
    struct list_head full_zoned;
};

struct zone_link_entry {
    struct list_head link;
    unsigned int id;
};

struct zone_info {
    /* Device containing this zone */
    struct zoned_dev		*dev;
    /* Zone type and state */
    unsigned long		flags;
    /* Zone activation reference count */
    atomic_t		refcount;
    /* Zone id */
    unsigned int		id;
    /* Zone write pointer block (relative to the zone start block) */
    unsigned int		wp_block;
};

/*
 * Zone flags.
 */
enum {
    /* Zone critical condition */
    DMZ_OFFLINE,
    DMZ_READ_ONLY,
};

#endif //DM_ZFTL_DM_ZFTL_H
