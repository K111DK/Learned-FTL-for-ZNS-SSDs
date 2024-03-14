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
#define DM_ZFTL_NO_MAPPING_TEST 1
#define DM_ZFTL_DEBUG 0
#define DM_ZFTL_DEBUG_WRITE 1
#define DM_ZFTL_MIN_BIOS 8192
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
enum {
    DMZAP_WR_OUTSTANDING,
};


struct dm_zftl_mapping_table{
    unsigned int l2p_table_sz;
    sector_t * l2p_table;
};


struct dm_zftl_io_work{
    struct work_struct	work;
    struct bio * bio_ctx;
    struct dm_zftl_target * target;
    refcount_t		ref;
    sector_t		user_sec;
};

struct dm_zftl_target {
    /* For cloned BIOs to conventional zones */
    struct bio_set		bio_set;
    unsigned long		write_bitmap;
    struct dm_zftl_mapping_table *mapping_table;
    struct zoned_dev *cache_device;
    struct zoned_dev *zone_device;
    sector_t capacity_nr_sectors;
    struct workqueue_struct *io_wq;
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
    struct zone_info * opened_zoned;
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
    /* Zone write pointer sector (relative to the zone start block) */
    unsigned int		wp;

    spinlock_t * lock_;
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
