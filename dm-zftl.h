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
#include <asm/atomic.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/pagemap.h>
#include <linux/random.h>
#include <linux/hardirq.h>
#include <linux/sysctl.h>
#include <linux/version.h>
#include <linux/pid.h>
#include <linux/jhash.h>


#define DM_ZFTL_WRITE_SPLIT 1
#define DM_ZFTL_EXPOSE_TYPE BLK_ZONED_NONE
#define DM_ZFTL_CLONE_BIO_SUBMITTED 0
#define DM_ZFTL_SPLIT_IO_NR_SECTORS 8
#define DM_REMAPPED 1
#define DM_ZFTL_MAPPING_DEBUG 0
#define DM_ZFTL_NO_MAPPING_TEST 0
#define DM_ZFTL_DEBUG 0
#define DM_ZFTL_DEBUG_WRITE 0
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
#define DM_ZFTL_ZONED_DEV_CAP_RATIO 0.8



enum {
    DMZAP_WR_OUTSTANDING,
};


struct dm_zftl_mapping_table{
    unsigned int l2p_table_sz; // in blocks
    uint32_t * l2p_table; // all unmapped lba will be mapped to 0 (which is metadata zoned)
    uint8_t * device_bitmap; // 0-> cache 1-> backedend 1B -> 4*8 = 32KB: 32MB/TB
    struct mutex l2p_lock;
};


//int dm_zftl_init_mapping_table(struct dm_zftl_target * dm_zftl);
//sector_t dm_zftl_get(struct dm_zftl_mapping_table * mapping_table, sector_t lba);
//int dm_zftl_set(struct dm_zftl_mapping_table * mapping_table, sector_t lba, sector_t ppa);
//int dm_zftl_update_mapping(struct dm_zftl_mapping_table * mapping_table, sector_t lba, sector_t ppa, unsigned int nr_blocks);
#if DM_ZFTL_WRITE_SPLIT
struct dm_zftl_read_io {
    struct bio * bio;
    unsigned int nr_io;
    unsigned int complete_io;
    unsigned int flag;
    spinlock_t lock_;
};
#endif


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
    struct dm_zftl_mapping_table *mapping_table;
    struct zoned_dev *cache_device;
    struct zoned_dev *zone_device;
    sector_t capacity_nr_sectors;
    struct workqueue_struct *io_wq;
    struct dm_io_client *io_client; /* Client memory pool*/
};

struct zoned_dev {

    struct block_device	*bdev;
    struct dm_dev * dmdev;
    struct dev_metadata *zoned_metadata;
    unsigned long		write_bitmap;

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
    spinlock_t lock_;
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
    spinlock_t lock_;
};

/*
 * Zone flags.
 */
enum {
    /* Zone critical condition */
    DMZ_OFFLINE,
    DMZ_READ_ONLY,
};

sector_t dm_zftl_get_seq_wp(struct zoned_dev * dev, struct bio * bio);
int dm_zftl_open_new_zone(struct zoned_dev * dev);
int dm_zftl_reset_all(struct zoned_dev * dev);
int dm_zftl_reset_zone(struct zoned_dev * dev, struct zone_info *zone);
void dm_zftl_zone_close(struct zoned_dev * dev, unsigned int zone_id);
int dm_zftl_dm_io_read(struct dm_zftl_target *dm_zftl,struct bio *bio);
#endif //DM_ZFTL_DM_ZFTL_H
