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
#include <linux/kfifo.h>

#define KB 2 /* in sectors */
#define MB 1024 * KB
#define GB 1024 * MB

#define DM_ZFTL_VMA_COPY_TEST 0
#define DM_ZFTL_RECLAIM_ENABLE 1
#define DM_ZFTL_RECLAIM_THRESHOLD 10
#define DM_ZFTL_RECLAIM_INTERVAL 200 * MB
#define DM_ZFTL_RECLAIM_DEBUG 1
#define DM_ZFTL_RECLAIM_MAX_READ_NUM_DEFAULT 3

#define DM_ZFTL_DEV_STR(dev) dm_zftl_is_cache(dev) ? "Cache" : "ZNS"
#define DM_ZFTL_RECLAIM_PERIOD	(1 * HZ)
#define DM_ZFTL_FULL_THRESHOLD 0
#define DM_ZFTL_UNMAPPED_PPA 0
#define DM_ZFTL_UNMAPPED_LPA ~((unsigned int) 0)
#define DM_ZFTL_READ_SPLIT 1
#define DM_ZFTL_EXPOSE_TYPE BLK_ZONED_NONE
#define DM_ZFTL_MAPPING_DEBUG 0
#define DM_ZFTL_DEBUG 0
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

#define DM_ZFTL_FOREGROUND_DEV DM_ZFTL_CACHE
#define DM_ZFTL_BACKGROUND_DEV DM_ZFTL_BACKEND

enum {
    DMZAP_WR_OUTSTANDING,
};


struct dm_zftl_mapping_table{
    unsigned int l2p_table_sz; // in blocks
    uint32_t * l2p_table; // all unmapped lba will be mapped to 0 (which is metadata zoned)
    uint32_t * p2l_table;
    uint8_t * device_bitmap; // 0-> cache 1-> backedend 1B -> 4*8 = 32KB: 32MB/TB
    uint8_t * validate_bitmap;
    struct mutex l2p_lock;
};


//int dm_zftl_init_mapping_table(struct dm_zftl_target * dm_zftl);
//sector_t dm_zftl_get(struct dm_zftl_mapping_table * mapping_table, sector_t lba);
//int dm_zftl_set(struct dm_zftl_mapping_table * mapping_table, sector_t lba, sector_t ppa);
//int dm_zftl_update_mapping(struct dm_zftl_mapping_table * mapping_table, sector_t lba, sector_t ppa, unsigned int nr_blocks);
#if DM_ZFTL_READ_SPLIT
struct dm_zftl_read_io {
    struct bio * bio;
    unsigned int nr_io;
    unsigned int complete_io;
    unsigned int flag;
    spinlock_t lock_;
};
#endif

enum {
    DM_ZFTL_IO_COMPLETE,
    DM_ZFTL_IO_IN_PROG
};
struct dm_zftl_io_work{
    struct work_struct	work;
    struct bio * bio_ctx;
    struct dm_zftl_target * target;
    refcount_t		ref;
    sector_t		user_sec;
    int io_complete;
    spinlock_t lock_;
};

struct dm_zftl_reclaim_read_work{
    struct work_struct work;
    struct dm_zftl_target * target;
};



struct dm_zftl_target {
    unsigned int total_write_traffic_sec_;
    unsigned int last_write_traffic_;

    /* For cloned BIOs to conventional zones */
    struct bio_set		bio_set;
    struct dm_zftl_mapping_table *mapping_table;
    struct zoned_dev *cache_device;
    struct zoned_dev *zone_device;
    sector_t capacity_nr_sectors;
    struct workqueue_struct *io_wq;
    struct dm_io_client *io_client; /* Client memory pool*/
    struct copy_buffer *buffer;

    struct workqueue_struct *reclaim_read_wq;
    atomic_t nr_reclaim_work;
    atomic max_reclaim_read_work;
    struct workqueue_struct *reclaim_write_wq;
    struct workqueue_struct *gc_read_wq;
    struct workqueue_struct *gc_write_wq;



    struct dm_zftl_reclaim_read_work *reclaim_work;
};


#define dm_zftl_is_cache(dev) dev->flags == DM_ZFTL_CACHE
#define dm_zftl_is_zns(dev) dev->flags == DM_ZFTL_BACKEND
/*
 * Zone flags.
 */
enum {
    /* Zone critical condition */
    DM_ZFTL_BACKEND,
    DM_ZFTL_CACHE,
};

struct copy_buffer {
    void * buffer;
    unsigned int * lpn_buffer;
    unsigned int nr_blocks;
};

sector_t dm_zftl_get_dev_addr(struct dm_zftl_target * dm_zftl, sector_t ppa);
int dm_zftl_update_mapping_by_lpn_array(struct dm_zftl_mapping_table * mapping_table,unsigned int * lpn_array,sector_t ppn,unsigned int nr_block);
void dm_zftl_reclaim_read_work(struct work_struct *work);
unsigned int dm_zftl_get_reclaim_zone(struct zoned_dev * dev);
void * dm_zftl_init_copy_buffer(struct dm_zftl_target * dm_zftl);
void * dm_zftl_get_buffer_block_addr(struct dm_zftl_target * dm_zftl, unsigned int idx);
int dm_zftl_async_dm_io(unsigned int num_regions, struct dm_io_region *where, int rw, void *data, unsigned long *error_bits);
sector_t dm_zftl_get_zone_start_vppn(struct zoned_dev * dev, unsigned int zone_id);
int dm_zftl_ppn_is_valid(struct dm_zftl_mapping_table * mapping_table, sector_t ppn);
void dm_zftl_copy_read_cb(unsigned long error, void * context);


struct copy_job {
    unsigned int reclaim_zone_id;
    unsigned int nr_blocks;
    unsigned int nr_read_complete;
    int read_complete;
    struct zoned_dev * copy_from;
    struct zoned_dev * writeback_to;
    struct dm_zftl_target * dm_zftl;
    struct work_struct work;
    spinlock_t lock_;
};

int dm_zftl_valid_data_writeback(struct dm_zftl_target * dm_zftl, struct copy_job * job);
int dm_zftl_read_valid_zone_data_to_buffer(struct dm_zftl_target * dm_zftl, struct copy_job * cp_job, unsigned int zone_id);


struct zoned_dev {
    struct kfifo write_fifo;

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
    sector_t addr_offset;
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

int dm_zftl_init_bitmap(struct dm_zftl_target * dm_zftl);




struct zoned_dev * dm_zftl_get_background_io_dev(struct dm_zftl_target * dm_zftl);
struct zoned_dev * dm_zftl_get_foregound_io_dev(struct dm_zftl_target * dm_zftl);
sector_t dm_zftl_get_seq_wp(struct zoned_dev * dev, sector_t len);
int dm_zftl_open_new_zone(struct zoned_dev * dev);
int dm_zftl_reset_all(struct zoned_dev * dev);
int dm_zftl_reset_zone(struct zoned_dev * dev, struct zone_info *zone);
void dm_zftl_zone_close(struct zoned_dev * dev, unsigned int zone_id);
int dm_zftl_dm_io_read(struct dm_zftl_target *dm_zftl,struct bio *bio);
int dm_zftl_need_reclaim(struct dm_zftl_target * dm_zftl);
void dm_zftl_do_reclaim(struct work_struct *work);
void dm_zftl_try_reclaim(struct dm_zftl_target * dm_zftl);
//use delay_work => trigger write_back when reach threshold
//1) block all incoming write io & wait all current write io done
//2) copy valid data to zns
//3) update mapping
//4) unblock io
// p2l->mapping
// page_list->
//
unsigned int dm_zftl_get_ppa_zone_id(struct dm_zftl_target * dm_zftl, sector_t ppa);
struct zoned_dev * dm_zftl_get_ppa_dev(struct dm_zftl_target * dm_zftl, sector_t ppa);
void dm_zftl_write_back_(struct work_struct *work);
#endif //DM_ZFTL_DM_ZFTL_H
