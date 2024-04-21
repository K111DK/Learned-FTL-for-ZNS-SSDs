//
// Created by root on 3/4/24.
//

#ifndef DM_ZFTL_DM_ZFTL_H
#define DM_ZFTL_DM_ZFTL_H
#include "dm-zftl-leaftl.h"
#include "dm-zftl-utils.h"

#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/device-mapper.h>
#include <linux/dm-kcopyd.h>
#include <linux/list.h>

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
#include <linux/kernel.h>

#define KB 2 /* in sectors */
#define MB 1024 * KB
#define GB 1024 * MB
#define DM_ZFTL_PIN_DEBUG 0
#define DM_ZFTL_VMA_COPY_TEST 0
#define DM_ZFTL_RECLAIM_ENABLE 1
#define DM_ZFTL_RECLAIM_THRESHOLD 10
#define DM_ZFTL_RECLAIM_INTERVAL 200 * MB
#define DM_ZFTL_RECLAIM_DEBUG 0
#define DM_ZFTL_RECLAIM_MAX_READ_NUM_DEFAULT 1

#define DM_ZFTL_DEV_STR(dev) dm_zftl_is_cache(dev) ? "Cache" : "ZNS"
#define DM_ZFTL_RECLAIM_PERIOD	(1 * HZ)
#define DM_ZFTL_FULL_THRESHOLD 0
#define DM_ZFTL_UNMAPPED_PPA 0 // First n zone is used as metadata zone
#define DM_ZFTL_UNMAPPED_LPA ~((unsigned int) 0) // [ 0,  MAX_UINT - 1 ]
#define DM_ZFTL_READ_SPLIT 1
#define DM_ZFTL_EXPOSE_TYPE BLK_ZONED_NONE
#define DM_ZFTL_MAPPING_DEBUG 0
#define DM_ZFTL_DEBUG 0
#define DM_ZFTL_MIN_BIOS 8192
#define BDEVNAME_SIZE 256
#define DM_ZFTL_COMPACT_ENABLE 1
#define DM_ZFTL_COMPACT_INTERVAL 2000000 //50 * 4MB = 200MB
/*
 * Creates block devices with 4KB blocks, always.
 * copy from dm-zoned
 */
#define DM_ZFTL_L2P_PIN 1
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

#define DM_ZFTL_ZNS_GC_WATERMARK_PERCENTILE 30
#define DM_ZFTL_FOREGROUND_DEV DM_ZFTL_CACHE
#define DM_ZFTL_BACKGROUND_DEV DM_ZFTL_BACKEND
#define DM_ZFTL_USING_LEA_FTL 1


enum {
    DMZAP_WR_OUTSTANDING,
};

enum{
    DM_ZFTL_P2L_READ_OUTSTANDING,
};


struct dm_zftl_mapping_table{
    struct lsm_tree * lsm_tree;
    struct dm_zftl_target * dm_zftl;
    unsigned int l2p_table_sz; // in blocks
    uint32_t * l2p_table; // all unmapped lba will be mapped to 0 (which is metadata zoned)
    uint32_t * p2l_table;
    uint8_t * device_bitmap; // 0-> cache 1-> backedend 1B -> 4*8 = 32KB: 32MB/TB
    uint8_t * validate_bitmap;
    struct mutex l2p_lock;
    struct dm_zftl_l2p_mem_pool * l2p_cache;
    unsigned long p2l_check_bitmap;
};

unsigned int dm_zftl_l2p_get(struct dm_zftl_mapping_table * mapping_table, unsigned int lpn);
int dm_zftl_lpn_is_in_cache(struct dm_zftl_mapping_table * mapping_table, sector_t lpn);
void dm_zftl_lpn_set_dev(struct dm_zftl_mapping_table * mapping_table, unsigned int lpn, int dev);
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
    struct l2p_pin_work * pin_work_ctx;
    refcount_t		ref;
    sector_t		user_sec;
    int io_complete;
    spinlock_t lock_;

    void (* pin_cb_fn)(void * context);
    void * pin_cb_ctx;
};

struct dm_zftl_reclaim_read_work{
    struct work_struct work;
    struct dm_zftl_target * target;
};

struct dm_zftl_compact_work{
    struct work_struct work;
    struct dm_zftl_target * target;
};

struct dm_zftl_l2p_frame{
    TAILQ_ENTRY(dm_zftl_l2p_frame) list_entry;
    unsigned int frame_no;
    int state;
    atomic_t on_lru_list;
    atomic_t ref_count;
    spinlock_t _lock;
};

struct dm_zftl_l2p_mem_pool{
    struct mutex mutex_lock;
    struct dm_zftl_l2p_frame ** l2f_table;// l2p page ->  dataframe+
    unsigned int max_frame;
    unsigned int lbns_in_frame;// n of lpn in a l2p frame (4B * 1024)
    unsigned int maxium_l2p_size;// in bytes
    unsigned int current_size;// in bytes
    spinlock_t _lock;
    TAILQ_HEAD(_frame_list, dm_zftl_l2p_frame) _frame_list;
    unsigned int * GTD;
    uint8_t * frame_access_cnt;
    //    struct fooq q;
//    TAILQ_INIT(&q);
//	  if (!TAILQ_EMPTY(&dev->rd_sq)) {
//		  io = TAILQ_FIRST(&dev->rd_sq);
//		  TAILQ_REMOVE(&dev->rd_sq, io, queue_entry);
};


struct dm_zftl_target {

    void * dummy_l2p_buffer;

    spinlock_t record_lock_;
    unsigned int cache_2_zns_reclaim_write_traffic_;
    unsigned int cache_2_zns_reclaim_read_traffic_;

    // cache/zns(include gc) wriite traffic (4KB)
    unsigned int zns_write_traffic_; // in 4K blocks = foregound reclaim + gc write io
    unsigned int cache_write_traffic_; // in 4K blocks = foregound write io

    // foreground R io traffic (4KB)
    unsigned int foreground_read_traffic_;
    // foreground W io traffic (4KB)
    unsigned int foreground_write_traffic_;


    unsigned int foreground_reclaim_cnt_;
    unsigned int background_reclaim_cnt_;

    //unused
    unsigned int total_write_traffic_sec_;

    // traffic since last gc
    unsigned int last_write_traffic_;

    // lsm tree traffic since last compact
    unsigned int last_compact_traffic_;




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
    atomic_t max_reclaim_read_work;
    struct workqueue_struct *reclaim_write_wq;
    struct workqueue_struct *gc_read_wq;
    struct workqueue_struct *gc_write_wq;

    struct workqueue_struct *lsm_tree_compact_wq;


    struct workqueue_struct *l2p_pin_wq;
    struct workqueue_struct *l2p_page_out_wq;
    struct workqueue_struct *l2p_try_pin_wq;

    struct dm_zftl_l2p_mem_pool *l2p_mem_pool;

    struct workqueue_struct *io_kick_off_wq;
    struct workqueue_struct *get_mapping_wq;


    struct dm_zftl_reclaim_read_work *reclaim_work;
};
struct try_l2p_pin {

    struct work_struct work;
    struct dm_zftl_target * dm_zftl;
    struct io_job * io_job;

};
struct get_mapping_work{
    struct work_struct work;
    unsigned int lpn;
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
void dm_zftl_do_background_reclaim(struct work_struct *work);
void dm_zftl_do_foreground_reclaim(struct work_struct *work);
void dm_zftl_do_reclaim(struct work_struct *work, struct zoned_dev *reclaim_from, struct zoned_dev *copy_to);
sector_t dm_zftl_get_dev_addr(struct dm_zftl_target * dm_zftl, sector_t ppa);
int dm_zftl_update_mapping_by_lpn_array(struct dm_zftl_mapping_table * mapping_table,unsigned int * lpn_array,sector_t ppn,unsigned int nr_block);
void dm_zftl_reclaim_read_work(struct work_struct *work);
unsigned int dm_zftl_get_reclaim_zone(struct zoned_dev * dev, struct dm_zftl_mapping_table * mappping_table);
void * dm_zftl_init_copy_buffer(struct dm_zftl_target * dm_zftl);
void * dm_zftl_get_buffer_block_addr(struct dm_zftl_target * dm_zftl, unsigned int idx);
int dm_zftl_async_dm_io(unsigned int num_regions, struct dm_io_region *where, int rw, void *data, unsigned long *error_bits);
sector_t dm_zftl_get_zone_start_vppn(struct zoned_dev * dev, unsigned int zone_id);
int dm_zftl_ppn_is_valid(struct dm_zftl_mapping_table * mapping_table, sector_t ppn);
void dm_zftl_copy_read_cb(unsigned long error, void * context);
int dm_zftl_update_mapping_cache(struct dm_zftl_mapping_table * mapping_table, sector_t lba, sector_t ppa, sector_t nr_blocks);
struct copy_job {
    struct l2p_pin_work * pin_work_ctx;
    unsigned int reclaim_zone_id;
    unsigned int nr_blocks;
    unsigned int nr_read_complete;
    int read_complete;
    struct zoned_dev * copy_from;
    struct zoned_dev * writeback_to;
    struct dm_zftl_target * dm_zftl;
    struct work_struct work;

    unsigned int * cp_lpn_array;
    unsigned int nr_read_io;
    unsigned int lpn_start_idx;// [start, end)

    void (* pin_cb_fn)(void * context);
    void * pin_cb_ctx;
    void (* unpin_fn)(void * context);
    void * unpin_ctx;

    spinlock_t lock_;
};

int dm_zftl_valid_data_writeback(struct dm_zftl_target * dm_zftl, struct copy_job * job);
void dm_zftl_read_valid_zone_data_to_buffer(void * context);


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



void dm_zftl_foreground_reclaim(struct dm_zftl_target * dm_zftl);
struct zoned_dev * dm_zftl_get_background_io_dev(struct dm_zftl_target * dm_zftl);
struct zoned_dev * dm_zftl_get_foregound_io_dev(struct dm_zftl_target * dm_zftl);
sector_t dm_zftl_get_seq_wp(struct zoned_dev * dev, sector_t len);
int dm_zftl_open_new_zone(struct zoned_dev * dev);
int dm_zftl_reset_all(struct zoned_dev * dev);
int dm_zftl_reset_zone(struct zoned_dev * dev, struct zone_info *zone);
void dm_zftl_zone_close(struct zoned_dev * dev, unsigned int zone_id);
int dm_zftl_dm_io_read(struct dm_zftl_target *dm_zftl,struct bio *bio);
int dm_zftl_need_reclaim(struct dm_zftl_target * dm_zftl);
void dm_zftl_cache_try_reclaim(struct dm_zftl_target * dm_zftl);
void dm_zftl_zns_try_gc(struct dm_zftl_target * dm_zftl);
//use delay_work => trigger write_back when reach threshold
//1) block all incoming write io & wait all current write io done
//2) copy valid data to zns
//3) update mappings
//4) unblock io
// p2l->mapping
// page_list->
//
unsigned int dm_zftl_get_ppa_zone_id(struct dm_zftl_target * dm_zftl, sector_t ppa);
struct zoned_dev * dm_zftl_get_ppa_dev(struct dm_zftl_target * dm_zftl, sector_t ppa);
void dm_zftl_write_back_(struct work_struct *work);
void dm_zftl_compact_work(struct work_struct *work);
void dm_zftl_lsm_tree_try_compact(struct dm_zftl_target * dm_zftl);
int dm_zftl_need_gc(struct dm_zftl_target * dm_zftl);




void dm_zftl_l2p_set_init(struct dm_zftl_target * dm_zftl);

enum {
    CP_JOB,
    IO_WORK
};

struct io_job{
    union {
        struct copy_job * cp_job;
        struct dm_zftl_io_work * io_work;
    };
    int flags;
    struct l2p_pin_work * pin_work;
};

struct frame_no_node {
    TAILQ_ENTRY(frame_no_node) list_entry;
    unsigned int frame_no;
};

struct l2p_pin_work{
    struct dm_zftl_target * dm_zftl;
    struct work_struct work;

    struct io_job * io_job;

    int total_l2p_page;
    unsigned int wanted_free_space;
    atomic_t pinned_cnt;
    atomic_t deferred_cnt;
    int deferred_count;
    int pinned_count;
    TAILQ_HEAD(_pinned_list, frame_no_node) _pinned_list;
    TAILQ_HEAD(_deferred_pin_list, frame_no_node) _deferred_pin_list;
};
enum {
    READY,// this frame is in DRAM
    IN_PROC, // this frame is being loading
    INIT, // this frame no in DRAM, and no other io is loading it
    FLUSHING, //
    TRY,
    ON_DISK,
    ON_DRAM
};
struct l2p_page_in_work{
    struct work_struct work;
    struct l2p_pin_work * pin_work;
    struct dm_zftl_l2p_frame * frame;
};

struct l2p_page_out_work{
    struct work_struct work;
    struct dm_zftl_l2p_mem_pool * l2p_cache;
    struct dm_zftl_l2p_frame * frame;
    struct dm_zftl_target * dm_zftl;
    int page_out_cnt;
};

struct l2p_pin_complete_work{
    struct work_struct work;
    struct l2p_pin_work * pin_work_ctx;
};
void dm_zftl_unpin(struct l2p_pin_work * pin_work_ctx);
struct dm_zftl_l2p_frame * dm_zftl_create_new_frame(unsigned int frame_no);
int dm_zftl_is_pin_complete(struct l2p_pin_work * pin_ctx);
void dm_zftl_try_l2p_pin(struct work_struct * work);
void dm_zftl_l2p_pin_complete(struct work_struct * work);
int dm_zftl_queue_l2p_pin_io(struct l2p_pin_work * pin_work_ctx);
void dm_zftl_do_l2p_pin_io(struct work_struct *work);
void dm_zftl_l2p_pin_io_cb(unsigned long error, void * context);
void dm_zftl_pin_frame(struct dm_zftl_l2p_mem_pool * l2p_cache, struct dm_zftl_l2p_frame * frame);
void dm_zftl_unpin_frame(struct dm_zftl_l2p_mem_pool * l2p_cache, struct dm_zftl_l2p_frame * frame);
void dm_zftl_del_from_lru(struct dm_zftl_l2p_mem_pool * l2p_cache, struct dm_zftl_l2p_frame * frame);
void dm_zftl_add_to_lru(struct dm_zftl_l2p_mem_pool * l2p_cache, struct dm_zftl_l2p_frame * frame);
void dm_zftl_l2p_promote(struct dm_zftl_l2p_mem_pool * l2p_cache, struct dm_zftl_l2p_frame * frame);
struct dm_zftl_l2p_frame * framedm_zftl_l2p_evict(struct dm_zftl_l2p_mem_pool * l2p_cache);
void dm_zftl_l2p_put(struct dm_zftl_l2p_mem_pool * l2p_cache, struct dm_zftl_l2p_frame * frame);
struct dm_zftl_l2p_frame * dm_zftl_l2p_coldest(struct dm_zftl_l2p_mem_pool * l2p_cache);
int dm_zftl_init_mapping_table(struct dm_zftl_target * dm_zftl);
sector_t dm_zftl_get(struct dm_zftl_mapping_table * mapping_table, sector_t lba);
void dm_zftl_queue_io(void * context);

void dm_zftl_invalidate_ppn(struct dm_zftl_mapping_table * mapping_table, sector_t ppn);
void dm_zftl_validate_ppn(struct dm_zftl_mapping_table * mapping_table, sector_t ppn);
void dm_zftl_l2p_evict_cb(unsigned long error, void * context);
void dm_zftl_do_evict(struct work_struct *work);
unsigned int dm_zftl_sftl_get_size(struct dm_zftl_mapping_table * mapping_table);
void dm_zftl_try_evict(struct dm_zftl_target * dm_zftl, struct dm_zftl_l2p_mem_pool * l2p_cache);
struct dm_zftl_io_work * dm_zftl_get_io_work(struct dm_zftl_target *dm_zftl, struct bio *bio);
int dm_zftl_cmp_(const void *a,const void *b);
int dm_zftl_get_sorted_vaild_lpn(struct copy_job * cp_job);
struct l2p_pin_work * dm_zftl_init_pin_ctx(struct dm_zftl_target * dm_zftl, struct io_job * io_job);
void lsm_tree_frame_status_check(struct lsm_tree * tree, status_type_t type,
                                 unsigned int status_flags, char *result,
                                 unsigned int maxlen);
#define DM_ZFTL_PAGE_SIZE (4096)// in bytes


#endif //DM_ZFTL_DM_ZFTL_H
