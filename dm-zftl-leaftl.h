//
// Created by root on 3/25/24.
//
#pragma once
#include "dm-zftl.h"
#include <asm/atomic.h>
#ifndef LEAFTL_DM_ZFTL_LEAFTL_H
#define LEAFTL_DM_ZFTL_LEAFTL_H
#define DM_ZFTL_LEA_DEBUG 1
#define DM_ZFTL_ZNS_GC_THRESHOLD 20
#define seg_end(seg) (seg->start_lpn + seg->len)
#define seg_start(seg) (seg->start_lpn)
#define DM_ZFTL_LEA_ORIGIN 1
#define ERROR_BOUND 0
#define DM_ZFTL_COMPACT_WITH_PROMOTE 1
#define DM_ZFTL_DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define ASSETR_UINT_EQ(eq1, eq2, test_name)     do {if(eq1 != eq2) \
                                                        printk("Test %s error: Expected:%u Got:%u\n", test_name, eq1, eq2); \
                                                    else                \
                                                        printk("Test %s pass: Expected:%u Got:%u\n", test_name, eq1, eq2);} while(0)
#if DM_ZFTL_LEA_DEBUG
#define DM_ZFTL_LOOK_UP_HIST_LEN 150


enum {
    SAME_LEVEL = 0,
    PUSH_DOWN = 1,
    DEL_SEG = 2
};

#define MALLOC(size) kvmalloc(size, GFP_NOIO)
#define FREE(mem) kvfree(mem)
#define MALLOC_ARRAY(num, size) kvmalloc_array(num, size, GFP_KERNEL | __GFP_ZERO)
#define DM_ZFTL_FRAME_LENGTH 256
#define DM_ZFTL_FRAME_LENGTH_BITS (DM_ZFTL_FRAME_LENGTH / 8)
#define DM_ZFTL_SEG_STRING(seg) ""
#define DM_ZFTL_FP_EMU  1
#define DM_ZFTL_COMPACT_DEBUG 0
#endif
extern enum {
    FULLY_COVER,
    PARTIAL_COVER,
    UNCOVER
} MERGE_STATE;

typedef struct frac_fp {
    long long numerator;
    long long denominator;
} frac_fp;

struct conflict_resolution_buffer {
    unsigned int buffer_len;
    unsigned int * lpn;
};
#if DM_ZFTL_FP_EMU
#include "dm-zftl-fixedpoint-math.h"
struct segment {
    unsigned int start_lpn;
    frac_fp slope;
    frac_fp intercept;
    unsigned int len;//dose not include start_lpn
    int is_acc_seg;
    int is_seq_seg;
    int valid_tag;
    struct segment * next;
    struct conflict_resolution_buffer * CRB;
};
typedef struct point {
    long long x;
    long long y;
} point;



int frac_is_larger(frac_fp x1, frac_fp x2);


typedef struct line {
    point s0;
    point s1;
    fp_t fp_rho;
    fp_t fp_b;
} line;
fp_t get_rho(point x, point y);
point get_point_upper(point s0);
point get_point_lower(point s0);
point get_intersection(line s0, line s1);
line get_line(point s0, point s1);
#else

struct segment {
    unsigned int start_lpn;
    float slope;
    int intercept;
    unsigned int len;
    int is_acc_seg;
    struct segment * next;
    struct conflict_resolution_buffer * CRB;
};

typedef struct point {
    float x;
    float y;
} point;

typedef struct line {
    point s0;
    point s1;
    float rho;
    float b;
} line;
float get_rho(point x, point y);
point get_point_upper(point s0);
point get_point_lower(point s0);
point get_intersection(line s0, line s1);
line get_line(point s0, point s1);

#endif

unsigned int cal_ppn(frac_fp slope, frac_fp intercept, unsigned int lpn);

struct lsm_tree_level{
    unsigned int level_len;
    struct segment * seg;
    struct lsm_tree_level * next_level;
};

struct lsm_tree_frame{
    unsigned int frame_no;
    struct lsm_tree_level * level;
    atomic_t nr_level;
    unsigned int access_count;
};

struct lsm_tree{
    atomic_t nr_total_query;
    atomic_t nr_mispredict;
    atomic_t look_up_hist[DM_ZFTL_LOOK_UP_HIST_LEN];
    struct lsm_tree_frame * frame;
    unsigned int nr_frame;
};

struct frame_valid_bitmap {
    unsigned char bitmap[DM_ZFTL_FRAME_LENGTH_BITS];
};
struct frame_valid_bitmap *get_level_bitmap(struct lsm_tree_level * level);
void set_seg_bitmap(struct segment * seg, struct frame_valid_bitmap *bm);


//Return fully cover if all lpn is covered by bm, o.w. change seg and return partial cover
int lsm_tree_seg_compact__(struct segment * seg, struct frame_valid_bitmap *bm);

//For each seg in level, if seg compact return fully cover, then this seg can be removed.
void lsm_tree_level_compact__(struct lsm_tree_level * level, struct frame_valid_bitmap * bm);

struct frame_valid_bitmap *dm_zftl_bitmap_or(struct frame_valid_bitmap *bm1, struct frame_valid_bitmap *bm2);
struct frame_valid_bitmap *dm_zftl_bitmap_not(struct frame_valid_bitmap *bm);
struct frame_valid_bitmap *dm_zftl_bitmap_and(struct frame_valid_bitmap *bm1, struct frame_valid_bitmap *bm2);
int all_zero_check(struct frame_valid_bitmap *bm);
int dm_zftl_bitmap_get(struct frame_valid_bitmap *bm, unsigned int idx);
void dm_zftl_bitmap_set(struct frame_valid_bitmap *bm, unsigned int idx, int val);



struct lsm_tree * lsm_tree_init(unsigned int total_blocks);
void lsm_tree_compact(struct lsm_tree * lsm_tree);
void lsm_tree_frame_compact__(struct lsm_tree_frame * frame);
void lsm_tree_promote(struct lsm_tree * lsm_tree);
void lsm_tree_frame_promote__(struct lsm_tree_frame * frame);




void lsm_tree_insert(struct segment * seg, struct lsm_tree * lsm_tree);
/* Return overlap segment */
struct segment *lsm_tree_insert_segs_to_level_(struct segment *insert_segs,
                                               struct lsm_tree_level *level);
struct segment * lsm_tree_insert_seg_to_level_(struct segment *insert_seg,
                                                  struct lsm_tree_level *level);
/* Create new level and insert into current level's next level, And return new level */
struct lsm_tree_level *lsm_tree_insert_new_level_(struct lsm_tree_frame * frame,
                                                  struct lsm_tree_level * current_level);
int lsm_tree_is_seg_overlap_(struct segment *origin_seg,
                             struct segment *insert_seg);
int lsm_tree_try_merge_seg_(struct segment * origin_seg,
                                    struct segment *insert_seg);
int lsm_tree_quick_insert_(struct lsm_tree_level * level, struct segment *insert_seg);

struct segment * lsm_tree_get_ppn_segment(struct lsm_tree * lsm_tree, unsigned int lpn);
unsigned int lsm_tree_get_ppn(struct lsm_tree * lsm_tree, unsigned int lpn);
struct segment * lsm_tree_search_level_(struct lsm_tree_level* level,
                                        unsigned int lpn);
unsigned int lsm_tree_cal_ppn_(struct segment * seg,
                                        unsigned int lpn);
unsigned int lsm_tree_cal_ppn_simple__(struct segment * seg,
                               unsigned int lpn);
unsigned int lsm_tree_cal_ppn_original__(struct segment * seg,
                                       unsigned int lpn);
int lsm_tree_CRB_search_lpn_(struct conflict_resolution_buffer * CRB,
                             unsigned int lpn);

void lsm_tree_update_seq(struct lsm_tree * lsm_tree, unsigned int start_lpn, int len, unsigned int start_ppn);
void lsm_tree_update_by_lpn_array(struct lsm_tree * lsm_tree, unsigned int * lpn_array, int len, unsigned int start_ppn);

struct segment * Regression(unsigned int * lpn_array, int len, unsigned int start_ppn);
void lsm_tree_level_wise_compact__(struct lsm_tree_level * upper_level, struct lsm_tree_level * lower_level);

int segment_acc_check(const unsigned int * lpn_array, int start_idx, int len, struct segment * seg,unsigned int start_ppn);
int segment_seq_check(const unsigned int * lpn_array, int start_idx, int len);

#if DM_ZFTL_FP_EMU
struct segment * greedy_piecewise_linear_regression__(const unsigned int * lpn_array, int len, unsigned int start_ppn);
struct segment * gen_segment(const unsigned int * lpn_array, int start_idx, int len, frac_fp k, frac_fp interception, unsigned int start_ppn);
struct segment * gen_segment_original__(const unsigned int * lpn_array, int start_idx, int len, frac_fp k, frac_fp interception, unsigned int start_ppn);
#else
struct segment * greedy_piecewise_linear_regression__(const unsigned int * lpn_array, int len, unsigned int start_ppn);
struct segment * gen_segment(const unsigned int * lpn_array, int start_idx, unsigned int len, float k, int interception, int start_ppn);
struct segment * gen_segment_original__(const unsigned int * lpn_array, int start_idx, unsigned int len, float k, int interception, int start_ppn);
#endif

struct segment * gen_segment_simple__(const unsigned int * lpn_array, int start_idx, int len, unsigned int start_ppn);
struct conflict_resolution_buffer * gen_CRB(const unsigned int * lpn_array, int start_idx, int len);



#define SIZE_CALCULATE_REAL 0 //Calculate with struct size
#define SIZE_LPN_BYTES 4
#define SIZE_INTERCEPTION_BYTES SIZE_START_LPN_BYTES
#define SIZE_START_LPN_BYTES 1
#define SIZE_LEN_BYTES 1
#define SIZE_SLOPE_BYTES 2
#define SIZE_FRAME_LPN_OFFSET_BYTES 1

unsigned int lsm_tree_get_size(struct lsm_tree * tree);
unsigned int lsm_tree_get_frame_size__(struct lsm_tree_frame * frame);
unsigned int lsm_tree_get_level_size__(struct lsm_tree_level * level);
unsigned int lsm_tree_get_seg_size__(struct segment * seg);
void lsm_tree_print_frame(struct lsm_tree_frame * frame);

void lsm_tree_print_level(struct lsm_tree_level * level);
struct frame_valid_bitmap *get_seg_bm(struct segment * seg);
void lsm_tree_level_promote__(struct lsm_tree_level * upper_level, struct lsm_tree_level * lower_level);
void free_seg(struct segment * seg);
int lsm_tree_can_insert(struct lsm_tree_level * level, struct segment *insert_seg);
void lsm_tree_seq_merge(struct lsm_tree_level * level);
int lsm_tree_try_clean_seg(struct frame_valid_bitmap * upper_bm, struct segment * origin_seg);
unsigned int lsm_tree_predict_correct(unsigned int *p2l_table, unsigned int lpn, unsigned int predicted_ppn);
#endif //LEAFTL_DM_ZFTL_LEAFTL_H
