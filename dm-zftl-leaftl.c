#ifdef __cplusplus
extern "C" {
#endif
#include "dm-zftl-leaftl.h"
#define MAX_PROMOTE_LAYER 20
#define MAX_COMPACT_LAYER 100


static struct segment * list_tail(struct segment * list){
    if(!list)
        return NULL;
    while(list->next)
        list = list->next;
    return list;
}

static void list_tail_add(struct segment ** list, struct segment * insert_seg){
    if(!*list){
        *list = insert_seg;
        insert_seg->next = NULL;
        return;
    }
    struct segment * tail = list_tail(*list);
    if(!tail) {
        *list = insert_seg;
        insert_seg->next = NULL;
        return;
    }
    tail->next = insert_seg;
    insert_seg->next = NULL;
}



static struct segment * replace_seg(struct segment *origin_seg, struct segment *insert_seg){
    struct segment * overlap_seg = MALLOC(sizeof (struct segment));
    *overlap_seg = *origin_seg;
    *origin_seg = *insert_seg;
    origin_seg->next = overlap_seg->next;
    *overlap_seg = *insert_seg;
    overlap_seg->next = NULL;
    return overlap_seg;
}


struct lsm_tree * lsm_tree_init(unsigned int total_blocks){
    struct lsm_tree * tree = MALLOC(sizeof(struct lsm_tree));

    unsigned int total_frame = total_blocks / 256 + 1;
    struct lsm_tree_frame * frame = MALLOC_ARRAY(total_frame, sizeof(struct  lsm_tree_frame));
    tree->nr_frame = total_frame;
    tree->frame = frame;

    unsigned int i;
    for(i = 0; i < DM_ZFTL_LOOK_UP_HIST_LEN; ++i) {
        tree->look_up_hist[i] = 0;
    }

    for (i = 0; i < total_frame; ++i){
        frame[i].access_count = 0;
        frame[i].frame_no = i;
        frame[i].nr_level = 0;
        frame[i].level = NULL;

#if DM_ZFTL_CONCURRENT_SUPPORT
        mutex_init(&frame[i]._lock);
#endif

    }
    return tree;
}

void lsm_tree_insert(struct segment * seg, struct lsm_tree * lsm_tree){
    if(seg == NULL){
        return;
    }

    unsigned int frame_no = seg->start_lpn / DM_ZFTL_FRAME_LENGTH;

    if(frame_no >= lsm_tree->nr_frame){
        return;
    }
    struct lsm_tree_frame * frame = &lsm_tree->frame[frame_no];



    if(!frame->level){
        frame->level = lsm_tree_insert_new_level_(frame, frame->level);
    }
    struct lsm_tree_level * first_level = frame->level;
    struct segment * overlap_segs = NULL;

    overlap_segs = lsm_tree_insert_segs_to_level_(seg, first_level);
    if(overlap_segs){
        struct lsm_tree_level * new_level = lsm_tree_insert_new_level_(frame, first_level);
        overlap_segs = lsm_tree_insert_segs_to_level_(overlap_segs, new_level);
        BUG_ON(overlap_segs);
    }
    //lsm_tree_promote(lsm_tree);
}


struct segment *lsm_tree_insert_segs_to_level_(struct segment *insert_segs,
                                               struct lsm_tree_level *level){
    struct segment * overlap_head = NULL;
    struct segment * overlap_tail = NULL;
    struct segment * overlap_segs_head;
    struct segment * overlap_segs_tail;
    struct segment * insert_seg = insert_segs;
    unsigned int flags;

#if DM_ZFTL_CONCURRENT_SUPPORT
    if(level)
        spin_lock_irqsave(&level->_lock, flags);
#endif

    while(insert_seg) {

        //DO NOT CHANGE FOLLOWING CODE ORDER!
        struct segment * next = insert_seg->next;
        overlap_segs_tail = overlap_segs_head = lsm_tree_insert_seg_to_level_(insert_seg, level);
        //

        //TODO: Too disguising, Rebuild it.
        if (overlap_segs_head) {

            //Get tail seg of overlap seg
            overlap_segs_tail = list_tail(overlap_segs_head);

            if (!overlap_head) {
                overlap_head = overlap_segs_head;
                overlap_tail = overlap_segs_tail;
            }else{
                overlap_tail->next = overlap_segs_head;
                overlap_tail = overlap_segs_tail;
            }
        }


        insert_seg = next;
    }

#if DM_ZFTL_CONCURRENT_SUPPORT
    if(level)
        spin_unlock_irqrestore(&level->_lock, flags);
#endif

    return overlap_head;
}

struct segment * lsm_tree_insert_seg_to_level_(struct segment *insert_seg,
                                               struct lsm_tree_level *level){

    if(!insert_seg)
        return NULL;

    if(!level)
        return NULL;


    if(!level->seg) {
        level->seg = insert_seg;
        insert_seg->next = NULL;
        return NULL;
    }

    struct segment *prev, *curr, *prev_of_insert, *next_of_insert;
    prev_of_insert = NULL;
    next_of_insert = NULL;
    prev = level->seg;
    curr = prev->next;
    struct segment ** overlap_seg_list = MALLOC(sizeof(struct segment *));
    *overlap_seg_list = NULL;

    //Only one seg in level
    if(curr == NULL){
        if(lsm_tree_is_seg_overlap_(prev, insert_seg)){
            int merge_state = lsm_tree_try_merge_seg_(prev, insert_seg);
            if(merge_state == PUSH_DOWN || merge_state == DEL_SEG){
                level->seg = insert_seg;
                insert_seg->next = NULL;
                prev->next = NULL;
                if(merge_state == PUSH_DOWN){
                    FREE(overlap_seg_list);
                    return prev;
                }else {
                    free_seg(prev);
                    FREE(overlap_seg_list);
                    return NULL;
                }
            }
        }
        lsm_tree_quick_insert_(level, insert_seg);
        FREE(overlap_seg_list);
        return NULL;
    }


    prev = NULL;
    curr = level->seg;
    struct segment * detach_seg;
    while(curr){

        if(lsm_tree_is_seg_overlap_(curr, insert_seg)){

            //TODO:seg of SAME_LEVEL suppose to be deleted(?)
            int merge_state = lsm_tree_try_merge_seg_(curr, insert_seg);
            if(merge_state == PUSH_DOWN || merge_state == DEL_SEG){
                // Detach segment
                //
                //   (prev) --> curr     --> next
                //              detach_seg   curr
                //
                detach_seg = curr;

                if(curr == level->seg && prev == NULL){
                    level->seg = curr->next;
                    curr = level->seg;
                }
                else {
                    prev->next = curr->next;
                    curr = prev->next;
                }

                detach_seg->next = NULL;

                if (merge_state == PUSH_DOWN)
                    list_tail_add(overlap_seg_list, detach_seg);
                else
                    free_seg(detach_seg);

                continue;
            }

        }

        prev = curr;
        curr = curr->next;
    }

    END:
    lsm_tree_quick_insert_(level, insert_seg);
    struct segment * overlap_segs = *overlap_seg_list;
    FREE(overlap_seg_list);
    return overlap_segs;
}

int lsm_tree_is_seg_overlap_(struct segment *origin_seg,
                             struct segment *insert_seg){
    unsigned int seg1_start,seg1_end, seg2_start,seg2_end;
    seg1_start = origin_seg->start_lpn;
    seg1_end = seg1_start + origin_seg->len;
    seg2_start = insert_seg->start_lpn;
    seg2_end = seg2_start + insert_seg->len;
    return (seg1_start >= seg2_start && seg1_start <= seg2_end) ||
           (seg2_start >= seg1_start && seg2_start <= seg1_end);
}

int lsm_tree_try_clean_seg(struct frame_valid_bitmap * upper_bm, struct segment * origin_seg){

    if(origin_seg->is_acc_seg) {

        unsigned int start = seg_start(origin_seg);
        unsigned int end = seg_end(origin_seg);
        long new_start = DM_ZFTL_FRAME_LENGTH;
        long new_end = DM_ZFTL_FRAME_LENGTH;
        unsigned int lpn;
        for(lpn = start; lpn <= end; ++lpn){
            if(!dm_zftl_bitmap_get(upper_bm, lpn)) {
                if(new_start == DM_ZFTL_FRAME_LENGTH){
                    new_start = lpn;
                    new_end = lpn;
                }
                new_end = new_end > lpn ? new_end : lpn;
            }
        }
        if(new_start != DM_ZFTL_FRAME_LENGTH) {
            origin_seg->start_lpn = new_start;
            origin_seg->len = new_end - new_start;
            goto SAME_LEVEL;
        }else{
            origin_seg->start_lpn = 0;
            goto DEL_SEG;
        }

    }else{

        unsigned int i = 0;
        unsigned int free_idx = 0;
        unsigned int lpn;


        for(i = 0; i < origin_seg->CRB->buffer_len; ++i){
            lpn = origin_seg->CRB->lpn[i];
            if(!dm_zftl_bitmap_get(upper_bm, lpn)){
                origin_seg->CRB->lpn[free_idx] = lpn;
                free_idx++;
            }
        }

        if(free_idx == 0) {
            origin_seg->len = 0;
            origin_seg->CRB->buffer_len = 0;
            goto DEL_SEG;
        }


        origin_seg->CRB->buffer_len = free_idx;
        origin_seg->start_lpn = origin_seg->CRB->lpn[0];
        origin_seg->len = origin_seg->CRB->lpn[free_idx - 1] - origin_seg->start_lpn;
        goto SAME_LEVEL;

    }





    SAME_LEVEL:

    return SAME_LEVEL;

    DEL_SEG:

    return DEL_SEG;
}

/*
 *
 * Merge two segment
 *
 * */
int lsm_tree_try_merge_seg_(struct segment *origin_seg,
                            struct segment *insert_seg){


    struct frame_valid_bitmap * insert_bm = get_seg_bm(insert_seg);

    if(insert_seg->is_acc_seg && origin_seg->is_acc_seg) {
        if(seg_start(insert_seg) > seg_start(origin_seg) && seg_end(insert_seg) < seg_end(origin_seg))
                goto PUSH_DOWN;
        if(seg_start(insert_seg) <= seg_start(origin_seg) && seg_end(insert_seg) >= seg_end(origin_seg))
                goto DEL_SEG;
        if(seg_start(origin_seg) < seg_start(insert_seg) && seg_end(origin_seg) >= seg_start(insert_seg)) {
            origin_seg->len = seg_start(insert_seg) - 1 - origin_seg->start_lpn;
                goto SAME_LEVEL;
        }
        if(seg_end(origin_seg) > seg_end(insert_seg) && seg_start(origin_seg) <= seg_end(insert_seg)) {
            unsigned int pre_start = origin_seg->start_lpn;
            origin_seg->start_lpn = seg_end(insert_seg) + 1;
            origin_seg->len -= origin_seg->start_lpn - pre_start;
            goto SAME_LEVEL;
        }
        goto PUSH_DOWN;
    }



    if(origin_seg->is_acc_seg) {

        unsigned int start = seg_start(origin_seg);
        unsigned int end = seg_end(origin_seg);
        long new_start = DM_ZFTL_FRAME_LENGTH;
        long new_end = DM_ZFTL_FRAME_LENGTH;
        unsigned int lpn;
        for(lpn = start; lpn <= end; ++lpn){
            if(!dm_zftl_bitmap_get(insert_bm, lpn)) {
                if(new_start == DM_ZFTL_FRAME_LENGTH){
                    new_start = lpn;
                    new_end = lpn;
                }
                new_end = new_end > lpn ? new_end : lpn;
            }
        }
        if(new_start != DM_ZFTL_FRAME_LENGTH) {
            origin_seg->start_lpn = new_start;
            origin_seg->len = new_end - new_start;
        }else{
            goto DEL_SEG;
        }
        int is_overlap = lsm_tree_is_seg_overlap_(origin_seg, insert_seg);
        if(is_overlap)
            goto PUSH_DOWN;
        goto SAME_LEVEL;

    }else{

        unsigned int i = 0;
        unsigned int free_idx = 0;
        unsigned int lpn;

        for(i = 0; i < origin_seg->CRB->buffer_len; ++i){
            lpn = origin_seg->CRB->lpn[i];
            if(!dm_zftl_bitmap_get(insert_bm, lpn)){
                    origin_seg->CRB->lpn[free_idx] = lpn;
                    free_idx++;
            }
        }

        if(free_idx == 0)
            goto DEL_SEG;


        origin_seg->CRB->buffer_len = free_idx;
        origin_seg->start_lpn = origin_seg->CRB->lpn[0];
        origin_seg->len = origin_seg->CRB->lpn[free_idx - 1] - origin_seg->start_lpn;
        int is_overlap = lsm_tree_is_seg_overlap_(origin_seg, insert_seg);
        if(is_overlap)
            goto PUSH_DOWN;
        else
            goto SAME_LEVEL;

    }



    DEL_SEG:
        FREE(insert_bm);
        return DEL_SEG;

    SAME_LEVEL:
        FREE(insert_bm);
        return SAME_LEVEL;

    PUSH_DOWN:
        FREE(insert_bm);
        return PUSH_DOWN;
}

// In original LeaFTL, f(lpn) = ppn, ppn may not correct, we need to do local search in [ppn - ε, ppn + ε]
//
// But in real-SSD env almost every segment's assigned ppn is always continuous
//
// [ppn1, ppn2, ppn3, ...]
// [lpn1, lpn2, lpn3, ...]
// ===> ppn(i) = ppn(i-1) + 1
//
// if we know ppn1 ( = f(lpn1) ),
// we can get ppn3 = f(lpn1) + 2
// without calculate f(lpn3) and do local search around f(lpn3)
struct segment * lsm_tree_get_ppn_segment(struct lsm_tree * lsm_tree, unsigned int lpn){
    struct segment * target_segment;
    unsigned int frame_no = lpn / DM_ZFTL_FRAME_LENGTH;
    if(frame_no >= lsm_tree->nr_frame){
        goto UNMAPPED;
    }

    struct lsm_tree_frame * frame = &lsm_tree->frame[frame_no];
    struct lsm_tree_level * level = frame->level;

    while(level){
        target_segment = lsm_tree_search_level_(level, lpn);

        if(target_segment){

            if(target_segment->is_acc_seg){
                return target_segment;
            }else {
                /* Check if this lpn belong to this approximate segment */
                int lpn_offset_in_seg;
                lpn_offset_in_seg = lsm_tree_CRB_search_lpn_(target_segment->CRB, lpn);
                /* This lpn doesn't belong to seg, keep searching */
                if(lpn_offset_in_seg != -1){
                    return target_segment;
                }
            }
        }

        level = level->next_level;
    }
    UNMAPPED:
    return NULL;
}

unsigned int lsm_tree_get_ppn(struct lsm_tree * lsm_tree, unsigned int lpn){
    unsigned int ppn, approximate_ppn;
    struct segment * target_segment;
    unsigned int frame_no = lpn / DM_ZFTL_FRAME_LENGTH;
    if(frame_no >= lsm_tree->nr_frame){
        goto UNMAPPED;
    }

    unsigned int look_up = 0;
    struct lsm_tree_frame * frame = &lsm_tree->frame[frame_no];
    struct lsm_tree_level * level = frame->level;

    while(level){
        look_up++;
        target_segment = lsm_tree_search_level_(level, lpn);

        if(target_segment){

            if(target_segment->is_acc_seg){
                ppn = lsm_tree_cal_ppn_(target_segment, lpn);

                //lsm_tree->look_up_hist[look_up] += 1;
                return ppn;

            }else {
                /*Check if this lpn really in this approximate segment*/
                int lpn_offset_in_seg;
                lpn_offset_in_seg = lsm_tree_CRB_search_lpn_(target_segment->CRB, lpn);

                /* This lpn doesn't in this seg, keep searching */
                if(lpn_offset_in_seg != -1){
                    /* Found in approximate seg */
#if DM_ZFTL_LEA_ORIGIN
                    ppn = lsm_tree_cal_ppn_(target_segment, lpn);
                    /* TODO: Search in p2l and do local search to find true ppn for lpn */
#else
                    ppn = lsm_tree_cal_ppn_(target_segment, lpn);
#endif
                    //lsm_tree->look_up_hist[look_up] += 1;
                    return ppn;
                }
            }
        }

        level = level->next_level;
    }
    UNMAPPED:
    return DM_ZFTL_UNMAPPED_PPA;
}

int lsm_tree_CRB_search_lpn_(struct conflict_resolution_buffer * CRB,
                             unsigned int lpn){
    int i=0;
    for(i = 0; i < CRB->buffer_len; ++i){
        if(CRB->lpn[i] == lpn)
            return i;
    }
    return -1;
}

struct segment * lsm_tree_search_level_(struct lsm_tree_level* level,
                                        unsigned int lpn){
    if(!level)
        return NULL;
    if(!level->seg)
        return NULL;
    struct segment * seg = level->seg;
    while(seg){
        if(seg_start(seg) <= lpn && seg_end(seg) >= lpn)
            return seg;
        seg = seg->next;
    }
    return NULL;
}

unsigned int lsm_tree_cal_ppn_(struct segment * seg, unsigned int lpn){
#if DM_ZFTL_LEA_ORIGIN
    return lsm_tree_cal_ppn_original__(seg, lpn);
#else
    return lsm_tree_cal_ppn_simple__(seg, lpn);
#endif
}

unsigned int lsm_tree_cal_ppn_simple__(struct segment * seg, unsigned int lpn){
    if(seg->is_acc_seg)
        return lpn - seg->start_lpn + seg->intercept.numerator / seg->intercept.denominator;
    else
        return lsm_tree_CRB_search_lpn_(seg->CRB, lpn) + seg->intercept.numerator / seg->intercept.denominator;
}

/* Dose this type safe ?*/
unsigned int lsm_tree_cal_ppn_original__(struct segment * seg,
                                         unsigned int lpn){
#if DM_ZFTL_FP_EMU
    unsigned int t;
    t = cal_ppn(seg->slope, seg->intercept, lpn);
    return t;
#else
    return seg->slope * lpn + seg->intercept;
#endif
}
void lsm_tree_update_seq(struct lsm_tree * lsm_tree, unsigned int start_lpn, int len, unsigned int start_ppn) {
    unsigned int i = 0;
    unsigned int pre_lpn = start_lpn;
    struct segment * segs;
    unsigned int pre_frame = start_lpn / DM_ZFTL_FRAME_LENGTH;
    for(i = start_lpn; i < start_lpn + len; ++i){
        unsigned int curr_frame = (start_lpn + i) / DM_ZFTL_FRAME_LENGTH;
        if(curr_frame != pre_frame) {
            segs = MALLOC(sizeof (struct segment));
            segs->CRB = NULL;
            segs->next = NULL;
            segs->start_lpn = pre_lpn;
            segs->len = i - pre_lpn - 1;
            segs->slope.denominator = 1;
            segs->slope.numerator = 1;
            segs->intercept.numerator = start_ppn + pre_lpn - start_lpn - segs->start_lpn;
            segs->intercept.denominator = 1;
            segs->is_acc_seg = 1;
            lsm_tree_insert(segs,
                            lsm_tree);
        }
    }
    segs = MALLOC(sizeof (struct segment));
    segs->is_acc_seg = 1;
    segs->CRB = NULL;
    segs->next = NULL;
    segs->start_lpn = pre_lpn;
    segs->len = i - pre_lpn - 1;
    segs->slope.denominator = 1;
    segs->slope.numerator = 1;
    segs->intercept.numerator = start_ppn + pre_lpn - start_lpn - segs->start_lpn;
    segs->intercept.denominator = 1;
    lsm_tree_insert(segs,
                    lsm_tree);
    return;
}

void lsm_tree_update_by_lpn_array(struct lsm_tree * lsm_tree, unsigned int * lpn_array, int len, unsigned int start_ppn){
    int i = 0;
    int pre_index = 0;
    struct segment * cp;
    struct segment * segs;
    unsigned int wp = start_ppn;
    unsigned int pre_frame = lpn_array[0] / DM_ZFTL_FRAME_LENGTH;
    for(i = 0; i < len; ++i){
        unsigned int curr_frame = lpn_array[i] / DM_ZFTL_FRAME_LENGTH;
        if(curr_frame != pre_frame) {
            segs = Regression(lpn_array + pre_index, i - pre_index, wp);
            lsm_tree_insert(segs,
                            lsm_tree);
            wp += i - pre_index;
            pre_index = i;
        }
    }
    segs = Regression(lpn_array + pre_index, i - pre_index, wp);
    lsm_tree_insert(segs,
                    lsm_tree);
    return;
}

struct segment * Regression(unsigned int * lpn_array, int len, unsigned int start_ppn){
    return greedy_piecewise_linear_regression__(lpn_array, len, start_ppn);
}


struct segment * gen_segment_simple__(const unsigned int * lpn_array, int start_idx, int len, unsigned int start_ppn){
    struct segment * seg = MALLOC(sizeof (struct segment));
    seg->valid_tag = 0;
    seg->start_lpn = lpn_array[start_idx];
    seg->len = lpn_array[start_idx + len - 1] - lpn_array[start_idx];;
    seg->next = NULL;
    seg->intercept.numerator = start_ppn;
    seg->intercept.denominator = 1;


    int is_acc;
//    is_acc = segment_acc_check(lpn_array, start_idx, len, seg, start_ppn) &&
//             segment_seq_check(lpn_array, start_idx, len);
    is_acc = segment_seq_check(lpn_array, start_idx, len);
    seg->is_acc_seg = is_acc;
    if(!seg->is_acc_seg){
        seg->CRB = gen_CRB(lpn_array, start_idx, len);
    }
    return seg;
}


int segment_seq_check(const unsigned int * lpn_array, int start_idx, int len){
    unsigned int i;
    int is_consecutive = 1;
    unsigned int pre_lpn = lpn_array[start_idx] - 1;
    for(i = start_idx; i < start_idx + len; ++i){
        if(lpn_array[i] != pre_lpn + 1){
            is_consecutive = 0;
            break;
        }
        pre_lpn = lpn_array[i];
    }
    return is_consecutive;
}


struct conflict_resolution_buffer * gen_CRB(const unsigned int * lpn_array, int start_idx, int len){
    struct conflict_resolution_buffer * CRB = MALLOC(sizeof(struct conflict_resolution_buffer));
    CRB->buffer_len = (unsigned int)len;
    CRB->lpn = MALLOC_ARRAY(len, sizeof(unsigned int));
    int i;
    for(i = start_idx; i < start_idx + len; ++i){
        CRB->lpn[i - start_idx] = lpn_array[i];
    }
    return CRB;
}



struct frame_valid_bitmap *get_level_bitmap(struct lsm_tree_level * level){
    struct frame_valid_bitmap *bm = MALLOC(sizeof(struct frame_valid_bitmap));
    int i;
    for(i = 0; i < DM_ZFTL_FRAME_LENGTH_BITS; ++i){
        bm->bitmap[i] = ((unsigned char)0);
    }
    struct segment * seg = level->seg;
    unsigned int lpn;
    while(seg){
        set_seg_bitmap(seg, bm);
        seg = seg->next;
    }
    return bm;
}

void set_seg_bitmap(struct segment * seg, struct frame_valid_bitmap *bm){
    int i;
    unsigned int lpn;
    if(seg->is_acc_seg){
        unsigned int start_lpn = seg_start(seg);
        unsigned int end_lpn = seg_end(seg);
        for(lpn = start_lpn; lpn <= end_lpn; ++lpn){
            bm->bitmap[(lpn % DM_ZFTL_FRAME_LENGTH) / 8] |= ((unsigned char )1 << ((lpn % DM_ZFTL_FRAME_LENGTH) % 8));
        }
    }else{
        i = 0;
        while(i < seg->CRB->buffer_len){
            lpn = seg->CRB->lpn[i];
            bm->bitmap[(lpn % DM_ZFTL_FRAME_LENGTH) / 8] |= ((unsigned char )1 << ((lpn % DM_ZFTL_FRAME_LENGTH) % 8));
            i++;
        }
    }
}

struct frame_valid_bitmap *dm_zftl_bitmap_or(struct frame_valid_bitmap *bm1, struct frame_valid_bitmap *bm2){
    struct frame_valid_bitmap *bm = MALLOC(sizeof(struct frame_valid_bitmap));
    int i;
    for(i = 0; i < DM_ZFTL_FRAME_LENGTH_BITS; ++i){
        bm->bitmap[i] = bm1->bitmap[i] | bm2->bitmap[i];
    }
    return bm;
}

struct frame_valid_bitmap *dm_zftl_bitmap_not(struct frame_valid_bitmap *bm){
    struct frame_valid_bitmap *bm_ = MALLOC(sizeof(struct frame_valid_bitmap));
    int i;
    for(i = 0; i < DM_ZFTL_FRAME_LENGTH_BITS; ++i){
        bm_->bitmap[i] = ~(bm->bitmap[i]);
    }
    return bm_;
}

struct frame_valid_bitmap *dm_zftl_bitmap_and(struct frame_valid_bitmap *bm1, struct frame_valid_bitmap *bm2){
    struct frame_valid_bitmap *bm = MALLOC(sizeof(struct frame_valid_bitmap));
    int i;
    for(i = 0; i < DM_ZFTL_FRAME_LENGTH_BITS; ++i){
        bm->bitmap[i] = bm1->bitmap[i] & bm2->bitmap[i];
    }
    return bm;
}

int all_zero_check(struct frame_valid_bitmap *bm){
    int i;
    for(i = 0; i < DM_ZFTL_FRAME_LENGTH_BITS; ++i){
        if(bm->bitmap[i])
            return 0;
    }
    return 1;
}

int dm_zftl_bitmap_get(struct frame_valid_bitmap *bm, unsigned int idx){
    return bm->bitmap[(idx % DM_ZFTL_FRAME_LENGTH) / 8] & ((unsigned char )1 << ((idx % DM_ZFTL_FRAME_LENGTH) % 8));
}


//TODO:check bit op
void dm_zftl_bitmap_set(struct frame_valid_bitmap *bm, unsigned int idx, int val){
    if(val){
        bm->bitmap[(idx % DM_ZFTL_FRAME_LENGTH) / 8] |= ((unsigned char )1 << ((idx % DM_ZFTL_FRAME_LENGTH) % 8));
    }else{
        bm->bitmap[(idx % DM_ZFTL_FRAME_LENGTH) / 8] &= ~((unsigned char )1 << ((idx % DM_ZFTL_FRAME_LENGTH) % 8));
    }
}

void lsm_tree_compact(struct lsm_tree * lsm_tree){
    int i = 0;
    for(i = 0; i < lsm_tree->nr_frame ; ++i)
        lsm_tree_frame_compact__(&lsm_tree->frame[i]);
}


void lsm_tree_clean_empty_level__(struct lsm_tree_frame * frame) {
    struct lsm_tree_level * pre_level = NULL;
    struct lsm_tree_level * level = frame->level;
    while(level){
        if(!level->seg){
            if(level == frame->level){
                frame->level = level->next_level;
                FREE(level);
                level = frame->level;
            }else{
                level = level->next_level;
                FREE(pre_level->next_level);
                pre_level->next_level = level;
            }
            continue;
        }
        pre_level = level;
        level = level->next_level;
    }
}

/* Compact the lsm tree upside-down */
void lsm_tree_frame_compact__(struct lsm_tree_frame * frame){
    if(!frame)
        return;

#if DM_ZFTL_CONCURRENT_SUPPORT
    mutex_lock(&frame->_lock);
#endif

    struct lsm_tree_level * level = frame->level;
    if(!level)
        return;
    struct frame_valid_bitmap * upper_level_bm = get_level_bitmap(level);
    struct frame_valid_bitmap * current_level_bm;
    struct frame_valid_bitmap * pre_level_bm = upper_level_bm;
    int level_cnt = 0;
    unsigned int before_size, after_size;
    while(level->next_level){
        level = level->next_level;
        current_level_bm = get_level_bitmap(level);
        lsm_tree_level_compact__(level, upper_level_bm);
        pre_level_bm = upper_level_bm;
        upper_level_bm = dm_zftl_bitmap_or(current_level_bm, upper_level_bm);

        FREE(pre_level_bm);
        FREE(current_level_bm);
        level_cnt++;
    }

    lsm_tree_clean_empty_level__(frame);
    FREE(upper_level_bm);

#if DM_ZFTL_COMPACT_DEBUG
    if(after_size < before_size) {
        printk(KERN_EMERG
        "[Compact] Frame:%llu Before:%llu B  After:%lluB"
                , frame->frame_no
                , before_size
                , after_size);
    }
#endif

#if DM_ZFTL_CONCURRENT_SUPPORT
    mutex_unlock(&frame->_lock);
#endif
}


void lsm_tree_level_wise_compact__(struct lsm_tree_level * upper_level, struct lsm_tree_level * lower_level) {
    if(!lower_level)
        return;
    if(!lower_level->seg)
        return;

    struct segment * upper_seg = upper_level->seg;
    while(upper_seg) {
        struct segment * lower_seg = lower_level->seg;
        struct segment * lower_pre_seg = NULL;
        while(lower_seg) {
            if(lsm_tree_is_seg_overlap_(lower_seg, upper_seg)){
                int state = lsm_tree_try_merge_seg_(lower_seg, upper_seg);
                if(state == DEL_SEG) {
                    struct segment * detach_seg = lower_seg;

                    if(lower_seg == lower_level->seg) {
                        lower_level->seg = lower_seg->next;
                        lower_seg = lower_seg->next;
                    }else{
                        lower_pre_seg->next = lower_seg->next;
                        lower_seg = lower_seg->next;
                    }

                    detach_seg->next = NULL;
                    free_seg(detach_seg);
                    continue;
                }
            }
            lower_pre_seg = lower_seg;
            lower_seg = lower_seg->next;
        }
        upper_seg = upper_seg->next;
    }
}
void lsm_tree_level_compact__(struct lsm_tree_level * level, struct frame_valid_bitmap * bm){
    struct segment * seg = level->seg;
    struct segment * pre_seg = NULL;
    if(!seg)
        return;

    struct segment * virtual_seg = MALLOC(sizeof(struct segment));
    virtual_seg->next = seg;
    virtual_seg->is_acc_seg = 1;
    virtual_seg->CRB = NULL;

    pre_seg = virtual_seg;

    int cover_state;
    while(seg){

        cover_state = lsm_tree_try_clean_seg(bm, seg);

        if(cover_state == DEL_SEG){
            struct segment * detach_seg = seg;

            pre_seg->next = seg->next;
            seg = pre_seg->next;

            detach_seg->next = NULL;
            free_seg(detach_seg);
            continue;
        }else{
            pre_seg = seg;
            seg = seg->next;
        }
    }

    level->seg = virtual_seg->next;
    virtual_seg->next = NULL;
    free_seg(virtual_seg);
}
//TODO:Change it
int lsm_tree_seg_compact__(struct segment * seg, struct frame_valid_bitmap *bm){
    int i;
    unsigned int lpn, valid=0;
    unsigned valid_cnt=0;
    unsigned invalid_cnt=0;
    if(seg->is_acc_seg){
        i = 0;
        while(i <= seg->len){
            lpn = seg->start_lpn + i;
            valid = bm->bitmap[(lpn % DM_ZFTL_FRAME_LENGTH) / 8] & (unsigned char)((unsigned char)1 << (lpn % 8));
            if(!valid){
                invalid_cnt++;
//                //Bm doesn't cover this lpn
            }else {
                valid_cnt++;
            }
            i++;
        }

    }else{
        i = 0;
        while(i < seg->CRB->buffer_len){
            lpn = seg->CRB->lpn[i];
            valid = bm->bitmap[(lpn % DM_ZFTL_FRAME_LENGTH) / 8] & (unsigned char)((unsigned char)1 << (lpn % 8));
            if(!valid){
                invalid_cnt++;
//                //Bm doesn't cover this lpn
            }else {
                valid_cnt++;
            }
            i++;
        }
    }
    if(invalid_cnt && valid_cnt)
        return PARTIAL_COVER;
    else if(valid_cnt == 0)
        return UNCOVER;
    else
        return FULLY_COVER;
}

/* Create new level and insert into curr level's next level, And return new level */
struct lsm_tree_level *lsm_tree_insert_new_level_(struct lsm_tree_frame * frame,
                                                  struct lsm_tree_level * curr_level){
    struct lsm_tree_level * level = MALLOC(sizeof (struct lsm_tree_level));
    level->next_level = NULL;
    level->seg = NULL;
    level->level_len = 0;

#if DM_ZFTL_CONCURRENT_SUPPORT
    spin_lock_init(&level->_lock);
#endif

    if(!curr_level){
        frame->level = level;
        level->next_level = NULL;
        level->seg = NULL;
    }else {
        level->next_level = curr_level->next_level;
        curr_level->next_level = level;
    }
    return level;
}



unsigned int lsm_tree_get_size(struct lsm_tree * tree){
    if(!tree)
        return 0;
    unsigned int total_size = 0;
    unsigned int i = 0;
    for(i = 0; i < tree->nr_frame; ++i){
        total_size += lsm_tree_get_frame_size__(&tree->frame[i]);
    }
#if SIZE_CALCULATE_REAL
    total_size += sizeof(struct lsm_tree);
#endif
    return total_size;
}

unsigned int lsm_tree_get_frame_size__(struct lsm_tree_frame * frame){
    if(!frame)
        return 0;
    unsigned int total_size = 0;
    struct lsm_tree_level * level = frame->level;
    while (level){
        total_size += lsm_tree_get_level_size__(level);
        level = level->next_level;
    }
#if SIZE_CALCULATE_REAL
    total_size += sizeof(struct lsm_tree_frame);
#endif
    return total_size;
}

unsigned int lsm_tree_get_level_size__(struct lsm_tree_level * level){
    if(!level)
        return 0;
    unsigned int total_size = 0;
    struct segment * seg = level->seg;
    while(seg){
        total_size += lsm_tree_get_seg_size__(seg);
        seg = seg->next;
    }
#if SIZE_CALCULATE_REAL
    total_size += sizeof(struct lsm_tree_level);
#endif
    return total_size;
}

unsigned int lsm_tree_get_seg_size__(struct segment * seg){
    unsigned int total_size = 0;
    if(!seg)
        return 0;
#if SIZE_CALCULATE_REAL
    //segment size
    total_size = sizeof(struct segment);

    //lpn size
    if(!seg->is_acc_seg){
        total_size += seg->CRB->buffer_len * sizeof(unsigned int);
    }

    total_size += sizeof (struct conflict_resolution_buffer);
#else
    //segment size
    total_size = SIZE_START_LPN_BYTES + SIZE_LEN_BYTES
                 + SIZE_SLOPE_BYTES + SIZE_INTERCEPTION_BYTES;

    //lpn size
    if(!seg->is_acc_seg){
        total_size += seg->CRB->buffer_len * SIZE_FRAME_LPN_OFFSET_BYTES;
    }
#endif
    return total_size;
}
void lsm_tree_frame_status_check(struct lsm_tree_frame * frame) {
    int acc_count = 0;
    int appro_count = 0;
    int crb_count = 0;
    int level_count = 0;

    if(!frame)
        return;
    struct lsm_tree_level * level = frame->level;
    if(!level)
        return;
    while(level) {
        level_count += 1;
        struct segment * segs = level->seg;
        while(segs) {
            if(segs->is_acc_seg)
                acc_count += 1;
            else {
                appro_count += 1;
                crb_count += (int)segs->CRB->buffer_len;
            }
            segs = segs->next;
        }
        level = level->next_level;
    }
    printk(KERN_EMERG"Acc seg:%d \n"
           "Appro seg:%d \n"
           "Total seg:%d \n"
           "CRB lpns:%d \n"
           "Level:%d \n"
           ,acc_count
           ,appro_count
           ,appro_count+acc_count
           ,crb_count
           ,level_count);


}


#if DM_ZFTL_FP_EMU
fp_t fp_div__(fp_t a, fp_t b)
{
    return (a << FSHIFT) / b;
}

fp_t fp_mul__(fp_t a, fp_t b)
{
    return (a * b) >> FSHIFT;
}

int frac_is_larger(frac_fp x1, frac_fp x2) {
    long long a,b;
    //   a1     a2
    //  ---- > ---- ? <==> a1 * b2 > a2 * b1
    //   b1     b2
    a = (long long)x1.numerator   *  (long long)x2.denominator;
    b = (long long)x1.denominator *  (long long)x2.numerator;
    return a > b ? 1 : 0;
}

struct segment * greedy_piecewise_linear_regression__(const unsigned int * lpn_array, int len, unsigned int start_ppn) {
    enum {
        STATE_FIRST,
        STATE_SECOND,
        STATE_READY,
    } learning_state;

    struct segment ** seg_list = MALLOC(sizeof(struct segment *));
    *seg_list = NULL;
    int state = STATE_FIRST;
    int start_idx = 0, idx = 0;
    point curr;
    point s0, s1, cone_apex;

    frac_fp  upper_rho;
    frac_fp  lower_rho;

    frac_fp  curr_upper_rho;
    frac_fp  curr_lower_rho;

    point  upper_point__;
    point  lower_point__;

    frac_fp k;
    frac_fp interception;

    while(idx < len){

        curr.x = lpn_array[idx];
        curr.y = start_ppn + idx;

        switch (state) {

            case STATE_FIRST:

                start_idx = idx;
                s0 = curr;
                state = STATE_SECOND;
                break;

            case STATE_SECOND:

                if(curr.x - s0.x >= DM_ZFTL_FRAME_LENGTH){
                    /* single point segment */
                    /* y = 1 * lpn + ppn - lpn */

                    k.numerator = 1;
                    k.denominator = 1;

                    interception.numerator = s0.y - s0.x;
                    interception.denominator = 1;

                    list_tail_add(seg_list,
                                  gen_segment(lpn_array, start_idx,
                                              1, k, interception, start_ppn + start_idx));

                    state = STATE_FIRST;
                    continue;

                }else{
                    s1 = curr;

                    cone_apex.x = (s0.x + s1.x) / 2;
                    cone_apex.y = (s0.y + s1.y) / 2;// Div round down

                    upper_rho.numerator = get_point_upper(s1).y - cone_apex.y;
                    upper_rho.denominator = get_point_upper(s1).x - cone_apex.x;
                    upper_point__ = get_point_upper(s1);

                    lower_rho.numerator = get_point_lower(s1).y - cone_apex.y;
                    lower_rho.denominator = get_point_lower(s1).x - cone_apex.x;
                    lower_point__ = get_point_lower(s1);



                    state = STATE_READY;

                }
                break;

            case STATE_READY:

                curr_upper_rho.numerator = get_point_upper(curr).y - cone_apex.y;
                curr_upper_rho.denominator = get_point_upper(curr).x - cone_apex.x;

                curr_lower_rho.numerator = get_point_lower(curr).y - cone_apex.y;
                curr_lower_rho.denominator = get_point_lower(curr).x - cone_apex.x;

                if(     (curr.x - s0.x) >= DM_ZFTL_FRAME_LENGTH  ||
                        frac_is_larger(curr_lower_rho, upper_rho)   ||
                        frac_is_larger(lower_rho, curr_upper_rho)    ){

                    point tail_mid_point;
                    tail_mid_point.x = ( upper_point__.x + lower_point__.x )/ 2;
                    tail_mid_point.y = ( upper_point__.y + lower_point__.y )/ 2;

//                    k.numerator = tail_mid_point.y - cone_apex.y;
//                    k.denominator = tail_mid_point.x - cone_apex.x;

                    k.numerator = upper_rho.numerator * lower_rho.denominator + lower_rho.numerator * upper_rho.denominator;
                    k.denominator = upper_rho.denominator * lower_rho.denominator * 2;
                    // k = upper_rho;

                    // cone_apex.y = k * cone_apex.x + interception
                    // interception = cone_apex.y - k * cone_apex.x
                    // k = 10 / 42
                    // I = 29400393716 / 42

                    interception.numerator =  ((long long)cone_apex.y *
                                                (long long)k.denominator - (long long)k.numerator * (long long)cone_apex.x);
                    interception.denominator = k.denominator;

                    list_tail_add(seg_list,
                    gen_segment(lpn_array, start_idx, idx - start_idx, k, interception, start_ppn + start_idx));
                    state = STATE_FIRST;
                    continue;

                }else {

                    s1 = curr;

                    if(frac_is_larger(upper_rho, curr_upper_rho)){
                        upper_rho = curr_upper_rho;
                        upper_point__ = get_point_upper(curr);
                    }

                    if(frac_is_larger( curr_lower_rho, lower_rho)){
                        lower_rho = curr_lower_rho;
                        lower_point__ = get_point_lower(curr);
                    }

                }
                break;
        }
        idx++;
    }


    point tail_mid_point;
    switch (state) {
        case STATE_SECOND:
            k.numerator = 1;
            k.denominator = 1;

            interception.numerator = s0.y - s0.x;
            interception.denominator = 1;

            list_tail_add(seg_list,
                          gen_segment(lpn_array, start_idx,
                                      1, k, interception, start_ppn + start_idx));
            break;
        case STATE_READY:

            tail_mid_point.x = ( upper_point__.x + lower_point__.x )/ 2;
            tail_mid_point.y = ( upper_point__.y + lower_point__.y )/ 2;

            k.numerator = upper_rho.numerator * lower_rho.denominator + lower_rho.numerator * upper_rho.denominator;
            k.denominator = upper_rho.denominator * lower_rho.denominator * 2;

            interception.numerator =  ((long long)cone_apex.y *
                                       (long long)k.denominator - (long long)k.numerator * (long long)cone_apex.x);
            interception.denominator = k.denominator;
            list_tail_add(seg_list,
                          gen_segment(lpn_array, start_idx, idx - start_idx, k, interception, start_ppn + start_idx));
            break;
        default:
            break;
    }

    struct segment * segs = *seg_list;
    FREE(seg_list);
    return segs;
}
struct segment * gen_segment(const unsigned int * lpn_array, int start_idx, int len, frac_fp k, frac_fp interception,unsigned int start_ppn){
#if DM_ZFTL_LEA_ORIGIN
    return gen_segment_original__(lpn_array, start_idx, len, k, interception, start_ppn);
#else
    return gen_segment_simple__(lpn_array, start_idx, len, start_ppn);
#endif
}


struct segment * gen_segment_original__(const unsigned int * lpn_array, int start_idx, int len, frac_fp k, frac_fp interception,unsigned int start_ppn) {
    struct segment * seg = MALLOC(sizeof (struct segment));
    seg->start_lpn = lpn_array[start_idx];
    seg->len = lpn_array[start_idx + len - 1] - lpn_array[start_idx];
    seg->slope = k;
    seg->valid_tag = 0;


    if(seg->slope.denominator == seg->slope.numerator) {
        seg->slope.denominator = 1;
        seg->slope.numerator = 1;
    }

    seg->intercept = interception;
    seg->next = NULL;



    int is_acc;
    is_acc = segment_acc_check(lpn_array, start_idx, len, seg, start_ppn) &&
             segment_seq_check(lpn_array, start_idx, len);

    seg->is_acc_seg = is_acc;
    if(!seg->is_acc_seg){
        seg->CRB = gen_CRB(lpn_array, start_idx, len);
    }
    return seg;
}

unsigned int cal_ppn(frac_fp slope, frac_fp intercept, unsigned int lpn) {
    unsigned int ret;
    ret = (unsigned int)(( (long long)intercept.denominator * (long long)slope.numerator * (long long)lpn
                           + (long long)intercept.numerator * (long long)slope.denominator) /
                         ((long long)intercept.denominator * (long long)slope.denominator));

    ret = (unsigned int)DM_ZFTL_DIV_ROUND_UP(((long long)intercept.denominator * (long long)slope.numerator * (long long)lpn
                                 + (long long)intercept.numerator * (long long)slope.denominator) ,
                               ((long long)intercept.denominator * (long long)slope.denominator) );
    //TODO: Use Div round up
    return ret;
}
int segment_acc_check(const unsigned int * lpn_array, int start_idx, int len, struct segment * seg,unsigned int start_ppn){
    int i;
    int acc = 1;
    for(i = start_idx; i < start_idx + len; i++){
        unsigned int calculate_ppn = cal_ppn(seg->slope, seg->intercept, lpn_array[i]);
        unsigned int ref_ppn = start_ppn + i - start_idx;
        int err = (int)((long)calculate_ppn  - (long)ref_ppn);
        err = err < 0 ? -err : err;

        if(err > ERROR_BOUND){
            printk(KERN_EMERG "Predict err, wanted:%u got:%u err:%u", ref_ppn, calculate_ppn, err);
        }

        if(ref_ppn != calculate_ppn)
            acc = 0;
    }
    return acc;
}
fp_t get_rho(point x, point y){
    fp_t deltaX = x.x - y.x;
    fp_t deltaY = x.y - y.y;
    return fp_div__(deltaY, deltaX);
}

point get_point_upper(point s0){
    struct point x;
    x.x = s0.x;
    x.y = s0.y + ERROR_BOUND;
    return x;
}

point get_point_lower(point s0){
    struct point x;
    x.x = s0.x;
    x.y = s0.y - ERROR_BOUND;
    return x;
}

line get_line(point s0, point s1){
    struct line l;
    l.s0 = s0;
    l.s1 = s1;
    l.fp_rho = get_rho(s0, s1);
    l.fp_b = l.s0.y - fp_mul__(l.fp_rho, l.s0.x);
    return l;
}

point get_intersection(line s0, line s1){
    struct point i;
    i.x = fp_div__(s1.fp_b - s0.fp_b, s0.fp_rho - s1.fp_rho);
    i.y = fp_div__(fp_mul__(s0.fp_rho, s1.fp_b) - fp_mul__(s1.fp_rho, s0.fp_b),
                   s0.fp_rho - s1.fp_rho);
    return i;
}
#else
struct segment * greedy_piecewise_linear_regression__(const unsigned int * lpn_array, int len, unsigned int start_ppn){
    enum {
        STATE_FIRST,
        STATE_SECOND,
        STATE_READY,
    } learning_state;

    struct segment ** seg_list = MALLOC(sizeof(struct segment *));
    *seg_list = NULL;
    int state = STATE_FIRST;
    int start_idx = 0, end_idx = 0, idx = 0;
    point curr;
    point s0, s1, cone_apex;
    line cone_upper, cone_lower;
    float curr_upper_rho = 0,curr_lower_rho = 0;
    int interception;
    while(idx < len){

        curr.x = lpn_array[idx];
        curr.y = start_ppn + idx;

        switch (state) {

            case STATE_FIRST:

                start_idx = idx;
                s0 = curr;
                state = STATE_SECOND;
                break;

            case STATE_SECOND:

                if(curr.x - s0.x >= DM_ZFTL_FRAME_LENGTH){
                    interception = s0.y - s0.x;
                    list_tail_add(seg_list,
                                  gen_segment(lpn_array, start_idx, 1, 1,
                                              interception, start_ppn + start_idx));

                    state = STATE_FIRST;
                    continue;

                }else{

                    s1 = curr;
                    cone_upper = get_line(get_point_lower(s0), get_point_upper(s1));
                    cone_lower = get_line(get_point_upper(s0), get_point_lower(s1));
                    cone_apex = get_intersection(cone_upper, cone_lower);
                    state = STATE_READY;

                }
                break;

            case STATE_READY:

                curr_upper_rho = get_rho(get_point_upper(curr),cone_apex);
                curr_lower_rho = get_rho(get_point_lower(curr), cone_apex);

                if( (curr.x - s0.x >= DM_ZFTL_FRAME_LENGTH) ||
                    (curr_upper_rho > cone_upper.rho)   ||
                    (curr_lower_rho < cone_lower.rho)    ){
                    float avg_rho = (cone_upper.rho + cone_lower.rho) / (float)2.0;
                    interception = (int)((float )- cone_apex.x * (float)avg_rho + (float )cone_apex.y);
                    list_tail_add(seg_list,
                                  gen_segment(lpn_array, start_idx, idx - start_idx, avg_rho, interception, start_ppn + start_idx));

                    state = STATE_FIRST;
                    continue;

                }else {

                    s1 = curr;

                    if(cone_upper.rho > curr_upper_rho){
                        cone_upper = get_line(cone_apex, get_point_upper(curr));
                    }

                    if(cone_lower.rho < curr_lower_rho){
                        cone_lower = get_line(cone_apex, get_point_lower(curr));
                    }

                }
                break;
        }
        idx++;
    }

    float avg_rho;
    switch (state) {
        case STATE_SECOND:
            interception = s0.y - s0.x;
            list_tail_add(seg_list,
                          gen_segment(lpn_array, start_idx, 1 , 1,
                                      interception, start_ppn + start_idx ));
            break;
        case STATE_READY:
            avg_rho = (cone_upper.rho + cone_lower.rho) / (float)2.0;
            interception = (int)((float )- cone_apex.x * (float)avg_rho + (float )cone_apex.y);
            list_tail_add(seg_list,
                          gen_segment(lpn_array, start_idx, idx - start_idx, avg_rho, interception, start_ppn + start_idx ));
            break;
        default:
            break;
    }

    struct segment * segs = *seg_list;
    FREE(seg_list);
    return segs;
}
struct segment * gen_segment(const unsigned int * lpn_array, int start_idx, unsigned int len, float k, int interception, int start_ppn){
#if DM_ZFTL_LEA_ORIGIN
    return gen_segment_original__(lpn_array, start_idx, len, k, interception, start_ppn);
#else
    return gen_segment_simple__(lpn_array, start_idx, len, start_ppn);
#endif
}
struct segment * gen_segment_original__(const unsigned int * lpn_array, int start_idx, unsigned int len, float k, int interception, int start_ppn){
    struct segment * seg = MALLOC(sizeof (struct segment));
    seg->start_lpn = lpn_array[start_idx];
    seg->len = lpn_array[start_idx + len - 1] - lpn_array[start_idx];
    seg->slope = k;
    seg->intercept = interception;
    seg->next = NULL;

    int is_acc;
    is_acc = segment_acc_check(lpn_array, start_idx, len, seg, start_ppn) &&
             segment_seq_check(lpn_array, start_idx, len);

    seg->is_acc_seg = is_acc;
    if(!seg->is_acc_seg){
        seg->CRB = gen_CRB(lpn_array, start_idx, len);
    }
    return seg;
}
int segment_acc_check(const unsigned int * lpn_array, int start_idx, int len, struct segment * seg, int start_ppn){
    int i;
    for(i = start_idx; i < start_idx + len; i++){
        int calculate_ppn = (int)(seg->slope * lpn_array[i] + seg->intercept);
        int ref_ppn = start_ppn + i - start_idx;
        if(ref_ppn != calculate_ppn)
            return 0;
    }
    return 1;
}
float get_rho(point x, point y){
    return (float )(y.y - x.y) / (float )(y.x - x.x);
}

point get_point_upper(point s0){
    struct point x = {.x=s0.x, .y=s0.y + ERROR_BOUND };
    return x;
}

point get_point_lower(point s0){
    struct point x = {.x=s0.x, .y=s0.y - ERROR_BOUND };
    return x;
}

line get_line(point s0, point s1){
    struct line l = {.s0 = s0, .s1 = s1, .rho = get_rho(s0, s1)};
    l.b = l.s0.y - l.s0.x * l.rho;
    return l;
}

point get_intersection(line s0, line s1){
//    p = (float(s2.b - s1.b) / (s1.k - s2.k),
//    float(s1.k * s2.b - s2.k * s1.b) / (s1.k - s2.k))
    struct point i = {
            .x = (float )(s1.b - s0.b) / (s0.rho - s1.rho),
            .y = (float )(s0.rho * s1.b - s1.rho * s0.b) / (s0.rho - s1.rho)
    };
    return i;
}
#endif
void lsm_tree_print_level(struct lsm_tree_level * level){
    struct segment * seg = level->seg;
    printk(KERN_EMERG "\n<level>");
    while(seg){
        if(seg->is_acc_seg) {
            printk(KERN_EMERG " [%llu %llu ] ", seg_start(seg), seg_end(seg));
        }
        else{
            printk(KERN_EMERG " [%llu %llu*] ", seg_start(seg), seg_end(seg));
        }
        seg = seg->next;
    }
    return;
}
void lsm_tree_print_frame(struct lsm_tree_frame * frame){
    if(!frame)
        return;
    if(!frame->level)
        return;
    struct segment * seg;
    struct lsm_tree_level * level = frame->level;
    int l_index = 0;
    while(level){
        lsm_tree_print_level(level);
        level = level->next_level;
    }
}


struct frame_valid_bitmap *get_seg_bm(struct segment * seg){
    struct frame_valid_bitmap * bm = MALLOC(sizeof(struct frame_valid_bitmap));
    int i;

    for(i = 0; i < DM_ZFTL_FRAME_LENGTH_BITS; ++i){
        bm->bitmap[i] = (unsigned char)0;
    }

    if(!seg)
        return NULL;

    if(seg->is_acc_seg){

        for(i = seg_start(seg); i <= seg_end(seg); ++i){
            bm->bitmap[(i % DM_ZFTL_FRAME_LENGTH) / 8] &= ((unsigned char )1 << ((i % DM_ZFTL_FRAME_LENGTH) % 8));
        }

    }else{

        for(i = 0; i < seg->CRB->buffer_len; ++i){
            bm->bitmap[(seg->CRB->lpn[i] % DM_ZFTL_FRAME_LENGTH) / 8]
            &= ((unsigned char )1 << ((seg->CRB->lpn[i] % DM_ZFTL_FRAME_LENGTH) % 8));
        }

    }
    return bm;
}

void lsm_tree_promote(struct lsm_tree * lsm_tree){
    int frame_no = 0;
    for(frame_no = 0; frame_no < lsm_tree->nr_frame; ++frame_no){
        lsm_tree_frame_promote__(&lsm_tree->frame[frame_no]);
    }
}



void lsm_tree_level_promote__(struct lsm_tree_level * upper_level, struct lsm_tree_level * lower_level){


    return;
}
void lsm_tree_frame_promote__(struct lsm_tree_frame * frame) {
    struct lsm_tree_level *level_array[MAX_PROMOTE_LAYER];
    int nr_level = 0;

    if(!frame)
        return;
    if(!frame->level)
        return;

    struct lsm_tree_level * level_ = frame->level;
    while(level_){
        if(nr_level == MAX_PROMOTE_LAYER)
            break;
        //do promote
        level_array[nr_level] = level_;
        nr_level++;
        level_ = level_->next_level;
    }

    if(nr_level < 10)
        return;

    int upper = 0;
    int lower = 0; //smaller is upper

    for(lower = 1; lower <= nr_level - 1; ++ lower){
            if(!level_array[lower])
                continue;
            //lsm_tree_level_promote__(level_array[upper], level_array[lower]);
            struct segment * seg = level_array[lower]->seg;
            struct segment * next = NULL;
            struct segment * pre = NULL;
            struct segment * detach_seg;

            while(seg){
                next = seg->next;

                int can_insert = 0;
                int insert_index = -1;

                for(upper = lower - 1; upper >= 0;  --upper){
                    if(!level_array[upper])
                        continue;
                    can_insert = lsm_tree_can_insert(level_array[upper], seg);
                    if(can_insert)
                        insert_index = upper;
                    else
                        break;
                }

                if(insert_index >= 0){
                    detach_seg = seg;

                    if(seg == level_array[lower]->seg)
                        level_array[lower]->seg = next;
                    else if(pre)
                        pre->next = next;
                    seg = next;
                    detach_seg->next = NULL;

                    lsm_tree_quick_insert_(level_array[insert_index], detach_seg);
                    continue;
                }

                pre = seg;
                seg = next;
            }


    }

    lsm_tree_clean_empty_level__(frame);
}

int lsm_tree_can_insert(struct lsm_tree_level * level, struct segment *insert_seg){
    if(!level)
        return 0;

    if(!insert_seg)
        return 0;

    if(!level->seg){
        return 1;
    }

    struct segment * curr = level->seg;
    if(seg_start(curr) > seg_end(insert_seg)){
        return 1;
    }

    while(curr){
        if(seg_end(curr) < seg_start(insert_seg)){
            struct segment * next = curr->next;
            if(!next){
                return 1;
            }
            if(seg_start(next) > seg_end(insert_seg)){
                return 1;
            }
        }
        curr = curr->next;
    }
    return 0;
}

int lsm_tree_quick_insert_(struct lsm_tree_level * level, struct segment *insert_seg){

    if(!insert_seg)
        return 0;

    if(!level->seg){
        level->seg = insert_seg;
        insert_seg->next = NULL;
        return 1;
    }

    struct segment * curr = level->seg;
    if(seg_start(curr) > seg_end(insert_seg)){
        level->seg = insert_seg;
        level->seg->next = curr;
        return 1;
    }

    while(curr){
        //                    /<--insert_seg-->/
        // /<---curr--->/                    /<---next--->/
        //
        if(seg_end(curr) < seg_start(insert_seg)){
            struct segment * next = curr->next;
            if(!next){
                insert_seg->next = curr->next;
                curr->next = insert_seg;
                return 1;
            }
            if(seg_start(next) > seg_end(insert_seg)){
                insert_seg->next = curr->next;
                curr->next = insert_seg;
                return 1;
            }
        }
        curr = curr->next;
    }
    return 0;
    //printf("Error can't insert into level after merge [%u, %u]",seg_start(insert_seg),seg_end(insert_seg));
}

void free_seg(struct segment * seg){
    if(!seg)
        return;

    if(seg->is_acc_seg){
        FREE(seg);
    }else{

        if(seg->CRB) {
            if(seg->CRB->lpn) {
                FREE(seg->CRB->lpn);
                seg->CRB->lpn = NULL;
            }
            FREE(seg->CRB);
            seg->CRB = NULL;
        }
        FREE(seg);
    }
}


// make sure max valid ppn no greadter than MAX + err_bound
unsigned int lsm_tree_predict_correct(unsigned int *p2l_table, unsigned int lpn, unsigned int predicted_ppn) {
    unsigned int predicted_lpn = p2l_table[predicted_ppn];
    if(predicted_lpn == lpn)
        return predicted_ppn;
    // o.w do localsearch
    unsigned int search_ppn;
    for(search_ppn = predicted_ppn - ERROR_BOUND; search_ppn <= predicted_ppn + ERROR_BOUND; ++search_ppn){
           if(p2l_table[search_ppn] == lpn)
               return search_ppn;
    }
    return DM_ZFTL_UNMAPPED_PPA;
}

#ifdef __cplusplus
}
#endif