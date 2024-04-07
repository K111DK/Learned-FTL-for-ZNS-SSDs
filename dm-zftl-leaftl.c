#ifdef __cplusplus
extern "C" {
#endif
#include "dm-zftl-leaftl.h"



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

    //Only one seg in level
    if(curr == NULL){
        if(lsm_tree_is_seg_overlap_(prev, insert_seg)){
            int merge_state = lsm_tree_try_merge_seg_(prev, insert_seg);
            if(merge_state == PUSH_DOWN || merge_state == DEL_SEG){
                level->seg = insert_seg;
                insert_seg->next = NULL;
                prev->next = NULL;
                if(merge_state == PUSH_DOWN)
                    return prev;
                else
                    FREE(prev);
            }
        }
        prev->next = insert_seg;
        insert_seg->next = NULL;
        return NULL;
    }


    prev = NULL;
    curr = level->seg;
    struct segment ** overlap_seg_list = MALLOC(sizeof(struct segment *));
    *overlap_seg_list = NULL;
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
                    FREE(detach_seg);

                continue;
            }

        }

        prev = curr;
        curr = curr->next;
    }

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

void lsm_tree_quick_insert_(struct lsm_tree_level * level, struct segment *insert_seg){

    if(!insert_seg)
        return;

    if(!level->seg){
        level->seg = insert_seg;
        insert_seg->next = NULL;
        return;
    }

    struct segment * curr = level->seg;
    if(seg_start(curr) >= seg_end(insert_seg)){
        level->seg = insert_seg;
        level->seg->next = curr;
        return;
    }

    while(curr){
        //                    /<--insert_seg-->/
        // /<---curr--->/                    /<---next--->/
        //
        if(seg_end(curr) <= seg_start(insert_seg)){
            struct segment * next = curr->next;
            if(!next){
                insert_seg->next = curr->next;
                curr->next = insert_seg;
                return;
            }
            if(seg_start(next) >= seg_end(insert_seg)){
                insert_seg->next = curr->next;
                curr->next = insert_seg;
                return;
            }
        }
        curr = curr->next;
    }
    //printf("Error can't insert into level after merge [%u, %u]",seg_start(insert_seg),seg_end(insert_seg));
}
/*
 *
 * Merge two segment
 *
 * */
int lsm_tree_try_merge_seg_(struct segment *origin_seg,
                                           struct segment *insert_seg){

    if(seg_start(insert_seg) <= seg_start(origin_seg) &&
       seg_end(insert_seg) >= seg_end(origin_seg) && insert_seg->is_acc_seg)
        return DEL_SEG;

    if(insert_seg->is_acc_seg && origin_seg->is_acc_seg){
        if(seg_start(origin_seg) <= seg_start(insert_seg) && seg_end(origin_seg) >= seg_start(insert_seg)){
            origin_seg->len -= (seg_end(origin_seg) - seg_start(insert_seg) + 1);
            return SAME_LEVEL;
        }else if(seg_start(origin_seg) >= seg_start(insert_seg) && seg_start(origin_seg) <= seg_end(insert_seg)){
            origin_seg->len -= (seg_end(insert_seg) - seg_start(origin_seg) + 1);
            origin_seg->start_lpn = seg_end(origin_seg) + 1;
            return  SAME_LEVEL;
        }
    }

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

                lsm_tree->look_up_hist[look_up] += 1;
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
                    lsm_tree->look_up_hist[look_up] += 1;
                    return ppn;
                }
            }
        }

        level = level->next_level;
    }
    UNMAPPED:
    return ~((unsigned int )0);
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
        return lpn - seg->start_lpn + seg->intercept;
    else
        return lsm_tree_CRB_search_lpn_(seg->CRB, lpn) + seg->intercept;
}

/* Dose this type safe ?*/
unsigned int lsm_tree_cal_ppn_original__(struct segment * seg,
                                         unsigned int lpn){
#if DM_ZFTL_FP_EMU
    fp_t t;
    t = LOAD_INT(ROUND(fp_mul__(seg->slope,TO_FP((long long int)lpn)) + seg->intercept));
    return t;
#else
    return seg->slope * lpn + seg->intercept;
#endif
}

void lsm_tree_update(struct lsm_tree * lsm_tree, unsigned int * lpn_array, int len, unsigned int start_ppn){
    int i = 0;
    int pre_index = 0;
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
}

struct segment * Regression(unsigned int * lpn_array, int len, unsigned int start_ppn){
    return greedy_piecewise_linear_regression__(lpn_array, len, start_ppn);
}


struct segment * gen_segment_simple__(const unsigned int * lpn_array, int start_idx, int len, int start_ppn){
    struct segment * seg = MALLOC(sizeof (struct segment));
    seg->start_lpn = lpn_array[start_idx];
    seg->len = lpn_array[start_idx + len - 1] - lpn_array[start_idx];;
    seg->next = NULL;
    seg->intercept = start_ppn;
    seg->intercept = start_ppn;
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
    CRB->buffer_len = len;
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
        i = 0;
        while(i < seg->len){
            lpn = seg->start_lpn + i;
            bm->bitmap[(lpn % DM_ZFTL_FRAME_LENGTH) / 8] |= ((unsigned char )1 << ((lpn % DM_ZFTL_FRAME_LENGTH) % 8));
            i++;
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
    return bm->bitmap[(idx % DM_ZFTL_FRAME_LENGTH) / 8] &= ((unsigned char )1 << ((idx % DM_ZFTL_FRAME_LENGTH) % 8));
}


//TODO:check bit op
void dm_zftl_bitmap_set(struct frame_valid_bitmap *bm, unsigned int idx, int val){
    if(val){
        bm->bitmap[(idx % DM_ZFTL_FRAME_LENGTH) / 8] |= ((unsigned char )1 << ((idx % DM_ZFTL_FRAME_LENGTH) % 8));
    }else{
        bm->bitmap[(idx % DM_ZFTL_FRAME_LENGTH) / 8] &= ((unsigned char )1 << ((idx % DM_ZFTL_FRAME_LENGTH) % 8));
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

    unsigned int before_size = lsm_tree_get_frame_size__(frame);

    struct frame_valid_bitmap * upper_level_bm = get_level_bitmap(level);
    struct frame_valid_bitmap * curr_level_bm;
    while(level->next_level){
        level = level->next_level;
        lsm_tree_level_compact__(level, upper_level_bm);
        FREE(upper_level_bm);
        curr_level_bm = get_level_bitmap(level);
        upper_level_bm = dm_zftl_bitmap_or(curr_level_bm, upper_level_bm);
    }

    //Remove empty levels
    lsm_tree_clean_empty_level__(frame);

    unsigned int after_size = lsm_tree_get_frame_size__(frame);

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

void lsm_tree_level_compact__(struct lsm_tree_level * level, struct frame_valid_bitmap * bm){
    struct segment * seg = level->seg;
    struct segment * pre_seg = NULL;
    if(!seg)
        return;
    int cover_state;
    while(seg){

        cover_state = lsm_tree_seg_compact__(seg, bm);

        //Remove those segments whose lpns were fully cover by upper layer valid lpns
        if(cover_state == FULLY_COVER){
            if(pre_seg == NULL){
                level->seg = seg->next;
                FREE(seg);
                pre_seg = NULL;
                seg = level->seg;
            }else{
                pre_seg->next = seg->next;
                FREE(seg);
                seg = pre_seg->next;
            }
            continue;
        }

        pre_seg = seg;
        seg = seg->next;
    }
}
//TODO:Change it
int lsm_tree_seg_compact__(struct segment * seg, struct frame_valid_bitmap *bm){
    int i;
    unsigned int lpn, valid;
    if(seg->is_acc_seg){
        i = 0;
        while(i < seg->len){
            lpn = seg->start_lpn + i;
            valid = bm->bitmap[(lpn % DM_ZFTL_FRAME_LENGTH) / 8] & (unsigned char)((unsigned char)1 << (lpn % 8));
            if(!valid){
                //Bm doesn't cover this lpn
                return PARTIAL_COVER;
            }
            i++;
        }
        return 0;
    }else{
        i = 0;
        while(i < seg->CRB->buffer_len){
            lpn = seg->CRB->lpn[i];
            valid = bm->bitmap[(lpn % DM_ZFTL_FRAME_LENGTH) / 8] & (unsigned char)((unsigned char)1 << (lpn % 8));
            if(!valid){
                //Bm doesn't cover this lpn
                return PARTIAL_COVER;
            }
            i++;
        }
    }
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

void lsm_tree_promote(struct lsm_tree * lsm_tree);
void lsm_tree_frame_promote__(struct lsm_tree_frame * frame);

#if DM_ZFTL_FP_EMU
fp_t fp_div__(fp_t a, fp_t b)
{
    return (a << FSHIFT) / b;
}

fp_t fp_mul__(fp_t a, fp_t b)
{
    return (a * b) >> FSHIFT;
}

struct segment * greedy_piecewise_linear_regression__(const unsigned int * lpn_array, unsigned int len, unsigned int start_ppn) {
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
    fp_t curr_upper_rho = 0, curr_lower_rho = 0;
    fp_t interception;
    while(idx < len){

        curr.x = TO_FP(lpn_array[idx]);
        curr.y = TO_FP(start_ppn + idx);

        switch (state) {

            case STATE_FIRST:

                start_idx = idx;
                s0 = curr;
                state = STATE_SECOND;
                break;

            case STATE_SECOND:

                if(LOAD_INT(curr.x - s0.x) >= DM_ZFTL_FRAME_LENGTH){
                    interception = s0.y - s0.x;
                    list_tail_add(seg_list,
                                  gen_segment(lpn_array, start_idx, 1,TO_FP(1),
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

                if( (LOAD_INT(curr.x - s0.x) >=DM_ZFTL_FRAME_LENGTH) ||
                    (curr_upper_rho > cone_upper.fp_rho)   ||
                    (curr_lower_rho < cone_lower.fp_rho)    ){
                    fp_t avg_rho = fp_div__(cone_upper.fp_rho + cone_lower.fp_rho,TO_FP(2));
                    interception = cone_apex.y - fp_mul__(cone_apex.x, avg_rho);
                    list_tail_add(seg_list,
                                  gen_segment(lpn_array, start_idx, idx - start_idx, avg_rho, interception, start_ppn + start_idx));

                    state = STATE_FIRST;
                    continue;

                }else {

                    s1 = curr;

                    if(cone_upper.fp_rho > curr_upper_rho){
                        cone_upper = get_line(cone_apex, get_point_upper(curr));
                    }

                    if(cone_lower.fp_rho < curr_lower_rho){
                        cone_lower = get_line(cone_apex, get_point_lower(curr));
                    }

                }
                break;
        }
        idx++;
    }

    fp_t avg_rho;
    switch (state) {
        case STATE_SECOND:
            interception = s0.y - s0.x;
            list_tail_add(seg_list,
                          gen_segment(lpn_array, start_idx, 1,TO_FP(1),
                                      interception, start_ppn + start_idx));
            break;
        case STATE_READY:
            avg_rho = fp_div__(cone_upper.fp_rho + cone_lower.fp_rho,TO_FP(2));
            interception = cone_apex.y - fp_mul__(cone_apex.x, avg_rho);
            list_tail_add(seg_list,
                          gen_segment(lpn_array, start_idx, idx - start_idx, avg_rho, interception, start_ppn + start_idx));
            break;
        default:
            break;
    }

    struct segment * segs = *seg_list;
    FREE(seg_list);
    return segs;
}
struct segment * gen_segment(const unsigned int * lpn_array, int start_idx, unsigned int len, fp_t k, fp_t interception, int start_ppn){
#if DM_ZFTL_LEA_ORIGIN
    return gen_segment_original__(lpn_array, start_idx, len, k, interception, start_ppn);
#else
    return gen_segment_simple__(lpn_array, start_idx, len, start_ppn);
#endif
}


struct segment * gen_segment_original__(const unsigned int * lpn_array, int start_idx, unsigned int len, fp_t k, fp_t interception, int start_ppn) {
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

unsigned int cal_ppn(fp_t slope, fp_t intercept, unsigned int lpn) {
    return LOAD_INT(ROUND(fp_mul__(slope,TO_FP(lpn)) + intercept));
}
int segment_acc_check(const unsigned int * lpn_array, int start_idx, int len, struct segment * seg, int start_ppn){
    int i;
    for(i = start_idx; i < start_idx + len; i++){
        unsigned int calculate_ppn = cal_ppn(seg->slope, seg->intercept, lpn_array[i]);
        unsigned int ref_ppn = start_ppn + i - start_idx;
         if(ref_ppn != calculate_ppn)
            return 0;
    }
    return 1;
}
fp_t get_rho(point x, point y){
    fp_t deltaX = x.x - y.x;
    fp_t deltaY = x.y - y.y;
    return fp_div__(deltaY, deltaX);
}

point get_point_upper(point s0){
    struct point x;
    x.x = s0.x;
    x.y = s0.y + TO_FP(ERROR_BOUND);
    return x;
}

point get_point_lower(point s0){
    struct point x;
    x.x = s0.x;
    x.y = s0.y - TO_FP(ERROR_BOUND);
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

void lsm_tree_print_frame(struct lsm_tree_frame * frame){
    if(!frame)
        return;
    if(!frame->level)
        return;
    struct segment * seg;
    struct lsm_tree_level * level = frame->level;
    int l_index = 0;
    while(level){
        seg = level->seg;
        printk(KERN_EMERG "\n<level %d>\n", l_index);
        while(seg){
            if(seg->is_acc_seg) {
                printk(KERN_EMERG
                "\n[%llu %llu  <%llu>acc]\n", seg_start(seg), seg_end(seg), seg->intercept);
            }
            else{
                printk(KERN_EMERG
                "\n[%llu %llu  <%llu>appro]\n", seg_start(seg), seg_end(seg), seg->intercept);
            }
            seg = seg->next;
        }
        l_index++;
        level = level->next_level;
    }
}

#ifdef __cplusplus
}
#endif