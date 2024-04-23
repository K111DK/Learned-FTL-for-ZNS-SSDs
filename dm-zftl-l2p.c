//
// Created by root on 4/13/24.
//
#include "dm-zftl.h"
void dm_zftl_lsm_tree_try_compact(struct dm_zftl_target * dm_zftl){
    if((dm_zftl->last_compact_traffic_ >= DM_ZFTL_COMPACT_INTERVAL) && DM_ZFTL_COMPACT_ENABLE){

#if DM_ZFTL_COMPACT_DEBUG
        printk(KERN_EMERG "[Compact] Trigger Compact");
#endif

        dm_zftl->last_compact_traffic_ = 0;
        struct dm_zftl_compact_work * _work = kmalloc(sizeof(struct dm_zftl_compact_work), GFP_NOIO);
        _work->target = dm_zftl;
        INIT_WORK(&_work->work, dm_zftl_compact_work);
        queue_work(dm_zftl->lsm_tree_compact_wq, &_work->work);
    }

}

void dm_zftl_compact_work(struct work_struct *work){
    struct dm_zftl_compact_work * _work = container_of(work, struct dm_zftl_compact_work, work);
    struct dm_zftl_target * dm_zftl = _work->target;
    mutex_lock(&dm_zftl->mapping_table->l2p_lock);
    lsm_tree_compact(dm_zftl->mapping_table->lsm_tree);
    lsm_tree_promote(dm_zftl->mapping_table->lsm_tree);
    mutex_unlock(&dm_zftl->mapping_table->l2p_lock);
}
//EXPORT_SYMBOL(dm_zftl_try_l2p_pin);
//EXPORT_SYMBOL(dm_zftl_get);
//EXPORT_SYMBOL(dm_zftl_unpin_frame);
//EXPORT_SYMBOL(dm_zftl_init_mapping_table);
//EXPORT_SYMBOL(dm_zftl_ppn_is_valid);
//EXPORT_SYMBOL(dm_zftl_l2p_set_init);
//EXPORT_SYMBOL(dm_zftl_get_lpn_frame);
//EXPORT_SYMBOL(dm_zftl_update_mapping_by_lpn_array);
//EXPORT_SYMBOL(dm_zftl_update_mapping_cache);
