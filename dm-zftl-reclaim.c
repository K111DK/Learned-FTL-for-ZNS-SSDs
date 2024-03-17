//
// Created by root on 3/14/24.
//
#include "dm-zftl.h"
//*
// *  bdev_zoned_model(bdev) == BLK_ZONED_NONE
// *	Updates the current zones wp and if nessesary the dmzap_zone_wp
// */
//void dm_zftl_update_seq_wp(struct zoned_dev * dev, sector_t bio_sectors)
//{
//    u32 i = 0;
//    u32 current_zone = 0;
//    struct zone_info * zone = dev->zoned_metadata->opened_zoned;
//    sector_t zone_nr_sec = dev->zone_nr_sectors;
//
//    zone->wp += bio_sectors;
//    int ret = 0;
//
//    if (zone->wp >= zone->id * zone_nr_sec + zone_nr_sec) {
//        //TODO ZNS capacity: if (zone->wp >= zone->start + zone->capacity) {
//        //TODO figure out how to finish the zone.
//        // ret = blkdev_zone_mgmt(dmzap->dev->bdev, REQ_OP_ZONE_FINISH,
//        //  					 zone->start, dmzap->dev->zone_nr_sectors, GFP_NOIO);
//        // if(ret){
//        // 	dmz_dev_err(dmzap->dev, "Zone finish failed! Return value: %d", ret);
//        // 	return;
//        // }
//#if DM_ZFTL_DEBUG_WRITE
//        printk(KERN_EMERG "Zone %ld Full", zone->id);
//#endif
//        dm_zftl_zone_close(dev, zone->id);
//        ret = dm_zftl_open_new_zone(dev);
//        if(ret){
//            printk(KERN_EMERG "Error: can't alloc free zone");
//        }
//    }
//}