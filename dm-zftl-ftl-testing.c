//
// Created by login on 2024/3/26.
//
#include "dm-zftl-leaftl.h"
#include "dm-zftl-fixedpoint-math.h"
#define MB 256 // nr of 4-KB block
#define GB (1024 * MB)
#define TB (1024 * GB)
#define CAPACITY (2 * TB)

//unsigned int l2p_reference_table[CAPACITY];
//unsigned int p2l_table[CAPACITY];
//void Test1();
//int main() {
//    Test1();
//    return 0;
//}
//
//  /31-34/ /60-63/ /90-95/
//      /33 - 133/
//
//void Test1(){
//    static unsigned int First_inserts[] =
//            {
//             112200,130000 };
//    unsigned int wp = 1122900;
//    unsigned int len = 2;
//    struct lsm_tree * lsm_tree = lsm_tree_init(CAPACITY);
//    lsm_tree_update(lsm_tree, First_inserts, len, wp);
//    //;
//    ASSETR_UINT_EQ( 1122900,lsm_tree_get_ppn(lsm_tree, 112200), "lsm tree get1");
//    ASSETR_UINT_EQ( 1122901,lsm_tree_get_ppn(lsm_tree, 130000), "lsm tree get2");
//    return;
//}