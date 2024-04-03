// 相当于 N，11 位二进制定点数

#pragma once
#define fp_t long long int
#define FSHIFT  18   /* nr of bits of precision */
// 用 (1 << N) 表示逻辑上的 1
// 相当于 __to_FP(1)
#define FIXED_1    ( 1 << FSHIFT )  /* 1.0 as fixed-point */
#define TO_FP(x) ( (x) << FSHIFT )
//#define FIXED_1/200

#define LOAD_INT(x) ((x) >> FSHIFT)

//固定保留小数点后2位

#define LOAD_FRAC(x) LOAD_INT( ((x) & (FIXED_1-1)) * 100 )
#define ROUND(x) ( x + FIXED_1 / 200 )
fp_t fp_div__(fp_t a, fp_t b);
fp_t fp_mul__(fp_t a, fp_t b);


