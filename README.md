# dm-LZFTL:A Learned-based Host-side FTL for ZNS SSDs

## Introduction
dm-LZFTL provides a Host-side FTL framework for ZNS SSD, which is mainly based on dm-zoned and Alibaba & Intel's CSAL(Cloud Storage Acceleration Layer).
dm-LZFTL will shape small indirect unit(<=4K) random writes into large IU(>=64k), seq write, which is best suitable for zns ssd.dm-LZFTL maintain a 4k block size level L2P mapping table in DRAM, and since this framework is mainly used to verify FTL and hot/cold seperation on such a FTL, it dosen't has a swap in/out machinism for mapping table and power-fail-safe support.
 
