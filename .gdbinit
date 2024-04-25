set print pretty on
add-auto-load-safe-path /home/log/Desktop/dm-LZFTL
add-auto-load-safe-path /home/log/Desktop/linux-5.10.209
target remote :1234
add-symbol-file dm-zftl.ko 0xffffffffa1410000


