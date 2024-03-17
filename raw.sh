dd if=./Test of=/dev/mapper/ZFTL
dd if=/dev/mapper/ZFTL of=Test.out
diff ./Test ./Test.out