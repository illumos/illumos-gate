# Updating Error Number Translations

To create an updated error number translation table, you can use the
`gen_errno` tool.  This tool requires, as input:

* the illumos native `errno.h` file
* a set of foreign operating system `errno.h` files

The output is a set of translation table entries suitable for inclusion in a
cstyled C array.  The index of the array is the native error number and the
value at each index is the translated error number for use with the foreign
operating system.

## Example

To generate a translation table for the LX Brand, you will require two files
from the current Linux source:

* `include/uapi/asm-generic/errno-base.h` (low-valued, or base, error numbers)
* `include/uapi/asm-generic/errno.h` (extended error numbers)

Assuming the files are in the current directory, you should run the tool as
follows:

    $ dmake
    ...
    $ ./gen_errno -F errno-base.h -F errno.h \
                  -N $SRC/uts/common/sys/errno.h
    0, /*  0: No Error                            */
    1, /*  1: EPERM       -->   1: EPERM          */
    2, /*  2: ENOENT      -->   2: ENOENT         */
    3, /*  3: ESRCH       -->   3: ESRCH          */
    4, /*  4: EINTR       -->   4: EINTR          */
    5, /*  5: EIO         -->   5: EIO            */
    6, /*  6: ENXIO       -->   6: ENXIO          */
    7, /*  7: E2BIG       -->   7: E2BIG          */
    ...

The output may be used in the `$SRC/common/brand/lx/lx_errno.c` file.
