typedef unsigned int uint;
typedef unsigned long ulong;

static int * int_2_iptr(int a) { return (int *)a; }
static int * uint_2_iptr(uint a) { return (int *)a; }

static void * int_2_vptr(int a) { return (void *)a; }
static void * uint_2_vptr(uint a) { return (void *)a; }

/*
 * check-name: cast-weirds
 * check-command: sparse -m64 $file
 * check-assert: sizeof(void *) == 8
 *
 * check-error-start
cast-weirds.c:4:48: warning: non size-preserving integer to pointer cast
cast-weirds.c:5:50: warning: non size-preserving integer to pointer cast
 * check-error-end
 */
