typedef unsigned int uint;
typedef unsigned long ulong;

static int uint_2_int(void) { return (int)123U; }
static int long_2_int(void) { return (int)123L; }
static int ulong_2_int(void) { return (int)123UL; }
static int vptr_2_int(void) { return (int)((void*)123); }
static int iptr_2_int(void) { return (int)((int*)128); }
static int float_2_int(void) { return (int)1.123F; }
static int double_2_int(void) { return (int)1.123L; }
static uint int_2_uint(void) { return (uint)123; }
static uint long_2_uint(void) { return (uint)123L; }
static uint ulong_2_uint(void) { return (uint)123UL; }
static uint vptr_2_uint(void) { return (uint)((void*)123); }
static uint iptr_2_uint(void) { return (uint)((int*)128); }
static uint float_2_uint(void) { return (uint)1.123F; }
static uint double_2_uint(void) { return (uint)1.123L; }
static long int_2_long(void) { return (long)123; }
static long uint_2_long(void) { return (long)123U; }
static long ulong_2_long(void) { return (long)123UL; }
static long vptr_2_long(void) { return (long)((void*)123); }
static long iptr_2_long(void) { return (long)((int*)128); }
static long float_2_long(void) { return (long)1.123F; }
static long double_2_long(void) { return (long)1.123L; }
static ulong int_2_ulong(void) { return (ulong)123; }
static ulong uint_2_ulong(void) { return (ulong)123U; }
static ulong long_2_ulong(void) { return (ulong)123L; }
static ulong vptr_2_ulong(void) { return (ulong)((void*)123); }
static ulong iptr_2_ulong(void) { return (ulong)((int*)128); }
static ulong float_2_ulong(void) { return (ulong)1.123F; }
static ulong double_2_ulong(void) { return (ulong)1.123L; }
static void * int_2_vptr(void) { return (void *)123; }
static void * uint_2_vptr(void) { return (void *)123U; }
static void * long_2_vptr(void) { return (void *)123L; }
static void * ulong_2_vptr(void) { return (void *)123UL; }
static void * iptr_2_vptr(void) { return (void *)((int*)128); }
static int * int_2_iptr(void) { return (int *)123; }
static int * uint_2_iptr(void) { return (int *)123U; }
static int * long_2_iptr(void) { return (int *)123L; }
static int * ulong_2_iptr(void) { return (int *)123UL; }
static int * vptr_2_iptr(void) { return (int *)((void*)123); }
static float int_2_float(void) { return (float)123; }
static float uint_2_float(void) { return (float)123U; }
static float long_2_float(void) { return (float)123L; }
static float ulong_2_float(void) { return (float)123UL; }
static float double_2_float(void) { return (float)1.123L; }
static double int_2_double(void) { return (double)123; }
static double uint_2_double(void) { return (double)123U; }
static double long_2_double(void) { return (double)123L; }
static double ulong_2_double(void) { return (double)123UL; }
static double float_2_double(void) { return (double)1.123F; }

/*
 * check-name: cast-constants.c
 * check-command: test-linearize -m64 $file
 * check-assert: sizeof(void *) == 8 && sizeof(long) == 8 && sizeof(double) == 8
 *
 * check-output-start
uint_2_int:
.L0:
	<entry-point>
	ret.32      $123


long_2_int:
.L2:
	<entry-point>
	ret.32      $123


ulong_2_int:
.L4:
	<entry-point>
	ret.32      $123


vptr_2_int:
.L6:
	<entry-point>
	ret.32      $123


iptr_2_int:
.L8:
	<entry-point>
	ret.32      $128


float_2_int:
.L10:
	<entry-point>
	ret.32      $1


double_2_int:
.L12:
	<entry-point>
	ret.32      $1


int_2_uint:
.L14:
	<entry-point>
	ret.32      $123


long_2_uint:
.L16:
	<entry-point>
	ret.32      $123


ulong_2_uint:
.L18:
	<entry-point>
	ret.32      $123


vptr_2_uint:
.L20:
	<entry-point>
	ret.32      $123


iptr_2_uint:
.L22:
	<entry-point>
	ret.32      $128


float_2_uint:
.L24:
	<entry-point>
	ret.32      $1


double_2_uint:
.L26:
	<entry-point>
	ret.32      $1


int_2_long:
.L28:
	<entry-point>
	ret.64      $123


uint_2_long:
.L30:
	<entry-point>
	ret.64      $123


ulong_2_long:
.L32:
	<entry-point>
	ret.64      $123


vptr_2_long:
.L34:
	<entry-point>
	ret.64      $123


iptr_2_long:
.L36:
	<entry-point>
	ret.64      $128


float_2_long:
.L38:
	<entry-point>
	ret.64      $1


double_2_long:
.L40:
	<entry-point>
	ret.64      $1


int_2_ulong:
.L42:
	<entry-point>
	ret.64      $123


uint_2_ulong:
.L44:
	<entry-point>
	ret.64      $123


long_2_ulong:
.L46:
	<entry-point>
	ret.64      $123


vptr_2_ulong:
.L48:
	<entry-point>
	ret.64      $123


iptr_2_ulong:
.L50:
	<entry-point>
	ret.64      $128


float_2_ulong:
.L52:
	<entry-point>
	ret.64      $1


double_2_ulong:
.L54:
	<entry-point>
	ret.64      $1


int_2_vptr:
.L56:
	<entry-point>
	ret.64      $123


uint_2_vptr:
.L58:
	<entry-point>
	ret.64      $123


long_2_vptr:
.L60:
	<entry-point>
	ret.64      $123


ulong_2_vptr:
.L62:
	<entry-point>
	ret.64      $123


iptr_2_vptr:
.L64:
	<entry-point>
	ret.64      $128


int_2_iptr:
.L66:
	<entry-point>
	ret.64      $123


uint_2_iptr:
.L68:
	<entry-point>
	ret.64      $123


long_2_iptr:
.L70:
	<entry-point>
	ret.64      $123


ulong_2_iptr:
.L72:
	<entry-point>
	ret.64      $123


vptr_2_iptr:
.L74:
	<entry-point>
	ret.64      $123


int_2_float:
.L76:
	<entry-point>
	setfval.32  %r39 <- 1.230000e+02
	ret.32      %r39


uint_2_float:
.L78:
	<entry-point>
	setfval.32  %r41 <- 1.230000e+02
	ret.32      %r41


long_2_float:
.L80:
	<entry-point>
	setfval.32  %r43 <- 1.230000e+02
	ret.32      %r43


ulong_2_float:
.L82:
	<entry-point>
	setfval.32  %r45 <- 1.230000e+02
	ret.32      %r45


double_2_float:
.L84:
	<entry-point>
	setfval.32  %r47 <- 1.123000e+00
	ret.32      %r47


int_2_double:
.L86:
	<entry-point>
	setfval.64  %r49 <- 1.230000e+02
	ret.64      %r49


uint_2_double:
.L88:
	<entry-point>
	setfval.64  %r51 <- 1.230000e+02
	ret.64      %r51


long_2_double:
.L90:
	<entry-point>
	setfval.64  %r53 <- 1.230000e+02
	ret.64      %r53


ulong_2_double:
.L92:
	<entry-point>
	setfval.64  %r55 <- 1.230000e+02
	ret.64      %r55


float_2_double:
.L94:
	<entry-point>
	setfval.64  %r57 <- 1.123000e+00
	ret.64      %r57


 * check-output-end
 */
