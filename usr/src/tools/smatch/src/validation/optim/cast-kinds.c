typedef unsigned int uint;
typedef unsigned long ulong;

static int uint_2_int(uint a) { return (int)a; }
static int long_2_int(long a) { return (int)a; }
static int ulong_2_int(ulong a) { return (int)a; }
static int vptr_2_int(void *a) { return (int)a; }
static int iptr_2_int(int *a) { return (int)a; }
static int float_2_int(float a) { return (int)a; }
static int double_2_int(double a) { return (int)a; }
static uint int_2_uint(int a) { return (uint)a; }
static uint long_2_uint(long a) { return (uint)a; }
static uint ulong_2_uint(ulong a) { return (uint)a; }
static uint vptr_2_uint(void *a) { return (uint)a; }
static uint iptr_2_uint(int *a) { return (uint)a; }
static uint float_2_uint(float a) { return (uint)a; }
static uint double_2_uint(double a) { return (uint)a; }
static long int_2_long(int a) { return (long)a; }
static long uint_2_long(uint a) { return (long)a; }
static long ulong_2_long(ulong a) { return (long)a; }
static long vptr_2_long(void *a) { return (long)a; }
static long iptr_2_long(int *a) { return (long)a; }
static long float_2_long(float a) { return (long)a; }
static long double_2_long(double a) { return (long)a; }
static ulong int_2_ulong(int a) { return (ulong)a; }
static ulong uint_2_ulong(uint a) { return (ulong)a; }
static ulong long_2_ulong(long a) { return (ulong)a; }
static ulong vptr_2_ulong(void *a) { return (ulong)a; }
static ulong iptr_2_ulong(int *a) { return (ulong)a; }
static ulong float_2_ulong(float a) { return (ulong)a; }
static ulong double_2_ulong(double a) { return (ulong)a; }
static void * int_2_vptr(int a) { return (void *)a; }
static void * uint_2_vptr(uint a) { return (void *)a; }
static void * long_2_vptr(long a) { return (void *)a; }
static void * ulong_2_vptr(ulong a) { return (void *)a; }
static void * iptr_2_vptr(int *a) { return (void *)a; }
static int * int_2_iptr(int a) { return (int *)a; }
static int * uint_2_iptr(uint a) { return (int *)a; }
static int * long_2_iptr(long a) { return (int *)a; }
static int * ulong_2_iptr(ulong a) { return (int *)a; }
static int * vptr_2_iptr(void *a) { return (int *)a; }
static float int_2_float(int a) { return (float)a; }
static float uint_2_float(uint a) { return (float)a; }
static float long_2_float(long a) { return (float)a; }
static float ulong_2_float(ulong a) { return (float)a; }
static float double_2_float(double a) { return (float)a; }
static double int_2_double(int a) { return (double)a; }
static double uint_2_double(uint a) { return (double)a; }
static double long_2_double(long a) { return (double)a; }
static double ulong_2_double(ulong a) { return (double)a; }
static double float_2_double(float a) { return (double)a; }

static float float_2_float(float a) { return a; }
static double double_2_double(double a) { return a; }

/*
 * check-name: cast-kinds
 * check-command: test-linearize -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast -m64 $file
 * check-assert: sizeof(void *) == 8 && sizeof(long) == 8 && sizeof(double) == 8
 *
 * check-output-start
uint_2_int:
.L0:
	<entry-point>
	ret.32      %arg1


long_2_int:
.L2:
	<entry-point>
	trunc.32    %r4 <- (64) %arg1
	ret.32      %r4


ulong_2_int:
.L4:
	<entry-point>
	trunc.32    %r7 <- (64) %arg1
	ret.32      %r7


vptr_2_int:
.L6:
	<entry-point>
	trunc.32    %r10 <- (64) %arg1
	ret.32      %r10


iptr_2_int:
.L8:
	<entry-point>
	trunc.32    %r14 <- (64) %arg1
	ret.32      %r14


float_2_int:
.L10:
	<entry-point>
	fcvts.32    %r17 <- (32) %arg1
	ret.32      %r17


double_2_int:
.L12:
	<entry-point>
	fcvts.32    %r20 <- (64) %arg1
	ret.32      %r20


int_2_uint:
.L14:
	<entry-point>
	ret.32      %arg1


long_2_uint:
.L16:
	<entry-point>
	trunc.32    %r25 <- (64) %arg1
	ret.32      %r25


ulong_2_uint:
.L18:
	<entry-point>
	trunc.32    %r28 <- (64) %arg1
	ret.32      %r28


vptr_2_uint:
.L20:
	<entry-point>
	trunc.32    %r31 <- (64) %arg1
	ret.32      %r31


iptr_2_uint:
.L22:
	<entry-point>
	trunc.32    %r35 <- (64) %arg1
	ret.32      %r35


float_2_uint:
.L24:
	<entry-point>
	fcvtu.32    %r38 <- (32) %arg1
	ret.32      %r38


double_2_uint:
.L26:
	<entry-point>
	fcvtu.32    %r41 <- (64) %arg1
	ret.32      %r41


int_2_long:
.L28:
	<entry-point>
	sext.64     %r44 <- (32) %arg1
	ret.64      %r44


uint_2_long:
.L30:
	<entry-point>
	zext.64     %r47 <- (32) %arg1
	ret.64      %r47


ulong_2_long:
.L32:
	<entry-point>
	ret.64      %arg1


vptr_2_long:
.L34:
	<entry-point>
	ret.64      %arg1


iptr_2_long:
.L36:
	<entry-point>
	ret.64      %arg1


float_2_long:
.L38:
	<entry-point>
	fcvts.64    %r57 <- (32) %arg1
	ret.64      %r57


double_2_long:
.L40:
	<entry-point>
	fcvts.64    %r60 <- (64) %arg1
	ret.64      %r60


int_2_ulong:
.L42:
	<entry-point>
	sext.64     %r63 <- (32) %arg1
	ret.64      %r63


uint_2_ulong:
.L44:
	<entry-point>
	zext.64     %r66 <- (32) %arg1
	ret.64      %r66


long_2_ulong:
.L46:
	<entry-point>
	ret.64      %arg1


vptr_2_ulong:
.L48:
	<entry-point>
	ret.64      %arg1


iptr_2_ulong:
.L50:
	<entry-point>
	ret.64      %arg1


float_2_ulong:
.L52:
	<entry-point>
	fcvtu.64    %r76 <- (32) %arg1
	ret.64      %r76


double_2_ulong:
.L54:
	<entry-point>
	fcvtu.64    %r79 <- (64) %arg1
	ret.64      %r79


int_2_vptr:
.L56:
	<entry-point>
	sext.64     %r82 <- (32) %arg1
	ret.64      %r82


uint_2_vptr:
.L58:
	<entry-point>
	zext.64     %r85 <- (32) %arg1
	ret.64      %r85


long_2_vptr:
.L60:
	<entry-point>
	ret.64      %arg1


ulong_2_vptr:
.L62:
	<entry-point>
	ret.64      %arg1


iptr_2_vptr:
.L64:
	<entry-point>
	ret.64      %arg1


int_2_iptr:
.L66:
	<entry-point>
	sext.64     %r94 <- (32) %arg1
	ret.64      %r94


uint_2_iptr:
.L68:
	<entry-point>
	zext.64     %r98 <- (32) %arg1
	ret.64      %r98


long_2_iptr:
.L70:
	<entry-point>
	ret.64      %arg1


ulong_2_iptr:
.L72:
	<entry-point>
	ret.64      %arg1


vptr_2_iptr:
.L74:
	<entry-point>
	ptrcast.64  %r108 <- (64) %arg1
	ret.64      %r108


int_2_float:
.L76:
	<entry-point>
	scvtf.32    %r111 <- (32) %arg1
	ret.32      %r111


uint_2_float:
.L78:
	<entry-point>
	ucvtf.32    %r114 <- (32) %arg1
	ret.32      %r114


long_2_float:
.L80:
	<entry-point>
	scvtf.32    %r117 <- (64) %arg1
	ret.32      %r117


ulong_2_float:
.L82:
	<entry-point>
	ucvtf.32    %r120 <- (64) %arg1
	ret.32      %r120


double_2_float:
.L84:
	<entry-point>
	fcvtf.32    %r123 <- (64) %arg1
	ret.32      %r123


int_2_double:
.L86:
	<entry-point>
	scvtf.64    %r126 <- (32) %arg1
	ret.64      %r126


uint_2_double:
.L88:
	<entry-point>
	ucvtf.64    %r129 <- (32) %arg1
	ret.64      %r129


long_2_double:
.L90:
	<entry-point>
	scvtf.64    %r132 <- (64) %arg1
	ret.64      %r132


ulong_2_double:
.L92:
	<entry-point>
	ucvtf.64    %r135 <- (64) %arg1
	ret.64      %r135


float_2_double:
.L94:
	<entry-point>
	fcvtf.64    %r138 <- (32) %arg1
	ret.64      %r138


float_2_float:
.L96:
	<entry-point>
	ret.32      %arg1


double_2_double:
.L98:
	<entry-point>
	ret.64      %arg1


 * check-output-end
 */
