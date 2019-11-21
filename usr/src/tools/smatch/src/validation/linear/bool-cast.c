extern int fun(void);
typedef unsigned int	u32;
typedef          int	s32;
typedef void *vdp;
typedef int  *sip;
typedef double dbl;
typedef unsigned short __attribute__((bitwise)) le16;

static _Bool fs32_i(s32 a) { return a; }
static _Bool fs32_e(s32 a) { return (_Bool)a; }
static _Bool fu32_i(u32 a) { return a; }
static _Bool fu32_e(u32 a) { return (_Bool)a; }
static _Bool fvdp_i(vdp a) { return a; }
static _Bool fvdp_e(vdp a) { return (_Bool)a; }
static _Bool fsip_i(sip a) { return a; }
static _Bool fsip_e(sip a) { return (_Bool)a; }
static _Bool ffun_i(void)  { return fun; }
static _Bool ffun_e(void)  { return (_Bool)fun; }
static _Bool fres_i(le16 a) { return a; }
static _Bool fres_e(le16 a) { return (_Bool)a; }
static _Bool fdbl_i(dbl a) { return a; }
static _Bool fdbl_e(dbl a) { return (_Bool)a; }

/*
 * check-name: bool-cast
 * check-command: test-linearize -m64 -fdump-ir=linearize $file
 * check-assert: sizeof(void*) == 8 && sizeof(long) == 8 && sizeof(double) == 8
 *
 * check-output-ignore
 * check-output-excludes: cast\\.
 * check-output-excludes: fcvt[us]\\.
 * check-output-excludes: ptrtu\\.
 * check-output-excludes: [sz]ext\\.
 * check-output-excludes: trunc\\.
 * check-output-pattern(12): setne\\.
 * check-output-pattern(2): fcmpune\\.
 */
