extern int ffun(void);
typedef void *vdp;
typedef int  *sip;

static _Bool fvdp_i(vdp a) { return a; }
static _Bool fvdp_e(vdp a) { return (_Bool)a; }
static _Bool fsip_i(sip a) { return a; }
static _Bool fsip_e(sip a) { return (_Bool)a; }
static _Bool ffun_i(void)  { return ffun; }
static _Bool ffun_e(void)  { return (_Bool)ffun; }

/*
 * check-name: bool-cast-pointer
 * check-command: test-linearize -m32 -fdump-ir $file
 * check-known-to-fail
 *
 * check-output-ignore
 * check-output-excludes: ptrtu\\.
 */
