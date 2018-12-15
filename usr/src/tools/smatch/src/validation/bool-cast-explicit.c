typedef unsigned int	u32;
typedef          int	s32;
typedef void *vdp;
typedef int  *sip;
typedef double dbl;
typedef unsigned short __attribute__((bitwise)) le16;

static _Bool fs32(s32 a) { return (_Bool)a; }
static _Bool fu32(u32 a) { return (_Bool)a; }
static _Bool fvdp(vdp a) { return (_Bool)a; }
static _Bool fsip(sip a) { return (_Bool)a; }
static _Bool fdbl(dbl a) { return (_Bool)a; }
static _Bool ffun(void)  { return (_Bool)ffun; }

static _Bool fres(le16 a) { return (_Bool)a; }

/*
 * check-name: bool-cast-explicit
 * check-command: test-linearize -m64 $file
 * check-output-ignore
 * check-output-excludes: cast\\.
 */
