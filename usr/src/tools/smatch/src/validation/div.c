#define	INT_MIN		(-__INT_MAX__ - 1)
#define	LONG_MIN	(-__LONG_MAX__ - 1)
#define	LLONG_MIN	(-__LONG_LONG_MAX__ - 1)

static int xd = 1 / 0;
static int xl = 1L / 0;
static int xll = 1LL / 0;

static int yd = INT_MIN / -1;
static long yl = LONG_MIN / -1;
static long long yll = LLONG_MIN / -1;

static int zd = INT_MIN % -1;
static long zl = LONG_MIN % -1;
static long long zll = LLONG_MIN % -1;

/*
 * check-name: division constants
 *
 * check-error-start
div.c:5:19: warning: division by zero
div.c:6:20: warning: division by zero
div.c:7:22: warning: division by zero
div.c:9:25: warning: constant integer operation overflow
div.c:10:27: warning: constant integer operation overflow
div.c:11:34: warning: constant integer operation overflow
div.c:13:25: warning: constant integer operation overflow
div.c:14:27: warning: constant integer operation overflow
div.c:15:34: warning: constant integer operation overflow
 * check-error-end
 */
