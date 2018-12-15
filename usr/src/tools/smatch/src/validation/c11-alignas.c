static _Alignas(8)	int v;
static _Alignas(long)	int t;
static _Alignas(void *)	int p;
static _Alignas(int[4])	int a;
static _Alignas(0)	int z;
static _Alignas(3)	int bnpow2;
static _Alignas(-1)	int bneg;
static _Alignas(-2)	int bnegpow2;
static _Alignas(v)	int bnc;
static _Alignas(+)	int bsyn;

static int check(void)
{
	if (_Alignof(v) != 8)
		return -1;
	if (_Alignof(t) != _Alignof(long))
		return -1;
	if (_Alignof(p) != _Alignof(void *))
		return -1;
	if (_Alignof(a) != _Alignof(int))
		return -1;

	return 0;
}

/*
 * check-name: c11-alignas
 * check-command: test-linearize -std=c11 $file
 *
 * check-error-start
c11-alignas.c:6:25: warning: non-power-of-2 alignment
c11-alignas.c:7:25: warning: non-positive alignment
c11-alignas.c:8:25: warning: non-positive alignment
c11-alignas.c:9:17: error: bad constant expression
c11-alignas.c:10:17: error: Syntax error in unary expression
 * check-error-end
 *
 * check-output-ignore
 * check-output-contains: ret\\.32 *\$0
 */
