#define MAX	(sizeof(int) * __CHAR_BIT__)

static int lmax(int a)
{
	return 1 << MAX;
}

static int lneg(int a)
{
	return 1 << -1;
}

static int rmax(int a)
{
	return 1 >> MAX;
}

static int rneg(int a)
{
	return 1 >> -1;
}

/*
 * check-name: bad-shift
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
lmax:
.L0:
	<entry-point>
	shl.32      %r1 <- $1, $32
	ret.32      %r1


lneg:
.L2:
	<entry-point>
	shl.32      %r3 <- $1, $0xffffffff
	ret.32      %r3


rmax:
.L4:
	<entry-point>
	asr.32      %r5 <- $1, $32
	ret.32      %r5


rneg:
.L6:
	<entry-point>
	asr.32      %r7 <- $1, $0xffffffff
	ret.32      %r7


 * check-output-end
 *
 * check-error-start
expand/bad-shift.c:5:18: warning: shift too big (32) for type int
expand/bad-shift.c:10:18: warning: shift count is negative (-1)
expand/bad-shift.c:15:18: warning: shift too big (32) for type int
expand/bad-shift.c:20:18: warning: shift count is negative (-1)
 * check-error-end
 */
