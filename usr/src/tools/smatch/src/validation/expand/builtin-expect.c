int flia(long a)
{
	return __builtin_expect(a, 1);
}

int flic(void)
{
	return __builtin_expect(1L << 32 | 1, 1);
}

long fila(int a)
{
	return __builtin_expect(a, 1);
}

long filc(void)
{
	return __builtin_expect(1L << 32 | 1, 1);
}

long filu(void)
{
	return __builtin_expect(0x80000000U, 1);
}

long fils(void)
{
	return __builtin_expect((int)0x80000000, 1);
}

void *fptr(void *a)
{
	return __builtin_expect(a, a);
}

/*
 * check-name: builtin-expect
 * check-command: test-linearize -m64 -Wno-decl $file
 * check-assert: sizeof(long) == 8
 *
 * check-output-start
flia:
.L0:
	<entry-point>
	trunc.32    %r2 <- (64) %arg1
	ret.32      %r2


flic:
.L2:
	<entry-point>
	ret.32      $1


fila:
.L4:
	<entry-point>
	sext.64     %r6 <- (32) %arg1
	ret.64      %r6


filc:
.L6:
	<entry-point>
	ret.64      $0x100000001


filu:
.L8:
	<entry-point>
	ret.64      $0x80000000


fils:
.L10:
	<entry-point>
	ret.64      $0xffffffff80000000


fptr:
.L12:
	<entry-point>
	ret.64      %arg1


 * check-output-end
 *
 * check-error-start
expand/builtin-expect.c:33:33: warning: incorrect type in argument 1 (different base types)
expand/builtin-expect.c:33:33:    expected long
expand/builtin-expect.c:33:33:    got void *a
expand/builtin-expect.c:33:36: warning: incorrect type in argument 2 (different base types)
expand/builtin-expect.c:33:36:    expected long
expand/builtin-expect.c:33:36:    got void *a
expand/builtin-expect.c:33:32: warning: incorrect type in return expression (different base types)
expand/builtin-expect.c:33:32:    expected void *
expand/builtin-expect.c:33:32:    got long
expand/builtin-expect.c:8:42: warning: cast truncates bits from constant value (100000001 becomes 1)
 * check-error-end
 */
