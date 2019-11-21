extern int fun(int a);

void symbol(int a)
{
	fun(a);
}

void pointer0(int a, int (*fun)(int))
{
	fun(a);
}

void pointer1(int a, int (*fun)(int))
{
	(*fun)(a);
}

void builtin(int a)
{
	__builtin_popcount(a);
}

/*
 * check-name: basic function calls
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
symbol:
.L0:
	<entry-point>
	call.32     %r2 <- fun, %arg1
	ret


pointer0:
.L2:
	<entry-point>
	call.32     %r5 <- %arg2, %arg1
	ret


pointer1:
.L4:
	<entry-point>
	call.32     %r8 <- %arg2, %arg1
	ret


builtin:
.L6:
	<entry-point>
	call.32     %r10 <- __builtin_popcount, %arg1
	ret


 * check-output-end
 */
