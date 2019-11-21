static void foo(int a)
{
	__range__(a, 0, 8);
}

static void bar(int a, int b, int c)
{
	__range__(a, b, c);
}

/*
 * check-name: range-op
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
foo:
.L0:
	<entry-point>
	range-check %arg1 between $0..$8
	ret


bar:
.L2:
	<entry-point>
	range-check %arg1 between %arg2..%arg3
	ret


 * check-output-end
 */
