static int foo(volatile int *a, int v)
{
	*a = v;
	return *a;
}

/*
 * check-name: memops-volatile
 * check-command: test-linearize $file
 *
 * check-output-start
foo:
.L0:
	<entry-point>
	store.32    %arg2 -> 0[%arg1]
	load.32     %r5 <- 0[%arg1]
	ret.32      %r5


 * check-output-end
 */
