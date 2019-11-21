extern int a[1];

static int foo(int n)
{
	int i = 0;
	int (*p)[1] = (typeof(++i, (int (*)[n])a)) &a;

	(void) p;

	return i;
}

/*
 * check-name: eval-typeof-vla
 * check-command: test-linearize -Wno-vla $file
 * check-known-to-fail
 *
 * check-output-start
foo:
.L0:
	<entry-point>
	ret.32      $1


 * check-output-end
 */
