static const char messg[] = "def";

static inline int add(int a, int b)
{
	return a + b;
}

int foo(int a, int b, int p)
{
	if (p) {
		add(a + b, 1);
		return p;
	}
	return 0;
}

/*
 * check-name: call-inlined
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
foo:
.L0:
	<entry-point>
	select.32   %r10 <- %arg3, %arg3, $0
	ret.32      %r10


 * check-output-end
 */
