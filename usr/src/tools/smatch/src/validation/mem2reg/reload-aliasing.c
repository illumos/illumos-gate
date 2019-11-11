extern int g, h;

void f00(int *s)
{
	g = *s;
	h = *s;
}

void f01(int *a, int *b, int *s)
{
	*a = *s;
	*b = *s;
}

/*
 * check-name: reload-aliasing.c
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
f00:
.L0:
	<entry-point>
	load.32     %r2 <- 0[%arg1]
	store.32    %r2 -> 0[g]
	load.32     %r4 <- 0[%arg1]
	store.32    %r4 -> 0[h]
	ret


f01:
.L2:
	<entry-point>
	load.32     %r6 <- 0[%arg3]
	store.32    %r6 -> 0[%arg1]
	load.32     %r9 <- 0[%arg3]
	store.32    %r9 -> 0[%arg2]
	ret


 * check-output-end
 */
