extern int g, h;

void f00u(int *s)
{
	g = *s;
	h = *s;
}

void f00r(int *restrict s)
{
	g = *s;
	h = *s;
}


void f01u(int *a, int *b, int *s)
{
	*a = *s;
	*b = *s;
}

void f01r(int *restrict a, int *restrict b, int *restrict s)
{
	*a = *s;
	*b = *s;
}

/*
 * check-name: optim/restrict
 * check-command: test-linearize -Wno-decl $file
 * check-known-to-fail
 *
 * check-output-start
f00u:
.L0:
	<entry-point>
	load.32     %r2 <- 0[%arg1]
	store.32    %r2 -> 0[g]
	load.32     %r4 <- 0[%arg1]
	store.32    %r4 -> 0[h]
	ret


f00r:
.L2:
	<entry-point>
	load.32     %r6 <- 0[%arg1]
	store.32    %r6 -> 0[g]
	store.32    %r6 -> 0[h]
	ret


f01u:
.L4:
	<entry-point>
	load.32     %r10 <- 0[%arg3]
	store.32    %r10 -> 0[%arg1]
	load.32     %r13 <- 0[%arg3]
	store.32    %r13 -> 0[%arg2]
	ret


f01r:
.L6:
	<entry-point>
	load.32     %r16 <- 0[%arg3]
	store.32    %r16 -> 0[%arg1]
	store.32    %r16 -> 0[%arg2]
	ret


 * check-output-end
 */
