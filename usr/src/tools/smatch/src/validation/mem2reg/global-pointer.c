int a, c, d;

int foo_ptr(void)
{
	int b, *bp = &b;
	int e, *ep = &e;

	if (a)
		*bp = c;
	else
		*bp = d;
	if (c)
		a = *bp;
	if (b)
		e = a;
	return e;
}

/*
 * check-name: global pointer
 * check-command: test-linearize -Wno-decl -fdump-ir=mem2reg $file
 * check-known-to-fail
 * check-output-ignore
 * check-output-pattern(4,5): load\\.
 * check-output-pattern(3): store\\.
 */
