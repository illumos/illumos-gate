int a, c, d;

int foo(void)
{
	int b, e;
	if (a)
		b = c;
	else
		b = d;
	if (c)
		a = b;
	if (b)
		e = a;
	return e;
}

/*
 * check-name: global direct undef
 * check-command: test-linearize -Wno-decl -fdump-ir=mem2reg $file
 * check-output-ignore
 * check-output-pattern(4,5): load\\.
 * check-output-pattern(1): store\\.
 */
