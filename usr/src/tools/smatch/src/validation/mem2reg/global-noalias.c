int a, b, c, d, e;

void foo(void)
{
	if (a)
		b = c;
	else
		b = d;
	if (c)
		a = b;
	if (b)
		e = a;
}

/*
 * check-name: global no-alias
 * check-command: test-linearize -Wno-decl -fdump-ir=mem2reg $file
 * check-output-ignore
 * check-output-pattern(4,7): load\\.
 * check-output-pattern(4): store\\.
 */
