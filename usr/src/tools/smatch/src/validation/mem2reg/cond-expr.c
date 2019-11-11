int fun(int);

int foo(int a, int b, int c)
{
	return a ? fun(b) : fun(c);
}

/*
 * check-name: cond-expr
 * check-command: test-linearize -Wno-decl -fdump-ir=mem2reg $file
 * check-output-ignore
 * check-output-pattern(2): phi\\.
 * check-output-pattern(3): phisrc\\.
 */
