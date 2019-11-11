static int foo(int a)
{
	int r = a;
	r;
}

/*
 * check-name: missing-return4
 * check-command: test-linearize -Wno-decl $file
 *
 * check-error-ignore
 * check-output-ignore
 * check-output-contains: ret\\..*UNDEF
 */
