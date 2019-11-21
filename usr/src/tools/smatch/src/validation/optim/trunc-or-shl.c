char foo(int a, int b)
{
	return (a << 8) | b;
}

/*
 * check-name: trunc-or-shl
 * check-command: test-linearize -Wno-decl $file
 * check-known-to-fail
 *
 * check-output-ignore
 * check-output-contains: ret\\..*%arg2
 */
