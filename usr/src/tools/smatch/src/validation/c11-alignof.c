static int foo(void)
{
	return _Alignof(short);
}

/*
 * check-name: c11-alignof
 * check-command: test-linearize -std=c11 $file
 *
 * check-output-ignore
 * check-output-contains: ret\\.32 *\\$2
 */
