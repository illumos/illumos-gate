unsigned long long foo(unsigned long long x)
{
	return (((unsigned int) x) & 0x7ffU);
}

/*
 * check-name: trunc-mask-zext
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: trunc\\.
 * check-output-excludes: zext\\.
 */
