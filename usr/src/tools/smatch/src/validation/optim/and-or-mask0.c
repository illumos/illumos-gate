int foo(int a, int b)
{
	return ((a & 0xfffff000) | b) & 0xfff;
}

/*
 * check-name: and-or-mask0
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: or\\.
 */
