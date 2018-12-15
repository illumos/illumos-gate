int foo(int a)
{
	if (a)
		return 0;
	else
		return 1;
	return 2;
}

/*
 * check-name: Ignore VOID in if-convert
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-excludes: phisrc\\.
 * check-output-excludes: phi\\.
 * check-output-excludes: VOID
 * check-output-contains: seteq\\.
 */
