void foo(int a)
{
	while (1)
		a ^= 0;
}

/*
 * check-name: trivial phis
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: phi\\.
 * check-output-excludes: phisrc\\.
 */
