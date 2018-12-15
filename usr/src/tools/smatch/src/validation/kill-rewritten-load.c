int foo(int i)
{
	i++;
	if (i && 0)
		i;
	return 0;
}


/*
 * check-name: kill-rewritten-load
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-excludes: add\\.
 */
