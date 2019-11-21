static int sel0(int a)
{
	if (a)
		return 0;
	else
		return a;
}

/*
 * check-name: select-zero
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-contains: ret.32 *\\$0
 * check-output-excludes: select\\.
 */
