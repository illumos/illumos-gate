static int foo(int a)
{
	goto label;
	switch(a) {
	default:
label:
		break;
	}
	return 0;
}

/*
 * check-name: unreachable-label0
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-contains: ret\\.
 * check-output-excludes: END
 */
