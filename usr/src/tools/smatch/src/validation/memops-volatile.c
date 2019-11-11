static int foo(volatile int *a, int v)
{
	*a = v;
	*a = 0;
	return *a;
}

/*
 * check-name: memops-volatile
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-contains: store\\..*%arg2 -> 0\\[%arg1]
 * check-output-contains: store\\..*\\$0 -> 0\\[%arg1]
 * check-output-contains: load\\..*%r.* <- 0\\[%arg1]
 */
