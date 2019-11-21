extern int *ip[];

void foo(void);
void foo(void)
{
	ip[0] = (void *)0L;
	ip[1] = (int *)0L;
	ip[2] = (void *)0;
	ip[3] = (int *)0;
	ip[4] = (void *)(long)0;
	ip[5] = (int *)(long)0;
	ip[6] = (void *)123;
	ip[7] = (int *)123;
	ip[8] = (void *)123L;
	ip[9] = (int *)123L;
	ip[10] = (void *)(long)123;
	ip[11] = (int *)(long)123;
}

/*
 * check-name: constant pointers
 * check-command: sparse-llvm $file
 * check-output-ignore
 */
