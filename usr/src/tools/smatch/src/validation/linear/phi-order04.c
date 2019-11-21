static void foo(int *b)
{
	if (1) {
		int c;
		b = &c;
	}
}

/*
 * check-name: phi-order04
 * check-command: sparse -vir -flinearize=last $file
 */
