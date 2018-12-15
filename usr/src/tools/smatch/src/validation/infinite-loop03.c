static void foo(int *buf)
{
	int a = 1;
	int *b;
	do {
		if (a)
			b = buf;
		if (a)
			*buf = 0;
	} while (!(a = !a));
}

/*
 * check-name: infinite loop 03
 * check-command: sparse -Wno-decl $file
 */
