static void foo(void)
{
	int b[] = { 8 };
	int c;
	for (;;)
		b[c] = b[0];
}

/*
 * check-name: bug-crash16
 */
