extern void use(char);

static void foo(char *b)
{
	while (b) {
		if (b++)
			continue;
		++b;
		use(*b);
		&b;
	}
}

/*
 * check-name: internal infinite loop (4)
 * check-command: sparse $file
 * check-timeout:
 */
