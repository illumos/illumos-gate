int i;

int foo(void)
{
	int j = 1;
	i = 6;

	do {
		if (i != 6)
			i++;
		i++;
	} while (i != j);

	return j;
}

/*
 * check-name: loop02 global
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 * check-output-excludes: load\\.
 */
