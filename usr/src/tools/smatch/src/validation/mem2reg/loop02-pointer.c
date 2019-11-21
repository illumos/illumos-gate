

int foo(int *i)
{
	int j = 1;
	*i = 6;

	do {
		if (*i != 6)
			(*i)++;
		(*i)++;
	} while (*i != j);

	return j;
}

/*
 * check-name: loop02 pointer
 * check-command: test-linearize -Wno-decl -fdump-ir=mem2reg $file
 * check-output-ignore
 * check-output-pattern(0,4): load\\.
 * check-output-pattern(1,3): store\\.
 */
