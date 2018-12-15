extern int foo(int a, void *b);

int foo(a, b)
	int a;
	void *b;
{
	if (b)
		return a;
}

/*
 * check-name: old-stype-definition disabled
 * check-command: sparse -Wno-old-style-definition $file
 */
