extern int foo(int a, void *b);

int foo(a, b)
	int a;
	void *b;
{
	if (b)
		return a;
}

/*
 * check-name: old-stype-definition enabled
 * check-command: sparse -Wold-style-definition $file
 *
 * check-error-start
old-style-definition1.c:4:9: warning: non-ANSI definition of function 'foo'
 * check-error-end
 */
