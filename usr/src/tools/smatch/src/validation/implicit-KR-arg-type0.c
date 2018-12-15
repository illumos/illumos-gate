int foo(a, b)
	int a;
{
	if (b)
		return a;
}

/*
 * check-name: implicit-KR-arg-type
 * check-command: sparse -Wno-decl -Wold-style-definition -Wno-implicit-int $file
 *
 * check-error-start
implicit-KR-arg-type0.c:2:9: warning: non-ANSI definition of function 'foo'
 * check-error-end
 */
