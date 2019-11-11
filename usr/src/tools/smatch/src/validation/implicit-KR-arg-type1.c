int foo(a, b)
	int a;
{
	if (b)
		return a;
}

/*
 * check-name: implicit-KR-arg-type1
 * check-command: sparse -Wold-style-definition -Wimplicit-int $file
 *
 * check-error-start
implicit-KR-arg-type1.c:2:9: warning: non-ANSI definition of function 'foo'
implicit-KR-arg-type1.c:1:12: error: missing type declaration for parameter 'b'
 * check-error-end
 */
