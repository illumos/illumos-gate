void foo(int a)
{
	return a;
}

int bar(void)
{
	return;
}

/*
 * check-name: bad return type
 * check-command: sparse -Wno-decl $file
 *
 * check-error-start
bad-return-type.c:3:16: error: return expression in void function
bad-return-type.c:8:9: error: return with no return value
 * check-error-end
 */
