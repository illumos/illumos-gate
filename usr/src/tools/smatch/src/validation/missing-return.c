int foo(int a)
{
}

int bar(int a)
{
	if (a)
		return 0;
}

/*
 * check-name: missing return
 * check-command: sparse -Wno-decl $file
 * check-known-to-fail
 *
 * check-error-start
missing-return.c:3:1: warning: control reaches end of non-void function
missing-return.c:9:1: warning: control reaches end of non-void function
 * check-error-end
 */
