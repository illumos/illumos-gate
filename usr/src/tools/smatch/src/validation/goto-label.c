void foo(void)
{
	goto a;
a:
a:
	return;
}

void g(void)
{
	goto a;
a:
	return;
}

void bar(void)
{
	goto neverland;
}

/*
 * check-name: goto labels
 *
 * check-error-start
goto-label.c:5:1: error: label 'a' redefined
goto-label.c:18:9: error: label 'neverland' was not declared
 * check-error-end
 */

