static void foo(void)
{
	goto return;
}

/*
 * check-name: goto-reserved
 *
 * check-error-start
goto-reserved.c:3:14: error: Trying to use reserved word 'return' as identifier
 * check-error-end
 */
