static typeof(undef) a;

static int foo(void)
{
	return a;
}

/*
 * check-name: typeof-bad
 *
 * check-error-start
typeof-bad.c:1:15: error: undefined identifier 'undef'
typeof-bad.c:5:16: warning: incorrect type in return expression (different base types)
typeof-bad.c:5:16:    expected int
typeof-bad.c:5:16:    got bad type static [toplevel] a
 * check-error-end
 */
