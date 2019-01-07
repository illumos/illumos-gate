/* example from gcc documents */

void function_that_never_returns (void);

static int g (int c)
{
	if (c)
		return 1;
	function_that_never_returns ();
	__builtin_unreachable ();
}
     
/*
 * check-name: __builtin_unreachable()
 */
