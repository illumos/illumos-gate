#if 0
/*
From 6.10.1(5):
	Each directive's condition is checked in order.  If it evaluates
	to false (zero), the group it controls is skipped: directives are
	processed only through the name that determines the directive in
	order to keep track of the level of nested conditionals; the rest
	of the directives' preprocessing tokens are ignores, >>as are the
	other preprocessing tokens in the group<<.

In other words, bogus arguments of directives are silently ignored and
so are text lines and non-directives (# <something unknown>).  We *do*
complain about the things like double #else or #elif after #else, since
they hit before we get to the level of groups.
*/

#define 1
#undef 1
#bullshit

#endif
/*
 * check-name: Preprocessor #16
 * check-command: sparse -E $file
 *
 * check-output-start


 * check-output-end
 */
