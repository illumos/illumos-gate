extern void *memset (void *s, int c, int n);

static void foo(void *a)
{
	memset(foo, + ', 20);
}
/*
 * check-name: Segfault in check_byte_count after syntax error
 *
 * check-error-start
check_byte_count-ice.c:6:0: warning: Newline in string or character constant
check_byte_count-ice.c:5:23: warning: multi-character character constant
check_byte_count-ice.c:6:1: error: Expected ) in function call
check_byte_count-ice.c:6:1: error: got }
builtin:0:0: error: Expected } at end of function
builtin:0:0: error: got end-of-input
check_byte_count-ice.c:5:15: error: not enough arguments for function memset
 * check-error-end
 */
