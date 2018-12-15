static void f(void)
{
	char *s1 = __func__;
	char arr[2 * (sizeof __func__ == 2) - 1];
	char *s2 = __func__ __func__;
}
/*
 * check-name: __func__
 * check-command: sparse -Wall $file
 *
 * check-error-start
__func__.c:5:29: error: Expected ; at end of declaration
__func__.c:5:29: error: got __func__
 * check-error-end
 */
