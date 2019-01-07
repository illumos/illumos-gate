extern void v(int a, ...);

extern inline __attribute__((__always_inline__)) void f(int a, ...)
{
	__SIZE_TYPE__ b = __builtin_va_arg_pack_len();
}

extern inline __attribute__((__always_inline__)) void g(int a, ...)
{
	v(a, __builtin_va_arg_pack());
}

static void h(void)
{
	f(0, 0);
	g(0, 0);
}
/*
 * check-name: __builtin_va_arg_pack()
 */
