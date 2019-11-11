#define __user __attribute__((address_space(__user)))

extern void fun(void *addr);

static void foo(void __user *ptr)
{
	return fun(ptr);
}
/*
 * check-name: as-name attribute
 *
 * check-error-start
as-name.c:7:20: warning: incorrect type in argument 1 (different address spaces)
as-name.c:7:20:    expected void *addr
as-name.c:7:20:    got void __user *ptr
 * check-error-end
 */
