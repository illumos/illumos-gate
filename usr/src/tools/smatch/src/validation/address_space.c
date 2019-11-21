#define __user __attribute__((address_space(1)))

extern int poke_memory(void *addr);

static int sys_do_stuff(void __user *user_addr)
{
	return poke_memory(user_addr);
}
/*
 * check-name: address_space attribute
 *
 * check-error-start
address_space.c:7:28: warning: incorrect type in argument 1 (different address spaces)
address_space.c:7:28:    expected void *addr
address_space.c:7:28:    got void <asn:1> *user_addr
 * check-error-end
 */
