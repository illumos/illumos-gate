/*
 * Structure members should get the address
 * space of their pointer.
 */
#define __user __attribute__((address_space(1)))

struct hello {
	int a;
};

extern int test(int __user *ip);

static int broken(struct hello __user *sp)
{
	return test(&sp->a);
}
/*
 * check-name: Address space of a struct member
 */
