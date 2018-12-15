#define	__as		__attribute__((address_space(1)))

static void test_as(void)
{
	int __as obj, *ptr;
	typeof(obj) var = obj;
	typeof(ptr) ptr2 = ptr;
	typeof(*ptr) var2 = obj;
	typeof(*ptr) *ptr3 = ptr;	/* check-should-pass */
	typeof(obj) *ptr4 = ptr;	/* check-should-pass */
	obj = obj;
	ptr = ptr;
	ptr = &obj;
	obj = *ptr;
}

/*
 * check-name: typeof-addresspace.c
 * check-known-to-fail
 */
