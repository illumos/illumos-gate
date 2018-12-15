#define	__noderef	__attribute__((noderef))

static void test_noderef(void)
{
	int __noderef obj, *ptr;
	typeof(ptr) ptr2 = ptr;
	typeof(*ptr) *ptr3 = ptr;
	typeof(obj) *ptr4 = ptr;
	ptr = ptr;
	ptr = &obj;
}

/*
 * check-name: typeof-noderef
 * check-known-to-fail
 *
 * check-error-start
 * check-error-end
 */
