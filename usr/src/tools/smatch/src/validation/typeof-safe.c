#define	__safe		__attribute__((safe))

static void test_safe(void)
{
	int __safe obj, *ptr;
	typeof(obj) var = obj;
	typeof(ptr) ptr2 = ptr;
	typeof(*ptr) var2 = obj;
	typeof(*ptr) *ptr3 = ptr;
	typeof(obj) *ptr4 = ptr;
	obj = obj;
	ptr = ptr;
	ptr = &obj;
	obj = *ptr;
}

/*
 * check-name: typeof-safe
 * check-known-to-fail
 *
 * check-error-start
 * check-error-end
 */
