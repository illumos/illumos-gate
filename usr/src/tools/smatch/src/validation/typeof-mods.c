#define	__noderef	__attribute__((noderef))
#define	__bitwise	__attribute__((bitwise))
#define	__nocast	__attribute__((nocast))
#define	__safe		__attribute__((safe))

static void test_spec(void)
{
	unsigned int obj, *ptr;
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

static void test_const(void)
{
	const int obj, *ptr;
	typeof(obj) var = obj;
	typeof(ptr) ptr2 = ptr;
	typeof(*ptr) var2 = obj;
	typeof(*ptr) *ptr3 = ptr;
	typeof(obj) *ptr4 = ptr;
	ptr = ptr;
	ptr = &obj;
}

static void test_volatile(void)
{
	volatile int obj, *ptr;
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

static void test_restrict(void)
{
	int *restrict obj, *restrict *ptr;
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

static void test_atomic(void)
{
	int _Atomic obj, *ptr;
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

static void test_bitwise(void)
{
	typedef int __bitwise type_t;
	type_t obj, *ptr;
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

static void test_static(void)
{
	static int obj, *ptr;
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

static void test_tls(void)
{
	__thread int obj, *ptr;
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

static void test_nocast(void)
{
	int __nocast obj, *ptr;
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
 * check-name: typeof-mods
 *
 * check-error-start
 * check-error-end
 */
