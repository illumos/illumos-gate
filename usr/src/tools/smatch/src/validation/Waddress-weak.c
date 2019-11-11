extern int var       __attribute__((weak));
extern int arr[]     __attribute__((weak));
extern int fun(void) __attribute__((weak));

int test_addr_weak_fun(void)
{
	if ( &var) return 1;
	if (  arr) return 1;
	if ( &arr) return 1;
	if (  fun) return 1;
	if ( &fun) return 1;
	if ( *fun) return 1;
	if (!&var) return 0;
	if (! arr) return 0;
	if (!&arr) return 0;
	if (! fun) return 0;
	if (!&fun) return 0;
	if (!*fun) return 0;
	return -1;
}

/*
 * check-name: Waddress-weak
 * check-note: Undefined weak symbols (can) have a null address.
 * check-command: sparse -Wno-decl -Waddress $file
 * check-known-to-fail
 */
