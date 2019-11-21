int foo(void) {
	extern int a[];

	if (a)
		return 1;
	return 0;
}

int bar(void) {
	int a[2];

	if (a)
		return 1;
	return 0;
}

/*
 * check-name: Waddress-array
 * check-command: sparse -Wno-decl -Waddress $file
 *
 * check-error-start
Waddress-array.c:4:13: warning: the address of an array will always evaluate as true
Waddress-array.c:12:13: warning: the address of an array will always evaluate as true
 * check-error-end
 */
