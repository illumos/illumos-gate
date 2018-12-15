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
 * check-name: cond-address-array.c
 * check-command: test-linearize -Wno-decl -Waddress $file
 * check-output-ignore
 *
 * check-error-start
cond-address-array.c:4:13: warning: the address of an array will always evaluate as true
cond-address-array.c:12:13: warning: the address of an array will always evaluate as true
 * check-error-end
 */
