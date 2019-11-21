int foo(void)
{
	struct {
		int a:8;
		int b:16;
		int c:8;
	} s = { 0xff, 0x0000, 0xff };

	return s.b = 0x56781234;
}

/*
 * check-name: bitfield-store
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: ret\\..*\\$0x1234
 *
 * check-error-start
linear/bitfield-store.c:9:22: warning: cast truncates bits from constant value (56781234 becomes 1234)
 * check-error-end
 */
