struct s {
	int a:8;
	int b:8;
};

int foo(void)
{
	struct s x = { .a = 12, .b = 34, };

	return x.b;
}

int bar(int a)
{
	struct s x = { .a = 12, .b = a, };

	return x.b;
}

/*
 * check-name: bitfield expand deref
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: ret\\..*\\$12
 * check-output-contains: ret\\..*\\$34
 */
