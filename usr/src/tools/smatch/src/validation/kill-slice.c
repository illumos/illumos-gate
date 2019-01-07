struct bar {
	int x;
	int y[2];
};
struct bar bar(void);

int foo(void)
{
	int x = bar().x;
	return x & 0;
}

/*
 * check-name: kill-slice
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-excludes: slice\\.
 */
