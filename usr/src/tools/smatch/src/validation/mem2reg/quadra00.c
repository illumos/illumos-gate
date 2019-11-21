#define	TEST(N)			\
	do {			\
		d = b + a[N];	\
		if (d < b)	\
			c++;	\
		b = d;		\
	} while (0)

int foo(int *a, int b, int c)
{
	int d;

	TEST(0);
	TEST(1);
	TEST(2);

	return d + c;
}

/*
 * check-name: quadratic phisrc
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 * check-output-excludes: phi\\..*, .*, .*
 * check-output-excludes: phi\\..*, .*, .*, .*
 * check-output-pattern(6): phisrc\\.
 */
