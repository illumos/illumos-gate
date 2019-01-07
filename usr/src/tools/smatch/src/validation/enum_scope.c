enum {A = 12};

static void f(void)
{
	enum {A = A + 1, B};
	char s[1 - 2 * (B != 14)];
}

/*
 * check-name: enumeration constants' scope [6.2.1p7]
 */
