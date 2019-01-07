typedef unsigned short __attribute__((bitwise))__le16;
static __le16 foo(__le16 a)
{
	return a |= ~a;
}

static int baz(__le16 a)
{
	return ~a == ~a;
}

static int barf(__le16 a)
{
	return a == (a & ~a);
}

static __le16 bar(__le16 a)
{
	return -a;
}

/*
 * check-name: foul bitwise
 * check-error-start
foul-bitwise.c:9:16: warning: restricted __le16 degrades to integer
foul-bitwise.c:9:22: warning: restricted __le16 degrades to integer
foul-bitwise.c:19:16: warning: restricted __le16 degrades to integer
foul-bitwise.c:19:16: warning: incorrect type in return expression (different base types)
foul-bitwise.c:19:16:    expected restricted __le16
foul-bitwise.c:19:16:    got int
 * check-error-end
 */
