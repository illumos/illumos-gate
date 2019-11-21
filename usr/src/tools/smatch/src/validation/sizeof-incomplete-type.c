struct s {
	char a;
	char b[sizeof(struct s)];
	char c;
	char d[sizeof(struct s)];
	int  j:sizeof(struct s);
};

static int array[] = {
	[0]		= 0,
	[sizeof(array)] = 1,
	[2]		= 0,
	[sizeof(array)] = 2,
};

/*
 * check-name: sizeof incomplete type
 *
 * check-known-to-fail
 * check-error-start
sizeof-incomplete-type.c:3:16: error: invalid application of 'sizeof' to incomplete type 'struct s'
sizeof-incomplete-type.c:5:16: error: invalid application of 'sizeof' to incomplete type 'struct s'
sizeof-incomplete-type.c:6:16: error: invalid application of 'sizeof' to incomplete type 'struct s'
sizeof-incomplete-type.c:11:17: error: invalid application of 'sizeof' to incomplete type 'int[]'
sizeof-incomplete-type.c:13:17: error: invalid application of 'sizeof' to incomplete type 'int[]'
 * check-error-end
 */
