struct s;

void foo(struct s s)
{
}

struct s bar(void)
{
	struct s s;
	return s;
}

/*
 * check-name: incomplete struct
 * check-command: sparse -Wno-decl $file
 * check-known-to-fail
 *
 * check-error-start
incomplete-struct.c:3:19: error: parameter 's' has incomplete type
incomplete-struct.c:7:10: error: return type is incomplete
incomplete-struct.c:9:11: error: 's' has incompelete type
 * check-error-end
 */
