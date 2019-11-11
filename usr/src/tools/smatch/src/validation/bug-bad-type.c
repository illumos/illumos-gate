struct s {
	int   i;
};

long a;
void foo(void)
{
	(struct s) { .i = (foo - a), };
}

/*
 * check-name: bug-bad-type
 *
 * check-error-start
bug-bad-type.c:5:6: warning: symbol 'a' was not declared. Should it be static?
bug-bad-type.c:8:32: error: arithmetics on pointers to functions
 * check-error-end
 */
