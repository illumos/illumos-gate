/*
 * Sparse used to get this wrong.
 *
 * When evaluating the argument to the inline function for the array, Sparse
 * didn't properly demote the "char []" to a "char *", but instead it would
 * follow the dereference and get a "struct hello".
 *
 * Which made no sense at all.
 */

static inline int deref(const char *s)
{
	return *s;
}

struct hello {
	char array[10];
};

static int test(struct hello *arg)
{
	return deref(arg->array);
}

/*
 * check-name: "char []" to "char *" demotion
 */
