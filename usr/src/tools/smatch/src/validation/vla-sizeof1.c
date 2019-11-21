#define N 2
#define T int

static unsigned int foo(int x)
{
	T a[(x,N)];

	return sizeof(a) == (N * sizeof(T));
}

/*
 * check-name: vla-sizeof var,cte
 * check-command: test-linearize -Wvla $file
 *
 * check-output-ignore
 * check-output-contains: ret\\.32 *\\$1
 *
 * check-error-start
vla-sizeof1.c:6:15: warning: Variable length array is used.
 * check-error-end
 */
