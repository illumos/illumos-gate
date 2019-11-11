#define N 2UL
#define T int

static unsigned long foo(int x)
{
	T a[x][N];

	return sizeof(a) == (N * x * sizeof(T));
}

/*
 * check-name: vla-sizeof var X cte
 * check-command: test-linearize -Wvla $file
 *
 * check-output-ignore
 * check-output-contains: ret\\..*\\$1
 *
 * check-error-start
vla-sizeof3.c:6:13: warning: Variable length array is used.
 * check-error-end
 */
