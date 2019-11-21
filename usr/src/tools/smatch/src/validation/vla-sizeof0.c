#define N 2
#define T int

static unsigned int foo(int x)
{
	T a[(1,N)];

	return sizeof(a) == (N * sizeof(T));
}

/*
 * check-name: vla-sizeof cte,cte
 * check-command: test-linearize -Wvla $file
 *
 * check-output-ignore
 * check-output-contains: ret\\.32 *\\$1
 *
 * check-error-start
 * check-error-end
 */
