#define N 2
#define T int

static unsigned long foo(int x)
{
	T a[x];

	return sizeof(a) == (x * sizeof(T));
}

/*
 * check-name: vla-sizeof var
 * check-command: test-linearize -Wvla $file
 *
 * check-output-ignore
 * check-output-contains: ret\\..*\\$1
 *
 * check-error-start
vla-sizeof2.c:6:13: warning: Variable length array is used.
 * check-error-end
 */
