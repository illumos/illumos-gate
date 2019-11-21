#define N 2
#define T int

static unsigned long foo(int x, int y)
{
	T a[x][y];

	return sizeof(a) == (x * (y * sizeof(T)));
}

/*
 * check-name: vla-sizeof var X var
 * check-command: test-linearize -Wvla $file
 *
 * check-output-ignore
 * check-output-contains: ret\\..*\\$1
 *
 * check-error-start
vla-sizeof4.c:6:16: warning: Variable length array is used.
vla-sizeof4.c:6:13: warning: Variable length array is used.
 * check-error-end
 */
