#define NULL	((void*)0)

extern int print(const char *msg, ...);

int foo(const char *fmt, int a, long l, int *p)
{
	return print("msg %c: %d %d/%ld %ld/%p %p\n", 'x', a, __LINE__, l, 0L, p, NULL);
}

/*
 * check-name: call-variadic
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
foo:
.L0:
	<entry-point>
	call.32     %r5 <- print, "msg %c: %d %d/%ld %ld/%p %p\n", $120, %arg2, $7, %arg3, $0, %arg4, $0
	ret.32      %r5


 * check-output-end
 */
