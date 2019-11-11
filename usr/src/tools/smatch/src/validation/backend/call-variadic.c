#define NULL	((void*)0)

extern int print(const char *msg, ...);

int foo(const char *fmt, int a, long l, int *p);
int foo(const char *fmt, int a, long l, int *p)
{
	return print(fmt, 'x', a, __LINE__, l, 0L, p, NULL);
}

/*
 * check-name: call-variadic
 * check-command: sparse-llvm-dis -m64 $file
 *
 * check-output-start
; ModuleID = '<stdin>'
source_filename = "sparse"

define i32 @foo(i8* %ARG1., i32 %ARG2., i64 %ARG3., i32* %ARG4.) {
L0:
  %R5. = call i32 (i8*, ...) @print(i8* %ARG1., i32 120, i32 %ARG2., i32 8, i64 %ARG3., i64 0, i32* %ARG4., i8* null)
  ret i32 %R5.
}

declare i32 @print(i8*, ...)
 * check-output-end
 */
