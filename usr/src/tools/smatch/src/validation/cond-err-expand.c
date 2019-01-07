static inline void f(void)
{
	__builtin_constant_p(0);
}

void foo(void)
{
	0 ? 0 : f();
}

void bar(void)
{
	1 ? f() : 0;
}

/*
 * check-name: cond-err-expand.c
 * check-command: test-linearize -Wno-decl $file
 *
 * check-error-start
cond-err-expand.c:8:11: error: incompatible types in conditional expression (different base types)
cond-err-expand.c:13:11: error: incompatible types in conditional expression (different base types)
 * check-error-end
 *
 * check-output-ignore
 * check-excludes: call.* __builtin_constant_p
 */
