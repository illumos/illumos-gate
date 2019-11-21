typedef int (*fun_t)(void*);

int foo(void *a, void *fun)
{
	return ((fun_t)fun)(a);
}

int bar(void *a, void *fun)
{
	return ((int (*)(void *))fun)(a);
}

int qux(void *a, void *fun)
{
	return (*(fun_t)fun)(a);
}

int quz(void *a, void *fun)
{
	return (*(int (*)(void *))fun)(a);
}

/*
 * check-name: call via casted function pointer
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: load
 * check-output-pattern(4): ptrcast\\..* %arg2
 * check-output-pattern(4): call\\..* %arg1
 */
