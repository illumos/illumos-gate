typedef int  (*binop_t)(int, int);
typedef int  (*unop_t)(int);
typedef int  (*idef_t)(void);
typedef long (*ldef_t)(void);
typedef void (*use_t)(int);

// We want to 'fn' have several different types.
// The goal is for the ->priv member to be used
// with a type different from what it was first stored.

int foo(void *fn, int arg1, int arg2);
int foo(void *fn, int arg1, int arg2)
{
	int res = 0;

	res += ((binop_t)fn)(arg1, arg2);
	res += ((unop_t)fn)(arg1);
	res += ((ldef_t)fn)();
	res += ((idef_t)fn)();
	((use_t)fn)(res);
	return res;
}

int bar(int (*fn)(int), int arg1, int arg2);
int bar(int (*fn)(int), int arg1, int arg2)
{
	int res = 0;

	res += ((binop_t)fn)(arg1, arg2);
	res += fn(arg1);
	return res;
}

/*
 * check-name: mutate function pointer's type
 * check-command: sparsec -c $file -o tmp.o
 */
