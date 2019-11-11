extern int fun(void);
extern int (*ptr)(void);

static inline int inl(int *a)
{
	return *a + 1;
}


int test(void);
int test(void)
{
	unsigned int s = 0;

	// OK
	s += sizeof &fun;
	s += sizeof  ptr;
	s += sizeof &ptr;
	s += sizeof &inl;

	// KO
	s += sizeof  fun;
	s += sizeof *fun;

	s += sizeof *ptr;

	s += sizeof  inl;
	s += sizeof *inl;

	s += sizeof  __builtin_trap;
	s += sizeof *__builtin_trap;

	return s;
}

/*
 * check-name: sizeof-function
 * check-command: sparse -Wpointer-arith -Wno-decl $file
 *
 * check-error-start
sizeof-function.c:22:14: warning: expression using sizeof on a function
sizeof-function.c:23:14: warning: expression using sizeof on a function
sizeof-function.c:25:14: warning: expression using sizeof on a function
sizeof-function.c:27:14: warning: expression using sizeof on a function
sizeof-function.c:28:14: warning: expression using sizeof on a function
sizeof-function.c:30:14: warning: expression using sizeof on a function
sizeof-function.c:31:14: warning: expression using sizeof on a function
 * check-error-end
 */
