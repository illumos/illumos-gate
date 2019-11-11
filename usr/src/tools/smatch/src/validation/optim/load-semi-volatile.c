struct s {
	volatile int a;
};

struct s s;

void foo(void)
{
	s;
	s.a;
}

/*
 * check-name: load-semi-volatile
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(1): load
 *
 * check-description:
 *	The load at line 9 must be removed.
 *	The load at line 10 is volatile and thus
 *	must not be removed.
 */
