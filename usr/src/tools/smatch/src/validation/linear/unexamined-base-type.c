# define __force	__attribute__((force))

struct s {
	int a;
};

static int foo(struct s *s)
{
	return (*((typeof(s->a) __force *) &s->a)) & 1;
}

static void bar(struct s *d, struct s *s1, struct s *s2)
{
	*d = *s1, *d = *s2;
}

/*
 * check-name: unexamined base type
 * check-command: test-linearize -Wno-decl $file
 * check-description:
 *	Test case for missing examine in evaluate_dereference()'s
 *	target base type. In this case, the loaded value has a
 *	a null size, giving the wrongly generated code for foo():
 *		ptrcast.64  %r3 <- (64) %arg1
 *		load        %r4 <- 0[%r3]
 *		    ^^^				!! WRONG !!
 *		cast.32     %r5 <- (0) %r4
 *		                   ^^^		!! WRONG !!
 *		and.32      %r6 <- %r5, $1
 *		ret.32      %r6
 *
 * check-output-ignore
 * check-output-excludes: load[^.]
 * check-output-excludes: cast\\..*(0)
 * check-output-excludes: store[^.]
 */
