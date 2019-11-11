struct s {
	char a:3;
	char b:3;
	char c:2;
};

void foo(struct s *p)
{
	p->a = 1;
	p->b = 2;
	p->c = 3;
}

/*
 * check-name: and-or-bf2
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
foo:
.L0:
	<entry-point>
	store.8     $209 -> 0[%arg1]
	ret


 * check-output-end
 */
