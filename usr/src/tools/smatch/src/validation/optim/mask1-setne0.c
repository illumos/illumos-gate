struct s {
	unsigned i:1;
};

int foo(struct s x)
{
	unsigned int i = x.i;

	if (i == 0)
		return 1;
	else if (i == 1)
		return 1;
	return 0;
}

/*
 * check-name: mask1-setne0
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
foo:
.L0:
	<entry-point>
	ret.32      $1


 * check-output-end
 */
