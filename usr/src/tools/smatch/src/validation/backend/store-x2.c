void foo(int *p, int a, int b);
void foo(int *p, int a, int b)
{
	int c = a + b;

	p[0] = c;
	p[1] = c;
}

/*
 * check-name: store-x2
 * check-command: sparsec -c $file -o tmp.o
 * check-description: Verify in output_op_store() that
 *	the first store doesn't mess anymore with the
 *	'target' and thus making the second store unusable.
 */
