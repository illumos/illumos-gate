#define A __attribute__((address_space(1)))
static int (A *p);
static int A *q;
static void (*f)(A int *x, A int *y) = (void *)0;
static void g(int A *x)
{
	f(x, x);
	p = q;
}
/*
 * check-name: attribute after ( in direct-declarator
 */
