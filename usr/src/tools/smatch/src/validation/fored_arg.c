/*
 * check-name: Forced function argument type.
 */

#define __iomem	__attribute__((noderef, address_space(2)))
#define __force __attribute__((force))

static void foo(__force void * addr)
{
}


static void bar(void)
{
	void __iomem  *a;
	foo(a);
}

