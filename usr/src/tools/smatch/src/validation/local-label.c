void f(unsigned long ip);
static void g(void)
{
       if (1) {
	     f(({ __label__ x; x: (unsigned long)&&x; }));
       }
       f(({ __label__ x; x: (unsigned long)&&x; }));
}
/*
 * check-name: Local label
 */
