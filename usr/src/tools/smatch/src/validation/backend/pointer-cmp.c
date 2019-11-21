int cmpint(   int x,   int y)	{ return x == y; }
int cmpflt( float x, float y)	{ return x == y; }
int cmpvptr(void *x, void *y)	{ return x == y; }
int cmpiptr(int  *x, int  *y)	{ return x == y; }

int cmpmptr(long  x, int  *y)	{ return (int*)x == y; }
int cmpnptr(int  *x, long  y)	{ return x == (int*)y; }

/*
 * check-name: pointer comparison
 * check-command: sparsec -Wno-decl -c $file -o tmp.o
 */
