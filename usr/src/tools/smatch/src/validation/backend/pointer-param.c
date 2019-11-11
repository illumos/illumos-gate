extern int gfun(int);
static int sfun(int a) { return a; }

void usei(int *);
void usef(int (*)(int));
void usev(void *);

void foo(int *p, int a[5], int (*pfun)(int));
void foo(int *p, int a[5], int (*pfun)(int))
{
	extern int valg[5], valh[5], vali[5];
	static int vals[5], valt[5], valr[5];
	       int vala[5], valb[5], valc[5];

	usei(p);
	usei(valg);
	usei(&valh[0]);
	usei(&vali[1]);
	usei(vals);
	usei(&valt[0]);
	usei(&valr[1]);
	usei(vala);
	usei(&valb[0]);
	usei(&valc[1]);

	usef(pfun);
	usef(gfun);
	usef(&gfun);
	usef(sfun);
	usef(&sfun);

	usev(pfun);
	usev(gfun);
	usev(&gfun);
	usev(sfun);
	usev(&sfun);
}

/*
 * check-name: pointer-param
 * check-command: sparsec -c $file -o tmp.o
 */
