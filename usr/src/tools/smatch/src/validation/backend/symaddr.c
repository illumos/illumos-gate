extern void useip(int *);
extern void useia(int (*)[3]);
extern void usevp(void *);
static int  sfun(void) { return 0; }
static int  spun(void) { return 0; }

void lfoo(int *p, int a)
{
	int larra[3], larrb[3], larrc[3], larrd[3], larre[3], larrf[3];
	useip(p);
	useip(larra);
	useip(larrb + 1);
	useip(larrc + a);
	useip(&larrd[1]);
	useip(&larre[a]);
	useia(&larrf);
}

static int sarra[3], sarrb[3], sarrc[3], sarrd[3], sarre[3], sarrf[3];
static int s, sfun(void), spun(void);
void sfoo(int *p, int a)
{
	useip(p);
	useip(&s);
	useip(sarra);
	useip(sarrb + 1);
	useip(sarrc + a);
	useip(&sarrd[1]);
	useip(&sarre[a]);
	useia(&sarrf);
	usevp(sfun);
	usevp(&spun);
}

extern int xarra[3], xarrb[3], xarrc[3], xarrd[3], xarre[3], xarrf[3];
extern int x, xfun(void), xpun(void);
void xfoo(int *p, int a)
{
	useip(p);
	useip(&x);
	useip(xarra);
	useip(xarrb + 1);
	useip(xarrc + a);
	useip(&xarrd[1]);
	useip(&xarre[a]);
	useia(&xarrf);
	usevp(xfun);
	usevp(&xpun);
}

int garra[3], garrb[3], garrc[3], garrd[3], garre[3], garrf[3];
int g, gfun(void), gpun(void);
void gfoo(int *p, int a)
{
	useip(p);
	useip(&g);
	useip(garra);
	useip(garrb + 1);
	useip(garrc + a);
	useip(&garrd[1]);
	useip(&garre[a]);
	useia(&garrf);
	usevp(gfun);
	usevp(&gpun);
}

/*
 * check-name: symbol address
 * check-command: sparsec -Wno-decl -c $file -o tmp.o
 */
