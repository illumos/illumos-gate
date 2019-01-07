extern char a;
extern int b;
extern char *c, *d;
extern void e(void);
extern void f(char *);

int g(int h);
int g(int h)
{
	if (h > 1)
		e();
	if (h > 1)
		return 0;
	for (;;) {
		if (a) {
			while (c) ;
			b = 0;
		} else {
			c = (void*)0;
			b = 1;
		}
		if (b) {
			f(c);
			continue;
		}
		d = c;
		while (*c++) ;
	}
}

/*
 * check-name: crazy03.c
 */
