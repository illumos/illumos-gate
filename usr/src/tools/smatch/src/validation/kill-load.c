int keep(volatile int *p)	{ return *p && 0; }
int kill(int *p, int i)		{ return *p && 0; }
void ind(volatile int *p,int i)	{ int v = i++; if (i && 0) p[v]; }


/*
 * check-name: kill-load
 * check-command: test-linearize -Wno-decl $file
 * check-description:
 *	Check that loads are optimized away but only
 *	when needed:
 *	- non-volatile
 *	- bb unreachable.
 *
 * check-output-ignore
 * check-output-pattern(1): load\\.
 */
