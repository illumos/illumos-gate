void keep(int *p)	 { *p = 0; }
void kill(int *p, int i) { if (i && 0) *p = 0; }
void dead(int *p, int i) { int v = i++; if (i && 0) p[v] = 0; }


/*
 * check-name: kill-store
 * check-command: test-linearize -Wno-decl $file
 * check-description:
 *	Check that stores are optimized away but only
 *	when needed:
 *	- bb unreachable.
 *
 * check-output-ignore
 * check-output-pattern(1): store\\.
 */
