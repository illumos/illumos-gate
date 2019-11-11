int  tstv(void *p) { return !p; }
int  cmpv(void *p) { return p == ((void*)0); }

int  tsti(int  *p) { return !p; }
int  cmpi(int  *p) { return p == ((int *)0); }
int  cmpx(int  *p) { return p == ((void*)0); }

/*
 * check-name: compare-with-null
 * check-command: sparsec -Wno-decl -c $file -o tmp.o
 * check-output-ignore
 */
