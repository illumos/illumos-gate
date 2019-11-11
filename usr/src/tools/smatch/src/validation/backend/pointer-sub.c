long subv0(void *p, int   a) { return p - ((void*)0); }
long subvc(void *p, int   a) { return p - ((void*)8); }
long subva(void *p, int   a) { return p - ((void*)a); }
long subvq(void *p, void *q) { return p - q; }

long subi0(int  *p, int   a) { return p - ((int *)0); }
long subic(int  *p, int   a) { return p - ((int *)8); }
long subia(int  *p, int   a) { return p - ((int *)a); }
long subiq(int  *p, int  *q) { return p - q; }

long subvm3(void *p, int   a) { return (p - ((void*)0)) * 3; }
long subvx3(void *p, int   a) { return (p - ((void*)0)) ^ 3; }

/*
 * check-name: pointer-sub
 * check-command: sparsec -Wno-int-to-pointer-cast -Wno-decl -c $file -o tmp.o
 */
