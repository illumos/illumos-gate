char creti(void) { return 3; }
int  ireti(void) { return 3; }
long lreti(void) { return 3; }

char cinii(void) { char r = 3; return r; }
int  iinii(void) { int  r = 3; return r; }
long linii(void) { long r = 3; return r; }


void *vretn(void) { return (void*)0; }
char *cretn(void) { return (void*)0; }
int  *iretn(void) { return (void*)0; }
long *lretn(void) { return (void*)0; }

void *vinin(void) { void *r = (void*)0; return r; }
char *cinin(void) { char *r = (void*)0; return r; }
int  *iinin(void) { int  *r = (void*)0; return r; }
long *linin(void) { long *r = (void*)0; return r; }

/*
 * check-name: type-constant
 * check-command: sparsec -Wno-decl -c $file -o r.o
 */
