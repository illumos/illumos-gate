const char *s = "abc";
int x = 4;
int y;

int *p = &x;
int *q;

int loadn(void) { return y; }
int loadi(void) { return x; }

const char *loads(void) { return s; }

int *retpn(void) { return  q; }
int loadpn(void) { return *q; }
int *retpi(void) { return  p; }
int loadpi(void) { return *p; }

/*
 * check-name: use simple value from global vars
 * check-command: sparsec -Wno-decl -c $file -o tmp.o
 */
