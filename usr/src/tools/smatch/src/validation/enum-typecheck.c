enum good { G, };
enum bad  { B, };
enum good g;

enum good compat_int(void) { return 1; }

void parg(enum good);
void parg(enum bad);

void farg(enum good a);
void farg(enum bad  a) { }

enum good pret(void);
enum bad  pret(void);

enum good fret(void);
enum bad  fret(void) { return 0; }


enum good *ptr;
enum bad  *ptr;

enum good *gptr = &g;
enum bad  *bptr = &g;

/*
 * check-name: enum-typecheck
 * check-command: sparse -Wno-decl $file
 * check-known-to-fail
 *
 * check-error-start
enum-typecheck.c:8:6: error: symbol 'parg' redeclared with different type
enum-typecheck.c:11:6: error: symbol 'farg' redeclared with different type
enum-typecheck.c:14:11: error: symbol 'pret' redeclared with different type
enum-typecheck.c:17:11: error: symbol 'fret' redeclared with different type
enum-typecheck.c:21:12: error: symbol 'ptr' redeclared with different type
enum-typecheck.c:24:20: warning: incorrect type in initializer (different type sizes)
 * check-error-end
 */
