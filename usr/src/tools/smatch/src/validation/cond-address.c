extern void f(void);
extern int a[];

int foo(void) { if (f) return 1; return 0; }
int bar(void) { if (a) return 1; return 0; }
int qux(void) { if (f && a) return 1; return 0; }

/*
 * check-name: cond-address.c
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-excludes: VOID
 */
