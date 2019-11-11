extern int fun(void);

int ff(void) { return fun(); }

int f0(void) { return (fun)(); }
int f1(void) { return (*fun)(); }	// C99,C11 6.5.3.2p4
int f2(void) { return (**fun)(); }	// C99,C11 6.5.3.2p4
int f3(void) { return (***fun)(); }	// C99,C11 6.5.3.2p4

/*
 * check-name: direct calls
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: load
 * check-output-pattern(5): call\\..* fun
 */
