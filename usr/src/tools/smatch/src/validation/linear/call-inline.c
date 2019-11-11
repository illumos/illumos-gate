static inline int fun(void) { return 42; }

int fi(void) { return fun(); }

int i0(void) { return (fun)(); }
int i1(void) { return (*fun)(); }		// C99,C11 6.5.3.2p4
int i2(void) { return (**fun)(); }		// C99,C11 6.5.3.2p4
int i3(void) { return (***fun)(); }		// C99,C11 6.5.3.2p4

/*
 * check-name: inline calls
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: load
 * check-output-excludes: call
 * check-output-pattern(5): ret\\..* \\$42
 */
