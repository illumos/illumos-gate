int gg(int (*fun)(void)) { return fun(); }

int g0(int (*fun)(void)) { return (fun)(); }
int g1(int (*fun)(void)) { return (*fun)(); }	// C99,C11 6.5.3.2p4
int g2(int (*fun)(void)) { return (**fun)(); }	// C99,C11 6.5.3.2p4
int g3(int (*fun)(void)) { return (***fun)(); }	// C99,C11 6.5.3.2p4

/*
 * check-name: indirect calls
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: load
 * check-output-pattern(5): call\\..* %arg1
 */
