int beq0(int a) { return a == 0; }
int bnotne0(int a) { return !(a != 0); }
int bnot(int a) { return !a; }

/*
 * check-name: bool-eq0
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-excludes: setne\\.
 * check-output-contains: seteq\\.
 */
