int bne0(int a) { return a != 0; }
int bnoteq0(int a) { return !(a == 0); }
int bnotnot(int a) { return !(!a); }

/*
 * check-name: bool-ne0
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-excludes: seteq\\.
 * check-output-contains: setne\\.
 */
