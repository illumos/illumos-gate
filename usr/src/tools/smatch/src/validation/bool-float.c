int ftst(double a)  { return !a; }

/*
 * check-name: not-operator on float
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-excludes: \\$0
 */
