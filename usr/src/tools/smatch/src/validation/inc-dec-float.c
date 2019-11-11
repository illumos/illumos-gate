double fincpre(double a)  { ++a; return a; }
double fdecpre(double a)  { --a; return a; }
double fincpost(double a) { a++; return a; }
double fdecpost(double a) { a--; return a; }

/*
 * check-name: float inc & dec
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-excludes: \\$1$
 * check-output-excludes: \\$-1$
 */
