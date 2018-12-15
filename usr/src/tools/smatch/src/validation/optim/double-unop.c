typedef unsigned int u32;

u32 unotnot(u32 a) { return ~(~a); }
int snotnot(int a) { return ~(~a); }
u32 unegneg(int a) { return -(-a); }
int snegneg(int a) { return -(-a); }

/*
 * check-name: double-unop
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-excludes: not\\.
 * check-output-excludes: neg\\.
 */
