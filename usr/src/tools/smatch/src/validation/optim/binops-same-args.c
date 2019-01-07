typedef unsigned int u32;

int ssub(int a) { return a - a; }
u32 usub(u32 a) { return a - a; }

int sdiv(int a) { return a / a; }
u32 udiv(u32 a) { return a / a; }
int smod(int a) { return a % a; }
u32 umod(u32 a) { return a % a; }

int seq(int a) { return a == a; }
int sne(int a) { return a != a; }
int slt(int a) { return a < a; }
int sgt(int a) { return a > a; }
int sle(int a) { return a <= a; }
int sge(int a) { return a >= a; }

u32 ueq(u32 a) { return a == a; }
u32 une(u32 a) { return a != a; }
u32 ult(u32 a) { return a < a; }
u32 ugt(u32 a) { return a > a; }
u32 ule(u32 a) { return a <= a; }
u32 uge(u32 a) { return a >= a; }

u32 xor(u32 a) { return a ^ a; }

u32 ior(u32 a) { return a | a; }
u32 and(u32 a) { return a & a; }

/*
 * check-name: double-unop
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-excludes: sub\\.
 * check-output-contains: divs\\.
 * check-output-contains: divu\\.
 * check-output-contains: mods\\.
 * check-output-contains: modu\\.
 * check-output-excludes: seteq\\.
 * check-output-excludes: setne\\.
 * check-output-excludes: set[gl]t\\.
 * check-output-excludes: set[gl]e\\.
 * check-output-excludes: set[ab]\\.
 * check-output-excludes: set[ab]e\\.
 * check-output-excludes: xor\\.
 * check-output-excludes: or\\.
 * check-output-excludes: and\\.
 */
