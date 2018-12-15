typedef unsigned int u32;

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

/*
 * check-name: tautological-compare
 * check-command: sparse -Wno-decl -Wtautological-compare $file
 *
 * check-error-start
tautological-compare.c:3:30: warning: self-comparison always evaluates to true
tautological-compare.c:4:30: warning: self-comparison always evaluates to false
tautological-compare.c:5:29: warning: self-comparison always evaluates to false
tautological-compare.c:6:29: warning: self-comparison always evaluates to false
tautological-compare.c:7:30: warning: self-comparison always evaluates to true
tautological-compare.c:8:30: warning: self-comparison always evaluates to true
tautological-compare.c:10:30: warning: self-comparison always evaluates to true
tautological-compare.c:11:30: warning: self-comparison always evaluates to false
tautological-compare.c:12:29: warning: self-comparison always evaluates to false
tautological-compare.c:13:29: warning: self-comparison always evaluates to false
tautological-compare.c:14:30: warning: self-comparison always evaluates to true
tautological-compare.c:15:30: warning: self-comparison always evaluates to true
 * check-error-end
 */
