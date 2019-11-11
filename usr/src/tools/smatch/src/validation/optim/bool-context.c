#define bool _Bool

bool bool_ior(int a, int b) { return a || b; }
bool bool_and(int a, int b) { return a && b; }

/*
 * check-name: bool-context
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-pattern(4): setne\\..* %arg[12]
 */
