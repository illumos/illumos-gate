static int add(int a, int b) { return (a + b) == (b + a); }
static int mul(int a, int b) { return (a * b) == (b * a); }
static int and(int a, int b) { return (a & b) == (b & a); }
static int ior(int a, int b) { return (a | b) == (b | a); }
static int xor(int a, int b) { return (a ^ b) == (b ^ a); }
static int  eq(int a, int b) { return (a == b) == (b == a); }
static int  ne(int a, int b) { return (a != b) == (b != a); }


/*
 * check-name: cse-commutativity
 * check-command: test-linearize $file
 * check-output-ignore
 *
 * check-output-excludes: add\\.
 * check-output-excludes: muls\\.
 * check-output-excludes: and\\.
 * check-output-excludes: or\\.
 * check-output-excludes: xor\\.
 * check-output-excludes: seteq\\.
 * check-output-excludes: setne\\.
 */
