static int eqeq(int a, int b) { return (a == b) == (b == a); }
static int nene(int a, int b) { return (a != b) == (b != a); }

static int ltgt(int a, int b) { return (a <  b) == (b >  a); }
static int lege(int a, int b) { return (a <= b) == (b >= a); }
static int gele(int a, int b) { return (a >= b) == (b <= a); }
static int gtlt(int a, int b) { return (a >  b) == (b <  a); }

static int eneqne(int a, int b) { return (a == b) == !(b != a); }
static int enneeq(int a, int b) { return (a != b) == !(b == a); }

static int enltle(int a, int b) { return (a <  b) == !(b <= a); }
static int enlelt(int a, int b) { return (a <= b) == !(b <  a); }
static int engegt(int a, int b) { return (a >= b) == !(b >  a); }
static int engtge(int a, int b) { return (a >  b) == !(b >= a); }

static int neeqne(int a, int b) { return (a == b) != (b != a); }
static int neneeq(int a, int b) { return (a != b) != (b == a); }

static int neltle(int a, int b) { return (a <  b) != (b <= a); }
static int nelelt(int a, int b) { return (a <= b) != (b <  a); }
static int negegt(int a, int b) { return (a >= b) != (b >  a); }
static int negtge(int a, int b) { return (a >  b) != (b >= a); }

/*
 * check-name: cse-dual-compare
 * check-command: test-linearize $file
 * check-output-ignore
 * check-known-to-fail
 *
 * check-output-excludes: set[gl][et]\\.
 * check-output-excludes: seteq\\.
 * check-output-excludes: setne\\.
 */
