static int ior(int a) { return a || a; }
static int and(int a) { return a && a; }

/*
 * check-name: bool-same-args
 * check-command: test-linearize $file
 * check-output-ignore
 *
 * check-output-excludes: or-bool\\.
 * check-output-excludes: and-bool\\.
 * check-output-contains: setne\\.
 */
