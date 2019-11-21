char foo(int a) { return a != 0; }

/*
 * check-name: setne0-trunc
 * check-command: test-linearize -m64 -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: trunc\\.
 */
