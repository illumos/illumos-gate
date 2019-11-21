unsigned long foo(int a) { return (unsigned int) (a != 0); }

/*
 * check-name: setne0-zext
 * check-command: test-linearize -m64 -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: zext\\.
 */
