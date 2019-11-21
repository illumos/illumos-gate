_Bool equ0(unsigned char a) { return a == 0; }
_Bool equ1(unsigned char a) { return a == 1; }
_Bool neu0(unsigned char a) { return a != 0; }
_Bool neu1(unsigned char a) { return a != 1; }

/*
 * check-name: bool-zext-test
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: zext\\.
 */
