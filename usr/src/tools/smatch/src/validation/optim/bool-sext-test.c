_Bool eqs0(  signed char a) { return a == 0; }
_Bool eqs1(  signed char a) { return a == 1; }
_Bool nes0(  signed char a) { return a != 0; }
_Bool nes1(  signed char a) { return a != 1; }

/*
 * check-name: bool-sext-test
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: sext\\.
 */
