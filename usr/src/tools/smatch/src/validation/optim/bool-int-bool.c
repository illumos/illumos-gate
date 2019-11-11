_Bool beq0(_Bool a) { return (a == 0); }
_Bool beq1(_Bool a) { return (a == 1); }
_Bool bne0(_Bool a) { return (a != 0); }
_Bool bne1(_Bool a) { return (a != 1); }

/*
 * check-name: bool - int - bool constants
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: cast\\.
 */
