static _Noreturn void foo(void) { while (1) ; }

/*
 * check-name: c11-noreturn
 * check-command: test-parsing -std=c11 $file
 *
 * check-output-ignore
 * check-output-contains: \\[noreturn\\]
 */
