static _Thread_local int foo;

/*
 * check-name: c11-thread-local
 * check-command: test-parsing -std=c11 $file
 *
 * check-output-ignore
 * check-output-contains: \\[tls\\]
 */
