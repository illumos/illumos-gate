static void foo(enum bar baz);

/*
 * check-name: enum not in scope
 * check-known-to-fail
 *
 * check-error-start
badtype1.c:1:22: warning: bad scope for 'enum bar'
 * check-error-end
 */
