int a.

/*
 * check-name: fdiag-prefix
 * check-command: sparse -fdiagnostic-prefix=prefix $file
 *
 * check-error-start
fdiag-prefix.c:1:6: prefix: error: Expected ; at end of declaration
fdiag-prefix.c:1:6: prefix: error: got .
 * check-error-end
 */
