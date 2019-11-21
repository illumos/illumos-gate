__CHECKER__
F(__CHECKER__,__CHECKER__)
S(#__CHECKER__)
const char str[] = "__CHECKER__";

/*
 * check-name: builtin
 * check-command: sparse -E $file
 *
 * check-output-start

1
F(1,1)
S(#1)
const char str[] = "__CHECKER__";
 * check-output-end
 */
