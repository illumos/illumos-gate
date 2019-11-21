M(0,1)
/*
 * check-name: cli: allow spaces in macros
 * check-command: sparse -E '-DM(X, Y)=a' $file
 *
 * check-output-start

a
 * check-output-end
 */
