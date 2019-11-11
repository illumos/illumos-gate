/*
 * check-name: dump-macros with empty file
 * check-command: sparse -E -dD empty-file
 *
 * check-output-ignore
check-output-pattern(1): #define __CHECKER__ 1
 */
