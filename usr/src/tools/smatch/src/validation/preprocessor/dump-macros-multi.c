/*
 * check-name: dump-macros with multiple files
 * check-command: sparse -E -dD empty-file $file
 *
 * check-output-ignore
check-output-pattern-2-times: #define __CHECKER__ 1
 */
