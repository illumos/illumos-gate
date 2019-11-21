#include "predef.c"

/*
 * check-name: predefined macros for LLP64
 * check-command: test-linearize -Wno-decl -msize-llp64 $file
 * check-output-ignore
 *
 * check-output-contains: ret\\..*\\$0
 */
