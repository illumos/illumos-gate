#include "predef.c"

/*
 * check-name: predefined macros for LP64
 * check-command: test-linearize -Wno-decl -m64 $file
 * check-output-ignore
 *
 * check-output-contains: ret\\..*\\$0
 */
