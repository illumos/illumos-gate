#include "predef.c"

/*
 * check-name: predefined macros for LP32
 * check-command: test-linearize -Wno-decl -m32 $file
 * check-output-ignore
 *
 * check-output-contains: ret\\..*\\$0
 */
