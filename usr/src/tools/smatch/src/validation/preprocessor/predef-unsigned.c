#include "predef.c"

/*
 * check-name: predefined macros for -funsigned-char
 * check-command: test-linearize -Wno-decl -funsigned-char $file
 * check-output-ignore
 *
 * check-output-contains: ret\\..*\\$0
 */
