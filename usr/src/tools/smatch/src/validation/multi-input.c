int a = 1;
int foo(void) {}

static int b = 1;
static int bar(void) {}

/*
 * check-name: multi-input
 * check-command: sparse -Wno-decl $file $file
 * check-known-to-fail
 */
