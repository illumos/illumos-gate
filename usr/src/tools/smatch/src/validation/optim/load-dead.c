void foo(int *p) { *p; }

int *p;
void bar(void) { *p; }

/*
 * check-name: load-dead
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 * check-output-excludes: load\\.
 */
