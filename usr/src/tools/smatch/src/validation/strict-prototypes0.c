extern void func1();
extern void myfunction(), myfunc2();

/*
 * check-name: strict-prototypes disabled
 * check-command: sparse -Wno-strict-prototypes $file
 */
