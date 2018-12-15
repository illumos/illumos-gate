void *foo(void) __attribute__((__assume_aligned__(4096)));
void *foo(void) __attribute__((assume_aligned(4096)));
/*
 * check-name: attribute assume_aligned
 */

