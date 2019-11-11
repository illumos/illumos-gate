extern int fun(void);

void fa(void) { int (*f)(void); f = &fun; }
void f0(void) { int (*f)(void); f = fun; }	// C99,C11 6.3.2.1p4
void f1(void) { int (*f)(void); f = *fun; }	// C99,C11 6.5.3.2p4
void f2(void) { int (*f)(void); f = **fun; }	// C99,C11 6.5.3.2p4
void f3(void) { int (*f)(void); f = ***fun; }	// C99,C11 6.5.3.2p4

/*
 * check-name: type of function pointers
 * check-command: sparse -Wno-decl $file
 */
