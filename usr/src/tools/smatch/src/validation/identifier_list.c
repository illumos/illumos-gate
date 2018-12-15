typedef int T;
void f(...);
void g(*);
void h(x,int);
void i_OK(T);
void j(x,T);
/*
 * check-name: identifier-list parsing
 * check-error-start
identifier_list.c:2:8: warning: variadic functions must have one named argument
identifier_list.c:3:8: error: Expected ) in function declarator
identifier_list.c:3:8: error: got *
identifier_list.c:4:9: error: Expected ) in function declarator
identifier_list.c:4:9: error: got ,
identifier_list.c:6:9: error: Expected ) in function declarator
identifier_list.c:6:9: error: got ,
 * check-error-end
 */
