typedef int  ok_t;
typedef int  ok_t;

typedef int  ko_t;
typedef long ko_t;

/*
 * check-name: typedef-redef
 *
 * check-error-start
typedef-redef.c:5:14: error: symbol 'ko_t' redeclared with different type (originally declared at typedef-redef.c:4) - different type sizes
 * check-error-end
 */
