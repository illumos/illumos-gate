#define A(1) x
#define B(x
#define C(x,
#define D(,)
#define E(__VA_ARGS__)
#define F(x+
#define G(x...,
#define H(x...,y)
#define I(...+
#define J(x,y)
/*
 * check-name: Preprocessor #11
 * check-command: sparse -E $file
 *
 * check-output-start


 * check-output-end
 *
 * check-error-start
preprocessor/preprocessor11.c:1:11: error: "1" may not appear in macro parameter list
preprocessor/preprocessor11.c:2:11: error: missing ')' in macro parameter list
preprocessor/preprocessor11.c:3:12: error: missing ')' in macro parameter list
preprocessor/preprocessor11.c:4:11: error: parameter name missing
preprocessor/preprocessor11.c:5:11: error: __VA_ARGS__ can only appear in the expansion of a C99 variadic macro
preprocessor/preprocessor11.c:6:12: error: "+" may not appear in macro parameter list
preprocessor/preprocessor11.c:7:12: error: missing ')' in macro parameter list
preprocessor/preprocessor11.c:8:12: error: missing ')' in macro parameter list
preprocessor/preprocessor11.c:9:11: error: missing ')' in macro parameter list
 * check-error-end
 */
