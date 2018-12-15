#define A(x) ## x
#define B(x) x ##
#define C(x) x ## ## ##
#define D(x) x#y
#define E x#y
#define F(x,y) x x##y #x y
#define G a##b
#define H 1##2
#define I(x,y,z) x y z
"A(x)"			: A(x)
"B(x)"			: B(x)
"C(x)"			: C(x)
"D(x)"			: D(x)
"x#y"			: E
"ab GH \"G\" 12"	: F(G,H)
"a ## b"		: I(a,##,b)
/*
 * check-name: Preprocessor #8
 * check-command: sparse -E $file
 *
 * check-output-start

"A(x)" : A(x)
"B(x)" : B(x)
"C(x)" : C(x)
"D(x)" : D(x)
"x#y" : x#y
"ab GH \"G\" 12" : ab GH "G" 12
"a ## b" : a ## b
 * check-output-end
 *
 * check-error-start
preprocessor/preprocessor8.c:1:14: error: '##' cannot appear at the ends of macro expansion
preprocessor/preprocessor8.c:2:16: error: '##' cannot appear at the ends of macro expansion
preprocessor/preprocessor8.c:3:22: error: '##' cannot appear at the ends of macro expansion
preprocessor/preprocessor8.c:4:15: error: '#' is not followed by a macro parameter
 * check-error-end
 */
