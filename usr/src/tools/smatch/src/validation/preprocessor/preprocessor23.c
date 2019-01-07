#define H(x,...) ,##x##__VA_ARGS__##,##__VA_ARGS__
H()
H(x)
H(,)
H(x,)
H(,x)
H(x,x)
#define I(x,...) ,##x##__VA_ARGS__
I()
I(x)
I(,)
I(x,)
I(,x)
I(x,x)
#define J(...) ,##__VA_ARGS__
J()
J(x)
/*
 * check-name: Preprocessor #23
 * check-command: sparse -E $file
 *
 * check-output-start

,
,x
,,
,x,
,x,x
,xx,x
,x
,
,x
,x
,xx
,x
 * check-output-end
 *
 * check-error-start
preprocessor/preprocessor23.c:3:1: error: '##' failed: concatenation is not a valid token
preprocessor/preprocessor23.c:4:1: error: '##' failed: concatenation is not a valid token
preprocessor/preprocessor23.c:5:1: error: '##' failed: concatenation is not a valid token
preprocessor/preprocessor23.c:5:1: error: '##' failed: concatenation is not a valid token
preprocessor/preprocessor23.c:6:1: error: '##' failed: concatenation is not a valid token
preprocessor/preprocessor23.c:6:1: error: '##' failed: concatenation is not a valid token
preprocessor/preprocessor23.c:7:1: error: '##' failed: concatenation is not a valid token
preprocessor/preprocessor23.c:7:1: error: '##' failed: concatenation is not a valid token
preprocessor/preprocessor23.c:10:1: error: '##' failed: concatenation is not a valid token
preprocessor/preprocessor23.c:12:1: error: '##' failed: concatenation is not a valid token
preprocessor/preprocessor23.c:14:1: error: '##' failed: concatenation is not a valid token
 * check-error-end
 */
