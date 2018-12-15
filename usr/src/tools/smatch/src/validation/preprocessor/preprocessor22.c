#define CONFIG_FOO 1

#define define_struct(name, fields...) struct fields name;

define_struct(a, {
#ifdef CONFIG_FOO
  int b;
#elif defined(CONFIG_BAR)
  int c;
#else
  int d;
#endif
});
/*
 * check-name: Preprocessor #22
 *
 * check-description: Directives are not allowed within a macro argument list,
 * although cpp deals with it to treat macro more like C functions.
 *
 * check-command: sparse -E $file
 *
 * check-error-start
preprocessor/preprocessor22.c:6:1: error: directive in argument list
preprocessor/preprocessor22.c:8:1: error: directive in argument list
preprocessor/preprocessor22.c:10:1: error: directive in argument list
preprocessor/preprocessor22.c:12:1: error: directive in argument list
 * check-error-end
 *
 * check-output-start

struct {
int b;
} a;;
 * check-output-end
 */
