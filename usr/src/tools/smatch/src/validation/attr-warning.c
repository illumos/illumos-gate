# define __warndecl(name, msg) \
  extern void name (void) __attribute__((__warning__ (msg)))

__warndecl (__warn_func, "warn message");

/*
 * check-name: attribute warning
 */
