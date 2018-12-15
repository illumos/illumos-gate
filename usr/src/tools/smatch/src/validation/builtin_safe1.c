#define MY_MACRO(a) do { \
  __builtin_warning(!__builtin_safe_p(a), "Macro argument with side effects: " #a); \
    a;	\
  } while (0)

int g(int);
int h(int) __attribute__((pure));
int i(int) __attribute__((const));

static int foo(int x, int y)
{
  /* unsafe: */
  MY_MACRO(x++);
  MY_MACRO(x+=1);
  MY_MACRO(x=x+1);
  MY_MACRO(x%=y);
  MY_MACRO(x=y);
  MY_MACRO(g(x));
  MY_MACRO((y,g(x)));
  /* safe: */
  MY_MACRO(x+1);
  MY_MACRO(h(x));
  MY_MACRO(i(x));
  return x;
}

/*
 * check-name: __builtin_safe
 * check-error-start
builtin_safe1.c:13:3: warning: Macro argument with side effects: x++
builtin_safe1.c:14:3: warning: Macro argument with side effects: x+=1
builtin_safe1.c:15:3: warning: Macro argument with side effects: x=x+1
builtin_safe1.c:16:3: warning: Macro argument with side effects: x%=y
builtin_safe1.c:17:3: warning: Macro argument with side effects: x=y
builtin_safe1.c:18:3: warning: Macro argument with side effects: g(x)
builtin_safe1.c:19:3: warning: Macro argument with side effects: (y,g(x))
 * check-error-end
 */
