//typedef int undef;
extern undef bar(void);
static undef foo(char *c)
{
  char p = *c;
  switch (p) {
  default:
    return bar();
  }
}

/*
 * check-name: missing type
 * check-error-start
badtype2.c:2:8: warning: 'undef' has implicit type
badtype2.c:2:14: error: Expected ; at end of declaration
badtype2.c:2:14: error: got bar
badtype2.c:3:14: error: Expected ; at end of declaration
badtype2.c:3:14: error: got foo
badtype2.c:6:3: error: Trying to use reserved word 'switch' as identifier
badtype2.c:7:3: error: not in switch scope
badtype2.c:10:1: error: Expected ; at the end of type declaration
badtype2.c:10:1: error: got }
 * check-error-end
 */
