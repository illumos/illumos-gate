int
foo (int (*func) (undef, void *), void *data)
{
  int err = 0;
  while (cur) {
    if ((*func) (cur, data))
      break;
  }
  return err;
}

/*
 * check-name: missing type in argument list
 * check-error-start
badtype3.c:2:18: warning: identifier list not in definition
badtype3.c:2:24: error: Expected ) in function declarator
badtype3.c:2:24: error: got ,
badtype3.c:5:3: error: Trying to use reserved word 'while' as identifier
badtype3.c:7:7: error: break/continue not in iterator scope
badtype3.c:9:3: error: Trying to use reserved word 'return' as identifier
badtype3.c:9:10: error: Expected ; at end of declaration
badtype3.c:9:10: error: got err
badtype3.c:10:1: error: Expected ; at the end of type declaration
badtype3.c:10:1: error: got }
badtype3.c:6:11: error: undefined identifier 'func'
 * check-error-end
 */
