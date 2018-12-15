extern int foo (const char *, ...);
static void sparse_error(const char err[])
{
  foo("%s\n",err);
}
/*
 * check-name: Varargs bogus warning regression test #1
 */
