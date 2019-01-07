static void
g (struct Bar { int i; } *x)
{
  struct Bar y;
  y.i = 1;
}

static void
h (void)
{
  // This is not in scope and should barf loudly.
  struct Bar y;
  y.i = 1;
}

/*
 * check-name: struct not in scope
 * check-known-to-fail
 *
 * check-error-start
struct-ns2.c:2:11: warning: bad scope for 'struct Bar'
struct-ns2.c:12:14: error: incomplete type/unknown size for 'y'
struct-ns2.c:13:5: error: using member 'i' in incomplete 'struct Bar'
 * check-error-end
 */
