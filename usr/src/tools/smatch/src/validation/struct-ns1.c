// This actually isn't allowed in C99, but sparse and gcc will take it:
enum Foo;

static void
f (void)
{
  enum Foo *pefoo;         // Pointer to incomplete type
  struct Foo;              // Forward declaration
  struct Foo *psfoo;       // Pointer to incomplete type
  {
    struct Foo { int foo; }; // Local definition.
    struct Foo foo;          // variable declaration.
    foo.foo = 1;
  }
}

enum Foo { FOO };
/*
 * check-name: struct namespaces #1
 */
