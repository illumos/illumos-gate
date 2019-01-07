struct A;
struct B {
  struct A *pA;
};
struct C;
struct E {
  struct A **pA;
  struct C *pC;
};
static void f(struct E *pE, struct B *pB)
{
  pB->pA = pE->pA[0];
}
static const struct { int x; } foo[] = {{ 1 }};
struct C {
  int bar[(sizeof foo/sizeof foo[0])];
};

/*
 * check-name: struct size
 */
