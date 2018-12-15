#include "lib.h"
#include "allocate.h"
#include <stdio.h>
#include <stdlib.h>

static int
int_cmp (const void *_a, const void *_b)
{
  const int *a = _a;
  const int *b = _b;
  return *a - *b;
}

#define MIN(_x,_y) ((_x) < (_y) ? (_x) : (_y))

int
main (int argc, char **argv)
{
  struct ptr_list *l = NULL, *l2;
  int i, *e;
  const int N = argv[1] ? atoi (argv[1]) : 10000;

  srand (N);
  for (i = 0; i < 1000; i++)
    (void)rand ();

  for (i = 0; i < N; i++) {
    e = (int *)malloc (sizeof (int));
    *e = rand ();
    add_ptr_list (&l, e);
  }
  sort_list (&l, int_cmp);
  // Sort already sorted stuff.
  sort_list (&l, int_cmp);

  l2 = l;
  do {
    l2->nr = MIN (l2->nr, rand () % 3);
    for (i = 0; i < l2->nr; i++)
      *((int *)(l2->list[i])) = rand();
    l2 = l2->next;
  } while (l2 != l);
  sort_list (&l, int_cmp);

  return 0;
}
