
#define __u16 unsigned short
int foo(__u16 n);
static inline __u16 f(__u16 val)
{
       return val;
}

static inline unsigned int bar(__u16 n)
{
      switch (n) {
      case (1 ? 1 : f(1)):
              return 4;
      }
}

int foo(__u16 n)
{
       bar(n);
       bar(n);
       return 0;
}
/*
 * check-name: inlining switch statement
 */
