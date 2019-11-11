extern void *malloc(unsigned long);

static inline __attribute__((__const__)) unsigned squarec(unsigned n)
{
        return n*n;
}

static inline unsigned square(unsigned n)
{
        return n*n;
}

static inline unsigned long long bignum(void)
{
        return 1000000000000ULL;
}

static inline __attribute__((__const__)) unsigned long long bignumc(void)
{
        return 1000000000000ULL;
}

// test if x is an integer constant expression [C99,C11 6.6p6]
#define ICE_P(x) \
    (__builtin_types_compatible_p(typeof(0?((void*)((long)(x)*0l)):(int*)1),int*))

#define CHX_P(X)	__builtin_choose_expr(ICE_P(X), 1, 0)
#define CST_P(X)	__builtin_constant_p(ICE_P(X))

#define TEST(R, X)	_Static_assert(ICE_P(X) == R, "ICE_P(" #X ") => " #R);	\
			_Static_assert(ICE_P(ICE_P(X)), "ICE_P2(" #X ")");	\
			_Static_assert(CHX_P(X) == R, "CHX_P(" #X ") => " #R);	\
			_Static_assert(CST_P(X) == 1, "CST_P(" #X ")")

int main(int argc, char *argv[])
{
        char fla[3];
        char vla[argc++];
        char **p, **q;
        int x = 5, y = 8;
        void *v;

        p = &argv[3];
        q = &argv[6];

        TEST(1, 4);
        TEST(1, sizeof(long));
        TEST(1, 5ull - 3u);
        TEST(1, 3.2);
        TEST(1, sizeof(fla));

        TEST(0, square(2));
        TEST(0, square(argc));
        TEST(0, squarec(2));
        TEST(0, squarec(argc));
        TEST(0, 1+argc-argc);
        TEST(0, 1+argc+argc+1-argc-argc);
        TEST(0, bignum() - 1);
        TEST(0, 0*bignum());
        TEST(0, 0*bignumc());
        TEST(0, sizeof(vla));
        TEST(0, p);
        TEST(0, p < q);
        TEST(0, p++);
        TEST(0, main);
        TEST(0, malloc(8));
        TEST(0, v = malloc(8));
        TEST(0, v);
        TEST(0, x++);
        TEST(0, y++);
        TEST(0, (3, 2, 1));
        TEST(0, ({x++; 0; }));
        TEST(0, ({square(y--); 0; }));
        TEST(0, (square(x), 3));
        TEST(0, (squarec(x), 3));
        TEST(0, ({squarec(x); 3;}));
        TEST(0, ({squarec(x);}));

        return 0;
}

/*
 * check-name: integer-const-expr
 * check-command: sparse -Wno-vla $file
 */
