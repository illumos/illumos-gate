static void OK(void)
{
#define TEST(x) { T a; x *b = &a; }
#define TEST2(x, y) TEST(x y) TEST(y x)
#define TEST3(x, y, z) TEST(x y z) TEST(x z y) TEST(y x z) \
		       TEST(y z x) TEST(z x y) TEST(z y x)
#define TEST4(x, y, z, w) TEST2(x y, z w) TEST2(x y, w z) \
			  TEST2(y x, z w) TEST2(y x, w z) \
			  TEST2(x z, y w) TEST2(x z, w y) \
			  TEST2(z x, y w) TEST2(z x, w y) \
			  TEST2(x w, y z) TEST2(x w, z y) \
			  TEST2(w x, y z) TEST2(w x, z y)


#define T char
TEST(char)
#undef T

#define T signed char
TEST2(char, signed)
#undef T

#define T unsigned char
TEST2(char, unsigned)
#undef T

#define T short
TEST(short)
TEST2(int, short)
#undef T

#define T int
TEST(int)
#undef T

#define T long
TEST(long)
TEST2(int, long)
#undef T

#define T long long
TEST2(long, long)
TEST3(int, long, long)
#undef T

#define T signed short
TEST2(short, signed)
TEST3(int, short, signed)
#undef T

#define T signed
TEST(signed)
TEST2(int, signed)
#undef T

#define T signed long
TEST2(long, signed)
TEST3(int, long, signed)
#undef T

#define T signed long long
TEST3(long, long, signed)
TEST4(int, long, long, signed)
#undef T

#define T unsigned short
TEST2(short, unsigned)
TEST3(int, short, unsigned)
#undef T

#define T unsigned
TEST(unsigned)
TEST2(int, unsigned)
#undef T

#define T unsigned long
TEST2(long, unsigned)
TEST3(int, long, unsigned)
#undef T

#define T unsigned long long
TEST3(long, long, unsigned)
TEST4(int, long, long, unsigned)
#undef T

#define T float
TEST(float)
#undef T

#define T double
TEST(double)
#undef T

#define T long double
TEST2(double, long)
#undef T
}
/*
 * check-name: valid specifier combinations
 * check-command: sparse $file
 */
