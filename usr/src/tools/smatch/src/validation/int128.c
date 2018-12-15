typedef		 __int128	 int128_t;
typedef   signed __int128	sint128_t;
typedef unsigned __int128	uint128_t;

typedef	__int128 int	badxi;
typedef int __int128	badix;
typedef unsigned unsigned __int128 baduu;
typedef double __int128 baddx;
typedef __int128 double badxd;

int sizeof_int128(void)
{
	return sizeof(__int128);
}

typedef unsigned long long u64;
typedef unsigned long      u32;

u64 foo(u64 a, u64 b, u64 c, u32 s)
{
       unsigned __int128 tmp;

       tmp = (((uint128_t)a) * b) + c;
       return (u64) (tmp >> s);
}

/*
 * check-name: int128
 * check-command: test-linearize $file
 * check-output-ignore
 *
 * check-output-contains: ret\\..*\\$16
 * check-output-contains: mulu\\.128
 * check-output-contains: add\\.128
 *
 * check-error-start
int128.c:5:18: error: two or more data types in declaration specifiers
int128.c:5:18: error: Trying to use reserved word 'int' as identifier
int128.c:5:25: error: Expected ; at end of declaration
int128.c:5:25: error: got badxi
int128.c:6:13: error: two or more data types in declaration specifiers
int128.c:6:13: error: Trying to use reserved word '__int128' as identifier
int128.c:6:25: error: Expected ; at end of declaration
int128.c:6:25: error: got badix
int128.c:7:18: error: impossible combination of type specifiers: unsigned unsigned
int128.c:7:18: error: Trying to use reserved word 'unsigned' as identifier
int128.c:7:27: error: Expected ; at end of declaration
int128.c:7:27: error: got __int128
int128.c:8:16: error: two or more data types in declaration specifiers
int128.c:8:16: error: Trying to use reserved word '__int128' as identifier
int128.c:8:25: error: Expected ; at end of declaration
int128.c:8:25: error: got baddx
int128.c:9:18: error: two or more data types in declaration specifiers
int128.c:9:18: error: Trying to use reserved word 'double' as identifier
int128.c:9:25: error: Expected ; at end of declaration
int128.c:9:25: error: got badxd
 * check-error-end
 */
