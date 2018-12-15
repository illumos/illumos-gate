typedef unsigned   int __attribute__((bitwise)) large_t;
#define	LBIT	((__attribute__((force)) large_t) 1)

_Bool lfoo(large_t x) { return x; }
_Bool qfoo(large_t x) { _Bool r = x; return r; }
_Bool xfoo(large_t x) { return (_Bool)x; }
_Bool lbar(large_t x) { return ~x; }
_Bool qbar(large_t x) { _Bool r = ~x; return r; }
_Bool xbar(large_t x) { return (_Bool)~x; }
_Bool lbaz(large_t x) { return !x; }
_Bool qbaz(large_t x) { _Bool r = !x; return r; }
_Bool xbaz(large_t x) { return (_Bool)!x; }
_Bool lqux(large_t x) { return x & LBIT; }
_Bool qqux(large_t x) { _Bool r = x & LBIT; return r; }
_Bool xqux(large_t x) { return (_Bool)(x & LBIT); }


typedef unsigned short __attribute__((bitwise)) small_t;
#define	SBIT	((__attribute__((force)) small_t) 1)

_Bool sfoo(small_t x) { return x; }
_Bool tfoo(small_t x) { _Bool r = x; return r; }
_Bool zfoo(small_t x) { return (_Bool)x; }
_Bool sbar(small_t x) { return ~x; }
_Bool tbar(small_t x) { _Bool r = ~x; return r; }
_Bool zbar(small_t x) { return (_Bool)~x; }
_Bool sbaz(small_t x) { return !x; }
_Bool tbaz(small_t x) { _Bool r = !x; return r; }
_Bool zbaz(small_t x) { return (_Bool)!x; }
_Bool squx(small_t x) { return x & SBIT; }
_Bool tqux(small_t x) { _Bool r = x & SBIT; return r; }
_Bool zqux(small_t x) { return (_Bool)(x & SBIT); }

/*
 * check-name: bool-cast-restricted.c
 * check-command: sparse -Wno-decl $file
 *
 * check-error-start
bool-cast-restricted.c:24:32: warning: restricted small_t degrades to integer
bool-cast-restricted.c:25:35: warning: restricted small_t degrades to integer
bool-cast-restricted.c:26:33: warning: restricted small_t degrades to integer
 * check-error-end
 */
