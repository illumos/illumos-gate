#if __SIZEOF_INT__ == __SIZEOF_FLOAT__
typedef   signed int si;
typedef unsigned int ui;
#else
#error "no float-sized integer type"
#endif

#if __SIZEOF_LONG_LONG__ == __SIZEOF_DOUBLE__
typedef   signed long long sl;
typedef unsigned long long ul;
#else
#error "no double-sized integer type"
#endif

si f2si(float  a) { return a; }
ui f2ui(float  a) { return a; }
sl f2sl(float  a) { return a; }
ul f2ul(float  a) { return a; }
si d2si(double a) { return a; }
ui d2ui(double a) { return a; }
sl d2sl(double a) { return a; }
ul d2ul(double a) { return a; }

/*
 * check-name: fp2i cast
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(4): fcvts\\.
 * check-output-pattern(4): fcvtu\\.
 */
