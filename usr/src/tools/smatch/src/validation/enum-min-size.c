enum i { I = 1 };
_Static_assert(sizeof(enum i) == sizeof(int), "int");
enum u { U = 1U };
_Static_assert(sizeof(enum u) == sizeof(int), "uint");

enum l { L = 1L };
_Static_assert(sizeof(enum l) == sizeof(int), "long");
enum m { M = 1UL };
_Static_assert(sizeof(enum m) == sizeof(int), "ulong");

enum n { N = 1LL };
_Static_assert(sizeof(enum n) == sizeof(int), "llong");
enum o { O = 1ULL };
_Static_assert(sizeof(enum o) == sizeof(int), "ullong");


enum mi { MI = -1 };
_Static_assert(sizeof(enum i) == sizeof(int), "int");

enum ml { ML = -1L };
_Static_assert(sizeof(enum l) == sizeof(int), "long");

enum mn { MN = -1LL };
_Static_assert(sizeof(enum n) == sizeof(int), "llong");


/*
 * check-name: enum-min-size
 */
