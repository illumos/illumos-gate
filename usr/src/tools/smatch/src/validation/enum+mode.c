enum e { ZERO, ONE, TWO };

struct s {
	enum e __attribute__ ((mode(__byte__))) b;
	enum e __attribute__ ((mode(__word__))) w;
	enum e __attribute__ ((mode(__TI__))) t;
};

static struct s s;

_Static_assert(sizeof(s.b) == 1, "");
_Static_assert(sizeof(s.w) == sizeof(long), "");
_Static_assert(sizeof(s.t) == sizeof(long long), "");

/*
 * check-name: enum+mode
 * check-known-to-fail
 */
