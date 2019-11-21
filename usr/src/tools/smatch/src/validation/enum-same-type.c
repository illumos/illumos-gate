enum num {
	NEG = -1,
	NIL = 0,
	ONE = 1U,
	DUO = 2LL,
};

_Static_assert([typeof(NIL)] == [typeof(NEG)], "enum same type");
_Static_assert([typeof(ONE)] == [typeof(NEG)], "enum same type");
_Static_assert([typeof(DUO)] == [typeof(NEG)], "enum same type");

/*
 * check-name: enum-same-type
 */
