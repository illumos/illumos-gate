enum e { OK, KO = -1 };
typedef _Bool bool;

static int test(int i, long l, long long ll, enum e e, bool b, void *p)
{
	int rc = 0;

	// should be OK
	rc += __builtin_add_overflow(i, i, &i);
	rc += __builtin_add_overflow(l, i, &i);
	rc += __builtin_add_overflow(i, l, &i);
	rc += __builtin_add_overflow(i, i, &l);
	rc += __builtin_add_overflow(ll, i, &i);
	rc += __builtin_add_overflow(i, ll, &i);
	rc += __builtin_add_overflow(i, i, &ll);

	rc += __builtin_add_overflow_p(i, i, i);
	rc += __builtin_add_overflow_p(l, i, i);
	rc += __builtin_add_overflow_p(i, l, i);
	rc += __builtin_add_overflow_p(i, i, l);
	rc += __builtin_add_overflow_p(ll, i, i);
	rc += __builtin_add_overflow_p(i, ll, i);
	rc += __builtin_add_overflow_p(i, i, ll);

	rc += __builtin_sub_overflow(i, i, &i);
	rc += __builtin_sub_overflow(l, i, &i);
	rc += __builtin_sub_overflow(i, l, &i);
	rc += __builtin_sub_overflow(i, i, &l);
	rc += __builtin_sub_overflow(ll, i, &i);
	rc += __builtin_sub_overflow(i, ll, &i);
	rc += __builtin_sub_overflow(i, i, &ll);

	rc += __builtin_sub_overflow_p(i, i, i);
	rc += __builtin_sub_overflow_p(l, i, i);
	rc += __builtin_sub_overflow_p(i, l, i);
	rc += __builtin_sub_overflow_p(i, i, l);
	rc += __builtin_sub_overflow_p(ll, i, i);
	rc += __builtin_sub_overflow_p(i, ll, i);
	rc += __builtin_sub_overflow_p(i, i, ll);

	rc += __builtin_mul_overflow(i, i, &i);
	rc += __builtin_mul_overflow(l, i, &i);
	rc += __builtin_mul_overflow(i, l, &i);
	rc += __builtin_mul_overflow(i, i, &l);
	rc += __builtin_mul_overflow(ll, i, &i);
	rc += __builtin_mul_overflow(i, ll, &i);
	rc += __builtin_mul_overflow(i, i, &ll);

	rc += __builtin_mul_overflow_p(i, i, i);
	rc += __builtin_mul_overflow_p(l, i, i);
	rc += __builtin_mul_overflow_p(i, l, i);
	rc += __builtin_mul_overflow_p(i, i, l);
	rc += __builtin_mul_overflow_p(ll, i, i);
	rc += __builtin_mul_overflow_p(i, ll, i);
	rc += __builtin_mul_overflow_p(i, i, ll);

	// should be KO
	rc += __builtin_add_overflow();
	rc += __builtin_add_overflow(i);
	rc += __builtin_add_overflow(i, i);
	rc += __builtin_add_overflow(i, i, &i, i);
	rc += __builtin_add_overflow(e, i, &i);
	rc += __builtin_add_overflow(i, e, &i);
	rc += __builtin_add_overflow(i, i, &e);
	rc += __builtin_add_overflow(b, i, &i);
	rc += __builtin_add_overflow(i, b, &i);
	rc += __builtin_add_overflow(i, i, &b);
	rc += __builtin_add_overflow(i, i, p);

	rc += __builtin_add_overflow_p();
	rc += __builtin_add_overflow_p(i);
	rc += __builtin_add_overflow_p(i, i);
	rc += __builtin_add_overflow_p(i, i, i, i);
	rc += __builtin_add_overflow_p(e, i, i);
	rc += __builtin_add_overflow_p(i, e, i);
	rc += __builtin_add_overflow_p(i, i, e);
	rc += __builtin_add_overflow_p(b, i, i);
	rc += __builtin_add_overflow_p(i, b, i);
	rc += __builtin_add_overflow_p(i, i, b);
	rc += __builtin_add_overflow_p(i, i, p);

	rc += __builtin_sub_overflow();
	rc += __builtin_sub_overflow(i);
	rc += __builtin_sub_overflow(i, i);
	rc += __builtin_sub_overflow(i, i, &i, i);
	rc += __builtin_sub_overflow(e, i, &i);
	rc += __builtin_sub_overflow(i, e, &i);
	rc += __builtin_sub_overflow(i, i, &e);
	rc += __builtin_sub_overflow(b, i, &i);
	rc += __builtin_sub_overflow(i, b, &i);
	rc += __builtin_sub_overflow(i, i, &b);
	rc += __builtin_sub_overflow(i, i, p);

	rc += __builtin_sub_overflow_p();
	rc += __builtin_sub_overflow_p(i);
	rc += __builtin_sub_overflow_p(i, i);
	rc += __builtin_sub_overflow_p(i, i, i, i);
	rc += __builtin_sub_overflow_p(e, i, i);
	rc += __builtin_sub_overflow_p(i, e, i);
	rc += __builtin_sub_overflow_p(i, i, e);
	rc += __builtin_sub_overflow_p(b, i, i);
	rc += __builtin_sub_overflow_p(i, b, i);
	rc += __builtin_sub_overflow_p(i, i, b);
	rc += __builtin_sub_overflow_p(i, i, p);

	rc += __builtin_mul_overflow();
	rc += __builtin_mul_overflow(i);
	rc += __builtin_mul_overflow(i, i);
	rc += __builtin_mul_overflow(i, i, &i, i);
	rc += __builtin_mul_overflow(e, i, &i);
	rc += __builtin_mul_overflow(i, e, &i);
	rc += __builtin_mul_overflow(i, i, &e);
	rc += __builtin_mul_overflow(b, i, &i);
	rc += __builtin_mul_overflow(i, b, &i);
	rc += __builtin_mul_overflow(i, i, &b);
	rc += __builtin_mul_overflow(i, i, p);

	rc += __builtin_mul_overflow_p();
	rc += __builtin_mul_overflow_p(i);
	rc += __builtin_mul_overflow_p(i, i);
	rc += __builtin_mul_overflow_p(i, i, i, i);
	rc += __builtin_mul_overflow_p(e, i, i);
	rc += __builtin_mul_overflow_p(i, e, i);
	rc += __builtin_mul_overflow_p(i, i, e);
	rc += __builtin_mul_overflow_p(b, i, i);
	rc += __builtin_mul_overflow_p(i, b, i);
	rc += __builtin_mul_overflow_p(i, i, b);
	rc += __builtin_mul_overflow_p(i, i, p);

	return rc;
}

/*
 * check-name: builtin-overflow
 *
 * check-error-start
builtin-overflow.c:58:37: error: not enough arguments for __builtin_add_overflow
builtin-overflow.c:59:37: error: not enough arguments for __builtin_add_overflow
builtin-overflow.c:60:37: error: not enough arguments for __builtin_add_overflow
builtin-overflow.c:61:37: error: too many arguments for __builtin_add_overflow
builtin-overflow.c:62:38: error: invalid type for argument 1:
builtin-overflow.c:62:38:         int enum e e
builtin-overflow.c:63:41: error: invalid type for argument 2:
builtin-overflow.c:63:41:         int enum e e
builtin-overflow.c:64:45: error: invalid type for argument 3:
builtin-overflow.c:64:45:         int enum e *
builtin-overflow.c:65:38: error: invalid type for argument 1:
builtin-overflow.c:65:38:         bool [usertype] b
builtin-overflow.c:66:41: error: invalid type for argument 2:
builtin-overflow.c:66:41:         bool [usertype] b
builtin-overflow.c:67:45: error: invalid type for argument 3:
builtin-overflow.c:67:45:         bool *
builtin-overflow.c:68:44: error: invalid type for argument 3:
builtin-overflow.c:68:44:         void *p
builtin-overflow.c:70:39: error: not enough arguments for __builtin_add_overflow_p
builtin-overflow.c:71:39: error: not enough arguments for __builtin_add_overflow_p
builtin-overflow.c:72:39: error: not enough arguments for __builtin_add_overflow_p
builtin-overflow.c:73:39: error: too many arguments for __builtin_add_overflow_p
builtin-overflow.c:74:40: error: invalid type for argument 1:
builtin-overflow.c:74:40:         int enum e [addressable] e
builtin-overflow.c:75:43: error: invalid type for argument 2:
builtin-overflow.c:75:43:         int enum e [addressable] e
builtin-overflow.c:76:46: error: invalid type for argument 3:
builtin-overflow.c:76:46:         int enum e [addressable] e
builtin-overflow.c:77:40: error: invalid type for argument 1:
builtin-overflow.c:77:40:         bool [addressable] [usertype] b
builtin-overflow.c:78:43: error: invalid type for argument 2:
builtin-overflow.c:78:43:         bool [addressable] [usertype] b
builtin-overflow.c:79:46: error: invalid type for argument 3:
builtin-overflow.c:79:46:         bool [addressable] [usertype] b
builtin-overflow.c:80:46: error: invalid type for argument 3:
builtin-overflow.c:80:46:         void *p
builtin-overflow.c:82:37: error: not enough arguments for __builtin_sub_overflow
builtin-overflow.c:83:37: error: not enough arguments for __builtin_sub_overflow
builtin-overflow.c:84:37: error: not enough arguments for __builtin_sub_overflow
builtin-overflow.c:85:37: error: too many arguments for __builtin_sub_overflow
builtin-overflow.c:86:38: error: invalid type for argument 1:
builtin-overflow.c:86:38:         int enum e [addressable] e
builtin-overflow.c:87:41: error: invalid type for argument 2:
builtin-overflow.c:87:41:         int enum e [addressable] e
builtin-overflow.c:88:45: error: invalid type for argument 3:
builtin-overflow.c:88:45:         int enum e *
builtin-overflow.c:89:38: error: invalid type for argument 1:
builtin-overflow.c:89:38:         bool [addressable] [usertype] b
builtin-overflow.c:90:41: error: invalid type for argument 2:
builtin-overflow.c:90:41:         bool [addressable] [usertype] b
builtin-overflow.c:91:45: error: invalid type for argument 3:
builtin-overflow.c:91:45:         bool *
builtin-overflow.c:92:44: error: invalid type for argument 3:
builtin-overflow.c:92:44:         void *p
builtin-overflow.c:94:39: error: not enough arguments for __builtin_sub_overflow_p
builtin-overflow.c:95:39: error: not enough arguments for __builtin_sub_overflow_p
builtin-overflow.c:96:39: error: not enough arguments for __builtin_sub_overflow_p
builtin-overflow.c:97:39: error: too many arguments for __builtin_sub_overflow_p
builtin-overflow.c:98:40: error: invalid type for argument 1:
builtin-overflow.c:98:40:         int enum e [addressable] e
builtin-overflow.c:99:43: error: invalid type for argument 2:
builtin-overflow.c:99:43:         int enum e [addressable] e
builtin-overflow.c:100:46: error: invalid type for argument 3:
builtin-overflow.c:100:46:         int enum e [addressable] e
builtin-overflow.c:101:40: error: invalid type for argument 1:
builtin-overflow.c:101:40:         bool [addressable] [usertype] b
builtin-overflow.c:102:43: error: invalid type for argument 2:
builtin-overflow.c:102:43:         bool [addressable] [usertype] b
builtin-overflow.c:103:46: error: invalid type for argument 3:
builtin-overflow.c:103:46:         bool [addressable] [usertype] b
builtin-overflow.c:104:46: error: invalid type for argument 3:
builtin-overflow.c:104:46:         void *p
builtin-overflow.c:106:37: error: not enough arguments for __builtin_mul_overflow
builtin-overflow.c:107:37: error: not enough arguments for __builtin_mul_overflow
builtin-overflow.c:108:37: error: not enough arguments for __builtin_mul_overflow
builtin-overflow.c:109:37: error: too many arguments for __builtin_mul_overflow
builtin-overflow.c:110:38: error: invalid type for argument 1:
builtin-overflow.c:110:38:         int enum e [addressable] e
builtin-overflow.c:111:41: error: invalid type for argument 2:
builtin-overflow.c:111:41:         int enum e [addressable] e
builtin-overflow.c:112:45: error: invalid type for argument 3:
builtin-overflow.c:112:45:         int enum e *
builtin-overflow.c:113:38: error: invalid type for argument 1:
builtin-overflow.c:113:38:         bool [addressable] [usertype] b
builtin-overflow.c:114:41: error: invalid type for argument 2:
builtin-overflow.c:114:41:         bool [addressable] [usertype] b
builtin-overflow.c:115:45: error: invalid type for argument 3:
builtin-overflow.c:115:45:         bool *
builtin-overflow.c:116:44: error: invalid type for argument 3:
builtin-overflow.c:116:44:         void *p
builtin-overflow.c:118:39: error: not enough arguments for __builtin_mul_overflow_p
builtin-overflow.c:119:39: error: not enough arguments for __builtin_mul_overflow_p
builtin-overflow.c:120:39: error: not enough arguments for __builtin_mul_overflow_p
builtin-overflow.c:121:39: error: too many arguments for __builtin_mul_overflow_p
builtin-overflow.c:122:40: error: invalid type for argument 1:
builtin-overflow.c:122:40:         int enum e [addressable] e
builtin-overflow.c:123:43: error: invalid type for argument 2:
builtin-overflow.c:123:43:         int enum e [addressable] e
builtin-overflow.c:124:46: error: invalid type for argument 3:
builtin-overflow.c:124:46:         int enum e [addressable] e
builtin-overflow.c:125:40: error: invalid type for argument 1:
builtin-overflow.c:125:40:         bool [addressable] [usertype] b
builtin-overflow.c:126:43: error: invalid type for argument 2:
builtin-overflow.c:126:43:         bool [addressable] [usertype] b
builtin-overflow.c:127:46: error: invalid type for argument 3:
builtin-overflow.c:127:46:         bool [addressable] [usertype] b
builtin-overflow.c:128:46: error: invalid type for argument 3:
builtin-overflow.c:128:46:         void *p
 * check-error-end
 */
