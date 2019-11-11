int simple(int s, unsigned int u, int p)
{
	s = s >> 100;
	u = u >> 101;
	u = u << 102;
	s = s >>  -1;
	u = u >>  -2;
	u = u <<  -3;
	if (0) return s >> 103;
	if (0) return u >> 104;
	if (0) return u << 105;
	if (0) return s >>  -4;
	if (0) return u >>  -5;
	if (0) return u <<  -6;
	if (p && 0) return s >> 106;
	if (p && 0) return u >> 107;
	if (p && 0) return u << 108;
	if (p && 0) return s >>  -7;
	if (p && 0) return u >>  -8;
	if (p && 0) return u <<  -9;
	s = s >> ((p & 0) + 109); u ^= p; // reloaded because now == 0
	u = u >> ((p & 0) + 110); u ^= p; // reloaded because now == 0
	u = u << ((p & 0) + 111); u ^= p; // reloaded because now == 0
	s = s >> ((p & 0) + -10);
	u = u >> ((p & 0) + -11); u ^= p; // reloaded because now == 0
	u = u << ((p & 0) + -12); u ^= p; // reloaded because now == 0
	return s + u;
}

int compound(int s, unsigned int u, int p)
{
	s >>= 100;
	u >>= 101;
	u <<= 102;
	s >>=  -1;
	u >>=  -2;
	u <<=  -3;
	if (0) return s >>= 103;
	if (0) return u >>= 104;
	if (0) return u <<= 105;
	if (0) return s >>=  -4;
	if (0) return u >>=  -5;
	if (0) return u <<=  -6;
	if (p && 0) return s >>= 106;
	if (p && 0) return u >>= 107;
	if (p && 0) return u <<= 108;
	if (p && 0) return s >>=  -7;
	if (p && 0) return u >>=  -8;
	if (p && 0) return u <<=  -9;
	s >>= ((p & 0) + 109); u ^= p; // reloaded because now == 0
	u >>= ((p & 0) + 110); u ^= p; // reloaded because now == 0
	u <<= ((p & 0) + 111); u ^= p; // reloaded because now == 0
	s >>= ((p & 0) + -10);
	u >>= ((p & 0) + -11); u ^= p; // reloaded because now == 0
	u <<= ((p & 0) + -12); u ^= p; // reloaded because now == 0
	return s + u;
}

int ok(int s, unsigned int u, int p)
{
	// GCC doesn't warn on these
	if (0 && (s >> 100)) return 0;
	if (0 && (u >> 101)) return 0;
	if (0 && (u << 102)) return 0;
	if (0 && (s >>  -1)) return 0;
	if (0 && (u >>  -2)) return 0;
	if (0 && (u <<  -3)) return 0;
	if (0 && (s >>= 103)) return 0;
	if (0 && (u >>= 104)) return 0;
	if (0 && (u <<= 105)) return 0;
	if (0 && (s >>=  -4)) return 0;
	if (0 && (u >>=  -5)) return 0;
	if (0 && (u <<=  -6)) return 0;
	return 1;
}

struct bf {
	unsigned int u:8;
	         int s:8;
};

int bf(struct bf *p)
{
	unsigned int r = 0;
	r += p->s << 8;
	r += p->s >> 8;
	r += p->u >> 8;
	return r;
}

/*
 * The following is used in the kernel at several places
 * It shouldn't emit any warnings.
 */
typedef unsigned long long u64;
typedef unsigned       int u32;

extern void hw_w32x2(u32 hi, u32 lo);

inline void hw_w64(u64 val)
{
	hw_w32x2(val >> 32, (u32) val);
}

void hw_write(u32 val)
{
	hw_w64(val);
}

/*
 * check-name: shift too big or negative
 * check-command: sparse -Wno-decl $file
 *
 * check-error-start
shift-undef.c:3:15: warning: shift too big (100) for type int
shift-undef.c:4:15: warning: shift too big (101) for type unsigned int
shift-undef.c:5:15: warning: shift too big (102) for type unsigned int
shift-undef.c:6:15: warning: shift count is negative (-1)
shift-undef.c:7:15: warning: shift count is negative (-2)
shift-undef.c:8:15: warning: shift count is negative (-3)
shift-undef.c:9:25: warning: shift too big (103) for type int
shift-undef.c:10:25: warning: shift too big (104) for type unsigned int
shift-undef.c:11:25: warning: shift too big (105) for type unsigned int
shift-undef.c:12:25: warning: shift count is negative (-4)
shift-undef.c:13:25: warning: shift count is negative (-5)
shift-undef.c:14:25: warning: shift count is negative (-6)
shift-undef.c:15:30: warning: shift too big (106) for type int
shift-undef.c:16:30: warning: shift too big (107) for type unsigned int
shift-undef.c:17:30: warning: shift too big (108) for type unsigned int
shift-undef.c:18:30: warning: shift count is negative (-7)
shift-undef.c:19:30: warning: shift count is negative (-8)
shift-undef.c:20:30: warning: shift count is negative (-9)
shift-undef.c:21:29: warning: shift too big (109) for type int
shift-undef.c:22:29: warning: shift too big (110) for type unsigned int
shift-undef.c:23:29: warning: shift too big (111) for type unsigned int
shift-undef.c:24:29: warning: shift count is negative (-10)
shift-undef.c:25:29: warning: shift count is negative (-11)
shift-undef.c:26:29: warning: shift count is negative (-12)
shift-undef.c:32:11: warning: shift too big (100) for type int
shift-undef.c:33:11: warning: shift too big (101) for type unsigned int
shift-undef.c:34:11: warning: shift too big (102) for type unsigned int
shift-undef.c:35:11: warning: shift count is negative (-1)
shift-undef.c:36:11: warning: shift count is negative (-2)
shift-undef.c:37:11: warning: shift count is negative (-3)
shift-undef.c:38:25: warning: shift too big (103) for type int
shift-undef.c:39:25: warning: shift too big (104) for type unsigned int
shift-undef.c:40:25: warning: shift too big (105) for type unsigned int
shift-undef.c:41:25: warning: shift count is negative (-4)
shift-undef.c:42:25: warning: shift count is negative (-5)
shift-undef.c:43:25: warning: shift count is negative (-6)
shift-undef.c:44:30: warning: shift too big (106) for type int
shift-undef.c:45:30: warning: shift too big (107) for type unsigned int
shift-undef.c:46:30: warning: shift too big (108) for type unsigned int
shift-undef.c:47:30: warning: shift count is negative (-7)
shift-undef.c:48:30: warning: shift count is negative (-8)
shift-undef.c:49:30: warning: shift count is negative (-9)
shift-undef.c:50:26: warning: shift too big (109) for type int
shift-undef.c:51:26: warning: shift too big (110) for type int
shift-undef.c:52:26: warning: shift too big (111) for type int
shift-undef.c:53:26: warning: shift count is negative (-10)
shift-undef.c:54:26: warning: shift count is negative (-11)
shift-undef.c:55:26: warning: shift count is negative (-12)
 * check-error-end
 */
