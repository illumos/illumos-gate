typedef	unsigned short		u16;
typedef	unsigned int		u32;

union u {
	u32	a;
	u16	b;
};

struct s {
	u32	a;
	u16	b;
};


void bar(u16, u32);
void union_to_int(u16 val);
void struct_to_int(u16 val);


void union_to_int(u16 val)
{
	union u u;

	u.b = val;
	bar(u.b, u);
}

void struct_to_int(u16 val)
{
	struct s s;

	s.b = val;
	bar(s.b, s);
}

/*
 * check-name: cast-bad 00
 *
 * check-error-start
cast-bad-00.c:25:18: warning: incorrect type in argument 2 (different base types)
cast-bad-00.c:25:18:    expected unsigned int [usertype]
cast-bad-00.c:25:18:    got union u [assigned] u
cast-bad-00.c:33:18: warning: incorrect type in argument 2 (different base types)
cast-bad-00.c:33:18:    expected unsigned int [usertype]
cast-bad-00.c:33:18:    got struct s [assigned] s
 * check-error-end
 */
