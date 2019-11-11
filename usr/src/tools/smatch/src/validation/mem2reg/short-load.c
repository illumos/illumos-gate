#ifdef __SIZEOF_INT__ == 4
typedef unsigned int u32;
#endif
#ifdef __SIZEOF_SHORT__ == 2
typedef unsigned short u16;
#endif


union u {
	u32	a;
	u16	b;
};

void bar(u16, union u);

void foo(u16 val)
{
	union u u;

	u.b = val;
	bar(u.b, u);
}

/*
 * check-name: short-load
 * check-command: test-linearize -Wno-decl -fdump-ir=mem2reg $file
 * check-output-ignore
 * check-output-contains: load\\.32
 */
