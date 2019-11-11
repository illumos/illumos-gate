typedef unsigned short u16;
typedef          short s16;
typedef unsigned   int u32;
typedef            int s32;
typedef unsigned  long long u64;
typedef           long long s64;

u64 ufoo(int x)
{
	return x & 0x7fff;
}

u64 sfoo(int x)
{
	return x & 0x7fff;
}

/*
 * check-name: and-extend
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: and\\.64.*0x7fff
 */
