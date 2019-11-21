typedef unsigned short u16;
typedef          short s16;
typedef unsigned   int u32;
typedef            int s32;

u32 ufoo(u32 x)
{
	u16 i = ((u16)x) & 0x7fffU;
	return i;
}

u32 sfoo(u32 x)
{
	s16 i = ((s16)x) & 0x7fff;
	return i;
}

/*
 * check-name: and-extend
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: trunc\\.
 * check-output-excludes: zext\\.
 * check-output-excludes: sext\\.
 * check-output-contains: and\\.32.*0x7fff
 */
