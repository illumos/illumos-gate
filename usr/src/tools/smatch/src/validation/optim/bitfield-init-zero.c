struct bfu {
	unsigned int a:11;
	unsigned int f:9;
	unsigned int  :2;
	unsigned int z:3;
};

struct bfu bfuu_init(unsigned int a)
{
	struct bfu bf = { .f = a, };
	return bf;
}

struct bfu bfus_init(int a)
{
	struct bfu bf = { .f = a, };
	return bf;
}

unsigned int bfu_get0(void)
{
	struct bfu bf = { };
	return bf.f;
}


struct bfs {
	signed int a:11;
	signed int f:9;
	signed int  :2;
	signed int z:3;
};

struct bfs bfsu_init(unsigned int a)
{
	struct bfs bf = { .f = a, };
	return bf;
}

struct bfs bfss_init(int a)
{
	struct bfs bf = { .f = a, };
	return bf;
}

int bfs_get0(void)
{
	struct bfs bf = { };
	return bf.f;
}

/*
 * check-name: bitfield implicit init zero
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
bfuu_init:
.L0:
	<entry-point>
	and.32      %r4 <- %arg1, $511
	shl.32      %r5 <- %r4, $11
	ret.32      %r5


bfus_init:
.L2:
	<entry-point>
	and.32      %r13 <- %arg1, $511
	shl.32      %r14 <- %r13, $11
	ret.32      %r14


bfu_get0:
.L4:
	<entry-point>
	ret.32      $0


bfsu_init:
.L6:
	<entry-point>
	and.32      %r27 <- %arg1, $511
	shl.32      %r28 <- %r27, $11
	ret.32      %r28


bfss_init:
.L8:
	<entry-point>
	and.32      %r36 <- %arg1, $511
	shl.32      %r37 <- %r36, $11
	ret.32      %r37


bfs_get0:
.L10:
	<entry-point>
	ret.32      $0


 * check-output-end
 */
