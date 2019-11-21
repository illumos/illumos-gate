struct bfu {
	unsigned int a:11;
	unsigned int f:9;
	unsigned int z:3;
};

struct bfu bfu_init_00_11(int a)
{
	struct bfu bfu = { .a = a, };
	return bfu;
}

struct bfu bfu_init_20_23(int a)
{
	struct bfu bfu = { .z = a, };
	return bfu;
}

/*
 * check-name: bitfield initializer mask
 * check-command: test-linearize -fdump-ir=linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-contains: and\\..*fffff800\$
 * check-output-contains: shl\\..* \\$20
 * check-output-contains: and\\..*ff8fffff\$
 */
