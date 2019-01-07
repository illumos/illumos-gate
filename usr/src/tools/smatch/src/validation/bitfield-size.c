struct bfu {
	unsigned int a:4;
	unsigned int  :2;
	unsigned int b:4;
};
unsigned int get__bfu_a(struct bfu bf) { return bf.a; }
unsigned int get__bfu_b(struct bfu bf) { return bf.b; }
unsigned int get_pbfu_a(struct bfu *bf) { return bf->a; }
unsigned int get_pbfu_b(struct bfu *bf) { return bf->b; }


struct bfs {
	signed int a:4;
	signed int  :2;
	signed int b:4;
};
signed int get__bfs_a(struct bfs bf) { return bf.a; }
signed int get__bfs_b(struct bfs bf) { return bf.b; }
signed int get_pbfs_a(struct bfs *bf) { return bf->a; }
signed int get_pbfs_b(struct bfs *bf) { return bf->b; }


struct bfi {
	int a:4;
	int  :2;
	int b:4;
};
unsigned int get__bfi_a(struct bfi bf) { return bf.a; }
unsigned int get__bfi_b(struct bfi bf) { return bf.b; }
unsigned int get_pbfi_a(struct bfi *bf) { return bf->a; }
unsigned int get_pbfi_b(struct bfi *bf) { return bf->b; }

/*
 * check-name: bitfield size
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-pattern-24-times: cast\\.
 * check-output-pattern-12-times: cast\\.4
 * check-output-pattern-6-times: lsr\\..*\\$6
 */
