struct bfb {
	_Bool a:1;
	_Bool f:1;
	_Bool z:1;
};


struct bfb foo(struct bfb s)
{
	return s;
}

/*
 * check-name: bitfield-bool-layout
 * check-description: given that bool is here 1-bit wide
 *	each field here above completely 'fill' a bool.
 *	Thus 3 bools need to be allocated, but since the
 *	alignment is 1-byte the result has a size of 3
 *	bytes, 24 bits thus instead of 8.
 * check-command: test-linearize -Wno-decl $file
 *
 * check-known-to-fail
 * check-output-ignore
 * check-output-excludes: ret\\.24
 * check-output-contains: ret\\.8
 */
