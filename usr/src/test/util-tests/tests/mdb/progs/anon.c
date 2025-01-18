/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2025 Oxide Computer Company
 */

/*
 * This file is paired with the sou/tst.anon.ksh mdb test. It's design to
 * include a number of structures and unions with anonymous values that we can
 * test with various commands to make sure we properly resolve member names
 * through them.
 */

struct foo {
	int foo;
};

struct bar {
	const char *bar;
	union {
		struct foo bar_foo;
		int bar_int;
	};
};

struct baz {
	struct {
		const char *baz_str;
		int baz_anon;
	};
	int baz_int;
};

struct foobar {
	int foobar_int;
	union {
		struct foo foo;
		struct bar bar;
		struct baz baz;
		struct {
			void *foobar_ptr;
			int foobar_anon;
		};
	};
	struct {
		int a;
		int b;
		int c;
	};
	union {
		int d;
		int e;
		int f;
	};
};

struct foo foo = { .foo = 42 };
struct bar bar = { .bar = "hello world", .bar_int = 0x7777 };
struct baz baz = {
	.baz_anon = 0x9999,
	.baz_str = "It's a trap?!",
	.baz_int = -4
};

struct foobar foobar = {
	.foobar_int = 0xb295,
	.bar = { .bar = "Elbereth", .bar_int = 0x7777 },
	.a = 0x9876,
	.b = 0x12345,
	.c = 0xb22b,
	.e = 0xfdcba
};

struct stringless {
	union {
		struct {
			int life;
			int hope;
		};
		int dreams;
		union {
			char k;
			short e;
			int f;
			long a;
		};
		double destroy;
	};
};

struct stringless stringless = { .life = 0xaa7777aa, .hope = 0x339999ee };

int
main(void)
{
	return (0);
}
