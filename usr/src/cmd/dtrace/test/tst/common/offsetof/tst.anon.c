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
 * This contains a few anonymous structs and unions (nested), that test that the
 * D language offsetof works correctly in these cases.
 */

struct foo {
	int a;
	union {
		int b;
		int c;
		struct {
			int d;
			int e;
			int f;
		};
		int g[3];
	};
	struct {
		int h;
		union {
			int i;
			struct {
				int j;
				union {
					int k;
					struct {
						int l;
						int m;
						union {
							int n;
							struct {
								int o;
							};
						};
						int p;
					};
					int q;
				};
				int r;
			};
			int s;
		};
		int t;
	};
};

struct foo foo;

int
main(void)
{
	return (0);
}
