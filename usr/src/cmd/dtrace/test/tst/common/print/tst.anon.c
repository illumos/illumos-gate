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
 * This embeds type information with anonymous structures and unions and passes
 * it to a function which allows the pid provider to get at it with various
 * forms of the print() action in tst.anon.ksh.
 */

#include <stdio.h>
#include <string.h>

struct elves {
	int feanor;
	struct {
		int fingolfin;
	};
	union {
		int maedhros;
		int fingon;
		struct {
			int aredhel;
			union {
				int turgon;
				struct {
					int tuor;
					int idril;
					struct {
						union {
							int earendil;
							int elwing;
						};
						int silmaril;
					};
				};
				union {
					int maeglin;
					int morgoth;
					union {
						int balrog;
						int gondolin;
						int glorfindel;
						int ecthelion;
					};
				};
			};
		};
	};
	struct {
		int elrond;
		int elros;
	};
};

void
mandos(struct elves *elves)
{
	(void) fprintf(stderr, "%x\n", elves->feanor);
}

int
main(void)
{
	struct elves elves;
	(void) memset(&elves, 0, sizeof (elves));
	elves.feanor = 0x1497;
	elves.fingolfin = 0x467;
	elves.maedhros = 0x587;
	elves.turgon = 0x510;
	elves.idril = 0x525;
	elves.earendil = 0x7777;
	elves.silmaril = 0x9999;
	elves.elrond = 0x3021;
	elves.elros = 0x442;

	mandos(&elves);
};
