/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <libgen.h>
#include <errno.h>
#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <findfp.h>
#include <util.h>

#define	OP(x)		((unsigned)(0x3 & x) << 30)	/* general opcode */
#define	OP2(x)		((0x7 & x) << 22)	/* op2 opcode */
#define	OP3(x)		((0x3f & x) << 19)	/* op3 opcode */

#define	OPMSK		0xC0000000
#define	OP2MSK		0x01C00000
#define	OP3MSK		0x01F80000

#define	MAXEXCLUDES	5

typedef struct mask {
	uint32_t m_mask;
	uint32_t m_val;
	const char *m_name;
} mask_t;

static const mask_t masks[] = {
	{ OPMSK|OP2MSK, OP(0) | OP2(5), "FBPfcc" },
	{ OPMSK|OP2MSK, OP(0) | OP2(6), "FBfcc" },
	{ OPMSK|OP3MSK, OP(2) | OP3(0x34), "FPop1" },
	{ OPMSK|OP3MSK, OP(2) | OP3(0x35), "FPop2" },
	{ OPMSK|OP3(0x38), OP(3) | OP3(0x20), "FPldst1" },
	{ OPMSK|OP3(0x38), OP(3) | OP3(0x30), "FPldst2" }
};

const char *progname;

static void
usage(void)
{
	(void) fprintf(stderr, "Usage: %s infile\n", progname);
	exit(2);
}

int
main(int argc, char **argv)
{
	Elf *elf;
	Elf_Scn *scn;
	GElf_Shdr shdr;
	Elf_Data *text;
	uint32_t *instrs;
	char *excludes[MAXEXCLUDES];
	int fd, textidx, i, j, c;
	int shownames = 1;
	int nexcludes = 0;
	int found = 0;
	char *filename;

	progname = basename(argv[0]);

	while ((c = getopt(argc, argv, ":nx:")) != EOF) {
		switch (c) {
		case 'n':
			shownames = 0;
			break;
		case 'x':
			if (nexcludes == MAXEXCLUDES - 1)
				die("exclusion limit is %d", MAXEXCLUDES);
			excludes[nexcludes++] = optarg;
			break;
		default:
			usage();
		}
	}

	if (argc - optind != 1)
		usage();
	filename = argv[optind];

	if ((fd = open(filename, O_RDONLY)) < 0)
		die("failed to open %s", filename);

	(void) elf_version(EV_CURRENT);
	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
		elfdie("failed to open %s as ELF", filename);

	if ((textidx = findelfsecidx(elf, ".text")) < 0)
		die("failed to find .text section in %s\n", filename);

	if ((scn = elf_getscn(elf, textidx)) == NULL ||
	    gelf_getshdr(scn, &shdr) == NULL ||
	    (text = elf_rawdata(scn, NULL)) == NULL)
		elfdie("failed to read .text");

	instrs = text->d_buf;

	for (i = 0; i < shdr.sh_size / 4; i++) {
		for (j = 0; j < sizeof (masks) / sizeof (mask_t); j++) {
			char *symname = NULL;
			offset_t off;
			int len = 35;
			int xcl;

			if ((instrs[i] & masks[j].m_mask) != masks[j].m_val)
				continue;

			if (findelfsym(elf, i * 4, &symname, &off)) {
				if (nexcludes > 0) {
					for (xcl = 0; xcl < nexcludes; xcl++) {
						if (strcmp(symname,
						    excludes[xcl]) == 0)
							break;
					}

					if (xcl < nexcludes)
						continue; /* exclude matched */
				}
			}

			found++;

			if (!shownames || symname == NULL) {
				(void) printf("%-*x", len, i * 4);
			} else {
				len -= printf("%s+%llx", symname, off);
				(void) printf("%*s", (len > 0 ? len : 0), "");
			}

			(void) printf(" %08x %s\n", instrs[i],
			    masks[j].m_name);
		}
	}

	(void) elf_end(elf);
	(void) close(fd);

	return (found > 0);
}
