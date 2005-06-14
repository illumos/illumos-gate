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

/*
 * Set bits in the DT_FLAGS_1 member of the .dynamic section of an object.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <libelf.h>
#include <gelf.h>
#include <string.h>
#include <fcntl.h>
#include <libgen.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/link.h>

#include <util.h>

/*
 * These are here because we can't be sure (yet) that the build machine has a
 * sys/link.h that includes the following #defines.  This tool will be executed
 * on the build machine, so we have to use its headers (rather than the ones
 * in $ROOT which will, by definition, be up to date).  These #defines can be
 * removed when we're sure that all build machines have recent copies of
 * sys/link.h.
 */
#ifndef	DF_1_IGNMULDEF
#define	DF_1_IGNMULDEF	0x00040000
#endif
#ifndef	DF_1_NOKSYMS
#define	DF_1_NOKSYMS	0x00080000
#endif

struct dtflagval {
	char *fv_name;
	ulong_t fv_val;
};

static struct dtflagval dtflagvals[] = {
	{ "DF_1_IGNMULDEF", DF_1_IGNMULDEF },
	{ "DF_1_NOKSYMS", DF_1_NOKSYMS },
	{ NULL }
};

const char *progname;

static void
usage(void)
{
	(void) fprintf(stderr, "Usage: %s -f flag_val file\n", progname);
	exit(2);
}

static void
set_flag(char *ifile, ulong_t flval)
{
	Elf *elf;
	Elf_Scn *scn;
	Elf_Data *data;
	GElf_Shdr shdr;
	GElf_Dyn dyn;
	int fd, secidx, nent, i;

	(void) elf_version(EV_CURRENT);

	if ((fd = open(ifile, O_RDWR)) < 0)
		die("Can't open %s", ifile);

	if ((elf = elf_begin(fd, ELF_C_RDWR, NULL)) == NULL)
		elfdie("Can't start ELF for %s", ifile);

	if ((secidx = findelfsecidx(elf, ".dynamic")) == -1)
		die("Can't find .dynamic section in %s\n", ifile);

	if ((scn = elf_getscn(elf, secidx)) == NULL)
		elfdie("elf_getscn (%d)", secidx);

	if (gelf_getshdr(scn, &shdr) == NULL)
		elfdie("gelf_shdr");

	if ((data = elf_getdata(scn, NULL)) == NULL)
		elfdie("elf_getdata");

	nent = shdr.sh_size / shdr.sh_entsize;
	for (i = 0; i < nent; i++) {
		if (gelf_getdyn(data, i, &dyn) == NULL)
			elfdie("gelf_getdyn");

		if (dyn.d_tag == DT_FLAGS_1) {
			dyn.d_un.d_val |= (Elf64_Xword)flval;

			if (gelf_update_dyn(data, i, &dyn) == 0)
				elfdie("gelf_update_dyn");

			break;
		}
	}

	if (i == nent) {
		die("%s's .dynamic section doesn't have a DT_FLAGS_1 "
		    "field\n", ifile);
	}

	if (elf_update(elf, ELF_C_WRITE) == -1)
		elfdie("Couldn't update %s with changes", ifile);

	(void) elf_end(elf);
	(void) close(fd);
}

static ulong_t
parse_flag(char *optarg)
{
	ulong_t flval = 0L;
	char *arg;
	int i;

	for (arg = strtok(optarg, ","); arg != NULL; arg = strtok(NULL, ",")) {
		for (i = 0; dtflagvals[i].fv_name != NULL; i++) {
			if (strcmp(dtflagvals[i].fv_name, arg) == 0)
				flval |= dtflagvals[i].fv_val;
		}
	}

	return (flval);
}

int
main(int argc, char **argv)
{
	ulong_t flval = 0L;
	int c;

	progname = basename(argv[0]);

	while ((c = getopt(argc, argv, "f:")) != EOF) {
		switch (c) {
		case 'f':
			if ((flval = strtoul(optarg, NULL, 0)) == 0 &&
			    (flval = parse_flag(optarg)) == 0)
				usage();
			break;
		default:
			usage();
		}
	}

	if (flval == 0 || argc - optind != 1)
		usage();

	set_flag(argv[optind], flval);

	return (0);
}
