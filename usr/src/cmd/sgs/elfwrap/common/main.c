/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Wrap data in an elf file.
 */
#include	<fcntl.h>
#include	<unistd.h>
#include	<libgen.h>
#include	<errno.h>
#include	<stdio.h>
#include	<string.h>
#include	<locale.h>
#include	<libintl.h>
#include	<conv.h>
#include	<msg.h>
#include	<_elfwrap.h>

const char *
_elfwrap_msg(Msg mid)
{
	return (gettext(MSG_ORIG(mid)));
}

int
main(int argc, char **argv, char **envp)
{
	const char	*prog, *ofile = NULL, *pstr = NULL;
	int		fd, var;
	uchar_t		class = ELFCLASS32;
	ushort_t	mach = EM_NONE;
	ObjDesc_t	odesc = { NULL, 0, 0, 0 };

	/*
	 * If we're on a 64-bit kernel, try to exec a full 64-bit version of
	 * the binary.  If successful, conv_check_native() won't return.
	 */
	(void) conv_check_native(argv, envp);

	/*
	 * Establish locale.
	 */
	(void) setlocale(LC_MESSAGES, MSG_ORIG(MSG_STR_EMPTY));
	(void) textdomain(MSG_ORIG(MSG_SUNW_OST_SGS));

	(void) setvbuf(stdout, NULL, _IOLBF, 0);
	(void) setvbuf(stderr, NULL, _IOLBF, 0);

	prog = basename(argv[0]);
	opterr = 0;
	while ((var = getopt(argc, argv, MSG_ORIG(MSG_ARG_OPTIONS))) != EOF) {
		switch (var) {
		case '6':			/* Create a 64-bit object */
			if (optarg[0] != '4') {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ARG_ILLEGAL), prog,
				    MSG_ORIG(MSG_ARG_6), optarg);
				return (1);
			}
			class = ELFCLASS64;
			break;
		case 'o':			/* output file name */
			ofile = optarg;
			break;
		case 'z':			/* output file platform */
			if (strncmp(optarg, MSG_ORIG(MSG_ARG_TARGET),
			    MSG_ARG_TARGET_SIZE) == 0)
				pstr = optarg + MSG_ARG_TARGET_SIZE;
			else {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ARG_ILLEGAL), prog,
				    MSG_ORIG(MSG_ARG_Z), optarg);
				return (1);
			}
			break;
		case '?':
			(void) fprintf(stderr, MSG_INTL(MSG_USAGE_BRIEF),
			    prog);
			return (1);
		default:
			break;
		}
	}

	/*
	 * Verify that we have at least one input data file, and if no output
	 * file has been specified, provide a default.  Update argc and argv
	 * for input() to continue processing any input files.
	 */
	argv += optind;
	argc -= optind;
	if (argc == 0) {
		(void) fprintf(stderr, MSG_INTL(MSG_USAGE_BRIEF), prog);
		return (1);
	}
	if (ofile == NULL)
		ofile = MSG_ORIG(MSG_STR_AWRAPO);

	/*
	 * If the user specified a target, use it to determine the machine type
	 * for the output object.  If no target is specified, we leave "mach" as
	 * EM_NONE.  output() will replace EM_NONE with the appropriate machine
	 * code for the system running elfwrap(1).
	 */
	if (pstr) {
		if (strcasecmp(pstr, MSG_ORIG(MSG_TARG_SPARC)) == 0) {
			if (class == ELFCLASS64)
				mach = EM_SPARCV9;
			else
				mach = EM_SPARC;

		} else if (strcasecmp(pstr, MSG_ORIG(MSG_TARG_X86)) == 0) {
			if (class == ELFCLASS64)
				mach = EM_AMD64;
			else
				mach = EM_386;

		} else {
			(void) fprintf(stderr, MSG_INTL(MSG_ARG_BADTARG), prog,
			    pstr);
			return (1);
		}
	}

	/*
	 * Create the input information for the new image.
	 */
	if (class == ELFCLASS64) {
		if (input64(argc, argv, prog, ofile, &odesc) == 1)
			return (1);
	} else {
		if (input32(argc, argv, prog, ofile, &odesc) == 1)
			return (1);
	}

	/*
	 * Create and truncate the output file.
	 */
	if ((fd = open(ofile, (O_RDWR | O_CREAT | O_TRUNC), 0666)) < 0) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_OPEN), prog,
		    ofile, strerror(err));
		return (1);
	}

	/*
	 * Initialize libelf, and create the new ELF file as the class dictates.
	 */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_LIBELF), prog,
		    EV_CURRENT);
		return (1);
	}
	if (class == ELFCLASS64)
		return (output64(prog, fd, ofile, mach, &odesc));
	else
		return (output32(prog, fd, ofile, mach, &odesc));
}
