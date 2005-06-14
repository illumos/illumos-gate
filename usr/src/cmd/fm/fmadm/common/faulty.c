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

#include <strings.h>
#include <fmadm.h>

static const char *
rsrc_state_name(const fmd_adm_rsrcinfo_t *ari)
{
	switch (ari->ari_flags & (FMD_ADM_RSRC_FAULTY|FMD_ADM_RSRC_UNUSABLE)) {
	default:
		return ("ok");
	case FMD_ADM_RSRC_FAULTY:
		return ("degraded");
	case FMD_ADM_RSRC_UNUSABLE:
		return ("unknown");
	case FMD_ADM_RSRC_FAULTY | FMD_ADM_RSRC_UNUSABLE:
		return ("faulted");
	}
}

static const char faulty_line[] = "-------- "
"----------------------------------------------------------------------";

#define	IS_FAULTY(ari)	\
	(((ari)->ari_flags & (FMD_ADM_RSRC_FAULTY | \
	FMD_ADM_RSRC_INVISIBLE)) == FMD_ADM_RSRC_FAULTY)

/*ARGSUSED*/
static int
faulty_fmri(const fmd_adm_rsrcinfo_t *ari, void *opt_a)
{
	if (opt_a || IS_FAULTY(ari)) {
		(void) printf("%s\n%8s %s\n%8s %s\n",
		    faulty_line, rsrc_state_name(ari), ari->ari_fmri, "",
		    ari->ari_case ? ari->ari_case : "-");
	}

	return (0);
}

/*ARGSUSED*/
static int
faulty_uuid(const fmd_adm_rsrcinfo_t *ari, void *opt_a)
{
	if (opt_a || IS_FAULTY(ari)) {
		(void) printf("%s\n%8s %s\n%8s %s\n",
		    faulty_line, rsrc_state_name(ari), ari->ari_fmri, "",
		    ari->ari_uuid);
	}

	return (0);
}

int
cmd_faulty(fmd_adm_t *adm, int argc, char *argv[])
{
	fmd_adm_rsrc_f *func = faulty_fmri;
	int c, opt_a = 0;

	while ((c = getopt(argc, argv, "ai")) != EOF) {
		switch (c) {
		case 'a':
			opt_a++;
			break;
		case 'i':
			func = faulty_uuid;
			break;
		default:
			return (FMADM_EXIT_USAGE);
		}
	}

	if (optind < argc)
		return (FMADM_EXIT_USAGE);

	if (func == faulty_fmri)
		(void) printf("%8s %s\n", "STATE", "RESOURCE / UUID");
	else
		(void) printf("%8s %s\n", "STATE", "RESOURCE / CACHE-ID");

	if (fmd_adm_rsrc_iter(adm, opt_a, func, (void *)opt_a) != 0)
		die("failed to retrieve resource data");

	(void) printf("%s\n", faulty_line);
	return (FMADM_EXIT_SUCCESS);
}

int
cmd_flush(fmd_adm_t *adm, int argc, char *argv[])
{
	int i, status = FMADM_EXIT_SUCCESS;

	if (argc < 2 || (i = getopt(argc, argv, "")) != EOF)
		return (FMADM_EXIT_USAGE);

	for (i = 1; i < argc; i++) {
		if (fmd_adm_rsrc_flush(adm, argv[i]) != 0) {
			warn("failed to flush %s", argv[i]);
			status = FMADM_EXIT_ERROR;
		} else
			note("flushed resource history for %s\n", argv[i]);
	}

	return (status);
}

int
cmd_repair(fmd_adm_t *adm, int argc, char *argv[])
{
	int err;

	if (getopt(argc, argv, "") != EOF)
		return (FMADM_EXIT_USAGE);

	if (argc - optind != 1)
		return (FMADM_EXIT_USAGE);

	/*
	 * For now, we assume that if the input string contains a colon, it is
	 * an FMRI and if it does not it is a UUID.  If things get more complex
	 * in the future with multiple UUID formats, an FMRI parser can be
	 * added here to differentiate the input argument appropriately.
	 */
	if (strchr(argv[optind], ':') != NULL)
		err = fmd_adm_rsrc_repair(adm, argv[optind]);
	else
		err = fmd_adm_case_repair(adm, argv[optind]);

	if (err != 0)
		die("failed to record repair to %s", argv[optind]);

	note("recorded repair to %s\n", argv[optind]);
	return (FMADM_EXIT_SUCCESS);
}
