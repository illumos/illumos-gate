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
 * smbstat: Server Message Block File System statistics
 */
#include <stdio.h>
#include <stdlib.h>
#include <kstat.h>
#include <stdarg.h>
#include <errno.h>
#include <inttypes.h>
#include <strings.h>
#include <utility.h>
#include <libintl.h>
#include <zone.h>
#include <smbsrv/smb_kstat.h>

static kstat_ctl_t	*kc;		/* libkstat cookie */
static kstat_t		*smb_server;
static kstat_t		*smb_cmds;

static int get_smbinfo_stat(void);
static int get_smbdispatch_stat(void);
static void smbstat_init(void);
static void smbstat_fini(void);
static void smbstat_smb_server_print();
static void smbstat_smb_cmds_print();
static void smbstat_print(const char *, kstat_t *, int);
static int smbstat_width(kstat_t *, int);
static void smbstat_fail(int, char *, ...);
static kid_t smbstat_kstat_read(kstat_ctl_t *, kstat_t *, void *);
static void smbstat_usage(void);

#define	MAX_COLUMNS	80

int
main(int argc, char *argv[])
{
	int c;
	int iflag = 0;		/* smb_server stats */
	int dflag = 0;		/* smb_cmds_all stats */

	if (getzoneid() != GLOBAL_ZONEID) {
		(void) fprintf(stderr,
		    gettext("%s: Cannot execute in non-global zone.\n"),
		    argv[0]);
		return (0);
	}

	if (is_system_labeled()) {
		(void) fprintf(stderr,
		    gettext("%s: Trusted Extensions not supported.\n"),
		    argv[0]);
		return (0);
	}

	while ((c = getopt(argc, argv, "id")) != EOF) {
		switch (c) {
		case 'i':
			iflag++;
			break;
		case 'd':
			dflag++;
			break;
		case '?':
		default:
			smbstat_usage();
		}
	}

	if ((argc - optind) > 0) {
		smbstat_usage();
	}

	smbstat_init();

	if (iflag) {
		smbstat_smb_server_print();
	} else if (dflag) {
		smbstat_smb_cmds_print();
	} else {
		smbstat_smb_server_print();
		smbstat_smb_cmds_print();
	}

	smbstat_fini();
	return (0);
}


static int
get_smbinfo_stat(void)
{
	(void) smbstat_kstat_read(kc, smb_server, NULL);
	return (smbstat_width(smb_server, 0));
}

static int
get_smbdispatch_stat(void)
{
	(void) smbstat_kstat_read(kc, smb_cmds, NULL);
	return (smbstat_width(smb_cmds, 0));
}

static void
smbstat_smb_server_print()
{
	int	field_width;
	int	i, j, nreq, ncolumns;
	char	fixlen[128];
	kstat_named_t *knp;

	field_width = get_smbinfo_stat();
	if (field_width == 0)
		return;

	(void) printf("%s\n", "\nSMB Info:\n");
	ncolumns = (MAX_COLUMNS -1)/field_width;

	knp = KSTAT_NAMED_PTR(smb_server);
	nreq = smb_server->ks_ndata;

	for (i = 0; i < nreq; i += ncolumns) {
		/* prints out the titles of the columns */
		for (j = i; j < MIN(i + ncolumns, nreq); j++) {
			(void) printf("%-*s", field_width, knp[j].name);
		}
		(void) printf("\n");
		/* prints out the stat numbers */
		for (j = i; j < MIN(i + ncolumns, nreq); j++) {
			(void) sprintf(fixlen, "%" PRIu32 " ",
			    knp[j].value.ui32);
			(void) printf("%-*s", field_width, fixlen);
		}
		(void) printf("\n");
	}
}

static void
smbstat_smb_cmds_print()
{
	int field_width;

	field_width = get_smbdispatch_stat();
	if (field_width == 0)
		return;

	smbstat_print(gettext("\nAll dispatched SMB requests statistics:\n"),
	    smb_cmds, field_width);
}

static void
smbstat_init(void)
{
	char	smbsrv_name[KSTAT_STRLEN];

	(void) snprintf(smbsrv_name, sizeof (smbsrv_name), "%s%d",
	    SMBSRV_KSTAT_NAME, getzoneid());

	if ((kc = kstat_open()) == NULL)
		smbstat_fail(1, gettext("kstat_open(): can't open /dev/kstat"));

	smb_server = kstat_lookup(kc, SMBSRV_KSTAT_MODULE, 0, smbsrv_name);
	smb_cmds = kstat_lookup(kc, SMBSRV_KSTAT_MODULE, 0,
	    SMBSRV_KSTAT_NAME_CMDS);

	if ((smb_server == NULL) || (smb_cmds == NULL))
		smbstat_fail(0, gettext("kstat lookups failed for smb. "
		    "Your kernel module may not be loaded\n"));
}

static void
smbstat_fini(void)
{
	(void) kstat_close(kc);
}

static int
smbstat_width(kstat_t *req, int field_width)
{
	int i, nreq, len;
	char fixlen[128];
	kstat_named_t *knp;

	knp = KSTAT_NAMED_PTR(req);
	nreq = req->ks_ndata;

	for (i = 0; i < nreq; i++) {
		len = strlen(knp[i].name) + 1;
		if (field_width < len)
			field_width = len;
		(void) sprintf(fixlen, "%" PRIu64, knp[i].value.ui64);
		len = strlen(fixlen) + 1;
		if (field_width < len)
			field_width = len;
	}
	return (field_width);
}

static void
smbstat_print(const char *title_string, kstat_t *req, int field_width)
{
	int i, j, nreq, ncolumns;
	char fixlen[128];
	kstat_named_t *knp;

	if (req == NULL)
		return;

	if (field_width == 0)
		return;

	(void) printf("%s\n", title_string);
	ncolumns = (MAX_COLUMNS -1)/field_width;

	knp = KSTAT_NAMED_PTR(req);
	nreq = req->ks_ndata;

	for (i = 0; i < nreq; i += ncolumns) {
		/* prints out the titles of the columns */
		for (j = i; j < MIN(i + ncolumns, nreq); j++) {
			(void) printf("%-*s", field_width, knp[j].name);
		}
		(void) printf("\n");
		/* prints out the stat numbers */
		for (j = i; j < MIN(i + ncolumns, nreq); j++) {
			(void) sprintf(fixlen, "%" PRIu64 " ",
			    knp[j].value.ui64);
			(void) printf("%-*s", field_width, fixlen);
		}
		(void) printf("\n");

	}
}

static void
smbstat_usage(void)
{
	(void) fprintf(stderr, gettext("Usage: smbstat [-id]\n"));
	exit(1);
}

static void
smbstat_fail(int do_perror, char *message, ...)
{
	va_list args;

	va_start(args, message);
	(void) fprintf(stderr, gettext("smbstat: "));
	/* LINTED E_SEC_PRINTF_VAR_FMT */
	(void) vfprintf(stderr, message, args);
	va_end(args);
	if (do_perror)
		(void) fprintf(stderr, ": %s", strerror(errno));
	(void) fprintf(stderr, "\n");
	exit(1);
}

static kid_t
smbstat_kstat_read(kstat_ctl_t *kc, kstat_t *ksp, void *data)
{
	kid_t kstat_chain_id = kstat_read(kc, ksp, data);

	if (kstat_chain_id == -1)
		smbstat_fail(1, gettext("kstat_read('%s') failed"),
		    ksp->ks_name);
	return (kstat_chain_id);
}

/*
 * Enable libumem debugging by default on DEBUG builds.
 */
#ifdef DEBUG
const char *
_umem_debug_init(void)
{
	return ("default,verbose"); /* $UMEM_DEBUG setting */
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents"); /* $UMEM_LOGGING setting */
}
#endif
