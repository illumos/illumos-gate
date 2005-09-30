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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * nislog.c
 *
 * This module simply reads the internal format of the log and prints
 * it out for the user to stdout. The format of the transaction log
 * is an *INTERNAL* interface and will change from time to time. The
 * service uses the log specific functions defined in the nis_log.c
 * module. They are reproduced here for this test code.
 *
 */

#include <stdio.h>
#include <syslog.h>
#include <values.h> 	/* MAXINT define */
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpcsvc/nis.h>
#include "log.h"

/*
 * nislog(1M) doesn't use 'cons', but we need it defined following the
 * code rearrangements for the MT rpc.nisd.
 */
FILE *cons = NULL;

extern unsigned long __maxloglen;

extern int optind, opterr;
extern char *optarg;
int verbose = 0;
/*
 * This macro returns true if the two objects have identical OIDs
 */
#define	sameobj(o1, o2)	(((o1)->zo_oid.ctime == (o2)->zo_oid.ctime) && \
				((o1)->zo_oid.mtime == (o2)->zo_oid.mtime))

int
abort_transaction(xid)
	int	xid;
{
	return (0);
}


void
print_transaction(cur, num)
	log_upd	*cur;
	int	num;
{
	XDR		xdrs;
	log_entry	le;

	printf("@@@@@@@@@@@@@@@@ Transaction @@@@@@@@@@@@@@@@@@\n");
	printf("#%05d, XID : %d\n", num, cur->lu_xid);
	printf("Time        : %s\n", ctime((time_t *)&(cur->lu_time)));
	printf("Directory   : %s\n", cur->lu_dirname);
	memset((char *)&le, 0, sizeof (le));
	xdrmem_create(&xdrs, (char *)(cur->lu_data), cur->lu_size, XDR_DECODE);
	xdr_log_entry(&xdrs, &le);
	printf("Entry type : ");
	switch (le.le_type) {
		case ADD_NAME :
			printf("ADD Name\n");
			break;
		case REM_NAME :
			printf("REMOVE Name\n");
			break;
		case ADD_IBASE :
			printf("ADD Entry\n");
			break;
		case REM_IBASE :
			printf("REMOVE Entry\n");
			break;
		case MOD_NAME_OLD :
			printf("MODIFY (Original Value)\n");
			break;
		case MOD_NAME_NEW :
			printf("MODIFY (New Value)\n");
			break;
		case UPD_STAMP :
			printf("UPDATE time stamp.\n");
			break;
		default:
			printf("Unknown (%d)!\n", le.le_type);
			break;
	}
	printf("Entry timestamp : %s", ctime((time_t *)&(le.le_time)));
	printf("Principal       : %s\n", le.le_princp);
	printf("Object name     : %s\n", __make_name(&le));
	printf(".................. Object .....................\n");
	nis_print_object(&le.le_object);
	printf("...............................................\n");
	xdr_free(xdr_log_entry, (char *)&le);
}

static
void
buserr_exit()
{
	printf("Transaction log checkpointed while reading.\n");
	exit(0);
}

void
usage(char *s)
{
	if ((strcmp(s, "loghead") == 0) || (strcmp(s, "logtail") == 0))
		fprintf(stderr, "usage: nislog %s [-v] num\n", s);
	else
		fprintf(stderr, "usage: %s [-h [num] | -t [num] ] [-v] \n", s);
	exit(1);
}

char		*directories[128];

int
main(int argc, char *argv[])
{
	log_upd		*cur;
	char		**dir;
	int		entries = MAXINT;
	char		*cmd;
	int		i, c;
	struct sigaction sa;
	int		tail_only = 0;
	char		logname[NIS_MAXNAMELEN];

	if (geteuid() != (uid_t)0) {
		fprintf(stderr, "nislog must be run as root.\n");
		exit(1);
	}

	memset(logname, 0, sizeof (logname));
	printf("NIS Log printing facility.\n");
	opterr = 0;
	/*
	 * if the cmdname is "logtail" or "loghead" change the
	 * arguments a bit, any other name and we default to
	 * "nislog" behaviour.
	 */
	cmd = (char *)strrchr(argv[0], '/');
	if (! cmd)
		cmd = argv[0];
	if ((strcmp(cmd, "logtail") == 0) ||
	    (strcmp(cmd, "loghead") == 0)) {
		if (strcmp(cmd, "logtail") == 0)
			tail_only = 1;

		while ((c = getopt(argc, argv, "v")) != -1) {
			switch (c) {
				case 'v' :
					verbose = 1;
					break;
				case '?' :
					usage(cmd);
					break;
			}
		}
		if (optind < argc) {
			entries = atoi(argv[optind]);
			optind++;
		}
		i = 0;
		while (optind < argc)
			directories[i++] = argv[optind++];
	} else {
		while ((c = getopt(argc, argv, "h:t:v")) != -1) {
			switch (c) {
				case 'h' :
					entries = atoi(optarg);
					break;
				case 't' :
					tail_only = 1;
					entries = atoi(optarg);
					break;
				case 'v' :
					verbose = 1;
					break;
				case '?' :
					usage(cmd);
					break;
			}
		}
		i = 0;
		while (optind < argc)
			directories[i++] = argv[optind++];
	}

	/*
	 *  If we have a long transaction log mmapped and rpc.nisd
	 *  truncates the log before we have hit all of the pages,
	 *  then when we hit a page past the current end of file for
	 *  the first time, we will get a SIGBUS.  We simple set a
	 *  signal handler to catch the signal and exit with status 0.
	 */
	memset((char *)&sa, 0, sizeof (sa));
	sa.sa_handler = buserr_exit;
	sigaction(SIGBUS, &sa, NULL);

	sprintf(logname, "%s", LOG_FILE);
	if (map_log(logname, FNISLOG)) {
		fprintf(stderr, "Unable to map log!\n");
		exit(1);
	}
	printf("NIS Log dump :\n");
	printf("\tLog state : ");
	switch (__nis_log->lh_state) {

		case LOG_STABLE :
			printf("STABLE.\n");
			break;
		case LOG_RESYNC :
			printf("RESYNCING.\n");
			break;
		case LOG_UPDATE :
			printf("UPDATING.\n");
			break;
		case LOG_CHECKPOINT :
			printf("CHECKPOINTING.\n");
			break;
	}
	printf("Number of updates    : %d\n", __nis_log->lh_num);
	printf("Current XID          : %d\n", __nis_log->lh_xid);
	printf("Size of Log in bytes : %d\n",
		(__nis_log->lh_tail) ? LOG_SIZE(__nis_log) : sizeof (log_hdr));
	printf("*** UPDATES ***\n");
	if (! __nis_log->lh_num) {
		printf("--None--\n");
		exit(0);
	}
	dir = directories;
	do {
		cur = (tail_only) ? __nis_log->lh_tail : __nis_log->lh_head;

		if (tail_only) {
			for (i = 0; cur && (i < entries);  cur = cur->lu_prev) {
				if ((*dir) &&
				    (nis_dir_cmp(*dir, cur->lu_dirname)
								!= SAME_NAME))
				continue;
				print_transaction(cur, __nis_log->lh_num-i-1);
				i++;
			}
		} else {
			for (i = 0; cur && (i < entries); cur = cur->lu_next) {
				if ((*dir) &&
				    (nis_dir_cmp((*dir), cur->lu_dirname)
								!= SAME_NAME))
					continue;
				print_transaction(cur, i);
				i++;
			}
		}
		dir++;
	} while (*dir != NULL);
	return (0);
}
