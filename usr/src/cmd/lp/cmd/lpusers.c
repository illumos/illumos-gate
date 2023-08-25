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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/* lpusers [-q priority-level] -u (user-list | "")
   lpusers -d priority-level
   lpusers -l
*/
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <locale.h>

#include "lp.h"
#include "users.h"
#include "msgs.h"

#define	WHO_AM_I	I_AM_LPUSERS
#include "oam.h"

char message[100],
     reply[100];

char	*PRIORITY;

int add_user(), del_user();

int
main(int argc, char *argv[])
{
    int mtype, size, c,
	list = FALSE, limit = -1, deflt = -1;
    int fd;
    char *userlist = 0, *user, **users, *p;
    char stroptsw[] = "-X";
    short status;
    struct user_priority *ppri_tbl, *ld_priority_file();
    extern char *optarg;
    extern int optind, opterr, optopt, errno;

    setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define TEXT_DOMAIN "SYS_TEST"
#endif
    (void) textdomain(TEXT_DOMAIN);


    if(argc == 1) {
usage:
	(void) printf(gettext("usage: \n"));
  	(void) printf(gettext("(assign priority limit to users)\n"));
	(void) printf(gettext("\tlpusers -q priority -u user-list\n"));

  	(void) printf(gettext(
		"(assign default priority limit for balance of users)\n"));
	(void) printf(gettext("\tlpusers -q priority\n"));

  	(void) printf(gettext("(put users back to default priority limit)\n"));
	(void) printf(gettext("\tlpusers -u user-list\n"));

  	(void) printf(gettext("(assign default priority)\n"));
	(void) printf(gettext("\tlpusers -d priority\n"));

  	(void) printf(gettext("(examine priority limits, defaults)\n"));
	(void) printf(gettext("\tlpusers -l\n"));

	exit(argc == 1);
    }

    opterr = 0; /* disable printing of errors by getopt */
    while ((c = getopt(argc, argv, "ld:q:u:")) != -1)
	switch(c) {
	case 'l':
	    if (list)
		LP_ERRMSG1(WARNING, E_LP_2MANY, 'l');
	    list = TRUE;
	    break;
	case 'd':
	    if (deflt != -1)
		LP_ERRMSG1(WARNING, E_LP_2MANY, 'd');
	    deflt = (int)strtol(optarg,&p,10);
	    if (*p || deflt<PRI_MIN || deflt>PRI_MAX) {
		LP_ERRMSG1(ERROR, E_LP_BADPRI, optarg);
		exit(1);
	    }
	    break;
	case 'q':
	    if (limit != -1)
		LP_ERRMSG1(WARNING, E_LP_2MANY, 'q');
	    limit = (int)strtol(optarg,&p,10);
	    if (*p || limit<PRI_MIN || limit>PRI_MAX) {
		LP_ERRMSG1(ERROR, E_LP_BADPRI, optarg);
		exit(1);
	    }
	    break;
	case 'u':
	    if (userlist)
		LP_ERRMSG1(WARNING, E_LP_2MANY, 'u');
	    userlist = optarg;
	    break;
	case '?':
	    if (optopt == '?')
		    goto usage;
	    stroptsw[1] = optopt;
	    if (strchr("ldqu", optopt))
		LP_ERRMSG1(ERROR, E_LP_OPTARG, stroptsw);
	    else
		LP_ERRMSG1(ERROR, E_LP_OPTION, stroptsw);
	    exit(1);
	}

    if (optind < argc) {
	LP_ERRMSG1(ERROR, E_LP_EXTRA, argv[optind]);
	exit(1);
    }

    if (((list || deflt != -1) && (limit != -1 || userlist))
	|| (list && deflt != -1)) {
	LP_ERRMSG(ERROR, E_LP_OPTCOMB);
	/* invalid combination of options */
	exit(1);
    }

    PRIORITY = Lp_Users;

    /* load existing priorities from file */
    if (!(ppri_tbl = ld_priority_file(PRIORITY))) {
	switch (errno) {
	case EBADF:
	    LP_ERRMSG1(ERROR, E_LPU_BADFORM, PRIORITY);
	    break;
	default:
	    LP_ERRMSG2(ERROR, E_LPU_BADFILE, PRIORITY, errno);
	}
	exit(1);
    }

    if (list) {
	print_tbl(ppri_tbl);
	exit (0);
    } else {
	if (userlist) {
	    users = getlist(userlist, " \t", ",");
	    if (users)
		while (user = *users++) {
		    if (del_user(ppri_tbl, user) && (limit == -1))
			LP_ERRMSG1(WARNING, E_LPU_NOUSER, user);
		    if (limit != -1) {
			if (add_user(ppri_tbl, user, limit))
			    LP_ERRMSG1(WARNING, E_LPU_BADU, user);
		    }
		}
	} else if (deflt != -1)
	    ppri_tbl->deflt = deflt;
	else
	    ppri_tbl->deflt_limit = limit;

	if ((fd = open_locked(PRIORITY, "w", LPU_MODE)) < 0) {
	    LP_ERRMSG1(ERROR, E_LP_ACCESS, PRIORITY);
	    exit(1);
	}
	output_tbl(fd, ppri_tbl);
	close(fd);
    }

    if (mopen()) /* error on mopen == no spooler, exit quietly */
	exit(0);

    (void)putmessage (message, S_LOAD_USER_FILE);

    if (msend(message))
	goto Error;
    if (mrecv(reply, sizeof(reply)) == -1)
	goto Error;
    mtype = getmessage(reply, R_LOAD_USER_FILE, &status);
    if (mtype != R_LOAD_USER_FILE) {
	LP_ERRMSG1 (ERROR, E_LP_BADREPLY, mtype);
	goto NoError;
    }

    if (status == 0)
	goto NoError;

Error:	LP_ERRMSG (ERROR, E_LPU_NOLOAD);

NoError:(void)mclose ();
    return (0);
}
