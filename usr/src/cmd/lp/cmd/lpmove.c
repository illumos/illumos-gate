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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1984 AT&T	*/
/*	  All Rights Reserved  	*/


/*	lpmove dest1 dest2 - move all requests from dest1 to dest2
 *	lpmove request ... dest - move requests to destination dest
 *
 *	This command may be used only by an LP Administrator
 */

#include <assert.h>
#include <signal.h>
#include <locale.h>
#include <sys/types.h>

#include "lp.h"
#include "msgs.h"
#include "printers.h"

#define WHO_AM_I	I_AM_LPMOVE
#include "oam.h"

char message[100],
     reply[100];

#define TRUE	1
#define FALSE	0

void startup(), cleanup(), err_exit();
#if	defined(__STDC__)
void	catch();
#else
int catch();
#endif

void
usage()
{
	(void) printf (gettext(
"usage:\n"
"\n"
"  (move all requests, reject any new requests)\n"
"	lpmove from-destination to-destination\n"
"\n"
"  (move individual requests)\n"
"	lpmove requests ... to-destination\n"));

	return;
}

char *strncpy();

void
main(argc, argv)
int argc;
char *argv[];
{
    int i, type, size, rc = 0, wasrej;
    short status;
    char *strchr(), *rq_id, *chkp;
    long chkbits;
    short nmove = 0;

    (void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

    if (argc == 2 && STREQU(argv[1], "-?")) {
	usage();
	exit(0);
    }
    if(argc < 3) {
	usage();
	exit(1);
    }

    startup();

    if (!isrequest(argv[1])) { /* if first arg is a dest */
	if(argc != 3) {
	    usage();
	    exit(1);
	}

	if ((wasrej = reject(argv[1],argv[2])) == 1) err_exit();

	printf(gettext("move in progress ...\n"));
	size = putmessage(message, S_MOVE_DEST, argv[1], argv[2]);
	assert(size != -1);
    	if (msend(message)) {
	    LP_ERRMSG(ERROR, E_LP_MSEND);
	    goto Errexit;
	}
	while (1) {
	    if ((type = mrecv(reply, sizeof(reply))) == -1) {
		LP_ERRMSG(ERROR, E_LP_MRECV);
		goto Errexit;
	    }
    	    if (type != R_MOVE_DEST
	      || getmessage(reply, type, &status, &rq_id, &nmove) == -1) {
		LP_ERRMSG1 (ERROR, E_LP_BADREPLY, type);
		goto Errexit;
	    }
	    switch (status) {
	    case MOK:
		break;
	    case MNODEST:
		LP_ERRMSG1(ERROR, E_LP_DSTUNK, rq_id);
Errexit:	if (!wasrej) accept(argv[1]);
		err_exit();
	    case MERRDEST:
		LP_ERRMSG1(WARNING, E_MOV_BADDEST, rq_id);
		rc = 1;
		break;
	    case MMORERR:
		LP_ERRMSG1(WARNING, E_MOV_BADDEST, rq_id);
		rc = 1;
		continue;
	    case MNOPERM:
		LP_ERRMSG(ERROR, E_LP_NOTADM);
		err_exit();
	    default:
		LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, status);
		rc = 1;
	    }
	    break;
	}
	printf(gettext("total of %d requests moved from %s to %s\n"),
	    nmove, argv[1], argv[2]);
    } else {
	for(i = 1; i < argc - 1; i++) {
	    size = putmessage(message,
		S_MOVE_REQUEST, argv[i], argv[argc-1]);
	    assert(size != -1);
	    if (msend(message)) {
		LP_ERRMSG(ERROR, E_LP_MSEND);
		err_exit();
	    }
	    if ((type = mrecv(reply, sizeof(reply))) == -1) {
		LP_ERRMSG(ERROR, E_LP_MRECV);
		err_exit();
	    }
	    if (type != R_MOVE_REQUEST
		 || getmessage(reply, type, &status, &chkbits) == -1) {
		LP_ERRMSG1 (ERROR, E_LP_BADREPLY, type);
		err_exit();
	    }
	    switch (status) {
	    case MOK:
		nmove++;
		break;
	    case MDENYDEST:
		if (chkbits) {
		    chkp = message;
		    if (chkbits & PCK_TYPE) chkp += sprintf(chkp, "printer type, ");
		    if (chkbits & PCK_CHARSET) chkp += sprintf(chkp, "character set, ");
		    if (chkbits & PCK_CPI) chkp += sprintf(chkp, "cpi, ");
		    if (chkbits & PCK_LPI) chkp += sprintf(chkp, "lpi, ");
		    if (chkbits & PCK_WIDTH) chkp += sprintf(chkp, "width, ");
		    if (chkbits & PCK_LENGTH) chkp += sprintf(chkp, "length, ");
		    if (chkbits & PCK_BANNER) chkp += sprintf(chkp, "banner req., ");
		    chkp[-2] = 0;
		    LP_ERRMSG2(ERROR, E_MOV_PTRCHK, argv[i], message);
		}
		else LP_ERRMSG1(ERROR, E_MOV_DENYDEST, argv[i]);
		rc = 1;
		break;
	    case MNOMEDIA:
		LP_ERRMSG1(ERROR, E_MOV_NOMEDIA, argv[i]);
		rc = 1;
		break;
	    case MDENYMEDIA:
		LP_ERRMSG1(ERROR, E_MOV_DENYMEDIA, argv[i]);
		rc = 1;
		break;
	    case MNOMOUNT:
		LP_ERRMSG1(ERROR, E_MOV_NOMOUNT, argv[i]);
		rc = 1;
		break;
	    case MNOFILTER:
		LP_ERRMSG1(ERROR, E_MOV_NOFILTER, argv[i]);
		rc = 1;
		break;
	    case MERRDEST:
		LP_ERRMSG1(ERROR, E_LP_REQDENY, argv[argc-1]);
		rc = 1;
		break;
	    case MNODEST:
		LP_ERRMSG1(ERROR, E_LP_DSTUNK, argv[argc-1]);
		err_exit();
	    case MUNKNOWN:
		LP_ERRMSG1(ERROR, E_LP_UNKREQID, argv[i]);
		rc = 1;
		break;
	    case MBUSY:
		LP_ERRMSG1(ERROR, E_LP_BUSY, argv[i]);
		rc = 1;
		break;
	    case M2LATE:
		LP_ERRMSG1(ERROR, E_LP_2LATE, argv[i]);
		rc = 1;
		break;
	    case MNOPERM:
		LP_ERRMSG (ERROR, E_LP_NOTADM);
		err_exit();
	    case MGONEREMOTE:
		LP_ERRMSG1(ERROR, E_LP_GONEREMOTE, argv[i]);
		break;
	    default:
		LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, status);
		rc = 1;
	    }
	}
	printf(gettext("total of %d requests moved to %s\n"), nmove, argv[argc-1]);
    }

    cleanup();
    exit(rc);
}

accept(dest)
char *dest;
{
    int type, size;
    short status;
 
    size = putmessage(message, S_ACCEPT_DEST, dest);
    assert(size != -1);
    if (msend(message)) {
	LP_ERRMSG(ERROR, E_LP_MSEND);
	return(1);
    }
    if ((type = mrecv(reply, size)) == -1) {
	LP_ERRMSG(ERROR, E_LP_MRECV);
	return(1);
    }
    if (type != R_ACCEPT_DEST
	 || getmessage(reply, type, &status) == -1) {
	LP_ERRMSG(ERROR, E_LP_BADREPLY);
	return(1);
    }
    switch (status) {
    case MNODEST:
	LP_ERRMSG1(ERROR, E_LP_DSTUNK, dest);
	return(1);
    case MNOPERM:
	LP_ERRMSG (ERROR, E_LP_NOTADM);
	return(1);
    default:
	LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, status);
	return(1);
    case MOK:
    case MERRDEST:
	;
    }

    return(0);
}

reject(d1, d2)
char *d1;
char *d2;
{
    int type, size;
    short status;
    char reason[128];
 
    /* reject(dest, reason) */
    snprintf(reason, sizeof (reason), "requests moved to %s", d2);
    size = putmessage(message, S_REJECT_DEST, d1, reason);
    assert(size != -1);
    if (msend(message)) {
	LP_ERRMSG(ERROR, E_LP_MSEND);
	return(1);
    }
    if ((type = mrecv(reply, size)) == -1) {
	LP_ERRMSG(ERROR, E_LP_MRECV);
	return(1);
    }
    if (type != R_REJECT_DEST
	 || getmessage(reply, type, &status) == -1) {
	LP_ERRMSG(ERROR, E_LP_BADREPLY);
	return(1);
    }
    switch (status) {
    case MNODEST:
	LP_ERRMSG1(ERROR, E_LP_DSTUNK, d1);
	return(1);
    case MNOPERM:
	LP_ERRMSG (ERROR, E_LP_NOTADM);
	return(1);
    default:
	LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, status);
	return(1);
    case MERRDEST:
	return(-1); /* was rejecting */
    case MOK:
	printf(gettext("destination %s is not accepting requests\n"), d1);
	break;
    }

    return(0);
}

void
startup()
{
    if (mopen()) {LP_ERRMSG(ERROR, E_LP_MOPEN); exit(1);}

    if(signal(SIGHUP, SIG_IGN) != SIG_IGN)
	signal(SIGHUP, catch);
    if(signal(SIGINT, SIG_IGN) != SIG_IGN)
	signal(SIGINT, catch);
    if(signal(SIGQUIT, SIG_IGN) != SIG_IGN)
	signal(SIGQUIT, catch);
    if(signal(SIGTERM, SIG_IGN) != SIG_IGN)
	signal(SIGTERM, catch);
}

/* catch -- catch signals */

#if	defined(__STDC__)
void
#endif
catch()
{

    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    err_exit();
}

void
cleanup()
{
    (void)mclose ();
}

void
err_exit()
{
    cleanup();
    exit(1);
}
