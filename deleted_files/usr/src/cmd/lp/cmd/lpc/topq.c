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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>

#include "lp.h"
#include "printers.h"
#include "class.h"
#include "msgs.h"
#include "requests.h"
#define WHO_AM_I	I_AM_OZ
#include "oam_def.h"

extern char	*Printer;

#if defined(__STDC__)
static	char	* start_change(char *);
static	int	  end_change(char *);
#else
static	char	* start_change();
static	int	  end_change();
#endif

int
#if defined(__STDC__)
topq_reqid(char *reqid, char *machine)
#else
topq_reqid(reqid, machine)
char	*reqid;
char	*machine;
#endif
{

	/* 
	** This is similar to: lp -i request-id -H IMMEDIATE
	*/ 

	char	*reqfile;			/* Name of request file */
	REQUEST	*oldrqp;
	char	 buf[50];

	if (machine) {
		(void) snprintf(buf, sizeof (buf), "%s!%s", machine, reqid);
		reqid = buf;
	}
	if (!(reqfile = start_change(reqid)))
		return(0);

	if (!(oldrqp = getrequest(reqfile))) 
		return (0);

	oldrqp->actions |= ACT_IMMEDIATE;

	if (putrequest(reqfile, oldrqp) == -1) {	/* write request file */
	    switch(errno) {
	    default:
		lp_fatal(E_LPP_FPUTREQ); 
		/*NOTREACHED*/
	    }
	}
	free(reqfile);
	(void)end_change(reqid);

	printf(gettext("\tmoved %s\n"), reqid);
	return(1);
}


/* start_change -- start change request */
static char *
#if defined(__STDC__)
start_change(char *rqid)
#else
start_change(rqid)
char	*rqid;
#endif
{
    	short	 status;
	char	*rqfile;

	snd_msg(S_START_CHANGE_REQUEST, rqid);
	rcv_msg(R_START_CHANGE_REQUEST, &status, &rqfile);

    	switch (status) {
    	case MOK:
		return((char *)strdup(rqfile));
	default:
		return(NULL);
	}
}

static int
#if defined(__STDC__)
end_change(char *rqid)
#else
end_change(rqid)
char	*rqid;
#endif
{
    	long	chkbits;
    	short	status;

    	snd_msg(S_END_CHANGE_REQUEST, rqid);
	rcv_msg(R_END_CHANGE_REQUEST, &status, &chkbits);

    	switch (status) {
    	case MOK:
		return(1);
	default:
		return(0);
	}
}

/*
**	topq command handler if user name is specified
**	Find request-ids of all jobs submitted by the user.
**	Save the request-ids
** 	Follow the same method as in topq_reqid for each if the ids.
*/	
int
#if defined(__STDC__)
topq_user(char *user, char *machine)
#else
topq_user(user, machine)
char	*user;
char	*machine;
#endif
{
	char	 *request_id, *form, *slabel, *character_set;
	char	  buf[50];
	char	**rqlist = NULL, **pp;
	short	  state, status;
	long	  size, date;
	int	  count = 0;


	if (machine) {
		(void) snprintf(buf, sizeof (buf), "%s!%s", machine, user);
		user = buf;
	}
	snd_msg(S_INQUIRE_REQUEST, "", Printer, "", user, "");
	do {
		rcv_msg(R_INQUIRE_REQUEST, &status,
					   &request_id,
					   &user,
					   &slabel,
					   &size,
					   &date,
					   &state,
					   &Printer,
					   &form,
					   &character_set);
		switch (status) {
		case MOK:
		case MOKMORE:
			appendlist(&rqlist, request_id);
			break;
		default:
			return(0);
		}
	} while (status == MOKMORE);
	for (pp = rqlist; *pp; pp++)
		count += topq_reqid(*pp, machine);
	freelist(rqlist);
	return(count);	/* Number of jobs moved to topq */
}
