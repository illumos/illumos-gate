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


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lpsched.h"

static char		*N_Msg[] = {
	"Subject: Status of lp request %s\n\nYour request %s destined for %s%s\n",
	"has completed successfully on printer %s.\n",
	"was canceled by the lpsched daemon%s\n", /* bugfix 1100252 */
	"encountered an error during filtering.\n",
	"encountered an error while printing on printer %s.\n",
	"Filtering stopped with an exit code of %d.\n",
	"Printing stopped with an exit code of %d.\n",
	"Filtering was interrupted with a signal %d.\n",
	"Printing was interrupted with a signal %d.\n",
	"\nReason for failure:\n\n%s\n",
	"\nReason for being canceled:\n\n%s\n",
};

static struct reason {
	short			reason;
	char			*msg;
}			N_Reason[] = {
    {
	MNODEST,
	"The requested print destination has been removed."
    }, {
	MERRDEST,
	"All candidate destinations are rejecting further requests."
    }, {
	MDENYDEST,
	"You are no longer allowed to use any printer suitable for\nthe request."
    }, {
	MDENYDEST,
	"No candidate printer can handle these characteristics:"
    }, {
	MNOMEDIA,
	"The form you requested no longer exists."
    }, {
	MDENYMEDIA,
	"You are no longer allowed to use the form you requested."
    }, {
	MDENYMEDIA,
	"The form you wanted now requires a different character set."
    }, {
	MNOFILTER,
	"There is no longer a filter that will convert your file for printing."
    }, {
	MNOMOUNT,
	"The form or print wheel you requested is not allowed on any\nprinter otherwise suitable for the request."
    }, {
	MNOSPACE,
	"Memory allocation problem."
    }, {
	-1,
	""
    }
};

	
static void print_reason(int, int);


/**
 ** notify() - NOTIFY USER OF FINISHED REQUEST
 **/
	
void
notify(register RSTATUS *prs, char *errbuf, int k, int e, int slow)
{
	register char		*cp;
	char			*file;
	int			fd;


	/*
	 * Screen out cases where no notification is needed.
	 */
	if (!(prs->request->outcome & RS_NOTIFY))
		return;
	if (
		!(prs->request->actions & (ACT_MAIL|ACT_WRITE|ACT_NOTIFY))
	     && !prs->request->alert
	     && !(prs->request->outcome & RS_CANCELLED)
	     && !e && !k && !errbuf       /* exited normally */
	)
		return;

	/*
	 * Create the notification message to the user.
	 */
	file = makereqerr(prs);
	if ((fd = open_locked(file, "w", MODE_NOREAD)) >= 0) {
		fdprintf(fd, N_Msg[0], prs->secure->req_id, prs->secure->req_id,
			prs->request->destination,
			STREQU(prs->request->destination, NAME_ANY)? " printer"
				: "");

		if (prs->request) {
			char file[BUFSIZ];
			
			GetRequestFiles(prs->request, file, sizeof(file));
			fdprintf(fd, "\nThe job title was:\t%s\n", file);
			fdprintf(fd, "     submitted by:\t%s\n",
				prs->request->user);
			fdprintf(fd, "               at:\t%s\n",
				ctime(&prs->secure->date));
		}
	
		if (prs->request->outcome & RS_PRINTED)
			fdprintf(fd, N_Msg[1], prs->printer->printer->name);

		if (prs->request->outcome & RS_CANCELLED)
			fdprintf(fd, N_Msg[2],
				(prs->request->outcome & RS_FAILED)? ", and"
					: ".");
		
	
		if (prs->request->outcome & RS_FAILED) {
			if (slow)
				fdprintf(fd, N_Msg[3]);
			else
				fdprintf(fd, N_Msg[4],
					prs->printer->printer->name);
	
			if (e > 0)
				fdprintf(fd, N_Msg[slow? 5 : 6], e);
			else if (k)
				fdprintf(fd, N_Msg[slow? 7 : 8], k);
		}
	
		if (errbuf) {
			for (cp = errbuf; *cp && *cp == '\n'; cp++)
				;
			fdprintf(fd, N_Msg[9], cp);
			if (prs->request->outcome & RS_CANCELLED)
				fdprintf(fd, "\n");
		}

		/* start fix for bugid 1100252	*/
		if (prs->request->outcome & RS_CANCELLED) {
			print_reason (fd, prs->reason);
		}

		close(fd);
		schedule (EV_NOTIFY, prs);

	}
	if (file)
		Free (file);

	return;
}

/**
 ** print_reason() - PRINT REASON FOR AUTOMATIC CANCEL
 **/

static void
print_reason(int fd, int reason)
{
	register int		i;


#define P(BIT,MSG)	if (chkprinter_result & BIT) fdprintf(fd, MSG)

	for (i = 0; N_Reason[i].reason != -1; i++)
		if (N_Reason[i].reason == reason) {
			if (reason == MDENYDEST && chkprinter_result)
				i++;
			if (reason == MDENYMEDIA && chkprinter_result)
				i++;
			fdprintf(fd, N_Msg[10], N_Reason[i].msg);
			if (reason == MDENYDEST && chkprinter_result) {
				P (PCK_TYPE,	"\tprinter type\n");
				P (PCK_CHARSET,	"\tcharacter set\n");
				P (PCK_CPI,	"\tcharacter pitch\n");
				P (PCK_LPI,	"\tline pitch\n");
				P (PCK_WIDTH,	"\tpage width\n");
				P (PCK_LENGTH,	"\tpage length\n");
				P (PCK_BANNER,	"\tno banner\n");
			}
			break;
		}

	return;
}
