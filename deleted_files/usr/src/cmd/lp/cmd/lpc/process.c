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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <locale.h>

#include "lp.h"
#include "printers.h"
#include "class.h"
#include "msgs.h"
#include "requests.h"
#include "oam.h"
#include "oam_def.h"
#include "lpc.h"

struct prnames {
	char		*printer; 	
	struct prnames  *next;
};

struct prnames	*prhead;
	
int		 got_all_prnames;

extern int	 When;
extern char	*Reason;

#if defined (__STDC__)
static	void	unlinkf(char *);
#else
static	void	unlinkf();
#endif

/**
 **   Obtain all printer names from LPSCHED and save them in
 **   a linked list of printer names.
 **/
static void
#if defined(__STDC__)
get_all_prnames(void)
#else
get_all_prnames()
#endif
{



	char	*printer,
		*reject_reason,
		*request_id,
		*form,
		*char_set,
		*disable_reason;

	short	 printer_status,
		 status;

	long	 enable_date,
		 reject_date;
	
	int 	 rc;
	register struct prnames	*ptr, *prcur;


	if (got_all_prnames) 
		return;


	/*
 	 * Send a message to LPSCHED to retrive all printer names
	 * This is done by sending a: S_INQUIRE_PRINTER_STATUS to LPSCHED.
	 * This will return the current status of the job underway on 
         * all the printers on the system. 
	 */
	prhead = NULL;
	snd_msg(S_INQUIRE_PRINTER_STATUS, "");
	do {
		rcv_msg(R_INQUIRE_PRINTER_STATUS, &status,
						  &printer,
						  &form,
						  &char_set,
						  &disable_reason,
						  &reject_reason,
						  &printer_status,
						  &request_id,
						  &enable_date,
						  &reject_date);
		if(!(ptr = (struct prnames *)malloc(sizeof(struct prnames)))) {
			lp_fatal(E_LP_MALLOC);
			/*NOTREACHED*/
		}
		if(prhead == NULL)
			prhead = ptr;
		else
			prcur->next = ptr;
		prcur = ptr;
		/* Copy : printer name
		 * Increment the entry count.
		 */
		ptr->printer = (char *)malloc(strlen(printer) + 1);
		strcpy(ptr->printer, printer);
		ptr->next = NULL;
	} while(status== MOKMORE);
	got_all_prnames = 1;
	return;
}



/* 
** The actual work in passing the commands to LPCSHED is done here
** i.e: Enable/disable the queues
**      Enable/disable the printers
**	canceling jobs and the temporary files etc
**/

/*
**	Disable the queue to a printer.
**/
void
#if defined(__STDC__)
disableq(char *dest)
#else
disableq(dest)
char	*dest;
#endif
{
    	short	 status;
	char	*reason = Reason;

	if (!reason)
		reason = "unknown reason";

	snd_msg(S_REJECT_DEST, dest, reason);
	rcv_msg(R_REJECT_DEST, &status);
	switch (status) {
	case MOK:
	case MERRDEST:
		printf(gettext("%s:\n\tqueuing disabled\n"), dest);
		break;
	case MNODEST:
 		printf(gettext("unknown printer %s\n"), dest);
		break;
	case MNOPERM:
		printf(gettext("%s:\n\tcannot disable queuing\n"), dest);
		break;
	default:
		lp_fatal(E_LP_BADSTATUS, status); 
		/*NOTREACHED*/
	}
}
/*
**	Enable the queue to a printer.
**/	

void	
#if defined(__STDC__)
enableq(char *dest)
#else
enableq(dest)
char	*dest;
#endif
{
    	short	status;

	snd_msg(S_ACCEPT_DEST, dest);
	rcv_msg(R_ACCEPT_DEST, &status);
	switch (status) {
	case MOK:
	case MERRDEST:
		printf("%s:\n", dest);
		printf(gettext("\tqueueing enabled\n"));
	    	break;
	case MNODEST:
  		printf(gettext("unknown printer %s\n"), dest);
	    	break;
	case MNOPERM:
		printf("%s:\n", dest);
		printf(gettext("\tcannot enable queueing\n"));
	    	break;
	default:
	    	lp_fatal(E_LP_BADSTATUS, status);
		/*NOTREACHED*/
	}

}

/*
**	Enable printing on the given printer.
**/
void
#if defined(__STDC__)
enablepr(char *dest)
#else
enablepr(dest)
char	*dest;
#endif
{
    	short	status;

	snd_msg(S_ENABLE_DEST, dest);
	rcv_msg(R_ENABLE_DEST, &status);
	switch (status) {
	case MOK:
	case MERRDEST:
		printf("%s:\n", dest);
		printf(gettext("\tprinting enabled\n"));
		break;
	case MNODEST:
		printf(gettext("unknown printer %s\n"), dest);
	    	break;
	case MNOPERM:
		printf("%s:\n", dest);
		printf(gettext("\tcannot enable printing\n"));
	    	break;
	default:
	    	lp_fatal(E_LP_BADSTATUS, status);
		/*NOTREACHED*/
	}
}

/*
**	Disable printing on the named printer.
**/
void
#if defined(__STDC__)
disablepr(char *dest)
#else
disablepr(dest)
char	*dest;
#endif
{
	short	 status;
	char	*req_id;
	char	*reason = Reason;

	if (!reason)
		reason = "stopped by user";

	snd_msg(S_DISABLE_DEST, dest, reason, When);
	rcv_msg(R_DISABLE_DEST, &status, &req_id);
	switch (status) {
    	case MOK:
	case MERRDEST:
		printf("%s:\n", dest);
		printf(gettext("\tprinting disabled\n"));
		break;
	case MNODEST:
		printf(gettext("unknown printer %s\n"), dest);
		break;
    	case MNOPERM:
		printf("%s:\n", dest);
		printf(gettext("\tcannot disable printing\n"));
		break;
    	default:
		lp_fatal(E_LP_BADSTATUS, status); 
		/*NOTREACHED*/
    	}
	return;
}
	
void
#if defined(__STDC__)
statuspr(char *printer)
#else
statuspr(printer)
char	*printer;
#endif
{
	char	*tprinter;
			
	int	 rc, entry_count;

	char	*user,
		*reject_reason,
		*request_id,
		*form,
		*slabel,
		*file,
		*char_set,
		*disable_reason;

	short	 printer_status,
		 status, rank,
		 state;

	long	 size,
		 enable_date,
		 reject_date,
		 date;
	char	buff[100];

	entry_count = 0;
	snd_msg(S_INQUIRE_PRINTER_STATUS, printer);
	rcv_msg(R_INQUIRE_PRINTER_STATUS, &status,
					  &tprinter,
					  &form,
					  &char_set,
					  &disable_reason,
					  &reject_reason,
					  &printer_status,
					  &request_id,
					  &enable_date,
					  &reject_date);
	switch (status) {
	case MOK:
	case MOKMORE:
		break;
	case MNODEST:
		printf(gettext("unknown printer %s\n"), printer);
		return;
	default:
		lp_fatal(E_LP_BADSTATUS, status);
		/*NOTREACHED*/
	}
	printf("%s:\n", printer);
	printf(gettext("\tqueueing is %s\n"), printer_status & PS_REJECTED ? gettext("disabled") :
 gettext("enabled"));
	printf(gettext("\tprinting is %s\n"), printer_status & PS_DISABLED ? gettext("disabled") :
 gettext("enabled"));
	snd_msg(S_INQUIRE_REQUEST_RANK, "", "", printer, "", "");
	do {
		rcv_msg(R_INQUIRE_REQUEST_RANK, &status,
					   &request_id,
					   &user,
					   &slabel,
					   &size,
					   &date,
					   &state,
					   &tprinter,
					   &form,
					   &char_set,
					   &rank,
					   &file);
		switch (status) {
		case MOK:
		case MOKMORE:
			if (!(state & RS_DONE))
				entry_count++;
			break;
		case MNOINFO:
			break;
		default:
			lp_fatal(E_LP_BADSTATUS, status);
			/*NOTREACHED*/
		}
	} while (status == MOKMORE);
	if (entry_count == 0 )
		printf(gettext("\tno entries\n"));
	else if (entry_count == 1)
		printf(gettext("\t1 entry in spool area\n"));
	else
		printf(gettext("\t%d entries in spool area\n"), entry_count);
	if (entry_count) {
		if (!(printer_status & (PS_FAULTED|PS_DISABLED)))
			printf(gettext("\t%s is ready and printing\n"), printer);
		else if (printer_status & PS_FAULTED)
			printf(gettext("\twaiting for %s to become ready (offline?)\n"), printer);
	}
			
	/*??? what to do for remote printers:
		possible status:
			"waiting for RM to come up"
			"waiting for queue to be enabled on RM"
			"sending to RM"
			"no space on remote; waiting for queue to drain"
	*/
}

void
#if defined(__STDC__)
restartpr(char *dest)
#else
restartpr(dest)
char	*dest;
#endif
{
	disablepr(dest);
	enablepr(dest);
}

void
#if defined(__STDC__)
uppr(char *dest)
#else
uppr(dest)
char	*dest;
#endif
{
	enableq(dest);
	enablepr(dest);
}

void
#if defined(__STDC__)
downpr(char *dest)
#else
downpr(dest)
char	*dest;
#endif
{
	disableq(dest);
	disablepr(dest);
}

/* avoids compiler type checking problem */
static int
#if defined(__STDC__)
_strcmp(const void *s1, const void *s2)
#else
_strcmp(s1, s2)
void *s1;
void *s2;
#endif
{
	return(strcmp(s1, s2));
}

void
#if defined(__STDC__)
cleanpr(char *dest)
#else
cleanpr(dest)
char	*dest;
#endif
{
        int                     i;
        short                   more;
        long                    status;
        char *                  req_id;

	snd_msg(S_CANCEL, dest, "", "");

	do {
		rcv_msg(R_CANCEL, &more, &status, &req_id);

	switch (status) {
                case MOK:
                        printf(gettext("\tremoved %s\n"), req_id);
                        break;
                case M2LATE:
                        printf(gettext("\tbusy %s failed\n"), req_id);
                        break;
		case MUNKNOWN:
                case MNOINFO:
		case MNOPERM:
                        printf(gettext("\t%s failed\n"), req_id);
                        break;
                default:
			printf(gettext("Unknown status from scheduler (%d)\n"),
				status);
                        exit (1);
                }
 
        } while (more == MOKMORE);
 
        return;



}

static void
#if defined(__STDC__)
unlinkf(char *name)
#else
unlinkf(name)
char	*name;
#endif
{
	if (unlink(name) < 0)
		printf(gettext("\tcannot remove %s\n"), name);
	else
		printf(gettext("\tremoved %s\n"), name);
}

void
#if defined(__STDC__)
do_all(void (*func)(char *))
#else
do_all(func)
void	(*func)();
#endif
{
	register struct prnames	*ptr;

	get_all_prnames();
	
	for (ptr = prhead; ptr; ptr = ptr->next)
		(*func)(ptr->printer);
}
