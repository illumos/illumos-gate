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

# include	<stdarg.h>
# include	<limits.h>
# include	<sys/types.h>
# include	<poll.h>
# include	<stropts.h>
# include	<unistd.h>
#include <syslog.h>

# include	"lpsched.h"

#define TURN_OFF(X,F)	(void)Fcntl(X, F_SETFL, (Fcntl(X, F_GETFL, 0) & ~(F)))


static void	conn_shutdown();

extern int		Filter_Status;
extern void		dispatch();
extern int		Waitrequest;
void			shutdown_messages();
static char		*Message;
static int		MaxClients		= 0,
			do_msg();
extern int		Reserve_Fds;
extern int		Shutdown;

MESG			*Net_md;

/*
** take_message() - WAIT FOR INTERRUPT OR ONE MESSAGE FROM USER PROCESS
*/

void take_message(void)
{
    int		bytes;
    int		i;
    MESG *	md;

    for (EVER) {	/* not really forever...returns are in the loop */
	if ((md = mlisten()) == NULL)
	    switch(errno) {
	      case EAGAIN:
	      case EINTR:
		return;

	      case ENOMEM:
		mallocfail();
		/* NOTREACHED */

	      default:
		fail ("Unexpected streams error in mlisten (%s).\n" , PERROR);
	    }
	
	/*
	 * Check for a dropped connection to a child.
	 * Normally a child should tell us that it is dying
	 * (with S_SHUTDOWN or S_SEND_CHILD), but it may have
	 * died a fast death. We'll simulate the message we
	 * wanted to get so we can use the same code to clean up.
	 */
	if ((md->event & POLLHUP) && !(md->event & POLLIN) ||
	    (md->event & (POLLERR|POLLNVAL))) {
		switch (md->type) {

		case MD_CHILD:
			/*
			 * If the message descriptor is found in the
			 * exec table, it must be an interface pgm,
			 * notification, etc. Otherwise, it must be
			 * a network child.
			 */
			for (i = 0; Exec_Table[i] != NULL; i++)
				if (Exec_Table[i]->md == md)
					break;

			if (Exec_Table[i] != NULL) {
				(void) putmessage(Message, S_CHILD_DONE,
					Exec_Table[i]->key, 0, 0);
			} else {
				(void) putmessage(Message, S_SHUTDOWN, 1);
			}
			bytes = 1;
			break;

		default:
			bytes = -1;
			break;

		}

	} else {
		if (md->readfd == -1) { /* something happened to the readfd */
			syslog(LOG_DEBUG, "take_message: readfd is -1");
			return;
		}
		bytes = mread(md, Message, MSGMAX);
	}

	switch (bytes) {
	  case -1:
	    if (errno == EINTR)
		return;
	    else
		fail ("Unexpected streams error (%s).\n" , PERROR);
	    break;

	  case 0:
	    break;

	  default:
	    if (do_msg(md))
		return;
	    break;
	}
    }
}

/*
** do_msg() - HANDLE AN INCOMING MESSAGE
*/

static int
do_msg(MESG *md)
{
    int			type = mtype(Message);

    if (type != S_GOODBYE) {
	    md->wait = 0;
	    dispatch (type, Message, md);
	    /*
	     * The message may have caused the need to
	     * schedule something, so go back and check.
	     */
	    return(1);
    }
    return(0);
}

/*
** calculate_nopen() - DETERMINE # FILE DESCRIPTORS AVAILABLE FOR QUEUES
*/

static void
calculate_nopen(void)
{
    int		fd, nopen;

    /*
     * How many file descriptorss are currently being used?
     */
    for (fd = nopen = 0; fd < OpenMax; fd++)
	if (fcntl(fd, F_GETFL, 0) != -1)
	    nopen++;

    /*
     * How many file descriptors are available for use
     * as open FIFOs? Leave one spare as a way to tell
     * clients we don't have any to spare (hmmm....) and
     * one for the incoming fifo.
     */

    MaxClients = OpenMax;
    MaxClients -= nopen;	/* current overhead */
    MaxClients -= Reserve_Fds;
    MaxClients -= 2;		/* incoming FIFO and spare outgoing */
    MaxClients--;		/* the requests log */
    MaxClients--;		/* HPI routines and lpsched log */

    return;
}

static void conn_shutdown ( )
{
    if (!Shutdown) {
	note ("The public connection \"%s\", has failed.\n", Lp_FIFO);
	lpshut(1);
    }
}

/*
** init_messages() - INITIALIZE MAIN MESSAGE QUEUE
*/

void
init_messages(void)
{
    char	*cmd;
    MESG *	md;

    (void) signal(SIGPIPE, SIG_IGN);

    calculate_nopen ();

    Message = (char *)Malloc(MSGMAX);

    (void) Chmod(Lp_Tmp, 0711);
    
    if ((md = mcreate(Lp_FIFO)) == NULL)
	fail ("Can't create public message device (%s).\n", PERROR);
    mon_discon(md, conn_shutdown);
    
    if (mlisteninit(md) != 0)
	if (errno == ENOMEM)
	    mallocfail();
	else
	    fail ("Unexpected streams error (%s).\n" , PERROR);

    (void) Chmod(Lp_FIFO, 0666);
    return;
}

    
void
shutdown_messages(void)
{
    MESG	*md;
    
    (void) Chmod(Lp_Tmp, 0700);
    (void) Chmod(Lp_FIFO, 0600);
    md = mlistenreset();
    mdestroy(md);
}
