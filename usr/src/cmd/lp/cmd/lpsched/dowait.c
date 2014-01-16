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

/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "lpsched.h"
#include "ctype.h"
#include "sys/stat.h"
#include <syslog.h>

/*
 * Macro to test if we should notify the user.
 */
#define SHOULD_NOTIFY(PRS) \
	( \
		(PRS)->request->actions & (ACT_MAIL|ACT_WRITE|ACT_NOTIFY)\
	     || (PRS)->request->alert \
	)

static char *		geterrbuf ( RSTATUS * );

/**
 ** dowait() - CLEAN UP CHILD THAT HAS FINISHED, RESCHEDULE ANOTHER TASK
 **/

void
dowait (void)
{
	int			exited,
				killed,
				canned,
				i;
	EXEC			*ep;
	char			*errbuf = NULL;
	register RSTATUS	*prs;
	register PSTATUS	*pps;
	register ALERT		*pas;

	syslog(LOG_DEBUG, "dowait(%d)", DoneChildren);
	while (DoneChildren > 0) {
		DoneChildren--;

		for (i = 0; (ep = Exec_Table[i]) != NULL; i++)
			if (ep->pid == -99)
				break;

		syslog(LOG_DEBUG, "dowait(): 0x%8.8x", ep);

		if (Exec_Table[i] == NULL)	/* nothing to cleanup */
			continue;

		syslog(LOG_DEBUG, "dowait(): cleaning up 0x%8.8x", ep);

		ep->pid = 0;
		ep->key = 0;	/* avoid subsequent sneaks */
		if (ep->md)
			DROP_MD(ep->md);

		killed = KILLED(ep->status);
		exited = EXITED(ep->status);

		syslog(LOG_DEBUG, "dowait(): type %d, killed %d, exited %d",
			ep->type, killed, exited);

		switch (ep->type) {

		case EX_INTERF:
			/*
			 * WARNING: It could be that when we get here
			 *
			 *	pps->request->printer != pps
			 *
			 * because the request has been assigned to
			 * another printer.
			 */
			pps = ep->ex.printer;
			prs = pps->request;
			pps->request = 0;
			pps->status &= ~PS_BUSY;

			/*
			 * If the interface program exited cleanly
			 * or with just a user error, the printer
			 * is assumed to be working.
			 */
			if (0 <= exited && exited < EXEC_EXIT_USER) {
				pps->status &= ~PS_FAULTED;
				if (pps->alert->active)
					cancel_alert (A_PRINTER, pps);
			}

			/*
			 * If the interface program was killed with
			 * SIGTERM, it may have been because we canceled
			 * the request, disabled the printer, or for some
			 * other reason stopped the request.
			 * If so, clear the "killed" flag because that's
			 * not the condition of importance here.
			 */
			canned = 0;
			if (killed == SIGTERM) {
				if (prs->request->outcome & RS_CANCELLED)
					canned = 1;

				if (
					canned
				     || pps->status & (PS_DISABLED|PS_FAULTED)
				     || prs->request->outcome & RS_STOPPED
				     || Shutdown
				)
					killed = 0;
			}

			/*
			 * If there was standard error output from the
			 * interface program, or if the interface program
			 * exited with a (user) exit code, or if it got
			 * a strange signal, the user should be notified.
			 */
			errbuf = geterrbuf(prs);
			if (
				errbuf
			     || (0 < exited && exited <= EXEC_EXIT_USER)
			     || killed
			) {
				if (exited != EXIT_RETRY) {
					prs->request->outcome |= RS_FAILED;
				}
				prs->request->outcome |= RS_NOTIFY;
				notify (prs, errbuf, killed, exited, 0);
				if (errbuf)
					Free (errbuf);

			/*
			 * If the request was canceled, call "notify()"
			 * in case we're to notify the user.
			 */
			} else if (canned) {
				if (SHOULD_NOTIFY(prs))
					prs->request->outcome |= RS_NOTIFY;
				notify (prs, (char *)0, 0, 0, 0);

			/*
			 * If the request finished successfully, call
			 * "notify()" in case we're to notify the user.
			 */
			} else if (exited == 0) {
				prs->request->outcome |= RS_PRINTED;

				if (SHOULD_NOTIFY(prs))
					prs->request->outcome |= RS_NOTIFY;
				notify (prs, (char *)0, 0, 0, 0);
			}

			/*
			 * If the interface program exits with an
			 * exit code higher than EXEC_EXIT_USER, it's
			 * a special case.
			 */

			switch (exited) {

			case EXEC_EXIT_FAULT:
				printer_fault (pps, prs, 0, 0);
				break;

			case EXEC_EXIT_HUP:
				printer_fault (pps, prs, HANGUP_FAULT, 0);
				break;

			case EXEC_EXIT_INTR:
				printer_fault (pps, prs, INTERRUPT_FAULT, 0);
				break;

			case EXEC_EXIT_PIPE:
				printer_fault (pps, prs, PIPE_FAULT, 0);
				break;

			case EXEC_EXIT_EXIT:
				note (
					"Bad exit from interface program for printer %s: %d\n",
					pps->printer->name,
					ep->Errno
				);
				printer_fault (pps, prs, EXIT_FAULT, 0);
				break;

			case EXEC_EXIT_NPORT:
				printer_fault (pps, prs, OPEN_FAULT, ep->Errno);
				break;

			case EXEC_EXIT_TMOUT:
				printer_fault (pps, prs, TIMEOUT_FAULT, 0);
				break;

			case EXEC_EXIT_NOPEN:
				errno = ep->Errno;
				note (
					"Failed to open a print service file (%s).\n",
					PERROR
				);
				break;

			case EXEC_EXIT_NEXEC:
				errno = ep->Errno;
				note (
					"Failed to exec child process (%s).\n",
					PERROR
				);
				break;

			case EXEC_EXIT_NOMEM:
				mallocfail ();
				break;

			case EXEC_EXIT_NFORK:
				errno = ep->Errno;
				note (
					"Failed to fork child process (%s).\n",
					PERROR
				);
				break;

			case EXEC_EXIT_NPUSH:
				printer_fault (pps, prs, PUSH_FAULT, ep->Errno);
				break;

			default:
				if ((exited & EXEC_EXIT_NMASK) == EXEC_EXIT_NDIAL)
					dial_problem (
						pps,
						prs,
						exited & ~EXEC_EXIT_NMASK
					);

				else if (
					exited < -1
				     || exited > EXEC_EXIT_USER
				)
					note (
						"Bad exit from exec() for printer %s: %d\n",
						pps->printer->name,
						exited
					);

				break;
			}

			/*
			 * Being in the "dowait()" routine means the
			 * interface (and fast filter!) have stopped.
			 * If we have a fault and we're expected to try
			 * again later, make sure we try again later.
			 */
			if (
				(pps->status & PS_FAULTED)
			     && !STREQU(pps->printer->fault_rec, NAME_WAIT)
			     && !(pps->status & (PS_LATER|PS_DISABLED))
			) {
				load_str (&pps->dis_reason, CUZ_STOPPED);
				schedule (EV_LATER, WHEN_PRINTER, EV_ENABLE, pps);
			}

			prs->request->outcome &= ~(RS_PRINTING|RS_STOPPED);

			/*
			 * If the printer to which this request was
			 * assigned is not able to handle requests now,
			 * push waiting requests off on to another
			 * printer.
			 */
			if (prs->printer->status & (PS_FAULTED|PS_DISABLED|PS_LATER))
				(void)queue_repel (prs->printer, 0, (qchk_fnc_type)0);

			/*
			 * If the request is now assigned to a different
			 * printer, call "schedule()" to fire up an
			 * interface. If this request also happens to
			 * be dead, or in need of refiltering, it won't
			 * get scheduled.
			 */
			if (
				prs->printer != pps
			)
				schedule (EV_INTERF, prs->printer);

			check_request (prs);

			/*
			 * Attract the FIRST request that is waiting to
			 * print to this printer, unless the printer isn't
			 * ready to print another request. We do this
			 * even though requests may already be assigned
			 * to this printer, because a request NOT assigned
			 * might be ahead of them in the queue.
			 */
			if (!(pps->status & (PS_FAULTED|PS_DISABLED|PS_LATER)))
				queue_attract (pps, qchk_waiting, 1);

			break;

		case EX_SLOWF:
			prs = ep->ex.request;
			ep->ex.request = 0;
			prs->exec = 0;
			prs->request->outcome &= ~RS_FILTERING;

			/*
			 * If the slow filter was killed with SIGTERM,
			 * it may have been because we canceled the
			 * request, stopped the filtering, or put a
			 * change hold on the request. If so, clear
			 * the "killed" flag because that's not the
			 * condition of importance.
			 */
			canned = 0;
			if (killed == SIGTERM){
				if (prs->request->outcome & RS_CANCELLED)
					canned = 1;

				if (
					canned
				     || prs->request->outcome & RS_STOPPED
				     || Shutdown
				)
					killed = 0;
			}

			/*
			 * If there was standard error output from the
			 * slow filter, or if the interface program exited
			 * with a non-zero exit code, the user should
			 * be notified.
			 */
			errbuf = geterrbuf(prs);
			if (prs->request->outcome
			    & (RS_REFILTER | RS_STOPPED)) {
				if (errbuf) {
					Free(errbuf);
					errbuf = NULL;
				}
			}
			if (
				errbuf
			     || 0 < exited && exited <= EXEC_EXIT_USER
			     || killed
			) {
				prs->request->outcome |= RS_FAILED;
				prs->request->outcome |= RS_NOTIFY;
				notify (prs, errbuf, killed, exited, 1);
				if (errbuf)
					Free (errbuf);


			/*
			 * If the request was canceled, call "notify()"
			 * in case we're to notify the user.
			 */
			} else if (canned) {
				if (SHOULD_NOTIFY(prs))
					prs->request->outcome |= RS_NOTIFY;
				notify (prs, (char *)0, 0, 0, 1);

			/*
			 * If the slow filter exited normally, mark
			 * the request as finished slow filtering.
			 */
			} else if (exited == 0) {
				prs->request->outcome |= RS_FILTERED;

			} else if (exited == -1) {
				/*EMPTY*/;

			} else if (exited == EXEC_EXIT_NOPEN) {
				errno = ep->Errno;
				note (
					"Failed to open a print service file (%s).\n",
					PERROR
				);

			} else if (exited == EXEC_EXIT_NEXEC) {
				errno = ep->Errno;
				note (
					"Failed to exec child process (%s).\n",
					PERROR
				);

			} else if (exited == EXEC_EXIT_NOMEM) {
				mallocfail ();

			}

			prs->request->outcome &= ~RS_STOPPED;

			schedule (EV_INTERF, prs->printer);
			if (
				prs->request->outcome & RS_REFILTER
			)
				schedule (EV_SLOWF, prs);
			else
				schedule (EV_SLOWF, (RSTATUS *)0);

			check_request (prs);
			break;

		case EX_NOTIFY:
			prs = ep->ex.request;
			ep->ex.request = 0;
			prs->exec = 0;

			prs->request->outcome &= ~RS_NOTIFYING;
			    if (!Shutdown || !killed)
				prs->request->outcome &= ~RS_NOTIFY;

			/*
			 * Now that this notification process slot
			 * has opened up, schedule the next notification
			 * (if any).
			 */
			schedule (EV_NOTIFY, (RSTATUS *)0);

			check_request (prs);
			break;

		case EX_ALERT:
			pas = ep->ex.printer->alert;
			goto CleanUpAlert;

		case EX_FALERT:
			pas = ep->ex.form->alert;
			goto CleanUpAlert;

		case EX_PALERT:
			pas = ep->ex.pwheel->alert;
			/*
			 * CAUTION: It may well be that we've removed
			 * the print wheel by the time we get here.
			 * Only the alert structure (and exec structure)
			 * can be considered okay.
			 */

CleanUpAlert:
			if (Shutdown)
				break;

			if (ep->flags & EXF_RESTART) {
				ep->flags &= ~(EXF_RESTART);
				if (exec(ep->type, ep->ex.form) == 0) {
					pas->active = 1;
					break;
				}
			}
			(void)Unlink (pas->msgfile);
			break;

		}
	}

	return;
}


/**
 ** geterrbuf() - READ NON-BLANK STANDARD ERROR OUTPUT
 **/

static char *
geterrbuf(RSTATUS *prs)
{
	register char		*cp;
	int                     fd,
				n;
	char                    *buf    = 0,
				*file;
	struct stat             statbuf;

	if (!prs) return(NULL);

	file = makereqerr(prs);
	if (
		Stat(file, &statbuf) == 0
	     && statbuf.st_size
	     && (fd = Open(file, O_RDONLY)) != -1
	) {
		/*
		 * Don't die if we can't allocate space for this
		 * file--the file may be huge!
		 */
		lp_alloc_fail_handler = 0;
		if ((buf = Malloc(statbuf.st_size + 1)))
			if ((n = Read(fd, buf, statbuf.st_size)) > 0) {
				buf[n] = 0;
				
				/*
				 * NOTE: Ignore error output with no
				 * printable text. This hides problems we
				 * have with some shell scripts that
				 * occasionally cause spurious newlines
				 * when stopped via SIGTERM. Without this
				 * check for non-blank output, stopping
				 * a request sometimes causes a request
				 * failure.
				 */
				for (cp = buf; *cp && isspace(*cp); cp++)
					;
				if (!*cp) {
					Free (buf);
					buf = 0;
				}
			} else {
				Free (buf);
				buf = 0;
			}
		lp_alloc_fail_handler = mallocfail;
		Close(fd);
	}
	if (file)
		Free (file);

	return (buf);
}

/**
 ** check_request() - CLEAN UP AFTER REQUEST
 **/

void
check_request(RSTATUS *prs)
{
	/*
	 * If the request is done, decrement the count of requests
	 * needing the form or print wheel. Update the disk copy of
	 * the request. If we're finished with the request, get rid of it.
	 */
	if (prs->request->outcome & RS_DONE) {
		unqueue_form (prs);
		unqueue_pwheel (prs);
		putrequest (prs->req_file, prs->request);
		if (!(prs->request->outcome & (RS_ACTIVE | RS_NOTIFY))) {
			rmfiles (prs, 1);
			free_rstatus (prs);
		}
	}
	return;
}

/**
 ** check_children()
 **/

void
check_children(void)
{
	register int		i;
    
	for (i = 0; Exec_Table[i] != NULL; i++)
		if (Exec_Table[i]->pid > 0)
			break;

	if (Exec_Table[i] == NULL)
		Shutdown = 2;
}
