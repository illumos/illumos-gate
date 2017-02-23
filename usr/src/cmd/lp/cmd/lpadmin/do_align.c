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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <libintl.h>

#include "lp.h"
#include "msgs.h"
#include "printers.h"
#include "requests.h"
#include "form.h"

#define	WHO_AM_I	I_AM_LPADMIN
#include "oam.h"

#include "lpadmin.h"


extern void		mount_unmount();

extern short		printer_status;

extern char		*cur_pwheel,
			*disable_reason,
			*reject_reason;

extern FORM		formbuf;

static int		again();

static void		disable(),
			enable(),
			accept(),
			reject(),
			cancel(),
			sigpipe(),
			sigother();

static jmp_buf		cleanup_env,
			pipe_env;

/**
 ** do_align() - SET UP PRINTER TO PRINT ALIGNMENT PATTERNS
 **/

int			do_align (printer, form, pwheel)
	char			*printer,
				*form,
				*pwheel;
{
	short			status;

	char			*req_id		= 0,
				*file_prefix,
				*rfile,
				*fifo,
				buffer[MSGMAX];

	long			printer_chk;

	int			try;

	FILE			*align_fp,
				*fifo_fp;

	REQUEST			req;

	void			(*old_sighup)(),
				(*old_sigint)(),
				(*old_sigquit)(),
				(*old_sigterm)();


	/*
	 * Having reached this point means we've already fetched
	 * the form definition. Now get the alignment pattern.
	 */
	if (getform(form, (FORM *)0, (FALERT *)0, &align_fp) == -1) {
		LP_ERRMSG2 (ERROR, E_LP_GETFORM, form, PERROR);
		done (1);
	}
	if (!align_fp) {
		LP_ERRMSG1 (WARNING, E_ADM_NOALIGN, form);
		return (0);
	}

	/*
	 * Having reached this far also means we've already obtained
	 * the printer status from the Spooler. We'll be changing the
	 * status of the printer and queue and will have to restore
	 * the disable/reject reasons.
	 * NOTE: We can't restore the dates!
	 */


	/*
	 * Construct a request to print a ``file'' for copy. The
	 * equivalent "lp" command (with a filename) would be:
	 *
	 * lp -p printer -H immediate -f form -T type -S charset -c -P 1-N
	 *
	 * "type", "charset", and "N" are derived from the form def'n.
	 * This command would make us next to print ONCE THE FORM IS
	 * MOUNTED.
	 *
	 * NOTE: Don't bother with the -S charset if it isn't mandatory,
	 * so we won't get a rejection. Also, we use either the print
	 * wheel given in the -S option or, lacking that, the currently
	 * mounted print wheel. (The former WILL be mounted.) This also
	 * avoids a rejection by the Spooler.
	 */
	req.copies	= 1;
	req.destination	= printer;
/*	req.file_list	= 0;	This is done later. */
	req.form	= form;
	req.actions	= ACT_IMMEDIATE | ACT_FAST;
	req.alert	= 0;
	req.options	= "nobanner";
	req.priority	= 20;	/* it doesn't matter */
	sprintf ((req.pages = "1-999999")+2, "%d", formbuf.np);
	req.charset	= NAME_ANY;	/* Don't restrict the request */
	req.modes	= 0;
	req.title	= "Aligning Form";
	req.input_type	= formbuf.conttype;
	req.user	= getname();


	/*
	 * The following code is sensitive to interrupts: We must
	 * catch interrupts so to restore the printer to its original
	 * state, but if we get interrupted while receiving a message
	 * from the Spooler, we can't issue additional messages because
	 * the old responses still in the response queue will confuse us.
	 * Thus while sending/receiving a message we ignore signals.
	 */
	if (setjmp(cleanup_env) != 0)
		done (1);
	trap_signals (); /* make sure we've done this once */
	old_sighup = signal(SIGHUP, sigother);
	old_sigint = signal(SIGINT, sigother);
	old_sigquit = signal(SIGQUIT, sigother);
	old_sigterm = signal(SIGTERM, sigother);

	/*
	 * We'll try the following twice, first with the page list
	 * set as above. If the request gets refused because there's
	 * no filter to convert the content, we'll try again without
	 * the page list. I don't think the number-of-pages-in-a-form
	 * feature is likely to be used much, so why hassle the
	 * administrator?
#if	defined(WARN_OF_TOO_MANY_LINES)
	 * However, do warn them.
#endif
	 */

	try = 0;
Again:	try++;

	/*
	 * Have the Spooler allocate a request file and another file
	 * for our use. We'll delete the other file and recreate it
	 * as a FIFO. We can do this because "lpadmin" can only be run
	 * (successfully) by an administrator. This is the key to what
	 * we're doing! We are submitting a named pipe (FIFO) for
	 * printing, which gives us a connection to the printer
	 * through any filters needed!
	 */

	BEGIN_CRITICAL
		send_message (S_ALLOC_FILES, 2);
		if (mrecv(buffer, MSGMAX) != R_ALLOC_FILES) {
			LP_ERRMSG (ERROR, E_LP_MRECV);
			done (1);
		}
	END_CRITICAL
	(void)getmessage (buffer, R_ALLOC_FILES, &status, &file_prefix);

	switch (status) {
	case MOK:
		break;

	case MNOMEM:
		LP_ERRMSG (ERROR, E_LP_MNOMEM);
		done (1);
	}

	if (!(rfile = malloc((unsigned int)strlen(file_prefix) + 2 + 1))) {
		LP_ERRMSG (ERROR, E_LP_MALLOC);
		done (1);
	}

	sprintf (rfile, "%s-1", file_prefix);

	if (!(fifo = makepath(Lp_Temp, rfile, (char *)0))) {
		LP_ERRMSG (ERROR, E_LP_MALLOC);
		done (1);
	}
	req.file_list = 0;
	addlist (&req.file_list, fifo);

	if (
		Unlink(fifo) == -1
	     || Mknod(fifo, S_IFIFO | 0600, 0) == -1
	) {
		LP_ERRMSG1 (ERROR, E_ADM_NFIFO, PERROR);
		done (1);
	}

	/*
	 * In quick succession,
	 *
	 *	- mount the form,
	 *	- disable the printer,
	 *	- make the Spooler accept requests (if need be),
	 *	- submit the request,
	 *	- make the Spooler reject requests (if need be).
	 *
	 * We want to minimize the window when another request can
	 * be submitted ahead of ours. Though this window is small,
	 * it is a flaw in our design. Disabling the printer will
	 * help, because it will stop any request that is printing
	 * (if the form is already mounted) and will prevent any other
	 * request from printing. (We disable the printer AFTER trying
	 * to mount the form, because we don't disable a printer for a
	 * regular mount, and we'd like to make this mount APPEAR to
	 * be as similar as possible.)
	 */

	if (try == 1) {

		mount_unmount (S_MOUNT, printer, NB(form), NB(pwheel));
		/* This will die if the mount fails, leaving */
		/* the Spooler to clean up our files.        */

		if (!(printer_status & PS_DISABLED))
			disable (printer, CUZ_MOUNTING, 0);

		if (printer_status & PS_REJECTED)
			accept (printer);

		if (setjmp(cleanup_env) != 0) {
			if (printer_status & PS_DISABLED)
				disable (printer, disable_reason, 1);
			if (printer_status & PS_REJECTED)
				reject (printer, reject_reason);
			if (req_id && *req_id)
				cancel (req_id);
			done (1);
		}
	}

	sprintf (rfile, "%s-0", file_prefix);
	if (putrequest(rfile, &req) == -1) {
		LP_ERRMSG1 (ERROR, E_LP_PUTREQUEST, PERROR);
		goto Done;
	}
	BEGIN_CRITICAL
		send_message (S_PRINT_REQUEST, rfile);
		if (mrecv(buffer, MSGMAX) != R_PRINT_REQUEST) {
			LP_ERRMSG (ERROR, E_LP_MRECV);
			done (1);
		}
	END_CRITICAL
	(void)getmessage (buffer, R_PRINT_REQUEST, &status, &req_id, &printer_chk);

	switch (status) {

	case MNOFILTER:
		if (try == 1) {
			req.pages = 0;
			goto Again;
		}
		LP_ERRMSG (ERROR, E_ADM_NFILTER);
		goto Done;

	case MOK:
#if	defined(WARN_OF_TOO_MANY_LINES)
		if (!req.pages)
			LP_ERRMSG1 (WARNING, E_ADM_NPAGES, formbuf.np);
#endif
		break;

	case MERRDEST:
		accept (printer); /* someone snuck a reject in! */
		goto Again;

	case MNOMEM:
		LP_ERRMSG (ERROR, E_LP_MNOMEM);
		goto Done;

	case MNODEST:
		LP_ERRMSG1 (ERROR, E_LP_PGONE, printer);
		goto Done;

	case MNOOPEN:	/* not quite, but close */
		LP_ERRMSG (ERROR, E_ADM_ERRDEST);
		goto Done;

	case MDENYDEST:
		if (printer_chk) {
			char			reason[1024],
						*cp	= reason;

			if (printer_chk & PCK_TYPE)
				cp += sprintf(cp, "printer type, ");
			if (printer_chk & PCK_CHARSET)
				cp += sprintf(cp, "character set, ");
			if (printer_chk & PCK_CPI)
				cp += sprintf(cp, "character pitch, ");
			if (printer_chk & PCK_LPI)
				cp += sprintf(cp, "line pitch, ");
			if (printer_chk & PCK_WIDTH)
				cp += sprintf(cp, "page width, ");
			if (printer_chk & PCK_LENGTH)
				cp += sprintf(cp, "page length, ");
			if (printer_chk & PCK_BANNER)
				cp += sprintf(cp, "nobanner, ");
			cp[-2] = 0;
			LP_ERRMSG1 (ERROR, E_LP_PTRCHK, reason);
			goto Done;
		}
		/*fall through*/

	case MUNKNOWN:
	case MNOMEDIA:
	case MDENYMEDIA:
	case MNOMOUNT:
	case MNOSPACE:
	case MNOPERM:
		LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, status);

Done:		if (!(printer_status & PS_DISABLED))
			enable (printer);
		if (printer_status & PS_REJECTED)
			reject (printer, reject_reason);
		done (1);
		/*NOTREACHED*/
	}

	if (printer_status & PS_REJECTED)
		reject (printer, reject_reason);

	/*
	 * Enable printing, to start the interface program going.
	 * Because of our precautions above, our request SHOULD be
	 * the one that prints!
 	 */
	enable (printer);

	/*
	 * Open the FIFO. One problem: This will hang until the
	 * interface program opens the other end!!
	 */
	if (!(fifo_fp = fopen(fifo, "w"))) {
		LP_ERRMSG1 (ERROR, E_ADM_NFIFO, PERROR);
		done (1);
	}

	/*
	 * Loop, dumping the ENTIRE alignment pattern to the FIFO
	 * each time. SIGPIPE probably means the printer faulted.
	 */
	if (setjmp(pipe_env) == 0) {
		/*
		 * Don't send a form feed after the last copy, since
		 * the interface program does that. To implement this,
		 * we send the form feed BEFORE the alignment pattern;
		 * this way we can simply not send it the first time.
		 */
		char *			ff		= 0;
		char *			ff_before	= 0;

		/*
		 * If we'll be inserting page breaks between alignment
		 * patterns, look up the control sequence for this.
		 *
		 * MORE: We currently don't have the smarts to figure out
		 * WHICH printer type the Spooler will pick; we would need
		 * to steal some of its code for that (see pickfilter.c)
		 * The best we do so far is use the alignment pattern's
		 * content type, if known.
		 */
		if (filebreak) {
			if (
				formbuf.conttype
			     && searchlist_with_terminfo(
					formbuf.conttype,
					T  /* having "filebreak" => OK */
				)
			)
				tidbit (formbuf.conttype, "ff", &ff);
			else
				tidbit (*T, "ff", &ff);
		}

		signal (SIGPIPE, sigpipe);
		do {
			register int		n;
			char			buf[BUFSIZ];

			if (ff_before && *ff_before)
				fputs (ff_before, fifo_fp);
			ff_before = ff;

			rewind (align_fp);
			while ((n = fread(buf, 1, BUFSIZ, align_fp)) > 0)
				fwrite (buf, 1, n, fifo_fp);

			fflush (fifo_fp);

		} while (again());
		fclose (align_fp);
		signal (SIGPIPE, SIG_DFL);

	} else {
		cancel (req_id);

#define P(X)	printf (X)

P("We were interrupted while printing the alignment pattern;\n");
P("check the printer. The form is mounted, so you will have to\n");
P("unmount it if you need to print more alignment patterns later.\n");
	}

	/*
	 * Disable the printer, if needed, and close the FIFO.
	 * Use the wait version of the disable, so our request isn't
	 * stopped, and do it before closing the FIFO, so another request
	 * can't start printing if it isn't supposed to.
	 */
	if (printer_status & PS_DISABLED)
		disable (printer, disable_reason, 1);
	fclose (fifo_fp);

	signal (SIGHUP, old_sighup);
	signal (SIGINT, old_sigint);
	signal (SIGQUIT, old_sigquit);
	signal (SIGTERM, old_sigterm);

	return (1);
}

/**
 ** accept() - MAKE PRINTER ACCEPT REQUESTS
 **/

static void		accept (printer)
	char			*printer;
{
	int			rc;

	BEGIN_CRITICAL
		send_message (S_ACCEPT_DEST, printer);
		rc = output(R_ACCEPT_DEST);
	END_CRITICAL

	switch (rc) {
	case MOK:
	case MERRDEST:	/* someone may have snuck in an accept */
		break;

	case MNODEST:	/* make up your mind, Spooler! */
	case MNOPERM:	/* taken care of up front */
	default:
		LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, rc);
		done (1);
	}
	return;
}

/**
 ** reject() - MAKE PRINTER REJECT REQUESTS
 **/

static void		reject (printer, reason)
	char			*printer,
				*reason;
{
	int			rc;

	BEGIN_CRITICAL
		send_message (S_REJECT_DEST, printer, reason);
		rc = output(R_REJECT_DEST);
	END_CRITICAL

	switch (rc) {

	case MOK:
	case MERRDEST:	/* someone may have snuck in a reject */
		break;

	case MNODEST:	/* make up your mind, Spooler! */
	case MNOPERM:	/* taken care of up front */
	default:
		LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, rc);
		done (1);
	}
	return;
}

/**
 ** enable() - ENABLE THE PRINTER
 **/

static void		enable (printer)
	char			*printer;
{
	int			rc;

	BEGIN_CRITICAL
		send_message (S_ENABLE_DEST, printer);
		rc = output(R_ENABLE_DEST);
	END_CRITICAL

	switch (rc) {
	case MOK:
	case MERRDEST:	/* someone may have snuck in an enable */
		break;

	case MNODEST:	/* make up your mind, Spooler! */
	case MNOPERM:	/* taken care of up front */
	default:
		LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, rc);
		done (1);
	}
	return;
}

/**
 ** disable() - DISABLE THE PRINTER
 **/

static void		disable (printer, reason, when)
	char			*printer,
				*reason;
	int			when;
{
	int			rc;

	BEGIN_CRITICAL
		send_message (S_DISABLE_DEST, printer, reason, when);
		rc = output(R_DISABLE_DEST);
	END_CRITICAL

	switch (rc) {
	case MOK:
	case MERRDEST:	/* someone may have snuck in a disable */
		break;

	case MNODEST:	/* make up your mind, Spooler! */
	case MNOPERM:	/* taken care of up front */
	default:
		LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, rc);
		done (1);
	}
	return;
}

/**
 ** cancel() - MAKE PRINTER ACCEPT REQUESTS
 **/

static void		cancel (req_id)
	char			*req_id;
{
	int			rc;

	BEGIN_CRITICAL
		send_message (S_CANCEL_REQUEST, req_id);
		rc = output(R_CANCEL_REQUEST);
	END_CRITICAL

	switch (rc) {
	case MOK:
	case MUNKNOWN:
	case M2LATE:
		break;

	case MNOPERM:
	default:
		LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, rc);
		done (1);
	}
	return;
}

/**
 ** again()
 **/

static int		again ()
{
	char			answer[BUFSIZ];


	for (;;) {

		printf (
		gettext("Press return to print an alignment pattern [q to quit]: ")
		);

		if (!fgets(answer, sizeof (answer), stdin))
			return (0);

		answer[strlen(answer) -1] = '\0';

		if (
		        STREQU(answer, "q")
		     || STREQU(answer, "n")
		     || STREQU(answer, "no")
		)
			return (0);

		else if (
			!*answer
		     || STREQU(answer, "y")
		     || STREQU(answer, "yes")
		)
			return (1);

		printf (gettext("Sorry?\n"));
	}
}

/**
 ** sigpipe()
 ** sigother()
 **/

static void		sigpipe ()
{
	signal (SIGPIPE, SIG_IGN);
	longjmp (pipe_env, 1);
	/*NOTREACHED*/
}

static void		sigother (sig)
	int			sig;
{
	signal (sig, SIG_IGN);
	longjmp (cleanup_env, 1);
	/*NOTREACHED*/
}
