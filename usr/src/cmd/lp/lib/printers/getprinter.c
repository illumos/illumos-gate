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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "stdio.h"
#include "string.h"
#include "errno.h"
#include "sys/types.h"
#include "stdlib.h"

#include "lp.h"
#include "printers.h"

extern struct {
	char			*v;
	short			len,
				okremote;
}			prtrheadings[];

/**
 ** getprinter() - EXTRACT PRINTER STRUCTURE FROM DISK FILE
 **/

PRINTER *
getprinter(char *name)
{
	static long		lastdir		= -1;

	static PRINTER		prbuf;

	char			buf[BUFSIZ];

	short			daisy;

	int			fld;

	int fd;

	FALERT			*pa;

	register char *		p;
	register char **	pp;
	register char ***	ppp;
	register char *		path;
	int			isNameAll;



	if (!name || !*name) {
		errno = EINVAL;
		return (0);
	}

	/*
	 * Getting ``all''? If so, jump into the directory
	 * wherever we left off.
	 */
	isNameAll = STREQU(NAME_ALL, name);
	for (; ; ) {  
		/* fix for bug 1117241 
		 * occasionally when a printer is removed, a printer directory
		 * is left behind, but the CONFIGFILE is removed.  In this
		 * case this directory terminates the search for additional
		 * printers as we have been returning 0 in this case.
		 * Now, we loop back and try the next directory until
		 * we have no more directories or we find a directory with
		 * a CONFIGFILE 
		 */
		if (isNameAll) {
			if (!(name = next_dir(Lp_A_Printers, &lastdir)))
				return (0);
		} else
			lastdir = -1;

		/*
		 * Get the printer configuration information.
		 */

		path = getprinterfile(name, CONFIGFILE);
		if (!path) {
			if (isNameAll)
				Free(name);
			return (0);
		}

		if ((fd = open_locked(path, "r", 0)) < 0) {
			Free(path);	/*
					 * go around to loop again for
					 * NAME_ALL case
					 */

			if (!isNameAll) /* fix for bug 1117241 */
				return(0);
			else
				Free(name);
		}
		else
			break;
	}
	Free (path);

	/*
	 * Initialize the entire structure, to ensure no random
	 * values get in it. However, make sure some values won't
	 * be null or empty. Do the latter here as opposed to
	 * after reading the file, because sometimes the file
	 * contains an empty header to FORCE a null/empty value.
	 */
	(void)memset ((char *)&prbuf, 0, sizeof(prbuf));
	prbuf.name = Strdup(name);
	if (isNameAll)
		Free(name);
	prbuf.printer_types = getlist(NAME_UNKNOWN, LP_WS, LP_SEP);
	prbuf.input_types = getlist(NAME_SIMPLE, LP_WS, LP_SEP);
#if	defined(CAN_DO_MODULES)
	prbuf.modules = getlist(NAME_DEFAULT, LP_WS, LP_SEP);
#endif

	/*
	 * Read the file.
	 */
	errno = 0;
	while (fdgets(buf, BUFSIZ, fd) != NULL) {

		buf[strlen(buf) - 1] = 0;

		for (fld = 0; fld < PR_MAX; fld++)
			if (
				prtrheadings[fld].v
			     && prtrheadings[fld].len
			     && STRNEQU(
					buf,
					prtrheadings[fld].v,
					prtrheadings[fld].len
				)
			) {
				p = buf + prtrheadings[fld].len;
				while (*p && *p == ' ')
					p++;
				break;
			}

		/*
		 * To allow future extensions to not impact applications
		 * using old versions of this routine, ignore strange
		 * fields.
		 */
		if (fld >= PR_MAX) 
			continue;

		switch (fld) {

		case PR_BAN:
			if ((pp = getlist(p, LP_WS, ":"))) {
				if (pp[0] != NULL) {
					if (strcmp(pp[0], NAME_OPTIONAL) == 0)
						prbuf.banner = BAN_OPTIONAL;
					else if (strcmp(pp[0], NAME_OFF) == 0)
						prbuf.banner = BAN_NEVER;
					else if (strcmp(pp[0], NAME_ON) == 0)
						prbuf.banner = BAN_ALWAYS;
					else /* default to the LP default */
						prbuf.banner = BAN_ALWAYS;
				}
				if (pp[1] && CS_STREQU(pp[1], NAME_ALWAYS))
					prbuf.banner |= BAN_ALWAYS;
				freelist (pp);
			}
			break;

		case PR_LOGIN:
			prbuf.login = LOG_IN;
			break;

		case PR_CPI:
			prbuf.cpi = getcpi(p);
			break;

		case PR_LPI:
			prbuf.lpi = getsdn(p);
			break;

		case PR_LEN:
			prbuf.plen = getsdn(p);
			break;

		case PR_WIDTH:
			prbuf.pwid = getsdn(p);
			break;

		case PR_CS:
			ppp = &(prbuf.char_sets);
			goto CharStarStar;

		case PR_ITYPES:
			ppp = &(prbuf.input_types);
CharStarStar:		if (*ppp)
				freelist (*ppp);
			*ppp = getlist(p, LP_WS, LP_SEP);
			break;

		case PR_DEV:
			pp = &(prbuf.device);
			goto CharStar;

		case PR_DIAL:
			pp = &(prbuf.dial_info);
			goto CharStar;

		case PR_RECOV:
			pp = &(prbuf.fault_rec);
			goto CharStar;

		case PR_INTFC:
			pp = &(prbuf.interface);
			goto CharStar;

		case PR_PTYPE:
			ppp = &(prbuf.printer_types);
			goto CharStarStar;

		case PR_REMOTE:
			pp = &(prbuf.remote);
			goto CharStar;

		case PR_SPEED:
			pp = &(prbuf.speed);
			goto CharStar;

		case PR_STTY:
			pp = &(prbuf.stty);
CharStar:		if (*pp)
				Free (*pp);
			*pp = Strdup(p);
			break;

#if	defined(CAN_DO_MODULES)
		case PR_MODULES:
			ppp = &(prbuf.modules);
			goto CharStarStar;
#endif

		case PR_OPTIONS:
			ppp = &(prbuf.options);
			goto CharStarStar;
			break;

		case PR_PPD:
		{
			pp = &(prbuf.ppd);
			goto CharStar;
		}
		}

	}
	if (errno != 0) {
		int			save_errno = errno;

		freeprinter (&prbuf);
		close(fd);
		errno = save_errno;
		return (0);
	}
	close(fd);

	/*
	 * Get the printer description (if it exists).
	 */
	if (!(path = getprinterfile(prbuf.name, COMMENTFILE)))
		return (0);
	if (!(prbuf.description = loadstring(path)) && errno != ENOENT) {
		Free (path);
		freeprinter (&prbuf);
		return (0);
	}
	Free (path);

	/*
	 * Get the information for the alert. Don't fail if we can't
	 * read it because of access permission UNLESS we're "root"
	 * or "lp"
	 */
	if (!(pa = getalert(Lp_A_Printers, prbuf.name))) {
		if (
			errno != ENOENT
		     && (
				errno != EACCES
			     || !getpid()		  /* we be root */
			     || STREQU(getname(), LPUSER) /* we be lp   */
			)
		) {
			freeprinter (&prbuf);
			return (0);
		}
	} else
		prbuf.fault_alert = *pa;

	/*
	 * Now go through the structure and see if we have
	 * anything strange.
	 */
	if (!okprinter(prbuf.name, &prbuf, 0)) {
		freeprinter (&prbuf);
		errno = EBADF;
		return (0);
	}

	/*
	 * Just in case somebody tried to pull a fast one
	 * by giving a printer type header by itself....
	 */
	if (!prbuf.printer_types)
		prbuf.printer_types = getlist(NAME_UNKNOWN, LP_WS, LP_SEP);

	/*
	 * If there are more than one printer type, then we can't
	 * have any input types, except perhaps ``simple''.
	 */
	if (
		lenlist(prbuf.printer_types) > 1
	     && prbuf.input_types
	     && (
			lenlist(prbuf.input_types) > 1
		     || !STREQU(NAME_SIMPLE, *prbuf.input_types)
		)
	) {
		freeprinter (&prbuf);
		badprinter = BAD_ITYPES;
		errno = EBADF;
		return (0);
	}

	/*
	 * If there are more than one printer types, none can
	 * be ``unknown''.
	 */
	if (
		lenlist(prbuf.printer_types) > 1
	     && searchlist(NAME_UNKNOWN, prbuf.printer_types)
	) {
		freeprinter (&prbuf);
		badprinter = BAD_PTYPES;
		errno = EBADF;
		return (0);
	}

	/*
	 * All the printer types had better agree on whether the
	 * printer takes print wheels!
	 */
	prbuf.daisy = -1;
	for (pp = prbuf.printer_types; *pp; pp++) {
		tidbit (*pp, "daisy", &daisy);
		if (daisy == -1)
			daisy = 0;
		if (prbuf.daisy == -1)
			prbuf.daisy = daisy;
		else if (prbuf.daisy != daisy) {
			freeprinter (&prbuf);
			badprinter = BAD_DAISY;
			errno = EBADF;
			return (0);
		}
	}

	/*
	 * Help out those who are still using the obsolete
	 * "printer_type" member.
	 */
	prbuf.printer_type = Strdup(*prbuf.printer_types);

	return (&prbuf);
}
