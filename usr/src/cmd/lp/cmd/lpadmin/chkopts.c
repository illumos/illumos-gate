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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "stdio.h"
#include "string.h"
#include "pwd.h"
#include "sys/types.h"
#include "errno.h"

#include "lp.h"
#include "printers.h"
#include "form.h"
#include "class.h"

#define	WHO_AM_I	I_AM_LPADMIN
#include "oam.h"

#include "lpadmin.h"

#define PPDZIP	".gz"


extern PRINTER		*printer_pointer;

extern PWHEEL		*pwheel_pointer;

extern struct passwd	*getpwnam();

void			chkopts2(),
			chkopts3();
static void		chksys();

FORM			formbuf;

char			**f_allow,
			**f_deny,
			**u_allow,
			**u_deny,
			**p_add,
			**p_remove;

PRINTER			*oldp		= 0;

PWHEEL			*oldS		= 0;

short			daisy		= 0;

static int		root_can_write();

static char		*unpack_sdn();

static char **		bad_list;

#if	defined(__STDC__)
static unsigned long	sum_chkprinter ( char ** , char * , char * , char * , char * , char * );
static int isPPD(char *ppd_file);
#else
static unsigned long	sum_chkprinter();
static int isPPD();
#endif

/**
 ** chkopts() -- CHECK LEGALITY OF COMMAND LINE OPTIONS
 **/

void			chkopts ()
{
	short		isfAuto = 0;

	/*
	 * Check -d.
	 */
	if (d) {
		if (
			a || c || f || P || j || m || M || t || p || r || u || x
#if	defined(DIRECT_ACCESS)
		     || C
#endif
#ifdef LP_USE_PAPI_ATTR
		     || n_opt
#endif
		     || strlen(modifications)
		) {
			LP_ERRMSG (ERROR, E_ADM_DALONE);
			done (1);
		}

		if (
			*d
		     && !STREQU(d, NAME_NONE)
		     && !isprinter(d)
		     && !isclass(d)
		) {
			LP_ERRMSG1 (ERROR, E_ADM_NODEST, d);
			done (1);
		}
		return;
	}

	/*
	 * Check -x.
	 */
	if (x) {
		if (	/* MR bl88-02718 */
			A || a || c || f || P || j || m || M || t || p || r || u || d
#if	defined(DIRECT_ACCESS)
		     || C
#endif
#ifdef LP_USE_PAPI_ATTR
		     || n_opt
#endif
		     || strlen(modifications)
		) {
			LP_ERRMSG (ERROR, E_ADM_XALONE);
			done (1);
		}

		if (
			!STREQU(NAME_ALL, x)
		     && !STREQU(NAME_ANY, x)
		     && !isprinter(x)
		     && !isclass(x)
		) {
			LP_ERRMSG1 (ERROR, E_ADM_NODEST, x);
			done (1);
		}
		return;
	}

	/*
	 * Problems common to both -p and -S (-S alone).
	 */
	if (A && STREQU(A, NAME_LIST) && (W != -1 || Q != -1)) {
		LP_ERRMSG (ERROR, E_ADM_LISTWQ);
		done (1);
	}


	/*
	 * Check -S.
	 */
	if (!p && S) {
		if (
			M || t || a || f || P || c || r || e || i || m || H || h
		     || l || v || I || T || D || F || u || U || j || o
#ifdef LP_USE_PAPI_ATTR
		     || n_opt
#endif
		) {
			LP_ERRMSG (ERROR, E_ADM_SALONE);
			done (1);
		}
		if (!A && W == -1 && Q == -1) {
			LP_ERRMSG (ERROR, E_ADM_NOAWQ);
			done (1);
		}
		if (S[0] && S[1])
			LP_ERRMSG (WARNING, E_ADM_ASINGLES);
		if (!STREQU(NAME_ALL, *S) && !STREQU(NAME_ANY, *S)) 
			chkopts3(1);
		return;
	}

	/*
	 * At this point we must have a printer (-p option).
	 */
	if (!p) {
		LP_ERRMSG (ERROR, E_ADM_NOACT);
		done (1);
	}
	if (STREQU(NAME_NONE, p)) {
		LP_ERRMSG1 (ERROR, E_LP_NULLARG, "p");
		done (1);
	}


	/*
	 * Mount but nothing to mount?
	 */
	if (M && (!f && !S)) {
		LP_ERRMSG (ERROR, E_ADM_MNTNONE);
		done (1);
	}

	/*
	 * -Q isn't allowed with -p.
	 */
	if (Q != -1) {
		LP_ERRMSG (ERROR, E_ADM_PNOQ);
		done (1);
	}

	/*
	 * Fault recovery.
	 */
	if (
		F
	     && !STREQU(F, NAME_WAIT)
	     && !STREQU(F, NAME_BEGINNING)
	     && (
			!STREQU(F, NAME_CONTINUE)
		     || j
		     && STREQU(F, NAME_CONTINUE)
		)
	) {
#if	defined(J_OPTION)
		if (j)
			LP_ERRMSG (ERROR, E_ADM_FBADJ);
		else
#endif
			LP_ERRMSG (ERROR, E_ADM_FBAD);
		done (1);
	}

#if	defined(J_OPTION)
	/*
	 * The -j option is used only with the -F option.
	 */
 	if (j) {
		if (M || t || a || f || P || c || r || e || i || m || H || h ||
#ifdef LP_USE_PAPI_ATTR
		    n_opt ||
#endif
		    l || v || I || T || D || u || U || o) {
			LP_ERRMSG (ERROR, E_ADM_JALONE);
			done (1);
		}
		if (j && !F) {
			LP_ERRMSG (ERROR, E_ADM_JNOF);
			done (1);
		}
		return;
	}
#endif

#if	defined(DIRECT_ACCESS)
	/*
	 * -C is only used to modify -u
	 */
	if (C && !u) {
		LP_ERRMSG (ERROR, E_ADM_CNOU);
		done (1);
	}
#endif

	/*
	 * The -a option needs the -M and -f options,
	 * Also, -ofilebreak is used only with -a.
	 */
	if (a && (!M || !f)) {
		LP_ERRMSG (ERROR, E_ADM_MALIGN);
		done (1);
	}
	if (filebreak && !a)
		LP_ERRMSG (WARNING, E_ADM_FILEBREAK);

	/*
	 * The "-p all" case is restricted to certain options.
	 */
	if (
		(STREQU(NAME_ANY, p) || STREQU(NAME_ALL, p))
	     && (
			a || h || l || M || t || D || e || f || P || H || s
#ifdef LP_USE_PAPI_ATTR
		      || n_opt
#endif
		     || i || I || m || S || T || u || U || v || banner != -1
		     || cpi || lpi || width || length || stty_opt
		)
	) {
		LP_ERRMSG (ERROR, E_ADM_ANYALLNONE);
		done (1);

	} 

	/*
	 * Allow giving -v or -U option as way of making
	 * remote printer into local printer.
	 * Note: "!s" here means the user has not given the -s;
	 * later it means the user gave -s local-system.
	 */
	if (!s && (v || U))
		s = Local_System;

	/*
	 * Be careful about checking "s" before getting here.
	 * We want "s == 0" to mean this is a local printer; however,
	 * if the user wants to change a remote printer to a local
	 * printer, we have to have "s == Local_System" long enough
	 * to get into "chkopts2()" where a special check is made.
	 * After "chkopts2()", "s == 0" means local.
	 */
	if (!STREQU(NAME_ALL, p) && !STREQU(NAME_ANY, p)) 
		/*
		 * If old printer, make sure it exists. If new printer,
		 * check that the name is okay, and that enough is given.
		 * (This stuff has been moved to "chkopts2()".)
		 */
		chkopts2(1);

	if (!s) {

		/*
		 * Only one of -i, -m, -e.
		 */
		if ((i && e) || (m && e) || (i && m)) {
			LP_ERRMSG (ERROR, E_ADM_INTCONF);
			done (1);
		}

		/*
		 * Check -e arg.
		 */
		if (e) {
			if (!isprinter(e)) {
				LP_ERRMSG1 (ERROR, E_ADM_NOPR, e);
				done (1);
			}
			if (strcmp(e, p) == 0) {
				LP_ERRMSG (ERROR, E_ADM_SAMEPE);
				done (1);
			}
		}

		/*
		 * Check -m arg.
		 */
		if (m && !ismodel(m)) {
			LP_ERRMSG1 (ERROR, E_ADM_NOMODEL, m);
			done (1);
		}

#ifdef LP_USE_PAPI_ATTR
		/*
		 * Check -n arg. The ppd file exists.
		 */
		if ((n_opt != NULL) && !isPPD(n_opt)) {
			LP_ERRMSG1 (ERROR, E_ADM_NOPPD, n_opt);
			done (1);
		}
#endif

		/*
		 * Need exactly one of -h or -l (but will default -h).
		 */
		if (h && l) {
			LP_ERRMSG2 (ERROR, E_ADM_CONFLICT, 'h', 'l');
			done (1);
		}
		if (!h && !l)
			h = 1;

		/*
		 * Check -c and -r.
		 */
		if (c && r && strcmp(c, r) == 0) {
			LP_ERRMSG (ERROR, E_ADM_SAMECR);
			done (1);
		}


		/*
		 * Are we creating a class with the same name as a printer?
		 */
		if (c) {
			if (STREQU(c, p)) {
				LP_ERRMSG1 (ERROR, E_ADM_CLNPR, c);
				done (1);
			}
			if (isprinter(c)) {
				LP_ERRMSG1 (ERROR, E_ADM_CLPR, c);
				done (1);
			}
		}

		if (v && (is_printer_uri(v) < 0)) {
			/*
			 * The device must be writeable by root.
			 */
			if (v && root_can_write(v) == -1)
				done (1);
		}

		/*
		 * Can't have both device and dial-out.
		 */
		if (v && U) {
			LP_ERRMSG (ERROR, E_ADM_BOTHUV);
			done (1);
		}

	} else
		if (
			A || a || e || H || h || i || l || m || ( t && !M) || ( M && !t) 
		     || o || U || v || Q != -1 || W != -1
#ifdef LP_USE_PAPI_ATTR
		     || n_opt
#endif
		) {
			LP_ERRMSG (ERROR, E_ADM_NOTLOCAL);
			done(1);
		}


	/*
	 * We need the printer type for some things, and the boolean
	 * "daisy" (from Terminfo) for other things.
	 */
	if (!T && oldp)
		T = oldp->printer_types;
	if (T) {
		short			a_daisy;

		char **			pt;


		if (lenlist(T) > 1 && searchlist(NAME_UNKNOWN, T)) {
			LP_ERRMSG (ERROR, E_ADM_MUNKNOWN);
			done (1);
		}

		for (pt = T; *pt; pt++)
			if (tidbit(*pt, (char *)0) == -1) {
				LP_ERRMSG1 (ERROR, E_ADM_BADTYPE, *pt);
				done (1);
			}

		/*
		 * All the printer types had better agree on whether the
		 * printer takes print wheels!
		 */
		daisy = a_daisy = -1;
		for (pt = T; *pt; pt++) {
			tidbit (*pt, "daisy", &daisy);
			if (daisy == -1)
				daisy = 0;
			if (a_daisy == -1)
				a_daisy = daisy;
			else if (a_daisy != daisy) {
				LP_ERRMSG (ERROR, E_ADM_MIXEDTYPES);
				done (1);
			}
		}
	}
	if (cpi || lpi || length || width || S || f || filebreak)
		if (!T) {
			LP_ERRMSG (ERROR, E_ADM_TOPT);
			done (1);

		}

	/*
	 * Check -o cpi=, -o lpi=, -o length=, -o width=
	 */
	if (cpi || lpi || length || width) {
		unsigned	long	rc;

		if ((rc = sum_chkprinter(T, cpi, lpi, length, width, NULL)) == 0) {
			if (bad_list)
				LP_ERRMSG1 (
					INFO,
					E_ADM_NBADCAPS,
					sprintlist(bad_list)
				);

		} else {
			if ((rc & PCK_CPI) && cpi)
				LP_ERRMSG1 (ERROR, E_ADM_BADCAP, "cpi=");

			if ((rc & PCK_LPI) && lpi)
				LP_ERRMSG1 (ERROR, E_ADM_BADCAP, "lpi=");

			if ((rc & PCK_WIDTH) && width)
				LP_ERRMSG1 (ERROR, E_ADM_BADCAP, "width=");

			if ((rc & PCK_LENGTH) && length)
				LP_ERRMSG1 (ERROR, E_ADM_BADCAP, "length=");

			LP_ERRMSG (ERROR, E_ADM_BADCAPS);
			done(1);
		}
	}

	/*
	 * Check -I (old or new):
	 */
	if (T && lenlist(T) > 1) {

#define BADILIST(X) (lenlist(X) > 1 || X && *X && !STREQU(NAME_SIMPLE, *X))
		if (
			I && BADILIST(I)
		     || !I && oldp && BADILIST(oldp->input_types)
		) {
			LP_ERRMSG (ERROR, E_ADM_ONLYSIMPLE);
			done (1);
		}
	}

	/*
	 * MOUNT:
	 * Only one print wheel can be mounted at a time.
	 */
	if (M && S && S[0] && S[1])
		LP_ERRMSG (WARNING, E_ADM_MSINGLES);

	/*
	 * NO MOUNT:
	 * If the printer takes print wheels, the -S argument
	 * should be a simple list; otherwise, it must be a
	 * mapping list. (EXCEPT: In either case, "none" alone
	 * means delete the existing list.)
	 */
	if (S && !M) {
		register char		**item,
					*cp;

		/*
		 * For us to be here, "daisy" must have been set.
		 * (-S requires knowing printer type (T), and knowing
		 * T caused call to "tidbit()" to set "daisy").
		 */
		if (!STREQU(S[0], NAME_NONE) || S[1])
		    if (daisy) {
			for (item = S; *item; item++) {
				if (strchr(*item, '=')) {
					LP_ERRMSG (ERROR, E_ADM_PWHEELS);
					done (1);
				}
				if (!syn_name(*item)) {
					LP_ERRMSG1 (ERROR, E_LP_NOTNAME, *item);
					done (1);
				}
			}
		    } else {
			register int		die = 0;

			for (item = S; *item; item++) {
				if (!(cp = strchr(*item, '='))) {
					LP_ERRMSG (ERROR, E_ADM_CHARSETS);
					done (1);
				}

				*cp = 0;
				if (!syn_name(*item)) {
					LP_ERRMSG1 (ERROR, E_LP_NOTNAME, *item);
					done (1);
				}
				if (PCK_CHARSET & sum_chkprinter(T, (char *)0, (char *)0, (char *)0, (char *)0, *item)) {
					LP_ERRMSG1 (ERROR, E_ADM_BADSET, *item);
					die = 1;
				} else {
					if (bad_list)
						LP_ERRMSG2 (
							INFO,
							E_ADM_NBADSET,
							*item,
							sprintlist(bad_list)
						);
				}
				*cp++ = '=';
				if (!syn_name(cp)) {
					LP_ERRMSG1 (ERROR, E_LP_NOTNAME, cp);
					done (1);
				}
			}
			if (die) {
				LP_ERRMSG (ERROR, E_ADM_BADSETS);
				done (1);
			}
		}
	}

	if (P) {
		int createForm = 0;
		char **plist;

		if (getform(P, &formbuf, (FALERT *)0, (FILE **)0) != -1) {
			if ((!formbuf.paper) || (!STREQU(formbuf.paper,P)) ) {
				LP_ERRMSG (ERROR, E_ADM_ALSO_SEP_FORM);
				done (1);
			}
		} else
			createForm = 1;

		if (*P == '~') { /* removing types of papers */
			P++;
			p_remove = getlist(P, LP_WS, LP_SEP);
			p_add = NULL;
		} else  { /* adding types of papers */
			p_add = getlist(P, LP_WS, LP_SEP);
			p_remove = NULL;
			if (createForm) {
				char cmdBuf[200];

				for (plist = p_add; *plist; plist++) {
					snprintf(cmdBuf, sizeof (cmdBuf),
					    "lpforms -f %s -d\n", *plist);
					system(cmdBuf);
				}
			}
		}

		if (!f && !M) {  /* make paper allowed on printer too */
			f = Malloc(strlen(P) + strlen(NAME_ALLOW) +
			    strlen(": "));
			sprintf(f, "%s:%s", NAME_ALLOW, P);
			isfAuto = 1;
		}
	}
	/*
	 * NO MOUNT:
	 * The -f option restricts the forms that can be used with
	 * the printer.
	 *	- construct the allow/deny lists
	 *	- check each allowed form to see if it'll work
	 *	  on the printer
	 */
	if (f && !M) {
		register char		*type	= strtok(f, ":"),
					*str	= strtok((char *)0, ":"),
					**pf;

		register int		die	= 0;


		if (STREQU(type, NAME_ALLOW) && str) {
			if ((pf = f_allow = getlist(str, LP_WS, LP_SEP)) != NULL) {
				while (*pf) {
					if ((!isfAuto) &&
						!STREQU(*pf, NAME_NONE)
					     && verify_form(*pf) < 0
					)
						die = 1;
					pf++;
				}
				if (die) {
					LP_ERRMSG (ERROR, E_ADM_FORMCAPS);
					done (1);
				}

			} else
				LP_ERRMSG1 (WARNING, E_ADM_MISSING, NAME_ALLOW);

		} else if (STREQU(type, NAME_DENY) && str) {
			if ((pf = f_deny = getlist(str, LP_WS, LP_SEP)) != NULL) {
				if (!STREQU(*pf, NAME_ALL)) {
					while (*pf) {
						if ((!isfAuto) &&
						  !STREQU(*pf, NAME_NONE) &&
					     	  getform(*pf, &formbuf,
						  (FALERT *)0, (FILE **)0) < 0
						) {
						   LP_ERRMSG2(WARNING,
							E_ADM_ICKFORM, *pf, p);
						   die = 1;
						}
						pf++;
					}
				}
				if (die) {
					done (1);
				}

			} else
				LP_ERRMSG1 (WARNING, E_ADM_MISSING, NAME_DENY);

		} else {
			LP_ERRMSG (ERROR, E_ADM_FALLOWDENY);
			done (1);
		}
	}

	/*
	 * The -u option is setting use restrictions on printers.
	 *	- construct the allow/deny lists
	 */
	if (u) {
		register char		*type	= strtok(u, ":"),
					*str	= strtok((char *)0, ":");

		if (STREQU(type, NAME_ALLOW) && str) {
			if (!(u_allow = getlist(str, LP_WS, LP_SEP)))
				LP_ERRMSG1 (WARNING, E_ADM_MISSING, NAME_ALLOW);

		} else if (STREQU(type, NAME_DENY) && str) {
			if (!(u_deny = getlist(str, LP_WS, LP_SEP)))
				LP_ERRMSG1 (WARNING, E_ADM_MISSING, NAME_DENY);

		} else {
			LP_ERRMSG (ERROR, E_LP_UALLOWDENY);
			done (1);
		}
	}

	return;
}

/**
 ** root_can_write() - CHECK THAT "root" CAN SENSIBLY WRITE TO PATH
 **/

static int		root_can_write (path)
	char			*path;
{
	static int		lp_uid		= -1;

	struct passwd		*ppw;

	struct stat		statbuf;


	if (lstat(path, &statbuf) == -1) {
		LP_ERRMSG1 (ERROR, E_ADM_NOENT, v);
		return (-1);
	}
	/*
	 * If the device is a symlink (and it is not a root owned symlink),
	 * verify that the owner matches the destination owner.
	 */
	if (S_ISLNK(statbuf.st_mode) && statbuf.st_uid != 0) {
		uid_t uid = statbuf.st_uid;

		if (Stat(path, &statbuf) == -1) {
			LP_ERRMSG1 (ERROR, E_ADM_NOENT, v);
			return (-1);
		}

		if (statbuf.st_uid != uid) {
			LP_ERRMSG1 (ERROR, E_ADM_ISMISMATCH, v);
			done(1);
		}

		LP_ERRMSG1(WARNING, E_ADM_ISNOTROOTOWNED, v);
	}

	if ((statbuf.st_mode & S_IFMT) == S_IFDIR) {
		LP_ERRMSG1 (WARNING, E_ADM_ISDIR, v);
	} else if ((statbuf.st_mode & S_IFMT) == S_IFBLK)
		LP_ERRMSG1 (WARNING, E_ADM_ISBLK, v);

	if (lp_uid == -1) {
		if (!(ppw = getpwnam(LPUSER)))
			ppw = getpwnam(ROOTUSER);
		endpwent ();
		if (ppw)
			lp_uid = ppw->pw_uid;
		else
			lp_uid = 0;
	}
	if (!STREQU(v, "/dev/null"))
	    if ((statbuf.st_uid && statbuf.st_uid != lp_uid)
		|| (statbuf.st_mode & (S_IWGRP|S_IRGRP|S_IWOTH|S_IROTH)))
		LP_ERRMSG1 (WARNING, E_ADM_DEVACCESS, v);

	return (0);
}

/**
 ** unpack_sdn() - TURN SCALED TYPE INTO char* TYPE
 **/

static char		*unpack_sdn (sdn)
	SCALED			sdn;
{
	register char		*cp;
	extern char		*malloc();

	if (sdn.val <= 0 || 99999 < sdn.val)
		cp = 0;

	else if (sdn.val == N_COMPRESSED)
		cp = strdup(NAME_COMPRESSED);

	else if ((cp = malloc(sizeof("99999.999x"))))
		(void) sprintf(cp, "%.3f%c", sdn.val, sdn.sc);

	return (cp);
}

/**
 ** verify_form() - SEE IF PRINTER CAN HANDLE FORM
 **/

int			verify_form (form)
	char			*form;
{
	register char		*cpi_f,
				*lpi_f,
				*width_f,
				*length_f,
				*chset;

	register int		rc	= 0;
	char			**paperAllowed = NULL;
	char			**paperDenied = NULL;

	register unsigned long	checks;


	if (STREQU(form, NAME_ANY))
		form = NAME_ALL;

	while (getform(form, &formbuf, (FALERT *)0, (FILE **)0) != -1) {
		if (formbuf.paper) {
			if (!paperAllowed) {
				load_paperprinter_access(p, &paperAllowed,
					&paperDenied);
				freelist(paperDenied);
			}
			if (!allowed(formbuf.paper,paperAllowed,NULL)) {
				LP_ERRMSG1 (INFO, E_ADM_BADCAP,
				gettext("printer doesn't support paper type"));
				rc = -1;
			}
		}
		else {
			
		cpi_f = unpack_sdn(formbuf.cpi);
		lpi_f = unpack_sdn(formbuf.lpi);
		width_f = unpack_sdn(formbuf.pwid);
		length_f = unpack_sdn(formbuf.plen);

		if (
			formbuf.mandatory
		     && !daisy
		     && !search_cslist(
				formbuf.chset,
				(S && !M? S : (oldp? oldp->char_sets : (char **)0))
			)
		)
			chset = formbuf.chset;
		else
			chset = 0;

		if ((checks = sum_chkprinter(
			T,
			cpi_f,
			lpi_f,
			length_f,
			width_f,
			chset
		))) {
			rc = -1;
			if ((checks & PCK_CPI) && cpi_f)
				LP_ERRMSG1 (INFO, E_ADM_BADCAP, "cpi");

			if ((checks & PCK_LPI) && lpi_f)
				LP_ERRMSG1 (INFO, E_ADM_BADCAP, "lpi");

			if ((checks & PCK_WIDTH) && width_f)
				LP_ERRMSG1 (INFO, E_ADM_BADCAP, "width");

			if ((checks & PCK_LENGTH) && length_f)
				LP_ERRMSG1 (INFO, E_ADM_BADCAP, "length");

			if ((checks & PCK_CHARSET) && formbuf.chset) {
				LP_ERRMSG1 (INFO, E_ADM_BADSET, formbuf.chset);
				rc = -2;
			}
			LP_ERRMSG1 (INFO, E_ADM_FORMCAP, formbuf.name);
		} else {
			if (bad_list)
				LP_ERRMSG2 (
					INFO,
					E_ADM_NBADMOUNT,
					formbuf.name,
					sprintlist(bad_list)
				);
		}
		}

		if (!STREQU(form, NAME_ALL)) {
			if (paperAllowed)
				freelist(paperAllowed);
			return (rc);
		}

	}
	if (paperAllowed)
		freelist(paperAllowed);

	if (!STREQU(form, NAME_ALL)) {
		LP_ERRMSG1 (ERROR, E_LP_NOFORM, form);
		done (1);
	}

	return (rc);
}

/*
	Second phase of parsing for -p option.
	In a seperate routine so we can call it from other
	routines. This is used when any or all are used as 
	a printer name. main() loops over each printer, and
	must call this function for each printer found.
*/
void
chkopts2(called_from_chkopts)
int	called_from_chkopts;
{
	/*
		Only do the getprinter() if we are not being called
		from lpadmin.c. Otherwise we mess up our arena for 
		"all" processing.
	*/
	if (!called_from_chkopts)
		oldp = printer_pointer;
	else if (!(oldp = getprinter(p)) && errno != ENOENT) {
		LP_ERRMSG2 (ERROR, E_LP_GETPRINTER, p, PERROR);
		done(1);
	}

	if (oldp) {
		if (
			!c && !d && !f && !P && !M && !t && !r && !u && !x && !A
	     		&& !strlen(modifications)
		) {
			LP_ERRMSG (ERROR, E_ADM_PLONELY);
			done (1);
		}

		/*
		 * For the case "-s local-system", we need to keep
		 * "s != 0" long enough to get here, where it keeps
		 * us from taking the old value. After this, we make
		 * "s == 0" to indicate this is a local printer.
		 */
		if (s && s != Local_System)
			chksys(s);
		if (!s && oldp->remote && *(oldp->remote))
			s = strdup(oldp->remote);
		if (s == Local_System)
			s = 0;

		/*
		 * A remote printer converted to a local printer
		 * requires device or dial info.
		 */
		if (!s && oldp->remote && !v && !U) {
			LP_ERRMSG (ERROR, E_ADM_NOUV);
			done (1);
		}


	} else {
		if (getclass(p)) {
			LP_ERRMSG1 (ERROR, E_ADM_PRCL, p);
			done (1);
		}

		if (!syn_name(p)) {
			LP_ERRMSG1 (ERROR, E_LP_NOTNAME, p);
			done (1);
		}

		if (s == Local_System)
			s = 0;
		if (s)
			chksys(s);

#ifdef LP_USE_PAPI_ATTR
		/*
		 * New printer - if no model and a PPD file is defined then
		 *               use 'standard_foomatic' otherwise use 
		 *               the 'standard' model.
		 */
		if (!(e || i || m) && !s) {
			if (n_opt != NULL) {
				m = STANDARD_FOOMATIC;
			} else {
				m = STANDARD;
			}
		}
#else
		/*
		 * New printer - if no model, use standard
		 */
		if (!(e || i || m) && !s)
			m = STANDARD;
#endif

		/*
		 * A new printer requires device or dial info.
		 */
		if (!v && !U && !s) {
			LP_ERRMSG (ERROR, E_ADM_NOUV);
			done (1);
		}

		/*
		 * Can't quiet a new printer,
		 * can't list the alerting for a new printer.
		 */
		if (
			A
		     && (STREQU(A, NAME_QUIET) || STREQU(A, NAME_LIST))
		) {
			LP_ERRMSG1 (ERROR, E_ADM_BADQUIETORLIST, p);
			done (1);
		}

		/*
		 * New printer - if no input types given, assume "simple".
		 */
		if (!I) {
			I = getlist(NAME_SIMPLE, LP_WS, LP_SEP);
			strcat (modifications, "I");
		}
	}
}

/*
	Second phase of parsing for -S option.
	In a seperate routine so we can call it from other
	routines. This is used when any or all are used as 
	a print wheel name. main() loops over each print wheel,
	and must call this function for each print wheel found.
*/
void
chkopts3(called_from_chkopts)
int	called_from_chkopts;
{
	/*
		Only do the getpwheel() if we are not being called
		from lpadmin.c. Otherwise we mess up our arena for 
		"all" processing.
	*/
	if (!called_from_chkopts)
		oldS = pwheel_pointer;
	else
		oldS = getpwheel(*S);

	if (!oldS) {
		if (!syn_name(*S)) {
			LP_ERRMSG1 (ERROR, E_LP_NOTNAME, *S);
			done (1);
		}

		/*
		 * Can't quiet a new print wheel,
		 * can't list the alerting for a new print wheel.
		 */
		if (
			A
		     && (STREQU(A, NAME_QUIET) || STREQU(A, NAME_LIST))
		) {
			LP_ERRMSG1 (ERROR, E_ADM_BADQUIETORLIST, *S);
			done (1);
		}
	}
}

static void
chksys(s)
char	*s;
{
	char	*cp;

	if (STREQU(s, NAME_ALL) || STREQU(s, NAME_ANY)) {
		LP_ERRMSG (ERROR, E_ADM_ANYALLSYS);
		done(1);
	}

	if ((cp = strchr(s, '!')) != NULL)
		*cp = '\0';

	if (cp)
		*cp = '!';

	return;
}

/**
 ** sum_chkprinter() - CHECK TERMINFO STUFF FOR A LIST OF PRINTER TYPES
 **/

#include "lp.set.h"

static unsigned long
#if	defined(__STDC__)
sum_chkprinter (
	char **			types,
	char *			cpi,
	char *			lpi,
	char *			len,
	char *			wid,
	char *			cs
)
#else
sum_chkprinter (types, cpi, lpi, len, wid, cs)
	char **			types;
	char *			cpi;
	char *			lpi;
	char *			len;
	char *			wid;
	char *			cs;
#endif
{
	char **			pt;

	unsigned long		worst	= 0;
	unsigned long		this	= 0;


	/*
	 * Check each printer type, to see if any won't work with
	 * the attributes requested. However, return ``success''
	 * if at least one type works. Keep a list of the failed
	 * types for the caller to report.
	 */
	bad_list = 0;
	for (pt = types; *pt; pt++) {
		this = chkprinter(*pt, cpi, lpi, len, wid, cs);
		if (this != 0)
			addlist (&bad_list, *pt);
		worst |= this;
	}
	if (lenlist(types) == lenlist(bad_list))
		return (worst);
	else
		return (0);
}

/*
 * Function:    isPPD()
 *
 * Description: Check that the given PPD file exists. The argument given can
 *              either be a relative path or a full path to the file.
 *
 * Returns:     1 = PPD file found
 *              0 = PPD file not found
 */

static int
isPPD(char *ppd_file)
{
	int result = 0;
	char *ppd = NULL;

	if (ppd_file != NULL) {
		if (*ppd_file == '/') {
			ppd = strdup(ppd_file);
		} else {
			ppd = makepath(Lp_Model, "ppd", ppd_file, (char *)0);
		}

		/*
		 * now check the file exists
		 */
		if ((ppd != NULL) && (Access(ppd, 04) != -1)) {
			result = 1;
		} else {
			/*
			 * files does not exist so append .gz and check if
			 * that exist
			 */
			ppd = Realloc(ppd, strlen(ppd)+ strlen(PPDZIP)+2);
			if (ppd != NULL) {
				ppd = strcat(ppd, PPDZIP);
				if (Access(ppd, 04) != -1) {
					result = 1;
				}
			}
		}

		if (ppd != NULL) {
			free(ppd);
		}
	}
	return (result);
} /* isPPD() */
