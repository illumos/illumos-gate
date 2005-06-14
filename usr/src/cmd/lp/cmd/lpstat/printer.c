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

#include <locale.h>
#include "stdio.h"
#include "string.h"
#include "errno.h"
#include "sys/types.h"
#include "stdlib.h"

#include "lp.h"
#include "printers.h"
#include "msgs.h"

#define	WHO_AM_I	I_AM_LPSTAT
#include "oam.h"

#include "lpstat.h"

static void	figure_pitch_size(char *, SCALED *, SCALED *, SCALED *,
			SCALED *);
static void	printallowdeny(FILE *, int, char **, char **);
static void	printpwheels(PRINTER *, char *);
static void	printsets(PRINTER *);
static int	put_flt(char *printer, char *flt);

#define	USERS_AD 0
#define	FORMS_AD 1

/*
 * do_printer()
 */

void
do_printer(char **list)
{
	while (*list) {
		if (STREQU(*list, NAME_ALL)) {
			send_message(S_INQUIRE_PRINTER_STATUS, "");
			(void) output(R_INQUIRE_PRINTER_STATUS);

		} else {
			send_message(S_INQUIRE_PRINTER_STATUS, *list);
			switch (output(R_INQUIRE_PRINTER_STATUS)) {
			case MNODEST:
				LP_ERRMSG1(ERROR, E_LP_NOPRINTER, *list);
				exit_rc = 1;
				break;
			}
		}
		list++;
	}
}

/*
 * putpline() - DISPLAY STATUS OF PRINTER
 */

void
putpline(char *printer, int printer_status, char *request_id,
	time_t date, char *disable_reason, char *form,
	char *character_set)
{
	register PRINTER	*prbufp;
	char			**u_allow	= 0,
				**u_deny	= 0,
				**f_allow	= 0,
				**f_deny	= 0,
				**pt;
	char			enable_date[SZ_DATE_BUFF];
	int			multi_type;

	if (!(prbufp = getprinter(printer))) {
		LP_ERRMSG2(ERROR, E_LP_GETPRINTER, printer, PERROR);
		done(1);
	}

	(void) strftime(enable_date, sizeof (enable_date), NULL,
		localtime(&date));

	/*
	 * if (prbufp->login)
	 * printf(gettext(" (login terminal)"));
	 */

	if (!(printer_status & (PS_DISABLED|PS_LATER))) {
		if (printer_status & PS_FAULTED) {
			if (printer_status & PS_BUSY)
				printf(gettext(
					"printer %s faulted printing %s."),
					printer, request_id);
			else
				printf(gettext("printer %s faulted."),
					printer);
		} else if (printer_status & PS_BUSY)
			printf(gettext("printer %s now printing %s."),
				printer, request_id);
		else
			printf(gettext("printer %s is idle."), printer);

		printf(gettext(" enabled since %s."), enable_date);

	} else if (printer_status & PS_DISABLED)
		printf(gettext("printer %s disabled since %s."),
			printer, enable_date);

	else if (printer_status & PS_LATER)
		printf(gettext("printer %s waiting for auto-retry."), printer);

	(void) load_userprinter_access(printer, &u_allow, &u_deny);
	printf(is_user_allowed(getname(), u_allow, u_deny) ?
		gettext(" available.\n") : gettext(" not available.\n"));

	if (printer_status & (PS_FAULTED | PS_DISABLED|PS_LATER)) {
		if (strncmp("Warning: ", disable_reason, 9) == 0) {
			if (! put_flt(printer, disable_reason))
				printf("\t%s\n", gettext(disable_reason));
		}
		else
			printf("\t%s\n", gettext(disable_reason));
	}

	if (D && !(verbosity & (V_LONG|V_BITS)))
		printf(gettext("\tDescription: %s\n"),
			NB(prbufp->description));

	else if (verbosity & V_BITS) {
		register char		*sep	= "	";

		BITPRINT(printer_status, PS_REJECTED);
		BITPRINT(printer_status, PS_DISABLED);
		BITPRINT(printer_status, PS_FAULTED);
		BITPRINT(printer_status, PS_BUSY);
		BITPRINT(printer_status, PS_LATER);
		BITPRINT(printer_status, PS_REMOTE);
		if (sep[0] == '|')
			printf("\n");

	} else if (verbosity & V_LONG) {
		char *ptrForm, *ptrEndForm;
		int trayNum;

		if (form && (ptrEndForm = strchr(form, *LP_SEP))) {
			if (*(ptrEndForm+1)) {
				printf(gettext("\tForms mounted:\n"));
				ptrForm = form;
				trayNum = 1;
				while (ptrEndForm) {
					*ptrEndForm = 0;
					printf(gettext("\ttray %d: %s\n"),
						trayNum++, ptrForm);
					ptrForm = ptrEndForm+1;
					ptrEndForm = strchr(ptrForm, *LP_SEP);
				}
			} else {
				*ptrEndForm = 0;
				printf(gettext("\tForm mounted: %s\n"),
					NB(form));
			}
		} else if (!prbufp->remote)
			printf(gettext("\tForm mounted: %s\n"), NB(form));

		printf(gettext("\tContent types:"));
		if (prbufp->input_types) {
			printlist_setup(" ", 0, ",", "");
			printlist(stdout, prbufp->input_types);
			printlist_unsetup();
		}
		printf("\n");

		printf(gettext("\tPrinter types:"));
		if (prbufp->printer_types) {
			printlist_setup(" ", 0, ",", "");
			printlist(stdout, prbufp->printer_types);
			printlist_unsetup();
		} else
			printf(gettext(" (unknown)"));
		printf("\n");

		printf(gettext("\tDescription: %s\n"), NB(prbufp->description));

		if (!prbufp->remote)
			printf(gettext("\tConnection: %s\n"),
				(prbufp->dial_info ? prbufp->dial_info :
				gettext(NAME_DIRECT)));

		if (!prbufp->remote)
			printf(gettext("\tInterface: %s\n"),
				NB(prbufp->interface));

		if (!prbufp->remote) {
			if (prbufp->ppd != NULL) {
				printf(gettext("\tPPD: %s\n"), NB(prbufp->ppd));
			} else {
				printf(gettext("\tPPD: %s\n"), "none");
			}
		}

		if (!prbufp->remote) {
			if (is_user_admin()) {
				printf("\t");
				printalert(stdout, &(prbufp->fault_alert), 1);
			}
			printf(gettext("\tAfter fault: %s\n"),
				(prbufp->fault_rec ? prbufp->fault_rec :
					gettext(NAME_CONTINUE)));
		}

		(void) load_formprinter_access(printer, &f_allow, &f_deny);
		printallowdeny(stdout, USERS_AD, u_allow, u_deny);
		printallowdeny(stdout, FORMS_AD, f_allow, f_deny);

		switch (prbufp->banner) {
		case BAN_ALWAYS:
			printf(gettext("\tBanner required\n"));
			break;
		case BAN_OPTIONAL:
			printf(gettext("\tBanner not required\n"));
			break;
		case BAN_NEVER:
			printf(gettext("\tBanner page never printed\n"));
			break;
		}

		if (prbufp->daisy) {
			printf(gettext("\tPrint wheels:\n"));
			printpwheels(prbufp, character_set);
		} else {
			printf(gettext("\tCharacter sets:\n"));
			printsets(prbufp);
		}

		multi_type = (lenlist(prbufp->printer_types) > 1);
		for (pt = prbufp->printer_types; *pt; pt++) {

			SCALED			cpi;
			SCALED			lpi;
			SCALED			pwid;
			SCALED			plen;

			cpi = prbufp->cpi;
			lpi = prbufp->lpi;
			pwid = prbufp->pwid;
			plen = prbufp->plen;

			figure_pitch_size (*pt, &cpi, &lpi, &pwid, &plen);

			if (multi_type)
				printf(gettext("\tDefault pitch(%s):"), *pt);
			else
				printf(gettext("\tDefault pitch:"));

			if (cpi.val == N_COMPRESSED)
				printf(" %s CPI", NAME_COMPRESSED);
			else {
				printsdn_setup(" ", gettext(" CPI"), "");
				printsdn(stdout, cpi);
			}
			printsdn_setup(" ", gettext(" LPI"), "");
			printsdn(stdout, lpi);
			printf("\n");

			if (multi_type)
				printf(gettext("\tDefault page size(%s):"),
					*pt);
			else
				printf(gettext("\tDefault page size:"));

			printsdn_setup(" ", gettext(" wide"), "");
			printsdn(stdout, pwid);
			printsdn_setup(" ", gettext(" long"), "");
			printsdn(stdout, plen);
			printf("\n");

			printsdn_unsetup();
		}

		if (!prbufp->remote)
			printf(gettext("\tDefault port settings: %s "),
				NB(prbufp->stty));
		if (!prbufp->remote) {
			if (prbufp->speed && prbufp->dial_info)
				if (!STREQU(prbufp->dial_info, NAME_DIRECT))
					printf("%s", NB(prbufp->speed));
			printf("\n");
		}

		if (!prbufp->remote) {
			if (prbufp->options) {
				printf(gettext("\tOptions:"));
				printlist_setup(" ", 0, ",", "");
				printlist(stdout, prbufp->options);
				printlist_unsetup();
				printf("\n");
			}
		}

		printf("\n");
	}
}

/*
 * figure_pitch_size() - CALCULATE *REAL* DEFAULT PITCH, PAGE SIZE
 */

static void
figure_pitch_size(char *type, SCALED *cpi, SCALED *lpi, SCALED *pwid,
	SCALED *plen)
{
	short			orc,
				orhi,
				orl,
				orvi,
				cols,
				lines;

	/*
	 * The user want's to know how the page will look if
	 * he or she uses this printer. Thus, if the administrator
	 * hasn't set any defaults, figure out what they are from
	 * the Terminfo entry.
	 */
	if (!type || STREQU(type, NAME_UNKNOWN))
		return;

	/*
	 * NOTE: We should never get a failure return unless
	 * someone has trashed the printer configuration file.
	 * Also, if we don't fail the first time, we can't fail
	 * subsequently.
	 */
	if (tidbit(type, "orc", &orc) == -1)
		return;
	(void) tidbit(type, "orhi", &orhi);
	(void) tidbit(type, "orl", &orl);
	(void) tidbit(type, "orvi", &orvi);
	(void) tidbit(type, "cols", &cols);
	(void) tidbit(type, "lines", &lines);

#define	COMPUTE(ORI, OR) \
	(ORI != -1 && OR != -1? (int)((ORI / (double)OR) + .5) : 0)

	if (cpi->val <= 0) {
		cpi->val = (float)COMPUTE(orhi, orc);
		cpi->sc = 0;
	}
	if (lpi->val <= 0) {
		lpi->val = (float)COMPUTE(orvi, orl);
		lpi->sc = 0;
	}
	if (pwid->val <= 0) {
		pwid->val = (float)cols;
		pwid->sc = 0;
	}
	if (plen->val <= 0) {
		plen->val = (float)lines;
		plen->sc = 0;
	}

}

/*
 * printallowdeny() - PRINT ALLOW/DENY LIST NICELY
 */

static void
printallowdeny(FILE *fp, int type, char **allow, char **deny)
{

	printlist_setup("\t\t", 0, 0, 0);

	if (allow || deny && !*deny || !deny) {
		if (type == USERS_AD)
			(void) fprintf(fp, gettext("\tUsers allowed:\n"));
		else
			(void) fprintf(fp, gettext("\tForms allowed:\n"));
		if (allow && *allow)
			printlist(fp, allow);
		else if (allow && !*allow || !deny)
			(void) fprintf(fp, gettext("\t\t(none)\n"));
		else
			(void) fprintf(fp, gettext("\t\t(all)\n"));

	} else {
		if (type == USERS_AD)
			(void) fprintf(fp, gettext("\tUsers denied:\n"));
		else
			(void) fprintf(fp, gettext("\tForms denied:\n"));
		printlist(fp, deny);

	}

	printlist_unsetup();
}

/*
 * printpwheels() - PRINT LIST OF PRINT WHEELS
 */

static void
printpwheels(PRINTER *prbufp, char *pwheel)
{
	register char		**list;

	register int		mount_in_list	= 0,
				something_shown	= 0;


	if ((list = prbufp->char_sets))
		while (*list) {
			printf("\t\t%s", *list);
			if (pwheel && STREQU(*list, pwheel)) {
				printf(gettext(" (mounted)"));
				mount_in_list = 1;
			}
			printf("\n");
			list++;
			something_shown = 1;
		}

	if (!mount_in_list && pwheel && *pwheel) {
		printf(gettext("\t\t%s (mounted)\n"), pwheel);
		something_shown = 1;
	}

	if (!something_shown)
		printf(gettext("\t\t(none)\n"));
}

/*
 * printsets() - PRINT LIST OF CHARACTER SETS, WITH MAPPING
 */

static void
printsets(PRINTER *prbufp)
{
	register char		**alist		= prbufp->char_sets,
				*cp;

	char			**tlist = 0;


	/*
	 * We'll report the administrator defined character set aliases
	 * and any OTHER character sets we find in the Terminfo database.
	 */
	tlist = get_charsets(prbufp, 0);

	if ((!alist || !*alist) && (!tlist || !*tlist)) {
		printf(gettext("\t\t(none)\n"));
		return;
	}

	if (alist)
		while (*alist) {
			cp = strchr(*alist, '=');
			if (cp)
				*cp++ = 0;

			/*
			 * Remove the alias from the Terminfo list so
			 * we don't report it twice.
			 */
			if (dellist(&tlist, *alist) == -1) {
				LP_ERRMSG(ERROR, E_LP_MALLOC);
				done(1);
			}

			if (cp)
				printf("\t\t%s (as %s)\n", cp, *alist);
			else
				printf("\t\t%s\n", *alist);

			alist++;
		}

	if (tlist)
		while (*tlist)
			printf("\t\t%s\n", *tlist++);

}

/*
 * if the msg is in the format:
 *  Warning: <printer> is down: <reason>\n
 * break it up and reprint it out so we can do it in the users language.
 */
static int
put_flt(char *printer, char *flt)
{
	char *dup, *p;

	if ((dup = strdup(flt)) == NULL)
		return (0);

	if (strtok(dup + 9, " ") == NULL) {	/* start after "Warning: " */
		free(dup);
		return (0);
	}

	p = strtok(NULL, " ");
	if (p == NULL || strcmp(p, "is") != 0) {
		free(dup);
		return (0);
	}

	p = strtok(NULL, " ");
	if (p == NULL || strcmp(p, "down:") != 0) {
		free(dup);
		return (0);
	}

	p += 6;
	if (*p == NULL) {
		free(dup);
		return (0);
	}

	if (*(p + (strlen(p) - 1)) == '\n')
		*(p + (strlen(p) - 1)) = 0;
	putchar('\t');
	printf(gettext("Warning: %s is down: %s\n"), printer, gettext(p));

	free(dup);
	return (1);
}
