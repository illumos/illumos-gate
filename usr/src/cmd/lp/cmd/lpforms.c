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
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <locale.h>
#include "stdio.h"
#include "errno.h"
#include "string.h"
#include "sys/types.h"
#include "sys/stat.h"
#include "stdlib.h"

#include "lp.h"
#include "access.h"
#include "form.h"
#include "msgs.h"

#define	WHO_AM_I	I_AM_LPFORMS
#include "oam.h"

#define	OPT_LIST	"f:F:xlLA:u:W:Q:P:d"

#define TMPDIR		"/usr/tmp"

typedef int		(*Action)();

#if	defined(__STDC__)

static int	add_form ( char * , FILE * , FALERT * , char * );
static int	add_alert ( char * , FILE * , FALERT * , char * );
static int	delete_form ( char * );
static int	list_form ( char * );
static int	list_alert ( char * );
static int	list_both ( char * );
static int	any_alert ( char * , FILE * , FALERT * );
static int	quiet_alert ( char * );
static int	notify_spooler ( int , int , char * );
static int	onerror ( int , int , int );

static Action	set_action ( int (*)() , char * );

#else

static int	add_form();
static int	add_alert();
static int	delete_form();
static int	list_form();
static int	list_alert();
static int	list_both();
static int	any_alert();
static int	quiet_alert();
static int	notify_spooler();
static int	onerror();

static Action	set_action();

#endif

/**
 ** usage()
 **/

void			usage ()
{
	(void) printf (gettext(
"usage:\n"
"\n"
"  (add or change form)\n"
"    lpforms -f form-name [options]\n"
"	[-F path-name | - | -P paper [-d] | -d ]	(form definition)\n"
"	   -F path-name			(initialize from file)\n"
"	   -				(initialize from stdin)\n"
"	   -P paper [-d]		(initialize with paper (as default))\n"
"	   -d				(create form with paper of same name)\n"
"	[-u allow:user-list | deny:user-list]	(who's allowed to use)\n"
"	[-A mail | write | shell-command]  (alert definition)\n"
"	[-Q threshold]			(# needed for alert)\n"
"	[-W interval]			(minutes between alerts)\n"
"\n"
"  (list form)\n"
"    lpforms -f form-name -l\n"
"    lpforms -f form-name -L (verbose for -P forms)\n"
"\n"
"  (delete form)\n"
"    lpforms -f form-name -x\n"
"\n"
"  (define alert for forms with no alert yet)\n"
"    lpforms -f any -A {mail | write | shell-command}\n"
"\n"
"  (define alert for all forms)\n"
"    lpforms -f all -A {mail | write | shell-command}\n"
"\n"
"  (examine alerting)\n"
"    lpforms -f form-name -A list\n"
"\n"
"  (stop alerting)\n"
"    lpforms -f form-name -A quiet		(temporarily)\n"
"    lpforms -f form-name -A none		(for good)"
"\n"
));

	return;
}

static char *P = NULL;
static int d = 0;
static int L = 0;
/**
 ** main()
 **/

int
main(int argc, char *argv[])
{
	extern int		optind;
	extern int		opterr;
	extern int		optopt;

	extern char *		optarg;

	int			c;
	int			cnt = 0;

	char *			form		= 0;
	char *			u		= 0;
	char *			cp;
	char *			rest;
	char			stroptsw[]	= "-X";

	Action			action		= 0;

	FILE			*input		= 0;

	FORM			fbuf;

	FALERT			alert		= { (char *)0, -1, -1 };

	struct stat		statbuf;


	(void) setlocale (LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (!is_user_admin()) {
		LP_ERRMSG (ERROR, E_LP_NOTADM);
		exit (1);
	}

	opterr = 0;

	while ((c = getopt(argc, argv, OPT_LIST)) != -1) {

		/*
		 * These options take values; "getopt()" passes values
		 * that begin with a dash without checking if they're
		 * options. If a value is missing, we want to complain
		 * about it.
		 */
		switch (c) {
		case 'W':
		case 'Q':
			/*
			 * These options take numeric values, which might
			 * be negative. Negative values are handled later,
			 * but here we just screen them.
			 */
			(void)strtol (optarg, &rest, 10);
			if (!rest || (!*rest && rest != optarg))
				break;
			/*FALLTHROUGH*/
		case 'f':
		case 'F':
		case 'A':
		case 'u':
			if (!*optarg) {
				stroptsw[1] = c;
				LP_ERRMSG1 (ERROR, E_LP_NULLARG, stroptsw);
				exit (1);
			}
			if (*optarg == '-') {
				stroptsw[1] = c;
				LP_ERRMSG1 (ERROR, E_LP_OPTARG, stroptsw);
				exit (1);
			}
			break;
		}

		switch (c) {

		case 'f':
			if (form)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'f');
			form = optarg;
			if (!syn_name(form)) {
				LP_ERRMSG1 (ERROR, E_LP_NOTNAME, form);
				exit (1);
			} else if (!*form)
				form = NAME_ALL;
			break;

		case 'F':
			if (input)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'F');
			if (!(input = fopen(optarg, "r"))) {
				LP_ERRMSG1 (ERROR, E_FOR_OPEN, optarg);
				exit (1);
			}
			action = set_action(add_form, "-F");
			break;

		case 'A':
			if (STREQU(NAME_LIST, optarg))
				action = set_action(list_alert, "\"-A list\"");

			else if (STREQU(NAME_QUIET, optarg))
				action = set_action(quiet_alert, "\"-A quiet\"");

			else {
				if (STREQU(MAIL, optarg) || STREQU(WRITE, optarg))
					alert.shcmd = makestr(optarg, " ", getname(), (char *)0);
				else
					alert.shcmd = strdup(optarg);
				action = set_action(add_alert, "-A");
			}
			break;

		case 'Q':
			if (alert.Q != -1)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'Q');
			if (STREQU(NAME_ANY, optarg))
				alert.Q = 1;
			else {
				alert.Q = strtol(optarg, &rest, 10);
				if (alert.Q < 0) {
					LP_ERRMSG1 (ERROR, E_LP_NEGARG, 'Q');
					exit (1);
				}
				if (rest && *rest) {
					LP_ERRMSG1 (ERROR, E_LP_GARBNMB, 'Q');
					exit (1);
				}
				if (alert.Q == 0) {
					LP_ERRMSG1 (ERROR, E_LP_ZEROARG, 'Q');
					exit (1);
				}
			}
			action = set_action(add_alert, "-Q");
			break;

		case 'W':
			if (alert.W != -1)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'W');
			if (STREQU(NAME_ONCE, optarg))
				alert.W = 0;
			else {
				alert.W = strtol(optarg, &rest, 10);
				if (alert.W < 0) {
					LP_ERRMSG1 (ERROR, E_LP_NEGARG, 'W');
					exit (1);
				}
				if (rest && *rest) {
					LP_ERRMSG1 (ERROR, E_LP_GARBNMB, 'W');
					exit (1);
				}
			}
			action = set_action(add_alert, "-W");
			break;

		case 'u':
			if (u)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'u');
			u = strdup(optarg);
			action = set_action(add_form, "-u");
			break;

		case 'x':
			action = set_action(delete_form, "-x");
			break;

		case 'L':
			L = 1;
			action = set_action(list_form, "-L");
			break;
		case 'l':
			action = set_action(list_form, "-l");
			break;

		case 'd':
			d = 1;
			action = set_action(add_form, "-d");
			break;

		case 'P':
			if (P)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'P');
			action = set_action(add_form, "-P");
			P = strdup(optarg);
			break;

		default:
			if (optopt == '?') {
				usage ();
				exit (0);
			}
			stroptsw[1] = optopt;
			if (strchr(OPT_LIST, optopt))
				LP_ERRMSG1 (ERROR, E_LP_OPTARG, stroptsw);
			else
				LP_ERRMSG1 (ERROR, E_LP_OPTION, stroptsw);
			exit (1);

		}
	}

	if (!form) {
		LP_ERRMSG (ERROR, E_FOR_FORMNAME);
		exit (1);
	}

	if (STREQU(NAME_ANY, form))
		action = set_action(any_alert, "\"-f any\"");

	if (optind < argc && STREQU(argv[optind], "-")) {
		action = set_action(add_form, "-");
		input = stdin;
		optind++;
	}
	if (optind < argc)
		LP_ERRMSG1 (WARNING, E_FOR_EXTRAARG, argv[optind]);

	if (!action) {
		LP_ERRMSG (ERROR, E_FOR_NOACT);
		exit (1);
	}

	if (action == any_alert && STREQU(alert.shcmd, NAME_NONE)) {
		LP_ERRMSG (WARNING, E_FOR_ANYDEL);
		exit (0);
	}

	/*
	 * We must have a shell command for the alert if:
	 *
	 *	(1) we're adding a new form and the -W or -Q options
	 *	    have been given, or
	 *
	 *	(2) the -f any option was given.
	 */
	if (
		(
			action == add_form
		     && !alert.shcmd
		     && (alert.Q != -1 || alert.W != -1)
		     && !STREQU(NAME_ALL, form)
		     && getform(form, &fbuf, (FALERT *)0, (FILE **)0) != 0
		)
	     || action == any_alert && !alert.shcmd
	) {
		LP_ERRMSG (ERROR, E_FOR_NOSHCMDERR);
		return (1);
	}

	if (P && (! STREQU(P,form))) {
		while (P && (cnt++ < 2)) {
			/*
			 * two times should do it unless user has edited
			 * files directly
			 */
			if (getform(P, &fbuf, (FALERT *)0, (FILE **)0) != -1) {
				if (!fbuf.paper) {
					LP_ERRMSG3(ERROR, E_FOR_ALSO_SEP_FORM,
						form, P, P);
					return (1);
				} else if (!STREQU(fbuf.paper, P))
					P = Strdup(fbuf.paper);
				else
					break;	 /* we found a good paper */
			} else {
				int result;
				int saveD;

				saveD = d;
				d = 1;
				result = ((*action)(P, NULL, &alert, u));
				d = saveD;
				return (result ? result :
					((*action)(form, input, &alert, u)));
			}
		}
	}

	if (d && !P)
		P = Strdup(form);

	return ((*action)(form, input, &alert, u));
}

/**
 ** add_alert()
 ** add_form()
 **/

/*
 * "add_alert()" exists just to simplify the checking of mixed
 * options in "set_action()".
 */

static int
#if	defined(__STDC__)
add_alert (
	char *			form,
	FILE *			input,
	FALERT *		p_new_alert,
	char *			u
)
#else
add_alert (form, input, new_alert, u)
	char *			form;
	FILE *			input;
	FALERT *		p_new_alert;
	char *			u;
#endif
{
	return (add_form(form, input, p_new_alert, u));
}

static int
#if	defined(__STDC__)
add_form (
	char *			form,
	FILE *			input,
	FALERT *		p_new_alert,
	char *			u
)
#else
add_form (form, input, new_alert, u)
	char *			form;
	FILE *			input;
	FALERT *		p_new_alert;
	char *			u;
#endif
{
	int			fld;
	int			which_set[FO_MAX];
	int			new_form	= 0;
	int			nform;
	int			return_code;

	char *			all_list[]	= { NAME_ALL, 0 };
	char **			u_allow		= 0;
	char **			u_deny		= 0;

	FILE *			align_fp	= 0;

	FORM			fbuf;
	FORM			new_fbuf;

	FALERT			alert;


	/*
	 * Read the input configuration (if any) and parse it into a form,
	 * storing it in the form buffer "fbuf". Keep track of
	 * which fields have been given, to avoid overwriting unchanged
	 * fields later.
	 */
	if (input) {
		for (fld = 0; fld < FO_MAX; fld++)
			which_set[fld] = 0;

		if (rdform(form, &new_fbuf, fileno(input), onerror,
				which_set) == -1) {
			LP_ERRMSG2 (ERROR, E_FOR_UNKNOWN, "(input)", PERROR);
			return (1);
		}
		for (fld = 0; fld < FO_MAX; fld++)
			if (which_set[fld])
				break;
		if (fld >= FO_MAX)
			LP_ERRMSG (WARNING, E_FOR_EMPTYFILE);

		/*
		 * Read the alignment pattern (if any) into a temporary
		 * file so that it can be used for (potentially) many
		 * forms.
		 */
		if (which_set[FO_ALIGN]) {

			size_t			n;

			char			buf[BUFSIZ];



			if ((align_fp = tmpfile()) == NULL) {
				LP_ERRMSG (ERROR, E_FOR_CTMPFILE);
				exit (1);
			}

			while ((n = fread(buf, 1, BUFSIZ, input)))
				fwrite (buf, 1, n, align_fp);
		}
	}

	/*
	 * Parse the user allow/deny list (if any).
	 */
	if (u) {

		char *			cp;
		char *			type;


		type = strtok(u, ":");
		cp = strtok((char *)0, ":");

		if (STREQU(type, NAME_ALLOW) && cp) {
			if (!(u_allow = getlist(cp, LP_WS, LP_SEP)))
				LP_ERRMSG1 (
					WARNING,
					E_LP_MISSING,
					NAME_ALLOW
				);

		} else if (STREQU(type, NAME_DENY) && cp) {
			if (!(u_deny = getlist(cp, LP_WS, LP_SEP)))
				LP_ERRMSG1 (
					WARNING,
					E_LP_MISSING,
					NAME_DENY
				);

		} else {
			LP_ERRMSG (ERROR, E_LP_UALLOWDENY);
			exit (1);
		}
	}

	/*
	 * The following loop gets either a particular form or
	 * all forms (one at a time). The value of "return_code"
	 * controls the loop and is also the value to use in the
	 * "return()" at the end.
	 */
	nform = 0;
	return_code = -1;
	while (return_code == -1) {

		/*
		 * If we are adding/changing a single form, set
		 * the loop control to get us out.
		 */
		if (!STREQU(NAME_ALL, form))
			return_code = 0;

		nform++;

		if (P) {
			memset ((char *)&fbuf, 0, sizeof(FORM));
			fbuf.name = strdup(form);
			fbuf.plen.val = DPLEN;
			fbuf.plen.sc = 0;
			fbuf.pwid.val = DPWIDTH;
			fbuf.pwid.sc = 0;
			fbuf.lpi.val = DLPITCH;
			fbuf.lpi.sc = 0;
			fbuf.cpi.val = DCPITCH;
			fbuf.cpi.sc = 0;
			fbuf.np = DNP;
			fbuf.chset = strdup(DCHSET);
			fbuf.mandatory = 0;
			fbuf.rcolor = strdup(DRCOLOR);
			fbuf.conttype = strdup(DCONTYP);
			fbuf.paper = P;
			fbuf.isDefault = d;
			alert.shcmd = 0;
			alert.W = alert.Q = -1;
			new_form = 1;

		} else if (getform(form, &fbuf, &alert, (FILE **)0) == -1)
			switch (errno) {

			case ENOENT:
				/*
				 * This is a problem only if it occurs
				 * immediately on trying to get ``all''.
				 */
				if (STREQU(NAME_ALL, form)) {
					if (nform > 1)
						return_code = 0;
					else {
						LP_ERRMSG (ERROR, E_FOR_NOFORMS);
						return_code = 1;
					}
					continue;
				}

				/*
				 * We're adding a new form,
				 * so set up default values.
				 */
				memset ((char *)&fbuf, 0, sizeof(FORM));
				fbuf.name = strdup(form);
				fbuf.plen.val = DPLEN;
				fbuf.plen.sc = 0;
				fbuf.pwid.val = DPWIDTH;
				fbuf.pwid.sc = 0;
				fbuf.lpi.val = DLPITCH;
				fbuf.lpi.sc = 0;
				fbuf.cpi.val = DCPITCH;
				fbuf.cpi.sc = 0;
				fbuf.np = DNP;
				fbuf.chset = strdup(DCHSET);
				fbuf.mandatory = 0;
				fbuf.rcolor = strdup(DRCOLOR);
				fbuf.conttype = strdup(DCONTYP);
				alert.shcmd = 0;
				alert.W = alert.Q = -1;

				new_form = 1;
				break;

			default:
				/*
				 * Don't know if we'll have a good name
				 * in the "all" case on getting here, so
				 * punt on naming the form in the error
				 * message.
				 */
				LP_ERRMSG2 (ERROR, E_LP_GETFORM, form, PERROR);
				return_code = 1;
				continue;
			}

		/*
		 * Copy just those items that were given in the input.
		 */
		if (!input && new_form && !P) {
			LP_ERRMSG1 (ERROR, E_LP_NOFORM, form);
			return (1);
		}
		if (input)
			for (fld = 0; fld < FO_MAX; fld++)
				if (which_set[fld]) switch(fld) {

				case FO_PLEN:
					fbuf.plen = new_fbuf.plen;
					break;

				case FO_PWID:
					fbuf.pwid = new_fbuf.pwid;
					break;

				case FO_CPI:
					fbuf.cpi = new_fbuf.cpi;
					break;

				case FO_LPI:
					fbuf.lpi = new_fbuf.lpi;
					break;

				case FO_NP:
					fbuf.np = new_fbuf.np;
					break;

				case FO_CHSET:
					fbuf.chset = new_fbuf.chset;
					fbuf.mandatory = new_fbuf.mandatory;
					break;

				case FO_RCOLOR:
					fbuf.rcolor = new_fbuf.rcolor;
					break;

				case FO_CMT:
					fbuf.comment = new_fbuf.comment;
					break;

				case FO_ALIGN:
					fbuf.conttype = new_fbuf.conttype;
					rewind (align_fp);
					break;

				case FO_PAPER:
					fbuf.paper = new_fbuf.paper;
					fbuf.isDefault = new_fbuf.isDefault;
					break;

				}

		/*
		 * Set just those alert elements that were given.
		 * However, complain about those form(s) that don't have
		 * a shell command yet, and none was given, yet -W or -Q
		 * were given.
		 */
		if (
			!alert.shcmd && !p_new_alert->shcmd
		     && (p_new_alert->W != -1 || p_new_alert->Q != -1)
		)
			LP_ERRMSG1 (WARNING, E_FOR_NOSHCMDWARN, fbuf.name);
		else {
			if (p_new_alert->shcmd)
				alert.shcmd = p_new_alert->shcmd;
			if (p_new_alert->Q != -1)
				alert.Q = p_new_alert->Q;
			if (p_new_alert->W != -1)
				alert.W = p_new_alert->W;
		}

		/*
		 * Create/update the form.
		 */
#define P_FBUF	(new_form || input? &fbuf : (FORM *)0)
		if (putform(fbuf.name, P_FBUF, &alert, &align_fp) == -1) {
			LP_ERRMSG2 (ERROR, E_LP_PUTFORM, fbuf.name, PERROR);
			return_code = 1;
			continue;
		}

		/*
		 * Allow/deny users.
		 */
		if (new_form && allow_user_form(all_list, fbuf.name) == -1) {
			LP_ERRMSG1 (ERROR, E_LP_ACCESSINFO, PERROR);
			return_code = 1;
			continue;
		}
		if (u_allow && allow_user_form(u_allow, fbuf.name) == -1) {
			LP_ERRMSG1 (ERROR, E_LP_ACCESSINFO, PERROR);
			return_code = 1;
			continue;
		}
		if (u_deny && deny_user_form(u_deny, fbuf.name) == -1) {
			LP_ERRMSG1 (ERROR, E_LP_ACCESSINFO, PERROR);
			return_code = 1;
			continue;
		}

		notify_spooler (S_LOAD_FORM, R_LOAD_FORM, fbuf.name);

	}

	if (align_fp)
		close_lpfile (align_fp);

	return (return_code);
}

/**
 ** list_form()
 ** list_alert()
 ** list_both()
 **/

#if	defined(__STDC__)

static int	list ( char * , void (*)() );
static void	_list_form ( FORM * , FALERT * , FILE * );
static void	_list_alert ( FORM * , FALERT * );
static void	_list_both ( FORM * , FALERT * , FILE * );

#else

static int	list();
static void	_list_form();
static void	_list_alert();
static void	_list_both();

#endif

static int
#if	defined(__STDC__)
list_form (
	char			*form
)
#else
list_form (form)
	char			*form;
#endif
{
	return (list(form, _list_form));
}

static int
#if	defined(__STDC__)
list_alert (
	char			*form
)
#else
list_alert (form)
	char			*form;
#endif
{
	return (list(form, _list_alert));
}

static int
#if	defined(__STDC__)
list_both (
	char			*form
)
#else
list_both (form)
	char			*form;
#endif
{
	return (list(form, _list_both));
}

static int
#if	defined(__STDC__)
list (
	char			*form,
	void			(*subaction)()
)
#else
list (form, subaction)
	char			*form;
	void			(*subaction)();
#endif
{
	FORM			fbuf;

	FALERT			alert;

	FILE * 			align_fp;

	char			*nl;


	if (STREQU(NAME_ALL, form)) {

		nl = "";
		while (getform(form, &fbuf, &alert, &align_fp) == 0) {
			printf (gettext("%sForm name: %s\n"), nl, fbuf.name);
			(*subaction) (&fbuf, &alert, align_fp);
			nl = "\n";
		}

		switch (errno) {
		case ENOENT:
			return (0);
		default:
			/*
			 * Don't know if we'll have a good name
			 * in the "all" case on getting here, so
			 * punt on naming the form in the error
			 * message.
			 */
			LP_ERRMSG2 (ERROR, E_LP_GETFORM, form, PERROR);
			return (1);
		}

	} else {

		if (getform(form, &fbuf, &alert, &align_fp) == 0) {
			(*subaction) (&fbuf, &alert, align_fp);
			return (0);
		}

		switch (errno) {
		case ENOENT:
			LP_ERRMSG1 (ERROR, E_LP_NOFORM, form);
			return (1);
		default:
			LP_ERRMSG2 (ERROR, E_LP_GETFORM, form, PERROR);
			return (1);
		}

	}
}

/**
 ** _list_form()
 **/

static void
#if	defined(__STDC__)
_list_form (
	FORM *			pf,
	FALERT *		palert,
	FILE *			align_fp
)
#else
_list_form (pf, palert, align_fp)
	FORM *			pf;
	FALERT *		palert;
	FILE *			align_fp;
#endif
{
	size_t			n;

	char			buf[BUFSIZ];

	int			which_set[FO_MAX];
	int			fld,whichVal;


	whichVal = (pf->paper && (L == 0) ? 0 : 1);
	for (fld = 0; fld < FO_MAX; fld++)
		which_set[fld] = whichVal;
	if (!align_fp)
		which_set[FO_ALIGN] = 0;
	if (pf->paper)
		which_set[FO_PAPER] = 1;
	wrform (pf->name, pf, 1, onerror, which_set);
	if (align_fp)
		while ((n = fread(buf, 1, BUFSIZ, align_fp)))
			write (1, buf, n);
}

/**
 ** _list_alert()
 **/

static void
#if	defined(__STDC__)
_list_alert (
	FORM *			ignore,
	FALERT *		palert
)
#else
_list_alert (ignore, palert)
	FORM *			ignore;
	FALERT *		palert;
#endif
{
	printalert (stdout, palert, 0);
}

/**
 ** _list_both()
 **/

static void
#if	defined(__STDC__)
_list_both (
	FORM *			pf,
	FALERT *		palert,
	FILE *			align_fp
)
#else
_list_both (pf, palert, align_fp)
	FORM *			pf;
	FALERT *		palert;
	FILE *			align_fp;
#endif
{
	_list_alert (pf, palert);
	_list_form (pf, palert, align_fp);
}

/**
 ** any_alert()
 **/

static int
#if	defined(__STDC__)
any_alert (
	char *			form,
	FILE *			ignore,
	FALERT *		p_new_alert
)
#else
any_alert (form, ignore, p_new_alert)
	char *			form;
	FILE *			ignore;
	FALERT *		p_new_alert;
#endif
{
	FORM			fbuf;

	FALERT			alert;


	while (getform(NAME_ALL, &fbuf, &alert, (FILE **)0) == 0)
		if (!alert.shcmd)
			if (putform(fbuf.name, (FORM *)0, p_new_alert, (FILE **)0) == -1) {
				LP_ERRMSG2 (ERROR, E_LP_PUTFORM, fbuf.name, PERROR);
				return (1);
			}

	return (0);
}

/**
 ** delete_form()
 ** quiet_alert()
 **/

#if	defined(__STDC__)

static int	dq ( char * , int (*)() );
static int	_delete_form ( char * );
static int	_quiet_alert ( char * );

#else

static int	dq();
static int	_delete_form();
static int	_quiet_alert();

#endif

static int
#if	defined(__STDC__)
delete_form (
	char			*form
)
#else
delete_form (form)
	char			*form;
#endif
{
	return (dq(form, _delete_form));
}

static int
#if	defined(__STDC__)
quiet_alert (
	char *			form
)
#else
quiet_alert (form)
	char *			form;
#endif
{
	return (dq(form, _quiet_alert));
}

static int
#if	defined(__STDC__)
dq (
	char			*form,
	int			(*subaction)()
)
#else
dq (form, subaction)
	char			*form;
	int			(*subaction)();
#endif
{
	FORM			fbuf;


	if (STREQU(NAME_ANY, form) || STREQU(NAME_NONE, form)) {
		LP_ERRMSG (ERROR, E_FOR_ANYNONE);
		exit (1);
	}

	if (STREQU(NAME_ALL, form)) {

		while (getform(form, &fbuf, (FALERT *)0, (FILE **)0) == 0)
			if ((*subaction)(fbuf.name) == 1)
				return (1);

		switch (errno) {
		case ENOENT:
			return (0);
		default:
			/*
			 * Don't know if we'll have a good name
			 * in the "all" case on getting here, so
			 * punt on naming the form in the error
			 * message.
			 */
			LP_ERRMSG2 (ERROR, E_LP_GETFORM, form, PERROR);
			return (1);
		}

	} else {

		if (getform(form, &fbuf, (FALERT *)0, (FILE **)0) == 0)
			return ((*subaction)(fbuf.name));

		switch (errno) {
		case ENOENT:
			LP_ERRMSG1 (ERROR, E_LP_NOFORM, form);
			return (1);
		default:
			LP_ERRMSG2 (ERROR, E_LP_GETFORM, form, PERROR);
			return (1);
		}
	}
}

static int
#if	defined(__STDC__)
_delete_form (
	char			*form
)
#else
_delete_form (form)
	char			*form;
#endif
{
	switch (notify_spooler(S_UNLOAD_FORM, R_UNLOAD_FORM, form)) {

	case -1:
		if (anyrequests()) {
			LP_ERRMSG (ERROR, E_FOR_MOPENREQX);
			return (1);
		}
		/*FALLTHROUGH*/

	case MNODEST:
		if (delform(form) == -1) {
			if (errno == ENOENT) {
				LP_ERRMSG1 (ERROR, E_LP_NOFORM, form);
				return (1);
			} else {
				LP_ERRMSG2 (
					ERROR,
		     			E_FOR_UNKNOWN,
					form,
					PERROR
				);
				return (1);
			}
		}
		break;

	case MOK:
		if (delform(form) == -1) {
    			LP_ERRMSG (ERROR, E_FOR_DELSTRANGE);
			return (1);
		}
		break;
	}
	return (0);
}

static int
#if	defined(__STDC__)
_quiet_alert (
	char *			form
)
#else
_quiet_alert (form)
	char *			form;
#endif
{
	char			*msgbuf;

	int			mtype;

	int			size;

	short			status;

	/*
	 * If the attempt to open a message queue to the
	 * Spooler fails, assume it isn't running and just
	 * return--don't say anything, `cause the user may
	 * know. Any other failure deserves an error message.
	 */

	if (mopen() == -1)
		return (0);

	size = putmessage (NULL, S_QUIET_ALERT, form, QA_FORM);
	msgbuf = malloc(size);
	putmessage (msgbuf, S_QUIET_ALERT, form, QA_FORM);

	if (msend(msgbuf) == -1) {
		LP_ERRMSG (ERROR, E_LP_MSEND);
		mclose ();
		return (1);
	}

	if (mrecv(msgbuf, size) == -1) {
		LP_ERRMSG (ERROR, E_LP_MRECV);
		mclose ();
		return (1);
	}

	mtype = getmessage(msgbuf, R_QUIET_ALERT, &status);
	free (msgbuf);
	mclose ();
	if (mtype != R_QUIET_ALERT) {
		LP_ERRMSG (ERROR, E_LP_BADREPLY);
		return (1);
	}

	switch (status) {

	case MOK:
		break;

	case MNODEST:	/* not quite, but not a lie either */
	case MERRDEST:
		LP_ERRMSG1 (WARNING, E_LP_NOQUIET, form);
		break;

	case MNOPERM:	/* taken care of up front */
	default:
		LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, status);
		return (1);
		/*NOTREACHED*/
	}

	return (0);
}

/**
 ** set_action() - CHECK FOR AMBIGUOUS ACTIONS
 **/

static Action
#if	defined(__STDC__)
set_action (
	Action			action,
	char *			option
)
#else
set_action (action, option)
	Action			action;
	char *			option;
#endif
{
	static Action		prev_action	= 0;

	static char *		prev_option;


	if (
		action == list_form && prev_action == list_alert
	     || action == list_alert && prev_action == list_form
	)
		action = list_both;

	else if (
		action == add_form && prev_action == add_alert
	     || action == add_alert && prev_action == add_form
	)
		action = add_form;

	else if (
		action == any_alert && prev_action == add_alert
	     || action == add_alert && prev_action == any_alert
	)
		action = any_alert;

	else if (prev_action && prev_action != action) {
 		LP_ERRMSG2 (ERROR, E_LP_AMBIG, option, prev_option);
		exit (1);
	}

	prev_action = action;
	prev_option = option;
	return (action);
}

/**
 ** notify_spooler() - NOTIFY SPOOLER OF ACTION ON FORMS DB
 **/

static int
#if	defined(__STDC__)
notify_spooler (
	int			sendmsg,
	int			replymsg,
	char *			form
)
#else
notify_spooler (sendmsg, replymsg, form)
	int			sendmsg;
	int			replymsg;
	char *			form;
#endif
{
	char *			msgbuf;

	int			mtype;
	int			size;

	short			status;

	/*
	 * If the attempt to open a message queue to the
	 * Spooler fails, assume it isn't running and just
	 * return--don't say anything, `cause the user may
	 * know. Any other failure deserves an error message.
	 */

	if (mopen() == -1)
		return (-1);

	size = putmessage((char *)0, sendmsg, form);
	msgbuf = malloc(size);
	putmessage (msgbuf, sendmsg, form);

	if (msend(msgbuf) == -1) {
		LP_ERRMSG (ERROR, E_LP_MSEND);
		mclose ();
		exit (1);
	}
	if (mrecv(msgbuf, size) == -1) {
		LP_ERRMSG (ERROR, E_LP_MRECV);
		mclose ();
		exit (1);
	}
	mclose ();

	mtype = getmessage(msgbuf, replymsg, &status);
	free (msgbuf);
	if (mtype != replymsg) {
		LP_ERRMSG (ERROR, E_LP_BADREPLY);
		exit (1);
	}

	if (status == MOK)
		return (MOK);

	if (sendmsg == S_LOAD_FORM)
		switch (status) {
		case MNOSPACE:
			LP_ERRMSG (ERROR, E_FOR_NOSPACE);
			break;
		case MNOPERM:
			LP_ERRMSG (ERROR, E_LP_NOTADM);
			break;

		/*
		 * The following two error conditions should have
		 * already been trapped, so treat them as bad status
		 * should they occur.
		 */
		case MNODEST:
		case MERRDEST:
		default:
			LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, status);
			break;
		}

	if (sendmsg == S_UNLOAD_FORM)
		switch (status) {
		case MBUSY:
			LP_ERRMSG1 (ERROR, E_FOR_FORMBUSY, form);
			break;
		case MNODEST:
			return (MNODEST);
		case MNOPERM:
			LP_ERRMSG (ERROR, E_LP_NOTADM);
			break;
		default:
			LP_ERRMSG (ERROR, E_LP_BADSTATUS);
			break;
		}

	exit (1);
}

/**
 ** onerror()
 **/

static int
#if	defined(__STDC__)
onerror (
	int			Errno,
	int			lp_errno,
	int			linenum
)
#else
onerror (Errno, lp_errno, linenum)
	int			Errno;
	int			lp_errno;
	int			linenum;
#endif
{
	static int		nerrors	= 0;


	if (Errno == EBADF) {
		switch (lp_errno) {
		case LP_EBADSDN:
			LP_ERRMSG1 (WARNING, E_FOR_BADSCALE, linenum);
			break;
		case LP_EBADINT:
			LP_ERRMSG1 (WARNING, E_FOR_BADINT, linenum);
			break;
		case LP_EBADNAME:
			LP_ERRMSG1 (WARNING, E_FOR_NOTNAME, linenum);
			break;
		case LP_EBADARG:
			LP_ERRMSG1 (WARNING, E_FOR_BADCHSETQUALIFIER, linenum);
			break;
		case LP_ETRAILIN:
			LP_ERRMSG1 (WARNING, E_FOR_TRAILIN, linenum);
			break;
		case LP_EBADCTYPE:
			LP_ERRMSG1 (WARNING, E_FOR_NOTCTYPE, linenum);
			break;
		case LP_EBADHDR:
			LP_ERRMSG1 (WARNING, E_FOR_BADHDR, linenum);
			break;
		}
		if (nerrors++ >= 5) {
			LP_ERRMSG (ERROR, E_LP_GARBAGE);
			return (-1);
		}
		return (0);
	} else {
		LP_ERRMSG2 (ERROR, E_FOR_UNKNOWN, "(stdin)", PERROR);
		return (-1);
	}
}
