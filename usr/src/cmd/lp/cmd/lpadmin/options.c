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

#include "ctype.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include <libintl.h>

#include "lp.h"
#include "printers.h"

#define	WHO_AM_I	I_AM_LPADMIN
#include "oam.h"

#include "lpadmin.h"

#ifdef LP_USE_PAPI_ATTR
#if	defined(CAN_DO_MODULES)
#define	OPT_LIST "A:ac:d:D:e:f:F:H:hi:I:lm:Mn:o:p:Q:r:S:s:T:u:U:v:W:x:t:P:"
#else
#define	OPT_LIST "A:ac:d:D:e:f:F:hi:I:lm:Mn:o:p:Q:r:S:s:T:u:U:v:W:x:t:P:"
#endif

#else
#if	defined(CAN_DO_MODULES)
#define	OPT_LIST	"A:ac:d:D:e:f:F:H:hi:I:lm:Mo:p:Q:r:S:s:T:u:U:v:W:x:t:P:"
#else
#define	OPT_LIST	"A:ac:d:D:e:f:F:hi:I:lm:Mo:p:Q:r:S:s:T:u:U:v:W:x:t:P:"
#endif
#endif

#define	MALLOC(pointer) \
	if (!(pointer = strdup(optarg))) { \
		LP_ERRMSG (ERROR, E_LP_MALLOC); \
		done (1); \
	} else

#define	REALLOC(pointer) \
	if (!(pointer = realloc(pointer, (unsigned) (strlen(pointer) + 1 + strlen(optarg) + 1)))) { \
		LP_ERRMSG (ERROR, E_LP_MALLOC); \
		done (1); \
	} else if (strcat(pointer, " ")) \
		(void)strcat (pointer, optarg); \
	else

extern char		*optarg;

extern int		optind,
			opterr,
			optopt;

extern double		strtod();

extern long		strtol();

int			a	= 0,	/* alignment needed for mount */
			banner	= -1,	/* allow/don't-allow nobanner */
#if	defined(DIRECT_ACCESS)
			C	= 0,	/* direct a.o.t. normal access */
#endif
		filebreak	= 0,
		h	= 0,	/* hardwired terminal */
		j	= 0,	/* do -F just for current job */
		l	= 0,	/* login terminal */
		M	= 0,	/* do mount */
		t	= 0,	/* tray number*/
		o	= 0,	/* some -o options given */
		Q	= -1,	/* queue threshold for alert */
		W	= -1;	/* alert interval */

char		*A	= 0,	/* alert type */
		*c	= 0,	/* class name */
		*cpi	= 0,	/* string value of -o cpi= */
		*d	= 0,	/* default destination */
		*D	= 0,	/* description */
		*e	= 0,	/* copy existing interface */
		*f	= 0,	/* forms list - allow/deny */
		*P	= 0,	/* paper list  */
		*F	= 0,	/* fault recovery */
		**H	= 0,	/* list of modules to push */
		*i	= 0,	/* interface pathname */
		**I	= 0,	/* content-type-list */
		*length	= 0,	/* string value of -o length= */
		*lpi	= 0,	/* string value of -o lpi= */
		*m	= 0,	/* model name */
		modifications[128], /* list of mods to make */
#ifdef LP_USE_PAPI_ATTR
		*n_opt	= NULL,	/* PPD file name */
#endif
		*p	= 0,	/* printer name */
		*r	= 0,	/* class to remove printer from */
		*s	= 0,	/* system printer is on */
		*stty_opt= 0,	/* string value of -o stty= */
		**o_options = 0,/* undefined lpadmin -o options */
		**S	= 0,	/* -set/print-wheel list */
		**T	= 0,	/* terminfo names */
		*u	= 0,	/* user allow/deny list */
		*U	= 0,	/* dialer_info */
		*v	= 0,	/* device pathname */
		*width	= 0,	/* string value of -o width= */
		*x	= 0;	/* destination to be deleted */

SCALED		cpi_sdn = { 0, 0 },
		length_sdn = { 0, 0 },
		lpi_sdn = { 0, 0 },
		width_sdn = { 0, 0 };

static char	*modp	= modifications;

static void	oparse();

static char *	empty_list[] = { 0 };

/**
 ** options() - PARSE COMMAND LINE ARGUMENTS INTO OPTIONS
 **/

void			options (argc, argv)
	int			argc;
	char			*argv[];
{
	int		optsw,
			ac,
			Aflag = 0;

	char		*cp,
			*rest,
			**av;
	char		stroptsw[] = "-X";

#if	defined(__STDC__)
	typedef char * const *	stupid;	/* dumb-ass ANSI C */
#else
	typedef char **		stupid;
#endif


	/*
	 * Add a fake value to the end of the "argv" list, to
	 * catch the case that a valued-option comes last.
	 */
	av = malloc((argc + 2) * sizeof(char *));
	for (ac = 0; ac < argc; ac++)
		av[ac] = argv[ac];
	av[ac++] = "--";

	opterr = 0;
	while ((optsw = getopt(ac, (stupid)av, OPT_LIST)) != EOF) {

		switch (optsw) {

		/*
		 * These options MAY take a value. Check the value;
		 * if it begins with a '-', assume it's really the next
		 * option.
		 */
		case 'd':
		case 'p':	/* MR bl87-27863 */
		case 'I':
#if	defined(CAN_DO_MODULES)
		case 'H':
#endif
			if (*optarg == '-') {
				/*
				 * This will work if we were given
				 *
				 *	-x -foo
				 *
				 * but would fail if we were given
				 *
				 *	-x-foo
				 */
				optind--;
				switch (optsw) {
				case 'd':
#if	defined(CAN_DO_MODULES)
				case 'H':
#endif
					optarg = NAME_NONE;
					break;
				case 'p':
					optarg = NAME_ALL;
					break;
				case 'I':
					optarg = 0;
					break;
				}
			}
			break;

		/*
		 * These options MUST have a value. Check the value;
		 * if it begins with a dash or is null, complain.
		 */
		case 'Q':
		case 'W':
		case 't':
			/*
			 * These options take numeric values, which might
			 * be negative. Negative values are handled later,
			 * but here we just screen them.
			 */
			(void)strtol(optarg, &rest, 10);
			if (!rest || !*rest)
				break;
			/*FALLTHROUGH*/
		case 'A':
		case 'c':
		case 'e':
		case 'f':
		case 'P':
		case 'F':
		case 'i':
		case 'm':
#ifdef LP_USE_PAPI_ATTR
		case 'n':
#endif
		case 'o':
/*		case 'p': */	/* MR bl87-27863 */
		case 'r':
		case 'S':
		case 's':
		case 'T':
		case 'u':
		case 'U':
		case 'v':
		case 'x':
			/*
			 * These options also must have non-null args.
			 */
			if (!*optarg) {
				stroptsw[1] = optsw;
				LP_ERRMSG1 (ERROR, E_LP_NULLARG, stroptsw);
				done (1);
			}
			if (*optarg == '-') {
				stroptsw[1] = optsw;
				LP_ERRMSG1 (ERROR, E_LP_OPTARG, stroptsw);
				done (1);
			}
			if (optsw == 'A')
				Aflag++;
			break;
		case 'D':
			/*
			 * These options can have a null arg.
			 */
			if (*optarg == '-') {
				stroptsw[1] = optsw;
				LP_ERRMSG1 (ERROR, E_LP_OPTARG, stroptsw);
				done (1);
			}
			break;
		}

		switch (optsw) {

		case 'a':	/* alignment pattern needed for mount */
			a = 1;
			break;

		case 'A':	/* alert type */
			if (A)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'A');
			MALLOC(A);
			Aflag++;
			if (!STREQU(A, NAME_QUIET) && !STREQU(A, NAME_LIST))
				*modp++ = 'A';
			break;

		case 'c':	/* class to insert printer p */
			if (c)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'c');
			MALLOC(c);
		break;

#if	defined(DIRECT_ACCESS)
		case 'C':
			C = 1;
			break;
#endif

		case 'd':	/* system default destination */
			if (d)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'd');
			MALLOC(d);
			break;

		case 'D':	/* description */
			if (D)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'D');
			MALLOC(D);
			*modp++ = 'D';
			break;

		case 'e':	/* existing printer interface */
			if (e)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'e');
			MALLOC(e);
			*modp++ = 'e';
			break;

		case 'f':	/* set up forms allow/deny */
			if (f)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'f');
			MALLOC(f);
			break;

		case 'P':	/* set up forms allow/deny */
			if (P)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'P');
			MALLOC(P);
			break;

		case 'F':	/* fault recovery */
			if (F)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'F');
			MALLOC(F);
			*modp++ = 'F';
			break;

#if	defined(CAN_DO_MODULES)
		case 'H':
			if (H)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'H');
			if (!optarg || !*optarg || STREQU(NAME_NONE, optarg))
				H = empty_list;
			if (!(H = getlist(optarg, LP_WS, LP_SEP))) {
				LP_ERRMSG (ERROR, E_LP_MALLOC);
				done(1);
			}
			*modp++ = 'H';
			break;
#endif

		case 'h':	/* hardwired terminal */
			h = 1;
			*modp++ = 'h';
			break;

		case 'i':	/* interface pathname */
			if (i)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'i');
			MALLOC(i);
			*modp++ = 'i';
			break;

		case 'I':	/* content-type-list */
			if (I)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'I');
			if (!optarg || !*optarg || STREQU(NAME_NONE, optarg))
				I = empty_list;
			else if (!(I = getlist(optarg, LP_WS, LP_SEP))) {
				LP_ERRMSG (ERROR, E_LP_MALLOC);
				done (1);
			}
			*modp++ = 'I';
			break;

#if	defined(J_OPTION)
		case 'j':	/* fault recovery just for current job */
			j = 1;
(void) printf (gettext("Sorry, the -j option is currently broken\n"));
			break;
#endif

		case 'l':	/* login terminal */
			l = 1;
			*modp++ = 'l';
			break;

		case 'm':	/* model interface */
			if (m)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'm');
			MALLOC(m);
			*modp++ = 'm';
			break;

#ifdef LP_USE_PAPI_ATTR
		case 'n':	/* PPD file */
			if (n_opt)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'n');
			MALLOC(n_opt);
			*modp++ = 'n';
			break;
#endif

		case 'M':	/* a mount request */
			M = 1;
			break;

		case 'o':	/* several different options */
			oparse (optarg);
			o = 1;
			break;

		case 'p':	/* printer name */
			if (p)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'p');
			MALLOC(p);
			break;

		case 'Q':
			if (Q != -1)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'Q');
			if (STREQU(NAME_ANY, optarg))
				Q = 1;
			else {
				Q = strtol(optarg, &rest, 10);
				if (Q < 0) {
					LP_ERRMSG1 (ERROR, E_LP_NEGARG, 'Q');
					done (1);
				}
				if (rest && *rest) {
					LP_ERRMSG1 (ERROR, E_LP_GARBNMB, 'Q');
					done (1);
				}
				if (Q == 0) {
					LP_ERRMSG1 (ERROR, E_ADM_ZEROARG, 'Q');
					done (1);
				}
			}
			*modp++ = 'Q';
			break;

		case 'r':	/* class to remove p from */
			if (r)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'r');
			MALLOC(r);
			break;

		case 'S':	/* char_set/print-wheels */
			if (S)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'S');
			if (!(S = getlist(optarg, LP_WS, LP_SEP))) {
				LP_ERRMSG (ERROR, E_LP_MALLOC);
				done (1);
			}
			*modp++ = 'S';
			break;

		case 's':
			if (s)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 's');

			if ((cp = strchr(optarg, '!')))
				*cp = '\0';

			if ((STREQU(optarg, NAME_NONE)) ||
				(STREQU(optarg, "localhost")))

				s = Local_System;
			else if (STREQU(optarg, Local_System)) {
				if (cp) {
					LP_ERRMSG (ERROR, E_ADM_NAMEONLOCAL);
					done(1);
				} else
					s = Local_System;
			} else {
				if (cp)
				    *cp = '!';

				MALLOC(s);
			}

			/* 's' already used for stty 'R' for remote? */
			*modp++ = 'R';
			break;

		case 't':	/* tray number*/
			if (t != 0) LP_ERRMSG1 (WARNING, E_LP_2MANY, 't');
			t = strtol(optarg, &rest, 10);
			if (t <= 0) {
				LP_ERRMSG1 (ERROR, E_LP_NEGARG, 't');
				done (1);
			}
			if (rest && *rest) {
				LP_ERRMSG1 (ERROR, E_LP_GARBNMB, 't');
				done (1);
			}
			break;

		case 'T':	/* terminfo names for p */
			if (T)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'T');
			if (!(T = getlist(optarg, LP_WS, LP_SEP))) {
				LP_ERRMSG (ERROR, E_LP_MALLOC);
				done (1);
			}
			*modp++ = 'T';
			break;

		case 'u':	/* user allow/deny list */
			if (u)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'u');
			MALLOC(u);
			break;

		case 'U':	/* dialer_info */
			if (U)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'U');
			MALLOC(U);
			*modp++ = 'U';
			break;

		case 'v':	/* device pathname */
			if (v)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'v');
			MALLOC(v);
			*modp++ = 'v';
			break;

		case 'W':	/* alert interval */
			if (W != -1)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'W');
			if (STREQU(NAME_ONCE, optarg))
				W = 0;
			else {
				W = strtol(optarg, &rest, 10);
				if (W < 0) {
					LP_ERRMSG1 (ERROR, E_LP_NEGARG, 'W');
					done (1);
				}
				if (rest && *rest) {
					LP_ERRMSG1 (ERROR, E_LP_GARBNMB, 'W');
					done (1);
				}
			}
			*modp++ = 'W';
			break;

		case 'x':	/* destination to be deleted */
			if (x)
				LP_ERRMSG1 (WARNING, E_LP_2MANY, 'x');
			MALLOC(x);
			break;

		default:
			if (optopt == '?') {
				usage ();
				done (0);

			} else {
				stroptsw[1] = optsw;

				if (strchr(OPT_LIST, optopt))
					LP_ERRMSG1 (ERROR, E_LP_OPTARG,
					    stroptsw);
				else
					LP_ERRMSG1 (ERROR, E_LP_OPTION,
					    stroptsw);
				done (1);
			}
		}
	}

	if (optind < argc)
		LP_ERRMSG1 (WARNING, E_LP_EXTRA, argv[optind]);

	if ((v) && (!Aflag)) {
		if (!(A = strdup("write"))) {
			LP_ERRMSG (ERROR, E_LP_MALLOC);
			done (1);
		}
		*modp++ = 'A';
	}

	return;
}

/**
 ** oparse() - PARSE -o OPTION
 **/

static void		oparse (optarg)
	char			*optarg;
{
	register char		**list	= dashos(optarg);


	if (!list)
		return;

	for ( ; (optarg = *list); list++)

		if (STREQU(optarg, "banner")) {
			if (banner != -1)
				LP_ERRMSG1 (
					WARNING,
					E_ADM_2MANY,
					"banner/nobanner"
				);
			banner = BAN_ALWAYS;
			*modp++ = 'b';

		} else if (STREQU(optarg, "nobanner")) {
			if (banner != -1)
				LP_ERRMSG1 (
					WARNING,
					E_ADM_2MANY,
					"banner/nobanner"
				);
			banner = BAN_OPTIONAL;
			*modp++ = 'b';

		/* handle banner=(always|optional|never) */
		} else if (STRNEQU(optarg, "banner=", 7)) {
			char *ptr;

			ptr = (optarg += 7);
			if (banner != -1)
				LP_ERRMSG1 ( WARNING, E_ADM_2MANY,
				"banner/nobanner/banner=(always|optional|never)"
				);

			/* like "banner", always print a banner */
			if (strcasecmp(ptr, "always") == 0)
				banner = BAN_ALWAYS;
			/* like "nobanner", print a banner unless requested */
			if (strcasecmp(ptr, "optional") == 0)
				banner = BAN_OPTIONAL;
			/* never print a banner */
			if (strcasecmp(ptr, "never") == 0)
				banner = BAN_NEVER;
			*modp++ = 'b';

		} else if (STRNEQU(optarg, "length=", 7)) {
			if (length)
				LP_ERRMSG1 (
					WARNING,
					E_ADM_2MANY,
					"length="
				);
			length = (optarg += 7);

			if (!*optarg) {
				length_sdn.val = 0;
				length_sdn.sc = 0;

			} else {
				length_sdn = _getsdn(optarg, &optarg, 0);
				if (errno == EINVAL) {
					LP_ERRMSG (ERROR, E_LP_BADSCALE);
					done (1);
				}
			}
			*modp++ = 'L';

		} else if (STRNEQU(optarg, "width=", 6)) {
			if (width)
				LP_ERRMSG1 (
					WARNING,
					E_ADM_2MANY,
					"width="
				);
			width = (optarg += 6);

			if (!*optarg) {
				width_sdn.val = 0;
				width_sdn.sc = 0;

			} else {
				width_sdn = _getsdn(optarg, &optarg, 0);
				if (errno == EINVAL) {
					LP_ERRMSG (ERROR, E_LP_BADSCALE);
					done (1);
				}
			}
			*modp++ = 'w';

		} else if (STRNEQU(optarg, "cpi=", 4)) {
			if (cpi)
				LP_ERRMSG1 (WARNING, E_ADM_2MANY, "cpi=");

			cpi = (optarg += 4);

			if (!*optarg) {
				cpi_sdn.val = 0;
				cpi_sdn.sc = 0;

			} else {
				cpi_sdn = _getsdn(optarg, &optarg, 1);
				if (errno == EINVAL) {
					LP_ERRMSG (ERROR, E_LP_BADSCALE);
					done (1);
				}
			}
			*modp++ = 'c';

		} else if (STRNEQU(optarg, "lpi=", 4)) {
			if (lpi)
				LP_ERRMSG1 (WARNING, E_ADM_2MANY, "lpi=");
			lpi = (optarg += 4);

			if (!*optarg) {
				lpi_sdn.val = 0;
				lpi_sdn.sc = 0;

			} else {
				lpi_sdn = _getsdn(optarg, &optarg, 0);
				if (errno == EINVAL) {
					LP_ERRMSG (ERROR, E_LP_BADSCALE);
					done (1);
				}
			}
			*modp++ = 'M';

		} else if (STRNEQU(optarg, "stty=", 5)) {

			optarg += 5;
			if (!*optarg)
				stty_opt = 0;

			else {
				if (strchr(LP_QUOTES, *optarg)) {
					register int		len
							= strlen(optarg);

					if (optarg[len - 1] == *optarg)
						optarg[len - 1] = 0;
					optarg++;
				}
				if (stty_opt)
					REALLOC (stty_opt);
				else
					MALLOC (stty_opt);
			}
			*modp++ = 's';

		} else if (STREQU(optarg, "filebreak")) {
			filebreak = 1;

		} else if (STREQU(optarg, "nofilebreak")) {
			filebreak = 0;

		/* added support for using -o to pass any key=value pair */
		} else if (*optarg) {

			if ((addlist(&o_options, optarg)) != 0) {
				fprintf(stderr, gettext("System Error %d\n"), errno);
			}

			*modp++ = 'o';
			optarg++;
		}

	return;
}
