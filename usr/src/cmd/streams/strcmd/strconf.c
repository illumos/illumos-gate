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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5	*/

/*
 * Streams Command strconf:	display the configuration of the
 *				stream associated with stdin.
 *
 * USAGE:	strconf
 *    or:	strconf -m module
 *    or:	strconf -t
 *
 * strconf with no options lists the modules on the stream.
 * -m module	echos "yes" and returns 0 if the module is on the stream.
 *		echos "no" and returns 2 if not.
 * -t		lists only the topmost module.  returns 0 if there is a
 *		module, 2 if not.
 *
 * RETURNS:
 *	0	SUCCESS		it works
 *	1	ERR_USAGE	bad invocation
 *	2	ERR_MODULE	module not there
 *	3	ERR_STDIN	an ioctl on the stdin stream failed
 *	4	ERR_MEM		couldn't allocate memory
 */

#include	<stdio.h>
#include	<sys/stropts.h>
#include	<string.h>
#include	<stdlib.h>
#include	<unistd.h>

#define	OPTLIST		"m:t"
#define	USAGE		"USAGE: %s [ -m module | -t ]\n"

#define	SUCCESS		0
#define	FAILURE		1

#define	ERR_USAGE	1	/* bad invocation			*/
#define	ERR_MODULE	2	/* module not there			*/
#define	ERR_STDIN	3	/* an ioctl on the stdin stream failed	*/
#define	ERR_MEM		4	/* couldn't allocate memory		*/

#define	NMODULES	16	/* "reasonable" # of modules on a stream  */
				/* 	(there can be more)		  */
#define	MAXMODULES	2048	/* max # of modules			  */

static char	*Cmd_namep;		/* how was it invoked?	*/
static int	more_modules(struct str_list *, int);

int
main(int argc, char **argv)
{
	char		*modp;		/* ptr to module name		*/
	int		i;		/* loop var & junk (what else?)	*/
	boolean_t	mod_present;	/* B_TRUE if -m module		*/
	boolean_t	topmost;	/* B_TRUE if -t			*/
	struct str_mlist mlist[NMODULES]; /* modlist for strlist	*/
	struct str_list	strlist;	/* mods on stream		*/

	/*
	 *	init
	 */
	Cmd_namep = argv[0];
	mod_present = topmost = B_FALSE;
	strlist.sl_nmods = NMODULES;
	strlist.sl_modlist = mlist;

	/*
	 *	parse args
	 */
	if (argc > 1) {
		while ((i = getopt(argc, argv, OPTLIST)) != -1) {
			switch (i) {
			case 'm':	/* module present ? */
				modp = optarg;
				mod_present = B_TRUE;
				break;

			case 't':	/* list topmost	*/
				topmost = B_TRUE;
				break;

			default:
				(void) fprintf(stderr, USAGE, Cmd_namep);
				return (ERR_USAGE);
			}
		}

		if (optind < argc) {
			(void) fprintf(stderr, USAGE, Cmd_namep);
			return (ERR_USAGE);
		}
	}

	if (topmost && mod_present) {
		(void) fprintf(stderr,
		    "%s: [-t] and [-m] options cannot be used together\n",
		    Cmd_namep);
		(void) fprintf(stderr, USAGE, Cmd_namep);
		return (ERR_USAGE);
	}

	/*
	 * get number of modules on stream
	 * allocate more room if needed
	 */
	if ((i = ioctl(STDIN_FILENO, I_LIST, NULL)) < 0) {
		perror("I_LIST");
		(void) fprintf(stderr,
			"%s: I_LIST ioctl failed\n", Cmd_namep);
		return (ERR_STDIN);
	}
	if (i > strlist.sl_nmods)
		if (more_modules(&strlist, i) != SUCCESS)
			return (ERR_MEM);

	/*
	 *	get list of modules on stream
	 */
	strlist.sl_nmods = i;
	if (ioctl(STDIN_FILENO, I_LIST, &strlist) < 0) {
		perror("I_LIST");
		(void) fprintf(stderr, "%s: I_LIST ioctl failed\n", Cmd_namep);
		return (ERR_STDIN);
	}

	/*
	 *	list topmost module
	 */
	if (topmost) {
		if (strlist.sl_nmods >= 2) {
			(void) puts(strlist.sl_modlist[0].l_name);
			return (SUCCESS);
		}
		return (ERR_MODULE);
	}

	/*
	 *	check if module is present
	 */
	if (mod_present) {
		for (i = 0; i < strlist.sl_nmods; i++) {
			if (strncmp(modp, strlist.sl_modlist[i].l_name,
			    FMNAMESZ) == 0) {
				(void) puts("yes");
				return (SUCCESS);
			}
		}
		(void) puts("no");
		return (ERR_MODULE);
	}

	/*
	 *	print names of all modules and topmost driver on stream
	 */
	for (i = 0; i < strlist.sl_nmods; i++)
		(void) puts(strlist.sl_modlist[i].l_name);
	return (SUCCESS);
}

/*
 * more_modules(listp, n)	allocate space for 'n' modules in 'listp'
 *
 * returns:	SUCCESS or FAILURE
 */

static int
more_modules(struct str_list *listp, int n)
{
	int			i;
	struct str_mlist	*modp;

	if (n > MAXMODULES) {
		(void) fprintf(stderr,
		    "%s: too many modules (%d) -- max is %d\n",
		    Cmd_namep, n, MAXMODULES);
		return (FAILURE);
	}

	if ((modp = calloc(n, sizeof (struct str_mlist))) == NULL) {
		perror("calloc");
		(void) fprintf(stderr,
		    "%s: failed to allocate space for module list\n",
		    Cmd_namep);
		return (FAILURE);
	}

	for (i = 0; i < listp->sl_nmods; ++i)
		(void) strncpy(modp[i].l_name, listp->sl_modlist[i].l_name,
		    FMNAMESZ);
	listp->sl_nmods = n;
	listp->sl_modlist = modp;
	return (SUCCESS);
}
