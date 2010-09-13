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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.6	*/

/*
 * Streams Command strchg:	change the configuration of the
 *				stream associated with stdin.
 *
 * USAGE:	strchg -h module1[,module2,module3 ...]
 *    or:	strchg -p
 *    or:	strchg -p -a
 *    or:	strchg -p -u module
 *    or:	strchg -f file
 *
 * -h		pusHes the named module(s) onto the stdin stream
 * -p		poPs the topmost module from the stdin stream
 * -p -a	poPs All modules
 * -p -u module	poPs all modules Up to, but not including, the named module
 * -f file	reads a list of modules from the named File, pops all modules,
 *		then pushes the list of modules
 *
 * RETURNS:
 *	0	SUCCESS		it worked
 *	1	ERR_USAGE	bad invocation
 *	2	ERR_MODULE	bad module name(s)
 *	3	ERR_STDIN	an ioctl or stat on the stdin stream failed
 *	4	ERR_MEM		couldn't allocate memory
 *	5	ERR_OPEN	couldn't open file in -f opt
 *	6	ERR_PERM	not owner or superuser
 *
 */


#include <stdio.h>
#include <sys/stropts.h>
#include <sys/termio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define	FALSE		0
#define	TRUE		1

#define	SUCCESS		0
#define	FAILURE		1

#define	NMODULES	16	/* "reasonable" # of modules to push	  */
				/* 	(can push more if you like)	  */
#define	MAXMODULES	2048	/* max # of modules to push		  */

#define	OPTLIST		"af:h:pu:"
#define	USAGE		"Usage:\t%s -h module1[,module2 ... ]\n\t%s -f file"\
			"\n\t%s -p [-a | -u module ]\n"

#define	ERR_USAGE	1	/* bad invocation			  */
#define	ERR_MODULE	2	/* bad module name(s) or too many modules */
#define	ERR_STDIN	3	/* an ioctl or stat on stdin failed	  */
#define	ERR_MEM		4	/* couldn't allocate memory		  */
#define	ERR_OPEN	5	/* couldn't open file in -f opt		  */
#define	ERR_PERM	6	/* not owner or superuser		  */

#define	STDIN		0

static char		*Cmd_namep;		/* how was it invoked?	*/
static struct str_mlist	Oldmods[NMODULES];	/* modlist for Oldlist	*/
static struct str_list	Oldlist;		/* original modules	*/

static int	pop_modules(int);
static int	push_module(const char *);
static int	more_modules(struct str_list *, int);
static void	restore(int, int);

int
main(int argc, char **argv)
{
	char		buf[BUFSIZ];	/* input buffer			*/
	char 		*file_namep;	/* file from -f opt		*/
	char		*modnamep;	/* mods from -h or -u opt	*/
	char		*modp;		/* for walking thru modnamep	*/

	FILE		*fp;		/* file pointer for -f file	*/

	int		i;		/* loop index and junk var	*/
	int		j;		/* loop index and junk var	*/
	int		euid;		/* effective uid		*/

	short		error;		/* TRUE if usage error		*/
	short		fromfile;	/* TRUE if -f file		*/
	short		is_a_tty;	/* TRUE if TCGETA succeeds	*/
	short		pop;		/* TRUE if -p			*/
	short		popall;		/* TRUE if -p -a		*/
	short		popupto;	/* TRUE if -p -u module		*/
	short		push;		/* TRUE if -h mod1[,mod2 ...]	*/

	struct str_mlist newmods[NMODULES]; /* mod list for new list	*/
	struct stat	stats;		/* stream stats			*/
	struct str_list	newlist;	/* modules to be pushed		*/
	struct termio	termio;		/* save state of tty		*/

	/*
	 *	init
	 */

	Cmd_namep = argv[0];
	error = fromfile = is_a_tty = pop = popall = popupto = push = FALSE;
	Oldlist.sl_modlist = Oldmods;
	Oldlist.sl_nmods = NMODULES;
	newlist.sl_modlist = newmods;
	newlist.sl_nmods = NMODULES;

	/*
	 *	only owner and root can change stream configuration
	 */
	if ((euid = geteuid()) != 0) {
		if (fstat(0, &stats) < 0) {
			perror("fstat");
			(void) fprintf(stderr, "%s: fstat of stdin failed\n",
				Cmd_namep);
			return (ERR_STDIN);
		}
		if (euid != stats.st_uid) {
			(void) fprintf(stderr,
				"%s: not owner of stdin\n", Cmd_namep);
			return (ERR_PERM);
		}
	}


	/*
	 *	parse args
	 */

	if (argc == 1) {
		(void) fprintf(stderr, USAGE, Cmd_namep, Cmd_namep, Cmd_namep);
		return (ERR_USAGE);
	}

	while (!error && (i = getopt(argc, argv, OPTLIST)) != -1) {

		switch (i) {

		case 'a':				/* pop All	*/
			if (fromfile || popupto || push)
				error = TRUE;
			else
				popall = TRUE;
			break;

		case 'f':				/* read from File */
			if (pop || push)
				error = TRUE;
			else {
				fromfile = TRUE;
				file_namep = optarg;
			}
			break;

		case 'h':				/* pusH		*/
			if (fromfile || pop)
				error = TRUE;
			else {
				push = TRUE;
				modnamep = optarg;
			}
			break;

		case 'p':				/* poP		*/
			if (fromfile || push)
				error = TRUE;
			else
				pop = TRUE;
			break;

		case 'u':				/* pop Upto	*/
			if (fromfile || popall || push)
				error = TRUE;
			else {
				popupto = TRUE;
				modnamep = optarg;
			}
			break;

		default:
			(void) fprintf(stderr,
				USAGE, Cmd_namep, Cmd_namep, Cmd_namep);
			return (ERR_USAGE);
			/*NOTREACHED*/
		}
	}

	if (error || optind < argc)  {
		(void) fprintf(stderr, USAGE, Cmd_namep, Cmd_namep, Cmd_namep);
		return (ERR_USAGE);
	}

	if (!pop && (popall || popupto)) {
		(void) fprintf(stderr,
		    "%s: -p option must be used with -a or -u to pop modules\n",
		    Cmd_namep);
		(void) fprintf(stderr, USAGE, Cmd_namep, Cmd_namep, Cmd_namep);
		return (ERR_USAGE);
	}


	/*
	 * Save state so can restore if something goes wrong
	 * (If are only going to push modules, don't need to
	 * save original module list for restore.)
	 */
	if (fromfile || pop) {

		/*
		 * get number of modules on stream
		 * allocate more room if needed
		 */
		if ((i =  ioctl(STDIN, I_LIST, NULL)) < 0) {
			perror("I_LIST");
			(void) fprintf(stderr,
				"%s: I_LIST ioctl failed\n", Cmd_namep);
			return (ERR_STDIN);
		}
		if (i > Oldlist.sl_nmods &&
		    more_modules(&Oldlist, i) != SUCCESS)
				return (ERR_MEM);

		/*
		 * get list of modules on stream
		 */
		Oldlist.sl_nmods = i;
		if (ioctl(STDIN, I_LIST, &Oldlist) < 0) {
			perror("I_LIST");
			(void) fprintf(stderr,
				"%s: I_LIST ioctl failed\n", Cmd_namep);
			return (ERR_STDIN);
		}

		/*
		 * The following attempts to avoid leaving a
		 * terminal line that does not respond to anything
		 * if the strchg -h or -f options failed due to
		 * specifying invalid module names for pushing
		 */
		if (ioctl(STDIN, TCGETA, &termio) >= 0)
			is_a_tty = TRUE;
	}


	/*
	 *	push modules on stream
	 */
	if (push) {
		/*
		 * pull mod names out of comma-separated list
		 */
		for (i = 0, modp = strtok(modnamep, ",");
		    modp != NULL; ++i, modp = strtok(NULL, ",")) {
			if (push_module(modp) == FAILURE) {
				/* pop the 'i' modules we just added */
				restore(i, 0);
				return (ERR_STDIN);
			}
		}
		return (SUCCESS);
	}

	/*
	 *	read configuration from a file
	 */
	if (fromfile) {

		if ((fp = fopen(file_namep, "r")) == NULL) {
			perror("fopen");
			(void) fprintf(stderr,
				"%s: could not open file '%s'\n",
				Cmd_namep, file_namep);
			return (ERR_OPEN);
		}

		/*
		 * read file and construct a new strlist
		 */
		i = 0;
		while (fgets(buf, BUFSIZ, fp) != NULL) {

			if (buf[0] == '#')
				continue;	/* skip comments */

			/*
			 * skip trailing newline, trailing and leading
			 * whitespace
			 */
			if ((modp = strtok(buf, " \t\n")) == NULL)
				continue;	/* blank line */

			(void) strncpy(newlist.sl_modlist[i].l_name,
			    modp, FMNAMESZ);
			++i;
			if ((modp = strtok(NULL, " \t\n")) != NULL) {
				/*
				 * bad format
				 * should only be one name per line
				 */
				(void) fprintf(stderr,
				    "%s: error on line %d in file %s: "
				    "multiple module names??\n",
				    Cmd_namep, i, file_namep);
				return (ERR_MODULE);
			}
			if (i > newlist.sl_nmods)
				if (more_modules(&newlist, i) != SUCCESS)
					return (ERR_MEM);
		}
		newlist.sl_nmods = i;

		/*
		 * If an empty file, exit silently
		 */
		if (i == 0)
			return (SUCCESS);

		/*
		 * Pop all modules currently on the stream.
		 */
		if ((i = pop_modules(Oldlist.sl_nmods - 1))
		    != (Oldlist.sl_nmods - 1)) {
			/* put back whatever we've popped */
			restore(0, i);
			return (ERR_STDIN);
		}

		/*
		 * Push new modules
		 */
		for (i = newlist.sl_nmods - 1; i >= 0; --i) {
			if (push_module(newlist.sl_modlist[i].l_name) ==
			    FAILURE) {

				/*
				 * pop whatever new modules we've pushed
				 * then push old module list back on
				 */
				restore((newlist.sl_nmods - 1 - i),
				    (Oldlist.sl_nmods - 1));

				/*
				 * If the stream is a tty line, at least try
				 * to set the state to what it was before.
				 */
				if (is_a_tty &&
				    ioctl(STDIN, TCSETA, &termio) < 0) {
					perror("TCSETA");
					(void) fprintf(stderr,
					    "%s: WARNING: Could not restore "
					    "the states of the terminal line "
					    "discipline\n", Cmd_namep);
				}
				return (ERR_STDIN);
			}
		}
		return (SUCCESS);
	}	/* end if-fromfile */


	/*
	 *	pop all modules (except driver)
	 */
	if (popall) {
		if (Oldlist.sl_nmods > 1) {
			if ((i = pop_modules(Oldlist.sl_nmods - 1)) !=
			    (Oldlist.sl_nmods - 1)) {
				restore(0, i);
				return (ERR_STDIN);
			}
		}
		return (SUCCESS);
	}

	/*
	 *	pop up to (but not including) a module
	 */
	if (popupto) {
		/*
		 * check that the module is in fact on the stream
		 */
		for (i = 0; i < Oldlist.sl_nmods; ++i)
			if (strncmp(Oldlist.sl_modlist[i].l_name, modnamep,
			    FMNAMESZ) == 0)
				break;
		if (i == Oldlist.sl_nmods) {
			/* no match found */
			(void) fprintf(stderr, "%s: %s not found on stream\n",
							Cmd_namep, modnamep);
			return (ERR_MODULE);
		}

		if ((j = pop_modules(i)) != i) {
			/* put back whatever we've popped */
			restore(0, j);
			return (ERR_STDIN);
		}
		return (SUCCESS);
	}

	/*
	 *	pop the topmost module
	 */
	if (pop) {
		if (Oldlist.sl_nmods > 1)
			if (pop_modules(1) != 1)
				/* no need to restore */
				return (ERR_STDIN);
		return (SUCCESS);
	}

	return (SUCCESS);
}

/*
 * pop_module(n)		pop 'n' modules from stream
 *
 * returns # of modules popped
 */
static int
pop_modules(int num_modules)
{
	int i;

	for (i = 0; i < num_modules; i++) {
		if (ioctl(STDIN, I_POP, 0) < 0) {
			perror("I_POP");
			(void) fprintf(stderr,
			    "%s: I_POP ioctl failed\n", Cmd_namep);
			return (i);
		}
	}
	return (i);
}

/*
 * push_module(modnamep)	pushes 'modnamep' module on stream
 *
 * returns SUCCESS or FAILURE
 */
static int
push_module(const char *modnamep)
{
	if (ioctl(STDIN, I_PUSH, modnamep) < 0) {
		perror("I_PUSH");
		(void) fprintf(stderr,
		    "%s: I_PUSH ioctl of %s failed\n", Cmd_namep, modnamep);
		return (FAILURE);
	}
	return (SUCCESS);
}


/*
 * restore(npop, npush)		restore original state of stream
 *
 * pops 'npop' modules, then pushes the topmost 'npush' modules from
 * Oldlist
 *
 */
static void
restore(int npop, int npush)
{
	int	i;

	if ((i = pop_modules(npop)) != npop) {
		(void) fprintf(stderr,
		    "%s: WARNING: could not restore state of stream\n",
		    Cmd_namep);
		return;
	}

	if (npush >= Oldlist.sl_nmods) {	/* "cannot" happen */
		(void) fprintf(stderr,
		    "%s: internal logic error in restore\n", Cmd_namep);
		(void) fprintf(stderr,
		    "%s: WARNING: could not restore state of stream\n",
		    Cmd_namep);
		return;
	}

	for (i = npush - 1; i >= 0; --i) {
		if (push_module(Oldlist.sl_modlist[i].l_name) == FAILURE) {
			(void) fprintf(stderr,
			    "%s: WARNING: could not restore state of stream\n",
			    Cmd_namep);
			return;
		}
	}
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
