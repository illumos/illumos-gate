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

/*    Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	All Rights Reserved */

#include	<sys/types.h>
#include	<sys/param.h>
#include	<stdio.h>
#include	<errno.h>
#include	<stdlib.h>
#include	<string.h>
#include	<fmtmsg.h>
#include	<devmgmt.h>
#include	<devtab.h>
#include	<values.h>

/*
 *  Local definitions
 *	TRUE		Boolean TRUE value
 *	FALSE		Boolean FALSE value
 *	TOKDELIMS	Char string of delimiters for lists
 */

#ifndef		TRUE
#define		TRUE		('t')
#endif

#ifndef		FALSE
#define		FALSE		0
#endif

#define		TOKDELIMS	", \t\n"


/*
 *  Exit codes:
 *	EX_OK		Exit code for all went well
 *	EX_ERROR	Exit code for something failed
 *	EX_TABLES	A table couldn't be accessed
 *	EX_NOALLOC	Exit code for allocation failed
 */

#define		EX_OK		0
#define		EX_ERROR	1
#define		EX_TABLES	2
#define		EX_NOALLOC	3

/*
 *  Messages:
 *	M_USAGE		Usage error
 *	M_INVKEY	Invalid key specified
 *	M_ERROR		Some strange error
 *	M_UNABLE	A list of devices is unavailable
 *	M_DEVTAB	Can't access device table (for reading)
 *	M_RSVTAB	Can't access device reservation table (for r/w)
 *	M_NODEV		A list of devices is invalid
 */

#define	M_USAGE		"usage: devreserv [key [devicelist [...]]]"
#define	M_INVKEY	"Invalid key: %s"
#define	M_ERROR		"Internal error, errno=%d"
#define	M_UNABLE	"Cannot reserve devices"
#define	M_DEVTAB	"Cannot open the device table: %s"
#define	M_RSVTAB	"Cannot open the device-reservation table: %s"
#define	M_NODEV		M_UNABLE


/*
 *  Local functions and static data
 *
 *	buildreqlist()	Builds the list of requested devices for devreserv()
 *	freereqlist()	Free space allocated to the list of requested devices
 *	ndevsin()	Get number of elements in a list
 *	stdmsg(r,l,s,m)	Standard message generation
 *			r	Recoverability flag
 *			l	Label
 *			s	Severity
 *			m	Message
 *
 *	lbl		Buffer for the label-component of a message
 *	txt		Buffer for the text-component of a message
 */

static char  ***buildreqlist();
static void	freereqlist();
static int	ndevsin();

#define	stdmsg(r, l, s, m)	\
	(void) fmtmsg(MM_PRINT | MM_UTIL | r, l, s, m, MM_NULLACT, MM_NULLTAG)

static	char	lbl[MM_MXLABELLN+1];
static	char	txt[MM_MXTXTLN+1];

/*
 *  devreserv [key [devlist [devlist [...]]]]
 *
 *	This command reserves sets of devices known to the OA&M device
 *	management system.  It reserves a device from each of the device
 *	lists presented to it, reserving them on the key (<key>).  If no
 *	device-lists are provided, the command lists those devices reserved
 *	on the given key (<key>).  If no key (<key>) is provided, the
 *	command lists all devices currently reserved.
 *
 *  Options:  None
 *
 *  Arguments:
 *	key		Key to lock the devices on
 *	devlist		A comma-, space-, or tab-list containing devices
 *			(pathnames or aliases).  For typical shells, space-
 *			and tab-lists should be quoted or the separator should
 *			be somehow escaped.
 *
 *  Command Values:
 *	EX_OK		0	Device(s) successfully allocated
 *	EX_ERROR	1	A syntax or other error occurred
 *	EX_TABLES	2	Either the device-table or the device-
 *				reservation table couldn't be opened as needed
 *	EX_NOALLOC	3	The device-reservation request couldn't be
 *				fulfilled.
 */

int
main(int argc, char *argv[])
{

	/* Automatics */
	char			***reqlist;	/* * to list of lists */
	char			**argp;		/* Ptr to current argument */
	char			**alloclist;	/* List of allocated devices */
	char			**pp;		/* Temp ptr to char ptrs */
	struct reservdev	**rsvd;		/* Ptr to list of rsvd devs */
	struct reservdev	**plk;		/* Running ptr to locks */
	char			*p;		/* Temp char ptr */
	char			*devtab;	/* Device table pathname */
	char			*rsvtab;	/* Dev-rsv tbl pathname */
	int			argcount;	/* Number of args on cmd */
	long			lkey;		/* Key for locking (long) */
	int			key;		/* Key for locking */
	int			exitcode;	/* Value to return */
	int			sev;		/* Message severity */
	int			syntaxerr;	/* Flag, TRUE if syntax error */
	int			c;		/* Option character */
	int			i;		/* Temp counter */
	const char		*errstr;


	/*
	 * Initializations
	 */

	/* Build a message label */
	if (p = strrchr(argv[0], '/')) p++;
	else p = argv[0];
	(void) strlcat(strcpy(lbl, "UX:"), p, sizeof (lbl));


	/*
	 * Allow only the text component of messages to be written
	 * (this will probably go away in SVR4.1)
	 */

	(void) putenv("MSGVERB=text");


	/*
	 * Parse the options from the command line
	 */

	opterr = 0;
	syntaxerr = FALSE;
	while ((c = getopt(argc, argv, "")) != EOF)
		switch (c) {
		default:
			syntaxerr = FALSE;
			break;
		}

	/* If there's (an obvious) syntax error, write a message and quit */
	if (syntaxerr) {
		stdmsg(MM_NRECOV, lbl, MM_ERROR, M_USAGE);
		exit(EX_ERROR);
	}

	/* Argument initializations */
	argcount = argc - optind;
	argp = &argv[optind];


	/*
	 *  devreserv
	 *
	 *	If euid == 0, write a list of all currently allocated devices.
	 */

	if (argcount == 0) {

		/* Get the list of reserved devices */
		if (rsvd = reservdev()) {

			/*
			 * Write the list of reserved devices with the key
			 * that the device was locked on.  The key should go
			 * in column 16, but separate it from the alias with at
			 * least one space
			 */

			exitcode = EX_OK;
			for (plk = rsvd; *plk; plk++) {
				if ((i = fputs((*plk)->devname, stdout)) >= 0)
					do {
						(void) fputc(' ', stdout);
					} while (++i < 16);
				(void) fprintf(stdout, "%ld\n", (*plk)->key);
			}

		} else {

			/* Problems getting the list of reserved devices */
			if (((errno == EINVAL) || (errno == EACCES)) &&
			    (rsvtab = _rsvtabpath())) {
				(void) snprintf(txt, sizeof (txt), M_RSVTAB,
				    rsvtab);
				exitcode = EX_TABLES;
				sev = MM_ERROR;
			} else {
				(void) sprintf(txt, M_ERROR, errno);
				exitcode = EX_ERROR;
				sev = MM_HALT;
			}
			stdmsg(MM_NRECOV, lbl, sev, txt);
		}

		/* Finished */
		exit(exitcode);
	}


	/*
	 *  devreserv key
	 *
	 *	Generate a list of the devices allocated on a specific key.
	 */

	if (argcount == 1) {

		/* Extract the key from the command */
		lkey = strtonum(*argp, 1, MAXINT, &errstr);
		if (errstr != NULL) {

			/* <key> argument invalid */
			(void) snprintf(txt, sizeof (txt), M_INVKEY, *argp);
			stdmsg(MM_NRECOV, lbl, MM_ERROR, txt);
			exitcode = EX_ERROR;

		} else {

			key = (int)lkey;

			/* Get the list of reserved devices ... */
			if (rsvd = reservdev()) {

				/*
				 * For each reserved device, write the alias
				 * to stdout
				 */
				exitcode = EX_OK;
				for (plk = rsvd; *plk; plk++) {
					if ((*plk)->key == key)
						(void) puts((*plk)->devname);
				}

			} else {

				/*
				 * Problems getting the list of reserved
				 * devices
				 */
				if (((errno == EINVAL) || (errno == EACCES)) &&
				    (rsvtab = _rsvtabpath())) {
					(void) snprintf(txt, sizeof (txt),
					    M_RSVTAB, rsvtab);
					exitcode = EX_TABLES;
					sev = MM_ERROR;
				} else {
					(void) sprintf(txt, M_ERROR, errno);
					exitcode = EX_ERROR;
					sev = MM_HALT;
				}
				stdmsg(MM_NRECOV, lbl, sev, txt);
			}
		}

		/* Finished */
		exit(exitcode);
	}


	/*
	 *  devreserv key devlist [...]
	 *
	 *	Reserve specific devices
	 */

	/* Open the device file (if there's one to be opened) */
	if (!_opendevtab("r")) {
		if (devtab = _devtabpath()) {
			(void) snprintf(txt, sizeof (txt), M_DEVTAB, devtab);
			exitcode = EX_TABLES;
			sev = MM_ERROR;
		} else {
			(void) sprintf(txt, M_ERROR, errno);
			exitcode = EX_ERROR;
			sev = MM_HALT;
		}
		stdmsg(MM_NRECOV, lbl, sev, txt);
		exit(exitcode);
	}

	/* Extract the key from the command */
	lkey = strtonum(*argp, 1, MAXINT, &errstr);
	if (errstr != NULL) {
		(void) snprintf(txt, sizeof (txt), M_INVKEY, *argp);
		stdmsg(MM_NRECOV, lbl, MM_ERROR, txt);
		exit(EX_ERROR);
	}

	key = (int)lkey;
	argp++;

	/* Build the device request list from the command arguments */
	if (reqlist = buildreqlist(argp)) {

		/* Attempt to allocate the devices */
		if (alloclist = devreserv(key, reqlist)) {

			/*
			 * For each allocated device, write the alias to stdout
			 * and free the space allocated for the string.
			 */

			for (pp = alloclist; *pp; pp++) {
				(void) puts(*pp);
				free(*pp);
			}

			/* Free the list of allocated devices */
			free(alloclist);
			exitcode = EX_OK;
		} else {
			/* Device allocation failed */
			if (errno == EAGAIN) {
				stdmsg(MM_NRECOV, lbl, MM_ERROR, M_UNABLE);
				exitcode = EX_NOALLOC;
			} else if (errno == ENODEV) {
				stdmsg(MM_NRECOV, lbl, MM_ERROR, M_NODEV);
				exitcode = EX_NOALLOC;
			} else {
				(void) sprintf(txt, M_ERROR, errno);
				stdmsg(MM_NRECOV, lbl, MM_HALT, txt);
				exitcode = EX_ERROR;
			}
		}
		freereqlist(reqlist);
	}


	/* Exit with the appropriate code */
	return (exitcode);
}

/*
 * char ***buildreqlist(args)
 *	char   **args
 *
 *	Build the list of lists of devices to request, as described by the
 *	arguments on the command line.
 *
 *  Arguments:
 *	char **args	The address of the first argument of the list of
 *			lists of devices to allocate.   (This list is
 *			terminated with a (char *) NULL.)
 *
 *  Returns:  char ***
 *	A pointer to a list containing addresses of lists of pointers to
 *	character-strings, as expected by "devreserv()"
 *
 *  Notes:
 *    -	Assuming that strtok() won't return "".  If it does, the
 *	parsing algorithm needs to be enhanced a bit to eliminate
 *	these cases.
 */

static char ***
buildreqlist(char **args)
{
	/* Local automatic data */
	char		***addrlist;	/* Addr of space for ptrs to lists */
	char		***ppp;		/* Pointer to pointers to pointers */
	char		**pp;		/* Pointer to pointers */
	char		**qq;		/* Pointer to pointers */
	int		noerror;	/* FLAG, TRUE if all's well */
	int		i;		/* Counter */
	int		n;		/* Another counter */


	/* Count the number of lists we have to work with */
	i = 1;
	for (pp = args; *pp; pp++)
		i++;


	/* If we can allocate space for the list of lists ... */
	if (addrlist = malloc(i * sizeof (char **))) {

		/* Parse each list, putting that list in the list of lists */
		ppp = addrlist;
		noerror = TRUE;
		for (pp = args; noerror && *pp; pp++) {
			n = ndevsin(*pp, TOKDELIMS);
			if (*ppp = malloc((n + 1) * sizeof (char *))) {
				qq = *ppp++;
				if (*qq++ = strtok(*pp, TOKDELIMS))
					while (*qq++ = strtok(NULL, TOKDELIMS))
						;
			} else {
				noerror = FALSE;
			}
		}

		/* If there was an error, clean up the malloc()s we've made */
		if (!noerror) {
			freereqlist(addrlist);
			addrlist = NULL;
		}
	}

	/* Return ptr to the list of addresses of lists (or NULL if none) */
	return (addrlist);
}

/*
 *  void freereqlist(list)
 *	char ***list
 *
 *	This function frees the space allocated to the list of lists
 *	referenced by <list>
 *
 *  Arguments:
 *	char ***list	Address of the list of lists
 *
 *  Returns:  void
 */

static void
freereqlist(char ***list)
{
	char ***ppp;
	if (list) {
		for (ppp = list; *ppp; ppp++)
			free(*ppp);
		free(list);
	}
}

/*
 * int ndevsin(list, delims)
 *	char   *list
 *	char   *delims
 *
 *	This function determines how many tokens are in the list <list>.
 *	The tokens are delimited by fields of characters in the string
 *	<delims>.  It returns the number of tokens in the list.
 *
 *  Arguments:
 *	char *list	The <delims>list of tokens to scan
 *	char *delims	The list of delimiters that define the list
 *
 *  Returns: int
 *	The number of elements in the list.
 *
 *  Notes:
 *    -	This function does not recognize "null" elements.  For example,
 *	a,b,,,,c,,d contains 4 elememts (if delims contains a ',')
 */

static int
ndevsin(char *list, char *delims)
{
	char   *p;			/* Running character pointer */
	int	count;			/* Number of tokens seen so far */
	int	tokflag;		/* TRUE if we're parsing a token */

	count = 0;			/* None seen yet */
	tokflag = FALSE;		/* Not in a token */

	/* Scan the character-string containing the list of tokens */
	for (p = list; *p; p++) {

		/* If a delimiter, we're not in a token */
		if (strchr(delims, *p)) {
			tokflag = FALSE;

		} else if (!tokflag) {
			/*
			 * Otherwise, if we weren't in a token,
			 * we've found one
			 */
			tokflag = TRUE;
			count++;
		}
	}

	/* Return the number of elements in the list */
	return (count);
}
