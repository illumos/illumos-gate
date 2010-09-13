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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * users.c
 *
 *	This file contains the source for the administrative command
 *	"listusers" (available to the general user population) that
 *	produces a report containing user login-IDs and their "free
 *	field" (typically contains the user's name and other information).
 */

/*
 *  Header files referenced:
 *	sys/types.h	System type definitions
 *	stdio.h		Definitions for standard I/O functions and constants
 *	string.h	Definitions for string-handling functions
 *	grp.h		Definitions for referencing the /etc/group file
 *	pwd.h		Definitions for referencing the /etc/passwd file
 *	varargs.h	Definitions for using a variable argument list
 *	fmtmsg.h	Definitions for using the standard message formatting
 *			facility
 */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <fmtmsg.h>
#include <stdlib.h>


/*
 *  Externals referenced (and not defined by a header file):
 *	malloc		Allocate memory from main memory
 *	getopt		Extract the next option from the command line
 *	optind		The argument count of the next option to extract from
 *			the command line
 *	optarg		A pointer to the argument of the option just extracted
 *			from the command line
 *	opterr		FLAG:  !0 tells getopt() to write an error message if
 *			it detects an error
 *	getpwent	Get next entry from the /etc/passwd file
 *	getgrent	Get next entry from the /etc/group file
 *	fmtmsg		Standard message generation facility
 *	putenv		Modify the environment
 *	exit		Exit the program
 */

/*
 *  Local constant definitions
 */

#ifndef	FALSE
#define	FALSE			0
#endif

#ifndef	TRUE
#define	TRUE			('t')
#endif

#define	USAGE_MSG		"usage: listusers [-g groups] [-l logins]"
#define	MAXLOGINSIZE		14
#define	LOGINFIELDSZ		MAXLOGINSIZE+2

#define	isauserlogin(uid)	(uid >= 100)
#define	isasystemlogin(uid)	(uid < 100)
#define	isausergroup(gid)	(gid >= 100)
#define	isasystemgroup(gid)	(gid < 100)

/*
 *  Local datatype definitions
 */

/*
 * This structure describes a specified group name
 * (from the -g groups option)
 */

struct	reqgrp {
	char		*groupname;
	struct reqgrp	*next;
	int		found;
	gid_t		groupID;
};

/*
 * This structure describes a specified login name
 * (from the -l logins option)
 */

struct	reqlogin {
	char		*loginname;
	struct reqlogin	*next;
	int		found;
};

/*
 *  These functions handle error and warning message writing.
 *  (This deals with UNIX(r) standard message generation, so
 *  the rest of the code doesn't have to.)
 *
 *  Functions included:
 *	initmsg		Initialize the message handling functions.
 *	wrtmsg		Write the message using the standard message
 *			generation facility.
 *
 *  Static data included:
 *	fcnlbl		The label for standard messages
 *	msgbuf		A buffer to contain the edited message
 */

static	char	fcnlbl[MM_MXLABELLN+1];	/* Buffer for message label */
static	char	msgbuf[MM_MXTXTLN+1];	/* Buffer for message text */

/*
 * void initmsg(p)
 *
 *	This function initializes the message handling functions.
 *
 *  Arguments:
 *	p	A pointer to a character string that is the name of the
 *		command, used to generate the label on messages.  If this
 *		string contains a slash ('/'), it only uses the characters
 *		beyond the last slash in the string (this permits argv[0]
 *		to be used).
 *
 *  Returns:  Void
 */

static void
initmsg(char *p)	/* Ptr to command name */
{
	/* Automatic data */
	char   *q;		/* Local multi-use pointer */

	/* Use only the simple filename if there is a slash in the name */
	if ((q = strrchr(p, '/')) == NULL)
		q = p;
	else
		q++;

	/* Build the label for messages */
	(void) snprintf(fcnlbl, sizeof (fcnlbl), "UX:%s", q);

	/*
	 * Now that we've done all of that work, set things up so that
	 * only the text-component of a message is printed.  (This piece
	 * of code will most probably go away in SVR4.1.
	 */
	(void) putenv("MSGVERB=text");
}

/*
 *  void wrtmsg(severity, action, tag, text[, txtarg1[, txtarg2[, ...]]])
 *
 *	This function writes a message using the standard message
 * 	generation facility.
 *
 *  Arguments:
 *	severity	The severity-component of the message
 *	action		The action-string used to generate the action-
 *			component of the message
 *	tag		Tag-component of the message
 *	text		The text-string used to generate the text-component
 *			of the message
 *	txtarg		Arguments to be inserted into the "text" string using
 *			vsnprintf()
 *
 *  Returns:  Void
 */

/* VARARGS4 */

static void
wrtmsg(int severity, char *action, char *tag, char *text, ...)
{
	/* Automatic data */
	int		errorflg;	/* FLAG:  True if error writing msg */
	va_list		argp;		/* Pointer into vararg list */

	errorflg = FALSE;

	/* Generate the error message */
	va_start(argp, text);
	if (text != MM_NULLTXT) {
		/* LINTED */
		errorflg = vsnprintf(msgbuf, sizeof (msgbuf), text, argp) >
		    MM_MXTXTLN;
	}
	(void) fmtmsg(MM_PRINT, fcnlbl, severity,
	    (text == MM_NULLTXT) ? MM_NULLTXT : msgbuf,
	    action, tag);
	va_end(argp);

	/*
	 *  If there would have been a buffer overflow generating the error
	 *  message, the message will be truncated, so write a message and quit.
	 */

	if (errorflg) {
		(void) fmtmsg(MM_PRINT, fcnlbl, MM_WARNING,
		    "Internal message buffer overflow",
		    MM_NULLACT, MM_NULLTAG);
		exit(100);
	}
}

/*
 *  These functions allocate space for the information we gather.
 *  It works by having a memory heap with strings allocated from
 *  the end of the heap and structures (aligned data) allocated
 *  from the beginning of the heap.  It begins with a 4k block of
 *  memory then allocates memory in 4k chunks.  These functions
 *  should never fail.  If they do, they report the problem and
 *  exit with an exit code of 101.
 *
 *  Functions contained:
 *	allocblk	Allocates a block of memory, aligned on a
 *			4-byte (double-word) boundary.
 *	allocstr	Allocates a block of memory with no particular
 *			alignment
 *
 *  Constant definitions:
 *	ALLOCBLKSZ	Size of a chunk of main memory allocated using
 *			malloc()
 *
 *  Static data:
 *	nextblkaddr	Address of the next available chunk of aligned
 *			space in the heap
 *	laststraddr	Address of the last chunk of unaligned space
 *			allocated from the heap
 *	toomuchspace	Message to write if someone attempts to allocate
 *			too much space (>ALLOCBLKSZ bytes)
 *	memallocdif	Message to write if there is a problem allocating
 *			main memory.
 */

#define	ALLOCBLKSZ	4096

static char	*nextblkaddr = NULL;
static char	*laststraddr = NULL;
static char	*memallocdif =
	"Memory allocation difficulty.  Command terminates";
static char	*toomuchspace =
	"Internal space allocation error.  Command terminates";

/*
 *  void *allocblk(size)
 *	unsigned int	size
 *
 *	This function allocates a block of aligned (4-byte or double-
 *	word boundary) memory from the program's heap.  It returns a
 *	pointer to that block of allocated memory.
 *
 *  Arguments:
 *	size		Minimum number of bytes to allocate (will
 *			round up to multiple of 4)
 *
 *  Returns:  void *
 *	Pointer to the allocated block of memory
 */

static void *
allocblk(unsigned int size)
{
	/* Automatic data */
	char   *rtnval;


	/* Make sure the sizes are aligned correctly */
	if ((size = size + (4 - (size % 4))) > ALLOCBLKSZ) {
		wrtmsg(MM_ERROR, MM_NULLACT, MM_NULLTAG, toomuchspace);
		exit(101);
	}

	/* Set up the value we're going to return */
	rtnval = nextblkaddr;

	/* Get the space we need off of the heap */
	if ((nextblkaddr += size) >= laststraddr) {
		if ((rtnval = malloc(ALLOCBLKSZ)) == NULL) {
			wrtmsg(MM_ERROR, MM_NULLACT, MM_NULLTAG, memallocdif);
			exit(101);
		}
		laststraddr = rtnval + ALLOCBLKSZ;
		nextblkaddr = rtnval + size;
	}

	/* We're through */
	return ((void *)rtnval);
}

/*
 *  char *allocstr(nbytes)
 *	unsigned int	nbytes
 *
 *	This function allocates a block of unaligned memory from the
 *	program's heap.  It returns a pointer to that block of allocated
 *	memory.
 *
 *  Arguments:
 *	nbytes		Number of bytes to allocate
 *
 *  Returns:  char *
 *	Pointer to the allocated block of memory
 */

static char *
allocstr(unsigned int nchars)
{
	if (nchars > ALLOCBLKSZ) {
		wrtmsg(MM_ERROR, MM_NULLACT, MM_NULLTAG, toomuchspace);
		exit(101);
	}
	if ((laststraddr -= nchars) < nextblkaddr) {
		if ((nextblkaddr = malloc(ALLOCBLKSZ)) == NULL) {
			wrtmsg(MM_ERROR, MM_NULLACT, MM_NULLTAG, memallocdif);
			exit(101);
		}
		laststraddr = nextblkaddr + ALLOCBLKSZ - nchars;
	}
	return (laststraddr);
}

/*
 *  These functions control the group membership list, as found in the
 *  /etc/group file.
 *
 *  Functions included:
 *	initmembers		Initialize the membership list (to NULL)
 *	addmember		Adds a member to the membership list
 *	isamember		Looks for a particular login-ID in the list
 *				of members
 *
 *  Datatype Definitions:
 *	struct grpmember	Describes a group member
 *
 *  Static Data:
 *	membershead		Pointer to the head of the list of group members
 */

struct	grpmember {
	char			*membername;
	struct grpmember	*next;
};

static	struct grpmember	*membershead;

/*
 *  void initmembers()
 *
 *	This function initializes the list of members of specified groups.
 *
 *  Arguments:  None
 *
 *  Returns:  Void
 */

static void
initmembers(void)
{
	/* Set up the members list to be a null member's list */
	membershead = NULL;
}

/*
 *  void addmember(p)
 *	char   *p
 *
 *	This function adds a member to the group member's list.  The
 *	group members list is a list of structures containing a pointer
 *	to the member-name and a pointer to the next item in the structure.
 *	The structure is not ordered in any particular way.
 *
 *  Arguments:
 *	p	Pointer to the member name
 *
 *  Returns:  Void
 */

static void
addmember(char *p)
{
	/* Automatic data */
	struct grpmember	*new;	/* Member being added */

	new = (struct grpmember *)allocblk(sizeof (struct grpmember));
	new->membername = strcpy(allocstr((unsigned int)strlen(p)+1), p);
	new->next = membershead;
	membershead = new;
}

/*
 *  init isamember(p)
 *	char   *p
 *
 *	This function examines the list of group-members for the string
 *	referenced by 'p'.  If 'p' is a member of the members list, the
 *	function returns TRUE.  Otherwise it returns FALSE.
 *
 *  Arguments:
 *	p	Pointer to the name to search for.
 *
 *  Returns:  int
 *	TRUE	If 'p' is found in the members list,
 *	FALSE	otherwise
 */

static int
isamember(char *p)
{
	/* Automatic Data */
	int			found;	/* FLAG:  TRUE if login found */
	struct grpmember	*pmem;	/* Pointer to group member */


	/* Search the membership list for the 'p' */
	found = FALSE;
	for (pmem = membershead; !found && pmem; pmem = pmem->next) {
		if (strcmp(p, pmem->membername) == 0) found = TRUE;
	}

	return (found);
}

/*
 *  These functions handle the display list.  The display list contains
 *  all of the information we're to display.  The list contains a pointer
 *  to the login-name, a pointer to the free-field (comment), and a pointer
 *  to the next item in the list.  The list is ordered alphabetically
 *  (ascending) on the login-name field.  The list initially contains a
 *  dummy field (to make insertion easier) that contains a login-name of "".
 *
 *  Functions included:
 *	initdisp	Initializes the display list
 *	adddisp		Adds information to the display list
 *	genreport	Generates a report from the items in the display list
 *
 *  Datatypes Defined:
 *	struct display	Describes the structure that contains the
 *			information to be displayed.  Includes pointers
 *			to the login-ID, free-field (comment), and the
 *			next structure in the list.
 *
 *  Static Data:
 *	displayhead	Pointer to the head of the list of login-IDs to
 *			be displayed.  Initially references the null-item
 *			on the head of the list.
 */

struct	display {
	char		*loginID;
	char		*freefield;
	struct display	*next;
};

static	struct display *displayhead;

/*
 *  void initdisp()
 *
 *	Initializes the display list.  An empty display list contains a
 *	single element, the dummy element.
 *
 *  Arguments:  None
 *
 *  Returns:  Void
 */

static void
initdisp(void)
{
	displayhead = (struct display *)allocblk(sizeof (struct display));
	displayhead->next = NULL;
	displayhead->loginID = "";
	displayhead->freefield = "";
}

/*
 *  void adddisp(pwent)
 *	struct passwd  *pwent
 *
 *	This function adds the appropriate information from the login
 *	description referenced by 'pwent' to the list if information
 *	to be displayed.  It only adds the information if the login-ID
 *	(user-name) is unique.  It inserts the information in the list
 *	in such a way that the list remains ordered alphabetically
 *	(ascending) according to the login-ID (user-name).
 *
 *  Arguments:
 *	pwent		Points to the (struct passwd) structure that
 *			contains all of the login information on the
 *			login being added to the list.  The only
 *			information that this function uses is the
 *			login-ID (user-name) and the free-field
 *			(comment field).
 *
 *  Returns:  Void
 */

static void
adddisp(struct passwd *pwent)
{
	/* Automatic data */
	struct display	*new;		/* Display item being added */
	struct display	*prev;		/* Previous display item */
	struct display	*current;	/* Next display item */
	int	found;			/* FLAG, insertion point found */
	int	compare = 1;		/* strcmp() compare value */


	/* Find where this value belongs in the list */
	prev = displayhead;
	current = displayhead->next;
	found = FALSE;
	while (!found && current) {
		if ((compare = strcmp(current->loginID, pwent->pw_name)) >= 0)
			found = TRUE;
		else {
			prev = current;
			current = current->next;
		}
	}

	/* Insert this value in the list, only if it is unique though */
	if (compare != 0) {
		/*
		 * Build a display structure containing the value to add to
		 * the list, and add to the list
		 */
		new = (struct display *)allocblk(sizeof (struct display));
		new->loginID =
		    strcpy(allocstr((unsigned int)strlen(pwent->pw_name)+1),
		    pwent->pw_name);
		if (pwent->pw_comment && pwent->pw_comment[0] != '\0')
			new->freefield =
			    strcpy(allocstr(
			    (unsigned int)strlen(pwent->pw_comment)+1),
			    pwent->pw_comment);
		else
			new->freefield =
			    strcpy(allocstr(
			    (unsigned int)strlen(pwent->pw_gecos)+1),
			    pwent->pw_gecos);
		new->next = current;
		prev->next = new;
	}
}

/*
 *  void genreport()
 *
 *	This function generates a report on the standard output stream
 *	(stdout) containing the login-IDs and the free-fields of the
 *	logins that match the list criteria (-g and -l options)
 *
 *  Arguments:  None
 *
 *  Returns:  Void
 */

static void
genreport(void)
{

	/* Automatic data */
	struct display		*current;	/* Value to display */
	int			i;		/* Counter of characters */

	/*
	 *  Initialization for loop.
	 *  (NOTE:  The first element in the list of logins to display
	 *  is a dummy element.)
	 */
	current = displayhead;

	/*
	 *  Display elements in the list
	 */
	for (current = displayhead->next; current; current = current->next) {
		(void) fputs(current->loginID, stdout);
		for (i = LOGINFIELDSZ - strlen(current->loginID); --i >= 0;
		    (void) putc(' ', stdout))
			;
		(void) fputs(current->freefield, stdout);
		(void) putc('\n', stdout);
	}
}

/*
 * listusers [-l logins] [-g groups]
 *
 *	This command generates a list of user login-IDs.  Specific login-IDs
 *	can be listed, as can logins belonging in specific groups.
 *
 *	-l logins	specifies the login-IDs to display.  "logins" is a
 *			comma-list of login-IDs.
 *	-g groups	specifies the names of the groups to which a login-ID
 *			must belong before it is included in the generated list.
 *			"groups" is a comma-list of group names.
 * Exit Codes:
 *	0	All's well that ends well
 *	1	Usage error
 */

int
main(int argc, char **argv)
{

	/* Automatic data */

	struct reqgrp	*reqgrphead;	/* Head of the req'd group list */
	struct reqgrp	*pgrp;	/* Current item in the req'd group list */
	struct reqgrp	*qgrp;		/* Prev item in the req'd group list */
	struct reqgrp	*rgrp;	/* Running ptr for scanning group list */
	struct reqlogin	*reqloginhead;	/* Head of req'd login list */
	struct reqlogin	*plogin; /* Current item in the req'd login list */
	struct reqlogin	*qlogin; /* Previous item in the req'd login list */
	struct reqlogin	*rlogin; /* Running ptr for scanning login list */
	struct passwd	*pwent;		/* Ptr to an /etc/passwd entry */
	struct group	*grent;		/* Ptr to an /etc/group entry */
	char	*token;		/* Ptr to a token extracted by strtok() */
	char	**pp;		/* Ptr to a member of a group */
	char	*g_arg;		/* Ptr to the -g option's argument */
	char	*l_arg;		/* Ptr to the -l option's argument */
	int	g_seen;		/* FLAG, true if -g on cmd */
	int	l_seen;		/* FLAG, TRUE if -l is on the command line */
	int	errflg;	/* FLAG, TRUE if there is a command-line problem */
	int	done;		/* FLAG, TRUE if the process (?) is complete */
	int	groupcount;	/* Number of groups specified by the user */
	int	rc;		/* Return code from strcmp() */
	int	c;		/* Character returned from getopt() */


	/* Initializations */
	initmsg(argv[0]);

	/* Command-line processing */
	g_seen = FALSE;
	l_seen = FALSE;
	errflg = FALSE;
	opterr = 0;
	while (!errflg && ((c = getopt(argc, argv, "g:l:")) != EOF)) {

		/* Case on the option character */
		switch (c) {

		case 'g':
			if (g_seen)
				errflg = TRUE;
			else {
				g_seen = TRUE;
				g_arg = optarg;
			}
			break;

		case 'l':
			if (l_seen)
				errflg = TRUE;
			else {
				l_seen = TRUE;
				l_arg = optarg;
			}
			break;

		default:
			errflg = TRUE;
		}
	}

	/* Write out a usage message if necessary and quit */
	if (errflg || (optind != argc)) {
		wrtmsg(MM_ERROR, MM_NULLACT, MM_NULLTAG, USAGE_MSG);
		exit(1);
	}


	/*
	 *  If the -g groups option was on the command line, build a
	 *  list containing groups we're to list logins for.
	 */
	if (g_seen) {

		/* Begin with an empty list */
		groupcount = 0;
		reqgrphead = NULL;

		/* Extract the first token putting an element on the list */
		if ((token = strtok(g_arg, ",")) != NULL) {
			pgrp = (struct reqgrp *)
			    allocblk(sizeof (struct reqgrp));
			pgrp->groupname = token;
			pgrp->found = FALSE;
			pgrp->next = NULL;
			groupcount++;
			reqgrphead = pgrp;
			qgrp = pgrp;

			/*
			 * Extract subsequent tokens (group names), avoiding
			 * duplicate names (note, list is NOT empty)
			 */
			while (token = strtok(NULL, ",")) {

				/* Check for duplication */
				rgrp = reqgrphead;
				while (rgrp &&
				    (rc = strcmp(token, rgrp->groupname)))
					rgrp = rgrp->next;
				if (rc != 0) {

					/* Not a duplicate.  Add on the list */
					pgrp = (struct reqgrp *)
					    allocblk(sizeof (struct reqgrp));
					pgrp->groupname = token;
					pgrp->found = FALSE;
					pgrp->next = NULL;
					groupcount++;
					qgrp->next = pgrp;
					qgrp = pgrp;
				}
			}
		}
	}

	/*
	 *  If -l logins is on the command line, build a list of logins
	 *  we're to generate reports for.
	 */
	if (l_seen) {

		/* Begin with a null list */
		reqloginhead = NULL;

		/* Extract the first token from the argument to the -l option */
		if (token = strtok(l_arg, ",")) {

			/* Put the first element in the list */
			plogin = (struct reqlogin *)
			    allocblk(sizeof (struct reqlogin));
			plogin->loginname = token;
			plogin->found = FALSE;
			plogin->next = NULL;
			reqloginhead = plogin;
			qlogin = plogin;

			/*
			 * For each subsequent token in the -l argument's
			 * comma list ...
			 */

			while (token = strtok(NULL, ",")) {

				/* Check for duplication (list is not empty) */
				rlogin = reqloginhead;
				while (rlogin &&
				    (rc = strcmp(token, rlogin->loginname)))
					rlogin = rlogin->next;

				/*
				 * If it's not a duplicate,
				 * add it to the list
				 */
				if (rc != 0) {
					plogin = (struct reqlogin *)
					    allocblk(sizeof (struct reqlogin));
					plogin->loginname = token;
					plogin->found = FALSE;
					plogin->next = NULL;
					qlogin->next = plogin;
					qlogin = plogin;
				}
			}
		}
	}


	/*
	 *  If the user requested that only logins be listed in that belong
	 *  to certain groups, compile a list of logins that belong in that
	 *  group.  If the user also requested specific logins, that list
	 *  will be limited to those logins.
	 */

	/* Initialize the login list */
	initmembers();
	if (g_seen) {

		/* For each group in the /etc/group file ... */
		while (grent = getgrent()) {

			/* For each group mentioned with the -g option ... */
			for (pgrp = reqgrphead; (groupcount > 0) && pgrp;
			    pgrp = pgrp->next) {

				if (pgrp->found == FALSE) {

					/*
					 * If the mentioned group is found in
					 * the /etc/group file ...
					 */
					if (strcmp(grent->gr_name,
					    pgrp->groupname) == 0) {

						/*
						 * Mark the entry is found,
						 * remembering the group-ID
						 * for later
						 */
						pgrp->found = TRUE;
						groupcount--;
						pgrp->groupID = grent->gr_gid;
						if (isausergroup(pgrp->groupID))
							for (pp = grent->gr_mem;
							    *pp; pp++)
								addmember(*pp);
					}
				}
			}
		}

		/*
		 * If any groups weren't found, write a message
		 * indicating such, then continue
		 */
		qgrp = NULL;
		for (pgrp = reqgrphead; pgrp; pgrp = pgrp->next) {
			if (!pgrp->found) {
				wrtmsg(MM_WARNING, MM_NULLACT, MM_NULLTAG,
				    "%s was not found", pgrp->groupname);
				if (!qgrp)
					reqgrphead = pgrp->next;
				else
					qgrp->next = pgrp->next;
			} else if (isasystemgroup(pgrp->groupID)) {
				wrtmsg(MM_WARNING, MM_NULLACT, MM_NULLTAG,
				    "%s is not a user group", pgrp->groupname);
				if (!qgrp)
					reqgrphead = pgrp->next;
				else
					qgrp->next = pgrp->next;
			} else
				qgrp = pgrp;
		}
	}


	/* Initialize the list of logins to display */
	initdisp();


	/*
	 *  Loop through the /etc/passwd file squirelling away the
	 *  information we need for the display.
	 */
	while (pwent = getpwent()) {

		/*
		 * The login from /etc/passwd hasn't been included in
		 * the display yet
		 */
		done = FALSE;


		/*
		 * If the login was explicitly requested, include it in
		 * the display if it is a user login
		 */

		if (l_seen) {
			for (plogin = reqloginhead; !done && plogin;
			    plogin = plogin->next) {
				if (strcmp(pwent->pw_name,
				    plogin->loginname) == 0) {
					plogin->found = TRUE;
					if (isauserlogin(pwent->pw_uid))
						adddisp(pwent);
					else
						wrtmsg(MM_WARNING, MM_NULLACT,
						    MM_NULLTAG,
						    "%s is not a user login",
						    plogin->loginname);
					done = TRUE;
				}
			}
		}


		/*
		 *  If the login-ID isn't already on the list, if its primary
		 *  group-ID is one of those groups requested, or it is a member
		 *  of the groups requested, include it in the display if it is
		 *  a user login (uid >= 100).
		 */

		if (isauserlogin(pwent->pw_uid)) {

			if (!done && g_seen) {
				for (pgrp = reqgrphead; !done && pgrp;
				    pgrp = pgrp->next)
					if (pwent->pw_gid == pgrp->groupID) {
						adddisp(pwent);
						done = TRUE;
					}
				if (!done && isamember(pwent->pw_name)) {
					adddisp(pwent);
					done = TRUE;
				}
			}


			/*
			 * If neither -l nor -g is on the command-line and
			 * the login-ID is a user login, include it in
			 * the display.
			 */

			if (!l_seen && !g_seen)
				adddisp(pwent);
		}
	}

	/* Let the user know about logins they requested that don't exist */
	if (l_seen)
		for (plogin = reqloginhead; plogin; plogin = plogin->next)
			if (!plogin->found)
				wrtmsg(MM_WARNING, MM_NULLACT, MM_NULLTAG,
				    "%s was not found", plogin->loginname);


	/*
	 * Generate a report from this display items we've squirreled away
	 */
	genreport();

	/*
	 *  We're through!
	 */
	return (0);
}
