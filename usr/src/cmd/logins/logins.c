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
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.15.1.2 */

/*
 * logins.c
 *
 *	This file contains the source for the administrative command
 *	"logins" (available to the administrator) that produces a report
 *	containing login-IDs and other requested information.
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <time.h>
#include <stdarg.h>
#include <fmtmsg.h>
#include <locale.h>

/*
 *  Local constant definitions
 *	TRUE			Boolean constant
 *	FALSE			Boolean constant
 *	USAGE_MSG		Message used to display a usage error
 *	MAXLOGINSIZE		Maximum length of a valid login-ID
 *	MAXSYSTEMLOGIN		Maximum value of a system user-ID.
 *	OPTSTR			Options to this command
 *	ROOT_ID			The user-ID of an administrator
 */

#ifndef	FALSE
#define	FALSE			0
#endif

#ifndef	TRUE
#define	TRUE			((int)'t')
#endif

#define	USAGE_MSG	"usage: logins [-admopstux] [-g groups] [-l logins]"
#define	MAXLOGINSIZE	14
#define	MAXSYSTEMLOGIN	99
#define	OPTSTR		"adg:l:mopstux"
#define	ROOT_ID		0

/*
 *  The following macros do their function for now but will probably have
 *  to be replaced by functions sometime in the near future.  The maximum
 *  system login value may someday be administerable, in which case these
 *  will have to be changed to become functions
 *
 *	isasystemlogin	Returns TRUE if the user-ID in the "struct passwd"
 *			structure referenced by the function's argument is
 *			less than or equal to the maximum value for a system
 *			user-ID, FALSE otherwise.
 *	isauserlogin	Returns TRUE if the user-ID in the "struct passwd"
 *			structure referenced by the function's argument is
 *			greater than the maximum value for a system user-ID,
 *			FALSE otherwise.
 */

#define	isauserlogin(pw)	(pw->pw_uid > MAXSYSTEMLOGIN)
#define	isasystemlogin(pw)	(pw->pw_uid <= MAXSYSTEMLOGIN)


/*
 *  Local datatype definitions
 *	struct reqgrp		Describes a group as requested through the
 *				-g option
 *	struct reqlogin		Describes a login-ID as requested through
 *				the -l option
 *	struct pwdinfo		Describes a password's aging information,
 *				as extracted from /etc/shadow
 *	struct secgrp		Describes a login-ID's secondary group
 */

/*  Describes a specified group name (from the -g groups option)  */
struct	reqgrp {
	char		*groupname;	/* Requested group name */
	struct reqgrp	*next;		/* Next item in the list */
	gid_t		groupID;	/* Group's ID */
};

/*  Describes a specified login name (from the -l logins option)  */
struct	reqlogin {
	char		*loginname;	/* Requested login name */
	struct reqlogin	*next;		/* Next item in the list */
	int		found;		/* TRUE if login in /etc/passwd */
};

/*
 * This structure describes a password's information
 */

struct	pwdinfo {
	long	datechg;	/* Date the password was changed (mmddyy) */
	char	*passwdstatus;	/* Password status */
	long	mindaystilchg;	/* Min days b4 pwd can change again */
	long	maxdaystilchg;	/* Max days b4 pwd can change again */
	long	warninterval;	/* Days before expire to warn user */
	long	inactive;	/* Lapsed days of inactivity before lock */
	long	expdate;	/* Date of expiration (mmddyy) */
};

/* This structure describes secondary groups that a user belongs to */
struct	secgrp {
	char		*groupname;	/* Name of the group */
	struct secgrp	*next;		/* Next item in the list */
	gid_t		groupID;	/* Group-ID */
};


/*
 *  These functions handle error and warning message writing.
 *  (This deals with UNIX(r) standard message generation, so
 *  the rest of the code doesn't have to.)
 *
 *  Functions included:
 *	initmsg		Initialize the message handling functions.
 *	wrtmsg		Write the message using fmtmsg().
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
 *		function, used to generate the label on messages.  If this
 *		string contains a slash ('/'), it only uses the characters
 *		beyond the last slash in the string (this permits argv[0]
 *		to be used).
 *
 *  Returns:  Void
 */

static void
initmsg(char *p)
{
	char   *q;	/* Local multi-use pointer */

	/* Use only the simple filename if there is a slash in the name */
	if (!(q = strrchr(p, '/'))) {
		q = p;
	} else {
		q++;
	}

	/* Build the label for messages */
	(void) snprintf(fcnlbl, MM_MXLABELLN, "UX:%s", q);

	/* Restrict messages to the text-component */
	(void) putenv("MSGVERB=text");
}


/*
 *  void wrtmsg(severity, action, tag, text[, txtarg1[, txtarg2[, ...]]])
 *
 *	This function writes a message using fmtmsg()
 *
 *  Arguments:
 *	severity	The severity-component of the message
 *	action		The action-string used to generate the
 *			action-component of the message
 *	tag		Tag-component of the message
 *	text		The text-string used to generate the text-
 *			component of the message
 *	txtarg		Arguments to be inserted into the "text"
 *			string using vsprintf()
 *
 *  Returns:  Void
 */
/*PRINTFLIKE4*/
static void
wrtmsg(int severity, char *action, char *tag, char *text, ...)
{
	int	errorflg;	/* TRUE if problem generating message */
	va_list	argp;		/* Pointer into vararg list */


	/* No problems yet */
	errorflg = FALSE;

	/* Generate the error message */
	va_start(argp, text);
	if (text != MM_NULLTXT) {
		errorflg = vsnprintf(msgbuf,
		    MM_MXTXTLN, text, argp) > MM_MXTXTLN;
	}
	(void) fmtmsg(MM_PRINT, fcnlbl, severity,
	    (text == MM_NULLTXT) ? MM_NULLTXT : msgbuf, action, tag);
	va_end(argp);

	/*
	 *  If there was a buffer overflow generating the error message,
	 *  write a message and quit (things are probably corrupt in the
	 *  static data space now
	 */
	if (errorflg) {
		(void) fmtmsg(MM_PRINT, fcnlbl, MM_WARNING,
		    gettext("Internal message buffer overflow"),
		    MM_NULLACT, MM_NULLTAG);
		exit(100);
	}
}

/*
 *  These functions control the group membership list, as found in
 *  the /etc/group file.
 *
 *  Functions included:
 *	addmember		Adds a member to the membership list
 *	isamember		Looks for a particular login-ID in the
 *				list of members
 *
 *  Datatype Definitions:
 *	struct grpmember	Describes a group member
 *
 *  Static Data:
 *	membershead		Pointer to the head of the list of
 *				group members
 */

struct	grpmember {
	char			*membername;
	struct grpmember	*next;
};

static	struct grpmember	*membershead;

/*
 *  void addmember(p)
 *	char   *p
 *
 *	This function adds a member to the group member's list.  The
 *	group members list is a list of structures containing a pointer
 *	to the member-name and a pointer to the next item in the
 *	structure.  The structure is not ordered in any particular way.
 *
 *  Arguments:
 *	p	Pointer to the member name
 *
 *  Returns:  Void
 */

static void
addmember(char *p)
{
	struct grpmember	*new;	/* Member being added */

	new = malloc(sizeof (struct grpmember));
	new->membername = strdup(p);
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
	int			found;	/* TRUE if login found in list */
	struct grpmember	*pmem;	/* Group member being examined */


	/* Search the membership list for 'p' */
	found = FALSE;
	for (pmem = membershead; !found && pmem; pmem = pmem->next) {
		if (strcmp(p, pmem->membername) == 0)
			found = TRUE;
	}

	return (found);
}


/*
 *  These functions handle the display list.  The display list contains
 *  all of the information we're to display.  The list contains a pointer
 *  to the login-name, a pointer to the free-field (comment), and a
 *  pointer to the next item in the list.  The list is ordered alpha-
 *  betically (ascending) on the login-name field.  The list initially
 *  contains a dummy field (to make insertion easier) that contains a
 *  login-name of "".
 *
 *  Functions included:
 *	initdisp	Initializes the display list
 *	adddisp		Adds information to the display list
 *	isuidindisp	Looks to see if a particular user-ID is in the
 *			display list
 *	genreport	Generates a report from the items in the display
 *			list
 *	applygroup	Add group information to the items in the display
 *			list
 *	applypasswd	Add extended password information to the items
 *			in the display list
 *
 *  Datatypes Defined:
 *	struct display	Describes the structure that contains the information
 *			to be displayed.  Includes pointers to the login-ID,
 *			free-field (comment), and the next structure in the
 *			list.
 *
 *  Static Data:
 *	displayhead	Pointer to the head of the display list.  Initially
 *			references the null-item on the head of the list.
 */

struct	display {
	char		*loginID;	/* Login name */
	char		*freefield;	/* Free (comment) field */
	char		*groupname;	/* Name of the primary group */
	char		*iwd;		/* Initial working directory */
	char		*shell;		/* Shell after login (may be null) */
	struct pwdinfo	*passwdinfo;	/* Password information structure */
	struct secgrp 	*secgrplist; 	/* Head of the secondary group list */
	uid_t		userID;		/* User ID */
	gid_t		groupID;	/* Group ID of primary group */
	struct display	*nextlogin;	/* Next login in the list */
	struct display	*nextuid;	/* Next user-ID in the list */
};

static	struct display	*displayhead;


/*
 *  void initdisp()
 *
 *	Initializes the display list.  An empty display list contains
 *	a single element, the dummy element.
 *
 *  Arguments:  None
 *
 *  Returns:  Void
 */

static void
initdisp(void)
{
	displayhead = malloc(sizeof (struct display));
	displayhead->nextlogin = NULL;
	displayhead->nextuid = NULL;
	displayhead->loginID = "";
	displayhead->freefield = "";
	displayhead->userID = (uid_t)-1;
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
 *	pwent		Structure that contains all of the login information
 *			of the login being added to the list.  The only
 *			information that this function uses is the login-ID
 *			(user-name) and the free-field (comment field).
 *
 *  Returns:  Void
 */

static void
adddisp(struct passwd *pwent)
{
	struct display *new;		/* Item being added to the list */
	struct display *prev;		/* Previous item in the list */
	struct display *current;	/* Next item in the list */
	int		found;		/* FLAG, insertion point found */
	int		compare = 1;	/* strcmp() compare value */


	/* Find where this value belongs in the list */
	prev = displayhead;
	found = FALSE;
	while (!found && (current = prev->nextlogin)) {
		if ((compare = strcmp(current->loginID, pwent->pw_name)) >= 0) {
			found = TRUE;
		} else {
			prev = current;
		}

	}
	/* Insert this value in the list, only if it is unique though */
	if (compare != 0) {
		new = malloc(sizeof (struct display));
		new->loginID = strdup(pwent->pw_name);
		if (pwent->pw_comment && pwent->pw_comment[0] != '\0') {
			new->freefield = strdup(pwent->pw_comment);
		} else {
		    new->freefield = strdup(pwent->pw_gecos);
		}
		if (!pwent->pw_shell || !(*pwent->pw_shell)) {
			new->shell = "/sbin/sh";
		} else {
			new->shell = strdup(pwent->pw_shell);
		}
		new->iwd = strdup(pwent->pw_dir);
		new->userID = pwent->pw_uid;
		new->groupID = pwent->pw_gid;
		new->secgrplist = NULL;
		new->passwdinfo = NULL;
		new->groupname = NULL;

		/* Add new display item to the list ordered by login-ID */
		new->nextlogin = current;
		prev->nextlogin = new;

		/*
		 * Find the appropriate place for the new item in the list
		 * ordered by userID
		 */
		prev = displayhead;
		found = FALSE;
		while (!found && (current = prev->nextuid)) {
			if (current->userID > pwent->pw_uid) {
				found = TRUE;
			} else {
				prev = current;
			}
		}

		/* Add the item into the list that is ordered by user-ID */
		new->nextuid = current;
		prev->nextuid = new;
	}
}


/*
 *  int isuidindisp(pwent)
 *	struct passwd  *pwent
 *
 *  This function examines the display list to see if the uid in
 *  the (struct passwd) referenced by "pwent" is already in the
 *  display list.  It returns TRUE if it is in the list, FALSE
 *  otherwise.
 *
 *  Since the display list is ordered by user-ID, the search continues
 *  until a match is found or a user-ID is found that is larger than
 *  the one we're searching for.
 *
 *  Arguments:
 *	pwent		Structure that contains the user-ID we're to
 *			look for
 *
 *  Returns:  int
 *	TRUE if the user-ID was found, FALSE otherwise.
 */

static int
isuidindisp(struct passwd *pwent)
{
	struct display *dp;


	/*
	 *  Search the list, beginning at the beginning (where else?)
	 *  and stopping when the user-ID is found or one is found that
	 *  is greater than the user-ID we're searching for.  Recall
	 *  that this list is ordered by user-ID
	 */

	for (dp = displayhead->nextuid; dp && (dp->userID < pwent->pw_uid);
	    dp = dp->nextuid) {
		continue;
	}

	/*
	 * If the pointer "dp" points to a structure that has a
	 * matching user-ID, return TRUE.  Otherwise FALSE
	 */
	return (dp && (dp->userID == pwent->pw_uid));
}


/*
 *  void applygroup(allgroups)
 *	int	allgroups
 *
 *  This function applies group information to the login-IDs in the
 *  display list.  It always applies the primary group information.
 *  If "allgroups" is TRUE, it applies secondary information as well.
 *
 *  Arguments:
 * 	allgroups	FLAG.  TRUE if secondary group info is to be
 *			applied -- FALSE otherwise.
 *
 *  Returns:  void
 */

static void
applygroup(int allgroups)
{
	struct display	*dp;		/* Display list running ptr */
	struct group	*grent;		/* Group info, from getgrent() */
	char		*p;		/* Temp char pointer */
	char		**pp;		/* Temp char * pointer */
	int		compare;	/* Value from strcmp() */
	int		done;		/* TRUE if finished, FALSE otherwise */
	struct secgrp	*psecgrp;	/* Block allocated for this info */
	struct secgrp	*psrch;		/* Secondary group -- for searching */

	if (!allgroups) {
		/* short circute getting all the groups */
		for (dp = displayhead->nextuid; dp; dp = dp->nextuid) {
			if ((grent = getgrgid(dp->groupID)) != NULL) {
				dp->groupname = strdup(grent->gr_name);
			}
		}
		return;
	}

	/* For each group-ID in the /etc/group file ... */
	while (grent = getgrent()) {
		/*
		 *  Set the primary group for the login-IDs in the display
		 *  list.  For each group-ID we get, leaf through the display
		 *  list and set the group-name if the group-IDs match
		 */

		p = NULL;
		for (dp = displayhead->nextuid; dp; dp = dp->nextuid) {
			if ((dp->groupID == grent->gr_gid) && !dp->groupname) {
				if (!p) {
					p = strdup(grent->gr_name);
				}
				dp->groupname = p;
			}
		}

		/*
		 *  If we're to be displaying secondary group membership,
		 *  leaf through the list of group members.  Then, attempt
		 *  to find that member in the display list.  When found,
		 *  attach secondary group info to the user.
		 */

		for (pp = grent->gr_mem; *pp; pp++) {
			done = FALSE;
			for (dp = displayhead->nextlogin; !done && dp;
			    dp = dp->nextlogin) {
				if (((compare = strcmp(dp->loginID,
				    *pp)) == 0) &&
				    !(grent->gr_gid == dp->groupID)) {
					if (!p) {
						p = strdup(grent->gr_name);
					}
					psecgrp = malloc(
					    sizeof (struct secgrp));
					psecgrp->groupID = grent->gr_gid;
					psecgrp->groupname = p;
					psecgrp->next = NULL;
					if (!dp->secgrplist) {
						dp->secgrplist = psecgrp;
					} else {
						for (psrch = dp->secgrplist;
						    psrch->next;
						    psrch = psrch->next) {
							continue;
						}
						psrch->next = psecgrp;
					}
					done = TRUE;
				} else if (compare > 0) {
						done = TRUE;
				}
			}
		}
	}

	/* Close the /etc/group file */
	endgrent();
}


/*
 *  void applypasswd()
 *
 *	This function applies extended password information to an item
 *	to be displayed.  It allocates space for a structure describing
 *	the password, then fills in that structure from the information
 *	in the /etc/shadow file.
 *
 *  Arguments:  None
 *
 *  Returns:  Void
 */

static void
applypasswd(void)
{
	struct pwdinfo	*ppasswd;	/* Ptr to pwd desc in current element */
	struct display	*dp;		/* Ptr to current element */
	struct spwd	*psp;		/* Pointer to a shadow-file entry */
	struct tm	*ptm;		/* Pointer to a time-of-day structure */
	time_t		pwchg;		/* System-time of last pwd chg */
	time_t		pwexp;		/* System-time of password expiration */


	/*  Make sure the shadow file is rewound  */
	setspent();


	/*
	 *  For each item in the display list...
	 */

	for (dp = displayhead->nextuid; dp; dp = dp->nextuid) {

		/* Allocate structure space for the password description */
		ppasswd = malloc(sizeof (struct pwdinfo));
		dp->passwdinfo = ppasswd;

		/*
		 * If there's no entry in the /etc/shadow file, assume
		 * that the login is locked
		 */

		if ((psp = getspnam(dp->loginID)) == NULL) {
			pwchg = 0L;			/* Epoch */
			ppasswd->passwdstatus = "LK";	/* LK, Locked */
			ppasswd->mindaystilchg = 0L;
			ppasswd->maxdaystilchg = 0L;
			ppasswd->warninterval = 0L;
			ppasswd->inactive = 0L;
			pwexp = 0L;
		} else {
			/*
			 * Otherwise, fill in the password information from the
			 * info in the shadow entry
			 */
			if (psp->sp_pwdp == NULL || (*psp->sp_pwdp) == '\0')
				ppasswd->passwdstatus = "NP";
			else if (strncmp(psp->sp_pwdp, LOCKSTRING,
			    sizeof (LOCKSTRING)-1) == 0)
				ppasswd->passwdstatus = "LK";
			else if (strncmp(psp->sp_pwdp, NOLOGINSTRING,
			    sizeof (NOLOGINSTRING)-1) == 0)
				ppasswd->passwdstatus = "NL";
			else if ((strlen(psp->sp_pwdp) == 13 &&
			    psp->sp_pwdp[0] != '$') ||
			    psp->sp_pwdp[0] == '$')
				ppasswd->passwdstatus = "PS";
			else
				ppasswd->passwdstatus = "UN";
			/*
			 * Set up the last-changed date,
			 * the minimum days between changes,
			 * the maximum life of a password,
			 * the interval before expiration that the user
			 * is warned,
			 * the number of days a login can be inactive before
			 * it expires, and the login expiration date
			 */

			pwchg = psp->sp_lstchg;
			ppasswd->mindaystilchg = psp->sp_min;
			ppasswd->maxdaystilchg = psp->sp_max;
			ppasswd->warninterval = psp->sp_warn;
			ppasswd->inactive = psp->sp_inact;
			pwexp = psp->sp_expire;
		}

		/*
		 * Convert the date of the last password change from days-
		 * since-epoch to mmddyy (integer) form.  Involves the
		 * intermediate step of converting the date from days-
		 * since-epoch to seconds-since-epoch.  We'll set this to
		 * somewhere near the middle of the day, since there are not
		 * always 24*60*60 seconds in a year.  (Yeech)
		 *
		 * Note:  The form mmddyy should probably be subject to
		 * internationalization -- Non-Americans will think that
		 * 070888 is 07 August 88 when the software is trying to say
		 * 08 July 88.  Systems Engineers seem to think that this isn't
		 * a problem though...
		 */

		if (pwchg != -1L) {
			pwchg = (pwchg * DAY) + (DAY/2);
			ptm = localtime(&pwchg);
			ppasswd->datechg = ((long)(ptm->tm_mon+1) * 10000L) +
			    (long)((ptm->tm_mday * 100) +
			    (ptm->tm_year % 100));
		} else {
			ppasswd->datechg = 0L;
		}

		/*
		 * Convert the passwd expiration date from days-since-epoch
		 * to mmddyy (long integer) form using the same algorithm and
		 * comments as above.
		 */

		if (pwexp != -1L) {
			pwexp = (pwexp * DAY) + (DAY/2);
			ptm = localtime(&pwexp);
			ppasswd->expdate = ((long)(ptm->tm_mon+1) * 10000L) +
			    (long)((ptm->tm_mday * 100) +
			    (ptm->tm_year % 100));
		} else {
			ppasswd->expdate = 0L;
		}
	}

	/* Close the shadow password file */
	endspent();
}


/*
 * int hasnopasswd(pwent)
 *	struct passwd  *pwent
 *
 *	This function examines a login's password-file entry
 *	and, if necessary, its shadow password-file entry and
 *	returns TRUE if that user-ID has no password, meaning
 *	that the user-ID can be used to log into the system
 *	without giving a password.  The function returns FALSE
 *	otherwise.
 *
 *  Arguments:
 *	pwent	Login to examine.
 *
 *  Returns:  int
 *	TRUE if the login can be used without a password, FALSE
 *	otherwise.
 */

static int
hasnopasswd(struct passwd *pwent)
{
	struct spwd    *psp;		/* /etc/shadow file struct */
	int		nopwflag;	/* TRUE if login has no passwd */

	/*
	 *  A login has no password if:
	 *    1.  There exists an entry for that login in the
	 *	  shadow password-file (/etc/passwd), and
	 *    2.  The encrypted password in the structure describing
	 *	  that entry is either:	 NULL or a null string ("")
	 */

	/* Get the login's entry in the shadow password file */
	if (psp = getspnam(pwent->pw_name)) {

		/* Look at the encrypted password in that entry */
		if (psp->sp_pwdp == (char *)0 ||
		    *psp->sp_pwdp == '\0') {
			nopwflag = TRUE;
		} else {
			nopwflag = FALSE;
		}
	} else {
		nopwflag = FALSE;
	}

	/* Done ... */
	return (nopwflag);
}


/*
 *  void writeunformatted(current, xtndflag, expflag)
 *	struct display *current
 *	int		xtndflag
 *	int		expflag
 *
 *  This function writes the data in the display structure "current"
 *  to the standard output file.  It writes the information in the
 *  form of a colon-list.  It writes secondary group information if
 *  that information is in the structure, it writes extended
 *  (initial working directory, shell, and password-aging) info
 *  if the "xtndflag" is TRUE, and it writes password expiration
 *  information if "expflag" is TRUE.
 *
 *  Arguments:
 *	current		Structure containing information to write.
 *	xtndflag	TRUE if extended information is to be written,
 *			FALSE otherwise
 *	expflag		TRUE if password expiration information is to
 *			be written, FALSE otherwise
 *
 *  Returns:  void
 */

static void
writeunformatted(struct display *current, int xtndflag, int expflag)
{
	struct secgrp  *psecgrp;	/* Secondary group info */
	struct pwdinfo *pwdinfo;	/* Password aging info */

	/* Write the general information */
	(void) fprintf(stdout, "%s:%u:%s:%u:%s",
	    current->loginID,
	    current->userID,
	    current->groupname == NULL ? "" : current->groupname,
	    current->groupID,
	    current->freefield);

	/*
	 * If the group information is there, write it (it's only
	 * there if it's supposed to be written)
	 */
	for (psecgrp = current->secgrplist; psecgrp; psecgrp = psecgrp->next) {
		(void) fprintf(stdout, ":%s:%u",
		    psecgrp->groupname, psecgrp->groupID);
	}

	/* If the extended info flag is TRUE, write the extended information */
	if (xtndflag) {
		pwdinfo = current->passwdinfo;
		(void) fprintf(stdout, ":%s:%s:%s:%6.6ld:%ld:%ld:%ld",
		    current->iwd, current->shell,
		    pwdinfo->passwdstatus,
		    pwdinfo->datechg,
		    pwdinfo->mindaystilchg, pwdinfo->maxdaystilchg,
		    pwdinfo->warninterval);
	}

	/* If the password expiration information is requested, write it.  */
	if (expflag) {
		pwdinfo = current->passwdinfo;
		(void) fprintf(stdout, ":%ld:%ld",
		    pwdinfo->inactive, pwdinfo->expdate);
	}

	/* Terminate the information with a new-line */
	(void) putc('\n', stdout);
}


/*
 *  void writeformatted(current, xtndflag, expflag)
 *	struct display *current
 *	int		xtndflag
 *	int		expflag
 *
 *  This function writes the data in the display structure "current"
 *  to the standard output file.  It writes the information in an
 *  easily readable format.  It writes secondary group information
 *  if that information is in the structure, it writes extended
 *  (initial working directory, shell, and password-aging) info if
 *  "xtndflag" is TRUE, and it write password expiration information
 *  if "expflag" is TRUE.
 *
 *  Arguments:
 *	current		Structure containing info to write.
 *	xtndflag	TRUE if extended information to be written,
 *			FALSE otherwise
 *	expflag 	TRUE if password expiration information to be written,
 *			FALSE otherwise
 *
 *  Returns:  void
 */

static void
writeformatted(struct display *current, int xtndflag, int expflag)
{
	struct secgrp  *psecgrp;	/* Secondary group info */
	struct pwdinfo *pwdinfo;	/* Password aging info */

	/* Write general information */
	(void) fprintf(stdout, "%-14s  %-6u  %-14s  %-6u  %s\n",
	    current->loginID, current->userID,
	    current->groupname == NULL ? "" : current->groupname,
	    current->groupID, current->freefield);

	/*
	 * Write information about secondary groups if the info exists
	 * (it only exists if it is to be written)
	 */
	for (psecgrp = current->secgrplist; psecgrp; psecgrp = psecgrp->next) {
	    (void) fprintf(stdout, "                        %-14s  %-6u\n",
		psecgrp->groupname, psecgrp->groupID);
	}

	/*
	 * If the extended information flag is TRUE,
	 * write the extended information
	 */

	if (xtndflag) {
		pwdinfo = current->passwdinfo;
		(void) fprintf(stdout, "                        %s\n",
		    current->iwd);
		(void) fprintf(stdout, "                        %s\n",
		    current->shell);
		(void) fprintf(stdout, "                        %s "
		    "%6.6ld %ld %ld %ld\n",
		    pwdinfo->passwdstatus,
		    pwdinfo->datechg, pwdinfo->mindaystilchg,
		    pwdinfo->maxdaystilchg,
		    pwdinfo->warninterval);
	}

	/*
	 * If the password expiration info flag is TRUE,
	 * write that information
	 */
	if (expflag) {
		pwdinfo = current->passwdinfo;
		(void) fprintf(stdout, "                        %ld %6.6ld\n",
		    pwdinfo->inactive, pwdinfo->expdate);
	}
}


/*
 *  void genuidreport(pipeflag, xtndflag, expflag)
 *	int	pipeflag
 *	int	xtndflag
 *	int	expflag
 *
 *	This function generates a report on the standard output
 *	stream (stdout) containing the login-IDs in the list of
 *	logins built by this command.  The list is ordered based
 *	on user-ID.  If the <pipeflag> variable is not zero, it
 *	will generate a report containing parsable records.
 *	Otherwise, it will generate a columnarized report.  If
 *	the <xtndflag> variable is not zero, it will include the
 *	extended set of information (password aging info, home
 *	directory, shell process, etc.).  If <expflag> is not
 *	zero, it will display password expiration information.
 *
 *  Arguments:
 *	pipeflag	int
 *			TRUE if a parsable report is needed,
 *			FALSE if a columnar report is needed
 *	xtndflag	int
 *			TRUE if extended set of info is to be displayed,
 *			FALSE otherwise
 *	expflag		int
 *			TRUE if password expiration information is to be
 *			displayed, FALSE otherwise
 *
 *  Returns:  void
 */

static void
genuidreport(int pipeflag, int xtndflag, int expflag)
{

	struct display *current;	/* Data being displayed */


	/*
	 *  Initialization for loop.
	 *  (NOTE:  The first element in the list of logins to	display is
	 *  a dummy element.)
	 */
	current = displayhead;

	/*
	 *  Display elements in the list
	 */
	if (pipeflag) {
		for (current = displayhead->nextuid; current;
		    current = current->nextuid) {
			writeunformatted(current, xtndflag, expflag);
		}
	} else {
		for (current = displayhead->nextuid; current;
		    current = current->nextuid) {
			writeformatted(current, xtndflag, expflag);
		}
	}
}


/*
 *  void genlogreport(pipeflag, xtndflag, expflag)
 *	int	pipeflag
 *	int	xtndflag
 *	int	expflag
 *
 *	This function generates a report on the standard output
 *	stream (stdout) containing the login-IDs in the list of
 *	logins built by this command.  The list is ordered based
 *	on user name.  If the <pipeflag> variable is not zero, it
 *	will generate a report containing parsable records.
 *	Otherwise, it will generate a columnarized report.  If
 *	the <xtndflag> variable is not zero, it will include the
 *	extended set of information (password aging info, home
 *	directory, shell process, etc.).  If <expflag> is not
 *	zero, it will include password expiration information.
 *
 *  Arguments:
 *	pipeflag	int
 *			TRUE if a parsable report is needed,
 *			FALSE if a columnar report is needed
 *	xtndflag	int
 *			TRUE if extended set of info is to be displayed,
 *			FALSE otherwise
 *	expflag		int
 *			TRUE if password expiration information is to
 *			be displayed, FALSE otherwise
 *
 *  Returns:  void
 */

static void
genlogreport(int pipeflag, int xtndflag, int expflag)
{
	struct display *p;	/* Value being displayed */


	/*
	 *  Initialization for loop.
	 *  (NOTE:  The first element in the list of logins to display is
	 *  a dummy element.)
	 */
	p = displayhead;

	/*
	 *  Display elements in the list
	 */
	if (pipeflag) {
		for (p = displayhead->nextlogin; p; p = p->nextlogin) {
			writeunformatted(p, xtndflag, expflag);
		}
	} else {
		for (p = displayhead->nextlogin; p; p = p->nextlogin) {
			writeformatted(p, xtndflag, expflag);
		}
	}
}

struct localpw {
	struct localpw *next;
	struct passwd pw;
};

struct localpw *pwtable = NULL;

/* Local passwd pointer for getpwent() -- -1 means not in use, NULL for EOF */
struct localpw *pwptr;

int in_localgetpwent = 0;	/* Set if in local_getpwent */

static struct localpw *
fill_localpw(struct localpw *lpw, struct passwd *pw) {
	struct localpw *cur;

	/*
	 * Copy the data -- we have to alloc areas for it all
	 */
	lpw->pw.pw_name = strdup(pw->pw_name);
	lpw->pw.pw_passwd = strdup(pw->pw_passwd);
	lpw->pw.pw_uid = pw->pw_uid;
	lpw->pw.pw_gid = pw->pw_gid;
	lpw->pw.pw_age = strdup(pw->pw_age);
	lpw->pw.pw_comment = strdup(pw->pw_comment);
	lpw->pw.pw_gecos  = strdup(pw->pw_gecos);
	lpw->pw.pw_dir = strdup(pw->pw_dir);
	lpw->pw.pw_shell = strdup(pw->pw_shell);

	cur = lpw;
	lpw->next = malloc(sizeof (struct localpw));
	return (cur);
}

void
build_localpw(struct reqlogin *req_head)
{
	struct localpw *next, *cur;
	struct passwd *pw;
	struct reqlogin *req_next;

	next = malloc(sizeof (struct localpw));

	pwtable = next;

	req_next = req_head;

	while (req_next != NULL) {
		if ((pw = getpwnam(req_next->loginname)) != NULL) {
			/*
			 * Copy the data -- we have to alloc areas for it all
			 */
			cur = fill_localpw(next, pw);
			req_next->found = TRUE;
			next = cur->next;
		}

		req_next = req_next->next;
	}

	if (req_head == NULL) {
		while ((pw = getpwent()) != NULL) {
			/*
			 * Copy the data -- we have to alloc areas for it all
			 */
			cur = fill_localpw(next, pw);
			next = cur->next;
		}
	}

	if (pwtable == next) {
		pwtable = NULL;
	} else {
		free(next);
		cur->next = NULL;
	}

	endpwent();
}

struct passwd *
local_getpwent(void)
{
	if (!in_localgetpwent) {
		in_localgetpwent = 1;
		pwptr = pwtable;
	} else if (pwptr != NULL) {
		pwptr = pwptr->next;
	}

	if (pwptr != NULL)
		return (&(pwptr->pw));
	else
		return (NULL);
}

void
local_endpwent(void)
{
	in_localgetpwent = 0;
}

long
local_pwtell(void)
{
	return ((long)pwptr);
}

void
local_pwseek(long ptr)
{
	pwptr = (struct localpw *)ptr;
}

/*
 * logins [-admopstux] [-l logins] [-g groups]
 *
 *	This command generates a report of logins administered on
 *	the system.  The list will contain logins that meet criteria
 *	described by the options in the list.  If there are no options,
 *	it will list all logins administered.  It is intended to be used
 *	only by administrators.
 *
 *  Options:
 *	-a		Display password expiration information.
 *	-d		list all logins that share user-IDs with another
 *			login.
 *	-g groups	specifies the names of the groups to which a login
 *			must belong before it is included in the generated
 *			list.  "groups" is a comma-list of group names.
 *	-l logins	specifies the logins to display.  "logins" is a
 *			comma-list of login names.
 *	-m		in addition to the usual information, for each
 *			login displayed, list all groups to which that
 *			login is member.
 *	-o		generate a report as a colon-list instead of in a
 *			columnar format
 *	-p		list all logins that have no password.
 *	-s		list all system logins
 *	-t		sort the report lexicographically by login name
 *			instead of by user-ID
 *	-u		list all user logins
 *	-x		in addition to the usual information, display an
 *			extended set of information that includes the home
 *			directory, initial process, and password status and
 *			aging information
 *
 * Exit Codes:
 *	0	All's well that ends well
 *	1	Usage error
 */

int
main(int argc, char *argv[])
{
	struct passwd	*plookpwd;	/* Ptr to searcher pw (-d) */
	struct reqgrp	*reqgrphead;	/* Head of the req'd group list */
	struct reqgrp	*pgrp;		/* Current item in req'd group list */
	struct reqgrp	*qgrp;		/* Prev item in the req'd group list */
	struct reqlogin *reqloginhead;	/* Head of req'd login list */
	struct reqlogin *plogin;	/* Current item in req'd login list */
	struct reqlogin *qlogin;	/* Prev item in req'd login list */
	struct passwd	*pwent;		/* /etc/passwd entry */
	struct group	*grent;		/* /etc/group entry */
	char		*token;		/* Token extracted by strtok() */
	char		**pp;		/* Group member */
	char		*g_arg;		/* -g option's argument */
	char		*l_arg;		/* -l option's argument */
	long		lookpos;	/* File pos'n, rec we're looking for */
	int		a_seen;		/* Is -a requested? */
	int		d_seen;		/* Is -d requested? */
	int		g_seen;		/* Is -g requested? */
	int		l_seen;		/* Is -l requested? */
	int		m_seen;		/* Is -m requested? */
	int		o_seen;		/* Is -o requested? */
	int		p_seen;		/* Is -p requested? */
	int		s_seen;		/* Is -s requested? */
	int		t_seen;		/* Is -t requested? */
	int		u_seen;		/* Is -u requested? */
	int		x_seen;		/* Is -x requested? */
	int		errflg;		/* Is there a command-line problem */
	int		done;		/* Is the process (?) is complete */
	int		groupcount;	/* Number of groups specified */
	int		doall;		/* Are all logins to be reported */
	int		c;		/* Character returned from getopt() */

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* Initializations */
	initmsg(argv[0]);



	/*  Command-line processing */

	/* Initializations */
	a_seen = FALSE;
	d_seen = FALSE;
	g_seen = FALSE;
	l_seen = FALSE;
	m_seen = FALSE;
	o_seen = FALSE;
	p_seen = FALSE;
	s_seen = FALSE;
	t_seen = FALSE;
	u_seen = FALSE;
	x_seen = FALSE;
	errflg = FALSE;
	opterr = 0;
	while (!errflg && ((c = getopt(argc, argv, OPTSTR)) != EOF)) {

		/* Case on the option character */
		switch (c) {

		/*
		 * -a option:
		 * Display password expiration information
		 */

		case 'a':
			if (a_seen)
				errflg = TRUE;
			else
				a_seen = TRUE;
			break;

		/*
		 * -d option:
		 * Display logins which share user-IDs with other logins
		 */

		case 'd':
			if (d_seen)
				errflg = TRUE;
			else
				d_seen = TRUE;
			break;

		/*
		 * -g <groups> option:
		 * Display the specified groups
		 */

		case 'g':
			if (g_seen) {
				errflg = TRUE;
			} else {
				g_seen = TRUE;
				g_arg = optarg;
			}
			break;

		/*
		 * -l <logins> option:
		 * Display the specified logins
		 */

		case 'l':
			if (l_seen) {
				errflg = TRUE;
			} else {
				l_seen = TRUE;
				l_arg = optarg;
			}
			break;

		/*
		 * -m option:
		 * Display multiple group information
		 */

		case 'm':
			if (m_seen)
				errflg = TRUE;
			else
				m_seen = TRUE;
			break;

		/*
		 * -o option:
		 * Display information as a colon-list
		 */

		case 'o':
			if (o_seen)
				errflg = TRUE;
			else
				o_seen = TRUE;
			break;

		/*
		 * -p option:
		 * Select logins that have no password
		 */

		case 'p':
			if (p_seen)
				errflg = TRUE;
			else
				p_seen = TRUE;
			break;

		/*
		 * -s option:
		 * Select system logins
		 */

		case 's':
			if (s_seen)
				errflg = TRUE;
			else
				s_seen = TRUE;
			break;

		/*
		 * -t option:
		 * Sort alphabetically by login-ID instead of numerically
		 * by user-ID
		 */

		case 't':
			if (t_seen)
				errflg = TRUE;
			else
				t_seen = TRUE;
			break;

		/*
		 * -u option:
		 * Select user logins
		 */

		case 'u':
			if (u_seen)
				errflg = TRUE;
			else
				u_seen = TRUE;
			break;

		/*
		 * -x option:
		 * Display extended info (init working dir, shell, pwd info)
		 */

		case 'x':
			if (x_seen)
				errflg = TRUE;
			else
				x_seen = TRUE;
			break;

		default:		/* Oops.... */
			errflg = TRUE;
		}
	}

	/* Write out a usage message if necessary and quit */
	if (errflg || (optind != argc)) {
		wrtmsg(MM_ERROR, MM_NULLACT, MM_NULLTAG, gettext(USAGE_MSG));
		exit(1);
	}

	/*
	 *  The following section does preparation work, setting up for
	 *  building the list of logins to display
	 */


	/*
	 *  If -l logins is on the command line, build a list of
	 *  logins we're to generate reports for.
	 */

	if (l_seen) {
		reqloginhead = NULL;
		if (token = strtok(l_arg, ",")) {
			plogin = malloc(sizeof (struct reqlogin));
			plogin->loginname = token;
			plogin->found = FALSE;
			plogin->next = NULL;
			reqloginhead = plogin;
			qlogin = plogin;
			while (token = strtok(NULL, ",")) {
				plogin = malloc(sizeof (struct reqlogin));
				plogin->loginname = token;
				plogin->found = FALSE;
				plogin->next = NULL;
				qlogin->next = plogin;
				qlogin = plogin;
			}
		}
		/*
		 * Build an in-core structure of just the passwd database
		 * entries requested.  This greatly reduces the time
		 * to get all entries and filter later.
		 */
		build_localpw(reqloginhead);
	} else {
		/*
		 * Build an in-core structure of all passwd database
		 * entries.  This is important since we have to assume that
		 * getpwent() is going out to one or more network name
		 * services that could be changing on the fly.  This will
		 * limit us to one pass through the network data.
		 */
		build_localpw(NULL);
	}

	/*
	 *  If the -g groups option was on the command line, build a
	 *  list containing groups we're to list logins for.
	 */

	if (g_seen) {
		groupcount = 0;
		reqgrphead = NULL;
		if (token = strtok(g_arg, ",")) {
			pgrp = malloc(sizeof (struct reqgrp));
			pgrp->groupname = token;
			pgrp->next = NULL;
			groupcount++;
			reqgrphead = pgrp;
			qgrp = pgrp;
			while (token = strtok(NULL, ",")) {
				pgrp = malloc(sizeof (struct reqgrp));
				pgrp->groupname = token;
				pgrp->next = NULL;
				groupcount++;
				qgrp->next = pgrp;
				qgrp = pgrp;
			}
		}
	}


	/*
	 *  Generate the list of login information to display
	 */

	/* Initialize the login list */
	membershead = NULL;


	/*
	 *  If -g groups was specified, generate a list of members
	 *  of the specified groups
	 */

	if (g_seen) {
		/* For each group mentioned with the -g option ... */
		for (pgrp = reqgrphead; (groupcount > 0) && pgrp;
		    pgrp = pgrp->next) {
			if ((grent = getgrnam(pgrp->groupname)) != NULL) {
				/*
				 * Remembering the group-ID for later
				 */

				groupcount--;
				pgrp->groupID = grent->gr_gid;
				for (pp = grent->gr_mem; *pp; pp++) {
					addmember(*pp);
				}
			} else {
				wrtmsg(MM_WARNING, MM_NULLACT, MM_NULLTAG,
				    gettext("%s was not found"),
				    pgrp->groupname);
			}
		}
	}


	/* Initialize the list of logins to display */
	initdisp();


	/*
	 *  Add logins that have user-IDs that are used more than once,
	 *  if requested.  This command is pretty slow, since the algorithm
	 *  reads from the /etc/passwd file 1+2+3+...+n times where n is the
	 *  number of login-IDs in the /etc/passwd file.  (Actually, this
	 *  can be optimized so it's not quite that bad, but the order or
	 *  magnitude stays the same.)
	 *
	 *  Note:  This processing needs to be done before any other options
	 *	   are processed -- the algorithm contains an optimization
	 *	   that insists on the display list being empty before this
	 *	   option is processed.
	 */

	if (d_seen) {

		/*
		 * The following code is a quick&dirty reimplementation of the
		 * original algorithm, which opened the password file twice (to
		 * get two file pointer into the data) and then used fgetpwent()
		 * in undocumented ways to scan through the file, checking for
		 * duplicates.  This does not work when getpwent() is used to
		 * go out over the network, since there is not file pointer.
		 *
		 * Instead an in-memory list of passwd structures is built,
		 * and then this list is scanned.  The routines
		 * Local_getpwent(), etc., are designed to mimic the standard
		 * library routines, so this code does not have to be
		 * extensively modified.
		 */

		/*
		 * For reference, here is the original comment about the next
		 * section of code.  Some of the code has changed, but the
		 * algorithm is the same:
		 *
		 * Open the system password file once.  This instance will be
		 * used to leaf through the file once, reading each entry once,
		 * and searching the remainder of the file for another login-ID
		 * that has the same user-ID.  Note that there are lots of
		 * contortions one has to go through when reading two instances
		 * of the /etc/passwd file.  That's why there's some seeking,
		 * re-reading of the same record, and other junk.  Luckily, this
		 * feature won't be requested very often, and still isn't too
		 * slow...
		 */

		/* For each entry in the passwd database ... */
		while (plookpwd = local_getpwent()) {
			/*
			 * Optimization -- If the login's user-ID is already
			 * in the display list, there's no reason to process
			 * this  entry -- it's already there.
			 */
			if (!isuidindisp(plookpwd)) {
				/*
				 * Rememeber the current entry's position,
				 * so when we finish scanning through the
				 * database looking for duplicates we can
				 * return to the current place, so that the
				 * enclosing loop will march in an orderly
				 * fashion through the passwd database.
				 */
				done = FALSE;
				lookpos = local_pwtell();

				/*
				 * For each record in the passwd database
				 * beyond the searching record ...
				 */
				while (pwent = local_getpwent()) {

					/*
					 * If there's a match between the
					 * searcher's user-ID and the
					 * searchee's user-ID ...
					 */
					if (pwent->pw_uid == plookpwd->pw_uid) {
						/*
						 * If this is the first
						 * duplicate of this searcher
						 * that we find,
						 * add the searcher's
						 * record to the display list
						 * (It wants to be on the
						 * list first to avoid
						 * ordering "flakeyness")
						 */
						if (done == FALSE) {
							adddisp(plookpwd);
							done = TRUE;
						}

						/*
						 * Now add the searchee's
						 * record
						 */
						adddisp(pwent);

					}
				}
				/* Reposition to searcher record */
				local_pwseek(lookpos);
			}
		}

		local_endpwent();
	}


	/*
	 *  Loop through the passwd database squirelling away the
	 *  information we need for the display.
	 *
	 *  NOTE:  Once a login is added to the list, the rest of the
	 *	   body of the loop is bypassed (via a continue statement).
	 */

	doall = !(s_seen || u_seen || p_seen || d_seen || l_seen || g_seen);

	if (doall || s_seen || u_seen || p_seen || l_seen || g_seen) {

		while (pwent = local_getpwent()) {
			done = FALSE;

			/*
			 * If no user-specific options were specified,
			 * include this login-ID
			 */
			if (doall) {
				adddisp(pwent);
				continue;
			}

			/*
			 * If the user specified system login-IDs,
			 * and this is a system ID, include it
			 */
			if (s_seen) {
				if (isasystemlogin(pwent)) {
					adddisp(pwent);
					continue;
				}
			}

			/*
			 * If the user specified user login-IDs,
			 * and this is a user ID, include it
			 */
			if (u_seen) {
				if (isauserlogin(pwent)) {
					adddisp(pwent);
					continue;
				}
			}

			/*
			 * If the user is asking for login-IDs that have
			 * no password, and this one has no password, include it
			 */
			if (p_seen) {
				if (hasnopasswd(pwent)) {
					adddisp(pwent);
					continue;
				}
			}

			/*
			 * If specific logins were requested, leaf through
			 * the list of logins they requested.  If this login
			 * is on the list, include it.
			 */
			if (l_seen) {
				for (plogin = reqloginhead; !done && plogin;
				    plogin = plogin->next) {
					if (strcmp(pwent->pw_name,
					    plogin->loginname) == 0) {
						plogin->found = TRUE;
						adddisp(pwent);
						done = TRUE;
					}
				}
				if (done)
					continue;
			}

			/*
			 * If specific groups were requested, leaf through the
			 * list of login-IDs that belong to those groups.
			 * If this login-ID is in that list, or its primary
			 * group is one of those requested, include it.
			 */

			if (g_seen) {
				for (pgrp = reqgrphead; !done && pgrp;
				    pgrp = pgrp->next) {
					if (pwent->pw_gid == pgrp->groupID) {
						adddisp(pwent);
						done = TRUE;
					}
				}
				if (!done && isamember(pwent->pw_name)) {
					adddisp(pwent);
					done = TRUE;
				}
			}
			if (done)
				continue;
		}

		local_endpwent();
	}

	/* Let the user know about logins they requested that don't exist */
	if (l_seen) {
		for (plogin = reqloginhead; plogin; plogin = plogin->next) {
			if (!plogin->found) {
				wrtmsg(MM_WARNING, MM_NULLACT, MM_NULLTAG,
				    gettext("%s was not found"),
				    plogin->loginname);
			}
		}
	}

	/*  Apply group information */
	applygroup(m_seen);


	/*
	 * Apply password information (only needed if the extended
	 * set of information has been requested)
	 */
	if (x_seen || a_seen)
		applypasswd();


	/*
	 * Generate a report from this display items we've squirreled away
	 */

	if (t_seen)
		genlogreport(o_seen, x_seen, a_seen);
	else
		genuidreport(o_seen, x_seen, a_seen);

	/*  We're through! */
	return (0);
}
