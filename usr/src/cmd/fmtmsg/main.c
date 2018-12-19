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

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * fmtmsg.c
 *
 * Contains:
 *	fmtmsg		Command that writes a message in the standard
 *			message format.  May in future make these
 *			messages available for logging.
 */


/*
 * Header files used:
 *	<stdio.h>	C Standard I/O function definitions
 *	<string.h>	C string-handling definitions
 *	<errno.h>	UNIX error-code "errno" definitions
 *	<fmtmsg.h>	Standard Message definitions
 */

#include	<stdio.h>
#include	<string.h>
#include	<errno.h>
#include	<fmtmsg.h>


/*
 * Externals referenced:
 *	strtol		Function that converts char strings to "long"
 *	fmtmsg		Function that writes a message in standard format
 *	getenv		Function that extracts an environment variable's
 *			value
 *	malloc		Allocate memory from the memory pool
 *	free		Frees allocated memory
 *	getopt		Function that extracts arguments from the command-
 *	optarg		Points to option's argument (from getopt())
 *	optind		Option's argument index (from getopt())
 *	opterr		FLAG, write error if invalid option (for getopt())
 *			line.
 *	exit		Exits the command
 */

extern	long		strtol();
extern	int		fmtmsg();
extern	char	       *getenv();
extern	void	       *malloc();
extern	void		free();
extern	int		getopt();
extern	char	       *optarg;
extern	int		optind;
extern	int		opterr;
extern	void		exit();

/*
 * Local definitions
 */

/*
 * Local constants
 */


/*
 * Boolean constants
 *	TRUE	Boolean value for "true" (any bits on)
 *	FALSE	Boolean value for "false" (all bits off)
 */

#ifndef	FALSE
#define	FALSE		(0)
#endif

#ifndef TRUE
#define	TRUE		(1)
#endif


#define	CLASS		(MM_PRINT|MM_SOFT|MM_NRECOV|MM_UTIL)
#define BIGUSAGE	"fmtmsg [-a action] [-c class] [-l label] [-s severity] [-t tag]\n       [-u subclass[,subclass[,...]]] [text]\n"


/*
 * Local data-type definitions
 */

/*
 * Structure used for tables containing keywords and integer values
 */

struct sev_info {
	char   *keyword;
	int	value;
};


/*
 * Structure used for tables containing keywords, long values
 */

struct class_info {
	char   *keyword;
	long	value;
	long	conflict;
};


/*
 * Severity string structure
 *
 *	struct sevstr
 *		sevvalue	Value of the severity-level being defined
 *		sevkywd		Keyword identifying the severity
 *		sevprptr	Pointer to the string associated with the value
 *		sevnext		Pointer to the next value in the list.
 */

struct sevstr {
	int		sevvalue;
	char           *sevkywd;
	char	       *sevprstr;
	struct sevstr  *sevnext;
};


/*
 * Local static data
 */


/*
 * Table contains the keywords for the classes of a message
 */

static	struct class_info	classes[] = {

	{"hard", 	MM_HARD,	MM_SOFT|MM_FIRM},	/* hardware */
	{"soft", 	MM_SOFT,	MM_HARD|MM_FIRM},	/* software */
	{"firm", 	MM_FIRM,	MM_SOFT|MM_FIRM},	/* firmware */

	{(char *) NULL,	0L,		0L}			/* end of list */

};


/*
 * Table contains the keywords for the subclasses for a message
 */

static	struct class_info	subclasses[] = 	{

	{"appl",     	MM_APPL,	MM_UTIL|MM_OPSYS},	/* Application */
	{"util",     	MM_UTIL,	MM_APPL|MM_OPSYS},	/* Utility */
	{"opsys",    	MM_OPSYS,	MM_APPL|MM_UTIL},	/* Operating System */

	{"recov",    	MM_RECOVER,	MM_NRECOV},		/* Recoverable */
	{"nrecov",   	MM_NRECOV,	MM_RECOVER},		/* Non-recoverable */

	{"print",    	MM_PRINT,	0L}, 			/* Write message to stderr */
	{"console",  	MM_CONSOLE,	0L},			/* Write message on /dev/console */
	{(char *) NULL,	0L,		0L}			/* End of list */

};


/*
 * Table contains the keywords for the standard severities of a message.
 * User may supply more through the SEV_LEVEL environment variable.
 */

static  struct sev_info		severities[] =  {
	{"halt",	MM_HALT},	/* halt */
	{"error",	MM_ERROR},	/* error */
	{"warn",	MM_WARNING},	/* warn */
	{"info",	MM_INFO},	/* info */
	{(char *) NULL,	0}		/* end of list */
};


/*
 * Buffers used by the command
 */

static	char	labelbuf[128];		/* Buf for message label */
static	char	msgbuf[256];		/* Buf for messages */

/*
 * static char *exttok(str, delims)
 *	char   *str
 *	char   *delims
 *
 *	This function examines the string pointed to by "str", looking
 *	for the first occurrence of any of the characters in the string
 *	whose address is "delims".  It returns the address of that
 *	character or (char *) NULL if there was nothing to search.
 *
 * Arguments:
 *	str	Address of the string to search
 *	delims	Address of the string containing delimiters
 *
 * Returns:  char *
 *	Returns the address of the first occurrence of any of the characters
 *	in "delim" in the string "str" (incl '\0').  If there was nothing
 *	to search, the function returns (char *) NULL.
 *
 * Notes:
 *    - This function is needed because strtok() can't be used inside a
 *	function.  Besides, strtok() is destructive in the string, which
 *	is undesirable in many circumstances.
 *    - This function understands escaped delimiters as non-delimiters.
 *	Delimiters are escaped by preceding them with '\' characters.
 *	The '\' character also must be escaped.
 */

static char *
exttok(tok, delims)
	char   *tok;		/* Ptr to the token we're parsing */
	char   *delims;		/* Ptr to string with delimiters */
{

	/* Automatic Data */
	char   *tokend;		/* Ptr to the end of the token */
	char   *p, *q;	 	/* Temp pointers */


	/* Algorithm:
	 *    1.  Get the starting address (new string or where we
	 *	  left off).  If nothing to search, return (char *) NULL
	 *    2.  Find the end of the string
	 *    3.  Look for the first unescaped delimiter closest to the 
	 *	  beginning of the string
	 *    4.  Remember where we left off
	 *    5.  Return a pointer to the delimiter we found
	 */

	/* Begin at the beginning, if any */
	if (tok == (char *) NULL) {
	    return ((char *) NULL);
	}

	/* Find end of the token string */
	tokend = tok + strlen(tok);

	/* Look for the 1st occurrence of any delimiter */
	for (p = delims ; *p != '\0' ; p++) {
	    for (q = strchr(tok, *p) ; q && (q != tok) && (*(q-1) == '\\') ; q = strchr(q+1, *p)) ;
	    if (q && (q < tokend)) tokend = q;
	}

	/* Done */
	return(tokend);
}

/*
 * char *noesc(str)
 *	
 *	This function squeezes out all of the escaped character sequences
 *	from the string <str>.  It returns a pointer to that string.
 *
 *  Arguments:
 *	str	char *
 *		The string that is to have its escaped characters removed.
 *
 *  Returns:  char *
 *	This function returns its argument <str> always.
 *
 *  Notes:
 *	This function potentially modifies the string it is given.
 */

char *
noesc(str) 
	char   *str;		/* String to remove escaped characters from */
{
	char   *p;		/* Temp string pointer */
	char   *q;		/* Temp string pointer */

	/* Look for an escaped character */
	p = str;
	while (*p && (*p != '\\')) p++;


	/* 
	 * If there was at least one, squeeze them out 
	 * Otherwise, don't touch the argument string 
	 */

	if (*p) {
	    q = p++;
	    while (*q++ = *p++) if (*p == '\\') p++;
	}

	/* Finished.  Return our argument */
	return(str);
}

/*
 * struct sevstr *getauxsevs(ptr)
 *
 *	Parses a string that is in the format of the severity definitions.
 *	Returns a pointer to a (malloc'd) structure that contains the
 *	definition, or (struct sevstr *) NULL if none was parsed.
 *
 * Arguments:
 *	ptr	char *
 *		References the string from which data is to be extracted.
 *		If (char *) NULL, continue where we left off.  Otherwise,
 *		start with the string referenced by ptr.
 *
 * Returns: struct sevstr *
 *	A pointer to a malloc'd structure containing the severity definition
 *	parsed from string, or (struct sevstr *) NULL if none.
 *
 * Notes:
 *    - This function is destructive to the string referenced by its argument.
 */


/* Static data */
static	char	       *leftoff = (char *) NULL;

static	struct sevstr *
getauxsevs(ptr)
	char   *ptr;
{

	/* Automatic data */
	char	       *current;	/* Ptr to current sev def'n */
	char	       *tokend;		/* Ptr to end of current sev def'n */
	char	       *kywd;		/* Ptr to extracted kywd */
	char	       *valstr;		/* Ptr to extracted sev value */
	char	       *prstr;		/* Ptr to extracted print str */
	char	       *p;		/* Temp pointer */
	int		val;		/* Converted severity value */
	int		done;		/* Flag, sev def'n found and ok? */
	struct sevstr  *rtnval;		/* Value to return */


	/* Start anew or start where we left off? */
	current = (ptr == (char *) NULL) ? leftoff : ptr;


	/* If nothing to parse, return (char *) NULL */
	if (current == (char *) NULL) {
	    return ((struct sevstr *) NULL);
	}


	/*
	 * Look through the string "current" for a token of the form
	 * <kywd>,<sev>,<printstring> delimited by ':' or '\0'
	 */

	/* Loop initializations */
	done = FALSE;
	rtnval = (struct sevstr *) NULL;
	while (!done) {

	    /* Eat leading junk */
	    while (*(tokend = exttok(current, ":,")) == ':') {
		current = tokend + 1;
	    }

	    /* If we've found a <kywd>,... */
	    if (*tokend == ',') {
		kywd = current;
		*tokend = '\0';

		/* Look for <kywd>,<sev>,... */
		current = tokend + 1;
		if (*(tokend = exttok(current, ":,")) == ',') {
		    valstr = current;
		    *tokend = '\0';
		    current = tokend+1;
		    prstr = current;

		    /* Make sure <sev> > 4 */
		    val = (int) strtol(noesc(valstr), &p, 0);
		    if ((val > 4) && (p == tokend)) {

			/*
			 * Found <kywd>,<sev>,<printstring>.
			 * remember where we left off
			 */

		        if (*(tokend = exttok(current, ":")) == ':') {
			    *tokend = '\0';
			    leftoff = tokend + 1;
			} else leftoff = (char *) NULL;

			/* Alloc structure to contain severity definition */
			if (rtnval = (struct sevstr *) malloc(sizeof(struct sevstr))) {

			    /* Fill in structure */
			    rtnval->sevkywd = noesc(kywd);
			    rtnval->sevvalue = val;
			    rtnval->sevprstr = noesc(prstr);
			    rtnval->sevnext = (struct sevstr *) NULL;
			}

			done = TRUE;

		    } else {

			/* Invalid severity value, eat thru end of token */
			current = tokend;
			if (*(tokend = exttok(prstr, ":")) == ':')
			    current++;
		    }

		} else {

		    /* Invalid severity definition, eat thru end of token */
		    current = tokend;
		    if (*tokend == ':')
			current++;
		}

	    } else {

		/* End of string found */
		done = TRUE;
		leftoff = (char *) NULL;
	    }

	} /* while (!done) */

	/* Finished */
	return(rtnval);
}

/*
 * fmtmsg [-a action] [-c classification] [-l label] [-s severity] [-t tag]
 *        [-u subclass[,subclass[,...]]] [text]
 *
 * Function:
 *	Writes a message in the standard format.  Typically used by shell
 *	scripts to write error messages to the user.
 *
 * Arguments:
 *	text		String that is the text of the message
 *
 * Options:
 *   -a action		String that describes user action to take to
 *			correct the situation
 *   -c classification	Keyword that identifies the type of the message
 *   -l label		String that identifies the source of the message
 *   -s severity	Keyword that identifies the severity of the message
 *   -t tag		String that identifies the message (use unclear)
 *   -u sub_classes	Comma-list of keywords that refines the type of
 *			the message
 *
 * Environment Variables Used:
 *	MSGVERB		Defines the pieces of a message the user expects
 *			to see.  It is a list of keywords separated by
 *			colons (':').
 *	SEV_LEVEL	Defines a list of auxiliary severity keywords, values,
 *			and print-strings.  It is a list of fields separated
 *			by colons (':').  Each field consists of three
 *			elements, keyword, value (in octal, hex, or decimal),
 *			and print-string, separated by commas (',').
 *
 * Needs:
 *
 * Open Issues:
 */

int
main(int argc, char **argv)
{

	/* Local automatic data */

	long			class;		/* Classification (built) */

	int			severity;	/* User specified severity */
	int			msgrtn;		/* Value returned by fmtmsg() */
	int			optchar;	/* Opt char on cmdline */
	int			exitval;	/* Value to return */

	int			found;		/* FLAG, kywd found yet? */
	int			errflg;		/* FLAG, error seen in cmd */
	int			a_seen;		/* FLAG, -a option seen */
	int			c_seen;		/* FLAG, -c option seen */
	int			l_seen;		/* FLAG, -l option seen */
	int			s_seen;		/* FLAG, -s option seen */
	int			t_seen;		/* FLAG, -t option seen */
	int			u_seen;		/* FLAG, -u option seen */
	int			text_seen;	/* FLAG, text seen */

	char		       *text;		/* Ptr to user's text */
	char		       *label;		/* Ptr to user's label */
	char		       *tag;		/* Ptr to user's tag */
	char		       *action;		/* Ptr to user's action str */
	char		       *sstr;		/* Ptr to -s (severity) arg */
	char		       *ustr;		/* Ptr to -u (subclass) arg */
	char		       *cstr;		/* Ptr to -c (class) arg */
	char		       *sevstrval;	/* Ptr to SEV_LEVEL argument */
	char		       *sevval;		/* Ptr to temp SEV_LEVEL arg */
	char		       *tokenptr;	/* Ptr to current token */
	char		       *cmdname;	/* Ptr to base command name */
	char		       *p;		/* Multipurpose ptr */

	struct class_info      *class_info;	/* Ptr to class/subclass info structure */
	struct sev_info	       *sev_info;	/* Ptr to severity info struct */
	struct sevstr	       *penvsev;	/* Ptr to SEV_LEVEL values */



	/*
	 * fmtmsg
	 */


	/* Initializations */


	/* Extract the base command name from the command */
	if ((p = strrchr(argv[0], '/')) == (char *) NULL)
	    cmdname = argv[0];
	else
	    cmdname = p+1;

	/* Build the label for messages from "fmtmsg" */
	(void) snprintf(labelbuf, sizeof (labelbuf), "UX:%s", cmdname);


	/*
	 * Extract arguments from the command line
	 */

	/* Initializations */

	opterr = 0;			/* Disable messages from getopt() */
	errflg = FALSE;			/* No errors seen yet */

	a_seen = FALSE;			/* No action (-a) text seen yet */
	c_seen = FALSE;			/* No classification (-c) seen yet */
	l_seen = FALSE;			/* No label (-l) seen yet */
	s_seen = FALSE;			/* No severity (-s) seen yet */
	t_seen = FALSE;			/* No tag (-t) seen yet */
	u_seen = FALSE;			/* No subclass (-u) seen yet */
	text_seen = FALSE;		/* No text seen yet */


	/*
	 * If only the command name was used, write out a usage string to
	 * the standard output file.
	 */

	if (argc == 1) {
	    (void) fputs(BIGUSAGE, stderr);
	    exit(0);
	}


	/* Parce command line */
	while (((optchar = getopt(argc, argv, "a:c:l:s:t:u:")) != EOF) &&
	       !errflg) {

	    switch(optchar) {

	    case 'a':		/* -a actiontext */
		if (!a_seen) {
		    action = optarg;
		    a_seen = TRUE;
		} else errflg = TRUE;
		break;

	    case 'c':		/* -c classification */
		if (!c_seen) {
		    cstr = optarg;
		    c_seen = TRUE;
		} else errflg = TRUE;
		break;

	    case 'l':		/* -l label */
		if (!l_seen) {
		    label = optarg;
		    l_seen = TRUE;
		} else errflg = TRUE;
		break;

	    case 's':		/* -s severity */
		if (!s_seen) {
		    sstr = optarg;
		    s_seen = TRUE;
		} else errflg = TRUE;
		break;

	    case 't':		/* -t tag */
		if (!t_seen) {
		    tag = optarg;
		    t_seen = TRUE;
		} else errflg = TRUE;
		break;

	    case 'u':		/* -u subclasslist */
		if (!u_seen) {
		    ustr = optarg;
		    u_seen = TRUE;
		} else errflg = TRUE;
		break;

	    case '?':		/* -? or unknown option */
	    default:
		errflg = TRUE;
		break;

	    } /* esac */
	}


	/* Get the text */
	if (!errflg) {
	    if (argc == (optind+1)) {
		text = argv[optind];
		text_seen = TRUE;
	    }
	    else if (argc != optind) {
		errflg = TRUE;
	    }
	}


	/* Report syntax errors */
	if (errflg) {
	    (void) fputs(BIGUSAGE, stderr);
	    exit(1);
	}


	/*
	 * Classification.
	 */

	class = 0L;
	if (c_seen) {

	    /* Search for keyword in list */
	    for (class_info = &classes[0] ;
		 (class_info->keyword != (char *) NULL) &&
		 (strcmp(cstr, class_info->keyword)) ;
		 class_info++) ;

	    /* If invalid (keyword unknown), write a message and exit */
	    if (class_info->keyword == (char *) NULL) {
		(void) snprintf(msgbuf, sizeof (msgbuf),
			"Invalid class: %s", cstr);
		(void) fmtmsg(CLASS, labelbuf, MM_ERROR, msgbuf,
		              MM_NULLACT, MM_NULLTAG);
		exit(1);
	    }

	    /* Save classification */
	    class = class_info->value;

	}


	/*
	 * Subclassification.
	 */

	if (u_seen) {

	    errflg = FALSE;
	    p = strcpy(malloc((unsigned int) strlen(ustr)+1), ustr);
	    if ((tokenptr = strtok(p, ",")) == (char *) NULL) errflg = TRUE;
	    else do {

		/* Got a keyword.  Look for it in keyword list */
		for (class_info = subclasses ;
		     (class_info->keyword != (char *) NULL) &&
		     (strcmp(tokenptr, class_info->keyword) != 0) ;
		     class_info++) ;

		/* If found in list and no conflict, remember in class */
		if ((class_info->keyword != (char *) NULL) && ((class & class_info->conflict) == 0L))
		    class |= class_info->value;
		else 
		    errflg = TRUE;

	    } while (!errflg && ((tokenptr = strtok((char *) NULL, ",")) != (char *) NULL)) ;

	    if (errflg) {
		(void) snprintf(msgbuf, sizeof (msgbuf),
			"Invalid subclass: %s", ustr);
		(void) fmtmsg(CLASS, labelbuf, MM_ERROR, msgbuf,
		              MM_NULLACT, MM_NULLTAG);
		exit(1);
	    }

	}

	if (!c_seen && !u_seen) class = MM_NULLMC;



	/*
	 * Severity.
	 */

	if (s_seen) {

	    /* If the severity is specified as a number, use that value */
	    severity = strtol(sstr, &p, 10);
	    if (*p || (strlen(sstr) == 0)) {

		/* Look for the standard severities */
		for (sev_info = severities ;
		     (sev_info->keyword != (char *) NULL) &&
		     (strcmp(sstr, sev_info->keyword)) ;
		     sev_info++) ;

		/*
		 * If the "severity" argument is one of the standard keywords,
		 * remember it for fmtmsg().  Otherwise, look at the SEV_LEVEL
		 * environment variable for severity extensions.
		 */

		/* If the keyword is one of the standard ones, save severity */
		if (sev_info->keyword != (char *) NULL) severity = sev_info->value;

		else {

		    /*
		     * Severity keyword may be one of the extended set, if any.
		     */

		    /* Get the value of the SEV_LEVEL environment variable */
		    found = FALSE;
		    if ((sevstrval = getenv(SEV_LEVEL)) != (char *) NULL) {
			sevval = (char *) malloc((unsigned int) strlen(sevstrval)+1);
			penvsev = getauxsevs(strcpy(sevval, sevstrval));
			if (penvsev != (struct sevstr *) NULL) do {
			    if (strcmp(penvsev->sevkywd, sstr) == 0) {
				severity = penvsev->sevvalue;
				found = TRUE;
			    }
			    else {
				free(penvsev);
				penvsev = getauxsevs((char *) NULL);
			    }
			} while (!found && (penvsev != (struct sevstr *) NULL));

			if (found) free(penvsev);
			free(sevval);
		    }

		    if (!found) {
			(void) snprintf(msgbuf, sizeof (msgbuf),
				"Invalid severity: %s", sstr);
			(void) fmtmsg(CLASS, labelbuf, MM_ERROR, msgbuf,
				      MM_NULLACT, MM_NULLTAG);
			exit(1);
		    }

		}  /* <severity> is not one of the standard severities */

	    }  /* <severity> is not numeric */

	}  /* if (s_seen) */

	else severity = MM_NULLSEV;


	/*
	 * Other options
	 */

	if (!a_seen) action = MM_NULLACT;
	if (!l_seen) label = MM_NULLLBL;
	if (!t_seen) tag = MM_NULLTAG;
	if (!text_seen) text = MM_NULLTXT;


	/*
	 * Write the message
	 */

	msgrtn = fmtmsg(class, label, severity, text, action ,tag);


	/*
	 * Return appropriate value to the shell (or wherever)
	 */

	exitval = 0;
	if (msgrtn == MM_NOTOK) exitval = 32;
	else {
	    if (msgrtn & MM_NOMSG) exitval += 2;
	    if (msgrtn & MM_NOCON) exitval += 4;
	}

	return(exitval);
}
