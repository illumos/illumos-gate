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


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	Implements the "putdev" command.
 */
#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include	<unistd.h>
#include	<fmtmsg.h>
#include	<devmgmt.h>
#include	<devtab.h>


/*
 * General Purpose Constants
 *	TRUE		Boolean TRUE (if not already defined)
 *	FALSE		Boolean FALSE (if not already defined)
 *	NULL		Null address (if not already defined)
 */

#ifndef	TRUE
#define	TRUE	(1)
#endif

#ifndef	FALSE
#define	FALSE	(0)
#endif

/*
 * Exit codes
 *	EX_OK		All went well
 *	EX_ERROR	Usage or internal error
 *	EX_DEVTAB	Had trouble accessing/reading/writing the device table
 *	EX_EXISTS	The specified alias already exists
 *	EX_ATTRIB	One or more attributes requested for removal was not
 *			defined for the device
 *	EX_RELPATH	Pathname supplied for cdevice, bdevice or pathname
 *			attributes was not a full pathname
 */

#define	EX_OK		0
#define	EX_ERROR	1
#define	EX_DEVTAB	2
#define	EX_EXISTS	3
#define	EX_ATTRIB	4
#define	EX_RELPATH	4


/*
 * Error messages
 */

#define	E_USAGE		"usage: putdev -a alias [attribute=value [...]]\n       putdev -m device attribute=value [attribute=value [...]]\n       putdev -d device [attribute [...]]"
#define	E_ALIASIS	"Alias already exists in table: %s"
#define	E_NODEV		"Device does not exist in table: %s"
#define	E_NOALIAS	"Cannot use \"alias\" as an attribute"
#define	E_NOATTR	"Attribute not found: %s"
#define	E_NODEVTAB	"Cannot open the device table: %s"
#define	E_NOMKDTAB	"Cannot create a new device table: %s"
#define	E_INVALIAS	"Not a valid device alias: %s"
#define E_MULTIPLE	"Multiple definitions of an attribute are not allowed."
#define	E_INTERNAL	"Internal error, errno=%d"
#define	E_RELPATH	"Full pathname required for cdevice,bdevice and pathname attributes."


/*
 * Macros
 *	stdmsg(r,l,s,t)	    Using fmtmsg(), write a standard message to the
 *			    standard error stream.
 *			    Where:
 *				r   The recoverability of the error
 *				l   The label-component
 *				s   The severity-component
 *				t   The text-component
 */

#define stdmsg(r,l,s,t) (void) fmtmsg(MM_PRINT|MM_UTIL|r,l,s,t,MM_NULLACT,MM_NULLTAG)


/*
 * Static data
 *	msg		Space for message's text-component
 */

static	char		msg[256];	/* Space for text of message */

/*
 * char *mklbl(cmd)
 *	char   *cmd
 *
 *	This function builds a standard label from the command used to invoke
 *	this process and the standard label prefix ("UX:")
 *
 * Arguments:
 *	char *cmd	The command used to invoke this process.
 *
 * Returns:  char *
 *	Pointer to malloc()ed space containing the standard label,
 *	or (char *) NULL if an error occurred.
 */

static char *
mklbl(cmd)
	char   *cmd;
{
	/* Automatic data */
	char   *rtn;		/* Value to return */
	char   *p;		/* Temporary */

	/* Find the 1st char of the basename of the command */
	if (p = strrchr(cmd, '/')) p++;
	else p = cmd;

	/* Allocate and build the string value to return */
	if (rtn = (char *) malloc(strlen("UX:")+strlen(p)+1)) {
	    (void) strcpy(rtn, "UX:");
	    (void) strcat(rtn, p);
	}


	/* Now that we've done all of that work, change the environment
	 * so that only the text-component is written by fmtmsg().
	 * (This should go away in SVR4.1)
	 */

	(void) putenv("MSGVERB=text");

	
	/* Done */
	return(rtn);
}

/*
 * putdev -a alias [attribute=value [...]]
 * putdev -m alias attribute=value [attribute=value [...]]
 * putdev -d alias [attribute [...]]
 *
 * 	Modify the device-table.  If -a specified, add a record for <alias>
 * 	to the table.  If -m specified, modify the attributes specified for
 *	the <device> specified.  If -d specified, remove the specified
 *	attributes from the specified device or remove the specified device.
 *
 * Options:
 *	-a		Add an alias description to the device table
 *	-m		Modify an existing device description
 *	-d		(if no attributes specified) remove the specified
 *			device from the device table, or (if attributes
 *			specified) remove the specified attributes from
 *			the specified device.
 *
 * Exit values:
 *	0		All went well
 *	1		Usage error (includes specifying "alias" as an
 *			<attribute>)
 *	2		The device table file could not be opened, read
 *			or modified
 *	3		If -a, the alias already exists.  Otherwise, the
 *			specified device does not exist in the table
 *	4		One of the specified attributes did not exist
 *			for the device and therefore wasn't removed
 */

int
main(int argc, char *argv[])
{
	/* Automatic data */
	char	      **plist;		/* Ptr to list of undef'nd attrs */
	char	       *lbl;		/* Ptr to label for messages */
	char	       *alias;		/* Ptr to <alias> on command-line */
	char	       *device;		/* Ptr to <device> on command-line */
	char	       *p;		/* Temp ptr to char */
	int		noerr;		/* FLAG, TRUE if all's well */
	int		a_seen;		/* TRUE if -a seen on command-line */
	int		m_seen;		/* TRUE if -m seen on command-line */
	int		d_seen;		/* TRUE if -a seen on command-line */
	int		optchar;	/* Option extracted */
	int		exitcd;		/* Value to return at exit */
	int		nattrs;		/* Number of attributes on command */


	/* Generate the label for messages */
	lbl = mklbl(argv[0]);

	/* Extract arguments - validate usage */
	noerr = TRUE;
	a_seen = FALSE;
	m_seen = FALSE;
	d_seen = FALSE;
	opterr = FALSE;
	while ((optchar = getopt(argc, argv, "a:d:m:")) != EOF) switch (optchar) {

	case 'a':
	    if (!(a_seen || m_seen || d_seen)) {
		a_seen = TRUE;
		alias = optarg;
	    }
	    else noerr = FALSE;
	    break;

	case 'd':
	    if (!(a_seen || m_seen || d_seen)) {
		d_seen = TRUE;
		device = optarg;
	    }
	    else noerr = FALSE;
	    break;

	case 'm':
	    if (!(a_seen || m_seen || d_seen)) {
		m_seen = TRUE;
		device = optarg;
	    }
	    else noerr = FALSE;
	    break;

	case '?':
	default:
	    noerr = FALSE;
	}


	/* Write a usage message if we've seen a blatant error */
	if (!(a_seen || m_seen || d_seen) || !noerr) {
	    stdmsg(MM_NRECOV, lbl, MM_ERROR, E_USAGE);
	    exit(EX_ERROR);
	}


	/* Set up */
	exitcd = EX_OK;
	nattrs = argc - optind;


	/*  putdev -a alias [attr=value [...]] */

	if (a_seen) {

	    /* Syntax check */
	    if (nattrs < 0) {
		stdmsg(MM_NRECOV, lbl, MM_ERROR, E_USAGE);
		exitcd = EX_ERROR;
	    } else {

		/* Attempt to add the new alias */
		if (!(_adddevtabrec(alias, &argv[optind]))) {

		    /* Attempt failed.  Write appropriate error message. */

		    switch(errno) {

		    /*
		     * EINVAL indicates that <alias> is not valid or "alias"
		     * was mentioned as <attr> in <attr>=<value> pair.  If the
		     * alias is a valid alias, assume that's the problem.
		     */

		    case EINVAL:
			if (_validalias(alias))
			    p = E_NOALIAS;
			else (void) snprintf(p=msg, sizeof(msg), E_INVALIAS, alias);
			stdmsg(MM_NRECOV, lbl, MM_ERROR, p);
			exitcd = EX_ERROR;
			break;

		    /*
		     * EEXIST indicates that the alias <alias> already exists
		     * in the device table.
		     */

		    case EEXIST:
			(void) snprintf(msg, sizeof(msg), E_ALIASIS, alias);
			stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
			exitcd = EX_EXISTS;
			break;

		    /*
		     * EACCES and ENOENT indicate problems reading or writing
		     * the device table.
		     */

		    case EACCES:
		    case ENOENT:
	                p = _devtabpath();
			if (access(p, R_OK) == 0)
			    (void) snprintf(msg, sizeof(msg), E_NOMKDTAB, p);
			else
			    (void) snprintf(msg, sizeof(msg), E_NODEVTAB, p);
			stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
			exitcd = EX_DEVTAB;
			break;

		    /*
		     * EAGAIN indicates that an attribute was defined on the
		     * command line more than once.
		     */

		    case EAGAIN:
			stdmsg(MM_NRECOV, lbl, MM_ERROR, E_MULTIPLE);
			exitcd = EX_ERROR;
			break;

		    /*
		     * ENXIO indicates that a relative pathname was supplied
		     * for the cdevice, bdevice or pathname attributes.  Full
		     * pathnames are required for these attributes.
		     */
		    case ENXIO:
			stdmsg(MM_NRECOV, lbl, MM_ERROR, E_RELPATH);
			exitcd = EX_RELPATH;
			break;

		    /*
		     * Some other problem (odd?)
		     */

		    default:
			(void) sprintf(msg, E_INTERNAL, errno);
			stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
			exitcd = EX_ERROR;
		    }
		}
	    }
	}   /* End -a case */


	/* putdev -m device attr=value [...] */

	else if (m_seen) {

	    /* Check usage */

	    if (nattrs <= 0) {
		stdmsg(MM_NRECOV, lbl, MM_ERROR, E_USAGE);
		exitcd = EX_ERROR;
	    } else {

		/* Attempt to modify a device's record */
		if (!(_moddevtabrec(device, &argv[optind]))) {

		    /* Modification attempt failed */

		    switch(errno) {

		    /*
		     * EINVAL indicates that "alias" was used as an attribute
		     * in an <attr>=<value> pair.
		     */

		    case EINVAL:
			stdmsg(MM_NRECOV, lbl, MM_ERROR, E_NOALIAS);
			exitcd = EX_ERROR;
			break;

		    /*
		     * ENODEV indicates that the device that was to
		     * be modified doesn't exist.
		     */

		    case ENODEV:
			(void) snprintf(msg, sizeof(msg), E_NODEV, device);
			stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
			exitcd = EX_EXISTS;
			break;

		    /*
		     * ENOENT indicates that the device-table doesn't exist.
		     */

		    case ENOENT:
			(void) snprintf(msg, sizeof(msg), E_NODEVTAB, _devtabpath());
			stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
			exitcd = EX_DEVTAB;
			break;

		    /*
		     * EACCES indicates that there was a problem reading the
		     * old device table or creating the new table.  If the
		     * old table is readable, assume that we can't create the
		     * new table.  Otherwise, assume that the old table isn't
		     * accessible.
		     */

		    case EACCES:
	                p = _devtabpath();
			if (access(p, R_OK) == 0)
			    (void) snprintf(msg, sizeof(msg), E_NOMKDTAB, p);
			else
			    (void) snprintf(msg, sizeof(msg), E_NODEVTAB, p);
			stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
			exitcd = EX_DEVTAB;
			break;

		    /*
		     * EAGAIN indicates that an attribute was specified more than
		     * once on the command line.
		     */

		    case EAGAIN:
			stdmsg(MM_NRECOV, lbl, MM_ERROR, E_MULTIPLE);
			exitcd = EX_ERROR;
			break;

		    /*
		     * ENXIO indicates that a relative pathname was supplied
		     * for the cdevice, bdevice or pathname attributes.  Full
		     * pathnames are required for these attributes.
		     */
		    case ENXIO:
			stdmsg(MM_NRECOV, lbl, MM_ERROR, E_RELPATH);
			exitcd = EX_RELPATH;
			break;

		    /*
		     * Some strange problem...
		     */

		    default:
			(void) sprintf(msg, E_INTERNAL, errno);
			stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
			exitcd = EX_ERROR;
		    }
		}
	    }
	}   /* End -m case */

	else if (d_seen) {

	    /* putdev -d device [attr [...]] */

	    /* Check usage */
	    if (nattrs < 0) {
		stdmsg(MM_NRECOV, lbl, MM_ERROR, E_USAGE);
		exitcd = EX_ERROR;
	    } else {

		/*
		 * Determine case (removing a device or attributes
		 * to a device.
		 */

		if (nattrs == 0) {

		    /* putdev -d device */

		    /* Attempt to remove the specified device */
		    if (!(_rmdevtabrec(device))) switch(errno) {

			/*
			 * ENODEV indicates that the named device is not
			 * defined in the device table.
			 */

		    case ENODEV:
			(void) snprintf(msg, sizeof(msg), E_NODEV, device);
			stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
			exitcd = EX_EXISTS;
			break;

			/*
			 * ENOENT indicates that the device table can't
			 * be found.
			 */

		    case ENOENT:
			(void) snprintf(msg, sizeof(msg), E_NODEVTAB, _devtabpath());
			stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
			exitcd = EX_DEVTAB;
			break;

			/*
			 * EACCES indicates that there was a problem reading the
			 * old device table or creating the new table.  If the
			 * old table is readable, assume that we can't create the
			 * new table.  Otherwise, assume that the old table isn't
			 * accessible.
			 */

		    case EACCES:
			p = _devtabpath();
			if (access(p, R_OK) == 0)
			    (void) snprintf(msg, sizeof(msg), E_NOMKDTAB, p);
			else
			    (void) snprintf(msg, sizeof(msg), E_NODEVTAB, p);
			stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
			exitcd = EX_DEVTAB;
			break;

			/*
			 * Some strange problem...
			 */

		    default:
			(void) sprintf(msg, E_INTERNAL, errno);
			stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
			exitcd = EX_ERROR;

		    }   /* End switch */
		}
		else {

		    /* putdev -d device attr [attr [...]] */

		    /*
		     * Attempt to remove the specified attributes from the
		     * specified device.
		     */
		    if (!(_rmdevtabattrs(device, &argv[optind], &plist))) switch(errno) {

			/*
			 * EINVAL indicates that a named attribute was not
			 * defined for the specified device or "alias" was
			 * requested.  If "plist" points to a list of attrs,
			 * the former is the problem.  Otherwise, the latter
			 * is the problem.
			 */

		    case EINVAL:
			if (plist) {
			    exitcd = EX_ATTRIB;
			    for (; *plist; plist++) {
				(void) snprintf(msg, sizeof(msg), E_NOATTR, *plist);
				stdmsg(MM_RECOVER, lbl, MM_WARNING, msg);
			    }
			} else {
			    stdmsg(MM_NRECOV, lbl, MM_ERROR, E_NOALIAS);
			    exitcd = EX_ERROR;
			}
			break;

			/*
			 * ENODEV indicates that the named device is not
			 * defined in the device table.
			 */

		    case ENODEV:
			(void) snprintf(msg, sizeof(msg), E_NODEV, device);
			stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
			exitcd = EX_EXISTS;
			break;

			/*
			 * ENOENT indicates that the device table can't
			 * be found.
			 */

		    case ENOENT:
			(void) snprintf(msg, sizeof(msg), E_NODEVTAB, _devtabpath());
			stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
			exitcd = EX_DEVTAB;
			break;

			/*
			 * EACCES indicates that there was a problem reading the
			 * old device table or creating the new table.  If the
			 * old table is readable, assume that we can't create the
			 * new table.  Otherwise, assume that the old table isn't
			 * accessible.
			 */

		    case EACCES:
			p = _devtabpath();
			if (access(p, R_OK) == 0)
			    (void) snprintf(msg, sizeof(msg), E_NOMKDTAB, p);
			else
			    (void) snprintf(msg, sizeof(msg), E_NODEVTAB, p);
			stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
			exitcd = EX_DEVTAB;
			break;

			/*
			 * Some strange problem...
			 */

		    default:
			(void) sprintf(msg, E_INTERNAL, errno);
			stdmsg(MM_NRECOV, lbl, MM_ERROR, msg);
			exitcd = EX_ERROR;

		    }  /* End switch */

		}   /* End "putdev -d device attr [...]" case */

	    }   /* End passes usage-check case */

	}   /* End -d case */


	/* Done.  Return exit code (determined above) */
	return(exitcd);
}  /* main() */
