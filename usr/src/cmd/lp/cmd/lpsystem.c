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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.8	*/

/*==================================================================*/
/*
*/
#include	<sys/utsname.h>
#include	<stdio.h>
#include	<tiuser.h>
#include	<netconfig.h>
#include	<netdir.h>
#include	<locale.h>

#include	"lp.h"
#include	"systems.h"
#include	"msgs.h"
#include	"boolean.h"
#include	"access.h"
#include	"tsol/label.h"

#define WHO_AM_I	I_AM_LPSYSTEM
#include "oam.h"

#define	DEFAULT_TIMEOUT	-1
#define	DEFAULT_RETRY	10

static	int	Timeout;
static	int	Retry;
static	char	*Sysnamep;
static	char	*Protocolp;
static	char	*Timeoutp;
static	char	*Retryp;
static	char	*Commentp;

#ifdef	__STDC__
static	void	SecurityCheck (void);
static	void	TcpIpAddress (void);
static	void	ListSystems (char * []);
static	void	RemoveSystems (char * []);
static	void	AddModifySystems (char * []);
static	void	formatsys (SYSTEM *);
static	void	usage (void);
#else
static	void	SecurityCheck ();
static	void	TcpIpAddress ();
static	void	ListSystems ();
static	void	RemoveSystems ();
static	void	AddModifySystems ();
static	void	formatsys ();
static	void	usage ();
#endif

/*==================================================================*/

/*==================================================================*/
/*
*/
#ifdef	__STDC__
int
main (int argc, char * argv [])
#else
int
main (argc, argv)

int	argc;
char	*argv [];
#endif
{
		int	c;
		boolean	lflag = False,
			rflag = False,
			Aflag = False,
			badOptions = False;
	extern	int	opterr,
			optind;
	extern	char	*optarg;
 

	(void) setlocale (LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc == 1) {
		usage();
		exit(1);
	}
	while ((c = getopt(argc, argv, "t:T:R:y:lrA?")) != EOF)
	switch (c & 0xFF)
	{
	case 't':
		if (Protocolp)
		{
			(void)	fprintf (stderr,
				gettext("ERROR:  Too many -t options.\n"));
			return	1;
		}
		Protocolp = optarg;
		if (! STREQU(NAME_BSDPROTO, Protocolp))
		{
			(void)	fprintf (stderr,
		gettext("ERROR: Supported protocol is \"%s\".\n"), NAME_BSDPROTO);
			return	1;
		}
		break;
		
	case 'T':
		if (Timeoutp)
		{
			(void)	fprintf (stderr,
				gettext("ERROR:  Too many -T options.\n"));
			return	1;
		}
		Timeoutp = optarg;
		if (*Timeoutp == 'n')
			Timeout = -1;
		else
		if (sscanf (Timeoutp, "%d", &Timeout) != 1 || Timeout < 0)
		{
			(void)	fprintf (stderr,
				gettext("ERROR:  Bad timeout argument: %s\n"),
				Timeoutp);
				return	1;
		}
		break;
		
	case 'R':
		if (Retryp)
		{
			(void)	fprintf (stderr,
				gettext("ERROR:  Too many -R options.\n"));
			return	1;
		}
		Retryp = optarg;
		if (*Retryp == 'n')
			Retry = -1;
		else 
		if (sscanf (Retryp, "%d", &Retry) != 1 || Retry < 0)
		{
			(void)	fprintf (stderr, gettext("ERROR:  Bad retry argument: %s\n"), Retryp);

			return	1;
		}
		break;
		
	case 'y':
		if (Commentp)
		{
			(void)	fprintf (stderr,
				gettext("ERROR:  Too many -y options.\n"));
			return	1;
		}
		Commentp = optarg;
		break;

	case 'l':
		if (lflag)
		{
			(void)	fprintf (stderr,
				gettext("ERROR:  Too many -l options.\n"));
			return	1;
		}
		lflag++;
		break;
		
	case 'r':
		if (rflag)
		{
			(void)	fprintf (stderr,
				gettext("ERROR:  Too many -r options.\n"));
			return	1;
		}
		rflag++;
		break;

	case 'A':
		if (Aflag)
		{
			(void)	fprintf (stderr,
				gettext("ERROR:  Too many -A options.\n"));
			return	1;
		}
		Aflag++;
		break;

	default:
		(void)	fprintf (stderr,
			gettext("ERROR:  Unrecognized option \"-%c\".\n"), c & 0xFF);
		return	1;
		
	case '?':
		usage ();
		return	1;
	}

	/*
	**  Check for valid option combinations.
	**
	**  The '-A' option is mutually exclusive.
	**  The '-l' option is mutually exclusive.
	**  The '-r' option is mutually exclusive.
	*/
	if (Aflag && (Protocolp || Timeoutp || Retryp || Commentp))
		badOptions = True;

	if (lflag &&
	   (Protocolp || Timeoutp || Retryp || Commentp || rflag || Aflag))
		badOptions = True;

	if (rflag && (Protocolp || Timeoutp || Retryp || Commentp || Aflag))
		badOptions = True;

	if (badOptions)
	{
		(void)	fprintf (stderr, gettext("ERROR:  Improper usage.\n\n"));
		return	1;
	}

	/*
	**	Lets do some processing.
	**	We'll start with the flags.
	*/
	if (Aflag)
	{
		TcpIpAddress ();
		/*NOTREACHED*/
	}
	if (lflag)
	{
		ListSystems (&argv [optind]);
		/*NOTREACHED*/
	}
	if (rflag)
	{
		RemoveSystems (&argv [optind]);
		/*NOTREACHED*/
	}

	AddModifySystems (&argv [optind]);

	return	0;
}
/*==================================================================*/

/*==================================================================*/
/*
*/
#ifdef	__STDC__
static	void
SecurityCheck (void)
#else
static	void
SecurityCheck ()
#endif
{
	/* On labeled systems check that user has print admin authorization */
	if (is_system_labeled()) {
		if (is_user_admin() == 0) {
			(void) fprintf(stderr,
			    gettext(
			    "You are not authorized to administer printing.\n"\
			    ));
			(void) exit (1);
		}
	} else {
		if (geteuid () != 0)
		{
			(void)	fprintf (stderr,
				gettext("ERROR:  You must be root.\n"));
			(void)	exit (1);
		}
	}
}
/*==================================================================*/

/*==================================================================*/
/*
*/
#ifdef	__STDC__
static	void
TcpIpAddress (void)
#else
static	void
TcpIpAddress ()
#endif
{
	int	i;
	struct	netconfig	*configp;
	struct	nd_hostserv	hostserv;
	struct	nd_addrlist	*addrsp;

	struct	netconfig	*getnetconfigent ();

	configp = getnetconfigent ("tcp");
	if (! configp)
	{
/*
**		(void)	fprintf (stderr,
**			gettext("ERROR:  TCP/IP is not installed.\n"));
*/
		LP_ERRMSG (ERROR, E_SYS_NOTCPIP);
		(void)	exit (2);
	}
	hostserv.h_host = HOST_SELF;
	hostserv.h_serv = "printer";
	if (netdir_getbyname (configp, &hostserv, &addrsp))
	{
		(void)	fprintf (stderr, gettext("ERROR:  "));
		(void)	perror ("netdir_getbyname");
		(void)	exit (2);
	}
	for (i=0; i < addrsp->n_addrs->len; i++)
		(void)	printf ("%02x", addrsp->n_addrs->buf [i] & 0xFF );
	(void)	printf ("\n");
	(void)	exit (0);
}
/*==================================================================*/

/*==================================================================*/
/*
*/
#ifdef	__STDC__
static	void
ListSystems (char *syslistp [])
#else
static	void
ListSystems (syslistp)

char *syslistp [];
#endif
{
	char	*sysnamep;
	SYSTEM	*systemp;

	if (! *syslistp)
	{
		while ((systemp = getsystem (NAME_ALL)) != NULL)
			formatsys (systemp);
	}
	else
	for (sysnamep = *syslistp; sysnamep; sysnamep = *++syslistp)
	{
		if (STREQU(NAME_ANY, sysnamep)  ||
		    STREQU(NAME_NONE, sysnamep) ||
		    STREQU(NAME_ALL, sysnamep))
		{
			(void)	fprintf (stderr,
				gettext("WARNING:  \"%s\" is a reserved word "
				"and may not be used for a system name.\n"),
				sysnamep);
			continue;
		}
		if ((systemp = getsystem (sysnamep)) == NULL)
		{
			(void)	fprintf (stderr,
				gettext("WARNING:  \"%s\" not found.\n"),
				sysnamep);
			continue;
		}
		formatsys (systemp);
	}
	(void)	exit (0);
}
/*==================================================================*/

/*==================================================================*/
/*
*/
#ifdef	__STDC__
static	void
RemoveSystems (char *syslistp [])
#else
static	void
RemoveSystems (syslistp)

char	*syslistp [];
#endif
{
	char	*sysnamep;
	SYSTEM	*systemp;


	SecurityCheck ();

	if (! syslistp || ! *syslistp)
	{
		(void)	fprintf (stderr, gettext("ERROR:  Improper usage.\n\n"));
		(void)	exit (1);
	}
	for (sysnamep = *syslistp; sysnamep; sysnamep = *++syslistp)
	{
		if (STREQU(NAME_ANY, sysnamep)  ||
		    STREQU(NAME_NONE, sysnamep) ||
		    STREQU(NAME_ALL, sysnamep))
		{
			(void)	fprintf (stderr,
				gettext("WARNING:  \"%s\" is a reserved word "
				"and may not be used for a system name.\n"),
				sysnamep);
			continue;
		}
		if (! (systemp = getsystem (sysnamep)))
		{
			(void)	fprintf (stderr,
				gettext("WARNING:  \"%s\" not found.\n"),
				sysnamep);
			continue;
		}
		if (delsystem (sysnamep))
		{
			(void)  fprintf (stderr,
				gettext("ERROR:  Could not remove \"%s\".\n"),
				sysnamep);
			(void)  exit (2);
		}
		else

			(void)  printf (gettext("Removed \"%s\".\n"),
					sysnamep);
	}
	(void)	exit (0);
}
/*==================================================================*/

/*==================================================================*/
/*
*/

#ifdef	__STDC__
static	void
AddModifySystems (char *syslistp [])
#else
static	void
AddModifySystems (syslistp)

char	*syslistp [];
#endif
{
		char	*sysnamep;
		SYSTEM	*systemp,
			sysbuf;
		boolean	modifiedFlag;

	static	SYSTEM	DefaultSystem =
			{
				NULL, NULL, NULL, BSD_PROTO, -1,
				DEFAULT_TIMEOUT, DEFAULT_RETRY,
				NULL, NULL, NULL
			}; 


	SecurityCheck ();

	for (sysnamep = *syslistp; sysnamep; sysnamep = *++syslistp)
	{
		int changed = 0;
		modifiedFlag = False;
		if (systemp = getsystem (sysnamep))
		{
			sysbuf = *systemp;
			modifiedFlag = True;
		}
		else
		{
			sysbuf = DefaultSystem;
			sysbuf.name = sysnamep;
		}
		if (Protocolp)
		{
			changed++;
			sysbuf.protocol = BSD_PROTO;
		}
		if (Timeoutp)
		{
			changed++;
			sysbuf.timeout = Timeout;
		}
		if (Retryp)
		{
			changed++;
			sysbuf.retry = Retry;
		}
		if (Commentp)
		{
			changed++;
			sysbuf.comment = Commentp;
		}

		if (modifiedFlag && changed == 0) { /* no work done */
			printf(gettext("\"%s\" no change.\n"), sysnamep);
			continue;
		}

		if (putsystem (sysnamep, &sysbuf))
		{
			if (modifiedFlag) {
				(void)	fprintf (stderr,
		gettext("ERROR:  Could not modify \"%s\".\n"), sysnamep);
			}else {
				(void)	fprintf (stderr,
		gettext("ERROR:  Could not add \"%s\".\n"), sysnamep);
			}
			(void)	exit (2);
		}
		if (modifiedFlag)
		{
			(void)	printf (gettext("\"%s\" has been modified.\n"),
				sysnamep);
		}
		else
		{
			(void)	printf (gettext("\"%s\" has been added.\n"),
				sysnamep);
		}
	}
	(void)	exit (0);
}
/*==================================================================*/

/*==================================================================*/
/*
*/
#if	defined(__STDC__)
static	void
usage (void)
#else
static void
usage ()
#endif
{
	(void)	fprintf (stdout,
	gettext("Usage:  lpsystem [ options ] [system-name ... ]\n"
	"\nTo add or modify an existing system:\n"
	"        lpsystem [ -t type ] [ -T timeout ]\n"
	"                 [ -R retry ] [ -y comment ] system-name ...\n"
	"\nTo list a system (or all systems):\n"
	"        lpsystem -l [ system-name ...]\n"
	"\nTo remove a system:\n"
	"        lpsystem -r system-name ...\n"
	"\nTo get the TCP/IP address for the local port-monitor:\n"
	"        lpsystem -A\n"));
}
/*==================================================================*/

/*==================================================================*/
/*
*/
#ifdef	__STDC__
static	void
formatsys (SYSTEM * sys)
#else
static	void
formatsys (sys)
SYSTEM	*sys;
#endif
{
	(void)	printf (gettext("System:                     %s\n"), sys->name);
	(void)	printf (gettext("Type:                       %s\n"), NAME_BSDPROTO);
	if (sys->timeout == -1)
		(void)	printf (gettext("Connection timeout:         never\n"));
	else
		(void)	printf (gettext("Connection timeout:         %d minutes\n"),
			sys->timeout);
	if (sys->retry == -1)
		(void)	printf (gettext("Retry failed connections:   no\n"));
	else
		(void)	printf (
			gettext("Retry failed connections:   after %d minutes\n"),
			 sys->retry);
	if (sys->comment == NULL)
		(void)	printf (gettext("Comment:                    none\n"));
	else
		(void)	printf (gettext("Comment:                    %s\n"),
			sys->comment);
	(void)	printf ("\n");
}
/*==================================================================*/
