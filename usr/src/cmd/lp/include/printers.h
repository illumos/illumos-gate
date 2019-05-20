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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2019 Joyent, Inc.
 */

#if	!defined(_LP_PRINTERS_H)
#define	_LP_PRINTERS_H

/*
 * The following conflicts are also defined in sys/processor.h.
 */
#if defined PS_FAULTED
#undef  PS_FAULTED
#endif
#if defined PS_DISABLED
#undef  PS_DISABLED
#endif

/*
 * Define the following to support administrator configurable
 * streams modules:
 */
#define	CAN_DO_MODULES	1	/* */

/**
 ** The disk copy of the printer files:
 **/

/*
 * There are 19 fields in the printer configuration file.
 */
#define PR_MAX	19
# define PR_BAN		0
# define PR_CPI		1
# define PR_CS		2
# define PR_ITYPES	3
# define PR_DEV		4
# define PR_DIAL	5
# define PR_RECOV	6
# define PR_INTFC	7
# define PR_LPI		8
# define PR_LEN		9
# define PR_LOGIN	10
# define PR_PTYPE	11
# define PR_REMOTE	12
# define PR_SPEED	13
# define PR_STTY	14
# define PR_WIDTH	15
# define PR_MODULES	16
#define PR_OPTIONS	17
#define PR_PPD		18

/**
 ** The internal flags seen by the Spooler/Scheduler and anyone who asks.
 **/

#define	PS_REJECTED	0x001
#define	PS_DISABLED	0x002
#define	PS_FAULTED	0x004
#define	PS_BUSY		0x008
#define	PS_LATER	0x010	/* Printer is scheduled for service */
#define PS_SHOW_FAULT	0x100 /* set if exMess should be run when fault */
#define PS_USE_AS_KEY	0x200 /* to insure that status used as key is non 0 */
#define PS_FORM_FAULT	0x400 /* set a form fault rather a printer fault*/

/**
 ** The internal copy of a printer as seen by the rest of the world:
 **/

/*
 * A (char **) list is an array of string pointers (char *) with
 * a null pointer after the last item.
 */
typedef struct PRINTER {
	char   *name;		/* name of printer (redundant) */
	unsigned short banner;	/* banner page conditions */
	SCALED cpi;             /* default character pitch */
	char   **char_sets;     /* list of okay char-sets/print-wheels */
	char   **input_types;   /* list of types acceptable to printer */
	char   *device;         /* printer port full path name */
	char   *dial_info;      /* system name or phone # for dial-up */
	char   *fault_rec;      /* printer fault recovery procedure */
	char   *interface;      /* interface program full path name */
	SCALED lpi;             /* default line pitch */
	SCALED plen;            /* default page length */
	unsigned short login;	/* is/isn't a login terminal */
	char   *printer_type;   /* Terminfo look-up value (obsolete) */
	char   *remote;         /* remote machine!printer-name */
	char   *speed;          /* baud rate for connection */
	char   *stty;           /* space separated list of stty options */
	SCALED pwid;            /* default page width */
	char   *description;	/* comment about printer */
	FALERT fault_alert;	/* how to alert on printer fault */
	short  daisy;           /* 1/0 - printwheels/character-sets */
#if     defined(CAN_DO_MODULES)
	char   **modules;	/* streams modules to push */
#endif
	char   **printer_types; /* Terminfo look-up values */
	char	**options;	/* space separated list of undefined -o options */

#ifdef LP_USE_PAPI_ATTR
	char	*ppd;		/* printer's PPD file full path name */
#endif
	/*
	 * Adding new members to this structure? Check out
	 * cmd/lpadmin/do_printer.c, where we initialize
	 * each new printer structure.
	 */
}			PRINTER;

#define BAN_ALWAYS	0x01	/* user can't override banner */
#define BAN_OFF		0x02	/* don't print banner page */
#define BAN_NEVER	BAN_OFF
#define BAN_OPTIONAL	(BAN_ALWAYS | BAN_NEVER) /* user can override banner */

#define LOG_IN		0x01	/* printer is login terminal */

#define PCK_TYPE	0x0001	/* printer type isn't in Terminfo */
#define PCK_CHARSET	0x0002	/* printer type can't handle ".char_sets" */
#define PCK_CPI		0x0004	/* printer type can't handle ".cpi" */
#define PCK_LPI		0x0008	/* printer type can't handle ".lpi" */
#define PCK_WIDTH	0x0010	/* printer type can't handle ".pwid" */
#define PCK_LENGTH	0x0020	/* printer type can't handle ".plen" */
#define PCK_PAPER	0x0040	/* printer type can't handle paper */

/*
 * The following PCK_... bits are only set by the Spooler,
 * when refusing a request.
 */
#define PCK_BANNER	0x1000	/* printer needs banner */

/*
 * Flags set by "putprinter()" for things that go wrong.
 */
#define BAD_REMOTE	0x0001	/* has attributes of remote and local */
#define BAD_INTERFACE	0x0002	/* no interface or can't read it */
#define BAD_DEVDIAL	0x0004	/* no device or dial information */
#define BAD_FAULT	0x0008	/* not recognized fault recovery */
#define BAD_ALERT	0x0010	/* has reserved word for alert command */
#define BAD_ITYPES	0x0020	/* multiple printer AND input types */
#define BAD_PTYPES	0x0040	/* multiple printer types, incl unknown */
#define BAD_DAISY	0x0080	/* printer types don't agree on "daisy" */

/*
 * A comma separated list of STREAMS modules to be pushed on an
 * opened port.
 */
#define	DEFMODULES	"ldterm"

/*
 * For print wheels:
 */

typedef struct PWHEEL {
	char   *name;		/* name of print wheel */
	FALERT alert;		/* how to alert when mount needed */
}			PWHEEL;

extern unsigned long	badprinter,
			ignprinter;

/*
 * Set if ppd file information is from the user rather than
 * the configuration file.
 */
extern int ppdopt;

/**
 ** Various routines.
 **/

PRINTER *	getprinter ( char * );

PWHEEL *	getpwheel ( char * );

char *		getdefault ( void );

int		putprinter ( char *, PRINTER *);
int		delprinter ( char * );
int		putdefault ( char * );
int		deldefault ( void );
int		putpwheel ( char * , PWHEEL * );
int		delpwheel ( char * );
int		okprinter ( char * , PRINTER * , int );

unsigned long	chkprinter (char *, char *, char *, char *, char *, char *);

void		freeprinter ( PRINTER * );
void		freepwheel ( PWHEEL * );

char *	getpentry(char *, int);

/**
 ** Aliases (copies) of some important Terminfo caps.
 **/

extern int		ti_daisy;

#endif
