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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.11.2.1	*/

/*
 * lsparam.h:	listener parameters.  Includes default pathnames.
 */

#include <stdarg.h>

/* DEBUGMODE causes debug statements to be compiled in. */

/*  #define DEBUGMODE   */

#ifdef	DEBUGMODE
extern	int debug(int level, char *format, ...);
#define	DEBUG(ARGS)	debug ARGS
#else
#define	DEBUG(ARGS)
#endif

/*
 * CHARADDR is a debug aid only!!!!
 * with DEBUGMODE, if CHARADDR is defined, logical addresses which
 * are represented by printable characters, will be displayed in the
 * debug/log files
 */

#ifdef	DEBUGMODE
#define CHARADDR
#endif

/* listener parameters							*/

#define MAXNAMESZ	15		/* must coexist with ms-net (5c) */
#define SNNMBUFSZ	16		/* starlan network only		*/
#define NAMEBUFSZ	64
#define MINMSGSZ	(SMBIDSZ+2)	/* smallest acceptable msg size	*/
#define RCVBUFSZ	BUFSIZ		/* receive buffer size		*/
#define DBFLINESZ	BUFSIZ		/* max line size in data base 	*/
#define ALARMTIME	45		/* seconds to wait for t_rcv	*/
#define PATHSIZE	64		/* max size of pathnames	*/

/*
 * LOGMAX is default no of entries maintained
 */

#define LOGMAX	1000			/* default value for Logmax	*/

/*
 * if SMB server is defined, code is included to parse MS-NET messages
 * if undef'ed, the parsing routine logs an approp. error and returns an err.
 */

#define	SMBSERVER	1		/* undef to remove SMBSERVICE support*/

/*
 * if listener (or child) dies, dump core for diagnostic purposes
 */

/* #define COREDUMP */

/* the following filenames are used in homedir:	*/

#define BASEDIR	"/etc/saf"		/* base directory for listen	*/
#define ALTDIR "/var/saf"		/* alternate directory for files*/
#define	LOGNAME	"./log"			/* listener's logfile		*/
#define	OLOGNAME "./o.log"		/* listener's saved logfile	*/
#define	PDEBUGNAME "p_debug"		/* protoserver's debugfile	*/
#define DBGNAME	"debug"			/* debug output file		*/
#define PIDNAME	"./_pid"		/* listener's process id's	*/
#define DBFNAME	"./_pmtab"		/* listener data base file	*/

/* defines for SAC compatibility */

#define	SACPIPE	"../_sacpipe"		/* outgoing messages to SAC	*/
#define	PMPIPE	"./_pmpipe"		/* incoming messages from SAC	*/
#define MAXCLASS	1		/* maximum SAC protocol version */


/*
 * defaults which are normally overriden by cmd line/passwd file, etc
 */

#define NETSPEC	"starlan"
