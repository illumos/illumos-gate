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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved */


#ifndef _PARMS_H
#define _PARMS_H

/* If running SVR3, #define both ATTSVR3 and ATTSV */
#define ATTSVR3	/* System V Release 3 */

/* One of the following four lines should not be commented out.
 * The other three should be unless you are running a unique hybrid.
 */

#define	ATTSV	/* System III or System V */
/* #define	V7 */	/* Version 7 systems (32V, Berkeley 4BSD, 4.1BSD) */
/* #define	BSD4_2 */	/* Berkeley 4.2BSD */
/* #define	V8 */	/* Research Eighth Edition */

/* Owner of setud files running on behalf of uucp.  Needed in case
 * root runs uucp and euid is not honored by kernel.
 * GID is needed for some chown() calls.
 * Also used if guinfo() cannot find the current users ID in the
 * password file.
 */
#define UUCPUID		(uid_t) 5	/* */
#define UUCPGID		(gid_t) 5	/* */

/* define ATTSVKILL if your system has a kill(2) that accepts kill(0, pid)
 * as a test for killability.  If ATTSV is defined this will automatically
 * be defined anyway.
 */
#define ATTSVKILL	/* */

/*
 * the next two lines control high resolution sleeps, called naps.
 *
 * most UNIX versions have no nap() system call; they want NONAP defined,
 * in which case one is provided in the code.  this includes all standard
 * versions of UNIX.
 *
 * some sites use a fast timer that reads a number of clock ticks and naps
 * for that interval; they want NONAP defined, and FASTTIMER defined as
 * the name of the device, e.g., /dev/ft.
 *
 * repeating, NONAP should be disabled *only* if your standard library has a
 * function called nap.
 */


#define NONAP	/* nominal case -- no nap() in the standard library */
/* #define FASTTIMER "/dev/ft" */   /* identify the device used for naps */

/*
 * we use ustat to decide whether there's enough space to receive a
 * file.  if you're not ATTSV, you can use a setgid program to read the
 * number of free blocks and free inodes directly off the disk.  if you
 * choose this course, do not define NOUSTAT; rather, define V7USTAT to
 * be the name of that program.  be sure it accepts 2 args, major and minor
 * device numbers, and returns two numbers, blocks and inodes, in
 * "%d %d" format, or you'll never receive another file.
 */
/* #define V7USTAT  "/usr/local/lib/ustat" */
/* #define NOUSTAT   */ /* define NOUSTAT if you don't have ustat */

/* define GRPCHK if you want to restrict the ability to read */
/* Systems file stuff by way of the DEBUG flags based on a group id range */
/* ex: if (GRPCHK(getgid()) no_secrets(); */
#define GRPMIN	(gid_t) 2	/* */
#define GRPMAX	(gid_t) 10	/* */
#define GRPCHK(gid)	( gid >= GRPMIN && gid <= GRPMAX ? 1 : 0 )	/* */
/* #define GRPCHK(gid)	1 */	/* Systems info is not protected from DEBUG */

/* definitions for the types of networks and dialers that are available */
/* used to depend on STANDALONE, but now done at runtime via Sysfiles	*/
#define DATAKIT		/* define DATAKIT if datakit is available. */
/* #define UNET */	/* define UNET if you have 3com ethernet software */
/* #define TCP	*/	/* TCP (bsd systems) */
/* #define SYTEK*/	/* for sytek network */

#ifdef ATTSVR3
#define TLI		/* for AT&T Transport Layer Interface networks */
#define TLIS		/* for AT&T Transport Layer Interface networks */
			/* with streams module "tirdwr" */
#endif /* ATTSVR3 */

#define DIAL801	/* 801/212-103 auto dialers */

/* define DUMB_DN if your dn driver (801 acu) cannot handle '=' */
/* #define DUMB_DN */

/*
 * Define protocols that are to be linked into uucico:
 *
 * The following table shows which protocols and networks work well
 * together.  The g protocol works over noisy links.  The e protocol
 * assumes that the underlying network provides an error free communications
 * channel that transfers the data in sequence without duplication.  The
 * d protocols makes the same assumptions as the e protocol, but in addition
 * it does Datakit specific ioctl's.  The g protocol is always included in
 * uucico.  To include the other protocols, 1) insure that the symbol from
 * the Symbol column is defined in this file and 2) include the file from
 * the File comlumn in the definition of PROTOCOLS in uucp.mk.
 *
 * Prot.
 * Letter Symbol       File	Applicable Media
 *
 *   g	  none	       -	-
 *   e	  E_PROTOCOL   eio.c	TCP, UNET, TLI, and DATAKIT.
 *   d	  D_PROTOCOL   dio.c	DATAKIT
 *   x	  X_PROTOCOL   xio.c	-
 *
 * The next six lines conditionally define the protocol symbols for d
 * and e protocols based on the networks that were chosen above.  For the
 * x protocol you must explicitly define X_PROTOCOL.
 */

#ifdef DATAKIT		/* Should include D protocol for Datakit. */
#define D_PROTOCOL
#endif /* DATAKIT */

#if defined TCP || defined UNET || defined TLI || defined DATAKIT
#define E_PROTOCOL	/* Include e protocol. */
#endif	/* TCP || UNET || TLI || DATAKIT */

/* #define X_PROTOCOL */ /* define X_PROTOCOL to use the xio protocol */
#define X_PROTOCOL /* aeh - to check compilation */

#define MAXCALLTRIES	2	/* maximum call attempts per Systems file line */

/* define DEFAULT_BAUDRATE to be the baud rate you want to use when both */
/* Systems file and Devices file allow Any */
#define DEFAULT_BAUDRATE "9600"	/* */

/*define permission modes for the device */
#define M_DEVICEMODE (mode_t) 0600	/* manager device mode */
#define S_DEVICEMODE (mode_t) 0600	/* subsidiary device mode */
#define R_DEVICEMODE (mode_t) 0600	/* default mode to restore */

/* NO_MODEM_CTRL - define this if you have very old hardware
 * that does not know how to correctly handle modem control
 * Some old pdp/11 hardware such as dk, dl
 * If you define this, and have DH devices for direct lines,
 * the ports will often hang and be unusable.
*/
/*#define NO_MODEM_CTRL	*/


/* UUSTAT_TBL - this is the maximum number of machines that
 * status may be needed at any instant.
 * If you are not concerned with memory for a seldom used program,
 * make it very large.
 * This number is also used in uusched for its machine table -- it has
 * the same properties as the one in uustat.
 */

/* #define UUSTAT_TBL 1000 */		/* big machine with lots of traffic */
#define UUSTAT_TBL 200

/* define UNAME if uname() should be used to get uucpname
 * This will be defined automatically if ATTSV is defined
 */
#define UNAME /*  */

/* initial wait time after failure before retry */
#define RETRYTIME 300		/* 5 minutes */
/* MAXRETRYTIME is for exponential backoff  limit.
 * NOTE - this should not be 24 hours so that
 * retry is not always at the same time each day
 */
#define MAXRETRYTIME 82800	/* 23 hours */
#define ASSERT_RETRYTIME 86400	/* retry time for ASSERT errors */

/*  This is the path that will be used for uuxqt command executions */
#define PATH	"PATH=/usr/bin " /* */

/*  This is the set of default commands that can be executed */
/*  if non is given for the system name in PERMISSIONS file */
/*  It is a colon separated list as in PERMISSIONS file */
#define DEFAULTCMDS	"rmail"	/* standard default command list */

/* define HZ to be the number of clock ticks per second */
/* #define HZ 60 */ /* not needed for ATTSV or above */

/*
 * put in local uucp name of this machine if there is no "/etc/whoami"
 * and no uname() (this is a last resort)
 */
#define MYNAME		"kilroy"	/* */

/* define NOSTRANGERS if you want to reject calls from systems which
 * are not in your Systems file.   If defined, NOSTRANGERS should be the name
 * of the program to execute when such a system dials in.  The argument
 * to said program will be the name of said system.  Typically this is a shell
 * procedure that sends mail to the uucp administrator informing them of an
 * attempt to communicate by an unknown system.
 * NOTE - if this is defined, it can be overridden by the administrator
 * by making the command non-executable.  (It can be turned on and off
 * by changing the mode of the command.)
 */
#define NOSTRANGERS	"/usr/lib/uucp/remote.unknown"	/* */

/* define LIMITS to be the name of a file which contains information
 * about the number of simultaneous uucicos,uuxqts, and uuscheds
 * that are allowed to run. If it is not defined, then there may be
 * "many" uucicos, uuxqts, and uuscheds running.
 */
#define LIMITS		"/etc/uucp/Limits"		/* */

/* define USRSPOOLLOCKS if you like your lock files in /var/spool/locks
 * be sure other programs such as 'cu' and 'ct' know about this
 *
 * WARNING: if you do not define USRSPOOLLOCKS, then $LOCK in
 * uudemon.cleanup must be changed.
 */
#define USRSPOOLLOCKS  /* define to use /var/spool/locks for LCK files */

/* define PKSPEEDUP if you want to try the recommended speedup in pkcget.
 * this entails sleeping between reads at low baud rates.
 */
#define PKSPEEDUP	/* */

#endif /* !_PARMS_H */
