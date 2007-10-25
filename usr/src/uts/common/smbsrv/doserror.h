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


#ifndef _SMBSRV_DOSERROR_H
#define	_SMBSRV_DOSERROR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file defines the list of DOS error codes. I think the error
 * codes are divided into different classes, which is why there are
 * duplicate values.
 */

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Error source or class
 */
#define	SUCCESS		0x00	/* The request was successful. */
#define	ERRDOS		0x01	/* Core DOS operating system error. */
#define	ERRSRV		0x02	/* Server network file error */
#define	ERRHRD		0x03	/* Hardware error */
#define	ERRCMD		0xFF	/* Command was not in the "SMB" format. */


/*
 * ERRDOS error codes
 */
#define	ERRbadfunc	1 /* Invalid function. The server did not */
#define	ERRbadfile	2 /* File not found. The last component of a */
#define	ERRbadpath	3 /* Directory invalid. A directory component in */
#define	ERRnofids	4 /* Too many open files. The server has no file */
#define	ERRnoaccess	5 /* Access denied, the client's context does not */
#define	ERRbadfid	6 /* Invalid file handle. The file handle */
#define	ERRbadmcb	7 /* Memory control blocks destroyed. */
#define	ERRnomem	8 /* Insufficient server memory to perform the */
#define	ERRbadmem	9 /* Invalid memory block address. */
#define	ERRbadenv	10 /* Invalid environment. */
#define	ERRbadformat	11 /* Invalid format. */
#define	ERRbadaccess	12 /* Invalid open mode. */
#define	ERRbaddata	13 /* Invalid data (generated only by IOCTL calls */
#define	ERRbaddrive	15 /* Invalid drive specified. */
#define	ERRremcd	16 /* A Delete Directory request attempted to */
#define	ERRdiffdevice	17 /* Not same device (e.g., a cross volume rename */
#define	ERRnofiles	18 /* A File Search command can find no more files */
#define	ERRbadshare	32 /* The sharing mode specified for an Open */
#define	ERRlock		33 /* A Lock request conflicted with an existing */
#define	ERRfilexists	80 /* The file named in a Create Directory, Make */
#define	ERRnotlocked	158 /* No lock matched the unlock range */
#define	ERRnoatomiclocks 174 /* Change lock type not supported */
#define	ERRbadpipe	230 /* Pipe invalid. */
#define	ERRpipebusy	231 /* All instances of the requested pipe are busy. */
#define	ERRpipeclosing	232 /* Pipe close in progress. */
#define	ERRnotconnected	233 /* No process on other end of pipe. */
#define	ERRmoredata	234 /* There is more data to be returned. */
#define	ERRunknownlevel 124


/*
 * ERRSRV error codes
 */
#define	ERRerror	1 /* Non-specific error code. It is returned */
#define	ERRbadpw	2 /* Bad password - name/password pair in a Tree */
#define	ERRaccess	4 /* The client does not have the necessary access */
#define	ERRinvnid	5 /* The Tid specified in a command was invalid. */
#define	ERRinvnetname	6 /* Invalid network name in tree connect. */
#define	ERRinvdevice	7 /* Invalid device - printer request made to non- */
#define	ERRqfull	49 /* Print queue full (files) -- returned by open */
#define	ERRqtoobig	50 /* Print queue full -- no space. */
#define	ERRqeof		51 /* EOF on print queue dump. */
#define	ERRinvpfid	52 /* Invalid print file FID. */
#define	ERRsmbcmd	64 /* The server did not recognize the command */
#define	ERRsrverror	65 /* The server encountered an internal error, */
#define	ERRfilespecs	67 /* The Fid and pathname parameters contained an */
#define	ERRbadpermits	69 /* The access permissions specified for a file */
#define	ERRsetattrmode	71 /* The attribute mode in the Set File Attribute */
#define	ERRpaused	81 /* Server is paused. (reserved for messaging) */
#define	ERRmsgoff	82 /* Not receiving messages. (reserved for */
#define	ERRnoroom	83 /* No room to buffer message. (reserved for */
#define	ERRrmuns	87 /* Too many remote user names. (reserved for */
#define	ERRtimeout	88 /* Operation timed out. */
#define	ERRnoresource	89 /* No resources currently available for request. */
#define	ERRtoomanyuids	90 /* Too many Uids active on this session. */
#define	ERRbaduid	91 /* The Uid is not known as a valid user */
#define	ERRusempx	250 /* Temporarily unable to support Raw, use MPX */
#define	ERRusestd	251 /* Temporarily unable to support Raw, use */
#define	ERRcontmpx	252 /* Continue in MPX mode. */
#define	ERRnosupport	65535 /* Function not supported. */


/*
 * ERRHRD error codes
 */
#define	ERRnowrite	19 /* Attempt to write on write-protected media */
#define	ERRbadunit	20 /* Unknown unit. */
#define	ERRnotready	21 /* Drive not ready. */
#define	ERRbadcmd	22 /* Unknown command. */
#define	ERRdata		23 /* Data error (CRC). */
#define	ERRbadreq	24 /* Bad request structure length. */
#define	ERRseek		25 /* Seek error. */
#define	ERRbadmedia	26 /* Unknown media type. */
#define	ERRbadsector	27 /* Sector not found. */
#define	ERRnopaper	28 /* Printer out of paper. */
#define	ERRwrite	29 /* Write fault. */
#define	ERRread		30 /* Read fault. */
#define	ERRgeneral	31 /* General failure. */
#define	ERRbadshare	32 /* A open conflicts with an existing open. */
#define	ERRlock		33 /* A Lock request conflicted with an existing */
#define	ERRwrongdisk	34 /* The wrong disk was found in a drive. */
#define	ERRFCBUnavail	35 /* No FCBs are available to process request. */
#define	ERRsharebufexc	36 /* A sharing buffer has been exceeded. */


#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_DOSERROR_H */
