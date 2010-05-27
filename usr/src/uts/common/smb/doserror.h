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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SMB_DOSERROR_H
#define	_SMB_DOSERROR_H

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
#define	ERRDOS		0x01	/* Core DOS operating system error. */
#define	ERRSRV		0x02	/* Server network file error */
#define	ERRHRD		0x03	/* Hardware error */
#define	ERRCMD		0xFF	/* Command was not in the "SMB" format. */


/*
 * ERRDOS error codes
 */
#define	ERRbadfunc	1	/* Invalid function. */
#define	ERRbadfile	2	/* File not found (last component) */
#define	ERRbadpath	3	/* path not found (directory part) */
#define	ERRnofids	4	/* Too many open files. */
#define	ERRnoaccess	5	/* Access denied. */
#define	ERRbadfid	6	/* Invalid file handle. */
#define	ERRbadmcb	7	/* Memory control blocks destroyed. */
#define	ERRnomem	8	/* Insufficient memory. */
#define	ERRbadmem	9	/* Invalid memory block address. */
#define	ERRbadenv	10	/* Invalid environment. */
#define	ERRbadformat	11	/* Invalid format. */
#define	ERRbadaccess	12	/* Invalid open mode. */
#define	ERRbaddata	13	/* Invalid data (from IOCTL calls) */
#define	ERRbaddrive	15	/* Invalid drive specified. */
#define	ERRremcd	16	/* Attempted to delete current directory. */
#define	ERRdiffdevice	17	/* Not same device (cross volume rename) */
#define	ERRnofiles	18	/* File search found no more files. */
#define	ERRbadshare	32	/* Share mode conflict with existing open. */
#define	ERRlock		33	/* Lock conflict with existing lock, etc. */
#define	ERRdiskfull	39	/* No space left on device. */
#define	ERRfilexists	80	/* Requested file name already exists. */

/*
 * These are compatible with the MS header files, but the
 * smb/nterror.h names for these are preferred.
 */
#define	ERRbadpipe	230	/* See ERROR_BAD_PIPE (named pipe invalid) */
#define	ERRpipebusy	231	/* See ERROR_PIPE_BUSY (all instances busy) */
#define	ERRpipeclosing	232	/* See ERROR_NO_DATA (pipe closing) */
#define	ERRnotconnected	233	/* See ERROR_PIPE_NOT_CONNECTED */
#define	ERRmoredata	234	/* See ERROR_MORE_DATA (pipe has more) */


/*
 * ERRSRV error codes
 */
#define	ERRerror	1	/* Non-specific error code. */
#define	ERRbadpw	2	/* Bad password (tree connect, etc) */
#define	ERRbadtype	3	/* reserved */
#define	ERRaccess	4	/* access denied */
#define	ERRinvnid	5	/* Invalid tree ID */
#define	ERRinvnetname	6	/* Invalid network name (tree connect) */
#define	ERRinvdevice	7	/* Invalid device (print jobs, etc.) */
#define	ERRqfull	49	/* Print queue full (files) */
#define	ERRqtoobig	50	/* Print queue full (no space) */
#define	ERRqeof		51	/* EOF on print queue dump. */
#define	ERRinvpfid	52	/* Invalid print file FID. */
#define	ERRsmbcmd	64	/* Server did not recognize the command. */
#define	ERRsrverror	65	/* Server encountered an internal error. */
#define	ERRfilespecs	67	/* FID and path param combination is bad. */
#define	ERRbadpermits	69	/* Access permissions invalid (SetF*) */
#define	ERRsetattrmode	71	/* Attribute mode invalid (SetF*) */
#define	ERRpaused	81	/* Server is paused. */
#define	ERRmsgoff	82	/* Not receiving messages. */
#define	ERRnoroom	83	/* No room to buffer message. */
#define	ERRrmuns	87	/* Too many remote user names (messaging) */
#define	ERRtimeout	88	/* Operation timed out. */
#define	ERRnoresource	89	/* No resources available for request. */
#define	ERRtoomanyuids	90	/* Too many UIDs active on connection. */
#define	ERRbaduid	91	/* UID is not valid. */

#define	ERRusempx	250	/* Temporarily unable to support Raw, */
				/* use MPX mode */
#define	ERRusestd	251	/* Temporarily unable to support Raw, */
				/* use stdandard r/w */
#define	ERRcontmpx	252	/* Continue in MPX mode */

#define	ERRnosupport	0xffff	/* Function not supported. */


/*
 * ERRHRD error codes
 */
#define	ERRnowrite	19	/* Attempt to write on write-protected media */
#define	ERRbadunit	20	/* Unknown unit. */
#define	ERRnotready	21	/* Drive not ready. */
#define	ERRbadcmd	22	/* Unknown command. */
#define	ERRdata		23	/* Data error (CRC). */
#define	ERRbadreq	24	/* Bad request structure length. */
#define	ERRseek		25	/* Seek error. */
#define	ERRbadmedia	26	/* Unknown media type. */
#define	ERRbadsector	27	/* Sector not found. */
#define	ERRnopaper	28	/* Printer out of paper. */
#define	ERRwrite	29	/* Write fault. */
#define	ERRread		30	/* Read fault. */
#define	ERRgeneral	31	/* General failure. */
/*	ERRbadshare	32	Same as for DOSERR (see above) */
/*	ERRlock		33	Same as for DOSERR (see above) */
#define	ERRwrongdisk	34	/* The wrong disk was found in a drive. */
#define	ERRFCBUnavail	35	/* No FCBs are available to process request. */
#define	ERRsharebufexc	36	/* A sharing buffer has been exceeded. */


#ifdef __cplusplus
}
#endif

#endif /* _SMB_DOSERROR_H */
