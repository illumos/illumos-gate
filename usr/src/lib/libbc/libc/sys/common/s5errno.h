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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef _SYS_ERRNO_H
#define _SYS_ERRNO_H

#ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Error codes
 */

#define	EPERM	1	/* Not super-user			*/
#define	ENOENT	2	/* No such file or directory		*/
#define	ESRCH	3	/* No such process			*/
#define	EINTR	4	/* interrupted system call		*/
#define	EIO	5	/* I/O error				*/
#define	ENXIO	6	/* No such device or address		*/
#define	E2BIG	7	/* Arg list too long			*/
#define	ENOEXEC	8	/* Exec format error			*/
#define	EBADF	9	/* Bad file number			*/
#define	ECHILD	10	/* No children				*/
#define	EAGAIN	11	/* No more processes			*/
#define	ENOMEM	12	/* Not enough core			*/
#define	EACCES	13	/* Permission denied			*/
#define	EFAULT	14	/* Bad address				*/
#define	ENOTBLK	15	/* Block device required		*/
#define	EBUSY	16	/* Mount device busy			*/
#define	EEXIST	17	/* File exists				*/
#define	EXDEV	18	/* Cross-device link			*/
#define	ENODEV	19	/* No such device			*/
#define	ENOTDIR	20	/* Not a directory			*/
#define	EISDIR	21	/* Is a directory			*/
#define	EINVAL	22	/* Invalid argument			*/
#define	ENFILE	23	/* File table overflow			*/
#define	EMFILE	24	/* Too many open files			*/
#define	ENOTTY	25	/* Not a typewriter			*/
#define	ETXTBSY	26	/* Text file busy			*/
#define	EFBIG	27	/* File too large			*/
#define	ENOSPC	28	/* No space left on device		*/
#define	ESPIPE	29	/* Illegal seek				*/
#define	EROFS	30	/* Read only file system		*/
#define	EMLINK	31	/* Too many links			*/
#define	EPIPE	32	/* Broken pipe				*/
#define	EDOM	33	/* Math arg out of domain of func	*/
#define	ERANGE	34	/* Math result not representable	*/
#define	ENOMSG	35	/* No message of desired type		*/
#define	EIDRM	36	/* Identifier removed			*/
#define	ECHRNG	37	/* Channel number out of range		*/
#define	EL2NSYNC 38	/* Level 2 not synchronized		*/
#define	EL3HLT	39	/* Level 3 halted			*/
#define	EL3RST	40	/* Level 3 reset			*/
#define	ELNRNG	41	/* Link number out of range		*/
#define	EUNATCH 42	/* Protocol driver not attached		*/
#define	ENOCSI	43	/* No CSI structure available		*/
#define	EL2HLT	44	/* Level 2 halted			*/
#define	EDEADLK	45	/* Deadlock condition.			*/
#define	ENOLCK	46	/* No record locks available.		*/

/* Filesystem Quotas */
#define	EDQUOT	49	/* Disc quota exceeded			*/

/* Convergent Error Returns */
#define EBADE	50	/* invalid exchange			*/
#define EBADR	51	/* invalid request descriptor		*/
#define EXFULL	52	/* exchange full			*/
#define ENOANO	53	/* no anode				*/
#define EBADRQC	54	/* invalid request code			*/
#define EBADSLT	55	/* invalid slot				*/
#define EDEADLOCK 56	/* file locking deadlock error		*/

#define EBFONT	57	/* bad font file fmt			*/

/* stream problems */
#define ENOSTR	60	/* Device not a stream			*/
#define ENODATA	61	/* no data (for no delay io)		*/
#define ETIME	62	/* timer expired			*/
#define ENOSR	63	/* out of streams resources		*/

#define ENONET	64	/* Machine is not on the network	*/
#define ENOPKG	65	/* Package not installed                */
#define EREMOTE	66	/* The object is remote			*/
#define ENOLINK	67	/* the link has been severed */
#define EADV	68	/* advertise error */
#define ESRMNT	69	/* srmount error */

#define	ECOMM	70	/* Communication error on send		*/
#define EPROTO	71	/* Protocol error			*/
#define	EMULTIHOP 74	/* multihop attempted */
#define EBADMSG 77	/* trying to read unreadable message	*/
#define ENAMETOOLONG 78	/* path name is too long */
#define EOVERFLOW 79	/* value too large to be stored in data type */
#define ENOTUNIQ 80	/* given log. name not unique */
#define EBADFD	 81	/* f.d. invalid for this operation */
#define EREMCHG	 82	/* Remote address changed */

/* shared library problems */
#define ELIBACC	83	/* Can't access a needed shared lib.	*/
#define ELIBBAD	84	/* Accessing a corrupted shared lib.	*/
#define ELIBSCN	85	/* .lib section in a.out corrupted.	*/
#define ELIBMAX	86	/* Attempting to link in too many libs.	*/
#define ELIBEXEC 87	/* Attempting to exec a shared library.	*/
#define	EILSEQ 88	/* Illegal byte sequence. */
#define ENOSYS 89	/* Unsupported file system operation */
#define ELOOP	90	/* Symbolic link loop */
#define	ERESTART 91	/* Restartable system call */
#define ESTRPIPE 92	/* if pipe/FIFO, don't sleep in stream head */
#define ENOTEMPTY 93	/* directory not empty */
#define EUSERS	94	/* Too many users (for UFS) */

/* BSD Networking Software */
	/* argument errors */
#define	ENOTSOCK	95		/* Socket operation on non-socket */
#define	EDESTADDRREQ	96		/* Destination address required */
#define	EMSGSIZE	97		/* Message too long */
#define	EPROTOTYPE	98		/* Protocol wrong type for socket */
#define	ENOPROTOOPT	99		/* Protocol not available */
#define	EPROTONOSUPPORT	120		/* Protocol not supported */
#define	ESOCKTNOSUPPORT	121		/* Socket type not supported */
#define	EOPNOTSUPP	122		/* Operation not supported on socket */
#define	EPFNOSUPPORT	123		/* Protocol family not supported */
#define	EAFNOSUPPORT	124		/* Address family not supported by 
					   protocol family */
#define	EADDRINUSE	125		/* Address already in use */
#define	EADDRNOTAVAIL	126		/* Can't assign requested address */
	/* operational errors */
#define	ENETDOWN	127		/* Network is down */
#define	ENETUNREACH	128		/* Network is unreachable */
#define	ENETRESET	129		/* Network dropped connection because
					   of reset */
#define	ECONNABORTED	130		/* Software caused connection abort */
#define	ECONNRESET	131		/* Connection reset by peer */
#define	ENOBUFS		132	       	/* No buffer space available */
#define	EISCONN		133		/* Socket is already connected */
#define	ENOTCONN	134		/* Socket is not connected */
/* XENIX has 135 - 142 */
#define	ESHUTDOWN	143		/* Can't send after socket shutdown */
#define	ETOOMANYREFS	144		/* Too many references: can't splice */
#define	ETIMEDOUT	145		/* Connection timed out */
#define	ECONNREFUSED	146		/* Connection refused */
#define	EHOSTDOWN	147		/* Host is down */
#define	EHOSTUNREACH	148		/* No route to host */
#define EWOULDBLOCK	EAGAIN
#define EALREADY	149		/* operation already in progress */
#define EINPROGRESS	150		/* operation now in progress */

/* SUN Network File System */
#define	ESTALE		151		/* Stale NFS file handle */

#ifdef XENIX_MERGE
/* XENIX error numbers */
#define EUCLEAN 	135	/* Structure needs cleaning */
#define	ENOTNAM		137	/* Not a XENIX named type file */
#define	ENAVAIL		138	/* No XENIX semaphores available */
#define	EISNAM		139	/* Is a named type file */
#define EREMOTEIO	140	/* Remote I/O error */
#define EINIT		141	/* Reserved for future */
#define EREMDEV		142	/* Error 142 */
#endif /* XENIX_MERGE */

#endif	/* _SYS_ERRNO_H */
