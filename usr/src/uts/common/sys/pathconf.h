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
 *
 *	Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

#ifndef	_SYS_PATHCONF_H
#define	_SYS_PATHCONF_H

/*	pathconf.h 1.9 89/06/26 SMI	*/

#include <sys/unistd.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * POSIX pathconf information
 *
 * static pathconf kludge notes:
 *	For NFSv2 servers, we've added a vop (vop_cntl) to dig out pathconf
 *	information.  The mount program asked for the information from
 *	a remote mountd daemon.  If it gets it, it passes the info
 *	down in a new args field.  The info is passed in the struct below
 *	in nfsargs.pathconf.  There's a new NFS mount flag so that you know
 *	this is happening.  NFS stores the information locally; when a
 *	pathconf request is made, the request is intercepted at the client
 *	and the information is retrieved from the struct passed down by
 *	mount. It's a kludge that will go away as soon
 *	as we can ask the nfs protocol these sorts of questions (NFSr3).
 *	All code is noted by "static pathconf kludge" comments and is
 *	restricted to nfs code in the kernel.
 */

#define	_BITS		(8 * sizeof (short))
#define	_PC_N		((_PC_LAST + _BITS - 1) / _BITS)
#define	_PC_ISSET(n, a)	(a[(n) / _BITS] & (1 << ((n) % _BITS)))
#define	_PC_SET(n, a)	(a[(n) / _BITS] |= (1 << ((n) % _BITS)))
#define	_PC_ERROR	0

struct	pathcnf {
	/*
	 * pathconf() information
	 */
	int		pc_link_max;	/* max links allowed */
	short		pc_max_canon;	/* max line len for a tty */
	short		pc_max_input;	/* input a tty can eat all once */
	short		pc_name_max;	/* max file name length (dir entry) */
	short		pc_path_max;	/* path name len (/x/y/z/...) */
	short		pc_pipe_buf;	/* size of a pipe (bytes) */
	uchar_t		pc_vdisable;	/* safe char to turn off c_cc[i] */
	char		pc_xxx;		/* alignment padding; cc_t == char */
	short		pc_mask[_PC_N];	/* see below */
#ifdef	_KERNEL
	short		pc_refcnt;	/* number of mounts that use this */
	struct pathcnf	*pc_next;	/* linked list */
#endif
};

#ifdef _SYSCALL32
struct	pathcnf32 {
	/*
	 * pathconf() information
	 */
	int32_t		pc_link_max;	/* max links allowed */
	int16_t		pc_max_canon;	/* max line len for a tty */
	int16_t		pc_max_input;	/* input a tty can eat all once */
	int16_t		pc_name_max;	/* max file name length (dir entry) */
	int16_t		pc_path_max;	/* path name len (/x/y/z/...) */
	int16_t		pc_pipe_buf;	/* size of a pipe (bytes) */
	uint8_t		pc_vdisable;	/* safe char to turn off c_cc[i] */
	int8_t		pc_xxx;		/* alignment padding; cc_t == char */
	int16_t		pc_mask[_PC_N];	/* see below */
#ifdef	_KERNEL
	int16_t		pc_refcnt;	/* number of mounts that use this */
	caddr32_t	pc_next;	/* linked list */
#endif
};
#endif /* _SYSCALL32 */

/*
 * pc_mask is used to encode either
 *	a) boolean values (for chown_restricted and no_trunc)
 *	b) errno on/off (for link, canon, input, name, path, and pipe)
 * The _PC_XXX values are defined in unistd.h; they start at 1 and go up
 * sequentially.
 * _PC_ERROR is used as the first bit to indicate total failure
 * (all info invalid).
 * To check for an error something like
 * 	_PC_ISSET(_PC_PATHMAX, foo.pc_mask) != 0
 * is used.
 */

/*
 * The size of the non-kernel part of the struct.
 */
#ifdef	_KERNEL
#define	PCSIZ		((size_t)(&(((struct pathcnf *)0)->pc_refcnt)))
#define	PCCMP(p1, p2)	bcmp((char *)p1, (char *)p2, PCSIZ)
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PATHCONF_H */
