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
 * Copyright (c) 1992,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_DKTP_CMPKT_H
#define	_SYS_DKTP_CMPKT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct	cmpkt {
	opaque_t	cp_objp;	/* ptr to generic ctlr object	*/
	opaque_t	cp_ctl_private;	/* ptr to controller private	*/
	opaque_t	cp_dev_private; /* ptr to device driver private */

	int		cp_scblen;	/* len of status control blk	*/
	opaque_t	cp_scbp;	/* status control blk		*/
	int		cp_cdblen;	/* len of cmd description blk	*/
	opaque_t	cp_cdbp;	/* command description blk	*/
	long		cp_reason;	/* error status			*/
	void		(*cp_callback)(); /* callback function		*/
	long		cp_time;	/* timeout values		*/
	long		cp_flags;

	struct buf	*cp_bp;		/* link to buf structure	*/
	long		cp_resid;	/* data bytes not transferred	*/
	long		cp_byteleft;	/* remaining bytes to do	*/

					/* for a particular disk section */
	long		cp_bytexfer;	/* bytes xfer in this operation */

	daddr_t		cp_srtsec;	/* starting sector number	*/
	long		cp_secleft;	/* # of sectors remains		*/

	ushort_t	cp_retry;	/* retry count			*/
	ushort_t	cp_resv;

	void		(*cp_iodone)(); /* target driver iodone()	*/
	struct cmpkt 	*cp_fltpktp;	/* fault recovery pkt pointer	*/
	opaque_t	cp_private;
	opaque_t	cp_passthru;	/* pass through command ptr	*/
};

/*	reason code for completion status				*/
#define	CPS_SUCCESS	0		/* command completes with no err */
#define	CPS_FAILURE	1		/* command fails		*/
#define	CPS_CHKERR	2		/* command fails with status	*/
#define	CPS_ABORTED	3		/* command aborted		*/

/*	flags definitions						*/
#define	CPF_NOINTR	0x0001		/* polling mode			*/

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_CMPKT_H */
