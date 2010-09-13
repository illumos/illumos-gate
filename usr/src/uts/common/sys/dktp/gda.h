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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_DKTP_GDA_H
#define	_SYS_DKTP_GDA_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	GDA_RTYCNT	3

#define	GDA_BP_PKT(bp)	((struct cmpkt *)(bp)->av_back)

#ifdef  _KERNEL

extern void 	gda_inqfill(char *p, int l, char *s);
/*PRINTFLIKE4*/
extern void	gda_log(dev_info_t *, char *, uint_t, const char *, ...)
	__KPRINTFLIKE(4);
extern void	gda_errmsg(struct scsi_device *, struct cmpkt *, char *,
			int, daddr_t, daddr_t, char **, char **);
extern struct 	cmpkt *gda_pktprep(opaque_t objp, struct cmpkt *in_pktp,
			opaque_t dmatoken, int (*func)(caddr_t), caddr_t arg);
extern void	gda_free(opaque_t objp, struct cmpkt *pktp, struct buf *bp);

#endif  /* _KERNEL */

#define	GDA_GETGEOM_HEAD(X) (((X) >> 16) & 0xff)
#define	GDA_GETGEOM_SEC(X)  ((X) & 0xff)
#define	GDA_SETGEOM(hd, sec) (((hd) << 16) | (sec))

#define	GDA_KMFLAG(callback) (((callback) == DDI_DMA_SLEEP) ? \
				KM_SLEEP: KM_NOSLEEP)

#define	GDA_ALL			0
#define	GDA_UNKNOWN		1
#define	GDA_INFORMATIONAL	2
#define	GDA_RECOVERED		3
#define	GDA_RETRYABLE		4
#define	GDA_FATAL		5

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_GDA_H */
