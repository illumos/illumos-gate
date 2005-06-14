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
 * Copyright (c) 1997,1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_DKTP_SCTARGET_H
#define	_SYS_DKTP_SCTARGET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/scsi/impl/pkt_wrapper.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	UNDEFINED 	-1

#define	PRF		prom_printf

#define	SET_BP_SEC(bp, X) ((bp)->b_private = (void *) (X))
#define	GET_BP_SEC(bp) ((daddr_t)(bp)->b_private)

#define	BP_PKT(bp)	((struct scsi_pkt *)(bp)->av_back)
#define	PKT_BP(pktp)	(SC_XPKTP((pktp))->x_bp)

#define	GSC_DK_MSEN(pktp, pc)						\
		bzero((caddr_t)pktp->pkt_cdbp, CDB_GROUP0);		\
		makecom_g0((pktp),					\
			(struct scsi_device *)&((pktp)->pkt_address),	\
			(pktp)->pkt_flags, SCMD_MODE_SENSE, (pc)<<8,	\
			SC_XPKTP(pktp)->x_bytexfer)

#define	GSC_DK_MSEN10(pktp, pc)						\
		bzero((caddr_t)pktp->pkt_cdbp, CDB_GROUP1);		\
		makecom_g1((pktp),					\
			(struct scsi_device *)&((pktp)->pkt_address),	\
			(pktp)->pkt_flags, 0x5A, (pc)<<24,		\
			SC_XPKTP(pktp)->x_bytexfer)

#define	GSC_DK_SXWRITE(pktp)						\
		bzero((caddr_t)pktp->pkt_cdbp, CDB_GROUP1);		\
		makecom_g1((pktp),					\
			(struct scsi_device *)&((pktp)->pkt_address),	\
			(pktp)->pkt_flags, SCMD_WRITE_G1,		\
			(int)SC_XPKTP(pktp)->x_srtsec,			\
			SC_XPKTP(pktp)->x_seccnt)

#define	GSC_DK_SCWRITE(pktp)						\
		bzero((caddr_t)pktp->pkt_cdbp, CDB_GROUP0);		\
		makecom_g0((pktp),					\
			(struct scsi_device *)&((pktp)->pkt_address),	\
			(pktp)->pkt_flags, SCMD_WRITE,			\
			(int)SC_XPKTP(pktp)->x_srtsec,			\
			SC_XPKTP(pktp)->x_seccnt)

#define	GSC_DK_SXREAD(pktp)						\
		bzero((caddr_t)pktp->pkt_cdbp, CDB_GROUP1);		\
		makecom_g1((pktp),					\
			(struct scsi_device *)&((pktp)->pkt_address),	\
			(pktp)->pkt_flags, SCMD_READ_G1,		\
			(int)SC_XPKTP(pktp)->x_srtsec,			\
			SC_XPKTP(pktp)->x_seccnt)

#define	GSC_DK_SCREAD(pktp)						\
		bzero((caddr_t)pktp->pkt_cdbp, CDB_GROUP0);		\
		makecom_g0((pktp),					\
			(struct scsi_device *)&((pktp)->pkt_address),	\
			(pktp)->pkt_flags, SCMD_READ,			\
			(int)SC_XPKTP(pktp)->x_srtsec,			\
			SC_XPKTP(pktp)->x_seccnt)

#define	GSC_REQSEN(pktp)						\
		bzero((caddr_t)pktp->pkt_cdbp, CDB_GROUP0);		\
		makecom_g0((pktp),					\
			(struct scsi_device *)&((pktp)->pkt_address),	\
			(pktp)->pkt_flags, SCMD_REQUEST_SENSE, 0,	\
			SENSE_LENGTH)

#define	GSC_TESTUNIT(pktp)						\
		bzero((caddr_t)pktp->pkt_cdbp, CDB_GROUP0);		\
		makecom_g0((pktp),					\
			(struct scsi_device *)&((pktp)->pkt_address),	\
			(pktp)->pkt_flags, SCMD_TEST_UNIT_READY, 0, 0)

#define	GSC_START(pktp)							\
		bzero((caddr_t)pktp->pkt_cdbp, CDB_GROUP0);		\
		makecom_g0((pktp),					\
			(struct scsi_device *)&((pktp)->pkt_address),	\
			(pktp)->pkt_flags, SCMD_START_STOP, 0, 1)

#define	GSC_STOP(pktp)							\
		bzero((caddr_t)pktp->pkt_cdbp, CDB_GROUP0);		\
		makecom_g0((pktp),					\
			(struct scsi_device *)&((pktp)->pkt_address),	\
			(pktp)->pkt_flags, SCMD_START_STOP, 0, 0)

#define	GSC_INQUIRY(pktp)						\
		bzero((caddr_t)pktp->pkt_cdbp, CDB_GROUP0);		\
		makecom_g0((pktp),					\
			(struct scsi_device *)&((pktp)->pkt_address),	\
			(pktp)->pkt_flags, SCMD_INQUIRY, 0,		\
			sizeof (struct scsi_inquiry))

#define	GSC_REZERO(pktp)						\
		bzero((caddr_t)pktp->pkt_cdbp, CDB_GROUP0);		\
		makecom_g0((pktp),					\
			(struct scsi_device *)&((pktp)->pkt_address),	\
			(pktp)->pkt_flags, SCMD_REZERO_UNIT, 0, 0)

#define	GSC_RDCAP(pktp)							\
		bzero((caddr_t)pktp->pkt_cdbp, CDB_GROUP1);		\
		makecom_g1((pktp),					\
			(struct scsi_device *)&((pktp)->pkt_address),	\
			(pktp)->pkt_flags, SCMD_READ_CAPACITY, 0, 0)

#define	GSC_LOCK(pktp)							\
		bzero((caddr_t)pktp->pkt_cdbp, CDB_GROUP0);		\
		makecom_g0((pktp),					\
			(struct scsi_device *)&((pktp)->pkt_address),	\
			(pktp)->pkt_flags, SCMD_DOORLOCK, 0, 1)

#define	GSC_UNLOCK(pktp)						\
		bzero((caddr_t)pktp->pkt_cdbp, CDB_GROUP0);		\
		makecom_g0((pktp),					\
			(struct scsi_device *)&((pktp)->pkt_address),	\
			(pktp)->pkt_flags, SCMD_DOORLOCK, 0, 0)

#define	GSC_MSEL(pktp)							\
		bzero((caddr_t)pktp->pkt_cdbp, CDB_GROUP0);		\
		makecom_g0((pktp),					\
			(struct scsi_device *)&((pktp)->pkt_address),	\
			(pktp)->pkt_flags, SCMD_MODE_SELECT, 0,		\
			SC_XPKTP(pktp)->x_bytexfer)

#ifdef  _KERNEL
#ifdef  __STDC__
extern void 	scsi_incmplmsg(struct scsi_device *, char *label,
			struct scsi_pkt *);
extern void 	scsi_inqfill(char *p, int l, char *s);
extern ulong_t 	scsi_stoh_3byte(uchar_t *);
extern ulong_t 	scsi_stoh_long(ulong_t);
extern ushort_t	scsi_stoh_short(ushort_t);
extern int 	scsi_exam_arq(opaque_t scdevp, struct scsi_pkt *pktp,
			int (*rqshdl)(), dev_info_t dev, char *name);

#else   /* __STDC__ */

extern void 	scsi_incmplmsg();
extern void 	scsi_inqfill();
extern ulong_t 	scsi_stoh_3byte();
extern ulong_t 	scsi_stoh_long();
extern ushort_t	scsi_stoh_short();
extern int 	scsi_exam_arq();

#endif  /* __STDC__ */

#endif  /* _KERNEL */

#define	SDEV2ADDR(devp) (&((devp)->sd_address))

#define	SCBP(pkt)	((struct scsi_status *)(pkt)->pkt_scbp)
#define	SCBP_C(pkt)	((*(pkt)->pkt_scbp) & STATUS_MASK)
#define	CDBP(pkt)	((union scsi_cdb *)(pkt)->pkt_cdbp)

/*
 * packet action codes
 */
#define	COMMAND_DONE		0
#define	COMMAND_DONE_ERROR	1
#define	QUE_COMMAND		2
#define	QUE_SENSE		3
#define	JUST_RETURN		4

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_SCTARGET_H */
