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
 *
 *
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * PMC 8x6G Message Passing Interface Definitions
 */
#ifndef	_PMCS_MPI_H
#define	_PMCS_MPI_H
#ifdef	__cplusplus
extern "C" {
#endif

#define	PMCS_DWRD(x)	(x << 2)

/*
 * MPI Configuration Table Offsets
 */
#define	PMCS_MPI_AS	PMCS_DWRD(0)	/* ASCII Signature */
#define	PMCS_SIGNATURE	0x53434D50

#define	PMCS_MPI_IR	PMCS_DWRD(1)	/* Interface Revision */
#define	PMCS_MPI_REVISION1	1

#define	PMCS_MPI_FW	PMCS_DWRD(2)	/* Firmware Version */
#define	PMCS_FW_TYPE(hwp)		(hwp->fw & 0xf)
#define		PMCS_FW_TYPE_RELEASED		0
#define		PMCS_FW_TYPE_DEVELOPMENT	1
#define		PMCS_FW_TYPE_ALPHA		2
#define		PMCS_FW_TYPE_BETA		3
#define	PMCS_FW_VARIANT(hwp)		((hwp->fw >> 4) & 0xf)
#define	PMCS_FW_MAJOR(hwp)		((hwp->fw >> 24) & 0xff)
#define	PMCS_FW_MINOR(hwp)		((hwp->fw >> 16) & 0xff)
#define	PMCS_FW_MICRO(hwp)		((hwp->fw >>  8) & 0xff)
#define	PMCS_FW_REV(hwp)		((hwp->fw >> 8) & 0xffffff)
#define	PMCS_FW_VERSION(maj, min, mic)	((maj << 16)|(min << 8)|mic)

#define	PMCS_MPI_MOIO	PMCS_DWRD(3)	/* Maximum # of outstandiong I/Os */
#define	PMCS_MPI_INFO0	PMCS_DWRD(4)	/* Maximum S/G Elem, Max Dev Handle */
#define	PMCS_MSGL(x)	(x & 0xffff)
#define	PMCS_MD(x)	((x >> 16) & 0xffff)

#define	PMCS_MPI_INFO1	PMCS_DWRD(5)	/* Info #0 */

#define	PMCS_MNIQ(x)	(x & 0xff)		/* Max # of Inbound Queues */
#define	PMCS_MNOQ(x)	((x >> 8) & 0xff)	/* Max # of Outbound Queues */
#define	PMCS_HPIQ(x)	((x >> 16) & 0x1)	/* High Pri Queue Supported */
#define	PMCS_ICS(x)	((x >> 18) & 0x1)	/* Interrupt Coalescing */
#define	PMCS_NPHY(x)	((x >> 19) & 0x3f)	/* Numbers of PHYs */
#define	PMCS_SASREV(x)	((x >> 25) & 0x7)	/* SAS Revision Specification */

#define	PMCS_MPI_GSTO	PMCS_DWRD(6)	/* General Status Table Offset */
#define	PMCS_MPI_IQCTO	PMCS_DWRD(7)	/* Inbound Queue Config Table Offset */
#define	PMCS_MPI_OQCTO	PMCS_DWRD(8)	/* Outbound Queue Config Table Offset */

#define	PMCS_MPI_INFO2	PMCS_DWRD(9)	/* Info #1 */

#define	IQ_NORMAL_PRI_DEPTH_SHIFT	0
#define	IQ_NORMAL_PRI_DEPTH_MASK	0xff
#define	IQ_HIPRI_PRI_DEPTH_SHIFT	8
#define	IQ_HIPRI_PRI_DEPTH_MASK		0xff00
#define	GENERAL_EVENT_OQ_SHIFT		16
#define	GENERAL_EVENT_OQ_MASK		0xff0000
#define	DEVICE_HANDLE_REMOVED_SHIFT	24
#define	DEVICE_HANDLE_REMOVED_MASK	0xff000000ul

#define	PMCS_MPI_EVQS	PMCS_DWRD(0xA)	/* SAS Event Queues */
#define	PMCS_MPI_EVQSET(pwp, oq, phy)	{				\
	uint32_t woff = phy / 4;					\
	uint32_t shf = (phy % 4) * 8;					\
	uint32_t tmp = pmcs_rd_mpi_tbl(pwp, PMCS_MPI_EVQS + (woff << 2)); \
	tmp &= ~(0xff << shf);						\
	tmp |= ((oq & 0xff) << shf);					\
	pmcs_wr_mpi_tbl(pwp, PMCS_MPI_EVQS + (woff << 2), tmp);		\
}

#define	PMCS_MPI_SNCQ	PMCS_DWRD(0xC)	/* Sata NCQ Notification Queues */
#define	PMCS_MPI_NCQSET(pwp, oq, phy)	{				\
	uint32_t woff = phy / 4;					\
	uint32_t shf = (phy % 4) * 8;					\
	uint32_t tmp = pmcs_rd_mpi_tbl(pwp, PMCS_MPI_SNCQ + (woff << 2)); \
	tmp &= ~(0xff << shf);						\
	tmp |= ((oq & 0xff) << shf);					\
	pmcs_wr_mpi_tbl(pwp, PMCS_MPI_SNCQ + (woff << 2), tmp);		\
}

/*
 * I_T Nexus Target Event Notification Queue
 */
#define	PMCS_MPI_IT_NTENQ	PMCS_DWRD(0xE)

/*
 * SSP Target Event Notification Queue
 */
#define	PMCS_MPI_SSP_TENQ	PMCS_DWRD(0x10)

/*
 * I/O Abort Delay
 */
#define	PMCS_MPI_IOABTDLY	PMCS_DWRD(0x12)

/*
 * Customization Setting
 */
#define	PMCS_MPI_CUSTSET	PMCS_DWRD(0x13)

#define	PMCS_MPI_CUST_HW_RSC_BSY_ALT	0x1	/* Bit 0 */
#define	PMCS_MPI_CUST_ABORT_ITNL	0x2	/* Bit 1 */

/*
 * This specifies a log buffer in host memory for the MSGU.
 */
#define	PMCS_MPI_MELBAH	PMCS_DWRD(0x14)	/* MSGU Log Buffer high 32 bits */
#define	PMCS_MPI_MELBAL	PMCS_DWRD(0x15)	/* MSGU Log Buffer low 32 bits */
#define	PMCS_MPI_MELBS	PMCS_DWRD(0x16)	/* size in bytes of MSGU log buffer */
#define	PMCS_MPI_MELSEV	PMCS_DWRD(0x17)	/* Log Severity */

/*
 * This specifies a log buffer in host memory for the IOP.
 */
#define	PMCS_MPI_IELBAH	PMCS_DWRD(0x18)	/* IOP Log Buffer high 32 bits */
#define	PMCS_MPI_IELBAL	PMCS_DWRD(0x19)	/* IOP Log Buffer low 32 bits */
#define	PMCS_MPI_IELBS	PMCS_DWRD(0x1A)	/* size in bytes of IOP log buffer */
#define	PMCS_MPI_IELSEV	PMCS_DWRD(0x1B)	/* Log Severity */

/*
 * Fatal Error Handling
 */
#define	PMCS_MPI_FERR		PMCS_DWRD(0x1C)
#define	PMCS_FERRIE		0x1	/* Fatal Err Interrupt Enable */
#define	PMCS_PCAD64		0x2	/* PI/CI addresses are 64-bit */
#define	PMCS_FERIV_MASK		0xff00	/* Fatal Err Interrupt Mask */
#define	PMCS_FERIV_SHIFT	8	/* Fatal Err Interrupt Shift */

#define	PMCS_MPI_IRAE		0x20000	/* Interrupt Reassertion Enable */
#define	PMCS_MPI_IRAU		0x40000	/* Interrupt Reassertion Unit */
#define	PMCS_MPI_IRAD_MASK	0xfff80000 /* Reassertion Delay Mask */

#define	PMCS_FERDOMSGU		PMCS_DWRD(0x1D)
#define	PMCS_FERDLMSGU		PMCS_DWRD(0x1E)
#define	PMCS_FERDOIOP		PMCS_DWRD(0x1F)
#define	PMCS_FERDLIOP		PMCS_DWRD(0x20)

/*
 * MPI GST Table Offsets
 */

#define	PMCS_GST_BASE		0
#define	PMCS_GST_IQFRZ0		(PMCS_GST_BASE + PMCS_DWRD(1))
#define	PMCS_GST_IQFRZ1		(PMCS_GST_BASE + PMCS_DWRD(2))
#define	PMCS_GST_MSGU_TICK	(PMCS_GST_BASE + PMCS_DWRD(3))
#define	PMCS_GST_IOP_TICK	(PMCS_GST_BASE + PMCS_DWRD(4))
#define	PMCS_GST_PHY_INFO(x)	(PMCS_GST_BASE + PMCS_DWRD(0x6) + PMCS_DWRD(x))
#define	PMCS_GST_RERR_BASE	(PMCS_GST_BASE + PMCS_DWRD(0x11))
#define	PMCS_GST_RERR_INFO(x)	(PMCS_GST_RERR_BASE + PMCS_DWRD(x))

#define	PMCS_MPI_S(x)		((x) & 0x7)
#define	PMCS_QF(x)		(((x) >> 3) & 0x1)
#define	PMCS_GSTLEN(x)		(((x) >> 4) & 0x3fff)
#define	PMCS_HMI_ERR(x)		(((x) >> 16) & 0xffff)

#define	PMCS_MPI_STATE_NIL	0
#define	PMCS_MPI_STATE_INIT	1
#define	PMCS_MPI_STATE_DEINIT	2
#define	PMCS_MPI_STATE_ERR	3

/*
 * MPI Inbound Queue Configuration Table Offsets
 *
 * Each Inbound Queue configuration area consumes 8 DWORDS (32 bit words),
 * or 32 bytes.
 */
#define	PMCS_IQC_PARMX(x)	((x) << 5)
#define	PMCS_IQBAHX(x)		(((x) << 5) + 4)
#define	PMCS_IQBALX(x)		(((x) << 5) + 8)
#define	PMCS_IQCIBAHX(x)	(((x) << 5) + 12)
#define	PMCS_IQCIBALX(x)	(((x) << 5) + 16)
#define	PMCS_IQPIBARX(x)	(((x) << 5) + 20)
#define	PMCS_IQPIOFFX(x)	(((x) << 5) + 24)
#define	PMCS_IQDX(x)		((x) & 0xffff)
#define	PMCS_IQESX(x)		(((x) >> 16) & 0x3fff)
#define	PMCS_IQPX(x)		(((x) >> 30) & 0x3)

/*
 * MPI Outbound Queue Configuration Table Offsets
 *
 * Each Outbound Queue configuration area consumes 9 DWORDS (32 bit words),
 * or 36 bytes.
 */
#define	PMCS_OQC_PARMX(x)	(x * 36)
#define	PMCS_OQBAHX(x)		((x * 36) + 4)
#define	PMCS_OQBALX(x)		((x * 36) + 8)
#define	PMCS_OQPIBAHX(x)	((x * 36) + 12)
#define	PMCS_OQPIBALX(x)	((x * 36) + 16)
#define	PMCS_OQCIBARX(x)	((x * 36) + 20)
#define	PMCS_OQCIOFFX(x)	((x * 36) + 24)
#define	PMCS_OQIPARM(x)		((x * 36) + 28)
#define	PMCS_OQDICX(x)		((x * 36) + 32)

#define	PMCS_OQDX(x)		((x) & 0xffff)
#define	PMCS_OQESX(x)		(((x) >> 16) & 0x3fff)
#define	PMCS_OQICT(x)		((x) & 0xffff)
#define	PMCS_OQICC(x)		(((x) >> 16) & 0xff)
#define	PMCS_OQIV(x)		(((x) >> 24) & 0xff)

#define	OQIEX			(1 << 30)

#ifdef	__cplusplus
}
#endif
#endif	/* _PMCS_MPI_H */
