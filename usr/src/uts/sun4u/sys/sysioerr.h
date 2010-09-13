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
 * Copyright (c) 1991-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_SYSIOERR_H
#define	_SYS_SYSIOERR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Sbus error interrupt priorities
 */
#define	SBUS_UE_PIL		12
#define	SBUS_CE_PIL		11
#define	SBUS_ERR_PIL		12
#define	SBUS_THERMAL_PIL	9
#define	SBUS_PF_PIL		12
#define	SBUS_PM_PIL		12

/*
 * Bits of Sun5 SYSIO Control/Status Register
 */
#define	SYSIO_IMPL	0xF000000000000000ULL /* implementation number */
#define	SYSIO_VER	0x0F00000000000000ULL /* revision number */
#define	SYSIO_MID	0x00F8000000000000ULL /* UPA mid for SYSIO */
#define	SYSIO_INTGN	0x0007C00000000000ULL /* interrupt group number */
#define	SYSIO_APCKEN	0x0000000000000008ULL /* address parity check enable */
#define	SYSIO_APERR	0x0000000000000004ULL /* system address parity error */
#define	SYSIO_IAP	0x0000000000000002ULL /* invert UPA address parity */
#define	SYSIO_MODE	0x0000000000000001ULL /* speed of SYSIO clock */

/*
 * Bits of Sun5 SBus ECC Control Register
 */
#define	SECR_ECC_EN	0x8000000000000000ULL /* enable ECC checking */
#define	SECR_UE_INTEN	0x4000000000000000ULL /* enable UE_INT interrupt */
#define	SECR_CE_INTEN	0x2000000000000000ULL /* enable CE_INT interrupt */

/*
 * Bits of Sun5 SBus UE Asynchronous Fault Status Register
 */
#define	SB_UE_AFSR_P_PIO 0x8000000000000000ULL /* primary UE, PIO access */
#define	SB_UE_AFSR_P_DRD 0x4000000000000000ULL /* primary UE, DVMA read */
#define	SB_UE_AFSR_P_DWR 0x2000000000000000ULL /* primary UE, DVMA write */
#define	SB_UE_AFSR_P	 0xE000000000000000ULL /* primary UE */
#define	SB_UE_AFSR_S_PIO 0x1000000000000000ULL /* secondary UE, PIO access */
#define	SB_UE_AFSR_S_DRD 0x0800000000000000ULL /* secondary UE, DVMA read */
#define	SB_UE_AFSR_S_DWR 0x0400000000000000ULL /* secondary UE, DVMA write */
#define	SB_UE_AFSR_S	 0x1C00000000000000ULL /* secondary UE */
#define	SB_UE_AFSR_OFF   0x0000E00000000000ULL /* offset of dword w/pri. UE */
#define	SB_UE_AFSR_SIZE  0x00001C0000000000ULL /* 2**size of bad transfer */
#define	SB_UE_AFSR_MID   0x000003E000000000ULL /* master ID for pri. error */
#define	SB_UE_AFSR_ISAP	 0x0000001000000000ULL /* system parity error */

/*
 * Shifts for SBus Sysio UE Asynchronous Fault Status Register
 */
#define	SB_UE_DW_SHIFT		(45)
#define	SB_UE_SIZE_SHIFT	(42)
#define	SB_UE_MID_SHIFT		(37)

/*
 * Bits of Fusion Desktop SBus UE Asynchronous Fault Address Register
 */
#define	SB_UE_AFAR_PA	0x000001FFFFFFFFFF    /* PA<40:0>: physical address */

/*
 * Bits of Sun5 SBus CE Asynchronous Fault Status Register
 */
#define	SB_CE_AFSR_P_PIO 0x8000000000000000ULL /* primary CE, PIO access */
#define	SB_CE_AFSR_P_DRD 0x4000000000000000ULL /* primary CE, DVMA read */
#define	SB_CE_AFSR_P_DWR 0x2000000000000000ULL /* primary CE, DVMA write */
#define	SB_CE_AFSR_P	 0xE000000000000000ULL /* primary CE */
#define	SB_CE_AFSR_S_PIO 0x1000000000000000ULL /* secondary CE, PIO access */
#define	SB_CE_AFSR_S_DRD 0x0800000000000000ULL /* secondary CE, DVMA read */
#define	SB_CE_AFSR_S_DWR 0x0400000000000000ULL /* secondary CE, DVMA write */
#define	SB_CE_AFSR_S	 0x1C00000000000000ULL /* secondary CE */
#define	SB_CE_AFSR_SYND  0x00FF000000000000ULL /* CE syndrome bits */
#define	SB_CE_AFSR_OFF   0x0000E00000000000ULL /* offset of dword w/pri. CE */
#define	SB_CE_AFSR_SIZE	 0x00001C0000000000ULL /* 2**size of failed transfer */
#define	SB_CE_AFSR_MID	 0x000003E000000000ULL /* master ID for primary error */

/*
 * Shifts for Sun5 SBus CE Asynchronous Fault Status Register
 */
#define	SB_CE_SYND_SHIFT	(48)
#define	SB_CE_OFFSET_SHIFT	(45)
#define	SB_CE_SIZE_SHIFT	(42)
#define	SB_CE_MID_SHIFT		(37)

/*
 * Bits of Sun5 Fusion Desktop SBus CE Asynchronous Fault Address Register
 * Note: Fusion Desktop does not support E_SYND2.
 */
#define	SB_CE_E_SYND2	0xFF00000000000000ULL /* syndrome of prim. CE */
#define	SB_CE_AFAR_PA	0x000001FFFFFFFFFFULL /* PA<40:0>: physical address */

/*
 * Shift for Sun5 SBus CE Asynchronous Fault Address Register
 */
#define	SB_CE_SYND2_SHIFT	(56)

/*
 * Bits of Sun5 SBus Control and Status Register
 * See Fusion Desktop System Spec. Table 3-63 for details on slots 13-15
 */
#define	SB_CSR_IMPL	 0xF000000000000000ULL /* host adapter impl. number */
#define	SB_CSR_REV	 0x0F00000000000000ULL /* host adapter rev. number */
#define	SB_CSR_DPERR_S14 0x0020000000000000ULL /* SBus slot 14 aka Happy Meal */
#define	SB_CSR_DPERR_S13 0x0010000000000000ULL /* SBus slot 13 aka APC */
#define	SB_CSR_DPERR_S3  0x0008000000000000ULL /* SBus slot 3 DVMA parity err */
#define	SB_CSR_DPERR_S2  0x0004000000000000ULL /* SBus slot 2 DVMA parity err */
#define	SB_CSR_DPERR_S1  0x0002000000000000ULL /* SBus slot 1 DVMA parity err */
#define	SB_CSR_DPERR_S0  0x0001000000000000ULL /* SBus slot 0 DVMA parity err */
#define	SB_CSR_PIO_PERRS 0x00007F0000000000ULL /* SBus parity errors */
#define	SB_CSR_PPERR_S15 0x0000400000000000ULL /* SBus slot 15 aka slavio */
#define	SB_CSR_PPERR_S14 0x0000200000000000ULL /* SBus slot 14 aka Happy Meal */
#define	SB_CSR_PPERR_S13 0x0000100000000000ULL /* SBus slot 13 aka APC */
#define	SB_CSR_PPERR_S3  0x0000080000000000ULL /* SBus slot 3 PIO parity err */
#define	SB_CSR_PPERR_S2  0x0000040000000000ULL /* SBus slot 2 PIO parity err */
#define	SB_CSR_PPERR_S1  0x0000020000000000ULL /* SBus slot 1 PIO parity err */
#define	SB_CSR_PPERR_S0  0x0000010000000000ULL /* SBus slot 0 PIO parity err */
#define	SB_CSR_FAST_SBUS 0x0000000000000400ULL /* shorten PIO access latency */
#define	SB_CSR_WAKEUP_EN 0x0000000000000200ULL /* power-management bit */
#define	SB_CSR_ERRINT_EN 0x0000000000000100ULL /* enable intr. for SBus errs */
#define	SB_CSR_ARBEN_MAC 0x0000000000000020ULL /* enable DVMA for Macio */
#define	SB_CSR_ARBEN_APC 0x0000000000000010ULL /* enable DVMA for APC */
#define	SB_CSR_ARBEN_SLT 0x000000000000000FULL /* enable DVMA for SBus slots */

/*
 * Shifts for Sun5 SBus Control and Status Register
 */
#define	SB_CSR_IMPL_SHIFT	(60)
#define	SB_CSR_REV_SHIFT	(56)
#define	SB_CSR_DVMA_PERR_SHIFT	(48)
#define	SB_CSR_PIO_PERR_SHIFT	(40)

/*
 * Bits of Sun5 SBus Asynchronous Fault Status Register
 */
#define	SB_AFSR_P_ERRS	0xE000000000000000ULL /* primary errors */
#define	SB_AFSR_P_LE	0x8000000000000000ULL /* primary LATE_ERR */
#define	SB_AFSR_P_TO	0x4000000000000000ULL /* primary SBus TIMEOUT */
#define	SB_AFSR_P_BERR	0x2000000000000000ULL /* primary SBus ERR ack */
#define	SB_AFSR_S_ERRS	0x1C00000000000000ULL /* secondary errors */
#define	SB_AFSR_S_LE	0x1000000000000000ULL /* secondary LATE_ERR */
#define	SB_AFSR_S_TO	0x0800000000000000ULL /* secondary SBus TIMEOUT */
#define	SB_AFSR_S_BERR	0x0400000000000000ULL /* secondary SBus ERR ack */
#define	SB_AFSR_RD	0x0000800000000000ULL /* primary error was READ op. */
#define	SB_AFSR_SIZE	0x00001C0000000000ULL /* 2**size of failed transfer */
#define	SB_AFSR_MID	0x000003E000000000ULL /* master ID for primary error */

/*
 * Shifts for Sun5 SBus Asynchronous Fault Status Register
 */
#define	SB_AFSR_SIZE_SHIFT	(42)
#define	SB_AFSR_MID_SHIFT	(37)

/*
 * Bits of Fusion Desktop SBus Asynchronous Fault Address Register
 */
#define	SB_AFAR_PA	0x000001FFFFFFFFFFULL /* PA<40:0>: physical address */

/*
 * Function prototypes
 */
extern int
sysio_err_init(struct sbus_soft_state *softsp, caddr_t address);
extern int
sysio_err_resume_init(struct sbus_soft_state *softsp);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SYSIOERR_H */
