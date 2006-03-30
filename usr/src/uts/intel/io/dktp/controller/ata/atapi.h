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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ATAPI_H
#define	_ATAPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Additional atapi status bits (redefinitions)
 */
#define	ATE_ILI		0x01    /* Illegal length indication		*/
#define	ATE_EOM		0x02	/* End of media detected		*/
#define	ATE_MCR		0x08	/* Media change requested		*/
#define	ATS_SERVICE	0x10	/* overlap operation needs service	*/
#define	ATS_SENSE_KEY	0xf0	/* 4 bit sense key -see ata_sense_table */

#define	ATS_SENSE_KEY_SHIFT 4	/* shift to get to ATS_SENSE_KEY	*/

/*
 * Status bits from ATAPI Interrupt reason register (AT_COUNT) register
 */
#define	ATI_COD		0x01    /* Command or Data			*/
#define	ATI_IO		0x02    /* IO direction 			*/
#define	ATI_RELEASE	0x04	/* Release for ATAPI overlap		*/

/* ATAPI feature reg definitions */

#define	ATF_OVERLAP	0x02

/*
 * ATAPI IDENTIFY_DRIVE configuration word
 */

#define	ATAPI_ID_CFG_PKT_SZ   0x3
#define	ATAPI_ID_CFG_PKT_12B  0x0
#define	ATAPI_ID_CFG_PKT_16B  0x1
#define	ATAPI_ID_CFG_DRQ_TYPE 0x60
#define	ATAPI_ID_CFG_DRQ_INTR 0x20
#define	ATAPI_ID_CFG_DEV_TYPE 0x0f00
#define	ATAPI_ID_CFG_DEV_SHFT 8

/*
 * ATAPI IDENTIFY_DRIVE capabilities word
 */

#define	ATAPI_ID_CAP_DMA	0x0100
#define	ATAPI_ID_CAP_OVERLAP	0x2000

/* ATAPI SET FEATURE commands */

#define	ATAPI_FEAT_RELEASE_INTR		0x5d
#define	ATAPI_FEAT_SERVICE_INTR		0x5e

/*
 * ATAPI bits
 */
#define	ATAPI_SIG_HI	0xeb		/* in high cylinder register	*/
#define	ATAPI_SIG_LO	0x14		/* in low cylinder register	*/


#define	ATAPI_SECTOR_SIZE	2048
#define	ATAPI_MAX_BYTES_PER_DRQ	0xf800 /* 16 bits - 2KB  ie 62KB */
#define	ATAPI_HEADS		64
#define	ATAPI_SECTORS_PER_TRK   32

/* Useful macros */

#define	TRAN2CTL(tran)  ((ata_ctl_t *)((tran)->tran_hba_private))
#define	ADDR2CTL(ap)    (TRAN2CTL(ADDR2TRAN(ap)))

#define	SPKT2APKT(spkt)	(GCMD2APKT(PKTP2GCMDP(spkt)))
#define	APKT2SPKT(apkt)	(GCMDP2PKTP(APKT2GCMD(apkt)))

/* public function prototypes */

int	atapi_attach(ata_ctl_t *ata_ctlp);
void	atapi_detach(ata_ctl_t *ata_ctlp);
void	atapi_init_arq(ata_ctl_t *ata_ctlp);
int	atapi_init_drive(ata_drv_t *ata_drvp);
void	atapi_uninit_drive(ata_drv_t *ata_drvp);

int	atapi_id(ddi_acc_handle_t io_hdl1, caddr_t ioaddr1,
		ddi_acc_handle_t io_hdl2, caddr_t ioaddr2, struct ata_id *buf);
int	atapi_signature(ddi_acc_handle_t io_hdl, caddr_t ioaddr);

int	atapi_ccballoc(gtgt_t *gtgtp, gcmd_t *gcmdp, int cmdlen,
		int statuslen, int tgtlen, int ccblen);
void	atapi_ccbfree(gcmd_t *gcmdp);


int	atapi_fsm_intr(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
		ata_pkt_t *ata_pktp);
int	atapi_fsm_start(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
		ata_pkt_t *ata_pktp);
void	atapi_fsm_reset(ata_ctl_t *ata_ctlp);



#ifdef	__cplusplus
}
#endif

#endif /* _ATAPI_H */
