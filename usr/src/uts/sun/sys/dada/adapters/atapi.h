/*
 * Copyright (c) 1996 Sun Microsystems, Inc.  All Rights Reserved.
 */

#ifndef	_ATAPI_H
#define	_ATAPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/scsi/scsi.h>

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
 * ATAPI commands.
 */
#define	ATC_PI_SRESET	0x08    /* ATAPI soft reset			*/
#define	ATC_PI_ID_DEV	0xa1	/* ATAPI identify device		*/
#define	ATC_PI_PKT	0xa0	/* ATAPI packet command 		*/
#define	ATC_PI_SERVICE	0xa2	/* ATAPI overlap service command	*/

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

/*
 * ATAPI SET FEATURE commands
 */
#define	ATAPI_FEAT_RELEASE_INTR		0x5d
#define	ATAPI_FEAT_SERVICE_INTR		0x5e

/*
 * ATAPI bits
 */
#define	ATAPI_SIG_HI	0xeb		/* in high cylinder register	*/
#define	ATAPI_SIG_LO	0x14		/* in low cylinder register	*/

#define	ATAPIDRV(X)  ((X)->ad_flags & AD_ATAPI)
#define	ATAPIPKT(X)  ((X)->ap_flags & AP_ATAPI)

#define	ATAPI_SECTOR_SIZE	2048
#define	ATAPI_MAX_BYTES_PER_DRQ	0xf800 /* 16 bits - 2KB  ie 62KB */
#define	ATAPI_HEADS		64
#define	ATAPI_SECTORS_PER_TRK   32

/*
 * Useful macros
 */
#define	TRAN2CTL(tran)	((struct ata_controller *)((tran)->tran_hba_private))
#define	ADDR2CTL(ap)	(TRAN2CTL(ADDR2TRAN(ap)))

#define	SPKT2APKT(spkt)	(GCMD2APKT(PKTP2GCMDP(spkt)))
#define	APKT2SPKT(apkt)	(GCMDP2PKTP(APKT2GCMD(apkt)))

#define	SADR2CHNO(ap)	(((ap)->a_target > 1) ? 1 : 0)


/*
 * public function prototypes
 */
int atapi_init(struct ata_controller *ata_ctlp);
void atapi_destroy(struct ata_controller *ata_ctlp);
int atapi_init_drive(struct ata_drive *ata_drvp);
void atapi_destroy_drive(struct ata_drive *ata_drvp);

int atapi_id(ddi_acc_handle_t handle, uint8_t *ioaddr, ushort_t *buf);
int atapi_signature(ddi_acc_handle_t handle, uint8_t *ioaddr);

int atapi_reset_drive(struct ata_drive *ata_drvp);

int atapi_ccballoc(gtgt_t  *gtgtp, gcmd_t *gcmdp, int cmdlen,
		int statuslen, int tgtlen, int ccblen);
void atapi_ccbfree(gcmd_t *gcmdp);

#ifdef DSC_OVERLAP_SUPPORT
void atapi_dsc_poll(struct ata_drive *ata_drvp);
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _ATAPI_H */
