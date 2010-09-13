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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ATA_DISK_H
#define	_ATA_DISK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ATA disk commands.
 */

#define	ATC_SEEK	0x70    /* seek cmd, bottom 4 bits step rate 	*/
#define	ATC_RDVER	0x40	/* read verify cmd			*/
#define	ATC_RDSEC	0x20    /* read sector cmd			*/
#define	ATC_RDLONG	0x23    /* read long without retry		*/
#define	ATC_WRSEC	0x30    /* write sector cmd			*/
#define	ATC_SETMULT	0xc6	/* set multiple mode			*/
#define	ATC_RDMULT	0xc4	/* read multiple			*/
#define	ATC_WRMULT	0xc5	/* write multiple			*/
#define	ATC_READ_DMA	0xc8	/* read (multiple) w/DMA		*/
#define	ATC_WRITE_DMA	0xca	/* write (multiple) w/DMA		*/
#define	ATC_SETPARAM	0x91	/* set parameters command 		*/
#define	ATC_ID_DEVICE	0xec    /* IDENTIFY DEVICE command 		*/
#define	ATC_ACK_MC	0xdb	/* acknowledge media change		*/
#define	ATC_LOAD_FW	0x92	/* download microcode			*/
	/* ATA extended (48 bit) disk commands */
#define	ATC_RDSEC_EXT	0x24	/* read sector */
#define	ATC_RDMULT_EXT	0x29	/* read multiple */
#define	ATC_RDDMA_EXT	0x25	/* read DMA */
#define	ATC_WRSEC_EXT	0x34	/* write sector */
#define	ATC_WRMULT_EXT	0x39	/* write multiple */
#define	ATC_WRDMA_EXT	0x35	/* write DMA */

/*
 * Low bits for Read/Write commands...
 */
#define	ATCM_ECCRETRY	0x01    /* Enable ECC and RETRY by controller 	*/
				/* enabled if bit is CLEARED!!! 	*/
#define	ATCM_LONGMODE	0x02    /* Use Long Mode (get/send data & ECC) 	*/

/*
 * subcommand for DOWNLOAD MICROCODE command
 */
#define	ATCM_FW_TEMP		0x01 /* immediate, temporary use	*/
#define	ATCM_FW_MULTICMD	0x03 /* immediate and future use	*/
#define	ATCM_FW_PERM		0x07 /* immediate and future use	*/

#ifdef  DADKIO_RWCMD_READ
#define	RWCMDP(pktp)  ((struct dadkio_rwcmd *)((pktp)->cp_bp->b_back))
#endif

/* useful macros */

#define	CPKT2GCMD(cpkt)	((gcmd_t *)(cpkt)->cp_ctl_private)
#define	CPKT2APKT(cpkt)  (GCMD2APKT(CPKT2GCMD(cpkt)))

#define	GCMD2CPKT(cmdp)	((struct cmpkt *)((cmdp)->cmd_pktp))
#define	APKT2CPKT(apkt) (GCMD2CPKT(APKT2GCMD(apkt)))

/* public function prototypes */

int	ata_disk_attach(ata_ctl_t *ata_ctlp);
void	ata_disk_detach(ata_ctl_t *ata_ctlp);
int	ata_disk_init_drive(ata_drv_t *ata_drvp);
void	ata_disk_uninit_drive(ata_drv_t *ata_drvp);
int	ata_disk_id(ddi_acc_handle_t io_hdl1, caddr_t ioaddr1,
		ddi_acc_handle_t io_hdl2, caddr_t ioaddr2,
		struct ata_id *ata_idp);
int	ata_disk_bus_ctl(dev_info_t *d, dev_info_t *r, ddi_ctl_enum_t o,
		void *a, void *v);
int	ata_disk_setup_parms(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp);

#ifdef	__cplusplus
}
#endif

#endif /* _ATA_DISK_H */
