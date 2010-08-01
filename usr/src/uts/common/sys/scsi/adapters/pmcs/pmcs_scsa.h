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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * SCSI (SCSA) midlayer interface for PMC drier.
 */
#ifndef _PMCS_SCSA_H
#define	_PMCS_SCSA_H
#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/scsi/scsi_types.h>

#define	ADDR2TRAN(ap)		((ap)->a_hba_tran)
#define	ADDR2PMC(ap)		(ITRAN2PMC(ADDR2TRAN(ap)))

#define	CMD2TRAN(cmd)		(CMD2PKT(cmd)->pkt_address.a_hba_tran)
#define	CMD2PMC(cmd)		(ITRAN2PMC(CMD2TRAN(cmd)))

#define	PKT2ADDR(pkt)		(&((pkt)->pkt_address))
#define	PKT2CMD(pkt)		((pmcs_cmd_t *)(pkt->pkt_ha_private))
#define	CMD2PKT(sp)		(sp->cmd_pkt)
#define	PMCS_STATUS_LEN		264

#define	TRAN2PMC(tran)		((pmcs_hw_t *)(tran)->tran_hba_private)
#define	ITRAN2PMC(tran) \
	(((pmcs_iport_t *)(tran)->tran_hba_private)->pwp)
#define	ITRAN2IPORT(tran) \
	((pmcs_iport_t *)(tran)->tran_hba_private)

/*
 * Wrapper around scsi_pkt.
 */
struct pmcs_cmd {
	struct scsi_pkt		*cmd_pkt;	/* actual SCSI Packet */
	STAILQ_ENTRY(pmcs_cmd)	cmd_next;	/* linked list */
	pmcs_dmachunk_t		*cmd_clist;	/* list of dma chunks */
	pmcs_xscsi_t		*cmd_target;	/* Pointer to target */
	pmcs_lun_t		*cmd_lun;	/* Pointer to LU */
	uint32_t		cmd_tag;	/* PMC htag */
	uint8_t			cmd_satltag;	/* SATL tag */
};

#define	SCSA_CDBLEN(sp)		sp->cmd_pkt->pkt_cdblen
#define	SCSA_STSLEN(sp)		sp->cmd_pkt->pkt_scblen
#define	SCSA_TGTLEN(sp)		sp->cmd_pkt->pkt_tgtlen

#define	PMCS_WQ_RUN_SUCCESS		0
#define	PMCS_WQ_RUN_FAIL_RES		1 /* Failed to alloc rsrcs */
#define	PMCS_WQ_RUN_FAIL_RES_CMP	2 /* Failed rsrcs, but put on the CQ */
#define	PMCS_WQ_RUN_FAIL_OTHER		3 /* Any other failure */

int pmcs_scsa_init(pmcs_hw_t *, const ddi_dma_attr_t *);

void pmcs_latch_status(pmcs_hw_t *, pmcs_cmd_t *, uint8_t, uint8_t *,
    size_t, char *);
size_t pmcs_set_resid(struct scsi_pkt *, size_t, uint32_t);
boolean_t pmcs_scsa_wq_run_one(pmcs_hw_t *, pmcs_xscsi_t *);
void pmcs_scsa_wq_run(pmcs_hw_t *);
void pmcs_scsa_cq_run(void *);

int pmcs_config_one(pmcs_hw_t *, uint64_t, int, long, dev_info_t **);

dev_info_t *pmcs_find_child_smp(pmcs_hw_t *, char *);
int pmcs_config_one_smp(pmcs_hw_t *, uint64_t, dev_info_t **);

int pmcs_run_sata_special(pmcs_hw_t *, pmcs_xscsi_t *);
#ifdef	__cplusplus
}
#endif
#endif	/* _PMCS_SCSA_H */
