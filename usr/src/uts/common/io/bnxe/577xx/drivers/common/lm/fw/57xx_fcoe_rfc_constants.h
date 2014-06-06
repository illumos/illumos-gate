#ifndef __57XX_FCOE_RFC_CONSTANTS_H_
#define __57XX_FCOE_RFC_CONSTANTS_H_

/**
* This file defines FCoE RFC constants
*/


/* Frame Header type constants */

#define FC_TYPE_BLS	0x00	/* basic link service */
#define FC_TYPE_ELS	0x01	/* extended link service */
#define FC_TYPE_IP 	0x05	/* IP over FC, RFC 4338 */
#define FC_TYPE_FCP	0x08	/* SCSI FCP */
#define FC_TYPE_CT 	0x20	/* Fibre Channel Services (FC-CT) */
#define FC_TYPE_ILS	0x22	/* internal link service */


/* Frame Header R_CTL constants */

/* routing */
#define FC_RCTL_DDF				0x0	/* device data frames */
#define FC_RCTL_ELS				0x2	/* extended link services */
#define FC_RCTL_FC4_DATA		0x3	/* FC-4 Link Data */
#define FC_RCTL_BLS				0x8	/* basic link services */
#define FC_RCTL_LCF				0xc	/* link control frame */

/* info */
/* device data frames */
#define FC_RCTL_DDF_UNCAT		0x0	/* uncategorized information */
#define FC_RCTL_DDF_SOL_DATA	0x1	/* solicited data */
#define FC_RCTL_DDF_UNSOL_CTL	0x2	/* unsolicited control */
#define FC_RCTL_DDF_SOL_CTL		0x3	/* solicited control or reply */
#define FC_RCTL_DDF_UNSOL_DATA	0x4	/* unsolicited data */
#define FC_RCTL_DDF_DATA_DESC	0x5	/* data descriptor */
#define FC_RCTL_DDF_UNSOL_CMD	0x6	/* unsolicited command */
#define FC_RCTL_DDF_CMD_STATUS	0x7	/* command status */
/* Extended Link services */
#define FC_RCTL_ELS_REQ			0x2	/* extended link services request */
#define FC_RCTL_ELS_REP			0x3	/* extended link services reply */
/* Basic Link Services */
#define FC_RCTL_BLS_NOP			0x0	/* basic link service NOP */
#define FC_RCTL_BLS_ABTS		0x1	/* basic link service abort */
#define FC_RCTL_BLS_RMC			0x2	/* remove connection */
#define FC_RCTL_BLS_ACC			0x4	/* basic accept */
#define FC_RCTL_BLS_RJT			0x5	/* basic reject */
#define FC_RCTL_BLS_PRMT		0x6	/* dedicated connection preempted */
/* Link Control Information */
#define FC_RCTL_LCF_ACK_1 		0x0	/* acknowledge_1 */
#define FC_RCTL_LCF_ACK_0 		0x1	/* acknowledge_0 */
#define FC_RCTL_LCF_P_RJT 		0x2	/* port reject */
#define FC_RCTL_LCF_F_RJT 		0x3	/* fabric reject */
#define FC_RCTL_LCF_P_BSY 		0x4	/* port busy */
#define FC_RCTL_LCF_F_BSY 		0x5	/* fabric busy to data frame */
#define FC_RCTL_LCF_F_BSYL		0x6	/* fabric busy to link control frame */
#define FC_RCTL_LCF_LCR			0x7	/* link credit reset */
#define FC_RCTL_LCF_END			0x9	/* end */


/* Frame Header F_CTL constants */

/* exchange context */
#define	FC_FCTL_EX_CTX_SHIFT		23
#define	FC_FCTL_EX_CTX_MASK			(0x1 << FC_FCTL_EX_CTX_SHIFT)
#define	FC_FCTL_EX_CTX_ORIGINATOR	(0x0 << FC_FCTL_EX_CTX_SHIFT)
#define	FC_FCTL_EX_CTX_RESPONDER	(0x1 << FC_FCTL_EX_CTX_SHIFT)
/* sequence context */
#define	FC_FCTL_SEQ_CTX_SHIFT		22
#define	FC_FCTL_SEQ_CTX_MASK		(0x1 << FC_FCTL_SEQ_CTX_SHIFT)
#define	FC_FCTL_SEQ_CTX_INITIATOR	(0x0 << FC_FCTL_SEQ_CTX_SHIFT)
#define	FC_FCTL_SEQ_CTX_RECIPIENT	(0x1 << FC_FCTL_SEQ_CTX_SHIFT)
/* first sequence of exchange */
#define	FC_FCTL_FIRST_SEQ_SHIFT		21
#define	FC_FCTL_FIRST_SEQ_MASK		(0x1 << FC_FCTL_FIRST_SEQ_SHIFT)
#define	FC_FCTL_FIRST_SEQ_FALSE		(0x0 << FC_FCTL_FIRST_SEQ_SHIFT)
#define	FC_FCTL_FIRST_SEQ_TRUE		(0x1 << FC_FCTL_FIRST_SEQ_SHIFT)
/* last sequence of exchange */
#define	FC_FCTL_LAST_SEQ_SHIFT		20
#define	FC_FCTL_LAST_SEQ_MASK		(0x1 << FC_FCTL_LAST_SEQ_SHIFT)
#define	FC_FCTL_LAST_SEQ_FALSE		(0x0 << FC_FCTL_LAST_SEQ_SHIFT)
#define	FC_FCTL_LAST_SEQ_TRUE		(0x1 << FC_FCTL_LAST_SEQ_SHIFT)
/* last frame of sequence */
#define	FC_FCTL_END_SEQ_SHIFT		19
#define	FC_FCTL_END_SEQ_MASK		(0x1 << FC_FCTL_END_SEQ_SHIFT)
#define	FC_FCTL_END_SEQ_FALSE		(0x0 << FC_FCTL_END_SEQ_SHIFT)
#define	FC_FCTL_END_SEQ_TRUE		(0x1 << FC_FCTL_END_SEQ_SHIFT)
/* CS_CTL/priority enable */
#define	FC_FCTL_PRI_ENABLE_SHIFT	17
#define	FC_FCTL_PRI_ENABLE_MASK		(0x1 << FC_FCTL_PRI_ENABLE_SHIFT)
#define	FC_FCTL_PRI_ENABLE_FALSE	(0x0 << FC_FCTL_PRI_ENABLE_SHIFT)
#define	FC_FCTL_PRI_ENABLE_TRUE		(0x1 << FC_FCTL_PRI_ENABLE_SHIFT)
/* sequence initiative */
#define	FC_FCTL_SEQ_INIT_SHIFT		16
#define	FC_FCTL_SEQ_INIT_MASK		(0x1 << FC_FCTL_SEQ_INIT_SHIFT)
#define	FC_FCTL_SEQ_INIT_HOLD		(0x0 << FC_FCTL_SEQ_INIT_SHIFT)
#define	FC_FCTL_SEQ_INIT_TRANSFER	(0x1 << FC_FCTL_SEQ_INIT_SHIFT)
/* ack form */
#define	FC_FCTL_ACK_SHIFT			12
#define	FC_FCTL_ACK_MASK			(0x3 << FC_FCTL_ACK_SHIFT)
#define FC_FCTL_ACK_NONE			(0x0 << FC_FCTL_ACK_SHIFT)
#define FC_FCTL_ACK_1				(0x1 << FC_FCTL_ACK_SHIFT)
#define FC_FCTL_ACK_0				(0x3 << FC_FCTL_ACK_SHIFT)
/* retransmitted sequence */
#define	FC_FCTL_RETX_SEQ_SHIFT		9
#define	FC_FCTL_RETX_SEQ_MASK		(0x1 << FC_FCTL_RETX_SEQ_SHIFT)
#define FC_FCTL_RETX_SEQ_FALSE		(0x0 << FC_FCTL_RETX_SEQ_SHIFT)
#define FC_FCTL_RETX_SEQ_TRUE		(0x1 << FC_FCTL_RETX_SEQ_SHIFT)
/* abort sequence condition */
#define	FC_FCTL_ABT_SEQ_SHIFT				4
#define	FC_FCTL_ABT_SEQ_MASK				(0x2 << FC_FCTL_ABT_SEQ_SHIFT)
#define	FC_FCTL_ABT_SEQ_DISCARD_MULT		(0x0 << FC_FCTL_ABT_SEQ_SHIFT)
#define	FC_FCTL_ABT_SEQ_DISCARD_SINGLE		(0x1 << FC_FCTL_ABT_SEQ_SHIFT)
#define	FC_FCTL_ABT_SEQ_PROCESS_POLICY		(0x2 << FC_FCTL_ABT_SEQ_SHIFT)
#define	FC_FCTL_ABT_SEQ_DISCARD_MULT_RETX	(0x3 << FC_FCTL_ABT_SEQ_SHIFT)
/* relative offset */
#define	FC_FCTL_REL_OFF_SHIFT		3
#define	FC_FCTL_REL_OFF_MASK		(0x1 << FC_FCTL_REL_OFF_SHIFT)
#define FC_FCTL_REL_OFF_FALSE		(0x0 << FC_FCTL_REL_OFF_SHIFT)
#define FC_FCTL_REL_OFF_TRUE		(0x1 << FC_FCTL_REL_OFF_SHIFT)
/* bytes of trailing fill */
#define	FC_FCTL_FILL_SHIFT			0
#define	FC_FCTL_FILL_MASK			(0x3 << FC_FCTL_FILL_SHIFT)
#define	FC_FCTL_FILL_0_BYTES		(0x0 << FC_FCTL_FILL_SHIFT)
#define	FC_FCTL_FILL_1_BYTES		(0x1 << FC_FCTL_FILL_SHIFT)
#define	FC_FCTL_FILL_2_BYTES		(0x2 << FC_FCTL_FILL_SHIFT)
#define	FC_FCTL_FILL_3_BYTES		(0x3 << FC_FCTL_FILL_SHIFT)


/* SOF / EOF bytes */
#define FC_SOF_F	0x28   /* fabric */
#define FC_SOF_I4	0x29   /* initiate class 4 */
#define FC_SOF_I2	0x2d   /* initiate class 2 */
#define FC_SOF_I3	0x2e   /* initiate class 3 */
#define FC_SOF_N4	0x31   /* normal class 4 */
#define FC_SOF_N2	0x35   /* normal class 2 */
#define FC_SOF_N3	0x36   /* normal class 3 */
#define FC_SOF_C4	0x39   /* activate class 4 */
#define FC_EOF_N	0x41   /* normal (not last frame of seq) */
#define FC_EOF_T	0x42   /* terminate (last frame of sequence) */
#define FC_EOF_RT	0x44
#define FC_EOF_DT	0x46   /* disconnect-terminate class-1 */
#define FC_EOF_NI	0x49   /* normal-invalid */
#define FC_EOF_DTI	0x4e   /* disconnect-terminate-invalid */
#define FC_EOF_RTI	0x4f
#define FC_EOF_A	0x50   /* abort */


/* ELS Command codes - byte 0 of the frame payload */
#define	FC_ELS_CMD_LS_RJT		0x01	/* ESL reject */
#define	FC_ELS_CMD_LS_ACC		0x02	/* ESL Accept */
#define	FC_ELS_CMD_PLOGI		0x03	/* N_Port login */
#define	FC_ELS_CMD_FLOGI		0x04	/* F_Port login */
#define	FC_ELS_CMD_LOGO			0x05	/* Logout */
#define	FC_ELS_CMD_ABTX			0x06	/* Abort exchange - obsolete */
#define	FC_ELS_CMD_RCS			0x07	/* read connection status */
#define	FC_ELS_CMD_RES			0x08	/* read exchange status block */
#define	FC_ELS_CMD_RSS			0x09	/* read sequence status block */
#define	FC_ELS_CMD_RSI			0x0a	/* read sequence initiative */
#define	FC_ELS_CMD_ESTS			0x0b	/* establish streaming */
#define	FC_ELS_CMD_ESTC			0x0c	/* estimate credit */
#define	FC_ELS_CMD_ADVC			0x0d	/* advise credit */
#define	FC_ELS_CMD_RTV			0x0e	/* read timeout value */
#define	FC_ELS_CMD_RLS			0x0f	/* read link error status block */
#define	FC_ELS_CMD_ECHO			0x10	/* echo */
#define	FC_ELS_CMD_TEST			0x11	/* test */
#define	FC_ELS_CMD_RRQ			0x12	/* reinstate recovery qualifier */
#define	FC_ELS_CMD_REC			0x13	/* read exchange concise */
#define	FC_ELS_CMD_PRLI			0x20	/* process login */
#define	FC_ELS_CMD_PRLO			0x21	/* process logout */
#define	FC_ELS_CMD_SCN			0x22	/* state change notification */
#define	FC_ELS_CMD_TPLS			0x23	/* test process login state */
#define	FC_ELS_CMD_TPRLO		0x24	/* third party process logout */
#define	FC_ELS_CMD_LCLM			0x25	/* login control list mgmt (obs) */
#define	FC_ELS_CMD_GAID			0x30	/* get alias_ID */
#define	FC_ELS_CMD_FACT			0x31	/* fabric activate alias_id */
#define	FC_ELS_CMD_FDACDT		0x32	/* fabric deactivate alias_id */
#define	FC_ELS_CMD_NACT			0x33	/* N-port activate alias_id */
#define	FC_ELS_CMD_NDACT		0x34	/* N-port deactivate alias_id */
#define	FC_ELS_CMD_QOSR			0x40	/* quality of service request */
#define	FC_ELS_CMD_RVCS			0x41	/* read virtual circuit status */
#define	FC_ELS_CMD_PDISC		0x50	/* discover N_port service params */
#define	FC_ELS_CMD_FDISC		0x51	/* discover F_port service params */
#define	FC_ELS_CMD_ADISC		0x52	/* discover address */
#define	FC_ELS_CMD_RNC			0x53	/* report node cap (obs) */
#define	FC_ELS_CMD_FARP_REQ		0x54	/* FC ARP request */
#define	FC_ELS_CMD_FARP_REPL	0x55	/* FC ARP reply */
#define	FC_ELS_CMD_RPS			0x56	/* read port status block */
#define	FC_ELS_CMD_RPL			0x57	/* read port list */
#define	FC_ELS_CMD_RPBC			0x58	/* read port buffer condition */
#define	FC_ELS_CMD_FAN			0x60	/* fabric address notification */
#define	FC_ELS_CMD_RSCN			0x61	/* registered state change notification */
#define	FC_ELS_CMD_SCR			0x62	/* state change registration */
#define	FC_ELS_CMD_RNFT			0x63	/* report node FC-4 types */
#define	FC_ELS_CMD_CSR			0x68	/* clock synch. request */
#define	FC_ELS_CMD_CSU			0x69	/* clock synch. update */
#define	FC_ELS_CMD_LINIT		0x70	/* loop initialize */
#define	FC_ELS_CMD_LSTS			0x72	/* loop status */
#define	FC_ELS_CMD_RNID			0x78	/* request node ID data */
#define	FC_ELS_CMD_RLIR			0x79	/* registered link incident report */
#define	FC_ELS_CMD_LIRR			0x7a	/* link incident record registration */
#define	FC_ELS_CMD_SRL			0x7b	/* scan remote loop */
#define	FC_ELS_CMD_SBRP			0x7c	/* set bit-error reporting params */
#define	FC_ELS_CMD_RPSC			0x7d	/* report speed capabilities */
#define	FC_ELS_CMD_QSA			0x7e	/* query security attributes */
#define	FC_ELS_CMD_EVFP			0x7f	/* exchange virt. fabrics params */
#define	FC_ELS_CMD_LKA			0x80	/* link keep-alive */
#define	FC_ELS_CMD_AUTH_ELS		0x90	/* authentication ELS */

#endif /*__57XX_FCOE_RFC_CONSTANTS_H_ */
