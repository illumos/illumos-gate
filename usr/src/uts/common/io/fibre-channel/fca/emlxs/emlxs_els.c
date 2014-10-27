/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#include <emlxs.h>

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_ELS_C);

static void	emlxs_handle_sol_flogi(emlxs_port_t *port, emlxs_buf_t *sbp);
static void	emlxs_handle_sol_fdisc(emlxs_port_t *port, emlxs_buf_t *sbp);
static void	emlxs_handle_sol_plogi(emlxs_port_t *port, emlxs_buf_t *sbp);
static void	emlxs_handle_sol_adisc(emlxs_port_t *port, emlxs_buf_t *sbp);
static void	emlxs_handle_sol_logo(emlxs_port_t *port, emlxs_buf_t *sbp);
static void	emlxs_handle_sol_prli(emlxs_port_t *port, emlxs_buf_t *sbp);

static void	emlxs_handle_unsol_rscn(emlxs_port_t *port, CHANNEL *cp,
			IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
static void	emlxs_handle_unsol_flogi(emlxs_port_t *port, CHANNEL *cp,
			IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
static void	emlxs_handle_unsol_plogi(emlxs_port_t *port, CHANNEL *cp,
			IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
static void	emlxs_handle_unsol_logo(emlxs_port_t *port, CHANNEL *cp,
			IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
static void	emlxs_handle_unsol_adisc(emlxs_port_t *port, CHANNEL *cp,
			IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
static void	emlxs_handle_unsol_prli(emlxs_port_t *port, CHANNEL *cp,
			IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
static void	emlxs_handle_unsol_prlo(emlxs_port_t *port, CHANNEL *cp,
			IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
static void	emlxs_handle_unsol_auth(emlxs_port_t *port, CHANNEL *cp,
			IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
static void	emlxs_handle_unsol_gen_cmd(emlxs_port_t *port, CHANNEL *cp,
			IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
static void	emlxs_handle_unsol_echo(emlxs_port_t *port, CHANNEL *cp,
			IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
static void	emlxs_handle_unsol_rtv(emlxs_port_t *port, CHANNEL *cp,
			IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
static void	emlxs_handle_unsol_rls(emlxs_port_t *port, CHANNEL *cp,
			IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
static void	emlxs_handle_acc(emlxs_port_t *port, emlxs_buf_t *sbp,
			IOCBQ *iocbq, uint32_t flag);
static void	emlxs_handle_reject(emlxs_port_t *port, emlxs_buf_t *sbp,
			IOCBQ *iocbq, uint32_t flag);

#if (EMLXS_MODREV < EMLXS_MODREV4)
static void	emlxs_send_rsnn(emlxs_port_t *port);

#endif /* < EMLXS_MODREV4 */



/* Routine Declaration - Local */
/* End Routine Declaration - Local */

/*
 *  emlxs_els_handle_event
 *
 *  Description: Process an ELS Response Ring cmpl
 *
 */
extern int
emlxs_els_handle_event(emlxs_hba_t *hba, CHANNEL *cp, IOCBQ *iocbq)
{
	emlxs_port_t *port = &PPORT;
	IOCB *iocb;
	emlxs_buf_t *sbp;
	fc_packet_t *pkt;
	uint32_t *lp0;
	uint32_t command;
	NODELIST *ndlp;
	uint32_t did;
	ELS_PKT *els;

	iocb = &iocbq->iocb;

	HBASTATS.ElsEvent++;

	sbp = (emlxs_buf_t *)iocbq->sbp;

	if (!sbp) {
		/*
		 * completion with missing xmit command
		 */
		HBASTATS.ElsStray++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_stray_els_completion_msg,
		    "iocbq=%p cmd=0x%x iotag=0x%x status=0x%x perr=0x%x",
		    iocbq, (uint32_t)iocb->ULPCOMMAND,
		    (uint32_t)iocb->ULPIOTAG, iocb->ULPSTATUS,
		    iocb->un.ulpWord[4]);

		return (1);
	}

	if (cp->channelno != hba->channel_els) {
		HBASTATS.ElsStray++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_stray_els_completion_msg,
		    "Not ELS channel: channel=%d iocbq=%p cmd=0x%x iotag=0x%x "
		    "status=0x%x perr=0x%x", cp->channelno, iocbq,
		    (uint32_t)iocb->ULPCOMMAND, (uint32_t)iocb->ULPIOTAG,
		    iocb->ULPSTATUS, iocb->un.ulpWord[4]);

		return (1);
	}

	port = sbp->iocbq.port;
	pkt = PRIV2PKT(sbp);
	lp0 = (uint32_t *)pkt->pkt_cmd;
	command = *lp0 & ELS_CMD_MASK;
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);

	/* Check if a response buffer was provided */
	if (pkt->pkt_rsplen) {
		EMLXS_MPDATA_SYNC(pkt->pkt_resp_dma, 0, pkt->pkt_rsplen,
		    DDI_DMA_SYNC_FORKERNEL);
	}

	switch (iocb->ULPCOMMAND) {
		/*
		 * ELS Reply completion
		 */
	case CMD_XMIT_ELS_RSP_CX:
	case CMD_XMIT_ELS_RSP64_CX:

		HBASTATS.ElsRspCompleted++;

		if (command == ELS_CMD_ACC) {
			emlxs_handle_acc(port, sbp, iocbq, 1);
		} else {
			emlxs_handle_reject(port, sbp, iocbq, 1);
		}

		break;

		/*
		 * ELS command completion
		 */
	case CMD_ELS_REQUEST_CR:
	case CMD_ELS_REQUEST64_CR:
	case CMD_ELS_REQUEST_CX:
	case CMD_ELS_REQUEST64_CX:

		HBASTATS.ElsCmdCompleted++;

		sbp->pkt_flags |= PACKET_ELS_RSP_VALID;

		els = (ELS_PKT *)pkt->pkt_resp;

		pkt->pkt_resp_resid =
		    pkt->pkt_rsplen - iocb->un.elsreq64.bdl.bdeSize;
		pkt->pkt_data_resid = pkt->pkt_datalen;

		pkt->pkt_resp_fhdr.d_id = pkt->pkt_cmd_fhdr.s_id;
		pkt->pkt_resp_fhdr.s_id = pkt->pkt_cmd_fhdr.d_id;

		if ((iocb->ULPSTATUS == 0) && (els->elsCode == 0x02)) {
			HBASTATS.ElsCmdGood++;

			if (!(sbp->pkt_flags & PACKET_ALLOCATED)) {
				/*
				 * ULP patch - ULP expects
				 * resp_resid = 0 on success
				 */
				pkt->pkt_resp_resid = 0;
			}

			switch (command) {
			case ELS_CMD_FDISC:	/* Fabric login */
				emlxs_handle_sol_fdisc(port, sbp);

				break;

			case ELS_CMD_FLOGI:	/* Fabric login */
				emlxs_handle_sol_flogi(port, sbp);

				break;

			case ELS_CMD_PLOGI:	/* NPort login */
				emlxs_handle_sol_plogi(port, sbp);

				break;

			case ELS_CMD_ADISC:	/* Adisc */
				emlxs_handle_sol_adisc(port, sbp);

				break;

			case ELS_CMD_LOGO:	/* Logout */
				emlxs_handle_sol_logo(port, sbp);

				break;

			case ELS_CMD_PRLI:	/* Process Log In */
				emlxs_handle_sol_prli(port, sbp);

				break;

			default:
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_els_completion_msg, "%s: did=%x",
				    emlxs_elscmd_xlate(command), did);

				emlxs_pkt_complete(sbp, IOSTAT_SUCCESS, 0, 1);

				break;
			}

		} else {
			HBASTATS.ElsCmdError++;

			/* Look for LS_REJECT */
			if (iocb->ULPSTATUS == IOSTAT_LS_RJT) {
				pkt->pkt_state = FC_PKT_LS_RJT;
				pkt->pkt_action = FC_ACTION_RETRYABLE;
				pkt->pkt_reason = iocb->un.grsp.perr.statRsn;
				pkt->pkt_expln = iocb->un.grsp.perr.statBaExp;
				sbp->pkt_flags |= PACKET_STATE_VALID;

#ifdef SAN_DIAG_SUPPORT
				ndlp = emlxs_node_find_did(port, did, 1);
				if (ndlp) {
					emlxs_log_sd_lsrjt_event(port,
					    (HBA_WWN *)&ndlp->nlp_portname,
					    command, pkt->pkt_reason,
					    pkt->pkt_expln);
				}
#endif

				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_els_completion_msg,
				    "%s Rejected: did=%x rsn=%x exp=%x",
				    emlxs_elscmd_xlate(command), did,
				    pkt->pkt_reason, pkt->pkt_expln);
			} else if (iocb->ULPSTATUS == IOSTAT_LOCAL_REJECT) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_bad_els_completion_msg,
				    "%s: did=%x Local Reject. %s",
				    emlxs_elscmd_xlate(command), did,
				    emlxs_error_xlate(iocb->un.grsp.perr.
				    statLocalError));
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_bad_els_completion_msg,
				    "%s: did=%x %s (%02x%02x%02x%02x)",
				    emlxs_elscmd_xlate(command), did,
				    emlxs_state_xlate(iocb->ULPSTATUS),
				    iocb->un.grsp.perr.statAction,
				    iocb->un.grsp.perr.statRsn,
				    iocb->un.grsp.perr.statBaExp,
				    iocb->un.grsp.perr.statLocalError);
			}

			switch (command) {
			case ELS_CMD_PLOGI:	/* NPort login failed */
				ndlp = emlxs_node_find_did(port, did, 1);

				if (ndlp && ndlp->nlp_active) {
					/* Open the node again */
					emlxs_node_open(port, ndlp,
					    hba->channel_fcp);
					emlxs_node_open(port, ndlp,
					    hba->channel_ip);
#ifdef DHCHAP_SUPPORT
					if (pkt->pkt_state == FC_PKT_LS_RJT) {
						emlxs_dhc_state(port, ndlp,
						    NODE_STATE_NOCHANGE,
						    pkt->pkt_reason,
						    pkt->pkt_expln);
					}
#endif /*  DHCHAP_SUPPORT */
				}

				break;


			case ELS_CMD_PRLI:	/* Process Log In failed */
				ndlp = emlxs_node_find_did(port, did, 1);

				if (ndlp && ndlp->nlp_active) {
					/* Open the node again */
					emlxs_node_open(port, ndlp,
					    hba->channel_fcp);
				}

				break;

			case ELS_CMD_FDISC:	/* Fabric login */
			case ELS_CMD_FLOGI:	/* Fabric login */
				if (pkt->pkt_state == FC_PKT_LS_RJT) {
					/* This will cause ULP to retry */
					/* FLOGI requests */
					pkt->pkt_reason = FC_REASON_QFULL;
					pkt->pkt_expln = 0;

#ifdef DHCHAP_SUPPORT
					ndlp = emlxs_node_find_did(port,
					    did, 1);
					if (ndlp && ndlp->nlp_active) {
						emlxs_dhc_state(port, ndlp,
						    NODE_STATE_NOCHANGE,
						    pkt->pkt_reason,
						    pkt->pkt_expln);
					}
#endif /*  DHCHAP_SUPPORT */
				}

				if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
					/* Preset the state for deferred cmpl */
					emlxs_set_pkt_state(sbp,
					    iocb->ULPSTATUS,
					    iocb->un.grsp.perr.statLocalError,
					    1);

					if (emlxs_vpi_logi_failed_notify(
					    sbp->port, sbp) == 0) {
						/* Defer completion */
						return (0);
					}
				}

				break;

			default:
				break;
			}

			emlxs_pkt_complete(sbp, iocb->ULPSTATUS,
			    iocb->un.grsp.perr.statLocalError, 1);
		}

		break;

	default:

		HBASTATS.ElsStray++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_invalid_els_msg,
		    "Invalid iocb: cmd=0x%x", iocb->ULPCOMMAND);

		emlxs_pkt_complete(sbp, iocb->ULPSTATUS,
		    iocb->un.grsp.perr.statLocalError, 1);

		break;
	}	/* switch(iocb->ULPCOMMAND) */

	return (0);

} /* emlxs_els_handle_event() */


extern int
emlxs_els_handle_unsol_req(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	emlxs_hba_t *hba = HBA;
	uint32_t cmd_code;
	IOCB *iocb;

	HBASTATS.ElsCmdReceived++;

	iocb = &iocbq->iocb;
	cmd_code = *((uint32_t *)mp->virt) & ELS_CMD_MASK;

	if (!(port->flag & EMLXS_PORT_BOUND)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "%s: sid=%x. Port not bound: Rejecting.",
		    emlxs_elscmd_xlate(cmd_code),
		    iocbq->iocb.un.elsreq.remoteID);

		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT,
		    cmd_code, LSRJT_LOGICAL_BSY, LSEXP_OUT_OF_RESOURCE);

		return (0);
	}

	switch (cmd_code) {
	case ELS_CMD_RSCN:
		HBASTATS.ElsRscnReceived++;
		emlxs_handle_unsol_rscn(port, cp, iocbq, mp, size);
		break;

	case ELS_CMD_FLOGI:
		HBASTATS.ElsFlogiReceived++;
		emlxs_handle_unsol_flogi(port, cp, iocbq, mp, size);
		break;

	case ELS_CMD_PLOGI:
		HBASTATS.ElsPlogiReceived++;
		emlxs_handle_unsol_plogi(port, cp, iocbq, mp, size);
		break;

	case ELS_CMD_PRLI:
		HBASTATS.ElsPrliReceived++;
		emlxs_handle_unsol_prli(port, cp, iocbq, mp, size);
		break;

	case ELS_CMD_PRLO:
		HBASTATS.ElsPrloReceived++;
		emlxs_handle_unsol_prlo(port, cp, iocbq, mp, size);
		break;

	case ELS_CMD_LOGO:
		HBASTATS.ElsLogoReceived++;
		emlxs_handle_unsol_logo(port, cp, iocbq, mp, size);
		break;

	case ELS_CMD_ADISC:
		HBASTATS.ElsAdiscReceived++;
		emlxs_handle_unsol_adisc(port, cp, iocbq, mp, size);
		break;

	case ELS_CMD_AUTH:
		HBASTATS.ElsAuthReceived++;
		emlxs_handle_unsol_auth(port, cp, iocbq, mp, size);
		break;

	case ELS_CMD_TEST:
		HBASTATS.ElsTestReceived++;
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "%s: sid=%x. Dropping.",
		    emlxs_elscmd_xlate(cmd_code),
		    iocbq->iocb.un.elsreq.remoteID);

		/* drop it */
		emlxs_close_els_exchange(hba, port, iocb->ULPCONTEXT);
		break;

	case ELS_CMD_ESTC:
		HBASTATS.ElsEstcReceived++;
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "%s: sid=%x. Dropping.",
		    emlxs_elscmd_xlate(cmd_code),
		    iocbq->iocb.un.elsreq.remoteID);

		/* drop it */
		emlxs_close_els_exchange(hba, port, iocb->ULPCONTEXT);
		break;

	case ELS_CMD_FARPR:
		HBASTATS.ElsFarprReceived++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "%s: sid=%x. Dropping.",
		    emlxs_elscmd_xlate(cmd_code),
		    iocbq->iocb.un.elsreq.remoteID);

		/* drop it */
		emlxs_close_els_exchange(hba, port, iocb->ULPCONTEXT);
		break;

	case ELS_CMD_ECHO:
		HBASTATS.ElsEchoReceived++;
		emlxs_handle_unsol_echo(port, cp, iocbq, mp, size);
		break;

	case ELS_CMD_RLS:
		HBASTATS.ElsRlsReceived++;
		emlxs_handle_unsol_rls(port, cp, iocbq, mp, size);
		break;

	case ELS_CMD_RTV:
		HBASTATS.ElsRtvReceived++;
		emlxs_handle_unsol_rtv(port, cp, iocbq, mp, size);
		break;

	case ELS_CMD_ABTX:
	case ELS_CMD_RCS:
	case ELS_CMD_RES:
	case ELS_CMD_RSS:
	case ELS_CMD_RSI:
	case ELS_CMD_ESTS:
	case ELS_CMD_RRQ:
	case ELS_CMD_REC:
		HBASTATS.ElsGenReceived++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "%s: sid=%x. Rejecting.",
		    emlxs_elscmd_xlate(cmd_code),
		    iocbq->iocb.un.elsreq.remoteID);

		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT, cmd_code,
		    LSRJT_CMD_UNSUPPORTED, LSEXP_NOTHING_MORE);
		break;

	default:
		HBASTATS.ElsGenReceived++;
		emlxs_handle_unsol_gen_cmd(port, cp, iocbq, mp, size);
		break;
	}

	return (0);

} /* emlxs_els_handle_unsol_req() */


static uint32_t
emlxs_els_delay_discovery(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t	*hba = HBA;
	emlxs_config_t	*cfg;
	SERV_PARM	*parm;

	cfg = &CFG;
	if (!cfg[CFG_DELAY_DISCOVERY].current) {
		return (0);
	}

	parm = &port->fabric_sparam;
	if (((port->prev_did != port->did) ||
	    bcmp(&port->prev_fabric_sparam.portName,
	    &port->fabric_sparam.portName, 8)) &&
	    !(parm->cmn.CLEAN_ADDRESS_BIT)) {

		/* If this is the first time, check config parameter */
		if (port->prev_did || cfg[CFG_DELAY_DISCOVERY].current == 2) {

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_completion_msg,
			    "Clean Address delay: sid=%x prev=%x RATOV %d",
			    port->did, port->prev_did, hba->fc_ratov);

			port->clean_address_sbp = sbp;
			port->clean_address_timer =
			    hba->timer_tics + hba->fc_ratov;

			return (1);
		}
	}
	return (0);

} /* emlxs_els_delay_discovery() */


static void
emlxs_handle_sol_flogi(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	emlxs_port_t *vport;
	SERV_PARM *sp;
	fc_packet_t *pkt;
	MAILBOXQ *mbox;
	uint32_t did;
	IOCBQ *iocbq;
	IOCB *iocb;
	char buffer[64];
	uint32_t i;
	int rc;
	uint16_t altBbCredit;

	pkt = PRIV2PKT(sbp);
	sp = (SERV_PARM *)((caddr_t)pkt->pkt_resp + sizeof (uint32_t));
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);
	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	mutex_enter(&EMLXS_PORT_LOCK);

	/* Save the fabric service parameters and did */
	bcopy((void *)sp, (void *)&port->fabric_sparam, sizeof (SERV_PARM));

	/* Save E_D_TOV ticks in nanoseconds */
	if (sp->cmn.edtovResolution) {
		hba->fc_edtov = (LE_SWAP32(sp->cmn.e_d_tov) + 999999) / 1000000;
	} else {
		hba->fc_edtov = LE_SWAP32(sp->cmn.e_d_tov);
	}

	/* Save R_A_TOV ticks */
	hba->fc_ratov = (LE_SWAP32(sp->cmn.w2.r_a_tov) + 999) / 1000;

	if (sp->cmn.fPort) {
		hba->flag |= FC_FABRIC_ATTACHED;
		hba->flag &= ~FC_PT_TO_PT;

		port->did = iocb->un.elsreq.myID;
		pkt->pkt_resp_fhdr.s_id = LE_SWAP24_LO(FABRIC_DID);
		pkt->pkt_resp_fhdr.d_id = LE_SWAP24_LO(port->did);

		/*
		 * If we are a N-port connected to a Fabric,
		 * fixup sparam's so logins to devices on remote
		 * loops work.
		 */
		altBbCredit = (hba->topology != TOPOLOGY_LOOP)? 1:0;
		hba->sparam.cmn.altBbCredit = altBbCredit;

		/* Set this bit in all the port sparam copies */
		for (i = 0; i < MAX_VPORTS; i++) {
			vport = &VPORT(i);

			if (!(vport->flag & EMLXS_PORT_BOUND)) {
				continue;
			}

			vport->sparam.cmn.altBbCredit = altBbCredit;
		}

		if (sp->cmn.rspMultipleNPort) {
			hba->flag |= FC_NPIV_SUPPORTED;

			if (cfg[CFG_NPIV_DELAY].current) {
				/*
				 * PATCH: for NPIV support on
				 * Brocade switch firmware 5.10b
				 */
				if ((hba->flag & FC_NPIV_ENABLED) &&
				    ((sp->nodeName.IEEE[0] == 0x00) &&
				    (sp->nodeName.IEEE[1] == 0x05) &&
				    (sp->nodeName.IEEE[2] == 0x1e))) {
					hba->flag |= FC_NPIV_DELAY_REQUIRED;
				}
			}
		} else {
			hba->flag |= FC_NPIV_UNSUPPORTED;
		}

		if (!(hba->flag & FC_NPIV_ENABLED)) {
			(void) strlcpy(buffer, "npiv:Disabled ",
			    sizeof (buffer));
		} else if (hba->flag & FC_NPIV_SUPPORTED) {
			(void) strlcpy(buffer, "npiv:Supported ",
			    sizeof (buffer));
		} else {
			(void) strlcpy(buffer, "npiv:Unsupported ",
			    sizeof (buffer));
		}

#ifdef DHCHAP_SUPPORT
		if (!sp->cmn.fcsp_support) {
			(void) strlcat(buffer, "fcsp:Unsupported",
			    sizeof (buffer));
		} else if (cfg[CFG_AUTH_ENABLE].current &&
		    (port->vpi == 0 || cfg[CFG_AUTH_NPIV].current)) {
			(void) strlcat(buffer, "fcsp:Supported",
			    sizeof (buffer));
		} else {
			(void) strlcat(buffer, "fcsp:Disabled",
			    sizeof (buffer));
		}
#endif /* DHCHAP_SUPPORT */

		mutex_exit(&EMLXS_PORT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_completion_msg,
		    "FLOGI: did=%x sid=%x prev=%x %s",
		    did, port->did, port->prev_did, buffer);

		/* Update our service parms */
		if (hba->sli_mode <= EMLXS_HBA_SLI3_MODE) {
			/* Update our service parms */
			if ((mbox = (MAILBOXQ *)emlxs_mem_get(hba,
			    MEM_MBOX))) {
				emlxs_mb_config_link(hba, mbox);

				rc =  EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbox,
				    MBX_NOWAIT, 0);
				if ((rc != MBX_BUSY) && (rc != MBX_SUCCESS)) {
					emlxs_mem_put(hba, MEM_MBOX,
					    (void *)mbox);
				}
			}
		}

		/* Preset the state for the reg_did */
		emlxs_set_pkt_state(sbp, IOSTAT_SUCCESS, 0, 1);

		if (emlxs_els_delay_discovery(port, sbp)) {
			/* Deferred registration of this pkt until */
			/* Clean Address timeout */
			return;
		}

		if (EMLXS_SLI_REG_DID(port, FABRIC_DID, &port->fabric_sparam,
		    sbp, NULL, NULL) == 0) {
			/* Deferred completion of this pkt until */
			/* login is complete */
			return;
		}

		emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
		    IOERR_NO_RESOURCES, 1);

	} else {	/* No switch */

		hba->flag &= ~FC_FABRIC_ATTACHED;
		hba->flag |= FC_PT_TO_PT;

		hba->flag &= ~FC_NPIV_SUPPORTED;
		(void) strlcpy(buffer, "npiv:Disabled.", sizeof (buffer));

		if (emlxs_wwn_cmp((uint8_t *)&sp->portName,
		    (uint8_t *)&port->wwpn) > 0) {
			(void) strlcat(buffer, " P2P Master.",
			    sizeof (buffer));
		} else {
			(void) strlcat(buffer, " P2P Slave.",
			    sizeof (buffer));
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_completion_msg,
		    "FLOGI: did=%x sid=%x %s", did, port->did, buffer);

		mutex_exit(&EMLXS_PORT_LOCK);

		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			/* Preset the state for the reg_did */
			emlxs_set_pkt_state(sbp, IOSTAT_SUCCESS, 0, 1);

			if (EMLXS_SLI_REG_DID(port, FABRIC_DID,
			    &port->fabric_sparam, sbp, NULL, NULL) == 0) {
				/* Deferred completion of this pkt until */
				/* login is complete */
				return;
			}

			emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
			    IOERR_NO_RESOURCES, 1);

		} else {
			emlxs_pkt_complete(sbp, IOSTAT_SUCCESS, 0, 1);
		}
	}

	return;

} /* emlxs_handle_sol_flogi() */


static void
emlxs_handle_sol_fdisc(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	SERV_PARM *sp;
	fc_packet_t *pkt;
	uint32_t did;
	IOCBQ *iocbq;
	IOCB *iocb;
	char buffer[64];

	pkt = PRIV2PKT(sbp);
	sp = (SERV_PARM *)((caddr_t)pkt->pkt_resp + sizeof (uint32_t));
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);
	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	mutex_enter(&EMLXS_PORT_LOCK);

	/* Save the fabric service parameters and did */
	port->did = iocb->un.elsreq.myID;
	bcopy((void *)sp, (void *)&port->fabric_sparam, sizeof (SERV_PARM));

	pkt->pkt_resp_fhdr.d_id = LE_SWAP24_LO(port->did);

	mutex_exit(&EMLXS_PORT_LOCK);

	buffer[0] = 0;

#ifdef DHCHAP_SUPPORT
	if (!sp->cmn.fcsp_support) {
		(void) strlcat(buffer, "fcsp:Unsupported",
		    sizeof (buffer));
	} else if (cfg[CFG_AUTH_ENABLE].current && cfg[CFG_AUTH_NPIV].current) {
		(void) strlcat(buffer, "fcsp:Supported",
		    sizeof (buffer));
	} else {
		(void) strlcat(buffer, "fcsp:Disabled",
		    sizeof (buffer));
	}
#endif /* DHCHAP_SUPPORT */

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_completion_msg,
	    "FDISC: did=%x sid=%x %s", did, port->did, buffer);

	/* Preset the state for the reg_did */
	emlxs_set_pkt_state(sbp, IOSTAT_SUCCESS, 0, 1);

	if (emlxs_els_delay_discovery(port, sbp)) {
		/* Deferred registration of this pkt until */
		/* Clean Address timeout */
		return;
	}

	if (EMLXS_SLI_REG_DID(port, FABRIC_DID, &port->fabric_sparam, sbp,
	    NULL, NULL) == 0) {
		/*
		 * Deferred completion of this pkt until login is complete
		 */
		return;
	}

	emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT, IOERR_NO_RESOURCES, 1);

	return;

} /* emlxs_handle_sol_fdisc() */


static void
emlxs_handle_sol_plogi(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	SERV_PARM *sp;
	fc_packet_t *pkt;
	uint32_t did;
	uint32_t sid;
	NODELIST *ndlp;
	char buffer[64];

	pkt = PRIV2PKT(sbp);
	sp = (SERV_PARM *)((caddr_t)pkt->pkt_resp + sizeof (uint32_t));
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);
	sid = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.s_id);

	buffer[0] = 0;

#ifdef DHCHAP_SUPPORT
	if (!sp->cmn.fcsp_support) {
		(void) strlcat(buffer, "fcsp:Unsupported",
		    sizeof (buffer));
	} else if (cfg[CFG_AUTH_ENABLE].current && cfg[CFG_AUTH_E2E].current &&
	    (port->vpi == 0 || cfg[CFG_AUTH_NPIV].current)) {
		(void) strlcat(buffer, "fcsp:Supported",
		    sizeof (buffer));
	} else {
		(void) strlcat(buffer, "fcsp:Disabled",
		    sizeof (buffer));
	}
#endif /* DHCHAP_SUPPORT */

	if (hba->flag & FC_PT_TO_PT) {
		mutex_enter(&EMLXS_PORT_LOCK);

		port->did = sid;
		port->rdid = did;

		/* Save E_D_TOV ticks in nanoseconds */
		if (sp->cmn.edtovResolution) {
			hba->fc_edtov =
			    (LE_SWAP32(sp->cmn.e_d_tov) + 999999) / 1000000;
		} else {
			hba->fc_edtov = LE_SWAP32(sp->cmn.e_d_tov);
		}

		/* Only E_D_TOV is valid for PLOGI in pt2pt mode */

		mutex_exit(&EMLXS_PORT_LOCK);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_completion_msg,
	    "PLOGI: sid=%x did=%x %s", sid, did, buffer);

	/* Preset the pkt state for reg_did */
	emlxs_set_pkt_state(sbp, IOSTAT_SUCCESS, 0, 1);

	/*
	 * Do register login to Firmware before calling packet completion
	 */
	if (EMLXS_SLI_REG_DID(port, did, sp, sbp, NULL, NULL) == 0) {
		/*
		 * Deferred completion of this pkt until login is complete
		 */
		return;
	}

	ndlp = emlxs_node_find_did(port, did, 1);

	if (ndlp && ndlp->nlp_active) {
		/* Open the node again */
		emlxs_node_open(port, ndlp, hba->channel_fcp);
		emlxs_node_open(port, ndlp, hba->channel_ip);
	}

	emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT, IOERR_NO_RESOURCES, 1);

	return;

} /* emlxs_handle_sol_plogi() */


static void
emlxs_handle_sol_adisc(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	uint32_t did;
	NODELIST *ndlp;

	pkt = PRIV2PKT(sbp);
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_completion_msg, "ADISC: did=%x",
	    did);

	ndlp = emlxs_node_find_did(port, did, 1);

	if (ndlp && ndlp->nlp_active) {
		/* Open the node again */
		emlxs_node_open(port, ndlp, hba->channel_fcp);
		emlxs_node_open(port, ndlp, hba->channel_ip);

		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {

			emlxs_set_pkt_state(sbp, IOSTAT_SUCCESS, 0, 1);

			if (emlxs_rpi_resume_notify(port,
			    ndlp->rpip, sbp) == 0) {
				/*
				 * Delay ADISC cmpl to ULP till
				 * after RESUME_RPI
				 */
				return;
			}
		}
	}

	emlxs_pkt_complete(sbp, IOSTAT_SUCCESS, 0, 1);

	return;

} /* emlxs_handle_sol_adisc() */


static void
emlxs_handle_sol_prli(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	fc_packet_t *pkt;
	NODELIST *ndlp;
	uint32_t did;
	PRLI *npr;
	uint32_t task_retry_id;

	pkt = PRIV2PKT(sbp);
	npr = (PRLI *)((caddr_t)pkt->pkt_resp + sizeof (uint32_t));
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);

	ndlp = emlxs_node_find_did(port, did, 1);

	if (ndlp && ndlp->nlp_active) {
		/* Check for FCP support */
		if ((npr->acceptRspCode == PRLI_REQ_EXECUTED) &&
		    (npr->prliType == PRLI_FCP_TYPE)) {
			/* Clear FCP2 support if no ADISC support requested */
			if (cfg[CFG_ADISC_SUPPORT].current == 0) {
				npr->ConfmComplAllowed = 0;
				npr->TaskRetryIdReq = 0;
				npr->Retry = 0;
			}

			/* Check for target */
			if (npr->targetFunc) {
				ndlp->nlp_fcp_info |= NLP_FCP_TGT_DEVICE;
			} else {
				ndlp->nlp_fcp_info &= ~NLP_FCP_TGT_DEVICE;
			}
#ifdef NODE_THROTTLE_SUPPORT
			emlxs_node_throttle_set(port, ndlp);
#endif /* NODE_THROTTLE_SUPPORT */

			/* Check for initiator */
			if (npr->initiatorFunc) {
				ndlp->nlp_fcp_info |= NLP_FCP_INI_DEVICE;
			} else {
				ndlp->nlp_fcp_info &= ~NLP_FCP_INI_DEVICE;
			}

			/* If TRI support is not required then force */
			/* the task_retry_id value to one */
			if (cfg[CFG_TRI_REQUIRED].current == 0) {
				task_retry_id = 1;
			} else {
				task_retry_id = npr->TaskRetryIdReq;
			}

			/* Check for FCP2 target support */
			/* Retry and TaskRetryId bits are both required here */
			if (npr->targetFunc && npr->Retry && task_retry_id) {
				ndlp->nlp_fcp_info |= NLP_FCP_2_DEVICE;
			} else {
				ndlp->nlp_fcp_info &= ~NLP_FCP_2_DEVICE;
			}
		}

		/* Open the node again */
		emlxs_node_open(port, ndlp, hba->channel_fcp);

		EMLXS_SET_DFC_STATE(ndlp, NODE_ALLOC);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_completion_msg,
		    "PRLI: did=%x info=%02x", did, ndlp->nlp_fcp_info);

		/*
		 * Report PRLI completion
		 */
		emlxs_pkt_complete(sbp, IOSTAT_SUCCESS, 0, 1);

	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_completion_msg,
		    "PRLI: did=%x: Node not found. Failing.", did);

		/*
		 * Report PRLI failed
		 */
		emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
		    IOERR_INVALID_RPI, 1);
	}
	return;

} /* emlxs_handle_sol_prli() */


static void
emlxs_handle_sol_logo(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	uint32_t did;
	NODELIST *ndlp;

	pkt = PRIV2PKT(sbp);
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_completion_msg, "LOGO: did=%x",
	    did);

	ndlp = emlxs_node_find_did(port, did, 1);

	if (ndlp && ndlp->nlp_active) {
		EMLXS_SET_DFC_STATE(ndlp, NODE_LOGOUT);

		if ((hba->sli_mode == EMLXS_HBA_SLI4_MODE) &&
		    (ndlp->nlp_DID == FABRIC_DID)) {
			(void) emlxs_vpi_logo_cmpl_notify(port);
		} else {
			/* Close the node for any further normal IO */
			emlxs_node_close(port, ndlp, hba->channel_fcp, 60);
			emlxs_node_close(port, ndlp, hba->channel_ip, 60);

			/* Flush tx queues */
			(void) emlxs_tx_node_flush(port, ndlp, 0, 0, 0);

			/* Flush chip queues */
			(void) emlxs_chipq_node_flush(port, 0, ndlp, 0);
		}
	}

	emlxs_pkt_complete(sbp, IOSTAT_SUCCESS, 0, 1);

	if ((hba->sli_mode == EMLXS_HBA_SLI3_MODE) &&
	    (ndlp->nlp_DID == FABRIC_DID)) {
		port->flag &= ~EMLXS_PORT_FLOGI_CMPL;
	}

	return;

} /* emlxs_handle_sol_logo() */


/* ARGSUSED */
static void
emlxs_handle_unsol_rscn(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	uint32_t *lp;
	fc_unsol_buf_t *ubp;
	uint8_t *bp;
	IOCB *iocb;
	uint32_t count;
	uint32_t sid;
	emlxs_ub_priv_t *ub_priv;

	iocb = &iocbq->iocb;
	bp = mp->virt;
	lp = (uint32_t *)bp + 1;
	sid = iocb->un.elsreq.remoteID;

	/* Log the legacy rscn event for physical port only */
	if (port->vpi == 0) {
		emlxs_log_rscn_event(port, bp, size);
	}

	/* Log the vport rscn event for all ports */
	emlxs_log_vportrscn_event(port, bp, size);

	count = ((size - 4) / 4);

	ubp = (fc_unsol_buf_t *)emlxs_ub_get(port, size,
	    FC_TYPE_EXTENDED_LS, 1);

	if (ubp == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_no_unsol_buf_msg,
		    "RSCN rcvd: sid=%x  %d page(s): %08X, %08X. Rejecting.",
		    sid, count, LE_SWAP32(*lp),
		    ((count > 1) ? LE_SWAP32(*(lp + 1)) : 0));

		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT,
		    ELS_CMD_RSCN, LSRJT_LOGICAL_BSY, LSEXP_OUT_OF_RESOURCE);

		goto drop_it;
	}

	bcopy(bp, ubp->ub_buffer, size);
	ub_priv = ubp->ub_fca_private;
	ub_priv->cmd = ELS_CMD_RSCN;

	/*
	 * Setup frame header
	 */
	ubp->ub_frame.r_ctl = FC_ELS_REQ;
	ubp->ub_frame.type = FC_TYPE_EXTENDED_LS;
	ubp->ub_frame.s_id = LE_SWAP24_LO(iocb->un.elsreq.remoteID);
	ubp->ub_frame.d_id = LE_SWAP24_LO(iocb->un.elsreq.myID);
	ubp->ub_frame.ox_id = ub_priv->token;
	ubp->ub_frame.rx_id = iocb->ULPCONTEXT;
	ubp->ub_class = FC_TRAN_CLASS3;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
	    "RSCN: sid=%x  %d page(s): %08X, %08X  buffer=%p token=%x.", sid,
	    count, LE_SWAP32(*lp),
	    ((count > 1) ? LE_SWAP32(*(lp + 1)) : 0), ubp, ub_priv->token);

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_swap_els_ub(ubp);
#endif /* EMLXS_MODREV2X */

	emlxs_ub_callback(port, ubp);

drop_it:

	return;

} /* emlxs_handle_unsol_rscn() */


/* This is shared by FCT driver */
extern uint32_t
emlxs_process_unsol_flogi(emlxs_port_t *port, IOCBQ *iocbq, MATCHMAP *mp,
    uint32_t size, char *buffer, size_t len)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	uint8_t *bp;
	IOCB *iocb;
	uint32_t sid;
	SERV_PARM *sp;

	iocb = &iocbq->iocb;
	sid = iocb->un.elsreq.remoteID;

	/* Check payload size */
	if (size < (sizeof (SERV_PARM) + 4)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "FLOGI: sid=%x. Payload too small. %d<%d Rejecting.", sid,
		    size, (sizeof (SERV_PARM) + 4));

		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT,
		    ELS_CMD_FLOGI, LSRJT_PROTOCOL_ERR, LSEXP_NOTHING_MORE);

		return (1);
	}

	bp = mp->virt;
	sp = (SERV_PARM *)(bp + sizeof (uint32_t));

	mutex_enter(&EMLXS_PORT_LOCK);

	hba->flag &= ~FC_FABRIC_ATTACHED;
	hba->flag |= FC_PT_TO_PT;

	bcopy((void *)sp, (void *)&port->fabric_sparam, sizeof (SERV_PARM));

	/* Save E_D_TOV ticks in nanoseconds */
	if (sp->cmn.edtovResolution) {
		hba->fc_edtov =
		    (LE_SWAP32(sp->cmn.e_d_tov) + 999999) / 1000000;
	} else {
		hba->fc_edtov = LE_SWAP32(sp->cmn.e_d_tov);
	}

	/* Typically the FLOGI ACC rsp has the R_A_TOV value both sides use */

	hba->flag &= ~FC_NPIV_SUPPORTED;
	(void) strlcpy(buffer, "npiv:Disabled.", len);

	if (emlxs_wwn_cmp((uint8_t *)&sp->portName,
	    (uint8_t *)&port->wwpn) > 0) {
		(void) strlcat(buffer, " P2P Master.", len);
	} else {
		(void) strlcat(buffer, " P2P Slave.", len);
	}

#ifdef DHCHAP_SUPPORT
	if (!sp->cmn.fcsp_support) {
		(void) strlcat(buffer, " fcsp:Unsupported", len);
	} else if (cfg[CFG_AUTH_ENABLE].current &&
	    (port->vpi == 0 || cfg[CFG_AUTH_NPIV].current)) {
		(void) strlcat(buffer, " fcsp:Supported", len);
	} else {
		(void) strlcat(buffer, " fcsp:Disabled", len);
	}
#endif /* DHCHAP_SUPPORT */

	mutex_exit(&EMLXS_PORT_LOCK);

	return (0);

} /* emlxs_process_unsol_flogi() */


/* ARGSUSED */
static void
emlxs_handle_unsol_flogi(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	uint8_t *bp;
	fc_unsol_buf_t *ubp;
	IOCB *iocb;
	uint32_t sid;
	emlxs_ub_priv_t *ub_priv;
	char buffer[64];

	buffer[0] = 0;

	/* Perform processing of FLOGI payload */
	if (emlxs_process_unsol_flogi(port, iocbq, mp, size, buffer,
	    sizeof (buffer))) {
		return;
	}

	iocb = &iocbq->iocb;
	sid = iocb->un.elsreq.remoteID;
	bp = mp->virt;
	size = sizeof (SERV_PARM) + 4;

	ubp = (fc_unsol_buf_t *)emlxs_ub_get(port, size,
	    FC_TYPE_EXTENDED_LS, 0);

	if (ubp == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_no_unsol_buf_msg,
		    "FLOGI rcvd: sid=%x. Rejecting.", sid);

		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT,
		    ELS_CMD_FLOGI, LSRJT_LOGICAL_BSY, LSEXP_OUT_OF_RESOURCE);

		goto drop_it;
	}

	/*
	 * Setup unsolicited buffer and pass it up
	 */
	bcopy(bp, ubp->ub_buffer, size);
	ub_priv = ubp->ub_fca_private;
	ub_priv->cmd = ELS_CMD_FLOGI;

	/*
	 * Setup frame header
	 */
	ubp->ub_frame.r_ctl = FC_ELS_REQ;
	ubp->ub_frame.type = FC_TYPE_EXTENDED_LS;
	ubp->ub_frame.s_id = LE_SWAP24_LO(iocb->un.elsreq.remoteID);
	ubp->ub_frame.d_id = LE_SWAP24_LO(iocb->un.elsreq.myID);
	ubp->ub_frame.ox_id = ub_priv->token;
	ubp->ub_frame.rx_id = iocb->ULPCONTEXT;
	ubp->ub_class = FC_TRAN_CLASS3;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
	    "FLOGI: sid=%x buffer=%p token=%x %s", sid, ubp, ub_priv->token,
	    buffer);

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_swap_els_ub(ubp);
#endif /* EMLXS_MODREV2X */

	emlxs_ub_callback(port, ubp);

drop_it:

	return;

} /* emlxs_handle_unsol_flogi() */



/* This is shared by FCT driver */
extern uint32_t
emlxs_process_unsol_plogi(emlxs_port_t *port, IOCBQ *iocbq, MATCHMAP *mp,
    uint32_t size, char *buffer, size_t len)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	uint8_t *bp;
	IOCB *iocb;
	uint32_t sid;
	uint32_t did;
	SERV_PARM *sp;
	MAILBOXQ *mbox;
	emlxs_vvl_fmt_t vvl;
	int rc;

	iocb = &iocbq->iocb;
	did = iocb->un.elsreq.myID;
	sid = iocb->un.elsreq.remoteID;

	if (size < (sizeof (SERV_PARM) + 4)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "PLOGI: sid=%x. Payload too small. %d<%d Rejecting.", sid,
		    size, (sizeof (SERV_PARM) + 4));

		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT,
		    ELS_CMD_PLOGI, LSRJT_PROTOCOL_ERR, LSEXP_NOTHING_MORE);

		return (1);
	}

	bp = mp->virt;
	sp = (SERV_PARM *)(bp + sizeof (uint32_t));

	bzero((char *)&vvl, sizeof (emlxs_vvl_fmt_t));

	if (sp->VALID_VENDOR_VERSION) {

		bcopy((caddr_t *)&sp->vendorVersion[0],
		    (caddr_t *)&vvl, sizeof (emlxs_vvl_fmt_t));
		vvl.un0.word0 = LE_SWAP32(vvl.un0.word0);
		vvl.un1.word1 = LE_SWAP32(vvl.un1.word1);
	}

	if ((port->mode == MODE_INITIATOR) &&
	    (port->flag & EMLXS_PORT_RESTRICTED)) {
		uint32_t reject_it = 0;

		/* If remote port is the virtual port, then reject it */
		if ((vvl.un0.w0.oui == 0x0000C9) && (vvl.un1.w1.vport)) {
			reject_it = 1;
		}

		/* If we are a virtual port and the remote device */
		/* is not a switch, then reject it */
		else if (port->vpi && ((sid & FABRIC_DID_MASK) !=
		    FABRIC_DID_MASK)) {
			reject_it = 1;
		}

		if (reject_it) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
			    "PLOGI rcvd: sid=%x. Restricted. Rejecting.",
			    sid);

			(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT,
			    ELS_CMD_PLOGI, LSRJT_UNABLE_TPC,
			    LSEXP_NOTHING_MORE);

			/* Clear temporary RPI in firmware */
			if (hba->sli_mode <= EMLXS_HBA_SLI3_MODE) {
				(void) EMLXS_SLI_REG_DID(port, sid, sp,
				    NULL, NULL, (IOCBQ *)1);
			}

			return (1);
		}
	}

#ifdef DHCHAP_SUPPORT
	if (emlxs_dhc_verify_login(port, sid, sp)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "PLOGI: sid=%x. FCSP disabled. Rejecting.", sid);

		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT,
		    ELS_CMD_PLOGI, LSRJT_UNABLE_TPC, LSEXP_NOTHING_MORE);

		return (1);
	}

	if (!sp->cmn.fcsp_support) {
		(void) strlcat(buffer, "fcsp:Unsupported", len);
	} else if (cfg[CFG_AUTH_ENABLE].current && cfg[CFG_AUTH_E2E].current &&
	    (port->vpi == 0 || cfg[CFG_AUTH_NPIV].current)) {
		(void) strlcat(buffer, "fcsp:Supported", len);
	} else {
		(void) strlcat(buffer, "fcsp:Disabled", len);
	}
#endif /* DHCHAP_SUPPORT */

	/* Check if this was a point to point Plogi */
	if (hba->flag & FC_PT_TO_PT) {
		mutex_enter(&EMLXS_PORT_LOCK);

		port->did = did;
		port->rdid = sid;

		/* Save E_D_TOV ticks in nanoseconds */
		if (sp->cmn.edtovResolution) {
			hba->fc_edtov =
			    (LE_SWAP32(sp->cmn.e_d_tov) + 999999) / 1000000;
		} else {
			hba->fc_edtov = LE_SWAP32(sp->cmn.e_d_tov);
		}

		/* Only E_D_TOV is valid for PLOGI in pt2pt mode */

		mutex_exit(&EMLXS_PORT_LOCK);

		if (hba->sli_mode <= EMLXS_HBA_SLI3_MODE) {
			/* Update our service parms */
			if ((mbox = (MAILBOXQ *)emlxs_mem_get(hba,
			    MEM_MBOX))) {
				emlxs_mb_config_link(hba, mbox);

				rc =  EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbox,
				    MBX_NOWAIT, 0);
				if ((rc != MBX_BUSY) && (rc != MBX_SUCCESS)) {
					emlxs_mem_put(hba, MEM_MBOX,
					    (void *)mbox);
				}

			}
		}
	}

	return (0);

} /* emlxs_process_unsol_plogi() */


/* ARGSUSED */
static void
emlxs_handle_unsol_plogi(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	emlxs_hba_t *hba = HBA;
	fc_unsol_buf_t *ubp;
	uint8_t *bp;
	IOCB *iocb;
	uint32_t sid;
	uint32_t did;
	emlxs_ub_priv_t *ub_priv;
	SERV_PARM *sp;
	char buffer[64];

	buffer[0] = 0;

	/* Perform processing of PLOGI payload */
	if (emlxs_process_unsol_plogi(port, iocbq, mp, size, buffer,
	    sizeof (buffer))) {
		return;
	}

	iocb = &iocbq->iocb;
	sid = iocb->un.elsreq.remoteID;
	did = iocb->un.elsreq.myID;
	bp = mp->virt;
	sp = (SERV_PARM *)(bp + sizeof (uint32_t));
	size = sizeof (SERV_PARM) + 4;

#ifdef SAN_DIAG_SUPPORT
	emlxs_log_sd_basic_els_event(port, SD_ELS_SUBCATEGORY_PLOGI_RCV,
	    (HBA_WWN *)&sp->portName, (HBA_WWN *)&sp->nodeName);
#endif

	ubp = (fc_unsol_buf_t *)emlxs_ub_get(port, size,
	    FC_TYPE_EXTENDED_LS, 0);

	if (ubp == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_no_unsol_buf_msg,
		    "PLOGI rcvd: sid=%x. Rejecting.", sid);

		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT,
		    ELS_CMD_PLOGI, LSRJT_LOGICAL_BSY, LSEXP_OUT_OF_RESOURCE);

		goto drop_it;
	}

	/*
	 * Setup unsolicited buffer and pass it up
	 */
	bcopy(bp, ubp->ub_buffer, size);
	ub_priv = ubp->ub_fca_private;
	ub_priv->cmd = ELS_CMD_PLOGI;

	/*
	 * Setup frame header
	 */
	ubp->ub_frame.r_ctl = FC_ELS_REQ;
	ubp->ub_frame.type = FC_TYPE_EXTENDED_LS;
	ubp->ub_frame.s_id = LE_SWAP24_LO(iocb->un.elsreq.remoteID);
	ubp->ub_frame.d_id = LE_SWAP24_LO(iocb->un.elsreq.myID);
	ubp->ub_frame.ox_id = ub_priv->token;
	ubp->ub_frame.rx_id = iocb->ULPCONTEXT;
	ubp->ub_class = FC_TRAN_CLASS3;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
	    "PLOGI: sid=%x did=%x buffer=%p token=%x %s", sid, did, ubp,
	    ub_priv->token, buffer);

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_swap_els_ub(ubp);
#endif /* EMLXS_MODREV2X */

	/* Create a new node and defer callback */
	if (EMLXS_SLI_REG_DID(port, sid, sp, NULL, ubp, NULL) == 0) {
		/*
		 * Defer completion of this pkt until login is complete
		 */
		goto drop_it;
	}

	emlxs_ub_callback(port, ubp);

drop_it:

	return;

} /* emlxs_handle_unsol_plogi() */


/* ARGSUSED */
static void
emlxs_handle_unsol_prli(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	emlxs_hba_t	*hba = HBA;
	emlxs_config_t	*cfg = &CFG;
	IOCB *iocb;
	uint32_t sid;
	NODELIST *ndlp;
	PRLI *npr;
	fc_unsol_buf_t *ubp;
	emlxs_ub_priv_t *ub_priv;
	uint32_t task_retry_id;

	iocb = &iocbq->iocb;
	sid = iocb->un.elsreq.remoteID;
	ndlp = emlxs_node_find_did(port, sid, 1);

	if (!ndlp || !ndlp->nlp_active) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "PRLI: sid=%x: Node not found. Rejecting.", sid);

		/* Auto reply to PRLI's */
		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT,
		    ELS_CMD_PRLI, LSRJT_UNABLE_TPC, LSEXP_NOTHING_MORE);

		goto drop_it;
	}

	/* If node exists then save FCP2 support */
	npr = (PRLI *)((caddr_t)mp->virt + sizeof (uint32_t));

	/* Check for FCP2 support */
	if ((npr->prliType == PRLI_FCP_TYPE) && npr->targetFunc) {
		/* Clear FCP2 support if no ADISC support is requested */
		if (cfg[CFG_ADISC_SUPPORT].current == 0) {
			npr->ConfmComplAllowed = 0;
			npr->TaskRetryIdReq = 0;
			npr->Retry = 0;
		}

		/* Check for target */
		if (npr->targetFunc) {
			ndlp->nlp_fcp_info |= NLP_FCP_TGT_DEVICE;
		} else {
			ndlp->nlp_fcp_info &= ~NLP_FCP_TGT_DEVICE;
		}
#ifdef NODE_THROTTLE_SUPPORT
		emlxs_node_throttle_set(port, ndlp);
#endif /* NODE_THROTTLE_SUPPORT */

		/* Check for initiator */
		if (npr->initiatorFunc) {
			ndlp->nlp_fcp_info |= NLP_FCP_INI_DEVICE;
		} else {
			ndlp->nlp_fcp_info &= ~NLP_FCP_INI_DEVICE;
		}

		/* If TRI support is not required then force */
		/* the task_retry_id value to one */
		if (cfg[CFG_TRI_REQUIRED].current == 0) {
			task_retry_id = 1;
		} else {
			task_retry_id = npr->TaskRetryIdReq;
		}

		/* Check for FCP2 target support */
		/* Retry and TaskRetryId bits are both required here */
		if (npr->targetFunc && npr->Retry && task_retry_id) {
			ndlp->nlp_fcp_info |= NLP_FCP_2_DEVICE;
		} else {
			ndlp->nlp_fcp_info &= ~NLP_FCP_2_DEVICE;
		}
	}

#ifdef ULP_PATCH3
	if (cfg[CFG_ENABLE_PATCH].current & ULP_PATCH3) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "PRLI: sid=%x. Accepting.", sid);

		/* Auto reply to PRLI's */
		(void) emlxs_els_reply(port, iocbq, ELS_CMD_ACC,
		    ELS_CMD_PRLI, 0, 0);
		goto drop_it;
	}
#endif /* ULP_PATCH3 */

	/* Tell ULP about it */
	ubp = (fc_unsol_buf_t *)emlxs_ub_get(port, size,
	    FC_TYPE_EXTENDED_LS, 0);

	if (ubp == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_no_unsol_buf_msg,
		    "PRLI rcvd: sid=%x. Rejecting.", sid);

		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT,
		    ELS_CMD_PRLI, LSRJT_LOGICAL_BSY, LSEXP_OUT_OF_RESOURCE);

		goto drop_it;
	}

	/*
	 * Setup unsolicited buffer and pass it up
	 */
	bcopy(mp->virt, ubp->ub_buffer, size);
	ub_priv = ubp->ub_fca_private;
	ub_priv->cmd = ELS_CMD_PRLI;

	/*
	 * Setup frame header
	 */
	ubp->ub_frame.r_ctl = FC_ELS_REQ;
	ubp->ub_frame.type = FC_TYPE_EXTENDED_LS;
	ubp->ub_frame.s_id = LE_SWAP24_LO(iocb->un.elsreq.remoteID);
	ubp->ub_frame.d_id = LE_SWAP24_LO(iocb->un.elsreq.myID);
	ubp->ub_frame.ox_id = ub_priv->token;
	ubp->ub_frame.rx_id = iocb->ULPCONTEXT;
	ubp->ub_class = FC_TRAN_CLASS3;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
	    "PRLI: sid=%x buffer=%p token=%x info=%02x", sid, ubp,
	    ub_priv->token, ndlp->nlp_fcp_info);

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_swap_els_ub(ubp);
#endif /* EMLXS_MODREV2X */

	emlxs_ub_callback(port, ubp);

drop_it:

	return;

} /* emlxs_handle_unsol_prli() */


/* ARGSUSED */
static void
emlxs_handle_unsol_auth(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	IOCB *iocb;
	uint32_t sid;
	NODELIST *ndlp;

	iocb = &iocbq->iocb;
	sid = iocb->un.elsreq.remoteID;

#ifdef DHCHAP_SUPPORT
	ndlp = emlxs_node_find_did(port, sid, 1);

	if (!ndlp || !ndlp->nlp_active) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "AUTH: sid=%x: Node not found. Rejecting.", sid);

		/* Auto reply to AUTH_ELS's */
		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT,
		    ELS_CMD_AUTH, LSRJT_UNABLE_TPC, LSEXP_NOTHING_MORE);

		goto drop_it;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg, "AUTH: sid=%x", sid);

	(void) emlxs_dhchap_state_machine(port, cp, iocbq, mp, ndlp,
	    NODE_EVENT_RCV_AUTH_MSG);
#else

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
	    "AUTH: sid=%x: Rejecting.", sid);
	(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT, ELS_CMD_AUTH,
	    LSRJT_UNABLE_TPC, LSEXP_NOTHING_MORE);

#endif /* DHCAHP_SUPPORT */

drop_it:

	return;

} /* emlxs_handle_unsol_auth() */


/* ARGSUSED */
static void
emlxs_handle_unsol_adisc(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	IOCB		*iocb;
#ifdef SAN_DIAG_SUPPORT
	NODELIST	*ndlp;
#endif
	uint32_t	sid;

	iocb = &iocbq->iocb;
	sid = iocb->un.elsreq.remoteID;

#ifdef SAN_DIAG_SUPPORT
	ndlp = emlxs_node_find_did(port, sid, 1);

	if (ndlp) {
		emlxs_log_sd_basic_els_event(port, SD_ELS_SUBCATEGORY_ADISC_RCV,
		    (HBA_WWN *)&ndlp->nlp_portname,
		    (HBA_WWN *)&ndlp->nlp_nodename);
	}
#endif

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
	    "ADISC: sid=%x: Accepting.", sid);
	(void) emlxs_els_reply(port, iocbq, ELS_CMD_ACC, ELS_CMD_ADISC, 0, 0);

	return;

} /* emlxs_handle_unsol_adisc() */


/* ARGSUSED */
static void
emlxs_handle_unsol_prlo(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	emlxs_hba_t	*hba = HBA;
	emlxs_config_t	*cfg = &CFG;
	IOCB *iocb;
	uint32_t sid;
	fc_unsol_buf_t *ubp;
	emlxs_ub_priv_t *ub_priv;
	NODELIST *ndlp;

	iocb = &iocbq->iocb;
	sid = iocb->un.elsreq.remoteID;

	/* Get the node */
	ndlp = emlxs_node_find_did(port, sid, 1);

#ifdef SAN_DIAG_SUPPORT
	if (ndlp) {
		emlxs_log_sd_prlo_event(port, (HBA_WWN *)&ndlp->nlp_portname);
	}
#endif

#ifdef ULP_PATCH4
	if (cfg[CFG_ENABLE_PATCH].current & ULP_PATCH4) {
#ifdef ULP_PATCH6
		if (cfg[CFG_ENABLE_PATCH].current & ULP_PATCH6) {
			/* Check if this is a SCSI target */
			if (ndlp && (ndlp->nlp_fcp_info & NLP_FCP_TGT_DEVICE)) {
				/* This is a SCSI target */

				/* If only one node is present, then we can */
				/* conclude that we are direct attached */
				/* to a target */
				if (port->node_count == 1) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_unsol_els_msg,
					    "PRLO: sid=%x. Accepting and " \
					    "reseting link.",
					    sid);

					/* Send Acc */
					(void) emlxs_els_reply(port, iocbq,
					    ELS_CMD_ACC, ELS_CMD_PRLO, 0, 0);

					/* Spawn a thread to reset the link */
					emlxs_thread_spawn(hba,
					    emlxs_reset_link_thread,
					    NULL, NULL);

					goto drop_it;

				}
				/* Check if fabric is present */
				else if (hba->flag & FC_FABRIC_ATTACHED) {
					/* Auto reply to PRLO */
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_unsol_els_msg,
					    "PRLO: sid=%x. Accepting and " \
					    "generating RSCN.",
					    sid);

					/* Send Acc */
					(void) emlxs_els_reply(port, iocbq,
					    ELS_CMD_ACC, ELS_CMD_PRLO, 0, 0);

					/* Generate an RSCN to wakeup ULP */
					(void) emlxs_generate_rscn(port, sid);

					goto drop_it;
				}
			}
		}
#endif /* ULP_PATCH6 */

		/* Auto reply to PRLO */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "PRLO: sid=%x. Accepting.", sid);

		/* Send Acc */
		(void) emlxs_els_reply(port, iocbq, ELS_CMD_ACC,
		    ELS_CMD_PRLO, 0, 0);

		goto drop_it;
	}
#endif /* ULP_PATCH4 */

	/* Tell ULP about it */

	ubp = (fc_unsol_buf_t *)emlxs_ub_get(port, size,
	    FC_TYPE_EXTENDED_LS, 0);

	if (ubp == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_no_unsol_buf_msg,
		    "PRLO recvd: sid=%x. Rejecting.", sid);

		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT,
		    ELS_CMD_PRLO, LSRJT_LOGICAL_BSY, LSEXP_OUT_OF_RESOURCE);

		goto drop_it;
	}

	/*
	 * Setup unsolicited buffer and pass it up
	 */
	bcopy(mp->virt, ubp->ub_buffer, size);
	ub_priv = ubp->ub_fca_private;
	ub_priv->cmd = ELS_CMD_PRLO;

	/*
	 * Setup frame header
	 */
	ubp->ub_frame.r_ctl = FC_ELS_REQ;
	ubp->ub_frame.type = FC_TYPE_EXTENDED_LS;
	ubp->ub_frame.s_id = LE_SWAP24_LO(iocb->un.elsreq.remoteID);
	ubp->ub_frame.d_id = LE_SWAP24_LO(iocb->un.elsreq.myID);
	ubp->ub_frame.ox_id = ub_priv->token;
	ubp->ub_frame.rx_id = iocb->ULPCONTEXT;
	ubp->ub_class = FC_TRAN_CLASS3;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
	    "PRLO: sid=%x buffeiocbr=%p token=%x.", sid, ubp, ub_priv->token);

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_swap_els_ub(ubp);
#endif /* EMLXS_MODREV2X */

	emlxs_ub_callback(port, ubp);

drop_it:

	return;

} /* emlxs_handle_unsol_prlo() */


/* ARGSUSED */
static void
emlxs_handle_unsol_logo(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t	*cfg = &CFG;
	fc_unsol_buf_t *ubp;
	IOCB *iocb;
	uint32_t sid;
	emlxs_ub_priv_t *ub_priv;
	uint32_t reply_sent = 0;
	NODELIST *ndlp;

	iocb = &iocbq->iocb;
	sid = iocb->un.elsreq.remoteID;

	ndlp = emlxs_node_find_did(port, sid, 1);

#ifdef SAN_DIAG_SUPPORT
	if (ndlp) {
		emlxs_log_sd_basic_els_event(port,  SD_ELS_SUBCATEGORY_LOGO_RCV,
		    (HBA_WWN *)&ndlp->nlp_portname,
		    (HBA_WWN *)((uint32_t *)mp->virt + 2));
	}
#endif

	EMLXS_SET_DFC_STATE(ndlp, NODE_LOGOUT);

#ifdef ULP_PATCH6
	if (cfg[CFG_ENABLE_PATCH].current & ULP_PATCH6) {
		/* Check if this is a SCSI target */
		if (ndlp && (ndlp->nlp_fcp_info & NLP_FCP_TGT_DEVICE)) {
			/* This is a SCSI target */

			/* If only one node is present, then we can */
			/* conclude that we are direct attached to a target */
			if (port->node_count == 1) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
				    "LOGO: sid=%x. Accepting and "\
				    "reseting link.", sid);

				(void) emlxs_els_reply(port, iocbq,
				    ELS_CMD_ACC, ELS_CMD_LOGO, 0, 0);

				/* Spawn a thread to reset the link */
				emlxs_thread_spawn(hba, emlxs_reset_link_thread,
				    NULL, NULL);

				goto drop_it;
			}
			/* Check if fabric node is present */
			else if (hba->flag & FC_FABRIC_ATTACHED) {
				/* Send reply ourselves */
				/* We will block all attempts */
				/* for ULP to reply to a LOGO */
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
				    "LOGO: sid=%x. Accepting and " \
				    "generating RSCN.", sid);

				(void) emlxs_els_reply(port, iocbq, ELS_CMD_ACC,
				    ELS_CMD_LOGO, 0, 0);

				/* Generate an RSCN to wakeup ULP */
				if (emlxs_generate_rscn(port, sid)
				    == FC_SUCCESS) {
					goto drop_it;
				}

				reply_sent = 1;
			}
		}
	}
#endif /* ULP_PATCH6 */

	ubp = (fc_unsol_buf_t *)emlxs_ub_get(port, size,
	    FC_TYPE_EXTENDED_LS, 1);

	if (ubp == NULL) {
		if (!reply_sent) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_no_unsol_buf_msg,
			    "LOGO rcvd: sid=%x. Rejecting.", sid);

			(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT,
			    ELS_CMD_LOGO, LSRJT_LOGICAL_BSY,
			    LSEXP_OUT_OF_RESOURCE);
		}

		goto drop_it;

	}

	/* Setup unsolicited buffer and pass it up */
	bcopy(mp->virt, ubp->ub_buffer, size);
	ub_priv = ubp->ub_fca_private;
	ub_priv->cmd = ELS_CMD_LOGO;

	/* Setup frame header */
	ubp->ub_frame.r_ctl = FC_ELS_REQ;
	ubp->ub_frame.type = FC_TYPE_EXTENDED_LS;
	ubp->ub_frame.s_id = LE_SWAP24_LO(iocb->un.elsreq.remoteID);
	ubp->ub_frame.d_id = LE_SWAP24_LO(iocb->un.elsreq.myID);
	ubp->ub_frame.ox_id = ub_priv->token;
	ubp->ub_frame.rx_id = iocb->ULPCONTEXT;
	ubp->ub_class = FC_TRAN_CLASS3;

#ifdef ULP_PATCH2
	if (cfg[CFG_ENABLE_PATCH].current & ULP_PATCH2) {
		if (!reply_sent) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
			    "LOGO: sid=%x buffer=%p token=%x. Accepting.",
			    sid, ubp, ub_priv->token);

			ub_priv->flags |= EMLXS_UB_REPLY;

			/* Send Acc */
			/* Send reply ourselves because ULP */
			/* doesn't always reply to these */
			/* We ll block attempts for ULP to reply to a LOGO */
			(void) emlxs_els_reply(port, iocbq, ELS_CMD_ACC,
			    ELS_CMD_LOGO, 0, 0);
			reply_sent = 1;
		}
	}
#endif /* ULP_PATCH2 */

	if (!reply_sent) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "LOGO: sid=%x buffer=%p token=%x.", sid, ubp,
		    ub_priv->token);
	}

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_swap_els_ub(ubp);
#endif /* EMLXS_MODREV2X */

	/* Unregister the node */
	if ((sid & FABRIC_DID_MASK) == FABRIC_DID_MASK) {
		if (ndlp) {
			if (EMLXS_SLI_UNREG_NODE(port, ndlp, NULL,
			    ubp, NULL) == 0) {
				/*
				 * Deferred completion of this ubp
				 * until unreg login is complete
				 */
				return;
			}
		}
	}

	emlxs_ub_callback(port, ubp);

drop_it:

	return;

} /* emlxs_handle_unsol_logo() */



/* ARGSUSED */
static void
emlxs_handle_unsol_gen_cmd(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	uint8_t *bp;
	fc_unsol_buf_t *ubp;
	IOCB *iocb;
	uint32_t *lp;
	uint32_t cmd;
	uint32_t sid;
	emlxs_ub_priv_t *ub_priv;

	iocb = &iocbq->iocb;
	sid = iocb->un.elsreq.remoteID;

	bp = mp->virt;
	lp = (uint32_t *)bp;
	cmd = *lp & ELS_CMD_MASK;

	ubp = (fc_unsol_buf_t *)emlxs_ub_get(port, size,
	    FC_TYPE_EXTENDED_LS, 0);

	if (ubp == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_no_unsol_buf_msg,
		    "%s rcvd: sid=%x: Rejecting.", emlxs_elscmd_xlate(cmd),
		    sid);

		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT, cmd,
		    LSRJT_LOGICAL_BSY, LSEXP_OUT_OF_RESOURCE);

		goto drop_it;
	}

	bcopy(bp, ubp->ub_buffer, size);
	ub_priv = ubp->ub_fca_private;
	ub_priv->cmd = cmd;

	/* Setup frame header */
	ubp->ub_frame.r_ctl = FC_ELS_REQ;
	ubp->ub_frame.type = FC_TYPE_EXTENDED_LS;
	ubp->ub_frame.s_id = LE_SWAP24_LO(iocb->un.elsreq.remoteID);
	ubp->ub_frame.d_id = LE_SWAP24_LO(iocb->un.elsreq.myID);
	ubp->ub_frame.ox_id = ub_priv->token;
	ubp->ub_frame.rx_id = iocb->ULPCONTEXT;
	ubp->ub_class = FC_TRAN_CLASS3;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
	    "%s: sid=%x buffer=%p token=%x.", emlxs_elscmd_xlate(cmd), sid,
	    ubp, ub_priv->token);

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_swap_els_ub(ubp);
#endif /* EMLXS_MODREV2X */

	emlxs_ub_callback(port, ubp);

drop_it:

	return;

} /* emlxs_handle_unsol_gen_cmd() */


/* ARGSUSED */
static void
emlxs_handle_unsol_echo(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	emlxs_hba_t *hba = HBA;
	uint8_t *bp;
	IOCB *iocb;
	uint32_t *lp;
	uint32_t sid;
	fc_packet_t *pkt;
	uint32_t cmd;

	iocb = &iocbq->iocb;
	sid = iocb->un.elsreq.remoteID;

	bp = mp->virt;
	lp = (uint32_t *)bp;
	cmd = *lp & ELS_CMD_MASK;

	if (!(pkt = emlxs_pkt_alloc(port,
	    size, 0, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "ECHO: sid=%x. Unable to allocate pkt. Rejecting.",
		    sid);

		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT,
		    ELS_CMD_ECHO, LSRJT_UNABLE_TPC, LSEXP_NOTHING_MORE);
		return;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
	    "ECHO: sid=%x. Accepting.",
	    sid);

	/* Common initialization */
	pkt->pkt_tran_type = FC_PKT_OUTBOUND;
	pkt->pkt_timeout = (2 * hba->fc_ratov);

	if ((uint32_t)iocb->ULPCLASS == CLASS2) {
		pkt->pkt_tran_flags &= ~FC_TRAN_CLASS3;
		pkt->pkt_tran_flags |= FC_TRAN_CLASS2;
	}

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id =
	    LE_SWAP24_LO(iocb->un.elsreq.remoteID);
	pkt->pkt_cmd_fhdr.r_ctl =
	    R_CTL_EXTENDED_SVC | R_CTL_SOLICITED_CONTROL;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(iocb->un.elsreq.myID);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_XCHG_CONTEXT | F_CTL_LAST_SEQ | F_CTL_END_SEQ;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = (cmd >> ELS_CMD_SHIFT) & 0xff;
	pkt->pkt_cmd_fhdr.rx_id = iocb->ULPCONTEXT;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* Build the response */
	*lp = ELS_CMD_ACC;
	bcopy(lp, pkt->pkt_cmd, size);

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		/* Free the pkt */
		emlxs_pkt_free(pkt);
		emlxs_abort_els_exchange(hba, port, iocb->ULPCONTEXT);
	}

	return;

} /* emlxs_handle_unsol_echo() */


/* ARGSUSED */
static void
emlxs_handle_unsol_rtv(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	emlxs_hba_t *hba = HBA;
	uint8_t *bp;
	IOCB *iocb;
	uint32_t *lp;
	uint32_t sid;
	fc_packet_t *pkt;
	uint32_t cmd;
	SERV_PARM *sp;

	iocb = &iocbq->iocb;
	sid = iocb->un.elsreq.remoteID;

	bp = mp->virt;
	lp = (uint32_t *)bp;
	cmd = *lp & ELS_CMD_MASK;

	if (!(pkt = emlxs_pkt_alloc(port,
	    (4 * sizeof (uint32_t)), 0, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "RTV: sid=%x. Unable to allocate pkt. Rejecting.",
		    sid);

		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT,
		    ELS_CMD_RTV, LSRJT_UNABLE_TPC, LSEXP_NOTHING_MORE);
		return;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
	    "RTV: sid=%x. Accepting.",
	    emlxs_elscmd_xlate(cmd),
	    sid);

	/* Common initialization */
	pkt->pkt_tran_type = FC_PKT_OUTBOUND;
	pkt->pkt_timeout = (2 * hba->fc_ratov);

	if ((uint32_t)iocb->ULPCLASS == CLASS2) {
		pkt->pkt_tran_flags &= ~FC_TRAN_CLASS3;
		pkt->pkt_tran_flags |= FC_TRAN_CLASS2;
	}

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id =
	    LE_SWAP24_LO(iocb->un.elsreq.remoteID);
	pkt->pkt_cmd_fhdr.r_ctl =
	    R_CTL_EXTENDED_SVC | R_CTL_SOLICITED_CONTROL;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(iocb->un.elsreq.myID);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_XCHG_CONTEXT | F_CTL_LAST_SEQ | F_CTL_END_SEQ;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = (cmd >> ELS_CMD_SHIFT) & 0xff;
	pkt->pkt_cmd_fhdr.rx_id = iocb->ULPCONTEXT;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* Build the response */
	sp = (SERV_PARM *)&port->fabric_sparam;
	lp = (uint32_t *)pkt->pkt_cmd;
	lp[0] = ELS_CMD_ACC;
	lp[1] = LE_SWAP32(sp->cmn.w2.r_a_tov);
	lp[2] = LE_SWAP32(sp->cmn.e_d_tov);
	lp[3] = sp->cmn.edtovResolution << 26;

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		/* Free the pkt */
		emlxs_pkt_free(pkt);
		emlxs_abort_els_exchange(hba, port, iocb->ULPCONTEXT);
	}

	return;

} /* emlxs_handle_unsol_rtv() */


/* ARGSUSED */
static void
emlxs_rls_rsp_thread(emlxs_hba_t *hba, void *arg1, void *arg2)
{
	emlxs_port_t *port = (emlxs_port_t *)arg1;
	fc_packet_t *pkt = (fc_packet_t *)arg2;
	MAILBOXQ	*mbq = NULL;
	MAILBOX		*mb;
	la_els_rls_acc_t *rls;
	uint32_t rval;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
	    "RLS: sid=%x. Accepting.",
	    LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id));

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		goto dropit;
	}
	mb = (MAILBOX *)mbq;

	/* Read current link status */
	emlxs_mb_read_lnk_stat(hba, mbq);
	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0);

	if (rval != MBX_SUCCESS) {
		goto dropit;
	}

	/* Build the response */
	rls = (la_els_rls_acc_t *)pkt->pkt_cmd;
	rls->ls_code.ls_code = 0x02;
	rls->rls_link_params.rls_link_fail =
	    mb->un.varRdLnk.linkFailureCnt;
	rls->rls_link_params.rls_sync_loss =
	    mb->un.varRdLnk.lossSyncCnt;
	rls->rls_link_params.rls_sig_loss =
	    mb->un.varRdLnk.lossSignalCnt;
	rls->rls_link_params.rls_prim_seq_err =
	    mb->un.varRdLnk.primSeqErrCnt;
	rls->rls_link_params.rls_invalid_word =
	    mb->un.varRdLnk.invalidXmitWord;
	rls->rls_link_params.rls_invalid_crc =
	    mb->un.varRdLnk.crcCnt;

	LE_SWAP32_BUFFER((uint8_t *)rls, sizeof (la_els_rls_acc_t));

	emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
	mbq = NULL;

	if ((rval = emlxs_pkt_send(pkt, 1)) != FC_SUCCESS) {
		goto dropit;
	}

	return;

dropit:

	emlxs_abort_els_exchange(hba, port, pkt->pkt_cmd_fhdr.rx_id);

	emlxs_pkt_free(pkt);

	if (mbq) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
	}

	return;

} /* emlxs_rls_rsp_thread() */


/* ARGSUSED */
static void
emlxs_handle_unsol_rls(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	emlxs_hba_t *hba = HBA;
	uint8_t *bp;
	IOCB *iocb;
	uint32_t *lp;
	uint32_t sid;
	fc_packet_t *pkt;
	uint32_t cmd;

	iocb = &iocbq->iocb;
	sid = iocb->un.elsreq.remoteID;

	bp = mp->virt;
	lp = (uint32_t *)bp;
	cmd = *lp++ & ELS_CMD_MASK;

	if (!(pkt = emlxs_pkt_alloc(port,
	    sizeof (la_els_rls_acc_t), 0, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "RLS: sid=%x. Unable to allocate pkt.  Rejecting.",
		    sid);

		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT,
		    ELS_CMD_RLS, LSRJT_UNABLE_TPC, LSEXP_NOTHING_MORE);
		return;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
	    "RLS: sid=%x. Scheduling response.",
	    sid);

	/* Common initialization */
	pkt->pkt_tran_type = FC_PKT_OUTBOUND;
	pkt->pkt_timeout = (2 * hba->fc_ratov);

	if ((uint32_t)iocb->ULPCLASS == CLASS2) {
		pkt->pkt_tran_flags &= ~FC_TRAN_CLASS3;
		pkt->pkt_tran_flags |= FC_TRAN_CLASS2;
	}

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id =
	    LE_SWAP24_LO(iocb->un.elsreq.remoteID);
	pkt->pkt_cmd_fhdr.r_ctl =
	    R_CTL_EXTENDED_SVC | R_CTL_SOLICITED_CONTROL;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(iocb->un.elsreq.myID);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_XCHG_CONTEXT | F_CTL_LAST_SEQ | F_CTL_END_SEQ;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = (cmd >> ELS_CMD_SHIFT) & 0xff;
	pkt->pkt_cmd_fhdr.rx_id = iocb->ULPCONTEXT;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* We must spawn a separate thread to send the */
	/* read link status mailbox command becasue we are */
	/* normally in a hardware interrupt context here. */
	emlxs_thread_spawn(hba, emlxs_rls_rsp_thread,
	    (void *)port, (void *)pkt);

	return;

} /* emlxs_handle_unsol_rls() */


/* This handles the reply completions to unsolicited cmds */
/* ARGSUSED */
static void
emlxs_handle_acc(emlxs_port_t *port, emlxs_buf_t *sbp, IOCBQ *iocbq,
    uint32_t flag)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	IOCB *iocb;
	uint32_t did;
	NODELIST *ndlp;
	uint32_t ucmd;
	uint32_t cmd;
	uint32_t *lp;

	iocb = &iocbq->iocb;
	pkt = PRIV2PKT(sbp);
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);
	ucmd = pkt->pkt_cmd_fhdr.ox_id << ELS_CMD_SHIFT;
	lp = (uint32_t *)pkt->pkt_cmd;
	cmd = *lp & ELS_CMD_MASK;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_completion_msg,
	    "%s %s: did=%x %s %s", emlxs_elscmd_xlate(ucmd),
	    emlxs_elscmd_xlate(cmd), did, emlxs_state_xlate(iocb->ULPSTATUS),
	    emlxs_error_xlate(iocb->un.grsp.perr.statLocalError));

	switch (ucmd) {
	case ELS_CMD_PLOGI:
	case ELS_CMD_ADISC:

		ndlp = emlxs_node_find_did(port, did, 1);

		if (ndlp && ndlp->nlp_active) {
			/* Open the node again */
			emlxs_node_open(port, ndlp, hba->channel_fcp);
			emlxs_node_open(port, ndlp, hba->channel_ip);
		}

		break;

	case ELS_CMD_PRLI:

		ndlp = emlxs_node_find_did(port, did, 1);

		if (ndlp && ndlp->nlp_active) {
			EMLXS_SET_DFC_STATE(ndlp, NODE_ALLOC);

			/* Open the node again */
			emlxs_node_open(port, ndlp, hba->channel_fcp);
		}

		break;
	}

	emlxs_pkt_complete(sbp, iocb->ULPSTATUS,
	    iocb->un.grsp.perr.statLocalError, 1);

	return;

} /* emlxs_handle_acc() */


/* This handles the reply completions to unsolicited cmds */
/* ARGSUSED */
static void
emlxs_handle_reject(emlxs_port_t *port, emlxs_buf_t *sbp, IOCBQ *iocbq,
    uint32_t flag)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t	*pkt;
	NODELIST	*ndlp;
	IOCB		*iocb;
	uint32_t	did;
	uint32_t	ucmd;
	uint32_t	cmd;
	uint32_t	*lp;

	iocb = &iocbq->iocb;
	pkt = PRIV2PKT(sbp);
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);
	ucmd = pkt->pkt_cmd_fhdr.ox_id << ELS_CMD_SHIFT;
	lp = (uint32_t *)pkt->pkt_cmd;
	cmd = *lp & ELS_CMD_MASK;

	ndlp = emlxs_node_find_did(port, did, 1);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_els_completion_msg,
	    "%s %s: did=%x %s %s", emlxs_elscmd_xlate(ucmd),
	    emlxs_elscmd_xlate(cmd), did, emlxs_state_xlate(iocb->ULPSTATUS),
	    emlxs_error_xlate(iocb->un.grsp.perr.statLocalError));

	switch (ucmd) {
	case ELS_CMD_PLOGI:

		if (ndlp && ndlp->nlp_active) {
			/* Open the node again */
			emlxs_node_open(port, ndlp, hba->channel_fcp);
			emlxs_node_open(port, ndlp, hba->channel_ip);
		}

		break;

	case ELS_CMD_PRLI:

		if (ndlp && ndlp->nlp_active) {
			/* Open the node again */
			emlxs_node_open(port, ndlp, hba->channel_fcp);
		}

		break;
	}

	emlxs_pkt_complete(sbp, iocb->ULPSTATUS,
	    iocb->un.grsp.perr.statLocalError, 1);

	return;

} /* emlxs_handle_reject() */


/* ARGSUSED */
extern int32_t
emlxs_els_reply(emlxs_port_t *port, IOCBQ *iocbq, uint32_t type,
    uint32_t type2, uint32_t reason, uint32_t explain)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	fc_packet_t *pkt;
	ELS_PKT *els;
	IOCB *iocb;

	iocb = &iocbq->iocb;

	switch (type) {
	case ELS_CMD_ACC:	/* Accept Response */

		/* Allocate the pkt */
		switch (type2) {
		case ELS_CMD_FLOGI:
			pkt = emlxs_pkt_alloc(port,
			    sizeof (uint32_t) + sizeof (SERV_PARM), 0,
			    0, KM_NOSLEEP);
			break;

		case ELS_CMD_ADISC:
			pkt = emlxs_pkt_alloc(port,
			    sizeof (uint32_t) + sizeof (ADISC), 0, 0,
			    KM_NOSLEEP);
			break;

		case ELS_CMD_PRLI:
			pkt = emlxs_pkt_alloc(port,
			    sizeof (uint32_t) + sizeof (PRLI), 0, 0,
			    KM_NOSLEEP);
			break;

		case ELS_CMD_PRLO:
			pkt = emlxs_pkt_alloc(port,
			    sizeof (uint32_t) + sizeof (PRLO), 0, 0,
			    KM_NOSLEEP);
			break;

		case ELS_CMD_AUTH:
		default:
			pkt = emlxs_pkt_alloc(port, sizeof (uint32_t),
			    0, 0, KM_NOSLEEP);
			break;
		}

		if (!pkt) {
			goto dropit;
		}

		/* Common initialization */
		pkt->pkt_tran_type = FC_PKT_OUTBOUND;
		pkt->pkt_timeout = (2 * hba->fc_ratov);

		if ((uint32_t)iocb->ULPCLASS == CLASS2) {
			pkt->pkt_tran_flags &= ~FC_TRAN_CLASS3;
			pkt->pkt_tran_flags |= FC_TRAN_CLASS2;
		}

		/* Build the fc header */
		pkt->pkt_cmd_fhdr.d_id =
		    LE_SWAP24_LO(iocb->un.elsreq.remoteID);
		pkt->pkt_cmd_fhdr.r_ctl =
		    R_CTL_EXTENDED_SVC | R_CTL_SOLICITED_CONTROL;
		pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(iocb->un.elsreq.myID);
		pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
		pkt->pkt_cmd_fhdr.f_ctl =
		    F_CTL_XCHG_CONTEXT | F_CTL_LAST_SEQ | F_CTL_END_SEQ;
		pkt->pkt_cmd_fhdr.seq_id = 0;
		pkt->pkt_cmd_fhdr.df_ctl = 0;
		pkt->pkt_cmd_fhdr.seq_cnt = 0;
		pkt->pkt_cmd_fhdr.ox_id = (type2 >> ELS_CMD_SHIFT) & 0xff;
		pkt->pkt_cmd_fhdr.rx_id = iocb->ULPCONTEXT;
		pkt->pkt_cmd_fhdr.ro = 0;

		/*
		 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		 * "%s ACC send. oxid=%x", emlxs_elscmd_xlate(type2),
		 * pkt->pkt_cmd_fhdr.ox_id);
		 */

		/* Build the command */
		els = (ELS_PKT *)pkt->pkt_cmd;
		els->elsCode = 0x02;

		/* Build the payload */
		switch (type2) {
		case ELS_CMD_ADISC:

			els->un.adisc.hardAL_PA =
			    (uint8_t)cfg[CFG_ASSIGN_ALPA].current;
			bcopy(&port->wwnn, &els->un.adisc.nodeName,
			    sizeof (NAME_TYPE));
			bcopy(&port->wwpn, &els->un.adisc.portName,
			    sizeof (NAME_TYPE));
			els->un.adisc.DID = LE_SWAP24_LO(port->did);

			break;

		case ELS_CMD_PRLI:

			els->elsByte1 = 0x10;
			els->elsByte2 = 0;
			els->elsByte3 = 0x14;

			els->un.prli.prliType = PRLI_FCP_TYPE;
			els->un.prli.estabImagePair = 1;
			els->un.prli.acceptRspCode = PRLI_REQ_EXECUTED;

			if (port->mode == MODE_INITIATOR) {
				els->un.prli.initiatorFunc = 1;
			}

			if (port->mode == MODE_TARGET) {
				els->un.prli.targetFunc = 1;
			}

			els->un.prli.readXferRdyDis = 1;

			if ((hba->vpd.feaLevelHigh >= 0x02) &&
			    (cfg[CFG_ADISC_SUPPORT].current != 0)) {
				els->un.prli.ConfmComplAllowed = 1;
				els->un.prli.Retry = 1;
				els->un.prli.TaskRetryIdReq = 1;
			} else {
				els->un.prli.ConfmComplAllowed = 0;
				els->un.prli.Retry = 0;
				els->un.prli.TaskRetryIdReq = 0;
			}

			break;

		case ELS_CMD_PRLO:

			els->elsByte1 = 0x10;
			els->elsByte2 = 0;
			els->elsByte3 = 0x14;

			els->un.prlo.prloType = PRLO_FCP_TYPE;
			els->un.prlo.acceptRspCode = PRLO_REQ_EXECUTED;

			break;


		}	/* switch(type2) */
		break;

	case ELS_CMD_LS_RJT:	/* reject response */

		if (!(pkt = emlxs_pkt_alloc(port,
		    sizeof (uint32_t) + sizeof (LS_RJT), 0, 0, KM_NOSLEEP))) {
			goto dropit;
		}

		pkt->pkt_tran_type = FC_PKT_OUTBOUND;
		pkt->pkt_timeout = (2 * hba->fc_ratov);

		if ((uint32_t)iocb->ULPCLASS == CLASS2) {
			pkt->pkt_tran_flags &= ~FC_TRAN_CLASS3;
			pkt->pkt_tran_flags |= FC_TRAN_CLASS2;
		}

		/* Build the fc header */
		pkt->pkt_cmd_fhdr.d_id =
		    LE_SWAP24_LO(iocb->un.elsreq.remoteID);
		pkt->pkt_cmd_fhdr.r_ctl =
		    R_CTL_EXTENDED_SVC | R_CTL_SOLICITED_CONTROL;
		pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(iocb->un.elsreq.myID);
		pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
		pkt->pkt_cmd_fhdr.f_ctl =
		    F_CTL_XCHG_CONTEXT | F_CTL_LAST_SEQ | F_CTL_END_SEQ;
		pkt->pkt_cmd_fhdr.seq_id = 0;
		pkt->pkt_cmd_fhdr.df_ctl = 0;
		pkt->pkt_cmd_fhdr.seq_cnt = 0;
		pkt->pkt_cmd_fhdr.ox_id = (type2 >> ELS_CMD_SHIFT) & 0xff;
		pkt->pkt_cmd_fhdr.rx_id = iocb->ULPCONTEXT;
		pkt->pkt_cmd_fhdr.ro = 0;

		/*
		 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		 * "%s LS_RJT send. oxid=%x", emlxs_elscmd_xlate(type2),
		 * pkt->pkt_cmd_fhdr.ox_id);
		 */

		/* Build the command */
		els = (ELS_PKT *)pkt->pkt_cmd;
		els->elsCode = 0x01;
		els->un.lsRjt.un.b.lsRjtRsvd0 = 0;
		els->un.lsRjt.un.b.lsRjtRsnCode = LSRJT_UNABLE_TPC;
		els->un.lsRjt.un.b.lsRjtRsnCodeExp = LSEXP_NOTHING_MORE;
		els->un.lsRjt.un.b.vendorUnique = 0x01;

		break;

	default:
		return (1);
	}

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		/* Free the pkt */
		emlxs_pkt_free(pkt);
		goto dropit;
	}

	return (0);

dropit:

	emlxs_abort_els_exchange(hba, port, iocb->ULPCONTEXT);
	return (1);

} /* emlxs_els_reply() */


#ifdef ULP_PATCH6

extern uint32_t
emlxs_generate_rscn(emlxs_port_t *port, uint32_t d_id)
{
	fc_unsol_buf_t *ubp;
	fc_rscn_t *rscn;
	emlxs_ub_priv_t *ub_priv;
	uint32_t *page;

	ubp = (fc_unsol_buf_t *)emlxs_ub_get(port, 8, FC_TYPE_EXTENDED_LS, 1);

	if (ubp == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_no_unsol_buf_msg,
		    "RSCN create: sid=0xfffffd  1 page(s): %08X, 00000000. "
		    "Creation failed.", d_id);

		return ((uint32_t)FC_FAILURE);
	}

	/* Simulate an RSCN payload */
	rscn = (fc_rscn_t *)ubp->ub_buffer;
	rscn->rscn_code = 0x61;
	rscn->rscn_len = 0x04;
	rscn->rscn_payload_len = 0x0008;
	page = ((uint32_t *)rscn);
	page++;
	*page = d_id;

#ifdef EMLXS_I386
	/* Put payload in BE format */
	rscn->rscn_payload_len = LE_SWAP16(rscn->rscn_payload_len);
	*page = LE_SWAP32(d_id);
#endif /* EMLXS_I386 */

	ub_priv = ubp->ub_fca_private;
	ub_priv->cmd = ELS_CMD_RSCN;
	ub_priv->flags |= EMLXS_UB_INTERCEPT;

	ubp->ub_frame.r_ctl = FC_ELS_REQ;
	ubp->ub_frame.type = FC_TYPE_EXTENDED_LS;
	ubp->ub_frame.s_id = 0xfffffd;
	ubp->ub_frame.d_id = LE_SWAP24_LO(port->did);
	ubp->ub_frame.ox_id = ub_priv->token;
	ubp->ub_frame.rx_id = 0xffff;
	ubp->ub_class = FC_TRAN_CLASS3;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
	    "RSCN: sid=fffffd  1 page(s): %08X, 00000000  buffer=%p "
	    "token=%x. Created.", d_id, ubp, ub_priv->token);

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
	emlxs_swap_els_ub(ubp);
#endif /* EMLXS_MODREV2X */

	emlxs_ub_callback(port, ubp);

	return (FC_SUCCESS);

} /* emlxs_generate_rscn() */

#endif /* ULP_PATCH6 */


#ifdef MENLO_SUPPORT
extern int
emlxs_menlo_handle_event(emlxs_hba_t *hba, CHANNEL *cp, IOCBQ *iocbq)
{
	emlxs_port_t *port = &PPORT;
	IOCB *iocb;
	emlxs_buf_t *sbp;
	fc_packet_t *pkt;
	uint32_t cmd_code = 0;
	uint32_t rsp_code = 0;
	menlo_cmd_t *cmd;
	uint32_t *rsp;

	iocb = &iocbq->iocb;

	HBASTATS.CtEvent++;

	sbp = (emlxs_buf_t *)iocbq->sbp;

	if (!sbp) {
		/*
		 * completion with missing xmit command
		 */
		HBASTATS.CtStray++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_stray_ct_completion_msg,
		    "iocbq=%p cmd=0x%x iotag=0x%x status=0x%x perr=0x%x",
		    iocbq, (uint32_t)iocb->ULPCOMMAND,
		    (uint32_t)iocb->ULPIOTAG, iocb->ULPSTATUS,
		    iocb->un.ulpWord[4]);

		return (1);
	}

	if (cp->channelno != hba->channel_ct) {
		HBASTATS.CtStray++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_stray_ct_completion_msg,
		    "Invalid IO channel:%d iocbq=%p", cp->channelno, iocbq);

		return (1);
	}

	port = sbp->iocbq.port;
	pkt = PRIV2PKT(sbp);

	cmd = (menlo_cmd_t *)pkt->pkt_cmd;
	cmd_code = BE_SWAP32(cmd->code);

	/* Check if a response buffer was provided */
	if (pkt->pkt_rsplen) {
		EMLXS_MPDATA_SYNC(pkt->pkt_resp_dma, 0, pkt->pkt_rsplen,
		    DDI_DMA_SYNC_FORKERNEL);
	}

	switch (iocb->ULPCOMMAND) {
	/*
	 * MENLO Command completion
	 */
	case CMD_GEN_REQUEST64_CR:
	case CMD_GEN_REQUEST64_CX:

		HBASTATS.CtCmdCompleted++;

		sbp->pkt_flags |= PACKET_CT_RSP_VALID;

		rsp = (uint32_t *)pkt->pkt_resp;
		rsp_code = *rsp;
		rsp_code = BE_SWAP32(rsp_code);

		if (hba->sli_mode >= EMLXS_HBA_SLI3_MODE) {
			pkt->pkt_resp_resid =
			    pkt->pkt_rsplen - iocb->unsli3.ext_iocb.rsplen;
		} else {
			pkt->pkt_resp_resid =
			    pkt->pkt_rsplen - iocb->un.genreq64.bdl.bdeSize;
		}

		pkt->pkt_data_resid = pkt->pkt_datalen;
		pkt->pkt_cmd_fhdr.rx_id = iocb->ULPCONTEXT;

		if ((iocb->ULPSTATUS == 0) && (rsp_code == MENLO_RSP_SUCCESS)) {
			HBASTATS.CtCmdGood++;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_completion_msg,
			    "%s: %s rxid=0x%x",
			    emlxs_menlo_cmd_xlate(cmd_code),
			    emlxs_menlo_rsp_xlate(rsp_code),
			    iocb->ULPCONTEXT);

		} else {
			HBASTATS.CtCmdError++;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_completion_msg,
			    "%s: %s %s %s rxid=0x%x",
			    emlxs_menlo_cmd_xlate(cmd_code),
			    emlxs_menlo_rsp_xlate(rsp_code),
			    emlxs_state_xlate(iocb->ULPSTATUS),
			    emlxs_error_xlate(iocb->un.grsp.perr.
			    statLocalError), iocb->ULPCONTEXT);
		}

		emlxs_pkt_complete(sbp, iocb->ULPSTATUS,
		    iocb->un.grsp.perr.statLocalError, 1);

		break;

	default:

		HBASTATS.CtStray++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_invalid_ct_msg,
		    "Invalid iocb: cmd=0x%x", iocb->ULPCOMMAND);

		emlxs_pkt_complete(sbp, iocb->ULPSTATUS,
		    iocb->un.grsp.perr.statLocalError, 1);

		break;

	}	/* switch(iocb->ULPCOMMAND) */

	return (0);

} /* emlxs_menlo_handle_event() */

#endif /* MENLO_SUPPORT */


extern int
emlxs_ct_handle_event(emlxs_hba_t *hba, CHANNEL *cp, IOCBQ *iocbq)
{
	emlxs_port_t *port = &PPORT;
	IOCB *iocb;
	emlxs_buf_t *sbp;
	fc_packet_t *pkt;
	uint32_t *rsp;
	SLI_CT_REQUEST *CtRsp;
	SLI_CT_REQUEST *CtCmd;
	uint32_t cmd_code = 0;
	uint32_t rsp_code = 0;

	iocb = &iocbq->iocb;

	HBASTATS.CtEvent++;

	sbp = (emlxs_buf_t *)iocbq->sbp;

	if (!sbp) {
		/*
		 * completion with missing xmit command
		 */
		HBASTATS.CtStray++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_stray_ct_completion_msg,
		    "iocbq=%p cmd=0x%x iotag=0x%x status=0x%x perr=0x%x",
		    iocbq, (uint32_t)iocb->ULPCOMMAND,
		    (uint32_t)iocb->ULPIOTAG, iocb->ULPSTATUS,
		    iocb->un.ulpWord[4]);

		return (1);
	}

	if (cp->channelno != hba->channel_ct) {
		HBASTATS.CtStray++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_stray_ct_completion_msg,
		    "Invalid channel: channel=%d iocbq=%p", cp->channelno,
		    iocbq);

		return (1);
	}

	pkt = PRIV2PKT(sbp);
	port = sbp->iocbq.port;
	CtCmd = (SLI_CT_REQUEST *)pkt->pkt_cmd;
	cmd_code = LE_SWAP16(CtCmd->CommandResponse.bits.CmdRsp);

	if (cmd_code == SLI_CT_LOOPBACK) {
		HBASTATS.CtEvent--;
		return (emlxs_dfc_handle_event(hba, cp, iocbq));
	}

	/* Check if a response buffer was provided */
	if (pkt->pkt_rsplen) {
		EMLXS_MPDATA_SYNC(pkt->pkt_resp_dma, 0, pkt->pkt_rsplen,
		    DDI_DMA_SYNC_FORKERNEL);
	}

	switch (iocb->ULPCOMMAND) {
		/*
		 * CT Reply completion
		 */
	case CMD_XMIT_SEQUENCE_CX:
	case CMD_XMIT_SEQUENCE64_CX:

		HBASTATS.CtRspCompleted++;

		switch (CtCmd->FsType) {
		case 0xFC:	/* Name server */
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_completion_msg,
			    "%s: %s %s", emlxs_ctcmd_xlate(cmd_code),
			    emlxs_state_xlate(iocb->ULPSTATUS),
			    emlxs_error_xlate(iocb->un.grsp.perr.
			    statLocalError));
			break;

		case 0xFA:	/* Managment server */
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_completion_msg,
			    "%s: %s %s", emlxs_mscmd_xlate(cmd_code),
			    emlxs_state_xlate(iocb->ULPSTATUS),
			    emlxs_error_xlate(iocb->un.grsp.perr.
			    statLocalError));
			break;

		case 0x0A:	/* Emulex Remote server */
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_completion_msg,
			    "%s: %s %s", emlxs_rmcmd_xlate(cmd_code),
			    emlxs_state_xlate(iocb->ULPSTATUS),
			    emlxs_error_xlate(iocb->un.grsp.perr.
			    statLocalError));
			break;

		default:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_completion_msg,
			    "%s: %s %s", emlxs_ctcmd_xlate(cmd_code),
			    emlxs_state_xlate(iocb->ULPSTATUS),
			    emlxs_error_xlate(iocb->un.grsp.perr.
			    statLocalError));
		}

		emlxs_pkt_complete(sbp, iocb->ULPSTATUS,
		    iocb->un.grsp.perr.statLocalError, 1);

		break;

		/*
		 * CT Command completion
		 */
	case CMD_GEN_REQUEST64_CR:
	case CMD_GEN_REQUEST64_CX:

		HBASTATS.CtCmdCompleted++;

		sbp->pkt_flags |= PACKET_CT_RSP_VALID;

		rsp = (uint32_t *)pkt->pkt_resp;
		CtRsp = (SLI_CT_REQUEST *)pkt->pkt_resp;
		rsp_code = LE_SWAP16(CtRsp->CommandResponse.bits.CmdRsp);

		if (hba->sli_mode >= EMLXS_HBA_SLI3_MODE) {
			pkt->pkt_resp_resid =
			    pkt->pkt_rsplen - iocb->unsli3.ext_iocb.rsplen;
		} else {
			pkt->pkt_resp_resid =
			    pkt->pkt_rsplen - iocb->un.genreq64.bdl.bdeSize;
		}

		pkt->pkt_data_resid = pkt->pkt_datalen;

		/*
		 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_completion_msg,
		 * "INFO: pkt_resid=%d  %d  %d  %x", pkt->pkt_resp_resid,
		 * pkt->pkt_rsplen, iocb->un.genreq64.bdl.bdeSize,
		 * iocb->un.genreq64.bdl.bdeFlags);
		 */

		if ((iocb->ULPSTATUS == 0) &&
		    (rsp_code == SLI_CT_RESPONSE_FS_ACC)) {
			HBASTATS.CtCmdGood++;

			if (!(sbp->pkt_flags & PACKET_ALLOCATED)) {
				/* ULP patch - ULP expects */
				/* resp_resid = 0 on success */
				pkt->pkt_resp_resid = 0;
			}

			switch (CtCmd->FsType) {
			case 0xFC:	/* Name server */
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_ct_completion_msg,
				    "%s: %s: Rsn=%x Exp=%x [%08x,%08x]",
				    emlxs_ctcmd_xlate(cmd_code),
				    emlxs_ctcmd_xlate(rsp_code),
				    CtRsp->ReasonCode, CtRsp->Explanation,
				    LE_SWAP32(rsp[4]), LE_SWAP32(rsp[5]));

#if (EMLXS_MODREV < EMLXS_MODREV4)
				if (cmd_code == SLI_CTNS_RNN_ID) {
					emlxs_send_rsnn(port);
				}
#endif /* < EMLXS_MODREV4 */

				break;

			case 0xFA:	/* Managment server */
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_ct_completion_msg,
				    "%s: %s: Rsn=%x Exp=%x [%08x,%08x]",
				    emlxs_mscmd_xlate(cmd_code),
				    emlxs_mscmd_xlate(rsp_code),
				    CtRsp->ReasonCode, CtRsp->Explanation,
				    LE_SWAP32(rsp[4]), LE_SWAP32(rsp[5]));
				break;

			case 0x0A:	/* Emulex Remote server */
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_ct_completion_msg,
				    "%s: %s: Rsn=%x Exp=%x [%08x,%08x]",
				    emlxs_rmcmd_xlate(cmd_code),
				    emlxs_rmcmd_xlate(rsp_code),
				    CtRsp->ReasonCode, CtRsp->Explanation,
				    LE_SWAP32(rsp[4]), LE_SWAP32(rsp[5]));
				break;

			default:
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_ct_completion_msg,
				    "%s: %s: Rsn=%x Exp=%x [%08x,%08x]",
				    emlxs_ctcmd_xlate(cmd_code),
				    emlxs_ctcmd_xlate(rsp_code),
				    CtRsp->ReasonCode, CtRsp->Explanation,
				    LE_SWAP32(rsp[4]), LE_SWAP32(rsp[5]));
			}
		} else {
			HBASTATS.CtCmdError++;

			if (rsp_code == SLI_CT_RESPONSE_FS_RJT) {
				pkt->pkt_state = FC_PKT_FS_RJT;
				pkt->pkt_action = FC_ACTION_RETRYABLE;
				pkt->pkt_reason = CtRsp->ReasonCode;
				pkt->pkt_expln = CtRsp->Explanation;
				sbp->pkt_flags |= PACKET_STATE_VALID;

				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_ct_completion_msg,
				    "%s: Rejected. rsn=%x exp=%x",
				    emlxs_ctcmd_xlate(cmd_code),
				    pkt->pkt_reason, pkt->pkt_expln);
			} else if (iocb->ULPSTATUS == IOSTAT_LOCAL_REJECT) {
				switch (CtCmd->FsType) {
				case 0xFC:	/* Name server */
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_ct_completion_msg,
					    "%s: %s %s",
					    emlxs_ctcmd_xlate(cmd_code),
					    emlxs_state_xlate(iocb->
					    ULPSTATUS),
					    emlxs_error_xlate(iocb->un.grsp.
					    perr.statLocalError));
					break;

				case 0xFA:	/* Managment server */
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_ct_completion_msg,
					    "%s: %s %s",
					    emlxs_mscmd_xlate(cmd_code),
					    emlxs_state_xlate(iocb->
					    ULPSTATUS),
					    emlxs_error_xlate(iocb->un.grsp.
					    perr.statLocalError));
					break;

				case 0x0A:	/* Emulex Remote server */
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_ct_completion_msg,
					    "%s: %s %s",
					    emlxs_rmcmd_xlate(cmd_code),
					    emlxs_state_xlate(iocb->
					    ULPSTATUS),
					    emlxs_error_xlate(iocb->un.grsp.
					    perr.statLocalError));
					break;

				default:
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_ct_completion_msg,
					    "%s: %s %s",
					    emlxs_ctcmd_xlate(cmd_code),
					    emlxs_state_xlate(iocb->
					    ULPSTATUS),
					    emlxs_error_xlate(iocb->un.grsp.
					    perr.statLocalError));
				}
			} else {
				switch (CtCmd->FsType) {
				case 0xFC:	/* Name server */
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_ct_completion_msg,
					    "%s: %s (%02x%02x%02x%02x)",
					    emlxs_ctcmd_xlate(cmd_code),
					    emlxs_state_xlate(iocb->
					    ULPSTATUS),
					    iocb->un.grsp.perr.statAction,
					    iocb->un.grsp.perr.statRsn,
					    iocb->un.grsp.perr.statBaExp,
					    iocb->un.grsp.perr.
					    statLocalError);
					break;

				case 0xFA:	/* Managment server */
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_ct_completion_msg,
					    "%s: %s (%02x%02x%02x%02x)",
					    emlxs_mscmd_xlate(cmd_code),
					    emlxs_state_xlate(iocb->
					    ULPSTATUS),
					    iocb->un.grsp.perr.statAction,
					    iocb->un.grsp.perr.statRsn,
					    iocb->un.grsp.perr.statBaExp,
					    iocb->un.grsp.perr.
					    statLocalError);
					break;

				case 0x0A:	/* Emulex Remote server */
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_ct_completion_msg,
					    "%s: %s (%02x%02x%02x%02x)",
					    emlxs_rmcmd_xlate(cmd_code),
					    emlxs_state_xlate(iocb->
					    ULPSTATUS),
					    iocb->un.grsp.perr.statAction,
					    iocb->un.grsp.perr.statRsn,
					    iocb->un.grsp.perr.statBaExp,
					    iocb->un.grsp.perr.
					    statLocalError);
					break;

				default:
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_ct_completion_msg,
					    "%s: %s (%02x%02x%02x%02x)",
					    emlxs_ctcmd_xlate(cmd_code),
					    emlxs_state_xlate(iocb->
					    ULPSTATUS),
					    iocb->un.grsp.perr.statAction,
					    iocb->un.grsp.perr.statRsn,
					    iocb->un.grsp.perr.statBaExp,
					    iocb->un.grsp.perr.
					    statLocalError);
				}
			}
		}

		emlxs_pkt_complete(sbp, iocb->ULPSTATUS,
		    iocb->un.grsp.perr.statLocalError, 1);

		break;

	default:

		HBASTATS.CtStray++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_invalid_ct_msg,
		    "Invalid iocb: cmd=0x%x", iocb->ULPCOMMAND);

		emlxs_pkt_complete(sbp, iocb->ULPSTATUS,
		    iocb->un.grsp.perr.statLocalError, 1);

		break;
	}	/* switch(iocb->ULPCOMMAND) */

	return (0);

} /* emlxs_ct_handle_event() */


extern int
emlxs_ct_handle_unsol_req(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	emlxs_hba_t *hba = HBA;
	IOCB *iocb;
	SLI_CT_REQUEST *CtCmd;
	uint32_t cmd_code;

	iocb = &iocbq->iocb;

	CtCmd = (SLI_CT_REQUEST *)mp->virt;
	cmd_code = LE_SWAP16(CtCmd->CommandResponse.bits.CmdRsp);

	if (cmd_code == SLI_CT_LOOPBACK) {
		int rval;

		rval = emlxs_dfc_handle_unsol_req(port, cp, iocbq, mp, size);

		return (rval);
	}

	HBASTATS.CtCmdReceived++;

	switch (CtCmd->FsType) {
	case 0xFC:	/* Name server */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_ct_msg,
		    "%s: pl=%p size=%d rxid=%x", emlxs_ctcmd_xlate(cmd_code),
		    CtCmd, size, iocb->ULPCONTEXT);
		break;

	case 0xFA:	/* Managment server */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_ct_msg,
		    "%s: pl=%p size=%d rxid=%x", emlxs_mscmd_xlate(cmd_code),
		    CtCmd, size, iocb->ULPCONTEXT);
		break;

	case 0x0A:	/* Emulex Remote server */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_ct_msg,
		    "%s: pl=%p size=%d rxid=%x", emlxs_rmcmd_xlate(cmd_code),
		    CtCmd, size, iocb->ULPCONTEXT);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_ct_msg,
		    "%s: pl=%p size=%d rxid=%x", emlxs_ctcmd_xlate(cmd_code),
		    CtCmd, size, iocb->ULPCONTEXT);
	}

	if (emlxs_log_ct_event(port, (uint8_t *)mp->virt, size,
	    iocb->ULPCONTEXT)) {
		/* Abort the exchange */
		emlxs_abort_ct_exchange(hba, port, iocb->ULPCONTEXT);
	}

	return (0);

} /* emlxs_ct_handle_unsol_req() */


#if (EMLXS_MODREV < EMLXS_MODREV4)
static void
emlxs_send_rsnn(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	SLI_CT_REQUEST *ct;

	if (!(pkt = emlxs_pkt_alloc(port, sizeof (SLI_CT_REQUEST),
	    sizeof (SLI_CT_REQUEST), 0, KM_NOSLEEP))) {
		return;
	}

	pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	pkt->pkt_timeout = (2 * hba->fc_ratov);

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(NAMESERVER_DID);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_UNSOL_CONTROL;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(port->did);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_FC_SERVICES;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_FIRST_SEQ | F_CTL_END_SEQ | F_CTL_SEQ_INITIATIVE;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xffff;
	pkt->pkt_cmd_fhdr.rx_id = 0xffff;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* Build the command */
	ct = (SLI_CT_REQUEST *)pkt->pkt_cmd;

	ct->RevisionId.bits.Revision = SLI_CT_REVISION;
	ct->RevisionId.bits.InId = 0;

	ct->FsType = SLI_CT_DIRECTORY_SERVICE;
	ct->FsSubType = SLI_CT_DIRECTORY_NAME_SERVER;

	ct->CommandResponse.bits.Size = 0;
	ct->CommandResponse.bits.CmdRsp = LE_SWAP16(SLI_CTNS_RSNN_NN);

	bcopy((uint8_t *)&hba->wwnn, (char *)ct->un.rsnn.wwnn, 8);

	ct->un.rsnn.snn_len = strlen(port->snn);
	bcopy(port->snn, (char *)ct->un.rsnn.snn, ct->un.rsnn.snn_len);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ct_send_msg, "Sending RSNN_NN. [%s]",
	    port->snn);

	/* Send the pkt later in another thread */
	if (emlxs_pkt_send(pkt, 0) != FC_SUCCESS) {
		/* Free the pkt */
		emlxs_pkt_free(pkt);
	}

	return;

} /* emlxs_send_rsnn() */
#endif /* < EMLXS_MODREV4 */




extern uint32_t
emlxs_ub_send_login_acc(emlxs_port_t *port, fc_unsol_buf_t *ubp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	ELS_PKT *els;
	uint32_t rval;
	emlxs_ub_priv_t *ub_priv;

	ub_priv = ubp->ub_fca_private;

	if (!(pkt = emlxs_pkt_alloc(port,
	    sizeof (uint32_t) + sizeof (SERV_PARM), 0, 0, KM_NOSLEEP))) {
		return (1);
	}

	/* Common initialization */
	pkt->pkt_tran_type = FC_PKT_OUTBOUND;
	pkt->pkt_timeout = (2 * hba->fc_ratov);

	if ((uint32_t)ubp->ub_class == FC_TRAN_CLASS2) {
		pkt->pkt_tran_flags &= ~FC_TRAN_CLASS3;
		pkt->pkt_tran_flags |= FC_TRAN_CLASS2;
	}

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = ubp->ub_frame.s_id;
	pkt->pkt_cmd_fhdr.r_ctl =
	    R_CTL_EXTENDED_SVC | R_CTL_SOLICITED_CONTROL;
	pkt->pkt_cmd_fhdr.s_id = ubp->ub_frame.d_id;
	pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_XCHG_CONTEXT | F_CTL_LAST_SEQ | F_CTL_END_SEQ;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = (ub_priv->cmd >> ELS_CMD_SHIFT) & 0xff;
	pkt->pkt_cmd_fhdr.rx_id = ubp->ub_frame.rx_id;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* Build the command */
	els = (ELS_PKT *)pkt->pkt_cmd;
	els->elsCode = 0x02;
	bcopy((void *)&port->sparam, (void *)&els->un.logi,
	    sizeof (SERV_PARM));

	if ((rval = emlxs_pkt_send(pkt, 1)) != FC_SUCCESS) {
		/* Free the pkt */
		emlxs_pkt_free(pkt);
	} else {
		ub_priv->flags |= EMLXS_UB_INTERCEPT;
	}

	return (rval);

} /* emlxs_ub_send_login_acc */


extern void
emlxs_send_logo(emlxs_port_t *port, uint32_t d_id)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	ELS_PKT *els;

	if (!(hba->flag & FC_ONLINE_MODE)) {
		return;
	}

	if (hba->state <= FC_LINK_DOWN) {
		return;
	}

	if (!(pkt = emlxs_pkt_alloc(port,
	    sizeof (uint32_t) + sizeof (LOGO),
	    sizeof (uint32_t) + sizeof (LOGO), 0, KM_NOSLEEP))) {
		return;
	}

	pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	pkt->pkt_timeout = (2 * hba->fc_ratov);

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(d_id);
	pkt->pkt_cmd_fhdr.r_ctl =
	    R_CTL_EXTENDED_SVC | R_CTL_SOLICITED_CONTROL;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(port->did);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_FIRST_SEQ | F_CTL_END_SEQ | F_CTL_SEQ_INITIATIVE;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xffff;
	pkt->pkt_cmd_fhdr.rx_id = 0xffff;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* Build the command */
	els = (ELS_PKT *)pkt->pkt_cmd;
	els->elsCode = 0x05;
	els->un.logo.un.nPortId32 = pkt->pkt_cmd_fhdr.s_id;
	bcopy((uint8_t *)&port->wwpn, (uint8_t *)&els->un.logo.portName,
	    8);

	/* Send the pkt now */
	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		/* Free the pkt */
		emlxs_pkt_free(pkt);
	}

	return;

} /* emlxs_send_logo() */
