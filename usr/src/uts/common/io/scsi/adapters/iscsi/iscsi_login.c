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
 * Copyright 2000 by Cisco Systems, Inc.  All rights reserved.
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * iSCSI protocol login and enumeration
 */

#include "iscsi.h"
#include <sys/scsi/adapters/iscsi_protocol.h>
#include <sys/scsi/adapters/iscsi_door.h>

/* internal login protocol interfaces */
static iscsi_status_t iscsi_login(iscsi_conn_t *icp,
    char *buffer, size_t bufsize, uint8_t *status_class,
    uint8_t *status_detail);
static int iscsi_add_text(iscsi_hdr_t *ihp, char *data,
    int max_data_length, char *param, char *value);
static int iscsi_find_key_value(char *param, char *ihp, char *pdu_end,
    char **value_start, char **value_end);
static void iscsi_null_callback(void *user_handle, void *message_handle,
    int auth_status);
static iscsi_status_t iscsi_process_login_response(iscsi_conn_t *icp,
    iscsi_login_rsp_hdr_t *ilrhp, char *data, int max_data_length);
static iscsi_status_t iscsi_make_login_pdu(iscsi_conn_t *icp,
    iscsi_hdr_t *text_pdu, char *data, int max_data_length);
static iscsi_status_t iscsi_update_address(iscsi_conn_t *icp,
    char *address);
static char *iscsi_login_failure_str(uchar_t status_class,
    uchar_t status_detail);
static void iscsi_login_end(iscsi_conn_t *icp,
    iscsi_conn_event_t event, iscsi_task_t *itp);
static iscsi_status_t iscsi_login_connect(iscsi_conn_t *icp);

#define	ISCSI_LOGIN_RETRY_DELAY		5	/* seconds */
#define	ISCSI_LOGIN_POLLING_DELAY	60	/* seconds */

/*
 * +--------------------------------------------------------------------+
 * | External Login Interface						|
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_login_start - connect and perform iscsi protocol login
 */
iscsi_status_t
iscsi_login_start(void *arg)
{
	iscsi_task_t		*itp = (iscsi_task_t *)arg;
	iscsi_status_t		rval	= ISCSI_STATUS_LOGIN_FAILED;
	iscsi_conn_t		*icp;
	iscsi_sess_t		*isp;
	iscsi_hba_t		*ihp;
	char			*buf;
	unsigned char		status_class;
	unsigned char		status_detail;
	int			login_buf_size;
	clock_t			lbolt;

	ASSERT(itp != NULL);
	icp = (iscsi_conn_t *)itp->t_arg;
	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);

login_start:
	/* reset connection statsn */
	icp->conn_expstatsn = 0;
	icp->conn_laststatsn = 0;

	/* sync up authentication information */
	(void) iscsi_sess_set_auth(isp);

	/* sync up login and session parameters */
	if (!ISCSI_SUCCESS(iscsi_conn_sync_params(icp))) {
		/* unable to sync params.  fail connection attempts */
		iscsi_login_end(icp, ISCSI_CONN_EVENT_T30, itp);
		return (ISCSI_STATUS_LOGIN_FAILED);
	}

	/* delay the login process if required */
	lbolt = ddi_get_lbolt();
	if (lbolt < icp->conn_login_min) {
		delay(icp->conn_login_min - lbolt);
	}

	/* Attempt to open TCP connection */
	if (!ISCSI_SUCCESS(iscsi_login_connect(icp))) {
		/* retry this failure */
		goto login_retry;
	}

	/*
	 * allocate response buffer with based on default max
	 * transfer size.  This size might shift during login.
	 */
	login_buf_size = icp->conn_params.max_xmit_data_seg_len;
	buf = kmem_zalloc(login_buf_size, KM_SLEEP);

	/* Start protocol login */
	rval = iscsi_login(icp, buf, login_buf_size,
	    &status_class, &status_detail);

	/* done with buffer */
	kmem_free(buf, login_buf_size);

	/* hard failure in login */
	if (!ISCSI_SUCCESS(rval)) {
		iscsi_net->close(icp->conn_socket);
		/*
		 * We should just give up retry if these failures are
		 * detected.
		 */
		switch (rval) {
		/*
		 * We should just give up retry if these
		 * failures are detected.
		 */
		case ISCSI_STATUS_AUTHENTICATION_FAILED:
		case ISCSI_STATUS_INTERNAL_ERROR:
		case ISCSI_STATUS_VERSION_MISMATCH:
		case ISCSI_STATUS_NEGO_FAIL:
			/* we don't want to retry this failure */
			iscsi_login_end(icp, ISCSI_CONN_EVENT_T30, itp);
			return (ISCSI_STATUS_LOGIN_FAILED);
		default:
			/* retry this failure */
			goto login_retry;
		}
	}

	/* soft failure with reason */
	switch (status_class) {
	case ISCSI_STATUS_CLASS_SUCCESS:
		/* login was successful */
		iscsi_login_end(icp, ISCSI_CONN_EVENT_T5, itp);
		return (ISCSI_STATUS_SUCCESS);
	case ISCSI_STATUS_CLASS_REDIRECT:
		/* Retry at the redirected address */
		iscsi_net->close(icp->conn_socket);
		goto login_start;
	case ISCSI_STATUS_CLASS_TARGET_ERR:
		/* retry this failure */
		cmn_err(CE_WARN, "iscsi connection(%u) login failed - "
		    "%s (0x%02x/0x%02x)", icp->conn_oid,
		    iscsi_login_failure_str(status_class, status_detail),
		    status_class, status_detail);

		iscsi_net->close(icp->conn_socket);
		goto login_retry;
	case ISCSI_STATUS_CLASS_INITIATOR_ERR:
	default:
		/* All other errors are hard failures */
		cmn_err(CE_WARN, "iscsi connection(%u) login failed - "
		    "%s (0x%02x/0x%02x) Target: %s, TPGT: %d",
		    icp->conn_oid,
		    iscsi_login_failure_str(status_class, status_detail),
		    status_class, status_detail, isp->sess_name,
		    isp->sess_tpgt_conf);

		iscsi_net->close(icp->conn_socket);

		/* we don't want to retry this failure */
		iscsi_login_end(icp, ISCSI_CONN_EVENT_T30, itp);
		break;
	}
	return (ISCSI_STATUS_LOGIN_FAILED);

login_retry:
	/* retry this failure if we haven't run out of time */
	if (icp->conn_login_max > ddi_get_lbolt()) {

		if (icp->conn_state == ISCSI_CONN_STATE_POLLING) {
			icp->conn_login_min = ddi_get_lbolt() +
			    SEC_TO_TICK(ISCSI_LOGIN_POLLING_DELAY);
		} else {
			icp->conn_login_min = ddi_get_lbolt() +
			    SEC_TO_TICK(ISCSI_LOGIN_RETRY_DELAY);
		}

		if (itp->t_blocking == B_TRUE) {
			goto login_start;
		} else {
			if (ddi_taskq_dispatch(isp->sess_taskq,
			    (void(*)())iscsi_login_start, itp, DDI_SLEEP) !=
			    DDI_SUCCESS) {
				iscsi_login_end(icp,
				    ISCSI_CONN_EVENT_T7, itp);
			}
			return (ISCSI_STATUS_SUCCESS);
		}
	} else {
		/* Retries exceeded */
		iscsi_login_end(icp, ISCSI_CONN_EVENT_T7, itp);
	}
	return (ISCSI_STATUS_LOGIN_FAILED);
}

static void
iscsi_login_end(iscsi_conn_t *icp, iscsi_conn_event_t event,
    iscsi_task_t *itp)
{
	iscsi_sess_t	*isp;

	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	mutex_enter(&icp->conn_state_mutex);
	(void) iscsi_conn_state_machine(icp, event);
	mutex_exit(&icp->conn_state_mutex);

	/* If login failed reset nego tpgt */
	if (event != ISCSI_CONN_EVENT_T5) {
		isp->sess_tpgt_nego = ISCSI_DEFAULT_TPGT;
	}

	if (itp->t_blocking == B_FALSE) {
		kmem_free(itp, sizeof (iscsi_task_t));
	}
}

/*
 * +--------------------------------------------------------------------+
 * | Begin of protocol login routines					|
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_login - Attempt to login to the target.  The caller
 * must check the status class to determine if the login succeeded.
 * A return of 1 does not mean the login succeeded, it just means
 * this function worked, and the status class is valid info.  This
 * allows the caller to decide whether or not to retry logins, so
 * that we don't have any policy logic here.
 */
static iscsi_status_t
iscsi_login(iscsi_conn_t *icp, char *buffer, size_t bufsize,
    uint8_t *status_class, uint8_t *status_detail)
{
	iscsi_status_t		rval		= ISCSI_STATUS_INTERNAL_ERROR;
	struct iscsi_sess	*isp		= NULL;
	IscsiAuthClient		*auth_client	= NULL;
	int			max_data_length	= 0;
	iscsi_hdr_t		ihp;
	iscsi_login_rsp_hdr_t	*ilrhp = (iscsi_login_rsp_hdr_t *)&ihp;
	char			*data		= NULL;

	ASSERT(icp != NULL);
	ASSERT(buffer != NULL);
	ASSERT(status_class != NULL);
	ASSERT(status_detail != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	/*
	 * prepare the connection
	 */
	icp->conn_current_stage = ISCSI_INITIAL_LOGIN_STAGE;
	icp->conn_partial_response = 0;

	if (isp->sess_auth.auth_buffers &&
	    isp->sess_auth.num_auth_buffers) {

		auth_client = (IscsiAuthClient *)isp->
		    sess_auth.auth_buffers[0].address;

		/*
		 * prepare for authentication
		 */
		if (iscsiAuthClientInit(iscsiAuthNodeTypeInitiator,
		    isp->sess_auth.num_auth_buffers,
		    isp->sess_auth.auth_buffers) !=
		    iscsiAuthStatusNoError) {
			cmn_err(CE_WARN, "iscsi connection(%u) login failed - "
			    "unable to initialize authentication",
			    icp->conn_oid);
			return (ISCSI_STATUS_INTERNAL_ERROR);
		}

		if (iscsiAuthClientSetVersion(auth_client,
		    iscsiAuthVersionRfc) != iscsiAuthStatusNoError) {
			cmn_err(CE_WARN, "iscsi connection(%u) login failed - "
			    "unable to set authentication", icp->conn_oid);
			goto iscsi_login_done;
		}

		if (isp->sess_auth.username &&
		    (iscsiAuthClientSetUsername(auth_client,
		    isp->sess_auth.username) !=
		    iscsiAuthStatusNoError)) {
			cmn_err(CE_WARN, "iscsi connection(%u) login failed - "
			    "unable to set username", icp->conn_oid);
			goto iscsi_login_done;
		}

		if (isp->sess_auth.password &&
		    (iscsiAuthClientSetPassword(auth_client,
		    isp->sess_auth.password, isp->sess_auth.password_length) !=
		    iscsiAuthStatusNoError)) {
			cmn_err(CE_WARN, "iscsi connection(%u) login failed - "
			    "unable to set password", icp->conn_oid);
			goto iscsi_login_done;
		}

		if (iscsiAuthClientSetIpSec(auth_client, 1) !=
		    iscsiAuthStatusNoError) {
			cmn_err(CE_WARN, "iscsi connection(%u) login failed - "
			    "unable to set ipsec", icp->conn_oid);
			goto iscsi_login_done;
		}

		if (iscsiAuthClientSetAuthRemote(auth_client,
		    isp->sess_auth.bidirectional_auth) !=
		    iscsiAuthStatusNoError) {
			cmn_err(CE_WARN, "iscsi connection(%u) login failed - "
			    "unable to set remote authentication",
			    icp->conn_oid);
			goto iscsi_login_done;
		}
	}

	/*
	 * exchange PDUs until the login stage is complete, or an error occurs
	 */
	do {
		/* setup */
		bzero(buffer, bufsize);
		data = buffer;
		max_data_length = bufsize;
		rval = ISCSI_STATUS_INTERNAL_ERROR;

		/*
		 * fill in the PDU header and text data based on the
		 * login stage that we're in
		 */
		rval = iscsi_make_login_pdu(icp, &ihp, data, max_data_length);
		if (!ISCSI_SUCCESS(rval)) {
			cmn_err(CE_WARN, "iscsi connection(%u) login failed - "
			    "unable to make login pdu", icp->conn_oid);
			goto iscsi_login_done;
		}

		/* send a PDU to the target */
		rval = iscsi_net->sendpdu(icp->conn_socket, &ihp, data, 0);
		if (!ISCSI_SUCCESS(rval)) {
			cmn_err(CE_WARN, "iscsi connection(%u) login failed - "
			    "failed to transfer login", icp->conn_oid);
			goto iscsi_login_done;
		}

		/* read the target's response into the same buffer */
		bzero(buffer, bufsize);
		rval = iscsi_net->recvhdr(icp->conn_socket, &ihp,
		    sizeof (ihp), ISCSI_RX_TIMEOUT_VALUE, 0);
		if (!ISCSI_SUCCESS(rval)) {
			if (rval == ISCSI_STATUS_RX_TIMEOUT) {
#define	STRING_FTRLRT "failed to receive login response - timeout"
				cmn_err(CE_WARN,
				    "iscsi connection(%u) login failed - "
				    STRING_FTRLRT,
				    icp->conn_oid);
#undef STRING_FTRLRT
			} else {
				cmn_err(CE_WARN,
				    "iscsi connection(%u) login failed - "
				    "failed to receive login response",
				    icp->conn_oid);
			}
			goto iscsi_login_done;
		}
		isp->sess_rx_lbolt = icp->conn_rx_lbolt = ddi_get_lbolt();

		rval = iscsi_net->recvdata(icp->conn_socket, &ihp,
		    data, max_data_length, ISCSI_RX_TIMEOUT_VALUE, 0);
		if (!ISCSI_SUCCESS(rval)) {
			cmn_err(CE_WARN, "iscsi connection(%u) login failed - "
			    "failed to receive login response",
			    icp->conn_oid);
			goto iscsi_login_done;
		}
		isp->sess_rx_lbolt = icp->conn_rx_lbolt = ddi_get_lbolt();

		/* check the PDU response type */
		if (ihp.opcode != ISCSI_OP_LOGIN_RSP) {
			cmn_err(CE_WARN, "iscsi connection(%u) login failed - "
			    "received invalid login response (0x%02x)",
			    icp->conn_oid, ihp.opcode);
			rval = (ISCSI_STATUS_PROTOCOL_ERROR);
			goto iscsi_login_done;
		}

		/*
		 * give the caller the status class and detail from the
		 * last login response PDU received
		 */
		if (status_class) {
			*status_class = ilrhp->status_class;
		}
		if (status_detail) {
			*status_detail = ilrhp->status_detail;
		}

		switch (ilrhp->status_class) {
		case ISCSI_STATUS_CLASS_SUCCESS:
			/*
			 * process this response and possibly continue
			 * sending PDUs
			 */
			rval = iscsi_process_login_response(icp,
			    ilrhp, data, max_data_length);

			/* pass back whatever error we discovered */
			if (!ISCSI_SUCCESS(rval)) {
				goto iscsi_login_done;
			}

			break;
		case ISCSI_STATUS_CLASS_REDIRECT:
			/*
			 * we need to process this response to get the
			 * TargetAddress of the redirect, but we don't
			 * care about the return code.
			 */
			(void) iscsi_process_login_response(icp, ilrhp,
			    data, max_data_length);
			rval = ISCSI_STATUS_SUCCESS;
			goto iscsi_login_done;
		case ISCSI_STATUS_CLASS_INITIATOR_ERR:
			if (ilrhp->status_detail ==
			    ISCSI_LOGIN_STATUS_AUTH_FAILED) {
				cmn_err(CE_WARN, "iscsi connection(%u) login "
				    "failed - login failed to authenticate "
				    "with target", icp->conn_oid);
			}
			rval = ISCSI_STATUS_SUCCESS;
			goto iscsi_login_done;
		default:
			/*
			 * some sort of error, login terminated unsuccessfully,
			 * though this function did it's job. the caller must
			 * check the status_class and status_detail and decide
			 * what to do next.
			 */
			rval = ISCSI_STATUS_SUCCESS;
			goto iscsi_login_done;
		}

	} while (icp->conn_current_stage != ISCSI_FULL_FEATURE_PHASE);

	rval = ISCSI_STATUS_SUCCESS;

iscsi_login_done:
	if (auth_client) {
		if (iscsiAuthClientFinish(auth_client) !=
		    iscsiAuthStatusNoError) {
			cmn_err(CE_WARN, "iscsi connection(%u) login "
			    "failed - login failed to authenticate "
			    "with target", icp->conn_oid);
			if (ISCSI_SUCCESS(rval))
				rval = ISCSI_STATUS_INTERNAL_ERROR;
		}
	}
	return (rval);
}


/*
 * iscsi_make_login_pdu -
 *
 */
static iscsi_status_t
iscsi_make_login_pdu(iscsi_conn_t *icp, iscsi_hdr_t *ihp,
    char *data, int max_data_length)
{
	struct iscsi_sess	*isp		= NULL;
	int			transit		= 0;
	iscsi_login_hdr_t	*ilhp		= (iscsi_login_hdr_t *)ihp;
	IscsiAuthClient		*auth_client	= NULL;
	int			keytype		= 0;
	int			rc		= 0;
	char			value[iscsiAuthStringMaxLength];

	ASSERT(icp != NULL);
	ASSERT(ihp != NULL);
	ASSERT(data != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	auth_client =
	    (isp->sess_auth.auth_buffers && isp->sess_auth.num_auth_buffers) ?
	    (IscsiAuthClient *)isp->sess_auth.auth_buffers[0].address : NULL;

	/*
	 * initialize the PDU header
	 */
	bzero(ilhp, sizeof (*ilhp));
	ilhp->opcode = ISCSI_OP_LOGIN_CMD | ISCSI_OP_IMMEDIATE;
	ilhp->cid = icp->conn_cid;
	bcopy(&isp->sess_isid[0], &ilhp->isid[0], sizeof (isp->sess_isid));
	ilhp->tsid = 0;

	/* don't increment on immediate */
	ilhp->cmdsn = htonl(isp->sess_cmdsn);

	ilhp->min_version = ISCSI_DRAFT20_VERSION;
	ilhp->max_version = ISCSI_DRAFT20_VERSION;

	/*
	 * we have to send 0 until full-feature stage
	 */
	ilhp->expstatsn = htonl(icp->conn_expstatsn);

	/*
	 * the very first Login PDU has some additional requirements,
	 * * and we need to decide what stage to start in.
	 */
	if (icp->conn_current_stage == ISCSI_INITIAL_LOGIN_STAGE) {
		if ((isp->sess_hba->hba_name) &&
		    (isp->sess_hba->hba_name[0])) {
			if (!iscsi_add_text(ihp, data, max_data_length,
			    "InitiatorName",
			    (char *)isp->sess_hba->hba_name)) {
				return (ISCSI_STATUS_INTERNAL_ERROR);
			}
		} else {
			cmn_err(CE_WARN, "iscsi connection(%u) login "
			    "failed - initiator name is required",
			    icp->conn_oid);
			return (ISCSI_STATUS_INTERNAL_ERROR);
		}

		if ((isp->sess_hba->hba_alias) &&
		    (isp->sess_hba->hba_alias[0])) {
			if (!iscsi_add_text(ihp, data, max_data_length,
			    "InitiatorAlias",
			    (char *)isp->sess_hba->hba_alias)) {
				return (ISCSI_STATUS_INTERNAL_ERROR);
			}
		}

		if (isp->sess_type == ISCSI_SESS_TYPE_NORMAL) {
			if (isp->sess_name[0] != '\0') {
				if (!iscsi_add_text(ihp, data, max_data_length,
				    "TargetName", (char *)isp->sess_name)) {
					return (ISCSI_STATUS_INTERNAL_ERROR);
				}
			}

			if (!iscsi_add_text(ihp, data, max_data_length,
			    "SessionType", "Normal")) {
				return (ISCSI_STATUS_INTERNAL_ERROR);
			}
		} else if (isp->sess_type == ISCSI_SESS_TYPE_DISCOVERY) {
			if (!iscsi_add_text(ihp, data, max_data_length,
			    "SessionType", "Discovery")) {
				return (ISCSI_STATUS_INTERNAL_ERROR);
			}
		} else {
			return (ISCSI_STATUS_INTERNAL_ERROR);
		}

		if (auth_client) {
			/* we're prepared to do authentication */
			icp->conn_current_stage =
			    ISCSI_SECURITY_NEGOTIATION_STAGE;
		} else {
			/* can't do any authentication, skip that stage */
			icp->conn_current_stage =
			    ISCSI_OP_PARMS_NEGOTIATION_STAGE;
		}
	}

	/*
	 * fill in text based on the stage
	 */
	switch (icp->conn_current_stage) {
	case ISCSI_OP_PARMS_NEGOTIATION_STAGE:
		/*
		 * we always try to go from op params to full
		 * feature stage
		 */
		icp->conn_next_stage	= ISCSI_FULL_FEATURE_PHASE;
		transit			= 1;

		/*
		 * The terminology here may have gotten dated.  A partial
		 * response is a login response that doesn't complete a
		 * login.  If we haven't gotten a partial response, then
		 * either we shouldn't be here, or we just switched to
		 * this stage, and need to start offering keys.
		 */
		if (!icp->conn_partial_response) {
			/*
			 * request the desired settings the first time
			 * we are in this stage
			 */
			switch (icp->conn_params.header_digest) {
			case ISCSI_DIGEST_NONE:
				if (!iscsi_add_text(ihp, data,
				    max_data_length, "HeaderDigest", "None")) {
					return (ISCSI_STATUS_INTERNAL_ERROR);
				}
				break;
			case ISCSI_DIGEST_CRC32C:
				if (!iscsi_add_text(ihp, data,
				    max_data_length,
				    "HeaderDigest", "CRC32C")) {
					return (ISCSI_STATUS_INTERNAL_ERROR);
				}
				break;
			case ISCSI_DIGEST_CRC32C_NONE:
				if (!iscsi_add_text(ihp, data,
				    max_data_length, "HeaderDigest",
				    "CRC32C,None")) {
					return (ISCSI_STATUS_INTERNAL_ERROR);
				}
				break;
			default:
			case ISCSI_DIGEST_NONE_CRC32C:
				if (!iscsi_add_text(ihp, data,
				    max_data_length, "HeaderDigest",
				    "None,CRC32C")) {
					return (ISCSI_STATUS_INTERNAL_ERROR);
				}
				break;
			}

			switch (icp->conn_params.data_digest) {
			case ISCSI_DIGEST_NONE:
				if (!iscsi_add_text(ihp, data,
				    max_data_length, "DataDigest", "None")) {
					return (ISCSI_STATUS_INTERNAL_ERROR);
				}
				break;
			case ISCSI_DIGEST_CRC32C:
				if (!iscsi_add_text(ihp, data,
				    max_data_length, "DataDigest", "CRC32C")) {
					return (ISCSI_STATUS_INTERNAL_ERROR);
				}
				break;
			case ISCSI_DIGEST_CRC32C_NONE:
				if (!iscsi_add_text(ihp, data,
				    max_data_length, "DataDigest",
				    "CRC32C,None")) {
					return (ISCSI_STATUS_INTERNAL_ERROR);
				}
				break;
			default:
			case ISCSI_DIGEST_NONE_CRC32C:
				if (!iscsi_add_text(ihp, data,
				    max_data_length, "DataDigest",
				    "None,CRC32C")) {
					return (ISCSI_STATUS_INTERNAL_ERROR);
				}
				break;
			}

			(void) sprintf(value, "%d",
			    icp->conn_params.max_recv_data_seg_len);
			if (!iscsi_add_text(ihp, data, max_data_length,
			    "MaxRecvDataSegmentLength", value)) {
				return (ISCSI_STATUS_INTERNAL_ERROR);
			}

			(void) sprintf(value, "%d",
			    icp->conn_params.default_time_to_wait);
			if (!iscsi_add_text(ihp, data,
			    max_data_length, "DefaultTime2Wait", value)) {
				return (ISCSI_STATUS_INTERNAL_ERROR);
			}

			(void) sprintf(value, "%d",
			    icp->conn_params.default_time_to_retain);
			if (!iscsi_add_text(ihp, data,
			    max_data_length, "DefaultTime2Retain", value)) {
				return (ISCSI_STATUS_INTERNAL_ERROR);
			}

			(void) sprintf(value, "%d",
			    icp->conn_params.error_recovery_level);
			if (!iscsi_add_text(ihp, data,
			    max_data_length, "ErrorRecoveryLevel", "0")) {
				return (ISCSI_STATUS_INTERNAL_ERROR);
			}

			if (!iscsi_add_text(ihp, data,
			    max_data_length, "IFMarker",
			    icp->conn_params.ifmarker ? "Yes" : "No")) {
				return (ISCSI_STATUS_INTERNAL_ERROR);
			}

			if (!iscsi_add_text(ihp, data,
			    max_data_length, "OFMarker",
			    icp->conn_params.ofmarker ? "Yes" : "No")) {
				return (ISCSI_STATUS_INTERNAL_ERROR);
			}

			/*
			 * The following login parameters are "Irrelevant"
			 * for discovery sessions
			 */
			if (isp->sess_type != ISCSI_SESS_TYPE_DISCOVERY) {

				if (!iscsi_add_text(ihp, data,
				    max_data_length, "InitialR2T",
				    icp->conn_params.initial_r2t ?
				    "Yes" : "No")) {
					return (ISCSI_STATUS_INTERNAL_ERROR);
				}

				if (!iscsi_add_text(ihp, data,
				    max_data_length, "ImmediateData",
				    icp->conn_params.immediate_data ?
				    "Yes" : "No")) {
					return (ISCSI_STATUS_INTERNAL_ERROR);
				}

				(void) sprintf(value, "%d",
				    icp->conn_params.max_burst_length);
				if (!iscsi_add_text(ihp, data,
				    max_data_length, "MaxBurstLength", value)) {
					return (ISCSI_STATUS_INTERNAL_ERROR);
				}

				(void) sprintf(value, "%d",
				    icp->conn_params.first_burst_length);
				if (!iscsi_add_text(ihp, data, max_data_length,
				    "FirstBurstLength", value)) {
					return (ISCSI_STATUS_INTERNAL_ERROR);
				}

				(void) sprintf(value, "%d",
				    icp->conn_params.max_outstanding_r2t);
				if (!iscsi_add_text(ihp, data, max_data_length,
				    "MaxOutstandingR2T", value)) {
					return (ISCSI_STATUS_INTERNAL_ERROR);
				}

				(void) sprintf(value, "%d",
				    icp->conn_params.max_connections);
				if (!iscsi_add_text(ihp, data, max_data_length,
				    "MaxConnections", value)) {
					return (ISCSI_STATUS_INTERNAL_ERROR);
				}

				if (!iscsi_add_text(ihp, data,
				    max_data_length, "DataPDUInOrder",
				    icp->conn_params.data_pdu_in_order ?
				    "Yes" : "No")) {
					return (ISCSI_STATUS_INTERNAL_ERROR);
				}

				if (!iscsi_add_text(ihp, data,
				    max_data_length, "DataSequenceInOrder",
				    icp->conn_params.data_sequence_in_order ?
				    "Yes" : "No")) {
					return (ISCSI_STATUS_INTERNAL_ERROR);
				}
			}
		}
		break;

	case ISCSI_SECURITY_NEGOTIATION_STAGE:
		keytype = iscsiAuthKeyTypeNone;
		rc = iscsiAuthClientSendTransitBit(auth_client, &transit);

		/*
		 * see if we're ready for a stage change
		 */
		if (rc == iscsiAuthStatusNoError) {
			if (transit) {
				icp->conn_next_stage =
				    ISCSI_OP_PARMS_NEGOTIATION_STAGE;
			} else {
				icp->conn_next_stage =
				    ISCSI_SECURITY_NEGOTIATION_STAGE;
			}
		} else {
			return (ISCSI_STATUS_INTERNAL_ERROR);
		}

		/*
		 * enumerate all the keys the auth code might want to send
		 */
		while (iscsiAuthClientGetNextKeyType(&keytype) ==
		    iscsiAuthStatusNoError) {
			int present = 0;
			char *key = (char *)iscsiAuthClientGetKeyName(keytype);
			int key_length = key ? strlen(key) : 0;
			int pdu_length = ntoh24(ihp->dlength);
			char *auth_value = data + pdu_length + key_length + 1;
			unsigned int max_length = max_data_length -
			    (pdu_length + key_length + 1);

			/*
			 * add the key/value pairs the auth code wants to
			 * send directly to the PDU, since they could in
			 * theory be large.
			 */
			rc = iscsiAuthClientSendKeyValue(auth_client, keytype,
			    &present, auth_value, max_length);
			if ((rc == iscsiAuthStatusNoError) && present) {
				/*
				 * actually fill in the key
				 */
				(void) strncpy(&data[pdu_length], key,
				    key_length);
				pdu_length += key_length;
				data[pdu_length] = '=';
				pdu_length++;
				/*
				 * adjust the PDU's data segment length to
				 * include the value and trailing NULL
				 */
				pdu_length += strlen(auth_value) + 1;
				hton24(ihp->dlength, pdu_length);
			}
		}

		break;
	case ISCSI_FULL_FEATURE_PHASE:
		cmn_err(CE_WARN, "iscsi connection(%u) login "
		    "failed - can't send login in full feature stage",
		    icp->conn_oid);
		return (ISCSI_STATUS_INTERNAL_ERROR);
	default:
		cmn_err(CE_WARN, "iscsi connection(%u) login "
		    "failed - can't send login in unknown stage (%d)",
		    icp->conn_oid, icp->conn_current_stage);
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	/* fill in the flags */
	ilhp->flags = icp->conn_current_stage << 2;
	if (transit) {
		/* transit to the next stage */
		ilhp->flags |= icp->conn_next_stage;
		ilhp->flags |= ISCSI_FLAG_LOGIN_TRANSIT;
	} else {
		/* next == current */
		ilhp->flags |= icp->conn_current_stage;
	}

	return (ISCSI_STATUS_SUCCESS);
}


/*
 * iscsi_process_login_response - This assumes the text data is
 * always NUL terminated.  The caller can always arrange for that by
 * using a slightly larger buffer than the max PDU size, and then
 * appending a NUL to the PDU.
 */
static iscsi_status_t
iscsi_process_login_response(iscsi_conn_t *icp,
    iscsi_login_rsp_hdr_t *ilrhp, char *data, int max_data_length)
{
	iscsi_sess_t		*isp			= NULL;
	IscsiAuthClient		*auth_client		= NULL;
	int			transit			= 0;
	char			*text			= data;
	char			*end			= NULL;
	int			pdu_current_stage	= 0;
	int			pdu_next_stage		= 0;
	int			debug_status		= 0;
	unsigned long		tmp;
	char			*tmpe;
	boolean_t		fbl_irrelevant		= B_FALSE;

	ASSERT(icp != NULL);
	ASSERT(ilrhp != NULL);
	ASSERT(data != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	auth_client =
	    (isp->sess_auth.auth_buffers && isp->sess_auth.num_auth_buffers) ?
	    (IscsiAuthClient *) isp->sess_auth.auth_buffers[0].address : NULL;
	transit = ilrhp->flags & ISCSI_FLAG_LOGIN_TRANSIT;

	/* verify the initial buffer was big enough to hold everything */
	end = text + ntoh24(ilrhp->dlength) + 1;
	if (end >= (data + max_data_length)) {
		cmn_err(CE_WARN, "iscsi connection(%u) login failed - "
		    "buffer too small", icp->conn_oid);
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}
	*end = '\0';

	/* if the response status was success, sanity check the response */
	if (ilrhp->status_class == ISCSI_STATUS_CLASS_SUCCESS) {
		/* check the active version */
		if (ilrhp->active_version != ISCSI_DRAFT20_VERSION) {
			cmn_err(CE_WARN, "iscsi connection(%u) login "
			    "failed - target version incompatible "
			    "received:0x%0x2x expected:0x%02x",
			    icp->conn_oid, ilrhp->active_version,
			    ISCSI_DRAFT20_VERSION);
			return (ISCSI_STATUS_VERSION_MISMATCH);
		}

		/* make sure the current stage matches */
		pdu_current_stage = (ilrhp->flags &
		    ISCSI_FLAG_LOGIN_CURRENT_STAGE_MASK) >> 2;
		if (pdu_current_stage != icp->conn_current_stage) {
			cmn_err(CE_WARN, "iscsi connection(%u) login "
			    "failed - login response contained invalid "
			    "stage %d", icp->conn_oid, pdu_current_stage);
			return (ISCSI_STATUS_PROTOCOL_ERROR);
		}

		/*
		 * Make sure that we're actually advancing
		 * if the T-bit is set
		 */
		pdu_next_stage = ilrhp->flags &
		    ISCSI_FLAG_LOGIN_NEXT_STAGE_MASK;
		if (transit && (pdu_next_stage <= icp->conn_current_stage)) {
			cmn_err(CE_WARN, "iscsi connection(%u) login "
			    "failed - login response wants to go to stage "
			    "%d, but we want stage %d", icp->conn_oid,
			    pdu_next_stage, icp->conn_next_stage);
			return (ISCSI_STATUS_PROTOCOL_ERROR);
		}
	}

	if (icp->conn_current_stage == ISCSI_SECURITY_NEGOTIATION_STAGE) {
		if (iscsiAuthClientRecvBegin(auth_client) !=
		    iscsiAuthStatusNoError) {
			cmn_err(CE_WARN, "iscsi connection(%u) login failed - "
			    "authentication receive failed", icp->conn_oid);
			return (ISCSI_STATUS_INTERNAL_ERROR);
		}

		if (iscsiAuthClientRecvTransitBit(auth_client,
		    transit) != iscsiAuthStatusNoError) {
			cmn_err(CE_WARN, "iscsi connection(%u) login failed - "
			    "authentication transmit failed", icp->conn_oid);
			return (ISCSI_STATUS_INTERNAL_ERROR);
		}
	}

	/*
	 * scan the text data
	 */
more_text:
	while (text && (text < end)) {
		char *value = NULL;
		char *value_end = NULL;

		/*
		 * skip any NULs separating each text key=value pair
		 */
		while ((text < end) && (*text == '\0')) {
			text++;
		}
		if (text >= end) {
			break;
		}

		/*
		 * handle keys appropriate for each stage
		 */
		switch (icp->conn_current_stage) {
		case ISCSI_SECURITY_NEGOTIATION_STAGE:
			/*
			 * a few keys are possible in Security stage
			 * * which the auth code doesn't care about,
			 * * but which we might want to see, or at
			 * * least not choke on.
			 */
			if (iscsi_find_key_value("TargetAlias",
			    text, end, &value, &value_end)) {
				isp->sess_alias_length =
				    sizeof (isp->sess_alias) - 1;

				if ((value_end - value) <
				    isp->sess_alias_length) {
					isp->sess_alias_length =
					    value_end - value;
				}

				bcopy(value, isp->sess_alias,
				    isp->sess_alias_length);
				isp->sess_alias[isp->sess_alias_length + 1] =
				    '\0';
				text = value_end;

			} else if (iscsi_find_key_value("TargetAddress",
			    text, end, &value, &value_end)) {
				if (!ISCSI_SUCCESS(iscsi_update_address(
				    icp, value))) {
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - login redirection "
					    "invalid", icp->conn_oid);
					return (ISCSI_STATUS_PROTOCOL_ERROR);
				}
				text = value_end;
			} else if (iscsi_find_key_value("TargetPortalGroupTag",
			    text, end, &value, &value_end)) {
				/*
				 * We should have already obtained this via
				 * discovery.  We've already picked an isid,
				 * so the most we can do is confirm we reached
				 * the portal group we were expecting to.
				 */
				if (ddi_strtoul(value, &tmpe, 0, &tmp) != 0) {
					return (ISCSI_STATUS_PROTOCOL_ERROR);
				}
				if (isp->sess_tpgt_conf != ISCSI_DEFAULT_TPGT) {
					if (tmp != isp->sess_tpgt_conf) {

	cmn_err(CE_WARN, "iscsi connection(%u) login failed - target "
	    "protocol group tag mismatch, expected %d, received %lu",
	    icp->conn_oid, isp->sess_tpgt_conf, tmp);
	return (ISCSI_STATUS_PROTOCOL_ERROR);

					}
				}
				isp->sess_tpgt_nego = (int)tmp;
				text = value_end;
			} else {
				/*
				 * any key we don't recognize either goes
				 * to the auth code, or we choke on it
				 */
				int keytype = iscsiAuthKeyTypeNone;

				while (iscsiAuthClientGetNextKeyType(
				    &keytype) == iscsiAuthStatusNoError) {

					char *key =
					    (char *)iscsiAuthClientGetKeyName(
					    keytype);

					if ((key) &&
					    (iscsi_find_key_value(key,
					    text, end, &value, &value_end))) {

						if (iscsiAuthClientRecvKeyValue
						    (auth_client, keytype,
						    value) !=
						    iscsiAuthStatusNoError) {

	cmn_err(CE_WARN, "iscsi connection(%u) login failed - can't accept "
	    "%s in security stage", icp->conn_oid, text);
	return (ISCSI_STATUS_NEGO_FAIL);

						}
						text = value_end;
						goto more_text;
					}
				}

	cmn_err(CE_WARN, "iscsi connection(%u) login failed - can't except "
	    "%s in security stage", icp->conn_oid, text);

				return (ISCSI_STATUS_NEGO_FAIL);
			}
			break;
		case ISCSI_OP_PARMS_NEGOTIATION_STAGE:
			if (iscsi_find_key_value("TargetAlias", text,
			    end, &value, &value_end)) {
				isp->sess_alias_length =
				    sizeof (isp->sess_alias) - 1;

				if ((value_end - value) <
				    isp->sess_alias_length) {
					isp->sess_alias_length =
					    value_end - value;
				}

				bcopy(value, isp->sess_alias,
				    isp->sess_alias_length);
				isp->sess_alias[isp->sess_alias_length + 1] =
				    '\0';
				text = value_end;

			} else if (iscsi_find_key_value("TargetAddress",
			    text, end, &value, &value_end)) {
				if (!ISCSI_SUCCESS(iscsi_update_address(
				    icp, value))) {

	cmn_err(CE_WARN, "iscsi connection(%u) login failed - login "
	    "redirection invalid", icp->conn_oid);

					return (ISCSI_STATUS_PROTOCOL_ERROR);
				}
				text = value_end;
			} else if (iscsi_find_key_value("TargetPortalGroupTag",
			    text, end, &value, &value_end)) {
				/*
				 * We should have already obtained this via
				 * discovery.  We've already picked an isid,
				 * so the most we can do is confirm we reached
				 * the portal group we were expecting to.
				 */
				if (ddi_strtoul(value, &tmpe, 0, &tmp) != 0) {
					return (ISCSI_STATUS_PROTOCOL_ERROR);
				}
				if (isp->sess_tpgt_conf != ISCSI_DEFAULT_TPGT) {
					if (tmp != isp->sess_tpgt_conf) {

	cmn_err(CE_WARN, "iscsi connection(%u) login failed - target portal "
	    "tag mismatch, expected:%d received:%lu", icp->conn_oid,
	    isp->sess_tpgt_conf, tmp);
	return (ISCSI_STATUS_PROTOCOL_ERROR);

					}
				}
				isp->sess_tpgt_nego = (int)tmp;
				text = value_end;

			} else if (iscsi_find_key_value("InitialR2T",
			    text, end, &value, &value_end)) {

				/*
				 * iSCSI RFC section 12.10 states that
				 * InitialR2T is Irrelevant for a
				 * discovery session.
				 */
				if (isp->sess_type ==
				    ISCSI_SESS_TYPE_DISCOVERY) {
					/* EMPTY */
				} else if (value == NULL) {
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - InitialR2T is "
					    "invalid - protocol error",
					    icp->conn_oid);
					return (ISCSI_STATUS_PROTOCOL_ERROR);
				} else if (strcmp(value, "Yes") == 0) {
					icp->conn_params.initial_r2t = B_TRUE;
				} else if (strcmp(value, "No") == 0) {
					icp->conn_params.initial_r2t = B_FALSE;
				} else {
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - InitialR2T  is "
					    "invalid - protocol error",
					    icp->conn_oid);
					return (ISCSI_STATUS_PROTOCOL_ERROR);
				}
				text = value_end;

			} else if (iscsi_find_key_value("ImmediateData",
			    text, end, &value, &value_end)) {

				/*
				 * iSCSI RFC section 12.11 states that
				 * ImmediateData is Irrelevant for a
				 * discovery session.
				 */
				if (isp->sess_type ==
				    ISCSI_SESS_TYPE_DISCOVERY) {
					/* EMPTY */
				} else if (value == NULL) {
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - ImmediateData is "
					    "invalid - protocol error",
					    icp->conn_oid);
					return (ISCSI_STATUS_PROTOCOL_ERROR);
				} else if (strcmp(value, "Yes") == 0) {
					icp->conn_params.immediate_data = 1;
				} else if (strcmp(value, "No") == 0) {
					icp->conn_params.immediate_data = 0;
				} else {
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - ImmediateData is "
					    "invalid - protocol error",
					    icp->conn_oid);
					return (ISCSI_STATUS_PROTOCOL_ERROR);
				}
				text = value_end;

			} else if (iscsi_find_key_value(
			    "MaxRecvDataSegmentLength", text, end,
			    &value, &value_end)) {

				if (ddi_strtoul(value, &tmpe, 0, &tmp) != 0) {
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - MaxRecvDataSegment"
					    "Length is invalid - protocol "
					    "error", icp->conn_oid);
					return (ISCSI_STATUS_NEGO_FAIL);
				}
				icp->conn_params.max_recv_data_seg_len =
				    icp->conn_params.max_xmit_data_seg_len =
				    (int)tmp;

				text = value_end;
			} else if (iscsi_find_key_value("FirstBurstLength",
			    text, end, &value, &value_end)) {

				/*
				 * iSCSI RFC section 12.14 states that
				 * FirstBurstLength is Irrelevant if
				 * InitialR2T=Yes and ImmediateData=No
				 * or is this is a discovery session.
				 */
				if ((isp->sess_type ==
				    ISCSI_SESS_TYPE_DISCOVERY)) {
					/* EMPTY */
				} else if (value &&
				    (strcmp(value, "Irrelevant") == 0)) {
					/* irrelevant */
					fbl_irrelevant = B_TRUE;
				} else if (ddi_strtoul(
				    value, &tmpe, 0, &tmp) != 0) {
					/* bad value */
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - FirstBurstLength"
					    "is invalid - protocol error",
					    icp->conn_oid);
					return (ISCSI_STATUS_PROTOCOL_ERROR);
				} else {
					/* good value */
					icp->conn_params.first_burst_length =
					    (int)tmp;
				}
				text = value_end;
			} else if (iscsi_find_key_value("MaxBurstLength",
			    text, end, &value, &value_end)) {
				/*
				 * iSCSI RFC section 12.13 states that
				 * MaxBurstLength is Irrelevant for a
				 * discovery session.
				 */
				if (isp->sess_type ==
				    ISCSI_SESS_TYPE_DISCOVERY) {
					/* EMPTY */
				} else if (ddi_strtoul(
				    value, &tmpe, 0, &tmp) != 0) {
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - MaxBurstLength"
					    "is invalid - protocol error",
					    icp->conn_oid);
					return (ISCSI_STATUS_PROTOCOL_ERROR);
				} else {
					icp->conn_params.max_burst_length =
					    (int)tmp;
				}

				text = value_end;

			} else if (iscsi_find_key_value("HeaderDigest",
			    text, end, &value, &value_end)) {

				if (strcmp(value, "None") == 0) {
					if (icp->conn_params.header_digest !=
					    ISCSI_DIGEST_CRC32C) {
						icp->conn_params.header_digest =
						    ISCSI_DIGEST_NONE;
					} else {
						cmn_err(CE_WARN, "iscsi "
						    "connection(%u) login "
						    "failed - HeaderDigest="
						    "CRC32 is required, can't "
						    "accept %s",
						    icp->conn_oid, text);
						return (ISCSI_STATUS_NEGO_FAIL);
					}
				} else if (strcmp(value, "CRC32C") == 0) {
					if (icp->conn_params.header_digest !=
					    ISCSI_DIGEST_NONE) {
						icp->conn_params.header_digest =
						    ISCSI_DIGEST_CRC32C;
					} else {
						cmn_err(CE_WARN, "iscsi "
						    "connection(%u) login "
						    "failed - HeaderDigest="
						    "None is required, can't "
						    "accept %s",
						    icp->conn_oid, text);
						return (ISCSI_STATUS_NEGO_FAIL);
					}
				} else {
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - HeaderDigest "
					    "can't accept %s", icp->conn_oid,
					    text);
					return (ISCSI_STATUS_NEGO_FAIL);
				}
				text = value_end;
			} else if (iscsi_find_key_value("DataDigest", text,
			    end, &value, &value_end)) {

				if (strcmp(value, "None") == 0) {
					if (icp->conn_params.data_digest !=
					    ISCSI_DIGEST_CRC32C) {
						icp->conn_params.data_digest =
						    ISCSI_DIGEST_NONE;
					} else {
						cmn_err(CE_WARN, "iscsi "
						    "connection(%u) login "
						    "failed - DataDigest="
						    "CRC32C is required, "
						    "can't accept %s",
						    icp->conn_oid, text);
						return (ISCSI_STATUS_NEGO_FAIL);
					}
				} else if (strcmp(value, "CRC32C") == 0) {
					if (icp->conn_params.data_digest !=
					    ISCSI_DIGEST_NONE) {
						icp->conn_params.data_digest =
						    ISCSI_DIGEST_CRC32C;
					} else {
						cmn_err(CE_WARN, "iscsi "
						    "connection(%u) login "
						    "failed - DataDigest=None "
						    "is required, can't "
						    "accept %s",
						    icp->conn_oid, text);
						return (ISCSI_STATUS_NEGO_FAIL);
					}
				} else {
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - can't accept %s",
					    icp->conn_oid, text);
					return (ISCSI_STATUS_NEGO_FAIL);
				}
				text = value_end;

			} else if (iscsi_find_key_value("DefaultTime2Wait",
			    text, end, &value, &value_end)) {

				if (ddi_strtoul(value, &tmpe, 0, &tmp) != 0) {
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - DefaultTime2Wait "
					    "is invalid - protocol error",
					    icp->conn_oid);
					return (ISCSI_STATUS_PROTOCOL_ERROR);
				}
				icp->conn_params.default_time_to_wait =
				    (int)tmp;

				text = value_end;

			} else if (iscsi_find_key_value("DefaultTime2Retain",
			    text, end, &value, &value_end)) {

				if (ddi_strtoul(value, &tmpe, 0, &tmp) != 0) {
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - DefaultTime2Retain "
					    "is invalid - protocol error",
					    icp->conn_oid);
					return (ISCSI_STATUS_PROTOCOL_ERROR);
				}
				icp->conn_params.default_time_to_retain =
				    (int)tmp;

				text = value_end;

			} else if (iscsi_find_key_value("OFMarker", text,
			    end, &value, &value_end)) {

				/*
				 * result function is AND, target must
				 * honor our No
				 */
				text = value_end;

			} else if (iscsi_find_key_value("OFMarkInt", text,
			    end, &value, &value_end)) {

				/*
				 * we don't do markers, so we don't care
				 */
				text = value_end;

			} else if (iscsi_find_key_value("IFMarker", text,
			    end, &value, &value_end)) {

				/*
				 * result function is AND, target must
				 * honor our No
				 */
				text = value_end;

			} else if (iscsi_find_key_value("IFMarkInt", text,
			    end, &value, &value_end)) {

				/*
				 * we don't do markers, so we don't care
				 */
				text = value_end;

			} else if (iscsi_find_key_value("DataPDUInOrder",
			    text, end, &value, &value_end)) {

				/*
				 * iSCSI RFC section 12.18 states that
				 * DataPDUInOrder is Irrelevant for a
				 * discovery session.
				 */
				if (isp->sess_type ==
				    ISCSI_SESS_TYPE_DISCOVERY) {
					/* EMPTY */
				} else if (value == NULL) {
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - InitialR2T is "
					    "invalid - protocol error",
					    icp->conn_oid);
					return (ISCSI_STATUS_PROTOCOL_ERROR);
				} else if (strcmp(value, "Yes") == 0) {
					icp->conn_params.data_pdu_in_order =
					    B_TRUE;
				} else if (strcmp(value, "No") == 0) {
					icp->conn_params.data_pdu_in_order =
					    B_FALSE;
				} else {
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - InitialR2T is "
					    "invalid - protocol error",
					    icp->conn_oid);
					return (ISCSI_STATUS_PROTOCOL_ERROR);
				}
				text = value_end;

			} else if (iscsi_find_key_value("DataSequenceInOrder",
			    text, end, &value, &value_end)) {

				/*
				 * iSCSI RFC section 12.19 states that
				 * DataSequenceInOrder is Irrelevant for a
				 * discovery session.
				 */
				if (isp->sess_type ==
				    ISCSI_SESS_TYPE_DISCOVERY) {
					/* EMPTY */
				} else if (value == NULL) {
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - InitialR2T is "
					    "invalid - protocol error",
					    icp->conn_oid);
					return (ISCSI_STATUS_PROTOCOL_ERROR);
				} else if (strcmp(value, "Yes") == 0) {
					icp->conn_params.
					    data_sequence_in_order = B_TRUE;
				} else if (strcmp(value, "No") == 0) {
					icp->conn_params.
					    data_sequence_in_order = B_FALSE;
				} else {
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - InitialR2T is "
					    "invalid - protocol error",
					    icp->conn_oid);
					return (ISCSI_STATUS_PROTOCOL_ERROR);
				}
				text = value_end;

			} else if (iscsi_find_key_value("MaxOutstandingR2T",
			    text, end, &value, &value_end)) {

				/*
				 * iSCSI RFC section 12.17 states that
				 * MaxOutstandingR2T is Irrelevant for a
				 * discovery session.
				 */
				if (isp->sess_type ==
				    ISCSI_SESS_TYPE_DISCOVERY) {
					/* EMPTY */
				} else if (strcmp(value, "1")) {
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - can't accept "
					    "MaxOutstandingR2T %s",
					    icp->conn_oid, value);
					return (ISCSI_STATUS_NEGO_FAIL);
				}
				text = value_end;

			} else if (iscsi_find_key_value("MaxConnections",
			    text, end, &value, &value_end)) {

				/*
				 * iSCSI RFC section 12.2 states that
				 * MaxConnections is Irrelevant for a
				 * discovery session.
				 */
				if (isp->sess_type ==
				    ISCSI_SESS_TYPE_DISCOVERY) {
					/* EMPTY */
				} else if (strcmp(value, "1")) {
					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - can't accept "
					    "MaxConnections %s",
					    icp->conn_oid, value);
					return (ISCSI_STATUS_NEGO_FAIL);
				}
				text = value_end;

			} else if (iscsi_find_key_value("ErrorRecoveryLevel",
			    text, end, &value, &value_end)) {

				if (strcmp(value, "0")) {

					cmn_err(CE_WARN, "iscsi connection(%u) "
					    "login failed - can't accept "
					    "ErrorRecoveryLevel %s",
					    icp->conn_oid, value);
					return (ISCSI_STATUS_NEGO_FAIL);
				}
				text = value_end;

			} else {
				cmn_err(CE_WARN, "iscsi connection(%u) "
				    "login failed - ignoring login "
				    "parameter %s", icp->conn_oid, value);
				text = value_end;
			}
			break;
		default:
			return (ISCSI_STATUS_INTERNAL_ERROR);
		}
	}

	/*
	 * iSCSI RFC section 12.14 states that
	 * FirstBurstLength is Irrelevant if
	 * InitialR2T=Yes and ImmediateData=No.
	 * This is a final check to make sure
	 * the array didn't make a protocol
	 * violation.
	 */
	if ((fbl_irrelevant == B_TRUE) &&
	    ((icp->conn_params.initial_r2t != B_TRUE) ||
	    (icp->conn_params.immediate_data != B_FALSE))) {
		cmn_err(CE_WARN, "iscsi connection(%u) login failed - "
		    "FirstBurstLength=Irrelevant and (InitialR2T!=Yes or "
		    "ImmediateData!=No) - protocol error", icp->conn_oid);
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}

	if (icp->conn_current_stage == ISCSI_SECURITY_NEGOTIATION_STAGE) {
		switch (iscsiAuthClientRecvEnd(auth_client, iscsi_null_callback,
		    (void *)isp, NULL)) {
		case iscsiAuthStatusContinue:
			/*
			 * continue sending PDUs
			 */
			break;

		case iscsiAuthStatusPass:
			break;

		case iscsiAuthStatusInProgress:
			/*
			 * this should only occur if we were authenticating the
			 * target, which we don't do yet, so treat this as an
			 * error.
			 */
		case iscsiAuthStatusNoError:
			/*
			 * treat this as an error, since we should get a
			 * different code
			 */
		case iscsiAuthStatusError:
		case iscsiAuthStatusFail:
		default:
			debug_status = 0;

			if (iscsiAuthClientGetDebugStatus(auth_client,
			    &debug_status) != iscsiAuthStatusNoError) {

				cmn_err(CE_WARN, "iscsi connection(%u) login "
				    "failed - authentication failed with "
				    "target (%s)", icp->conn_oid,
				    iscsiAuthClientDebugStatusToText(
				    debug_status));

			} else {

				cmn_err(CE_WARN, "iscsi connection(%u) login "
				    "failed - authentication failed with "
				    "target", icp->conn_oid);

			}
			return (ISCSI_STATUS_AUTHENTICATION_FAILED);
		}
	}

	/*
	 * record some of the PDU fields for later use
	 */
	isp->sess_tsid = ntohs(ilrhp->tsid);
	isp->sess_expcmdsn = ntohl(ilrhp->expcmdsn);
	isp->sess_maxcmdsn = ntohl(ilrhp->maxcmdsn);
	if (ilrhp->status_class == ISCSI_STATUS_CLASS_SUCCESS) {
		icp->conn_expstatsn = ntohl(ilrhp->statsn) + 1;
	}

	if (transit) {
		/*
		 * advance to the next stage
		 */
		icp->conn_partial_response = 0;
		icp->conn_current_stage =
		    ilrhp->flags & ISCSI_FLAG_LOGIN_NEXT_STAGE_MASK;
	} else {
		/*
		 * we got a partial response, don't advance, more
		 * negotiation to do
		 */
		icp->conn_partial_response = 1;
	}

	/*
	 * this PDU is ok, though the login process
	 * may not be done yet
	 */
	return (ISCSI_STATUS_SUCCESS);
}

/*
 * iscsi_add_text - caller is assumed to be well-behaved and passing NUL
 * terminated strings
 */
int
iscsi_add_text(iscsi_hdr_t *ihp, char *data, int max_data_length,
    char *param, char *value)
{
	int	param_len	= 0;
	int	value_len	= 0;
	int	length		= 0;
	int	pdu_length	= 0;
	char	*text		= NULL;
	char	*end		= NULL;

	ASSERT(ihp != NULL);
	ASSERT(data != NULL);
	ASSERT(param != NULL);
	ASSERT(value != NULL);

	param_len = strlen(param);
	value_len = strlen(value);
	/* param, separator, value, and trailing NULL */
	length		= param_len + 1 + value_len + 1;
	pdu_length	= ntoh24(ihp->dlength);
	text		= data + pdu_length;
	end		= data + max_data_length;
	pdu_length	+= length;

	if (text + length >= end) {
		return (0);
	}

	/* param */
	(void) strncpy(text, param, param_len);
	text += param_len;

	/* separator */
	*text++ = ISCSI_TEXT_SEPARATOR;

	/* value */
	(void) strncpy(text, value, value_len);
	text += value_len;

	/* NULL */
	*text++ = '\0';

	/* update the length in the PDU header */
	hton24(ihp->dlength, pdu_length);

	return (1);
}

/*
 * iscsi_get_next_text - get the next line of text from the given data
 * buffer.  This function searches from the address given for the
 * curr_text parameter.  If curr_text_parameter is NULL return first
 * line in buffer.  The return value is the address of the next line
 * based upon where curr_text is located.
 *
 */
char *
iscsi_get_next_text(char *data, int max_data_length, char *curr_text)
{
	char *curr_data;

	ASSERT(data != NULL);

	/* check if any data exists, if not return */
	if (max_data_length == 0) {
		return (NULL);
	}

	/* handle first call to this function */
	if (curr_text == NULL) {
		return (data);
	}

	/* move to next text string */
	curr_data = curr_text;
	while ((curr_data < (data + max_data_length)) && *curr_data) {
		curr_data++;
	}
	curr_data++;		/* go past the NULL to the next entry */

	/* check whether data end reached */
	if (curr_data >= (data + max_data_length)) {
		return (NULL);
	}

	return (curr_data);
}


/*
 * iscsi_find_key_value -
 *
 */
static int
iscsi_find_key_value(char *param, char *ihp, char *pdu_end,
    char **value_start, char **value_end)
{
	char *str = param;
	char *text = ihp;
	char *value = NULL;

	if (value_start)
		*value_start = NULL;
	if (value_end)
		*value_end = NULL;

	/*
	 * make sure they contain the same bytes
	 */
	while (*str) {
		if (text >= pdu_end) {
			return (0);
		}
		if (*text == '\0') {
			return (0);
		}
		if (*str != *text) {
			return (0);
		}
		str++;
		text++;
	}

	if ((text >= pdu_end) ||
	    (*text == '\0') ||
	    (*text != ISCSI_TEXT_SEPARATOR)) {
		return (0);
	}

	/*
	 * find the value
	 */
	value = text + 1;

	/*
	 * find the end of the value
	 */
	while ((text < pdu_end) && (*text))
		text++;

	if (value_start)
		*value_start = value;
	if (value_end)
		*value_end = text;

	return (1);
}


/*
 * iscsi_update_address - This function is used on a login redirection.
 * During the login redirection we are asked to switch to an IP address
 * port different than the one we were logging into.
 */
static iscsi_status_t
iscsi_update_address(iscsi_conn_t *icp, char *in)
{
	char		*addr_str, *port_str, *tpgt_str;
	int		type;
	struct hostent	*hptr;
	unsigned long	tmp;
	int		error_num;
	int		port;

	ASSERT(icp != NULL);
	ASSERT(in != NULL);

	/* parse login redirection response */
	if (parse_addr_port_tpgt(in, &addr_str, &type,
	    &port_str, &tpgt_str) == B_FALSE) {
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}

	/* convert addr_str */
	hptr = kgetipnodebyname(addr_str, type, AI_ALL, &error_num);
	if (!hptr) {
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}

	/* convert port_str */
	if (port_str != NULL) {
		(void) ddi_strtoul(port_str, NULL, 0, &tmp);
		port = (int)tmp;
	} else {
		port = ISCSI_LISTEN_PORT;
	}

	iscsid_addr_to_sockaddr(hptr->h_length, *hptr->h_addr_list,
	    port, &icp->conn_curr_addr.sin);

	kfreehostent(hptr);
	return (ISCSI_STATUS_SUCCESS);
}


/*
 * iscsi_null_callback - This callback may be used under certain
 * conditions when authenticating a target, but I'm not sure what
 * we need to do here.
 */
/* ARGSUSED */
static void
iscsi_null_callback(void *user_handle, void *message_handle, int auth_status)
{
}


/*
 * iscsi_login_failure_str -
 *
 */
static char *
iscsi_login_failure_str(uchar_t status_class, uchar_t status_detail)
{
	switch (status_class) {
	case 0x00:
		switch (status_detail) {
		case 0x00:
			return ("Login is proceeding okay.");
		default:
			break;
		}
	case 0x01:
		switch (status_detail) {
		case 0x01:
			return ("Requested ITN has moved temporarily to "
			    "the address provided.");
		case 0x02:
			return ("Requested ITN has moved permanently to "
			    "the address provided.");
		default:
			break;
		}
	case 0x02:
		switch (status_detail) {
		case 0x00:
			return ("Miscellaneous iSCSI initiator errors.");
		case 0x01:
			return ("Initiator could not be successfully "
			    "authenticated.");
		case 0x02:
			return ("Initiator is not allowed access to the "
			    "given target.");
		case 0x03:
			return ("Requested ITN does not exist at this "
			    "address.");
		case 0x04:
			return ("Requested ITN has been removed and no "
			    "forwarding address is provided.");
		case 0x05:
			return ("Requested iSCSI version range is not "
			    "supported by the target.");
		case 0x06:
			return ("No more connections can be accepted on "
			    "this Session ID (SSID).");
		case 0x07:
			return ("Missing parameters (e.g., iSCSI initiator "
			    "and/or target name).");
		case 0x08:
			return ("Target does not support session spanning "
			    "to this connection (address).");
		case 0x09:
			return ("Target does not support this type of "
			    "session or not from this initiator.");
		case 0x0A:
			return ("Attempt to add a connection to a "
			    "nonexistent session.");
		case 0x0B:
			return ("Invalid request type during login.");
		default:
			break;
		}
	case 0x03:
		switch (status_detail) {
		case 0x00:
			return ("Target hardware or software error.");
		case 0x01:
			return ("iSCSI service or target is not currently "
			    "operational.");
		case 0x02:
			return ("Target has insufficient session, connection "
			    "or other resources.");
		default:
			break;
		}
	}
	return ("Unknown login response received.");
}


/*
 * iscsi_login_connect -
 */
static iscsi_status_t
iscsi_login_connect(iscsi_conn_t *icp)
{
	iscsi_hba_t	    *ihp;
	iscsi_sess_t	    *isp;
	struct sockaddr	    *addr;
	struct sonode	    *so = NULL;

	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);
	addr = &icp->conn_curr_addr.sin;

	so = iscsi_net->socket(addr->sa_family, SOCK_STREAM, 0);
	if (so == NULL) {
		cmn_err(CE_WARN, "iscsi connection(%u) unable "
		    "to acquire socket resources", icp->conn_oid);
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	/* bind if enabled */
	if (icp->conn_bound == B_TRUE) {
		/* bind socket */
		if (iscsi_net->bind(so, &icp->conn_bound_addr.sin,
		    SIZEOF_SOCKADDR(addr), 0, 0)) {
			cmn_err(CE_NOTE, "iscsi connection(%u) - "
			    "bind failed\n", icp->conn_oid);
		}
	}

	/* Make sure that scope_id is zero if it is an IPv6 address */
	if (addr->sa_family == AF_INET6) {
		((struct sockaddr_in6 *)addr)->sin6_scope_id = 0;
	}

	/* connect socket to target portal (ip,port) */
	if (!ISCSI_SUCCESS(iscsi_net->connect(so, addr,
	    SIZEOF_SOCKADDR(addr), 0, 0))) {

		cmn_err(CE_NOTE, "iscsi connection(%u) unable to "
		    "connect to target %s", icp->conn_oid,
		    icp->conn_sess->sess_name);

		/* ---- 2 indicates both cantsend and cantrecv ---- */
		iscsi_net->shutdown(so, 2);
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	icp->conn_socket = so;
	if (iscsi_net->getsockname(icp->conn_socket) != 0) {
		cmn_err(CE_NOTE, "iscsi connection(%u) failed to get "
		    "socket information", icp->conn_oid);
	}

	return (ISCSI_STATUS_SUCCESS);
}
