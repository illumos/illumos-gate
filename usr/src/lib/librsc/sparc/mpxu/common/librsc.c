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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * ENXS platform-specific functions
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "librsc.h"

/* rmcadm driver file descriptor */
static int rsc_fd = -1;

/*
 * librsc receive buffer - it is used as temporary buffer to store replies
 * from the remote side
 */

static uchar_t rsc_rx_buffer[RSC_MAX_RX_BUFFER];
static int rsc_rx_resp_len = 0;
static int rsc_rx_error = 0;
static rsci8 rsc_rx_resp_type = 0;

/*
 * Registered boot-protocol message callback routine.  This routine will be
 * called whenever a boot protocol message is received.
 */
static rscp_bpmsg_cb_t *bpmsg_cb;



/* lookup table to match request and response . This is in order to support */
/* obsolete functions (rscp_send, rscp_recv) */

static req_resp_table_t rr_table[] = {

	{ DP_GET_DATE_TIME,	DP_GET_DATE_TIME_R,
	    sizeof (dp_get_date_time_r_t), RR_TIMEOUT },
	{ DP_SET_DATE_TIME,	DP_SET_DATE_TIME_R,
	    sizeof (dp_set_date_time_r_t), RR_TIMEOUT },
	{ DP_GET_EVENT_LOG,	DP_GET_EVENT_LOG_R,
	    sizeof (dp_get_event_log_r_t), RR_TIMEOUT },
	{ DP_MODEM_CONNECT,	DP_MODEM_CONNECT_R,
	    sizeof (dp_modem_connect_r_t), RR_TIMEOUT },
	{ DP_MODEM_DISCONNECT,	DP_MODEM_DISCONNECT_R,
	    sizeof (dp_modem_disconnect_r_t), RR_TIMEOUT },
	{ DP_SEND_ALERT,	DP_SEND_ALERT_R,
	    sizeof (dp_send_alert_r_t), RR_TIMEOUT },
	{ DP_SET_CFGVAR,	DP_SET_CFGVAR_R,
	    sizeof (dp_set_cfgvar_r_t), RR_TIMEOUT },
	{ DP_GET_CFGVAR,	DP_GET_CFGVAR_R,
	    sizeof (dp_get_cfgvar_r_t), RR_TIMEOUT },
	{ DP_GET_CFGVAR_NAME,	DP_GET_CFGVAR_NAME_R,
	    sizeof (dp_get_cfgvar_name_r_t), RR_TIMEOUT },
	{ DP_GET_NETWORK_CFG,	DP_GET_NETWORK_CFG_R,
	    sizeof (dp_get_network_cfg_r_t), RR_TIMEOUT },
	{ DP_RSC_STATUS,	DP_RSC_STATUS_R,
	    sizeof (dp_rsc_status_r_t), RR_TIMEOUT },
	{ DP_USER_ADM,		DP_USER_ADM_R,
	    sizeof (dp_user_adm_r_t), RR_SEPROM_TIMEOUT},
	{ DP_RESET_RSC,		DP_NULL_MSG,
	    0,			1 },
	{ DP_GET_CONSOLE_LOG,	DP_GET_CONSOLE_LOG_R,
	    sizeof (dp_get_console_log_r_t),	RR_TIMEOUT },
	{ DP_GET_CONFIG_LOG,	DP_GET_CONFIG_LOG_R,
	    sizeof (dp_get_config_log_r_t),	RR_TIMEOUT },
	{ DP_GET_EVENT_LOG2,	DP_GET_EVENT_LOG2_R,
	    sizeof (dp_get_event_log2_r_t),	RR_TIMEOUT },
};

static const int rr_table_cnt = sizeof (rr_table) / sizeof (rr_table[0]);


/* lookup table to get timeout value for BP cmd reply. This is in order to */
/* support obsolete functions (rscp_send_bpmsg, rsc_raw_write) */

static req_resp_table_t rr_bp_table[] = {

	{ BP_OBP_BOOTINIT,	NULL,	sizeof (bp_msg_t),
	    RR_BOOT_INIT_TIMEOUT },
	{ BP_OBP_RESET,		NULL,	sizeof (bp_msg_t),
	    RR_BOOT_RESET_TIMEOUT }
};

static const int rr_bp_table_cnt =
    sizeof (rr_bp_table) / sizeof (rr_bp_table[0]);

static rsci8 unsupported_cmds[] = { DP_SET_DATE_TIME };

static int unsupported_cmds_cnt = sizeof (unsupported_cmds) /
    sizeof (unsupported_cmds[0]);

/*
 * Protocol version number, used to determine whether ALOM will
 * time out on unknown commands.
 */
static int sdp_version = -1;

/* function prototypes */

static req_resp_table_t *rsc_lookup_rr_table(req_resp_table_t *, int, rsci8);

static int rsc_check_unsupported_cmd(rsci8);

static int rsc_cmd_response_guaranteed(rsci8);

/*
 * Initialize the generic librsc data protocol routines. basically, it
 * open the rmcadm (pseudo) device and initialize data
 */
int
rscp_init(void)
{
	rscp_msg_t	request, response;
	dp_get_sdp_version_r_t version_msg;

	/*
	 * 'erase' the rx buffer
	 */
	(void) memset(rsc_rx_buffer, 0, sizeof (rsc_rx_buffer));
	rsc_rx_resp_len = 0;
	rsc_rx_error = 0;
	rsc_rx_resp_type = DP_NULL_MSG;

	/*
	 * open rmcadm driver
	 */
	if ((rsc_fd = open(RSC_RMCADM_DRV, O_RDWR)) < 0) {
#ifdef DEBUG
		printf("rscp_init: Error opening %s, error code = %d\n",
		    RSC_RMCADM_DRV, errno);
#endif
		return (errno);
	}

	/*
	 * Fetch the protocol version number in use between the host
	 * and ALOM.
	 */
	request.type = DP_GET_SDP_VERSION;
	request.len = 0;
	request.data = 0;

	response.type = DP_GET_SDP_VERSION_R;
	response.len = sizeof (version_msg);
	response.data = (caddr_t)&version_msg;

	if ((errno = rscp_send_recv(&request, &response, 0)) != 0)
		return (errno);

	sdp_version = version_msg.version;

#ifdef DEBUG
	printf("rscp_init: sdp version number is %d\n", sdp_version);
#endif

	return (0);
}

/*
 * send/receive interface: this is the new interface where application
 * (currently scadm, SunVTS) send a request and wait for a reply in a
 * single call. If a response is not required (resp=NULL), the function
 * will only return the status of the request (whether it has been successfully
 * or not).
 */
int
rscp_send_recv(rscp_msg_t *req, rscp_msg_t *resp, struct timespec *timeout)
{
	rmcadm_request_response_t	rr;
	rmcadm_msg_t			*rr_req = &rr.req;
	rmcadm_msg_t			*rr_resp = &rr.resp;

	if (rsc_fd < 0)
		return (EBADF);

	/*
	 * the request is required, it should not be NULL!
	 */
	if (req == NULL)
		return (EINVAL);

	/*
	 * Check if the command is actually supported
	 * if not, return an error
	 */
	if (rsc_check_unsupported_cmd(req->type) != 0)
		return (ENOTSUP);

	/*
	 * Check if this command will generate a response and if it will not,
	 * return an error.
	 */
	if (!rsc_cmd_response_guaranteed(req->type))
		return (ENOTSUP);

	rr_req->msg_type = req->type;
	rr_req->msg_len = req->len;
	rr_req->msg_buf = (caddr_t)req->data;

	if (resp != NULL) {
		rr_resp->msg_type = resp->type;
		rr_resp->msg_len = resp->len;
		rr_resp->msg_buf = (caddr_t)resp->data;
		rr_resp->msg_bytes = 0;
	} else {
		rr_resp->msg_type = DP_NULL_MSG;
		rr_resp->msg_buf = (caddr_t)NULL;
		rr_resp->msg_len = 0;
		rr_resp->msg_bytes = 0;
	}

	if (timeout == NULL) {
		rr.wait_time = RR_TIMEOUT;
	} else {
		rr.wait_time = timeout->tv_sec * 1000 +
		    timeout->tv_nsec / 1000000;
	}
	rr.status = 0;

	if (ioctl(rsc_fd, RMCADM_REQUEST_RESPONSE, &rr) < 0) {
#ifdef DEBUG
		printf("rscp_send_recv: req. failed, status=%d errno=%d\n",
		    rr_req->msg_type, rr.status, errno);
#endif
		return (errno);
	}

	return (0);
}

/*
 * function used to look up at the request/response table. Given a request
 * type, will return a record which provides the following information:
 * response expected and a timeout value
 */
static req_resp_table_t *
rsc_lookup_rr_table(req_resp_table_t *rr_table, int cnt, rsci8 type)
{
	int	i;

#ifdef DEBUG
	printf("lookup for type %x, count %d\n", type, cnt);
#endif

	for (i = 0; i < cnt; i++)
		if (rr_table[i].req_type == type) {
			return (rr_table + i);
		}

	return (NULL);
}

/*
 * function to check if a message type is in the list of unsupported commands
 * If so, will return 1.
 */
static int
rsc_check_unsupported_cmd(rsci8 type)
{
	int	i;

	for (i = 0; i < unsupported_cmds_cnt; i++)
		if (unsupported_cmds[i] == type) {
			return (1);
		}

	return (0);
}

/*
 * Returns 1 if ALOM will generate a response to the given command code,
 * otherwise it returns 0.  If a command is not in the following list,
 * and the protocol version is 2 or less, then ALOM will not generate
 * a response to the command.  This causes the driver to time out,
 * and we want to avoid that situation.
 */
static int
rsc_cmd_response_guaranteed(rsci8 type)
{
	switch (type) {
	case DP_GET_ALARM_STATE:
	case DP_GET_CFGVAR:
	case DP_GET_CFGVAR_NAME:
	case DP_GET_CIRCUIT_BRKS:
	case DP_GET_DATE_TIME:
	case DP_GET_DEVICE:
	case DP_GET_EVENT_LOG:
	case DP_GET_FAN_STATUS:
	case DP_GET_FRU_STATUS:
	case DP_GET_HANDLE:
	case DP_GET_HANDLE_NAME:
	case DP_GET_LED_STATE:
	case DP_GET_NETWORK_CFG:
	case DP_GET_PCMCIA_INFO:
	case DP_GET_PSU_STATUS:
	case DP_GET_SDP_VERSION:
	case DP_GET_SYSINFO:
	case DP_GET_TEMP:
	case DP_GET_TEMPERATURES:
	case DP_GET_TICKCNT:
	case DP_GET_TOD_CLOCK:
	case DP_GET_USER_WATCHDOG:
	case DP_GET_VOLTS:
	case DP_MODEM_CONNECT:
	case DP_MODEM_DATA:
	case DP_MODEM_DISCONNECT:
	case DP_RESET_RSC:
	case DP_RMC_EVENTS:
	case DP_RSC_STATUS:
	case DP_RUN_TEST:
	case DP_SEND_ALERT:
	case DP_SET_ALARM_STATE:
	case DP_SET_CFGVAR:
	case DP_SET_CPU_SIGNATURE:
	case DP_SET_DATE_TIME:
	case DP_SET_DEFAULT_CFG:
	case DP_SET_HOST_WATCHDOG:
	case DP_SET_LED_STATE:
	case DP_SET_USER_WATCHDOG:
	case DP_UPDATE_FLASH:
	case DP_USER_ADM:
		return (1);
	default:
		return (sdp_version >= SDP_RESPONDS_TO_ALL_CMDS);
	}
}

/*
 * RSC hard reset. Returns 0 on success, non-zero on error.
 */
int
rsc_nmi(void)
{
	if (rsc_fd < 0)
		return (EBADF);

	if (ioctl(rsc_fd, RMCADM_RESET_SP, NULL) < 0)
		return (errno);

	return (0);
}

/*
 * functions used (exclusively) for the firmware download
 */

/*
 * Call this routine to register a callback that will be called by the
 * generic data protocol routines when a boot protocol message is
 * received.  Only one of these routines may be registered at a time.
 * Note that receiving a boot protocol message has the effect of
 * re-initializing the data protocol.  Returns 0 on success, or non-
 * zero on failure.
 */
int
rscp_register_bpmsg_cb(rscp_bpmsg_cb_t *cb)
{
	if (rsc_fd < 0)
		return (EBADF);

	if (bpmsg_cb == NULL) {
		bpmsg_cb = cb;
		return (0);
	} else {
		return (EALREADY);
	}
}

/*
 * This routine un-registers a boot protocol message callback.
 */
int
rscp_unregister_bpmsg_cb(rscp_bpmsg_cb_t *cb)
{
	if (rsc_fd < 0)
		return (EBADF);

	if (bpmsg_cb == cb) {
		bpmsg_cb = NULL;
		return (0);
	} else {
		return (EINPROGRESS);
	}
}

/*
 * Call this routine to send a boot protocol message.
 */
void
rscp_send_bpmsg(bp_msg_t *bpmsg)
{
	rmcadm_request_response_t	rr_bp;
	rmcadm_msg_t			*req_bp = &rr_bp.req;
	rmcadm_msg_t			*resp_bp = &rr_bp.resp;
	req_resp_table_t		*rr_bp_item;
	bp_msg_t			bpmsg_reply;

	if (rsc_fd < 0 || bpmsg == NULL)
		return;

	/*
	 * get the timeout value
	 */
	if ((rr_bp_item = rsc_lookup_rr_table(rr_bp_table, rr_bp_table_cnt,
	    bpmsg->cmd)) != NULL) {

		rr_bp.wait_time = rr_bp_item->timeout;

	} else {

		rr_bp.wait_time = RR_BP_TIMEOUT;
	}

	rr_bp.status = 0;

	req_bp->msg_len = sizeof (bp_msg_t);
	req_bp->msg_buf = (caddr_t)bpmsg;

	if (rr_bp.wait_time == 0) {
		resp_bp->msg_buf = (caddr_t)NULL;
	} else {
		resp_bp->msg_len = sizeof (bp_msg_t);
		resp_bp->msg_buf = (caddr_t)&bpmsg_reply;
	}

#ifdef DEBUG
	printf("send BP cmd %x, expect reply %x/%d\n",
	    bpmsg->cmd, resp_bp->msg_buf, resp_bp->msg_len);
#endif
	if (ioctl(rsc_fd, RMCADM_REQUEST_RESPONSE_BP, &rr_bp) < 0) {
#ifdef DEBUG
		printf("rscp_send_bpmsg: BP cmd %x failed status=%d "
		    "errno=%d\n", bpmsg->cmd, rr_bp.status, errno);
#endif
		return;
	}

#ifdef DEBUG
	printf("got BP reply type=%x,%x,%x\n",
	    bpmsg_reply.cmd, bpmsg_reply.dat1, bpmsg_reply.dat2);
#endif

	/*
	 * reply received. call the registered callback (if any)
	 */
	if (bpmsg_cb != NULL && resp_bp->msg_buf != NULL)
		bpmsg_cb(&bpmsg_reply);
}

/*
 * Write raw characters to the RSC control device.  Returns 0 on success,
 * non-zero on error.
 */
int
rsc_raw_write(char *buf, int nbytes)
{
	rmcadm_send_srecord_bp_t	srec_bp;
	bp_msg_t			bpmsg_reply;

	if (rsc_fd < 0)
		return (EBADF);

	srec_bp.data_len = (uint_t)nbytes;
	srec_bp.data_buf = (caddr_t)buf;
	srec_bp.resp_bp.msg_len = sizeof (bp_msg_t);
	srec_bp.resp_bp.msg_buf = (caddr_t)&bpmsg_reply;
	srec_bp.wait_time = RR_BOOT_LOAD_TIMEOUT;
	srec_bp.status = 0;

#ifdef DEBUG
	printf("send srecord BP len=%d\n", nbytes);
#endif
	if (ioctl(rsc_fd, RMCADM_SEND_SRECORD_BP, &srec_bp) < 0) {
#ifdef DEBUG
		printf("rsc_raw_write: failed. status=%d ioctl error=%d\n",
		    srec_bp.status, errno);
#endif
		return (errno);
	}

#ifdef DEBUG
	printf("got BP reply type=%x\n", bpmsg_reply.cmd);
#endif

	/*
	 * reply received. call the registered callback (if any)
	 */
	if (bpmsg_cb != NULL)
		bpmsg_cb(&bpmsg_reply);

	return (0);
}

/*
 * obsolete functions provided for backward compatibility
 */

/*
 * This function is obsolete and it is provided for backward compatibility.
 * (no-op function). It was used to start up the data protocol. low-level
 * protocol has moved to the kernel and the rmc_comm driver is responsible
 * for setting up the data protocol.
 * (obsolete)
 */
int
rscp_start(void)
{
	if (rsc_fd < 0)
		return (EBADF);

	return (0);
}

/*
 * This function is obsolete and it is provided for backward compatibility.
 * Previously, rscp_send() and rscp_recv() where used to send a request and
 * read a reply respectively. Now, rscp_send_recv() should be used instead
 * (request/response in one call).
 *
 * This is used to send a message by making an RMCADM_REQUEST_RESPONSE ioctl
 * call. A lookup table (rr_table) is used to find out the expected reply
 * (if any) and the timeout value for a message to be sent. The reply is then
 * stored in a buffer (rsc_rx_buffer) to be returned by calling rscp_recv()
 */
int
rscp_send(rscp_msg_t *msgp)
{
	rmcadm_request_response_t	 rr;
	rmcadm_msg_t			*req = &rr.req;
	rmcadm_msg_t			*resp = &rr.resp;
	req_resp_table_t		*rr_item;

	if (rsc_fd < 0)
		return (EBADF);

	/*
	 * sanity check
	 */
	if (msgp == NULL)
		return (EINVAL);

	/*
	 * Check if the command is actually supported
	 * if not, return an error
	 */
	if (rsc_check_unsupported_cmd(msgp->type) != 0)
		return (ENOTSUP);

	/*
	 * Check if this command will generate a response and if it will not,
	 * return an error.
	 */
	if (!rsc_cmd_response_guaranteed(msgp->type))
		return (ENOTSUP);

	/*
	 * init rx buffer
	 */
	rsc_rx_resp_len = 0;
	rsc_rx_error = 0;

	req->msg_type = msgp->type;
	req->msg_len = msgp->len;
	req->msg_buf = msgp->data;

	if ((rr_item = rsc_lookup_rr_table(rr_table, rr_table_cnt,
	    msgp->type)) != NULL) {
		resp->msg_type = rr_item->resp_type;
		if (rr_item->resp_type == DP_NULL_MSG) {
			/*
			 * no reply expected. so, no reply buffer needed
			 * (set to NULL)
			 */
			resp->msg_len = 0;
			resp->msg_buf = (caddr_t)NULL;
		} else {
			resp->msg_len = RSC_MAX_RX_BUFFER;
			resp->msg_buf = (caddr_t)rsc_rx_buffer;
		}

		rr.wait_time = rr_item->timeout;
		rsc_rx_resp_type = rr_item->resp_type;
	} else {
		return (ENOTSUP);
	}
	rr.status = 0;

#ifdef DEBUG
	printf("request/response %x/%x\n", req->msg_type, resp->msg_type);
#endif
	if (ioctl(rsc_fd, RMCADM_REQUEST_RESPONSE, &rr) < 0) {
#ifdef DEBUG
		printf("rscp_send: req %x failed, status=%d errno=%d\n",
		    rr.req.msg_type, rr.status, errno);
#endif
		rsc_rx_error = errno;

		return (errno);
	}

	/*
	 * reply received. get the number of bytes effectively returned
	 */
	rsc_rx_resp_len = resp->msg_bytes;
	rsc_rx_resp_type = resp->msg_type;

#ifdef DEBUG
	printf("got reply type=%x len=%d\n", rsc_rx_resp_type, rsc_rx_resp_len);
#endif

	return (0);
}

/*
 * This function is obsolete and it is provided for backward compatibility
 * Previously, rscp_send() and rscp_recv() where used to send a request and
 * read a reply repectively. Now, rscp_send_recv() should be used instead
 * (request/response in one call).
 *
 * This function returns the reply received when a request was previously sent
 * using the rscp_send() function (stored in the rsc_rx_buffer buffer). If a
 * reply was not received, then an error is returned.
 *
 * timeout parameter is declared for backward compatibility but it is not used.
 */
/*ARGSUSED*/
int
rscp_recv(rscp_msg_t *msgp, struct timespec *timeout)
{
	int err = 0;

	if (rsc_fd < 0)
		return (EBADF);

	/*
	 * sanity check
	 */
	if (msgp == NULL)
		return (EINVAL);

	if (rsc_rx_error < 0) {
		msgp->type = DP_NULL_MSG;
		msgp->len = 0;
		msgp->data = NULL;

		err = rsc_rx_error;

	} else {
		msgp->type = rsc_rx_resp_type;
		msgp->len = rsc_rx_resp_len;
		msgp->data = rsc_rx_buffer;
	}

#ifdef DEBUG
	printf("read reply. type=%x, err=%d\n", msgp->type, err);
#endif

	rsc_rx_resp_len = 0;
	rsc_rx_error = 0;
	rsc_rx_resp_type = DP_NULL_MSG;

	return (err);
}

/*
 * used to free up a (received) message. no-op function
 */
/*ARGSUSED*/
int
rscp_free_msg(rscp_msg_t *msgp)
{
	if (rsc_fd < 0)
		return (EBADF);

	return (0);
}
