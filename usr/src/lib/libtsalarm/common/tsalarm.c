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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Telco-alarm library, which communicates through libpcp to set/get
 * alarms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <libpcp.h>

#include "tsalarm.h"

/* Message Types */
#define	TSALARM_CONTROL		15
#define	TSALARM_CONTROL_R	16

#define	TSALARM_CHANNEL_TIMEOUT	20
#define	TSALARM_MAX_RETRIES	3
#define	TSALARM_SERVICE_NAME	"SUNW,sun4v-telco-alarm"

int
tsalarm_get(uint32_t alarm_type, uint32_t *alarm_state)
{
	int		chnl_fd;
	tsalarm_req_t	*req_ptr = NULL;
	tsalarm_resp_t	*resp_ptr = NULL;
	pcp_msg_t	send_msg;
	pcp_msg_t	recv_msg;
	int		rc = TSALARM_SUCCESS;
	int		retries;

	/* initialize virtual channel */
	for (retries = 1; retries <= TSALARM_MAX_RETRIES; retries++) {
		if ((chnl_fd = pcp_init(TSALARM_SERVICE_NAME)) < 0) {
			if (retries == TSALARM_MAX_RETRIES) {
				rc = TSALARM_CHANNEL_INIT_FAILURE;
				goto cleanup;
			}
			(void) sleep(TSALARM_CHANNEL_TIMEOUT);
		} else
			break;
	}

	/* create request message data */
	req_ptr = malloc(sizeof (tsalarm_req_t));
	if (req_ptr == NULL) {
		rc = TSALARM_NULL_REQ_DATA;
		goto cleanup;
	}
	req_ptr->alarm_action = TSALARM_STATUS;
	req_ptr->alarm_id = alarm_type;

	send_msg.msg_type = TSALARM_CONTROL;
	send_msg.sub_type = 0;
	send_msg.msg_len = sizeof (tsalarm_req_t);
	send_msg.msg_data = (uint8_t *)req_ptr;

	/*
	 * Send the request and receive the response.
	 */
	if (pcp_send_recv(chnl_fd, &send_msg, &recv_msg,
	    TSALARM_CHANNEL_TIMEOUT) < 0) {
		/* we either timed out or erred; either way try again */
		(void) sleep(TSALARM_CHANNEL_TIMEOUT);

		if (pcp_send_recv(chnl_fd, &send_msg, &recv_msg,
		    TSALARM_CHANNEL_TIMEOUT) < 0) {
			rc = TSALARM_COMM_FAILURE;
			goto cleanup;
		}
	}

	/*
	 * verify that the Alarm action has taken place
	 */
	if ((resp_ptr = (tsalarm_resp_t *)recv_msg.msg_data) == NULL)
		goto cleanup;

	/*
	 * validate that this data was meant for us
	 */
	if (recv_msg.msg_type != TSALARM_CONTROL_R) {
		rc = TSALARM_UNBOUND_PACKET_RECVD;
		goto cleanup;
	}

	if (resp_ptr->status == TSALARM_ERROR) {
		rc = TSALARM_GET_ERROR;
		goto cleanup;
	}

	if (resp_ptr->alarm_state == TSALARM_STATE_UNKNOWN) {
		rc = TSALARM_GET_ERROR;
		goto cleanup;
	}

	*alarm_state = resp_ptr->alarm_state;

cleanup:
	if (req_ptr != NULL)
		free(req_ptr);

	/* free recv_msg.msg_data through pointer to make sure it is valid */
	if (resp_ptr != NULL)
		free(resp_ptr);

	/* close virtual channel fd */
	(void) pcp_close(chnl_fd);

	return (rc);
}

int
tsalarm_set(uint32_t alarm_type, uint32_t alarm_state)
{
	int		chnl_fd;
	tsalarm_req_t   *req_ptr = NULL;
	tsalarm_resp_t  *resp_ptr = NULL;
	pcp_msg_t	send_msg;
	pcp_msg_t	recv_msg;
	int		rc = TSALARM_SUCCESS;
	int		retries;

	/* initialize virtual channel */
	for (retries = 1; retries <= TSALARM_MAX_RETRIES; retries++) {
		if ((chnl_fd = pcp_init(TSALARM_SERVICE_NAME)) < 0) {
			if (retries == TSALARM_MAX_RETRIES) {
				rc = TSALARM_CHANNEL_INIT_FAILURE;
				goto cleanup;
			}
			(void) sleep(TSALARM_CHANNEL_TIMEOUT);
		} else
			break;
	}

	/* create request message data */
	req_ptr = malloc(sizeof (tsalarm_req_t));
	if (req_ptr == NULL) {
		rc = TSALARM_NULL_REQ_DATA;
		goto cleanup;
	}
	req_ptr->alarm_id = alarm_type;
	if (alarm_state == TSALARM_STATE_ON)
		req_ptr->alarm_action = TSALARM_ENABLE;
	else if (alarm_state == TSALARM_STATE_OFF)
		req_ptr->alarm_action = TSALARM_DISABLE;

	send_msg.msg_type = TSALARM_CONTROL;
	send_msg.sub_type = 0;
	send_msg.msg_len = sizeof (tsalarm_req_t);
	send_msg.msg_data = (uint8_t *)req_ptr;

	/*
	 * Send the request and receive the response.
	 */
	if (pcp_send_recv(chnl_fd, &send_msg, &recv_msg,
	    TSALARM_CHANNEL_TIMEOUT) < 0) {
		/* we either timed out or erred; either way try again */
		(void) sleep(TSALARM_CHANNEL_TIMEOUT);

		if (pcp_send_recv(chnl_fd, &send_msg, &recv_msg,
		    TSALARM_CHANNEL_TIMEOUT) < 0) {
			rc = TSALARM_COMM_FAILURE;
			goto cleanup;
		}
	}

	/*
	 * verify that the Alarm action has taken place
	 */
	if ((resp_ptr = (tsalarm_resp_t *)recv_msg.msg_data) == NULL)
		goto cleanup;

	/*
	 * validate that this data was meant for us
	 */
	if (recv_msg.msg_type != TSALARM_CONTROL_R) {
		rc = TSALARM_UNBOUND_PACKET_RECVD;
		goto cleanup;
	}

	if (resp_ptr->status == TSALARM_ERROR) {
		rc = TSALARM_SET_ERROR;
		goto cleanup;
	}

	/*
	 * ensure the Alarm action taken is the one requested
	 */
	if ((req_ptr->alarm_action == TSALARM_DISABLE) &&
	    (resp_ptr->alarm_state != TSALARM_STATE_OFF)) {
		rc = TSALARM_SET_ERROR;
		goto cleanup;
	} else if ((req_ptr->alarm_action == TSALARM_ENABLE) &&
	    (resp_ptr->alarm_state != TSALARM_STATE_ON)) {
		rc = TSALARM_SET_ERROR;
		goto cleanup;
	} else if (resp_ptr->alarm_state == TSALARM_STATE_UNKNOWN) {
		rc = TSALARM_SET_ERROR;
		goto cleanup;
	}

cleanup:
	if (req_ptr != NULL)
		free(req_ptr);

	/* free recv_msg.msg_data through pointer to make sure it is valid */
	if (resp_ptr != NULL)
		free(resp_ptr);

	/* close virtual channel fd */
	(void) pcp_close(chnl_fd);

	return (rc);
}
