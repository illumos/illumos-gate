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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This is utility library that provides APIs to interact with SMC driver
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stropts.h>
#include <syslog.h>
#include "smclib.h"

static int debug_on = 0;

/* Error messages */
#define	SMC_ERRMSG_OPEN		"SMC open failed, cmd = %x\n"
#define	SMC_ERRMSG_WRITE	"SMC write failed, cmd = %x\n"
#define	SMC_ERRMSG_POLLTIMEOUT	"SMC poll timed out, cmd = %x\n"
#define	SMC_ERRMSG_POLLFAILED	"SMC poll failed, cmd = %x\n"
#define	SMC_ERRMSG_POLL_T	"SMC poll timed out, dest = %x\n"
#define	SMC_ERRMSG_POLL_F	"SMC poll failed, dest = %x\n"
#define	SMC_ERRMSG_READ		"SMC read response failed, cmd = %x\n"
#define	SMC_ERRMSG_ERROR	"SMC error, cc = %d, msg_id = %x\n"
#define	SMC_ERRMSG_SETATTR	"SMC setting read attribute failed\n"
#define	SMC_ERRMSG_GET_SEQN	"SMC error in getting seqn for %x\n"
#define	SMC_ERRMSG_IPMI_ERR	"SMC IPMI invalid cc:%x, dest = %x\n"
#define	SMC_ERRMSG_GET_GEO	"SMC get GeoAddr failed\n"

/* Macros */
#define	REQ_SA(_X)	(((_X) < 10) ? (0xb0 + 2 * ((_X) - 1)) :\
					(0xb0 + 2 * (_X)))
#define	LUN_BITMASK 		0x03	/* last two bits */
#define	RESPONSE_MSG		0x01	/* last bit */

#define	SMC_LOCAL_SEQ_NO	10
#define	SMC_POLL_TIME		1000	/* 1 sec */
#define	NORMAL_COMPLETION_CODE	0
#define	IPMI_MSG_CHANNEL_0	0x0
#define	IPMI_REQ_HDR_LEN	0x8	/* includes command & data checksum */
#define	IPMI_RSP_HDR_LEN	0x8
#define	SMC_NETFN_SEQ_OFFSET	5
#define	SMC_CMD_OFFSET		6

#define	SMC_NODE		("/dev/ctsmc")
#define	DEFAULT_FD			-1
#define	DEFAULT_SEQN			128

/*
 * IPMI packet header
 */
typedef struct {
	uint8_t channel_no;		/* channel num */
	uint8_t rs_addr;		/* dest addr */
	uint8_t netfn_lun;		/* netfn and lun */
	uint8_t checksum;		/* checksum for dest and netfn_lun */
	uint8_t rq_addr;		/* sender addr */
	uint8_t seq_num;		/* sequence number */
	uint8_t cmd;			/* ipmi cmd */
} smc_ipmi_header_t;

/*
 * debug printf
 */
static void
dbg_print(const char *fmt, ...)
{
	if (debug_on > 0) {
		va_list ap;
		va_start(ap, fmt);
		(void) vprintf(fmt, ap);
		va_end(ap);
	}
}

/*
 * send a local command to SMC
 */
static smc_errno_t
smc_send_local_cmd(int fd, sc_reqmsg_t *req_pkt, sc_rspmsg_t *rsp_pkt,
	int poll_time)
{
	int	poll_rc;
	struct pollfd	poll_fds[1];

	poll_fds[0].fd		= fd;
	poll_fds[0].events	= POLLIN|POLLPRI;
	poll_fds[0].revents	= 0;

	/* send the command to SMC */
	if (write(fd, req_pkt, SC_SEND_HEADER + SC_MSG_LEN(req_pkt)) < 0) {
		dbg_print(SMC_ERRMSG_WRITE, SC_MSG_CMD(req_pkt));
		return (SMC_REQ_FAILURE);
	}

	poll_rc = poll(poll_fds, 1, poll_time);
	if (poll_rc == 0) {
		dbg_print(SMC_ERRMSG_POLLTIMEOUT, SC_MSG_CMD(req_pkt));
		return (SMC_ACK_FAILURE);
	} else if (poll_rc == -1) {
		dbg_print(SMC_ERRMSG_POLLFAILED, SC_MSG_CMD(req_pkt));
		return (SMC_ACK_FAILURE);
	}

	/* read the response from SMC */
	if (read(fd, rsp_pkt, SC_MSG_MAX_SIZE) == -1) {
		dbg_print(SMC_ERRMSG_READ, SC_MSG_CMD(req_pkt));
		return (SMC_ACK_FAILURE);
	}

	/* check if response is valid */
	if (SC_MSG_ID(rsp_pkt) != SC_MSG_ID(req_pkt)) {
		dbg_print(SMC_ERRMSG_ERROR, SC_MSG_CC(rsp_pkt),
			SC_MSG_ID(rsp_pkt));
		return (SMC_INVALID_SEQ);
	}

	if (SC_MSG_CC(rsp_pkt) != 0) {
		return (SMC_FAILURE);
	}

	return (SMC_SUCCESS);
}

/*
 * get_geo_addr -- returns the geographical address of a CPU board
 */
static int
get_geo_addr(uint8_t *geo_addr)
{
	int	fd, rc;
	sc_reqmsg_t	req_pkt;
	sc_rspmsg_t	rsp_pkt;

	if ((fd = open(SMC_NODE, O_RDWR)) < 0) {
		dbg_print(SMC_ERRMSG_OPEN,
			SMC_GET_GEOGRAPHICAL_ADDRESS);
		return (SMC_FAILURE);
	}

	SC_MSG_CMD(&req_pkt) = SMC_GET_GEOGRAPHICAL_ADDRESS;
	SC_MSG_LEN(&req_pkt) = 0;
	SC_MSG_ID(&req_pkt)  =  SMC_LOCAL_SEQ_NO;

	/* no request data */
	if ((rc = smc_send_local_cmd(fd, &req_pkt, &rsp_pkt,
		SMC_POLL_TIME)) != SMC_SUCCESS) {
		(void) close(fd);
		return (rc);
	}

	*geo_addr = rsp_pkt.data[0];
	(void) close(fd);
	return (SMC_SUCCESS);
}

/*
 * checksum - returns a 2-complement check sum
 */
static uint8_t
checksum(uint8_t buf[], int start, int end)
{
	int	i;
	uint8_t	sum = 0x0;

	for (i = start; i <= end; i++) {
		sum += buf[i];
	}
	sum = ~sum + 1;
	return (sum);
}

/*
 * func to send IPMI messages
 */
static smc_errno_t
smc_send_ipmi_message(int fd, sc_reqmsg_t *req_pkt, sc_rspmsg_t *rsp_pkt,
	int poll_time)
{
	int		result, nbytes, i = 0;
	struct		pollfd fds;
	uint8_t		cc, netfn;
	boolean_t	is_response = B_FALSE;
	char data[SC_MSG_MAX_SIZE], *p;

	if (debug_on) {
		bzero(data, SC_MSG_MAX_SIZE);
		p = data;
		for (i = 0; i < SC_MSG_LEN(req_pkt); i++) {
			(void) sprintf(p, "%02x ", req_pkt->data[i]);
			p = data + strlen(data);
		}
		p = data;
		syslog(LOG_ERR, "REQ> %s", p);
	}

	netfn = req_pkt->data[2] >> 2;
	if (netfn & RESPONSE_MSG) {
		is_response = B_TRUE;
	}

	if ((nbytes = write(fd, (char *)req_pkt, SC_SEND_HEADER  +
		SC_MSG_LEN(req_pkt))) < 0) {
		dbg_print(SMC_ERRMSG_WRITE, SMC_SEND_MESSAGE);
		return (SMC_REQ_FAILURE);
	}

	if ((nbytes = read(fd, (char *)rsp_pkt, SC_MSG_MAX_SIZE)) < 0) {
		dbg_print(SMC_ERRMSG_READ, SMC_SEND_MESSAGE);
		return (SMC_ACK_FAILURE);
	}

	if (SC_MSG_CC(rsp_pkt) != 0) {
		dbg_print(SMC_ERRMSG_ERROR, SC_MSG_CC(rsp_pkt),
			SC_MSG_ID(rsp_pkt));
		return (SMC_ACK_FAILURE);
	}

	if (is_response) {	/* need not wait for response */
		return (SMC_SUCCESS);
	}

	fds.fd  = fd;
	fds.events = POLLIN | POLLPRI;
	fds.revents = 0;
	result = poll(&fds, 1, poll_time);

	if (result == 0) {
		dbg_print(SMC_ERRMSG_POLL_T, req_pkt->data[1]);
		return (SMC_RSP_TIMEOUT);
	} else if (result < 0) {
		dbg_print(SMC_ERRMSG_POLL_F, req_pkt->data[1]);
		return (SMC_RSP_ERROR);
	}

	nbytes = read(fd, rsp_pkt, SC_MSG_MAX_SIZE);
	if (nbytes < 0) {
		dbg_print(SMC_ERRMSG_READ, SMC_SEND_MESSAGE);
		return (SMC_RSP_ERROR);
	}

	if (debug_on) {
		bzero(data, SC_MSG_MAX_SIZE);
		p = data;
		for (i = 0; i < nbytes; i++) {
			(void) sprintf(p, "%02x ", rsp_pkt->data[i]);
			p = data + strlen(data);
		}
		p = data;
		syslog(LOG_DEBUG, "RES> %s, seq = %x, cmd = %x, len = %x,"
			"cc = %x", p, SC_MSG_ID(rsp_pkt), SC_MSG_CMD(rsp_pkt),
				SC_MSG_LEN(rsp_pkt), SC_MSG_CC(rsp_pkt));
	}

	if (SC_MSG_CC(rsp_pkt) != 0) {
		dbg_print(SMC_ERRMSG_IPMI_ERR, rsp_pkt->hdr.cc,
			req_pkt->data[SMC_CMD_OFFSET]);
		return (SMC_RSP_ERROR);
	}

	if (req_pkt->data[SMC_NETFN_SEQ_OFFSET] !=
		rsp_pkt->data[SMC_NETFN_SEQ_OFFSET]) {
		dbg_print("SMC: Invalid sequence number in"
		" IPMI Response (sent %x, received %x)\n",
			req_pkt->data[5], rsp_pkt->data[SMC_NETFN_SEQ_OFFSET]);
	}

	if ((cc = rsp_pkt->data[IPMI_RSP_HDR_LEN-1]) != 0) {
		dbg_print("SMC:IPMI response completion "
			"error %x, command = %x\n",
				cc, req_pkt->data[SMC_CMD_OFFSET]);
	}
	return (SMC_SUCCESS);
}

/*
 * Initializes the IPMI request packet
 */
smc_errno_t
smc_init_ipmi_msg(sc_reqmsg_t *req_msg, uint8_t cmd, uint8_t msg_id,
	uint8_t msg_data_size, uint8_t *msg_data_buf, int8_t seq_num,
	int ipmb_addr, smc_netfn_t netfn, smc_lun_t lun)
{
	static uint8_t	geo_addr = 0;
	smc_ipmi_header_t ipmi_header;
	uint8_t data[2];
	if (msg_data_size > 0) {
		if ((msg_data_size > (SC_SEND_DSIZE - IPMI_REQ_HDR_LEN)) ||
			(msg_data_buf == NULL)) {
			return (SMC_FAILURE);
		}
	}

	/* get the geo addr for first time */
	if (geo_addr == 0) {
		if (get_geo_addr(&geo_addr) != SMC_SUCCESS) {
			dbg_print(SMC_ERRMSG_GET_GEO);
			return (SMC_FAILURE);
		}
	}

	SC_MSG_CMD(req_msg) = SMC_SEND_MESSAGE;
	SC_MSG_ID(req_msg) = msg_id;
	SC_MSG_LEN(req_msg) = IPMI_REQ_HDR_LEN + msg_data_size;
	ipmi_header.channel_no = IPMI_MSG_CHANNEL_0;
	ipmi_header.rs_addr = data[0] = ipmb_addr;
	ipmi_header.netfn_lun = data[1] = (netfn << 2) | lun;
	ipmi_header.checksum = checksum(data, 0, 1);
	ipmi_header.rq_addr = REQ_SA(geo_addr);
	ipmi_header.cmd = cmd;
	if (seq_num >= 0 && seq_num < 64) {
		ipmi_header.seq_num = (seq_num << 2) | SMC_SMS_LUN;
	} else {
		ipmi_header.seq_num = DEFAULT_SEQN;
	}

	/* copy the header */
	(void) bcopy((void *)&ipmi_header, SC_MSG_DATA(req_msg),
		sizeof (ipmi_header));

	/* copy the msg data into request packet */
	(void) bcopy((void *)msg_data_buf, (void *)((uchar_t *)req_msg->data +
		(IPMI_REQ_HDR_LEN - 1)), msg_data_size);
	return (SMC_SUCCESS);
}

/*
 * Initialize a SMC packet
 */
smc_errno_t
smc_init_smc_msg(sc_reqmsg_t *req_msg, smc_app_command_t cmd,
	uint8_t msg_id, uint8_t msg_data_size)
{
	if (msg_data_size > SC_SEND_DSIZE) {
		return (SMC_FAILURE);
	}

	/* fill the packet */
	SC_MSG_CMD(req_msg) = cmd;
	SC_MSG_LEN(req_msg) = msg_data_size;
	SC_MSG_ID(req_msg) = msg_id;
	return (SMC_SUCCESS);
}

/*
 * Sends SMC(local) and IPMI messages
 */
smc_errno_t
smc_send_msg(int fd, sc_reqmsg_t *req_msg, sc_rspmsg_t *rsp_msg,
	int poll_time)
{
	int rc = SMC_SUCCESS;
	uint8_t dsize, dest;
	boolean_t close_fd = B_FALSE;
	boolean_t free_seqn = B_FALSE;
	struct strioctl	scioc;
	sc_seqdesc_t smc_seq;
	int8_t seq_no;

	if (req_msg == NULL || rsp_msg == NULL) {
		return (SMC_FAILURE);
	}

	if (fd <  0) {
		close_fd = B_TRUE;
		if ((fd = open(SMC_NODE, O_RDWR)) < 0) {
			dbg_print(SMC_ERRMSG_OPEN,
				SC_MSG_CMD(req_msg));
			return (SMC_FAILURE);
		}
	}

	if (ioctl(fd, I_SRDOPT, RMSGD) < 0) {
		dbg_print(SMC_ERRMSG_SETATTR);
		if (close_fd)
			(void) close(fd);
		return (SMC_FAILURE);
	}

	if (SC_MSG_CMD(req_msg) != SMC_SEND_MESSAGE) {
		rc = smc_send_local_cmd(fd, req_msg, rsp_msg, poll_time);
		if (close_fd) {
			(void) close(fd);
		}
		return (rc);
	}

	/* This is an IPMI message */
	dsize = SC_MSG_LEN(req_msg) - IPMI_REQ_HDR_LEN;
	if (dsize > (SC_SEND_DSIZE - IPMI_REQ_HDR_LEN)) {
		if (close_fd) {
			(void) close(fd);
		}
		return (SMC_FAILURE);
	}

	/* check if sequence num is valid or not */
	if (req_msg->data[SMC_NETFN_SEQ_OFFSET] == DEFAULT_SEQN) {
		free_seqn = B_TRUE;
		bzero(&smc_seq, sizeof (sc_seqdesc_t));
		dest = smc_seq.d_addr  = req_msg->data[1]; /* dest */
		smc_seq.n_seqn = 1;
		smc_seq.seq_numbers[0] = 0;
		scioc.ic_cmd = SCIOC_RESERVE_SEQN;
		scioc.ic_timout = 0;
		scioc.ic_len = sizeof (sc_seqdesc_t);
		scioc.ic_dp = (char *)&smc_seq;
		if (ioctl(fd, I_STR, &scioc)  < 0) {
			dbg_print(SMC_ERRMSG_GET_SEQN, dest);
			if (close_fd) {
				(void) close(fd);
			}
			return (SMC_FAILURE);
		}
		seq_no = smc_seq.seq_numbers[0];
		req_msg->data[SMC_NETFN_SEQ_OFFSET] =
			(seq_no << 2) | SMC_SMS_LUN;
	}

	req_msg->data[(IPMI_REQ_HDR_LEN-1)+dsize] =
		checksum(req_msg->data, 4, (IPMI_REQ_HDR_LEN-2)+dsize);

	rc = smc_send_ipmi_message(fd, req_msg, rsp_msg, poll_time);

	if (free_seqn) {	/* free seqn if library reserved it */
		smc_seq.d_addr = dest;
		smc_seq.n_seqn  = 1;
		smc_seq.seq_numbers[0] = seq_no;
		scioc.ic_cmd = SCIOC_FREE_SEQN;
		scioc.ic_timout = 0;
		scioc.ic_len = sizeof (sc_seqdesc_t);
		scioc.ic_dp = (char *)&smc_seq;
		if (ioctl(fd, I_STR, &scioc) < 0) {
			dbg_print("SMC:Error in releasing sequence "
					"number\n");
			rc = SMC_FAILURE;
		}
	}
	if (close_fd) {
		(void) close(fd);
	}
	return (rc);
}
