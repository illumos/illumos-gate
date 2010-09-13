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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>

#include "libipmi.h"
#include "ipmi_lan.h"
#include "ipmi_impl.h"

#define	DEF_IPMI_LAN_TIMEOUT		3 /* seconds */
#define	DEF_IPMI_LAN_NUM_RETRIES	5
#define	IPMI_LAN_CHANNEL_E		0x0e

typedef struct ipmi_rs {
	uint8_t		ir_data[IPMI_BUF_SIZE];
	int		ir_dlen;
	ipmi_msg_hdr_t	ir_ihdr;
	uint8_t		ir_ccode;
} ipmi_rs_t;

static ipmi_rs_t *ipmi_lan_poll_recv(ipmi_handle_t *);

typedef struct ipmi_rq_entry {
	ipmi_list_t	ire_list;
	ipmi_cmd_t	ire_req;
	uint8_t		ire_target_cmd;
	uint8_t		ire_rq_seq;
	uint8_t		*ire_msg_data;
	int		ire_msg_len;
} ipmi_rq_entry_t;

ipmi_rq_entry_t *ipmi_req_entries = NULL;

/*
 * LAN transport-specific data
 */
typedef struct ipmi_lan {
	ipmi_handle_t	*il_ihp;
	char		il_host[MAXHOSTNAMELEN + 1];
	uint16_t	il_port;
	char		il_user[17];
	char		il_authcode[IPMI_AUTHCODE_BUF_SIZE + 1];
	uint8_t		il_challenge[16];
	uint32_t	il_session_id;
	int 		il_sd;
	boolean_t	il_send_authcode;
	boolean_t	il_session_active;
	uint8_t		il_authtype;
	uint8_t		il_privlvl;
	uint8_t		il_num_retries;
	uint32_t	il_in_seq;
	uint32_t	il_timeout;
	struct sockaddr_in il_addr;
	socklen_t	il_addrlen;
} ipmi_lan_t;

/*
 * Calculate and returns IPMI checksum
 *
 * Checksum algorithm is described in Section 13.8
 *
 * d:		buffer to check
 * s:		position in buffer to start checksum from
 */
static uint8_t
ipmi_csum(uint8_t *d, int s)
{
	uint8_t c = 0;
	for (; s > 0; s--, d++)
		c += *d;
	return (-c);
}

static ipmi_rq_entry_t *
ipmi_req_add_entry(ipmi_handle_t *ihp, ipmi_cmd_t *req)
{
	ipmi_rq_entry_t *e;

	if ((e = ipmi_zalloc(ihp, sizeof (ipmi_rq_entry_t))) == NULL)
		return (NULL);

	(void) memcpy(&e->ire_req, req, sizeof (ipmi_cmd_t));
	ipmi_list_append(&ipmi_req_entries->ire_list, e);

	return (e);
}

/*ARGSUSED*/
static ipmi_rq_entry_t *
ipmi_req_lookup_entry(ipmi_handle_t *ihp, uint8_t seq, uint8_t cmd)
{
	ipmi_rq_entry_t *e;

	for (e = ipmi_list_next(&ipmi_req_entries->ire_list); e != NULL;
	    e = ipmi_list_next(e))
		if (e->ire_rq_seq == seq && e->ire_req.ic_cmd == cmd)
			return (e);

	return (NULL);
}

static void
ipmi_req_remove_entry(ipmi_handle_t *ihp, uint8_t seq, uint8_t cmd)
{
	ipmi_rq_entry_t *e;

	e = ipmi_req_lookup_entry(ihp, seq, cmd);

	if (e) {
		ipmi_list_delete(&ipmi_req_entries->ire_list, e);
		ipmi_free(ihp, e->ire_msg_data);
		ipmi_free(ihp, e);
	}
}

static void
ipmi_req_clear_entries(ipmi_handle_t *ihp)
{
	ipmi_rq_entry_t *e;

	while ((e = ipmi_list_next(&ipmi_req_entries->ire_list)) != NULL) {
		ipmi_list_delete(&ipmi_req_entries->ire_list, e);
		ipmi_free(ihp, e);
	}
}

static int
get_random(void *buf, uint_t len)
{
	int fd;

	assert(buf != NULL && len > 0);
	if ((fd = open("/dev/urandom", O_RDONLY)) < 0)
		return (-1);

	if (read(fd, buf, len) < 0) {
		(void) close(fd);
		return (-1);
	}
	(void) close(fd);
	return (0);
}

static int
ipmi_lan_send_packet(ipmi_handle_t *ihp, uint8_t *data, int dlen)
{
	ipmi_lan_t *ilp = (ipmi_lan_t *)ihp->ih_tdata;

	return (send(ilp->il_sd, data, dlen, 0));
}

static ipmi_rs_t *
ipmi_lan_recv_packet(ipmi_handle_t *ihp)
{
	static ipmi_rs_t rsp;
	fd_set read_set, err_set;
	struct timeval tmout;
	ipmi_lan_t *ilp = (ipmi_lan_t *)ihp->ih_tdata;
	int ret;

	FD_ZERO(&read_set);
	FD_SET(ilp->il_sd, &read_set);

	FD_ZERO(&err_set);
	FD_SET(ilp->il_sd, &err_set);

	tmout.tv_sec = 	ilp->il_timeout;
	tmout.tv_usec = 0;

	ret = select(ilp->il_sd + 1, &read_set, NULL, &err_set, &tmout);
	if (ret < 0 || FD_ISSET(ilp->il_sd, &err_set) ||
	    !FD_ISSET(ilp->il_sd, &read_set))
		return (NULL);

	/*
	 * The first read may return ECONNREFUSED because the rmcp ping
	 * packet--sent to UDP port 623--will be processed by both the
	 * BMC and the OS.
	 *
	 * The problem with this is that the ECONNREFUSED takes
	 * priority over any other received datagram; that means that
	 * the Connection Refused shows up _before_ the response packet,
	 * regardless of the order they were sent out.  (unless the
	 * response is read before the connection refused is returned)
	 */
	ret = recv(ilp->il_sd, &rsp.ir_data, IPMI_BUF_SIZE, 0);

	if (ret < 0) {
		FD_ZERO(&read_set);
		FD_SET(ilp->il_sd, &read_set);

		FD_ZERO(&err_set);
		FD_SET(ilp->il_sd, &err_set);

		tmout.tv_sec = ilp->il_timeout;
		tmout.tv_usec = 0;

		ret = select(ilp->il_sd + 1, &read_set, NULL, &err_set, &tmout);
		if (ret < 0) {
			if (FD_ISSET(ilp->il_sd, &err_set) ||
			    !FD_ISSET(ilp->il_sd, &read_set))
				return (NULL);

			ret = recv(ilp->il_sd, &rsp.ir_data, IPMI_BUF_SIZE, 0);
			if (ret < 0)
				return (NULL);
		}
	}

	if (ret == 0)
		return (NULL);

	rsp.ir_data[ret] = '\0';
	rsp.ir_dlen = ret;

	return (&rsp);
}


/*
 * ASF/RMCP Pong Message
 *
 * See section 13.2.4
 */
struct rmcp_pong {
	rmcp_hdr_t rp_rmcp;
	asf_hdr_t rp_asf;
	uint32_t rp_iana;
	uint32_t rp_oem;
	uint8_t rp_sup_entities;
	uint8_t rp_sup_interact;
	uint8_t rp_reserved[6];
};

/*
 * parse response RMCP "pong" packet
 *
 * return -1 if ping response not received
 * returns 0 if IPMI is NOT supported
 * returns 1 if IPMI is supported
 */
/*ARGSUSED*/
static int
ipmi_handle_pong(ipmi_handle_t *ihp, ipmi_rs_t *rsp)
{
	struct rmcp_pong *pong;

	if (rsp == NULL)
		return (-1);

	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	pong = (struct rmcp_pong *)rsp->ir_data;

	return ((pong->rp_sup_entities & 0x80) ? 1 : 0);
}

/*
 * Build and send RMCP presence ping message
 */
static int
ipmi_lan_ping(ipmi_handle_t *ihp)
{
	rmcp_hdr_t rmcp_ping;
	asf_hdr_t asf_ping;
	uint8_t *data;
	int rv, dlen = sizeof (rmcp_ping) + sizeof (asf_ping);

	(void) memset(&rmcp_ping, 0, sizeof (rmcp_ping));
	rmcp_ping.rh_version = RMCP_VERSION_1;
	rmcp_ping.rh_msg_class = RMCP_CLASS_ASF;
	rmcp_ping.rh_seq = 0xff;

	(void) memset(&asf_ping, 0, sizeof (asf_ping));
	asf_ping.ah_iana = htonl(ASF_RMCP_IANA);
	asf_ping.ah_msg_type = ASF_TYPE_PING;

	if ((data = ipmi_zalloc(ihp, dlen)) == NULL)
		return (-1);

	(void) memcpy(data, &rmcp_ping, sizeof (rmcp_ping));
	(void) memcpy(data + sizeof (rmcp_ping), &asf_ping, sizeof (asf_ping));

	rv = ipmi_lan_send_packet(ihp, data, dlen);

	ipmi_free(ihp, data);

	if (rv < 0)
		return (ipmi_set_error(ihp, EIPMI_LAN_PING_FAILED, NULL));

	if (ipmi_lan_poll_recv(ihp) == NULL)
		return (ipmi_set_error(ihp, EIPMI_LAN_PING_FAILED, NULL));

	return (0);
}

static ipmi_rs_t *
ipmi_lan_poll_recv(ipmi_handle_t *ihp)
{
	rmcp_hdr_t rmcp_rsp;
	ipmi_rs_t *rsp;
	ipmi_rq_entry_t *entry;
	int off = 0, rv;
	ipmi_lan_t *ilp = (ipmi_lan_t *)ihp->ih_tdata;
	uint8_t rsp_authtype;

	rsp = ipmi_lan_recv_packet(ihp);

	while (rsp != NULL) {

		/* parse response headers */
		(void) memcpy(&rmcp_rsp, rsp->ir_data, 4);

		switch (rmcp_rsp.rh_msg_class) {
		case RMCP_CLASS_ASF:
			/* ping response packet */
			rv = ipmi_handle_pong(ihp, rsp);
			return ((rv <= 0) ? NULL : rsp);
		case RMCP_CLASS_IPMI:
			/* handled by rest of function */
			break;
		default:
			/* Invalid RMCP class */
			rsp = ipmi_lan_recv_packet(ihp);
			continue;
		}

		off = sizeof (rmcp_hdr_t);
		rsp_authtype = rsp->ir_data[off];
		if (ilp->il_send_authcode && (rsp_authtype || ilp->il_authtype))
			off += 26;
		else
			off += 10;

		(void) memcpy(&rsp->ir_ihdr, (void *)(rsp->ir_data + off),
		    sizeof (rsp->ir_ihdr));
		rsp->ir_ihdr.imh_seq = rsp->ir_ihdr.imh_seq >> 2;
		off += sizeof (rsp->ir_ihdr);
		rsp->ir_ccode = rsp->ir_data[off++];

		entry = ipmi_req_lookup_entry(ihp, rsp->ir_ihdr.imh_seq,
		    rsp->ir_ihdr.imh_cmd);
		if (entry) {
			ipmi_req_remove_entry(ihp, rsp->ir_ihdr.imh_seq,
			    rsp->ir_ihdr.imh_cmd);
		} else {
			rsp = ipmi_lan_recv_packet(ihp);
			continue;
		}
		break;
	}

	/* shift response data to start of array */
	if (rsp && rsp->ir_dlen > off) {
		rsp->ir_dlen -= off + 1;
		(void) memmove(rsp->ir_data, rsp->ir_data + off, rsp->ir_dlen);
		(void) memset(rsp->ir_data + rsp->ir_dlen, 0,
		    IPMI_BUF_SIZE - rsp->ir_dlen);
	}
	return (rsp);
}

/*
 * IPMI LAN Request Message Format
 *
 * See section 13.8
 *
 * +---------------------+
 * |  rmcp_hdr_t         | 4 bytes
 * +---------------------+
 * |  v15_session_hdr_t  | 9 bytes
 * +---------------------+
 * | [authcode]          | 16 bytes (if AUTHTYPE != none)
 * +---------------------+
 * |  msg length         | 1 byte
 * +---------------------+
 * |  ipmi_msg_hdr_t     | 6 bytes
 * +---------------------+
 * | [msg data]          | variable
 * +---------------------+
 * |  msg data checksum  | 1 byte
 * +---------------------+
 */
static ipmi_rq_entry_t *
ipmi_lan_build_cmd(ipmi_handle_t *ihp, ipmi_cmd_t *req)
{
	ipmi_lan_t *ilp = (ipmi_lan_t *)ihp->ih_tdata;
	rmcp_hdr_t rmcp_hdr;
	v15_session_hdr_t session_hdr;
	ipmi_msg_hdr_t msg_hdr;
	uint8_t *msg;
	int cs, tmp, off = 0, len;
	ipmi_rq_entry_t *entry;
	static int curr_seq = 0;

	if (curr_seq >= 64)
		curr_seq = 0;

	if ((entry = ipmi_req_add_entry(ihp, req)) == NULL)
		return (NULL);

	len = req->ic_dlen + 29;
	if (ilp->il_send_authcode && ilp->il_authtype)
		len += 16;

	if ((msg = ipmi_zalloc(ihp, len)) == NULL)
		/* ipmi_errno set */
		return (NULL);

	/* RMCP header */
	(void) memset(&rmcp_hdr, 0, sizeof (rmcp_hdr));
	rmcp_hdr.rh_version = RMCP_VERSION_1;
	rmcp_hdr.rh_msg_class = RMCP_CLASS_IPMI;
	rmcp_hdr.rh_seq = 0xff;
	(void) memcpy(msg, &rmcp_hdr, sizeof (rmcp_hdr));
	off = sizeof (rmcp_hdr);

	/* IPMI session header */
	(void) memset(&session_hdr, 0, sizeof (session_hdr));
	if (! ilp->il_send_authcode)
		session_hdr.sh_authtype = 0x00;
	else
		/* hardcode passwd authentication */
		session_hdr.sh_authtype = 0x04;

	(void) memcpy(&session_hdr.sh_seq, &ilp->il_in_seq, sizeof (uint32_t));
	(void) memcpy(&session_hdr.sh_id, &ilp->il_session_id,
	    sizeof (uint32_t));

	(void) memcpy(msg + off, &session_hdr, sizeof (session_hdr));
	off += sizeof (session_hdr);

	/* IPMI session authcode */
	if (ilp->il_send_authcode && ilp->il_authtype) {
		(void) memcpy(msg + off, ilp->il_authcode, 16);
		off += 16;
	}

	/* message length */
	msg[off++] = req->ic_dlen + 7;
	cs = off;

	/* IPMI message header */
	(void) memset(&msg_hdr, 0, sizeof (msg_hdr));
	msg_hdr.imh_addr1 = IPMI_BMC_SLAVE_ADDR;
	msg_hdr.imh_lun = req->ic_lun;
	msg_hdr.imh_netfn = req->ic_netfn;
	tmp = off - cs;
	msg_hdr.imh_csum = ipmi_csum(msg + cs, tmp);
	cs = off;
	msg_hdr.imh_addr2 = IPMI_BMC_SLAVE_ADDR;
	entry->ire_rq_seq = curr_seq++;
	msg_hdr.imh_seq = entry->ire_rq_seq << 2;
	msg_hdr.imh_cmd = req->ic_cmd;
	(void) memcpy(msg + off, &msg_hdr, sizeof (msg_hdr));
	off += sizeof (msg_hdr);

	/* message data */
	if (req->ic_dlen != 0) {
		(void) memcpy(msg + off, req->ic_data, req->ic_dlen);
		off += req->ic_dlen;
	}

	/* message data checksum */
	tmp = off - cs;
	msg[off++] = ipmi_csum(msg + cs, tmp);

	if (ilp->il_in_seq) {
		ilp->il_in_seq++;
		if (ilp->il_in_seq == 0)
			ilp->il_in_seq++;
	}

	entry->ire_msg_len = off;
	entry->ire_msg_data = msg;

	return (entry);
}

static int
ipmi_lan_send(void *data, ipmi_cmd_t *cmd, ipmi_cmd_t *response,
    int *completion)
{
	ipmi_lan_t *ilp = (ipmi_lan_t *)data;
	ipmi_rq_entry_t *entry = NULL;
	ipmi_rs_t *rsp = NULL;
	uint_t try = 0;

	for (;;) {
		if ((entry = ipmi_lan_build_cmd(ilp->il_ihp, cmd)) == NULL)
			return (-1);

		if (ipmi_lan_send_packet(ilp->il_ihp, entry->ire_msg_data,
		    entry->ire_msg_len) < 0) {
			if (++try >= ilp->il_num_retries)
				return (-1);
			(void) usleep(5000);
			continue;
		}

		(void) usleep(100);

		if ((rsp = ipmi_lan_poll_recv(ilp->il_ihp)) != NULL)
			break;

		(void) usleep(5000);
		ipmi_req_remove_entry(ilp->il_ihp, entry->ire_rq_seq,
		    entry->ire_req.ic_cmd);

		if (++try >= ilp->il_num_retries)
			return (-1);
	}
	response->ic_netfn = rsp->ir_ihdr.imh_netfn;
	response->ic_lun = rsp->ir_ihdr.imh_lun;
	response->ic_cmd = rsp->ir_ihdr.imh_cmd;
	if (rsp->ir_ccode != 0) {
		*completion = rsp->ir_ccode;
		response->ic_dlen = 0;
		response->ic_data = NULL;
	} else {
		*completion = 0;
		response->ic_dlen = rsp->ir_dlen;
		response->ic_data = rsp->ir_data;
	}
	return (0);
}

/*
 * IPMI Get Session Challenge Command
 *
 * Copies the returned session ID and 16-byte challenge string to the supplied
 * buffers
 *
 * See section 22.16
 */
static int
ipmi_get_session_challenge_cmd(ipmi_handle_t *ihp, uint32_t *session_id,
    uint8_t *challenge)
{
	ipmi_cmd_t cmd, resp;
	ipmi_lan_t *ilp = (ipmi_lan_t *)ihp->ih_tdata;
	char msg_data[17];
	int ccode;

	(void) memset(msg_data, 0, 17);

	switch (ilp->il_authtype) {
	case IPMI_SESSION_AUTHTYPE_NONE:
		msg_data[0] = 0x00;
		break;
	case IPMI_SESSION_AUTHTYPE_MD2:
		msg_data[0] = 0x01;
		break;
	case IPMI_SESSION_AUTHTYPE_MD5:
		msg_data[0] = 0x02;
		break;
	case IPMI_SESSION_AUTHTYPE_PASSWORD:
		msg_data[0] = 0x04;
		break;
	case IPMI_SESSION_AUTHTYPE_OEM:
		msg_data[0] = 0x05;
		break;
	}
	(void) memcpy(msg_data + 1, ilp->il_user, 16);

	cmd.ic_netfn = IPMI_NETFN_APP;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_GET_SESSION_CHALLENGE;
	cmd.ic_data = msg_data;
	cmd.ic_dlen = 17;

	if (ipmi_lan_send(ilp, &cmd, &resp, &ccode) != 0 || ccode)
		return (ipmi_set_error(ihp, EIPMI_LAN_CHALLENGE, NULL));

	(void) memcpy(session_id, resp.ic_data, 4);
	(void) memcpy(challenge, (uint8_t *)resp.ic_data + 4, 16);

	return (0);
}

/*
 * IPMI Activate Session Command
 *
 * See section 22.17
 */
static int
ipmi_activate_session_cmd(ipmi_handle_t *ihp)
{
	ipmi_cmd_t cmd, resp;
	ipmi_lan_t *ilp = (ipmi_lan_t *)ihp->ih_tdata;
	uint8_t msg_data[22], *resp_data;
	int ccode;

	cmd.ic_netfn = IPMI_NETFN_APP;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_ACTIVATE_SESSION;

	switch (ilp->il_authtype) {
	case IPMI_SESSION_AUTHTYPE_NONE:
		msg_data[0] = 0x00;
		break;
	case IPMI_SESSION_AUTHTYPE_MD2:
		msg_data[0] = 0x01;
		break;
	case IPMI_SESSION_AUTHTYPE_MD5:
		msg_data[0] = 0x02;
		break;
	case IPMI_SESSION_AUTHTYPE_PASSWORD:
		msg_data[0] = 0x04;
		break;
	case IPMI_SESSION_AUTHTYPE_OEM:
		msg_data[0] = 0x05;
		break;
	}
	msg_data[1] = ilp->il_privlvl;

	(void) memcpy(msg_data + 2, ilp->il_challenge, 16);

	/* setup initial outbound sequence number */
	(void) get_random(msg_data + 18, 4);

	cmd.ic_data = msg_data;
	cmd.ic_dlen = 22;

	ilp->il_send_authcode = B_TRUE;

	if (ipmi_lan_send(ilp, &cmd, &resp, &ccode) != 0 || ccode) {
		ilp->il_send_authcode = B_FALSE;
		return (ipmi_set_error(ihp, EIPMI_LAN_SESSION, NULL));
	}

	resp_data = (uint8_t *)resp.ic_data;
	(void) memcpy(&ilp->il_session_id, resp_data + 1, 4);
	ilp->il_in_seq = resp_data[8] << 24 | resp_data[7] << 16 |
	    resp_data[6] << 8 | resp_data[5];
	if (ilp->il_in_seq == 0)
		++ilp->il_in_seq;

	return (0);
}


/*
 * See section 22.18
 *
 * returns privilege level or -1 on error
 */
static int
ipmi_set_session_privlvl_cmd(ipmi_handle_t *ihp, uint8_t privlvl)
{
	ipmi_cmd_t cmd, resp;
	int ret = 0, ccode;

	if (privlvl > IPMI_SESSION_PRIV_OEM)
		return (ipmi_set_error(ihp, EIPMI_BADPARAM, NULL));

	cmd.ic_netfn	= IPMI_NETFN_APP;
	cmd.ic_lun 	= 0;
	cmd.ic_cmd	= IPMI_CMD_SET_SESSION_PRIVLVL;
	cmd.ic_data	= &privlvl;
	cmd.ic_dlen	= 1;

	if (ipmi_lan_send(ihp->ih_tdata, &cmd, &resp, &ccode) != 0)
		ret = ipmi_set_error(ihp, EIPMI_LAN_SETPRIV, NULL);

	return (ret);
}

/*
 * See section 22.19
 */
static int
ipmi_close_session_cmd(ipmi_handle_t *ihp)
{
	ipmi_lan_t *ilp = (ipmi_lan_t *)ihp->ih_tdata;
	ipmi_cmd_t cmd, resp;
	uint8_t msg_data[4];
	int ret = 0, ccode;

	if (! ilp->il_session_active)
		return (-1);

	(void) memcpy(&msg_data, &ilp->il_session_id, 4);

	cmd.ic_netfn	= IPMI_NETFN_APP;
	cmd.ic_lun	= 0;
	cmd.ic_cmd	= IPMI_CMD_CLOSE_SESSION;
	cmd.ic_data	= msg_data;
	cmd.ic_dlen	= 4;

	if (ipmi_lan_send(ilp, &cmd, &resp, &ccode) != 0)
		ret = -1;

	return (ret);
}

/*
 * IPMI LAN Session Activation
 *
 * See section 13.14
 *
 * 1. send "RMCP Presence Ping" message, response message will
 *    indicate whether the platform supports IPMI
 * 2. send "Get Channel Authentication Capabilities" command
 *    with AUTHTYPE = none, response packet will contain information
 *    about supported challenge/response authentication types
 * 3. send "Get Session Challenge" command with AUTHTYPE = none
 *    and indicate the authentication type in the message, response
 *    packet will contain challenge string and temporary session ID.
 * 4. send "Activate Session" command, authenticated with AUTHTYPE
 *    sent in previous message.  Also sends the initial value for
 *    the outbound sequence number for BMC.
 * 5. BMC returns response confirming session activation and
 *    session ID for this session and initial inbound sequence.
 */
static int
ipmi_lan_activate_session(ipmi_handle_t *ihp)
{
	ipmi_lan_t *ilp = (ipmi_lan_t *)ihp->ih_tdata;
	ipmi_channel_auth_caps_t *ac;

	if (ipmi_lan_ping(ihp) != 0)
		return (-1);

	if ((ac = ipmi_get_channel_auth_caps(ihp, IPMI_LAN_CHANNEL_E,
	    ilp->il_privlvl)) == NULL)
		return (-1);

	/*
	 * For the sake of simplicity, we're just supporting basic password
	 * authentication.  If this authentication type is not supported then
	 * we'll bail here.
	 */
	if (!(ac->cap_authtype & IPMI_SESSION_AUTHTYPE_PASSWORD)) {
		free(ac);
		return (ipmi_set_error(ihp, EIPMI_LAN_PASSWD_NOTSUP, NULL));
	}
	free(ac);

	if (ipmi_get_session_challenge_cmd(ihp, &ilp->il_session_id,
	    ilp->il_challenge) != 0)
		return (-1);

	if (ipmi_activate_session_cmd(ihp) != 0)
		return (-1);

	ilp->il_session_active = B_TRUE;

	if (ipmi_set_session_privlvl_cmd(ihp, ilp->il_privlvl) != 0)
		return (-1);

	return (0);
}

static void
ipmi_lan_close(void *data)
{
	ipmi_lan_t *ilp = (ipmi_lan_t *)data;

	if (ilp->il_session_active)
		(void) ipmi_close_session_cmd(ilp->il_ihp);

	if (ilp->il_sd >= 0)
		(void) close(ilp->il_sd);

	ipmi_req_clear_entries(ilp->il_ihp);
	ipmi_free(ilp->il_ihp, ipmi_req_entries);
	ipmi_free(ilp->il_ihp, ilp);
}

static void *
ipmi_lan_open(ipmi_handle_t *ihp, nvlist_t *params)
{
	int rc;
	struct hostent *host;
	ipmi_lan_t *ilp;
	char *hostname, *user, *authcode;

	if ((ilp = ipmi_zalloc(ihp, sizeof (ipmi_lan_t))) == NULL) {
		/* ipmi errno set */
		return (NULL);
	}
	ilp->il_ihp = ihp;
	ihp->ih_tdata = ilp;

	/*
	 * Parse the parameters passed in the params nvlist.  The following
	 * parameters are required
	 *  IPMI_LAN_HOST, IPMI_LAN_USER and IPMI_LAN_PASSWD
	 *
	 * If any of these were not specified then we abort
	 */
	if (nvlist_lookup_string(params, IPMI_LAN_HOST, &hostname) ||
	    nvlist_lookup_string(params, IPMI_LAN_USER, &user) ||
	    nvlist_lookup_string(params, IPMI_LAN_PASSWD, &authcode)) {
		ipmi_free(ihp, ilp);
		(void) ipmi_set_error(ihp, EIPMI_BADPARAM, NULL);
		return (NULL);
	}
	(void) strncpy(ilp->il_host, hostname, MAXHOSTNAMELEN);
	(void) strncpy(ilp->il_user, user, 16);
	(void) strncpy(ilp->il_authcode, authcode, 16);

	/*
	 * IPMI_LAN_PORT is an optional parameter and defaults to port 623
	 * IPMI_LAN_PRIVLVL is also optional and defaults to admin
	 * IPMI_LAN_TIMEOUT is optional and will default to 3 seconds
	 * IPMI_LAN_NUM_RETIES is optional and will default to 5
	 */
	if (nvlist_lookup_uint16(params, IPMI_LAN_PORT, &ilp->il_port))
		ilp->il_port = RMCP_UDP_PORT;

	if (nvlist_lookup_uint8(params, IPMI_LAN_PRIVLVL, &ilp->il_privlvl))
		ilp->il_privlvl = IPMI_SESSION_PRIV_ADMIN;

	if (nvlist_lookup_uint32(params, IPMI_LAN_TIMEOUT, &ilp->il_timeout))
		ilp->il_timeout = DEF_IPMI_LAN_TIMEOUT;

	if (nvlist_lookup_uint8(params, IPMI_LAN_NUM_RETRIES,
	    &ilp->il_num_retries))
		ilp->il_num_retries = DEF_IPMI_LAN_NUM_RETRIES;

	ilp->il_authtype = IPMI_SESSION_AUTHTYPE_PASSWORD;

	/*
	 * Open up and connect a UDP socket between us and the service
	 * processor
	 */
	ilp->il_addr.sin_family = AF_INET;
	ilp->il_addr.sin_port = htons(ilp->il_port);

	rc = inet_pton(AF_INET, (const char *)ilp->il_host,
	    &ilp->il_addr.sin_addr);
	if (rc <= 0) {
		if ((host = gethostbyname((const char *)ilp->il_host))
		    == NULL) {
			ipmi_free(ihp, ilp);
			(void) ipmi_set_error(ihp, EIPMI_LAN_OPEN_FAILED, NULL);
			return (NULL);
		}
		ilp->il_addr.sin_family = host->h_addrtype;
		(void) memcpy(&ilp->il_addr.sin_addr, host->h_addr,
		    host->h_length);
	}

	if ((ilp->il_sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		ipmi_free(ihp, ilp);
		(void) ipmi_set_error(ihp, EIPMI_LAN_OPEN_FAILED, NULL);
		return (NULL);
	}
	if (connect(ilp->il_sd, (struct sockaddr *)&ilp->il_addr,
	    sizeof (struct sockaddr_in)) < 0) {
		ipmi_lan_close(ilp);
		(void) ipmi_set_error(ihp, EIPMI_LAN_OPEN_FAILED, NULL);
		return (NULL);
	}

	if ((ipmi_req_entries = ipmi_zalloc(ihp, sizeof (ipmi_rq_entry_t)))
	    == NULL)
		return (NULL);

	/*
	 * Finally we start up the IPMI LAN session
	 */
	if ((rc = ipmi_lan_activate_session(ihp)) < 0) {
		ipmi_lan_close(ilp);
		return (NULL);
	}

	return (ilp);
}

ipmi_transport_t ipmi_transport_lan = {
	ipmi_lan_open,
	ipmi_lan_close,
	ipmi_lan_send
};
