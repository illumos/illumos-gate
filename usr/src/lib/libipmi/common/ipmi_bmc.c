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
 * Copyright 2012 Joyent, Inc.  All rights reserved.
 */

#include <errno.h>
#include <fcntl.h>
#include <libipmi.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>

#include <sys/ipmi.h>

#include "ipmi_impl.h"

/*
 * IPMI transport for the local BMC at /dev/ipmi.
 */

typedef struct ipmi_bmc {
	ipmi_handle_t	*ib_ihp;	/* ipmi handle */
	int		ib_fd;		/* /dev/ipmi filedescriptor */
	uint32_t	ib_msgseq;	/* message sequence number */
	uint8_t		*ib_msg;	/* message buffer */
	size_t		ib_msglen;	/* size of message buffer */
} ipmi_bmc_t;

#define	BMC_DEV	"/dev/ipmi"

static void
ipmi_bmc_close(void *data)
{
	ipmi_bmc_t *ibp = data;

	ipmi_free(ibp->ib_ihp, ibp->ib_msg);

	(void) close(ibp->ib_fd);

	ipmi_free(ibp->ib_ihp, ibp);
}

/*ARGSUSED*/
static void *
ipmi_bmc_open(ipmi_handle_t *ihp, nvlist_t *params)
{
	ipmi_bmc_t *ibp;

	if ((ibp = ipmi_zalloc(ihp, sizeof (ipmi_bmc_t))) == NULL)
		return (NULL);
	ibp->ib_ihp = ihp;

	/* open /dev/ipmi */
	if ((ibp->ib_fd = open(BMC_DEV, O_RDWR)) < 0) {
		ipmi_free(ihp, ibp);
		(void) ipmi_set_error(ihp, EIPMI_BMC_OPEN_FAILED, "%s",
		    strerror(errno));
		return (NULL);
	}

	if ((ibp->ib_msg = (uint8_t *)ipmi_zalloc(ihp, BUFSIZ)) == NULL) {
		ipmi_bmc_close(ibp);
		return (NULL);
	}
	ibp->ib_msglen = BUFSIZ;

	return (ibp);
}

static int
ipmi_bmc_send(void *data, ipmi_cmd_t *cmd, ipmi_cmd_t *response,
    int *completion)
{
	ipmi_bmc_t *ibp = data;
	struct ipmi_req req;
	struct ipmi_recv recv;
	struct ipmi_addr addr;
	fd_set rset;
	struct ipmi_system_interface_addr bmc_addr;

	bmc_addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	bmc_addr.channel = IPMI_BMC_CHANNEL;
	bmc_addr.lun = cmd->ic_lun;

	(void) memset(&req, 0, sizeof (struct ipmi_req));

	req.addr = (unsigned char *) &bmc_addr;
	req.addr_len = sizeof (bmc_addr);

	req.msgid = ibp->ib_msgseq++;
	req.msg.netfn = cmd->ic_netfn;
	req.msg.cmd = cmd->ic_cmd;
	req.msg.data = cmd->ic_data;
	req.msg.data_len = cmd->ic_dlen;

	if (ioctl(ibp->ib_fd, IPMICTL_SEND_COMMAND, &req) < 0) {
		(void) ipmi_set_error(ibp->ib_ihp, EIPMI_BMC_PUTMSG, "%s",
		    strerror(errno));
		return (-1);
	}

	/* get the response from the BMC */

	FD_ZERO(&rset);
	FD_SET(ibp->ib_fd, &rset);

	if (select(ibp->ib_fd + 1, &rset, NULL, NULL, NULL) < 0) {
		(void) ipmi_set_error(ibp->ib_ihp, EIPMI_BMC_GETMSG, "%s",
		    strerror(errno));
		return (-1);
	}
	if (FD_ISSET(ibp->ib_fd, &rset) == 0) {
		(void) ipmi_set_error(ibp->ib_ihp, EIPMI_BMC_GETMSG, "%s",
		    "No data available");
		return (-1);
	}

	recv.addr = (unsigned char *) &addr;
	recv.addr_len = sizeof (addr);
	recv.msg.data = (unsigned char *)ibp->ib_msg;
	recv.msg.data_len = ibp->ib_msglen;

	/* get data */
	if (ioctl(ibp->ib_fd, IPMICTL_RECEIVE_MSG_TRUNC, &recv) < 0) {
		(void) ipmi_set_error(ibp->ib_ihp, EIPMI_BMC_GETMSG, "%s",
		    strerror(errno));
		return (-1);
	}

	if (recv.recv_type != IPMI_RESPONSE_RECV_TYPE) {
		(void) ipmi_set_error(ibp->ib_ihp, EIPMI_BMC_RESPONSE,
		    "unknown BMC message type %d", recv.recv_type);
		return (-1);
	}

	response->ic_netfn = recv.msg.netfn;
	/* The lun is not returned in addr, return the lun passed in */
	response->ic_lun = cmd->ic_lun;
	response->ic_cmd = recv.msg.cmd;
	if (recv.msg.data[0] != 0) {
		*completion = recv.msg.data[0];
		response->ic_dlen = 0;
		response->ic_data = NULL;
	} else {
		*completion = 0;
		response->ic_dlen = (recv.msg.data_len > 0) ?
		    recv.msg.data_len - 1 : 0;
		response->ic_data = &(recv.msg.data[1]);
	}

	return (0);
}

ipmi_transport_t ipmi_transport_bmc = {
	ipmi_bmc_open,
	ipmi_bmc_close,
	ipmi_bmc_send
};
