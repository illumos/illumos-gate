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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBRSC_H
#define	_LIBRSC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/rmc_comm_lproto.h>
#include <sys/rmc_comm_hproto.h>
#include <sys/rmc_comm_dp_boot.h>
#include <sys/rmcadm.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The structure used to pass messages into and out of this layer.
 */
typedef struct rscp_msg {
	rsci8   type;
	rsci32  len;
	void   *data;
	void   *private;
} rscp_msg_t;

typedef void rscp_bpmsg_cb_t(bp_msg_t *msg);

#define	RSC_RMCADM_DRV		"/devices/pseudo/rmcadm@0:rmcadm"

#define	RSC_MAX_RX_BUFFER	DP_MAX_MSGLEN


/*
 * this table is used to match request/response in order to provide
 * backward compatibility to obsolete functions: rscp_send(), rscp_recv(),
 *
 * in the old way, send and receive were decoupled: applications sent a
 * request (rscp_send) and waited for a reply (rscp_recv) using two different
 * calls.
 * As the ioctl to the communication driver is a single call, send and receive
 * cannot be decoupled. So, when the rscp_send is called, this table will tell
 * which reply is expected and in what time. The reply is then stored in a
 * temporary buffer. When the rscp_recv is called, it will return the
 * content of the temporary buffer (if a reply was received) or an error
 */
typedef struct req_resp_table {

	uint8_t		req_type;
	uint8_t		resp_type;
	uint16_t	resp_size;
	uint_t		timeout;

} req_resp_table_t;


/* timeout value (millisecs) for request/response sessions */

#define	RR_TIMEOUT		10000
#define	RR_SEPROM_TIMEOUT	10000

#define	RR_BOOT_INIT_TIMEOUT	1000
#define	RR_BOOT_LOAD_TIMEOUT	10000
#define	RR_BOOT_RESET_TIMEOUT	0
#define	RR_BP_TIMEOUT		1000


/* function prototypes */

int rscp_init(void);
int rscp_send_recv(rscp_msg_t *, rscp_msg_t *, struct timespec *);
int rsc_nmi(void);


/* function prototypes for firmware download */

int rscp_register_bpmsg_cb(rscp_bpmsg_cb_t *);
int rscp_unregister_bpmsg_cb(rscp_bpmsg_cb_t *);
void rscp_send_bpmsg(bp_msg_t *);
int rsc_raw_write(char *, int);


/* prototypes of obsolete functions */

int rscp_send(rscp_msg_t *);
int rscp_recv(rscp_msg_t *, struct timespec *);
int rscp_start(void);
int rscp_free_msg(rscp_msg_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _LIBRSC_H */
