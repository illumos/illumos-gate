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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _RDR_MESSAGES_H
#define	_RDR_MESSAGES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * WARNING: The contents of this file are shared by all projects
 * that  wish to  perform  remote  Dynamic Reconfiguration  (DR)
 * operations. Copies of this file can be found in the following
 * locations:
 *
 *	Project	    Location
 *	-------	    --------
 *	Solaris	    usr/src/cmd/dcs/sparc/sun4u/%M%
 *	SMS	    src/sms/lib/librdr/%M%
 *
 * In order for proper communication to occur,  the files in the
 * above locations must match exactly. Any changes that are made
 * to this file should  be made to all of the files in the list.
 */

/*
 * This file is the interface to the Remote DR (RDR) module. It
 * contains prototypes for all relevant network operations such
 * as establishing a connection, sending and receiving messages,
 * and closing a connection. Also contained is an enumeration of
 * the error codes returned by these functions.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/socket.h>

/*
 * The DCA and DCS link this module in different ways. Because
 * of this, they each expect to find the headers in different
 * places. SMSLIB_TARGET will be defined for the DCA.
 */
#ifdef SMSLIB_TARGET

#include <librdr/remote_cfg.h>
#include <librdr/rdr_param_types.h>
#include <libscri/rsrc_info.h>

#else /* SMSLIB_TARGET */

#include "remote_cfg.h"
#include "rdr_param_types.h"
#include "rsrc_info.h"

int rdr_setsockopt(int fd, int level, int optname, const void *optval,
    int optlen);
#endif /* SMSLIB_TARGET */


int rdr_open(int family);

int rdr_init(int fd, struct sockaddr *addr, int *opts, int num_opts, int blog);

int rdr_connect_clnt(int fd, struct sockaddr *addr);

int rdr_connect_srv(int fd);

int rdr_reject(int fd);

int rdr_close(int fd);

int rdr_snd_msg(int fd, rdr_msg_hdr_t *hdr, cfga_params_t *param, int timeout);

int rdr_rcv_msg(int fd, rdr_msg_hdr_t *hdr, cfga_params_t *param, int timeout);

int rdr_cleanup_params(rdr_msg_opcode_t message_opcode, cfga_params_t *param);


/*
 * Return values for the RDR public functions. They
 * are offset to prevent overlapping with DCS error
 * codes, libcfgadm error codes, and DCA error codes.
 */
typedef enum {
	RDR_OK,
	RDR_ERROR = 500,
	RDR_NET_ERR,
	RDR_TIMEOUT,
	RDR_ABORTED,
	RDR_DISCONNECT,
	RDR_MSG_INVAL,
	RDR_MEM_ALLOC
} rdr_err_t;


#ifdef __cplusplus
}
#endif

#endif /* _RDR_MESSAGES_H */
