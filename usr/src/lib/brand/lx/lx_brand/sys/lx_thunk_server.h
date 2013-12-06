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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LX_THUNK_SERVER_H
#define	_LX_THUNK_SERVER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <netdb.h>
#include <procfs.h>

/*
 * Binary that should be exec'd to start up the thunking server
 */
#define	LXT_SERVER_BINARY	"/native/usr/lib/brand/lx/lx_thunk"

/*
 * When the thunking server is started it will need to communicate
 * to the client via two fifos.  These fifos will be passed to the
 * thunking server via the following file descriptors:
 */
#define	LXT_SERVER_FIFO_RD_FD	3
#define	LXT_SERVER_FIFO_WR_FD	4

/*
 * Operations supported by the thunking server
 */
#define	LXT_SERVER_OP_MIN		0
#define	LXT_SERVER_OP_PING		0
#define	LXT_SERVER_OP_NAME2HOST		1
#define	LXT_SERVER_OP_ADDR2HOST		2
#define	LXT_SERVER_OP_NAME2SERV		3
#define	LXT_SERVER_OP_PORT2SERV		4
#define	LXT_SERVER_OP_OPENLOG		5
#define	LXT_SERVER_OP_SYSLOG		6
#define	LXT_SERVER_OP_CLOSELOG		7
#define	LXT_SERVER_OP_MAX		8

/*
 * Macros used to translate pointer into offsets for when they are
 * being transmitted between the client and server processes.
 *
 * NOTE: We're going to add 1 to every offset value.  The reason
 * for this is that some of the pointers we're converting to offsets are
 * stored in NULL terminated arrays, and if one of the members of
 * one of these arrays happened to be at the beginning of the storage
 * buffer it would have an offset of 0 and when the client tries to
 * translate the offsets back into pointers it wouldn't be able
 * to differentiate between the 0 offset from the end of the array.
 */
#define	LXT_PTR_TO_OFFSET(ptr, base) \
		((void *)((uintptr_t)(ptr) - (uintptr_t)(base) + 1))
#define	LXT_OFFSET_TO_PTR(offset, base) \
		((void *)((uintptr_t)(offset) + (uintptr_t)(base) - 1))

/*
 * Structures passed to the thunking server via door calls
 */
typedef struct lxt_server_arg {
	int		lxt_sa_op;
	int		lxt_sa_success;
	int		lxt_sa_errno;
	char		lxt_sa_data[1];
} lxt_server_arg_t;

typedef struct lxt_gethost_arg {
	struct hostent	lxt_gh_result;

	int		lxt_gh_h_errno;

	int		lxt_gh_type;
	int		lxt_gh_token_len;
	int		lxt_gh_buf_len;

	int		lxt_gh_storage_len;
	char		lxt_gh_storage[1];
} lxt_gethost_arg_t;

typedef struct lxt_getserv_arg {
	struct servent	lxt_gs_result;

	int		lxt_gs_token_len;
	int		lxt_gs_buf_len;
	char		lxt_gs_proto[5];

	int		lxt_gs_storage_len;
	char		lxt_gs_storage[1];
} lxt_getserv_arg_t;

typedef struct lxt_openlog_arg {
	int		lxt_ol_logopt;
	int		lxt_ol_facility;
	char		lxt_ol_ident[128];
} lxt_openlog_arg_t;

typedef struct lxt_syslog_arg {
	int		lxt_sl_priority;
	pid_t		lxt_sl_pid;
	char		lxt_sl_progname[PRFNSZ];
	char		lxt_sl_message[1024];
} lxt_syslog_arg_t;


/*
 * Functions called by the brand library to manage startup of the
 * thunk server process.
 */
void lxt_server_init(int, char *[]);
int lxt_server_pid(int *pid);
void lxt_server_exec_check(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _LX_THUNK_SERVER_H */
