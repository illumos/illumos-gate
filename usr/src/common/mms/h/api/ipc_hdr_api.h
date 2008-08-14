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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _IPC_HDR_API_
#define	_IPC_HDR_API_

#define	HOSTID_SIZE		12
typedef struct {
	char name[HOSTID_SIZE];
} HOSTID;

typedef struct {
	unsigned long		byte_count;
	TYPE		module_type;
	unsigned char		options;
	unsigned long		seq_num;
	char		return_socket[SOCKET_NAME_SIZE];

	unsigned int		return_pid;
	unsigned long		ipc_identifier;
	TYPE		requestor_type;
	HOSTID		host_id;
} IPC_HEADER;

#endif /* _IPC_HDR_API_ */
