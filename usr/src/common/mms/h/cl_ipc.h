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


#ifndef _CL_IPC_H_
#define	_CL_IPC_H_

STATUS
cl_ipc_create(char    *sock_name);


STATUS
cl_ipc_destroy();

int
cl_select_input(int nfds,
	int *fds,
	long tmo);


int
cl_ipc_open(char    *sock_name_in,
	char    *sock_name_out);


STATUS
cl_ipc_read(char    buffer[],
	int	*byte_count);


STATUS
cl_ipc_send(char    *sock_name,
	char	*buffer,
	int	byte_count,
	int	retry_count);


STATUS
cl_ipc_write(char	*sock_name,
	char	*buffer,
	int	byte_count);


STATUS
cl_ipc_xmit(char    *sock_name,
	char	*buffer,
	int	byte_count);
#endif /* _CL_IPC_H_ */
