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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMB_WINPIPE_H_
#define	_SMB_WINPIPE_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _KERNEL
#include <stddef.h>
#endif /* _KERNEL */

#include <sys/thread.h>
#include <sys/door.h>
#include <sys/disp.h>
#include <sys/systm.h>
#include <sys/processor.h>
#include <sys/socket.h>
#include <inet/common.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	SMB_IO_MAX_SIZE 32
#define	SMB_MAX_PIPENAMELEN 32

#define	SMB_WINPIPE_DOOR_DOWN_PATH "/var/run/winpipe_doordown"
#define	SMB_WINPIPE_DOOR_UP_PATH "/var/run/winpipe_doorup"

#define	SMB_DOWNCALLINFO_MAGIC	0x19121969
#define	SMB_MLSVC_DOOR_VERSION 1

#define	SMB_RPC_FLUSH_MAGIC 0x123456CC
#define	SMB_RPC_TRANSACT 1
#define	SMB_RPC_READ	 2
#define	SMB_RPC_WRITE	 3
#define	SMB_RPC_FLUSH	 4

typedef struct {
	uint64_t md_tid;	/* caller's thread id */
	uint16_t md_version;	/* version number, start with 1 */
	uint16_t md_call_type;	/* transact, read, write, flush */
	uint32_t md_length;	/* max bytes to return */
	uint64_t md_reserved;
} mlsvc_door_hdr_t;

typedef struct {
	uint32_t sp_pipeid;
	char	 sp_pipename[SMB_MAX_PIPENAMELEN];
	int32_t  sp_datalen;
	char	 sp_data[1]; /* any size buffer */
} smb_pipe_t;

void smb_downcall_service(void *, door_arg_t *, void (**)(void *, void *),
    void **, int *);

#ifdef __cplusplus
}
#endif

#endif /* _SMB_WINPIPE_H_ */
