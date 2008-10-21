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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_DRCTL_H
#define	_SYS_DRCTL_H

#ifdef	__cplusplus
extern "C" {
#endif


#define	DRCTL_DEV "/devices/pseudo/drctl@0:drctl"

typedef enum {
	DRCTL_CPU_CONFIG_REQUEST = 1,
	DRCTL_CPU_CONFIG_NOTIFY,
	DRCTL_CPU_UNCONFIG_REQUEST,
	DRCTL_CPU_UNCONFIG_NOTIFY,
	DRCTL_MEM_CONFIG_REQUEST,
	DRCTL_MEM_CONFIG_NOTIFY,
	DRCTL_MEM_UNCONFIG_REQUEST,
	DRCTL_MEM_UNCONFIG_NOTIFY,
	DRCTL_IO_CONFIG_REQUEST,
	DRCTL_IO_CONFIG_NOTIFY,
	DRCTL_IO_UNCONFIG_REQUEST,
	DRCTL_IO_UNCONFIG_NOTIFY
} drctl_cmds_t;

/*
 * Responses to/from the daemon for a reconfig request.
 */
typedef enum {
	DRCTL_STATUS_INIT,		/* to daemon */
	DRCTL_STATUS_ALLOW,		/* from daemon */
	DRCTL_STATUS_DENY,		/* from daemon */
	DRCTL_STATUS_CONFIG_SUCCESS,	/* to daemon */
	DRCTL_STATUS_CONFIG_FAILURE	/* to daemon */
} drctl_status_t;

/*
 * Each resource descriptor consists of a common header
 * followed by a resource-specific structure.
 */

typedef struct drctl_rsrc_cpu {
	int		id;
} drctl_rsrc_cpu_t;

typedef struct drctl_rsrc_memory {
	uint64_t	size;
	uint64_t	addr;
} drctl_rsrc_mem_t;

typedef struct drctl_rsrc_dev {
	char		path[1];
} drctl_rsrc_dev_t;

typedef struct drctl_rsrc {
	drctl_status_t	status;
	uint64_t	offset;
	union {
		drctl_rsrc_cpu_t cpu;
		drctl_rsrc_mem_t mem;
		drctl_rsrc_dev_t dev;
	} un;
} drctl_rsrc_t;

#define	res_cpu_id	un.cpu.id
#define	res_mem_size	un.mem.size
#define	res_mem_addr	un.mem.addr
#define	res_dev_path	un.dev.path

/*
 * Response structure passed back by drctl to its clients
 * (resource-specific DR modules).
 */
typedef enum {
	DRCTL_RESP_ERR,
	DRCTL_RESP_OK
} drctl_resp_type_t;

typedef struct drctl_resp {
	drctl_resp_type_t resp_type;
	union {
		char err_msg[1];
		drctl_rsrc_t  resources[1];
	} un;
} drctl_resp_t;

#define	resp_err_msg		un.err_msg
#define	resp_resources		un.resources

/*
 * Message sent to DR daemon
 */
typedef struct drd_msg {
	uint_t		cmd;
	uint_t		count;
	int		flags;
	drctl_rsrc_t	data[1];
} drd_msg_t;

typedef void *drctl_cookie_t;

/*
 * DR RSMs (resource-specific modules) call these functions to
 * initialize or finalize a DR request.  A request may include
 * multiple resources of the same type.  The _init call returns
 * a cookie which must be supplied on by the corresponding
 * _fini call.
 */
extern int drctl_config_init(int, int,
    drctl_rsrc_t *, int, drctl_resp_t **, size_t *, drctl_cookie_t);
extern int drctl_config_fini(drctl_cookie_t, drctl_rsrc_t *, int);

/*
 * Values for the 2nd arg (flags) of drctl_config_init
 */
#define	DRCTL_FLAG_FORCE 1


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DRCTL_H */
