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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _RP_PLUGIN_H
#define	_RP_PLUGIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	RP_LIB_DIR	"/usr/lib/reparse"
#define	RP_PLUGIN_V1	1

/*
 * some error codes
 */
#define	RP_OK			0
#define	RP_NO_PLUGIN		ENOENT
#define	RP_NO_MEMORY		ENOMEM
#define	RP_NO_PLUGIN_DIR	ENOTDIR
#define	RP_INVALID_PROTOCOL	EINVAL

extern int rp_plugin_init();

typedef struct rp_plugin_ops {
	int rpo_version;
	int (*rpo_init)(void);
	int (*rpo_fini)(void);
	char *(*rpo_svc_types)(void);
	boolean_t (*rpo_supports_svc)(const char *);
	int (*rpo_form)(const char *, const char *, char *, size_t *);
	int (*rpo_deref)(const char *, const char *, char *, size_t *);
} rp_plugin_ops_t;

typedef struct rp_proto_plugin {
	struct rp_proto_plugin *plugin_next;
	rp_plugin_ops_t *plugin_ops;
	void *plugin_handle;
} rp_proto_plugin_t;

typedef struct rp_proto_handle {
	int rp_num_proto;
	rp_plugin_ops_t **rp_ops;
} rp_proto_handle_t;

#ifdef __cplusplus
}
#endif

#endif	/* _RP_PLUGIN_H */
