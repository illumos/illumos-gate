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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_FCDRIVER_FCDRIVER_H
#define	_FCDRIVER_FCDRIVER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/fcode.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct NODEIDs {
	fc_phandle_t		my_handle;
	device_t		*node;
} my_nodeid_t;

typedef struct MY_GLOBAL_DATA {
	int			fcode_fd;
	char			*path;
	char			*Progname;
	struct fc_parameters	fc;
	fc_phandle_t		attach;
	fc_resource_t		*nodeids;
	char			*search_path;
	int			init_done;
	int			first_node;
} common_data_t;

typedef struct MY_PRIVATE_DATA {
	common_data_t		*common;
	fc_phandle_t		node;
	fc_phandle_t		parent;
	struct fc_parameters	fc;
	void			*debug;
	int			upload;
} private_data_t;

#ifdef FCODE_INTERNAL
#include <fcdriver/proto.h>
#endif

void upload_nodes(fcode_env_t *);
void validate_nodes(fcode_env_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _FCDRIVER_FCDRIVER_H */
