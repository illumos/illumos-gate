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

#ifndef _FRURAW_H
#define	_FRURAW_H

#include <stdint.h>
#include <fru_access.h>
#include <libfruds.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	FRU_CONT_CONF_SPARC	"/usr/platform/sun4u/lib/fru_container.conf"
#define	FRU_CONT_CONF_X86	"/usr/lib/picl/plugins/fru_container.conf"
#define	FRU_CONT_CONF_ENV_VAR   "FRU_CONTAINER_CONF"
#define	IGNORE_CHECK		"IGNORE_CHECKSUM"

typedef struct segment_list {
	segment_t *segment;
	struct segment_list *next;
} segment_list_t;


typedef struct raw_list {
	uint8_t *raw;
	size_t size;
	char *cont_type;

	container_hdl_t cont;
	segment_list_t *segs;

	fru_treehdl_t hdl;
} raw_list_t;


/* raw_access.c */
container_hdl_t open_raw_data(raw_list_t *);
int fru_close_container(container_hdl_t);
raw_list_t *seghdl_to_rawlist(segment_hdl_t node);

#ifdef __cplusplus
}
#endif

#endif /* _FRURAW_H */
