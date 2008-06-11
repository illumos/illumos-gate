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

#ifndef	_LIBSES_H
#define	_LIBSES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

#include <stdarg.h>
#include <libnvpair.h>
#include <pthread.h>

#include <scsi/libscsi.h>
#include <scsi/plugins/ses/framework/ses2.h>
#include <scsi/plugins/ses/framework/libses.h>

#define	LIBSES_VERSION	1

typedef enum ses_node_type {
	SES_NODE_NONE = 0x0,
	SES_NODE_TARGET = 0x1,
	SES_NODE_ENCLOSURE = 0x2,
	SES_NODE_AGGREGATE = 0x4,
	SES_NODE_ELEMENT = 0x8
} ses_node_type_t;

typedef enum ses_errno {
	ESES_NONE,		/* no error */
	ESES_NOMEM,		/* no memory */
	ESES_ZERO_LENGTH,	/* zero-length allocation requested */
	ESES_VERSION,		/* library version mismatch */
	ESES_NVL,		/* nvlist manipulation error */
	ESES_BAD_NODE,		/* bad node */
	ESES_INVALID_OP,	/* invalid operation */
	ESES_RANGE,		/* value out of range */
	ESES_INVALID_PROP,	/* nonexistent or immutable property */
	ESES_BAD_TYPE,		/* incorrect property type */
	ESES_BAD_PAGE,		/* bad page number */
	ESES_BAD_RESPONSE,	/* bad response from target */
	ESES_BUSY,		/* target busy */
	ESES_TOOMUCHCHANGE,	/* target configuration changing too rapidly */
	ESES_LIBSCSI,		/* SCSI error */
	ESES_NOTSUP,		/* operation not supported */
	ESES_UNKNOWN,		/* error of unknown type */
	ESES_CHANGED,		/* generation count has changed */
	ESES_PLUGIN,		/* invalid or missing plugin */
	ESES_MAX		/* maximum libses errno value */
} ses_errno_t;

struct ses_target;
typedef struct ses_target ses_target_t;

struct ses_snap;
typedef struct ses_snap ses_snap_t;

struct ses_node;
typedef struct ses_node ses_node_t;

extern ses_target_t *ses_open(uint_t, const char *);
extern ses_target_t *ses_open_scsi(uint_t, libscsi_target_t *);
extern void ses_close(ses_target_t *);

extern libscsi_target_t *ses_scsi_target(ses_target_t *);

typedef enum ses_walk_action {
	SES_WALK_ACTION_CONTINUE,
	SES_WALK_ACTION_PRUNE,
	SES_WALK_ACTION_TERMINATE
} ses_walk_action_t;

typedef ses_walk_action_t (*ses_walk_f)(ses_node_t *, void *);

extern uint64_t ses_node_id(ses_node_t *);
extern ses_node_t *ses_node_lookup(ses_snap_t *, uint64_t);

extern ses_node_t *ses_root_node(ses_snap_t *);
extern ses_node_t *ses_node_sibling(ses_node_t *);
extern ses_node_t *ses_node_prev_sibling(ses_node_t *);
extern ses_node_t *ses_node_child(ses_node_t *);
extern ses_node_t *ses_node_parent(ses_node_t *);
extern int ses_walk(ses_snap_t *, ses_walk_f, void *);

extern ses_snap_t *ses_snap_hold(ses_target_t *);
extern void ses_snap_rele(ses_snap_t *);
extern ses_snap_t *ses_snap_new(ses_target_t *);
extern uint32_t ses_snap_generation(ses_snap_t *);

extern ses_node_type_t ses_node_type(ses_node_t *);
extern nvlist_t *ses_node_props(ses_node_t *);
extern int ses_node_ctl(ses_node_t *, const char *, nvlist_t *);
extern ses_snap_t *ses_node_snapshot(ses_node_t *);
extern ses_target_t *ses_node_target(ses_node_t *);

extern ses_errno_t ses_errno(void);
extern const char *ses_errmsg(void);
extern const char *ses_strerror(ses_errno_t);
extern const char *ses_nv_error_member(void);

extern ses_node_t *ses_snap_primary_enclosure(ses_snap_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSES_H */
