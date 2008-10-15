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

#ifndef	_LDOM_H
#define	_LDOM_H

#include <stdlib.h>
#include <libnvpair.h>
#include <sys/types.h>
#include <umem.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct ldom_hdl ldom_hdl_t;

extern ldom_hdl_t *ldom_init(void *(*allocp)(size_t size),
			    void (*freep)(void *addr, size_t size));
extern void ldom_fini(ldom_hdl_t *lhp);

extern int ldom_fmri_status(ldom_hdl_t *lhp, nvlist_t *nvl_fmri);
extern int ldom_fmri_retire(ldom_hdl_t *lhp, nvlist_t *nvl_fmri);
extern int ldom_fmri_unretire(ldom_hdl_t *lhp, nvlist_t *nvl_fmri);
extern int ldom_fmri_blacklist(ldom_hdl_t *lhp, nvlist_t *nvl_fmri);
extern int ldom_fmri_unblacklist(ldom_hdl_t *lhp, nvlist_t *nvl_fmri);

extern ssize_t ldom_get_core_md(ldom_hdl_t *lhp, uint64_t **buf);
extern ssize_t ldom_get_local_md(ldom_hdl_t *lhp, uint64_t **buf);

/*
 * domain type
 */
#define	LDOM_TYPE_LEGACY	0x1
#define	LDOM_TYPE_CONTROL	0x2
#define	LDOM_TYPE_ROOT		0x4
#define	LDOM_TYPE_IO		0x8
#define	LDOM_TYPE_ALL \
	(LDOM_TYPE_LEGACY | LDOM_TYPE_CONTROL | LDOM_TYPE_ROOT | LDOM_TYPE_IO)
#define	VALID_LDOM_TYPE(t)	((t) & LDOM_TYPE_ALL)

extern int ldom_get_type(ldom_hdl_t *lhp, uint32_t *type_mask);

/*
 * Resource map
 */
typedef enum ldom_rsrc {
	LDOM_RSRC_PCI,
	LDOM_RSRC_NIU,
	LDOM_RSRC_MAX
} ldom_rsrc_t;

extern int
ldom_find_id(ldom_hdl_t *lhp, uint64_t addr, ldom_rsrc_t type,
    uint64_t *virt_addr, char *name, int name_size, uint64_t *id);

/*
 * event notification
 */
typedef enum ldom_event {
	LDOM_EVENT_UNKNOWN,
	LDOM_EVENT_ADD,
	LDOM_EVENT_REMOVE,
	LDOM_EVENT_BIND,
	LDOM_EVENT_UNBIND,
	LDOM_EVENT_START,
	LDOM_EVENT_STOP,
	LDOM_EVENT_RESET,
	LDOM_EVENT_PANIC,
	LDOM_EVENT_MAX
} ldom_event_t;
#define	VALID_LDOM_EVENT(e)	((e) > LDOM_EVENT_UNKNOWN && \
				(e) < LDOM_EVENT_MAX)
#define	MAX_LDOM_NAME		256

typedef void *ldom_cb_arg_t;
typedef void (*ldom_reg_cb_t)(char *ldom_name, ldom_event_t event,
				ldom_cb_arg_t data);
extern int ldom_register_event(ldom_hdl_t *lhp, ldom_reg_cb_t cb,
				ldom_cb_arg_t data);
extern int ldom_unregister_event(ldom_hdl_t *lhp);

#ifdef	__cplusplus
}
#endif

#endif	/* _LDOM_H */
