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
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_SUNLDI_H
#define	_SYS_SUNLDI_H

#include <sys/modctl.h>
#include <sys/stream.h>
#include <sys/open.h>

/*
 * DDI interfaces for Layered driver support.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL


/*
 * Opaque layered driver data structures.
 *
 * The contents of these data structures are private to this
 * implementation of Solaris and are subject to change at any
 * time without notice.
 *
 * Applications and drivers accessing the contents of these structures
 * directly will fail to run on future releases.
 */
typedef struct __ldi_ident		*ldi_ident_t;

typedef struct __ldi_handle		*ldi_handle_t;

typedef struct __ldi_callback_id	*ldi_callback_id_t;

typedef struct __ldi_ev_cookie		*ldi_ev_cookie_t;

/*
 * LDI event interface related
 */
#define	LDI_EV_SUCCESS	0
#define	LDI_EV_FAILURE	(-1)
#define	LDI_EV_NONE	(-2)	/* no matching callbacks registered */
#define	LDI_EV_OFFLINE	"LDI:EVENT:OFFLINE"
#define	LDI_EV_DEGRADE	"LDI:EVENT:DEGRADE"
#define	LDI_EV_DEVICE_REMOVE	"LDI:EVENT:DEVICE_REMOVE"

#define	LDI_EV_CB_VERS_1	1
#define	LDI_EV_CB_VERS		LDI_EV_CB_VERS_1

typedef struct ldi_ev_callback {
	uint_t cb_vers;
	int (*cb_notify)(ldi_handle_t, ldi_ev_cookie_t, void *, void *);
	void (*cb_finalize)(ldi_handle_t, ldi_ev_cookie_t, int, void *, void *);
} ldi_ev_callback_t;

/*
 * LDI Ident manipulation functions
 */
extern ldi_ident_t ldi_ident_from_anon(void);

extern int ldi_ident_from_mod(struct modlinkage *, ldi_ident_t *);
extern int ldi_ident_from_major(major_t major, ldi_ident_t *);
extern int ldi_ident_from_dip(dev_info_t *dip, ldi_ident_t *);
extern int ldi_ident_from_dev(dev_t, ldi_ident_t *);
extern int ldi_ident_from_stream(struct queue *, ldi_ident_t *);
extern void ldi_ident_release(ldi_ident_t);


/*
 * LDI Handle manipulation functions
 */
extern int ldi_open_by_dev(dev_t *, int, int, cred_t *,
    ldi_handle_t *, ldi_ident_t);
extern int ldi_open_by_name(char *, int, cred_t *,
    ldi_handle_t *, ldi_ident_t);
extern int ldi_open_by_devid(ddi_devid_t, char *, int, cred_t *,
    ldi_handle_t *, ldi_ident_t);
extern int ldi_vp_from_name(char *, vnode_t **);
extern int ldi_vp_from_devid(ddi_devid_t, char *, vnode_t **);

extern int ldi_close(ldi_handle_t, int flag, cred_t *);

extern int ldi_read(ldi_handle_t, struct uio *, cred_t *);
extern int ldi_write(ldi_handle_t, struct uio *, cred_t *);
extern int ldi_ioctl(ldi_handle_t, int, intptr_t, int, cred_t *, int *);
extern int ldi_poll(ldi_handle_t, short, int, short *, struct pollhead **);
extern int ldi_get_size(ldi_handle_t, uint64_t *);
extern int ldi_prop_op(ldi_handle_t, ddi_prop_op_t, int,
    char *, caddr_t, int *);

extern int ldi_strategy(ldi_handle_t, struct buf *);
extern int ldi_dump(ldi_handle_t, caddr_t, daddr_t, int);
extern int ldi_devmap(ldi_handle_t, devmap_cookie_t, offset_t,
    size_t, size_t *, uint_t);
extern int ldi_aread(ldi_handle_t, struct aio_req *, cred_t *);
extern int ldi_awrite(ldi_handle_t, struct aio_req *, cred_t *);

extern int ldi_putmsg(ldi_handle_t, mblk_t *);
extern int ldi_getmsg(ldi_handle_t, mblk_t **, timestruc_t *);

extern int ldi_prop_lookup_int_array(ldi_handle_t lh,
    uint_t flags, char *name, int **data, uint_t *nelements);
extern int ldi_prop_lookup_int64_array(ldi_handle_t lh,
    uint_t flags, char *name, int64_t **data, uint_t *nelements);
extern int ldi_prop_lookup_string_array(ldi_handle_t lh,
    uint_t flags, char *name, char ***data, uint_t *nelements);
extern int ldi_prop_lookup_string(ldi_handle_t lh,
    uint_t flags, char *name, char **data);
extern int ldi_prop_lookup_byte_array(ldi_handle_t lh,
    uint_t flags, char *name, uchar_t **data, uint_t *nelements);
extern int ldi_prop_get_int(ldi_handle_t lh,
    uint_t flags, char *name, int defvalue);
extern int64_t ldi_prop_get_int64(ldi_handle_t lh,
    uint_t flags, char *name, int64_t defvalue);
extern int ldi_prop_exists(ldi_handle_t lh,
    uint_t flags, char *name);

extern int ldi_get_dev(ldi_handle_t, dev_t *);
extern int ldi_get_otyp(ldi_handle_t, int *);
extern int ldi_get_devid(ldi_handle_t, ddi_devid_t *);
extern int ldi_get_minor_name(ldi_handle_t, char **);

/*
 * LDI events related declarations
 */
extern int ldi_ev_get_cookie(ldi_handle_t lh, char *evname,
    ldi_ev_cookie_t *cookiep);
extern char *ldi_ev_get_type(ldi_ev_cookie_t cookie);
extern int ldi_ev_register_callbacks(ldi_handle_t lh,
    ldi_ev_cookie_t cookie, ldi_ev_callback_t *callb,
    void *arg, ldi_callback_id_t *id);
extern int ldi_ev_notify(dev_info_t *dip, minor_t minor, int spec_type,
    ldi_ev_cookie_t cookie, void *ev_data);
extern void ldi_ev_finalize(dev_info_t *dip, minor_t minor, int spec_type,
    int ldi_result, ldi_ev_cookie_t cookie, void *ev_data);
extern int ldi_ev_remove_callbacks(ldi_callback_id_t id);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SUNLDI_H */
