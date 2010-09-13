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

#ifndef	_LIBDS_H
#define	_LIBDS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * LDOMs User Domain Services library Interfaces
 */

typedef uint64_t	ds_hdl_t;		/* service handle */
typedef uint64_t	ds_domain_hdl_t;	/* domain handle */
typedef void		*ds_cb_arg_t;		/* client callback arg */

#define	DS_INVALID_HDL	(0)		/* a ds handle cannot be zero */

/*
 * LDOMs User Domain Services versioning
 */
typedef struct ds_ver {
	uint16_t	major;
	uint16_t	minor;
} ds_ver_t;

/*
 * LDOMs User Domain Services capability
 */
typedef struct ds_capability {
	char		*svc_id;	/* service identifier */
	ds_ver_t	*vers;		/* list of supported versions */
	uint_t		nvers;		/* number of supported versions */
} ds_capability_t;

/*
 * LDOMs User Domain Services event callbacks
 */
typedef struct ds_ops {
	void (*ds_reg_cb)(ds_hdl_t hdl, ds_cb_arg_t arg, ds_ver_t *ver,
	    ds_domain_hdl_t dhdl);
	void (*ds_unreg_cb)(ds_hdl_t hdl, ds_cb_arg_t arg);
	void (*ds_data_cb)(ds_hdl_t hdl, ds_cb_arg_t arg, void *buf,
	    size_t buflen);
	ds_cb_arg_t cb_arg;
} ds_ops_t;

extern int ds_init(void);
extern int ds_svc_reg(ds_capability_t *cap, ds_ops_t *ops);
extern int ds_clnt_reg(ds_capability_t *cap, ds_ops_t *ops);
extern int ds_hdl_lookup(char *service, boolean_t is_client, ds_hdl_t *hdlsp,
    uint_t maxhdls, uint_t *nhdlsp);
extern int ds_domain_lookup(ds_hdl_t hdl, ds_domain_hdl_t *dhdlp);
extern int ds_unreg_hdl(ds_hdl_t hdl);
extern int ds_send_msg(ds_hdl_t hdl, void *buf, size_t buflen);
extern int ds_recv_msg(ds_hdl_t hdl, void *buf, size_t buflen,
    size_t *msglen);
extern int ds_isready(ds_hdl_t hdl, boolean_t *is_ready);
extern int ds_dom_name_to_hdl(char *domain_name, ds_domain_hdl_t *dhdlp);
extern int ds_dom_hdl_to_name(ds_domain_hdl_t dhdl, char *domain_name,
    uint_t maxnamlen);
extern void ds_unreg_svc(char *service, boolean_t is_client);
extern void ds_fini(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDS_H */
