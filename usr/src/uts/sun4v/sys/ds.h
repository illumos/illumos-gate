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

#ifndef _DS_H
#define	_DS_H


/*
 * Domain Services Client Interface
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t	ds_svc_hdl_t;	/* opaque service handle */
typedef void		*ds_cb_arg_t;	/* client specified callback arg */

#define	DS_INVALID_HDL	(0)		/* a ds handle cannot be zero */

/*
 * Domain Services Versioning
 */
typedef struct ds_ver {
	uint16_t	major;
	uint16_t	minor;
} ds_ver_t;

/*
 * Domain Services Capability
 *
 * A DS capability is exported by a client using a unique service
 * identifier string. Along with this identifier is the list of
 * versions of the capability that the client supports.
 */
typedef struct ds_capability {
	char		*svc_id;	/* service identifier */
	ds_ver_t	*vers;		/* list of supported versions */
	int		nvers;		/* number of supported versions */
} ds_capability_t;

/*
 * Domain Services Client Event Callbacks
 *
 * A client implementing a DS capability provides a set of callbacks
 * when it registers with the DS framework. The use of these callbacks
 * is described below:
 *
 *    ds_reg_cb(ds_cb_arg_t arg, ds_ver_t *ver, ds_svc_hdl_t hdl)
 *
 *	    The ds_reg_cb() callback is invoked when the DS framework
 *	    has successfully completed version negotiation with the
 *	    remote endpoint for the capability. It provides the client
 *	    with the negotiated version and a handle to use when sending
 *	    data.
 *
 *    ds_unreg_cb(ds_cb_arg_t arg)
 *
 *	    The ds_unreg_cb() callback is invoked when the DS framework
 *	    detects an event that causes the registered capability to
 *	    become unavailable. This includes an explicit unregister
 *	    message, a failure in the underlying communication transport,
 *	    etc. Any such event invalidates the service handle that was
 *	    received from the register callback.
 *
 *    ds_data_cb(ds_cb_arg_t arg, void *buf, size_t buflen)
 *
 *	    The ds_data_cb() callback is invoked whenever there is an
 *	    incoming data message for the client to process. It provides
 *	    the contents of the message along with the message length.
 */
typedef struct ds_clnt_ops {
	void (*ds_reg_cb)(ds_cb_arg_t arg, ds_ver_t *ver, ds_svc_hdl_t hdl);
	void (*ds_unreg_cb)(ds_cb_arg_t arg);
	void (*ds_data_cb)(ds_cb_arg_t arg, void *buf, size_t buflen);
	ds_cb_arg_t cb_arg;
} ds_clnt_ops_t;

/*
 * Domain Services Capability Interface
 */
extern int ds_cap_init(ds_capability_t *cap, ds_clnt_ops_t *ops);
extern int ds_cap_fini(ds_capability_t *cap);
extern int ds_cap_send(ds_svc_hdl_t hdl, void *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* _DS_H */
