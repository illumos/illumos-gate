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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * etm_xport_api.h	FMA ETM-to-Transport API header
 *			for sun4v/Ontario
 *
 * const/type defns for transporting data between an
 * event transport module (ETM) and its associated transport
 * within a fault domain
 */

#ifndef _ETM_XPORT_API_H
#define	_ETM_XPORT_API_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ------------------------------ includes -----------------------------------
 */

#include <sys/fm/protocol.h>
#include <fm/fmd_api.h>

#include <libnvpair.h>

/*
 * -------------------------------- typdefs ----------------------------------
 */

typedef void* etm_xport_addr_t;  /* transport address handle */
typedef void* etm_xport_conn_t;  /* transport connection handle */

typedef enum {

	ETM_XPORT_LCC_TOO_LOW,	/* place holder to ease range checking */
	ETM_XPORT_LCC_CAME_UP,	/* endpoint came up (booted) */
	ETM_XPORT_LCC_WENT_DN,	/* endpoint went down (crashed/shutdown) */
	ETM_XPORT_LCC_TOO_BIG	/* place holder to ease range checking */

} etm_xport_lcc_t;		/* life cycle change of an endpoint */

/*
 * -------------------- connection management functions ----------------------
 */

/*
 * etm_xport_init - initialize/setup any transport infrastructure
 *			before any connections are opened,
 *			return 0 or -errno value if initialization failed
 */

int
etm_xport_init(fmd_hdl_t *hdl);

/*
 * etm_xport_open - open a connection with the given endpoint,
 *			return the connection handle,
 *			or NULL and set errno if open failed
 */

etm_xport_conn_t
etm_xport_open(fmd_hdl_t *hdl, etm_xport_addr_t addr);

/*
 * etm_xport_accept - accept a request to open a connection,
 *			pending until a remote endpoint opens a
 *			a new connection to us [and sends an ETM msg],
 *			per non-NULL addrp optionally indicate the
 *			remote address if known/avail (NULL if not),
 *			return the connection handle,
 *			or NULL and set errno on failure
 *
 * caveats:
 *		any returned transport address is valid only for
 *		as long as the associated connection remains open;
 *		callers should NOT try to free the transport address
 *
 *		if new connections are rapid relative to how
 *		frequently this function is called, fairness will
 *		be provided among which connections are accepted
 *
 *		this function may maintain state to recognize [new]
 *		connections and/or to provide fairness
 */

etm_xport_conn_t
etm_xport_accept(fmd_hdl_t *hdl, etm_xport_addr_t *addrp);

/*
 * etm_xport_close - close a connection from either endpoint,
 *			return the original connection handle,
 *			or NULL and set errno if close failed
 */

etm_xport_conn_t
etm_xport_close(fmd_hdl_t *hdl, etm_xport_conn_t conn);

/*
 * etm_xport_get_ev_addrv - indicate which transport addresses
 *				are implied as destinations by the
 *				given FMA event, if given no FMA event
 *				(NULL) indicate default or policy
 *				driven dst transport addresses,
 *				return an allocated NULL terminated
 *				vector of allocated transport addresses,
 *				or NULL and set errno if none
 * caveats:
 *		callers should never try to individually free an addr
 *		within the returned vector
 */

etm_xport_addr_t *
etm_xport_get_ev_addrv(fmd_hdl_t *hdl, nvlist_t *ev);

/*
 * etm_xport_free_addrv - free the given vector of transport addresses,
 *				including each transport address
 */

void
etm_xport_free_addrv(fmd_hdl_t *hdl, etm_xport_addr_t *addrv);

/*
 * etm_xport_get_addr_conn - indicate which connections in a NULL
 *				terminated vector of connection
 *				handles are associated with the
 *				given transport address,
 *				return an allocated NULL terminated
 *				vector of those connection handles,
 *				or NULL and set errno if none
 */

etm_xport_conn_t *
etm_xport_get_addr_conn(fmd_hdl_t *hdl, etm_xport_conn_t *connv,
			    etm_xport_addr_t addr);

/*
 * etm_xport_get_any_lcc - indicate which endpoint has undergone
 *			a life cycle change and what that change
 *			was (ex: come up), pending until a change
 *			has occured for some/any endpoint,
 *			return the appropriate address handle,
 *			or NULL and set errno if problem
 *
 * caveats:
 *		this function maintains or accesses state/history
 *		regarding life cycle changes of endpoints
 *
 *		if life cycle changes are rapid relative to how
 *		frequently this function is called, fairness will
 *		be provided among which endpoints are reported
 */

etm_xport_addr_t
etm_xport_get_any_lcc(fmd_hdl_t *hdl, etm_xport_lcc_t *lccp);

/*
 * etm_xport_fini - finish/teardown any transport infrastructure
 *			after all connections are closed,
 *			return 0 or -errno value if teardown failed
 */

int
etm_xport_fini(fmd_hdl_t *hdl);

/*
 * ------------------------ input/output functions ---------------------------
 */

/*
 * etm_xport_read - try to read N bytes from the connection
 *			into the given buffer,
 *			return how many bytes actually read
 *			or -errno value
 */

ssize_t
etm_xport_read(fmd_hdl_t *hdl, etm_xport_conn_t conn, void* buf,
							size_t byte_cnt);

/*
 * etm_xport_write - try to write N bytes to the connection
 *			from the given buffer,
 *			return how many bytes actually written
 *			or -errno value
 */

ssize_t
etm_xport_write(fmd_hdl_t *hdl, etm_xport_conn_t conn, void* buf,
							size_t byte_cnt);

/*
 * ------------------------ miscellaneous functions --------------------------
 */

typedef enum {

	ETM_XPORT_OPT_TOO_LOW = 0,	/* range check place holder */
	ETM_XPORT_OPT_MTU_SZ,		/* read/write MTU in bytes */
	ETM_XPORT_OPT_LINGER_TO,	/* close linger timeout in sec */
	ETM_XPORT_OPT_TOO_BIG		/* range check place holder */

} etm_xport_opt_t;		/* transport options w/ non-neg values */

/*
 * etm_xport_get_opt - get a connection's transport option value,
 *			return the current value
 *			or -errno value (ex: -ENOTSUP)
 */

ssize_t
etm_xport_get_opt(fmd_hdl_t *hdl, etm_xport_conn_t conn, etm_xport_opt_t opt);


/*
 * -------------------------- device driver defns ----------------------------
 *
 * Design_Note:	These device driver interface defns should be based upon a
 *		public sys include file provided by the transport device
 *		driver; the header uts/sun4v/sys/glvc.h was not accessible
 *		from the build's default include paths. Until that issue
 *		is resolved they need to be manually synced based upon the
 *		Ontario FMA Phase 1 ETM-to-Transport API Interface Spec.
 */

/* ioctls for peeking data and getting/setting options */

#define	ETM_XPORT_IOCTL_DATA_PEEK	(1)
#define	ETM_XPORT_IOCTL_OPT_OP		(2)

typedef struct etm_xport_msg_peek {
	void*		pk_buf;		/* ptr to buffer to hold peeked data */
	size_t		pk_buflen;	/* number of bytes of peeked data */
	uint16_t	pk_flags;	/* future control flags -- set to 0 */
	uint16_t	pk_rsvd;	/* reserved/padding -- set to 0 */
} etm_xport_msg_peek_t;

#define	ETM_XPORT_OPT_GET	(1)
#define	ETM_XPORT_OPT_SET	(2)

/* options for MTU size in bytes and linger timeout in sec */

#define	ETM_XPORT_OPT_MTU_SZ	(1)
#define	ETM_XPORT_OPT_LINGER_TO	(2)

typedef struct etm_xport_opt_op {
	int	oo_op;	/* which operation (ex: GET) */
	int	oo_opt;	/* which option (ex: MTU_SZ) */
	size_t	oo_val;	/* option value to use (ex: 512) */
} etm_xport_opt_op_t;

/* default values for options [if unable to get/set] */

/*
 * Design_Note:	These might need to be made into properties in prep
 *		for internet domain sockets as a future transport.
 */

#define	ETM_XPORT_MTU_SZ_DEF	(64)
#define	ETM_XPORT_LINGER_TO_DEF	(0)

/*
 * --------------------------------- prolog ----------------------------------
 */

#ifdef __cplusplus
}
#endif

#endif /* _ETM_XPORT_API_H */
