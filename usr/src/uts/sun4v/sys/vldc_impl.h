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

#ifndef _VLDC_IMPL_H
#define	_VLDC_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/stream.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ldc.h>
#include <sys/vldc.h>

/* default values */
#define	VLDC_DEFAULT_MTU	0x1000	/* default mtu size 4K */

/* VLDC limits */
#define	VLDC_MAX_COOKIE		0x40000	/* max. size of xfer to/from HV */
#define	VLDC_MAX_MTU		0x40000	/* 256K */
#define	VLDC_MAX_PORTS		0x800
#define	VLDC_MAX_MINORS		VLDC_MAX_PORTS

#define	VLDC_MINOR_MASK		(VLDC_MAX_PORTS - 1)
#define	VLDC_INST_SHIFT		11

#define	VLDC_HVCTL_SVCNAME	"hvctl"

/* get port number from minor number */
#define	VLDCPORT(vldcp, minor)	\
		((vldcp)->minor_tbl[(minor) & VLDC_MINOR_MASK].portno)

/* get minor table entry from minor number */
#define	VLDCMINOR(vldcp, minor)	\
		(&((vldcp)->minor_tbl[(minor) & VLDC_MINOR_MASK]))

/* get instance number from minor number */
#define	VLDCINST(minor)		((minor) >> VLDC_INST_SHIFT)

/* indicates an invalid port number */
#define	VLDC_INVALID_PORTNO	((uint_t)-1)

/* delay(in us) used to wait for pending callback to complete */
#define	VLDC_CLOSE_DELAY	MICROSEC	/* 1sec */

/*
 * Minor node number to port number mapping table.
 *
 * The lock field in the vldc_minor structure is used to serialize operations
 * on the port associated with the minor node. It also protects the minor node
 * in_use field which is used to track the number of active users of the minor
 * node.  Driver ops will either hold the lock over the whole operation or
 * will increment (and then decrement) the in use count if they need to
 * release and re-acquire the lock, e.g. when copying data in from or out to
 * userland. When the MDEG framework calls into the driver via the callback to
 * remove a port, the driver must wait until the in use count for the minor
 * node associated with the port drops to zero, before it can remove the
 * port.
 */
typedef struct vldc_minor {
	kmutex_t 	lock;			/* protects port/in_use count */
	kcondvar_t	cv;			/* for waiting on in use */
	uint_t		in_use;			/* in use counter */
	uint_t		portno;			/* port number */
	char		sname[MAXPATHLEN];	/* service name */
} vldc_minor_t;

typedef struct vldc_port {
	uint_t		number;			/* port number */
	uint32_t	status;			/* port status */
	uint_t		inst;			/* vldc instance */
	vldc_minor_t	*minorp;		/* minor table entry pointer */
	uint32_t	mtu;			/* port mtu */
	caddr_t		send_buf;		/* send buffer */
	caddr_t		recv_buf;		/* receive buffer */
	caddr_t		cookie_buf;		/* rd/wr cookie buffer */

	uint64_t	ldc_id;			/* Channel number */
	ldc_handle_t	ldc_handle;		/* Channel handle */
	ldc_mode_t	ldc_mode;		/* Channel mode */
	ldc_status_t	ldc_status;		/* Channel status */

	boolean_t	is_stream;		/* streaming mode */
	boolean_t	hanged_up;		/* port hanged up */

	struct pollhead	poll;			/* for poll */
} vldc_port_t;

/*
 * vldc driver's soft state structure
 */
typedef struct vldc {
	kmutex_t 		lock;		/* serializes detach and MDEG */
	boolean_t		detaching; 	/* true iff busy detaching */
	dev_info_t		*dip;		/* dev_info */
	mdeg_node_spec_t	*inst_spec;	/* vldc instance specifier */
	mdeg_handle_t		mdeg_hdl;	/* MD event handle */

	uint_t 			num_ports;
	vldc_port_t		port[VLDC_MAX_PORTS];

	/* table for assigned minors */
	vldc_minor_t		minor_tbl[VLDC_MAX_MINORS];

	/* number of minors already assigned */
	uint_t			minors_assigned;
} vldc_t;

#ifdef __cplusplus
}
#endif

#endif /* _VLDC_IMPL_H */
