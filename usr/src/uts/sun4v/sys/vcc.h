
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

#ifndef _VCC_H
#define	_VCC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/stream.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ioctl.h>

/*
 * vcc and vntsd exchange information using ioctl commands. When vntsd starts,
 * it uses VCC_NUM_CONSOLE to get number of existing ports and
 * VCC_CONS_TBL to obtain the table of existing consoles. In this table,
 * vcc returns information about each of the console ports using vcc_console_t
 * structure. Vntsd then sleeps on polling vcc control port.
 *
 * When there is a change in configuration, such as addtion or deletion
 * of a console port, vcc wakes up vntsd via the poll events. Subsequently,
 * vntsd uses VCC_INQUIRY ioctl to determine the reason for wakeup. In
 * response to the inquiry, vcc provides a vcc_response_t structure
 * containing reason and port number.
 *
 * If a port is being added or updated (group change), vntsd uses
 * VCC_CONS_INFO ioctl with port number to obtain configuration of
 * the port.
 *
 * If the port is being deleted, vntsd uses VCC_DEL_CONS_OK ioctl to notify
 * vcc after its clean up is done. Vcc subsequently tears down
 * its internal configuration and remove the associated TTY minor node.
 *
 * Only one open is allowd for each vcc port. If vntsd opens a port that is
 * already open, vntsd will use VNTSD_FORCE_CLOSE to take port from other
 * application
 */

/* VCC CNTRL IOCTL */

#define	    VCC_IOCTL_CMD		('c' << 8)


#define	    VCC_NUM_CONSOLE	VCC_IOCTL_CMD | 0x1	/* num of consoles */
#define	    VCC_CONS_TBL	VCC_IOCTL_CMD | 0x2	/* config table */
#define	    VCC_INQUIRY		VCC_IOCTL_CMD | 0x3	/* inquiry by vntsd */
#define	    VCC_CONS_INFO	VCC_IOCTL_CMD | 0x4	/* config */
#define	    VCC_CONS_STATUS	VCC_IOCTL_CMD | 0x5	/* console status */
#define	    VCC_FORCE_CLOSE	VCC_IOCTL_CMD | 0x6	/* force to close */

/* reasons to wake up vntsd */
typedef enum {
	VCC_CONS_ADDED,		    /* a port was added */
	VCC_CONS_DELETED,	    /* a port was removed */
	VCC_CONS_MISS_ADDED,	    /* wakeup after an added port was deleted */
	/* XXX not implemented yet */
	VCC_CONS_UPDATED	    /* a port configuration was changed */
} vcc_reason_t;

/*
 * structure that vcc returns to vntsd in response to VCC_CONS_TBL and
 * VCC_CONS_INFO  ioctl call.
 */
typedef struct vcc_console {
	int		cons_no;		    /* console port number  */
	uint64_t	tcp_port;		    /* tcp port for the group */
	char		domain_name[MAXPATHLEN];    /* domain name */
	char		group_name[MAXPATHLEN];	    /* group name */
	char		dev_name[MAXPATHLEN];
} vcc_console_t;

/* structure that vcc sends to vntsd in response to wake up inquiry */
typedef struct vcc_response {
	int		cons_no;	/* console port number */
	vcc_reason_t	reason;		/* wake up reason */
} vcc_response_t;

#ifdef __cplusplus
}
#endif

#endif /* _VCC_H */
