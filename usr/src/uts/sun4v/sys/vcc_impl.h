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

#ifndef _VCC_IMPL_H
#define	_VCC_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ioctl.h>
#include <sys/vcc.h>

#define	    VCC_DEV_TO_INST(dev)		(getminor(dev))
#define	    VCC_INST_TO_DEV(instance)		(instance)

#define	    VCC_DRIVER_NAME			"vcc"
#define	    VCC_NAME				VCC_DRIVER_NAME

/*
 * VCC Port States
 */

/*
 * There is one lock in port structure to protect the states of the port.
 * States of the port are:
 * 1. VCC_PORT_AVAIL
 * 2. VCC_PORT_OPEN
 * 3. VCC_PORT_USE_READ_LDC  - There is a thread doing vcc_read.
 * 4. VCC_PORT_USE_WRITE_LDC - There is a thread doing vcc_write.
 * 6. VCC_PORT_LDC_DATA_READY - Data is ready from ldc.
 * 5. VCC_PORT_LDC_WRITE_READY - Ldc has space to receive data.
 * 7. VCC_PORT_LDC_CHANNEL_READY - Ldc channel is up.
 * 8. VCC_PORT_ADDED		- A new port was added.
 * 9. VCC_PORT_TERM_RD		- Terminal read is enabled vs suspended
 * 10. VCC_PORT_TERM_WR		- Terminal write is enabled vc suspended
 * 11. VCC_PORT_NONBLOCK	- A port was opened with non blocking flag.
 * 12. VCC_PORT_LDC_LINK_DOWN
 *
 *
 * Code flow for port to transit from one state to another is as the follows:
 *
 * 1. VCC_PORT_AVAIL
 *
 *	    Transition from unavailable to available
 *		- obtain port lock
 *		Transit port to available and added states
 *		- release port lock
 *		- obtain softstate lock
 *		Increase total number of ports
 *		- release softsate lock
 *
 *		after download added port to vntsd
 *		- obtain port lock
 *		Transit port to not added state
 *		- release port lock
 *
 *	    Transition from available to unavailable
 *		- obtain port lock
 *		- cv_wait read available
 *		Transit port to read unavailable
 *		- cv_wait write available
 *		Transit port to write unavailable
 *		Transit port to not ready. (close ldc channel)
 *		Transit port to deleted state
 *		Transit port to read and write available
 *		- cv_broadcast
 *		- release lock
 *
 *		vntsd close the deleted port
 *		- obtained port lock
 *		Transit port to close and deleted state
 *		- release port lock
 *
 *		after vntsd deletion of the port
 *		- obtain softstate lock
 *		- cv_wait port table unlocked
 *		Transit softstate to port table locked
 *		- release softstate lock
 *		- obtain port lock
 *		Transit port to unavailable
 *		destroy port lock
 *		- obtain softstate lock
 *		Transit softstate to port table unlocked
 *		- cv_broadcast
 *		- release softsate lock
 *
 * 2. VCC_PORT_OPEN
 *
 *	    Transition from close to open
 *		- obtain port lock
 *		transit port to open
 *		- release port lock
 *
 *	    Transition from open to close
 *		- obtain port lock
 *		- cv_wait read available
 *		Transit port to read unavailable
 *		- cv_wait write available
 *		Transit port to write unavailable
 *		Transit port to not ready. (close ldc channel)
 *		Transit port to close state
 *		Transit port to read and write available
 *		- cv_broadcast
 *		- release lock
 *
 * 3. VCC_PORT_USE_READ_LDC/VCC_PORT_USE_WRITE_LDC
 *	    Transition from read availale/write available
 *	    to read unavailable/write unavailable
 *		- obtain port lock
 *		- cv_wait read available
 *		Transit to read/write unavailable
 *		- release port lock
 *
 *	    Transition from read unavailale/write unavailable
 *	    to read available/write available
 *		- obtain port lock
 *		Transit to read/write available
 *		- cv_broadcast
 *		- release port lock
 *
 * 4. VCC_PORT_LDC_CHANNEL_READY
 *	    Transition from data not ready to data ready
 *		- obtain port lock
 *		Transit to data ready
 *		- cv_broadcast
 *		- release port lock
 *
 *	    Transition from data ready to data not ready
 *		- obtain port lock
 *		Transit to data not ready
 *		- release port lock
 */

#define	    VCC_PORT_AVAIL		0x1	/* port is configured */
#define	    VCC_PORT_OPEN		0x2	/* port is opened */
#define	    VCC_PORT_LDC_CHANNEL_READY	0x4	/* ready for data transfer */
#define	    VCC_PORT_USE_READ_LDC	0x8	/* read lock */
#define	    VCC_PORT_USE_WRITE_LDC	0x10	/* write lock */
#define	    VCC_PORT_LDC_DATA_READY	0x20	/* data ready */
#define	    VCC_PORT_LDC_WRITE_READY	0x40	/* ldc ready receive data */
#define	    VCC_PORT_ADDED		0x80	/* added, no ack from vntsd */
#define	    VCC_PORT_UPDATED		0x100	/* updated, no ack from vntsd */
#define	    VCC_PORT_TERM_RD		0x200	/* suspend write */
#define	    VCC_PORT_TERM_WR		0x400	/* suspend read */
#define	    VCC_PORT_NONBLOCK		0x800	/* open with non block flag */
#define	    VCC_PORT_LDC_LINK_DOWN	0x1000	/* ldc link down */

/* Poll Flags */
#define	    VCC_POLL_CONFIG	    0x1	    /* poll configuration change  */

/* Poll evnets */
#define	    VCC_POLL_ADD_PORT	    0x10    /* add a console port */
#define	    VCC_POLL_UPDATE_PORT    0x20    /* update a console port  */

/* softstate port table state */
#define	    VCC_LOCK_PORT_TBL		0x1

/* VCC limits */
#define	    VCC_MAX_PORTS	    0x800	    /* number of domains */
#define	    VCC_MAX_MINORS	    VCC_MAX_PORTS   /* number of minors */


#define	    VCC_MAX_PORT_MINORS		(VCC_MAX_MINORS - 1)
#define	    VCC_CONTROL_MINOR_IDX	(VCC_MAX_MINORS - 1)

/* size of vcc message data */
#define	    VCC_MTU_SZ		    56

/* Default values */
#define	    VCC_HDR_SZ		    8	    /* header size */
#define	    VCC_BUF_SZ		    (VCC_HDR_SZ + VCC_MTU_SZ)

#define	    VCC_CONTROL_PORT	    0x7ff   /* port 2047 is control port  */
#define	    VCC_INST_SHIFT	    11
#define	    VCC_INVALID_CHANNEL	    -1
#define	    VCC_NO_PID_BLOCKING	    -1

#define	    VCC_MINOR_NAME_PREFIX   "ldom-" /* device name prefix */

/* HV message data type */
#define	    LDC_CONSOLE_CTRL	    0x1	    /* ctrl msg */
#define	    LDC_CONSOLE_DATA	    0x2	    /* data msg */

/* HV control messages */
#define	    LDC_CONSOLE_BREAK	    -1	    /* brk */
#define	    LDC_CONSOLE_HUP	    -2	    /* hup */

/*  minor number to port number */
#define	    VCCPORT(p, minor)	    (p->minor_tbl[(minor & \
    VCC_CONTROL_PORT)].portno)

/*  minor number to minor pointer */
#define	    VCCMINORP(p, minor)	    (&(p->minor_tbl[(minor & \
    VCC_CONTROL_PORT)]))

/* minor number to instance */
#define	    VCCINST(minor)	    ((minor) >> VCC_INST_SHIFT)


/* hv console packet format */
typedef struct vcc_msg {
	uint8_t		type;		    /* type - data or ctrl */
	uint8_t		size;		    /* data size */
	uint16_t	unused;		    /* not used */
	int32_t		ctrl_msg;	    /* data if type is ctrl */
	uint8_t		data[VCC_MTU_SZ];   /* data if type is data */
} vcc_msg_t;

/*
 *  minor node to port mapping table
 */
typedef struct vcc_minor {
	uint_t		portno;			    /* port number */
	char		domain_name[MAXPATHLEN];    /* doman name */
} vcc_minor_t;

/* console port structure */
typedef struct vcc_port {

	kmutex_t 	lock;		/* protects port */
	kcondvar_t	read_cv;	/* cv to sleep for reads */
	kcondvar_t	write_cv;	/* cv to sleep for writes */

	uint_t		number;		/* port number */
	uint32_t	status;		/* port status */

	char		group_name[MAXPATHLEN];
	uint64_t	tcp_port;	/* tcp port num */

	struct	termios	term;		/* terminal emulation */

	vcc_minor_t	*minorp;	/* pointer to minor table entry */

	uint64_t	ldc_id;		/* Channel number */
	ldc_handle_t	ldc_handle;	/* Channel handle */
	ldc_status_t	ldc_status;	/* Channel Status */

	uint_t		pollflag;	/* indicated poll status */
	struct pollhead	poll;
	uint32_t	pollevent;
	pid_t		valid_pid;	/* pid that allows cb_ops */

} vcc_port_t;

/*
 * vcc  driver's soft state structure
 */
typedef struct vcc {

	/* protects vcc_t (soft state)  */
	kmutex_t		lock;

	uint_t			status;

	dev_info_t		*dip;			   /* dev_info */

	mdeg_node_spec_t	*md_ispecp;		   /* mdeg prop spec */
	mdeg_handle_t		mdeg_hdl;		   /* mdeg handle */

	vcc_port_t		port[VCC_MAX_PORTS];	   /* port table */
	uint_t			num_ports;		   /* avail ports */

	vcc_minor_t		minor_tbl[VCC_MAX_PORTS];   /* minor table */
	uint_t			minors_assigned;	   /* assigned minors */
} vcc_t;

#ifdef __cplusplus
}
#endif

#endif	/* _VCC_IMPL_H */
