/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_BUSSTAT_H
#define	_BUSSTAT_H


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * busstat works by reading and writing from/to kstat's which are
 * exported by drivers on the system.
 *
 * busstat parses the command line it is given and builds up a
 * pair of linked list's to represent the various options specified.
 * An example command line is given below..
 *
 * -w ac2,pic0=wio_pkts,pic1=rbio_pkts -w ac2,pic0=rto_pkts,pic1=rto_pkts -r ac5
 * =============================================================================
 *
 * ______
 * |    |
 * | ac2|->wio_pkts->rto_pkts
 * |pic0|    |            |
 * |    |    -------<------
 * ------
 *    |
 *    |
 * ______
 * |    |
 * | ac2|->rbio_pkts->rto_pkts
 * |pic1|     |            |
 * |    |     --------<-----
 * ------
 *    |
 *    |
 * ______
 * |    |
 * | ac5|->evt
 * |pic0|
 * |    |
 * ------
 *   |
 *   |
 * ______
 * |    |
 * | ac5|->evt
 * |pic1|
 * |    |
 * ------
 *
 * The above diagram shows the lists created after the initial parsing.
 *
 * Each device instance/pic is represented by a device node. Hanging off
 * that is at least one event node.
 *
 * Event nodes come in two different types. Nodes that are the result of a -r
 * operation will have the r_w field in their parent dev_node set to EVT_READ,
 * and most of their other fields set to zero or NULL. An event node that was
 * created because of a -w operation (r_w = EVT_WRITE) will have all it's fields
 * filled in. When a device node is created, an  event node is automatically
 * created and marked as EVT_READ. If the device node was created as the result
 * of a -r operation, nothing more happens. But if it was a -w operation, then
 * the event node is modified (r_w changed to EVT_WRITE, event pcr mask and
 * event name written if known).
 *
 * Setting events : work along the list of dev_nodes, for each device node check
 * the event node pointed to by evt_node, if it is marked as EVT_WRITE in the
 * corresponding r_w array, if so set the event stored in the node.
 *
 * Reading events : work along the list of dev_nodes, for each device node check
 * the event node pointed to by evt_node, if it is marked EVT_WRITE, just read
 * the event count from the appropiate PIC and store it in the node. If the node
 * is EVT_READ however, read the PCR, determine the event name, store it in the
 * node along with the event count.
 *
 * Multiplexing is handled by cycling through the event nodes. The event nodes
 * are on a circular list, which allows each pic to be multiplexing between
 * different numbers of events.
 */

#define	TRUE	1
#define	FALSE	0
#define	FAIL	-1

#define	READ_EVT	1
#define	WRITE_EVT	0

#define	EVT_READ	0x1
#define	EVT_WRITE	0x2
#define	ONE_INST_CALL	0x4
#define	ALL_INST_CALL	0x8

#define	STATE_INIT	0x10	/* Initial state of node when created */
#define	STATE_INST	0x20	/* Node was created by specific instance call */
#define	STATE_ALL	0x40	/* Node was created by call for all instances */

#define	NANO		1000000000	/* To convert from nanosecs to secs */

#define	PIC_STR_LEN	3

#define	EVT_STR		-1

typedef struct evt_node {
	char		evt_name[KSTAT_STRLEN];	/* The event name */
	uint64_t	prev_count;	/* The previous count for this evt */
	uint64_t	total;		/* Total count for this event */
	uint64_t	evt_pcr_mask;	/* PCR mask for this event */
	struct evt_node *next;
} evt_node_t;

typedef struct dev_node {
	char		name[KSTAT_STRLEN];	/* Device name e.g. ac */
	int		dev_inst;	/* Device instance number */
	int		pic_num;	/* PIC number. */
	kstat_t		*cnt_ksp;	/* "counters" kstat pointer */
	kstat_t		*pic_ksp;	/* pointer to picN kstat */
	int		r_w;		/* r_w flag */
	int		state;		/* state flag */
	struct evt_node	*evt_node;	/* ptr to current evt_node */
	struct dev_node	*next;
} dev_node_t;

#endif	/* _BUSSTAT_H */
