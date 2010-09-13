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


#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/acct.h>
#include <sys/stream.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

/*
 * Might need to define no operation routines attach(), detach(),
 * reset(), probe(), identify() and get_dev_info().
 */

extern int nopropop();

struct cb_ops no_cb_ops = {
	nodev,		/* open		*/
	nodev,		/* close 	*/
	nodev,		/* strategy	*/
	nodev,		/* print	*/
	nodev,		/* dump		*/
	nodev,		/* read		*/
	nodev,		/* write	*/
	nodev,		/* ioctl	*/
	nodev,		/* devmap	*/
	nodev,		/* mmap		*/
	nodev,		/* segmap	*/
	nochpoll,	/* chpoll	*/
	nopropop,	/* cb_prop_op	*/
	0,		/* stream tab	*/
	D_NEW | D_MP	/* char/blk driver compatibility flag */
};

struct dev_ops nodev_ops = {
	DEVO_REV,		/* devo_rev	*/
	0,			/* refcnt	*/
	ddi_no_info,		/* info		*/
	nulldev,		/* identify	*/
	nulldev,		/* probe	*/
	ddifail,		/* attach	*/
	nodev,			/* detach	*/
	nulldev,		/* reset	*/
	&no_cb_ops,		/* character/block driver operations */
	(struct bus_ops *)0,	/* bus operations for nexus drivers */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

struct dev_ops	**devopsp;

int	devcnt;
