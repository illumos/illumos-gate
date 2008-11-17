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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_XDF_SHELL_H
#define	_XDF_SHELL_H

#ifdef	__cplusplus
extern "C" {
#endif

/* These interfaces are all dependant upon xdf */
#include <io/xdf.h>

/* Include files required for this header file. */
#include <sys/vtoc.h>

/*
 * These include files are not strictly required to include this header
 * file, but pretty much every xdf_shell client will need to include these
 * header files, so just include them here.
 */
#include <sys/cdio.h>
#include <sys/dklabel.h>
#include <sys/dktp/altsctr.h>
#include <sys/dktp/bbh.h>
#include <sys/dktp/cmdk.h>
#include <sys/dktp/dadev.h>
#include <sys/dktp/dadkio.h>
#include <sys/fdio.h>

/*
 * XDF Shell driver state structures
 */
typedef struct xdfs_state {
	dev_info_t	*xdfss_dip;
	const char	*xdfss_pv;
	const char	*xdfss_hvm;

	/* Members below are protected by xdfss_mutex */
	kmutex_t	xdfss_mutex;
	kcondvar_t	xdfss_cv;
	cmlb_handle_t	xdfss_cmlbhandle;
	int		xdfss_otyp_count[OTYPCNT][XDF_PEXT];

	/* Members below are only valid when xdfss_tgt_attached is true */
	dev_info_t	*xdfss_tgt_dip;
	boolean_t	xdfss_tgt_attached;
	int		xdfss_tgt_holds;
	dev_t		xdfss_tgt_dev;
	ddi_devid_t	xdfss_tgt_devid;
	boolean_t	xdfss_tgt_locked;
	boolean_t	xdfss_tgt_is_cd;
	ldi_handle_t	xdfss_tgt_lh[XDF_PEXT];
} xdfs_state_t;

typedef struct xdfs_h2p_map {
	const char	*xdfs_h2p_hvm;
	const char	*xdfs_h2p_pv;
} xdfs_h2p_map_t;

/*
 * Globals defined by xdf_shell.c
 */
extern major_t xdfs_major;

/*
 * Functions defined by xdf_shell.c
 */
extern int xdfs_lb_rdwr(dev_info_t *, uchar_t, void *, diskaddr_t, size_t,
    void *);
extern int xdfs_strategy(struct buf *);
extern void xdfs_minphys(struct buf *);

/*
 * Globals that must be defined by xdf_shell.c clients
 */
extern const char		*xdfs_c_name;
extern const char		*xdfs_c_linkinfo;
extern void			**xdfs_c_hvm_ss;
extern const size_t		xdfs_c_hvm_ss_size;
extern const struct dev_ops	*xdfs_c_hvm_dev_ops;
extern const xdfs_h2p_map_t	xdfs_c_h2p_map[];

/*
 * Functions that must be implemented by xdf_shell.c clients
 */

/*
 * xdfs_c_devid_setup() is invoked during device probe.  If possible, it
 * should create a devid for the associated disk device.  This routine will
 * not be invoked for cdrom devices.
 */
extern void xdfs_c_devid_setup(xdfs_state_t *);

/*
 * xdfs_c_bb_check() is invoked during device probe.  It should check for
 * the existance of bad blocks mappings in an alternate partition/slice and
 * return B_FALSE if there are no bad block mappings found and return B_TRUE
 * is there are bad block mappings found.  The presence of bad block
 * mappings will cause the device attach to fail.  This routine will not be
 * invoked for cdrom devices.
 */
extern boolean_t xdfs_c_bb_check(xdfs_state_t *);

/*
 * xdfs_c_getpgeom() is invoked during device probe.  It should return the
 * physical geometery of a disk device that is being attached.  The failure
 * of this routine will cause the device attach to fail.  This routine will
 * not be invoked for cdrom devices.
 */
extern int xdfs_c_getpgeom(dev_info_t *, cmlb_geom_t *);

/*
 * xdfs_c_cmlb_node_type() and xdfs_c_cmlb_alter_behavior() are invoked
 * during device probe while initializing the cmlb module for the device
 * node being probed.  They should return a cmlb node type and cmlb alter
 * behavior flag value that can be passed to cmlb_attach().
 */
extern char *xdfs_c_cmlb_node_type(xdfs_state_t *);
extern int xdfs_c_cmlb_alter_behavior(xdfs_state_t *);

/*
 * xdfs_c_attach() is invoked during device attach.  It provides an
 * opportunity for the client to create properties or do anything else
 * necessary for attach.
 */
extern void xdfs_c_attach(xdfs_state_t *);

/*
 * xdfs_c_getpgeom() is invoked to handle ioctl operations.
 */
extern int xdfs_c_ioctl(xdfs_state_t *, dev_t, int,
    int, intptr_t, int, cred_t *, int *, boolean_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _XDF_SHELL_H */
