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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FCGP2_H
#define	_SYS_FCGP2_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Header file for the GP2 (Safari) Fcode Interpreter
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	GP2_METHOD_OPS_VERSION    0

/*
 * gp2 platform specific method operations structure definition.
 *
 *	Function			Description
 *	--------			-----------
 *	xxx_method_op_claim_address	Allocate suitable Safari address
 *					space.
 *	xxx_method_op_unclaim_address	Free Safari address space that was
 *					previously claimed by the
 *					'claim-address' method.  Note there
 *					is no 'unclaim-address' method.  This
 *					function is called directly from gp2cfg
 *					where freeing a device node.
 */
typedef struct gp2_method_ops {
	int	gp2_method_op_version;	/* GP2_METHOD_OPS_VERSION */
	int	(*gp2_method_op_claim_address)(dev_info_t *ap,
		    fco_handle_t, fc_ci_t *);
	int	(*gp2_method_op_unclaim_address)(dev_info_t *ap,
		    fco_handle_t, fc_ci_t *);
} gp2_method_ops_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FCGP2_H */
