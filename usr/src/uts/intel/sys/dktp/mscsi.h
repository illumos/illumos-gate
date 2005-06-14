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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_DKTP_MSCSI_H
#define	_SYS_DKTP_MSCSI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * mscsi_bus header file.  Driver private interface
 * between a multiple scsi bus hba scsa nexus driver
 * and the mscsi-bus nexus driver, which provides
 * per-bus support.
 */

/*
 * mbus_ops:     mbus nexus drivers only.
 *
 * This structure provides a wrapper for the generic bus_ops
 * structure, allowing mscsi drivers to transparently remap
 * bus_ops functions as needed.
 *
 * Only nexus drivers should use this structure.
 *
 *      m_ops         -  Replacement struct bus_ops
 *	m_dops        -  Saved struct dev_ops
 *      m_bops        -  Saved struct bus_ops
 *      m_private     -  Any other saved private data
 */

struct mbus_ops {
	struct bus_ops	 m_ops;		/* private struct bus_ops */
	struct dev_ops  *m_dops;	/* saved struct dev_ops* */
	struct bus_ops  *m_bops;	/* saved struct bus_ops* */
	void 		*m_private;	/* saved private data */
};

#define	MSCSI_FEATURE			/* mscsi feature define */
#define	MSCSI_NAME	"mscsi"		/* nodename of mscsi driver */
#define	MSCSI_BUSPROP	"mscsi-bus"	/* propertyname of mscsi-bus no. */
#define	MSCSI_CALLPROP	"mscsi-call"	/* propertyname of callback request */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_DKTP_MSCSI_H */
