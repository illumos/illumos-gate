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

#ifndef	_SYS_DADA_DADA_ADDRESS_H
#define	_SYS_DADA_DADA_ADDRESS_H

#include <sys/dada/dada_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * DADA address definition.
 *
 * 	A target driver instance controls a target/lun instance.
 *	It sends the command to the device instance it controls.
 *	In generic case HBA drive maintains the target/lun information
 * 	in the cloned transport structure pointed to by a_hba_tran field.
 *
 */
struct	dcd_address {
	uchar_t			da_lun;		/* Not used. 		*/
	ushort_t		da_target;	/* The target identifier */
	struct dcd_hba_tran	*a_hba_tran; 	/* Transport vectors */
};
#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DADA_DADA_ADDRESS_H */
