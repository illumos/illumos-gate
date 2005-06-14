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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_FM_IO_PCI_H
#define	_SYS_FM_IO_PCI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PCI_ERROR_SUBCLASS	"pci"
#define	PCI_SEC_ERROR_SUBCLASS	"sec"

/* Common PCI ereport classes */
#define	PCI_DET_PERR		"dpe"
#define	PCI_MDPE		"mdpe"
#define	PCI_REC_SERR		"rserr"
#define	PCI_SIG_SERR		"sserr"
#define	PCI_MA			"ma"
#define	PCI_REC_TA		"rta"
#define	PCI_SIG_TA		"sta"
#define	PCI_DTO			"dto"
#define	PCI_TARG_MDPE		"target-mdpe"
#define	PCI_TARG_MA		"target-ma"
#define	PCI_TARG_REC_TA		"target-rta"
#define	PCI_NR			"nr"

/* PCI Error payload name fields */
#define	PCI_CONFIG_STATUS	"pci-status"
#define	PCI_CONFIG_COMMAND	"pci-command"
#define	PCI_SEC_CONFIG_STATUS	"pci-sec-status"
#define	PCI_BCNTRL		"pci-bdg-ctrl"
#define	PCI_PA			"pci-pa"

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FM_IO_PCI_H */
