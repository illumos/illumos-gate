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

/* Copyright 2010 QLogic Corporation */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_QL_IOCTL_H
#define	_QL_IOCTL_H

/*
 * ISP2xxx Solaris Fibre Channel Adapter (FCA) driver header file.
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2010 QLOGIC CORPORATION		**
 * *			ALL RIGHTS RESERVED				**
 * *									**
 * ***********************************************************************
 *
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Global Function Prototypes in ql_ioctl.c source file.
 */
int ql_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
int ql_open(dev_t *dev_p, int flags, int otyp, cred_t *cred_p);
int ql_close(dev_t dev, int flags, int otyp, cred_t *cred_p);
int ql_nv_util_load(ql_adapter_state_t *, void *, int);
int ql_nv_util_dump(ql_adapter_state_t *, void *, int);
int ql_vpd_load(ql_adapter_state_t *, void *, int);
int ql_vpd_dump(ql_adapter_state_t *, void *, int);
int32_t ql_vpd_lookup(ql_adapter_state_t *, uint8_t *, uint8_t *, int32_t);
int ql_r_m_w_flash(ql_adapter_state_t *, caddr_t, uint32_t, uint32_t, int);
int ql_get_nvram(ql_adapter_state_t *, void *, uint32_t, uint32_t);

#ifdef	__cplusplus
}
#endif

#endif /* _QL_IOCTL_H */
