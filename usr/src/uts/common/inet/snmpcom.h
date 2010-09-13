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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/* Copyright (c) 1990 Mentat Inc. */

#ifndef	_INET_SNMPCOM_H
#define	_INET_SNMPCOM_H

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL) && defined(__STDC__)

/* snmpcom_req function prototypes */
typedef int (*snmp_setf_t)(queue_t *, int, int, uchar_t *, int);
typedef int (*snmp_getf_t)(queue_t *, mblk_t *, int, boolean_t);

extern int	snmp_append_data(mblk_t *mpdata, char *blob, int len);
extern int	snmp_append_data2(mblk_t *mpdata, mblk_t **last_mpp,
		    char *blob, int len);

extern boolean_t	snmpcom_req(queue_t *q, mblk_t *mp,
    snmp_setf_t setfn, snmp_getf_t getfn, cred_t *cr);

#endif	/* defined(_KERNEL) && defined(__STDC__) */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_SNMPCOM_H */
