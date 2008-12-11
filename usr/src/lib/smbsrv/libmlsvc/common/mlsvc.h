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

#ifndef _SMBSRV_MLSVC_H
#define	_SMBSRV_MLSVC_H

#include <smbsrv/ndl/netlogon.ndl>

#ifdef __cplusplus
extern "C" {
#endif

int smb_dclocator_init(void);
void dssetup_initialize(void);
void srvsvc_initialize(void);
void wkssvc_initialize(void);
void lsarpc_initialize(void);
void logr_initialize(void);
void netr_initialize(void);
void samr_initialize(void);
void svcctl_initialize(void);
void winreg_initialize(void);
int srvsvc_gettime(unsigned long *);
void msgsvcsend_initialize(void);
void spoolss_initialize(void);

int netr_open(char *, char *, mlsvc_handle_t *);
int netr_close(mlsvc_handle_t *);
DWORD netlogon_auth(char *, mlsvc_handle_t *, DWORD);
int netr_setup_authenticator(netr_info_t *, struct netr_authenticator *,
    struct netr_authenticator *);
DWORD netr_validate_chain(netr_info_t *, struct netr_authenticator *);

#ifdef __cplusplus
}
#endif


#endif /* _SMBSRV_MLSVC_H */
