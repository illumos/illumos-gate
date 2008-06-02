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

#ifndef	_LIBMLSVC_H
#define	_LIBMLSVC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <smbsrv/smb_sid.h>
#include <smbsrv/hash_table.h>
#include <smbsrv/smb_token.h>
#include <smbsrv/smb_privilege.h>
#include <smbsrv/lmshare.h>
#include <smbsrv/libsmb.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern int mlsvc_init(void);
extern uint32_t mlsvc_lookup_name(char *, smb_sid_t **, uint16_t *);
extern uint32_t mlsvc_lookup_sid(smb_sid_t *, char **);
extern DWORD mlsvc_netlogon(char *, char *);
extern DWORD lsa_query_primary_domain_info(void);
extern DWORD lsa_query_account_domain_info(void);
extern DWORD lsa_enum_trusted_domains(void);

extern boolean_t smbd_locate_dc(char *, char *);

#define	SMB_AUTOHOME_FILE	"smbautohome"
#define	SMB_AUTOHOME_PATH	"/etc"

typedef struct smb_autohome {
	struct smb_autohome *ah_next;
	uint32_t ah_hits;
	time_t ah_timestamp;
	char *ah_name;		/* User account name */
	char *ah_path;		/* Home directory path */
	char *ah_container;	/* ADS container distinguished name */
} smb_autohome_t;

extern void smb_autohome_add(const char *);
extern void smb_autohome_remove(const char *);
extern boolean_t smb_is_autohome(const lmshare_info_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBMLSVC_H */
