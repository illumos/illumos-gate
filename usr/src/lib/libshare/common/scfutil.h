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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * basic API declarations for share management
 */

#ifndef _SCFUTIL_H
#define	_SCFUTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif
#include <libxml/tree.h>

typedef struct scfutilhandle {
	scf_handle_t		*handle;
	int			scf_state;
	scf_service_t		*service;
	scf_scope_t		*scope;
	scf_transaction_t	*trans;
	scf_transaction_entry_t	*entry;
	scf_propertygroup_t	*pg;
	scf_instance_t		*instance;
} scfutilhandle_t;

#define	SCH_STATE_UNINIT	0
#define	SCH_STATE_INITIALIZING	1
#define	SCH_STATE_INIT	2

extern void sa_scf_fini(scfutilhandle_t *);
extern scfutilhandle_t *sa_scf_init();
extern int sa_get_config(scfutilhandle_t *, xmlNodePtr, sa_handle_t);
extern int sa_get_instance(scfutilhandle_t *, char *);
extern int sa_create_instance(scfutilhandle_t *, char *);

/*
 * Shares are held in a property group with name of the form
 * S-<GUID>.  The total length of the name is 38 characters.
 */
#define	SA_SHARE_PG_PREFIX	"S-"
#define	SA_SHARE_PG_PREFIXLEN	2
#define	SA_SHARE_PG_LEN		38
#define	SA_SHARE_UUID_BUFLEN	64

/*
 * service instance related defines
 */
#define	SA_GROUP_SVC_NAME	"network/shares/group"
#define	SA_GROUP_INST_LEN	256

#ifdef	__cplusplus
}
#endif

#endif /* _SCFUTIL_H */
