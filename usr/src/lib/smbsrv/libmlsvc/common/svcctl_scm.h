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

#ifndef	_SVCCTL_H
#define	_SVCCTL_H

#include <libuutil.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/nterror.h>
#include <smbsrv/mlrpc.h>
#include <smbsrv/winsvc.h>
#include <smbsrv/ndl/svcctl.ndl>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Calculate the wide-char equivalent string length required to
 * store a string - including the terminating null wide-char.
 */
#define	SVCCTL_WNSTRLEN(S)	((strlen((S)) + 1) * sizeof (mts_wchar_t))

/* An AVL-storable node representing each service in the SCM database. */
typedef struct svcctl_svc_node {
	uu_avl_node_t		sn_node;
	char			*sn_name;	/* Service Name (Key) */
	char			*sn_fmri;	/* Display Name (FMRI) */
	char			*sn_desc;	/* Description */
	char			*sn_state;	/* State */
} svcctl_svc_node_t;

/* This structure provides context for each svcctl_s_OpenManager call. */
typedef struct svcctl_manager_context {
	scf_handle_t		*mc_scf_hdl;	  /* SCF handle */
	scf_propertygroup_t	*mc_scf_gpg;	  /* Property group */
	scf_property_t		*mc_scf_gprop;	  /* Property */
	scf_value_t		*mc_scf_gval;	  /* Value */
	uint32_t		mc_scf_numsvcs;   /* Number of SMF services */
	ssize_t			mc_scf_max_fmri_len;  /* Max FMRI length */
	ssize_t			mc_scf_max_value_len; /* Max Value length */
	uint32_t		mc_bytes_needed;  /* Number of bytes needed */
	uu_avl_pool_t		*mc_svcs_pool;	  /* AVL pool */
	uu_avl_t		*mc_svcs;	  /* AVL tree of SMF services */
} svcctl_manager_context_t;

/* This structure provides context for each svcctl_s_OpenService call. */
typedef struct svcctl_service_context {
	ndr_hdid_t		*sc_mgrid;	/* Manager ID */
	char			*sc_svcname;    /* Service Name */
} svcctl_service_context_t;

typedef enum {
	SVCCTL_MANAGER_CONTEXT = 0,
	SVCCTL_SERVICE_CONTEXT
} svcctl_context_type_t;

/* This structure provides abstraction for service and manager context call. */
typedef struct svcctl_context {
	svcctl_context_type_t	c_type;
	union {
		svcctl_manager_context_t *uc_mgr;
		svcctl_service_context_t *uc_svc;
		void *uc_cp;
	} c_ctx;
} svcctl_context_t;

/* Service Control Manager (SCM) functions */
int svcctl_scm_init(svcctl_manager_context_t *);
void svcctl_scm_fini(svcctl_manager_context_t *);
int svcctl_scm_scf_handle_init(svcctl_manager_context_t *);
void svcctl_scm_scf_handle_fini(svcctl_manager_context_t *);
int svcctl_scm_refresh(svcctl_manager_context_t *);
void svcctl_scm_bytes_needed(svcctl_manager_context_t *);
void svcctl_scm_enum_services(svcctl_manager_context_t *, unsigned char *);
uint32_t svcctl_scm_validate_service(svcctl_manager_context_t *, char *);
svcctl_svc_node_t *svcctl_scm_find_service(svcctl_manager_context_t *, char *);
uint32_t svcctl_scm_map_status(const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SVCCTL_H */
