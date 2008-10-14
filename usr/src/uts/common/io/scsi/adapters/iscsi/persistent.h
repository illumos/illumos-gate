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

#ifndef _PERSISTENT_H
#define	_PERSISTENT_H

#ifdef __cplusplus
extern "C" {
#endif


#include <iscsi.h>

/*
 * Data Structures
 */

typedef struct persistent_param {
	uint32_t		p_bitmap;	/* parameter override bitmap */
	iscsi_login_params_t	p_params;
} persistent_param_t;


/*
 * Function Prototypes
 */
boolean_t	persistent_init(boolean_t restart);
void		persistent_fini(void);
boolean_t	persistent_disc_meth_set(iSCSIDiscoveryMethod_t method);
iSCSIDiscoveryMethod_t	persistent_disc_meth_get(void);
boolean_t	persistent_disc_meth_clear(iSCSIDiscoveryMethod_t method);
boolean_t	persistent_initiator_name_set(char *p);
boolean_t	persistent_initiator_name_get(char *p, int size);
boolean_t	persistent_alias_name_set(char *p);
boolean_t	persistent_alias_name_get(char *p, int size);
boolean_t	persistent_static_addr_set(char *node, entry_t *e);
boolean_t	persistent_static_addr_next(void **v, char *node, entry_t *e);
boolean_t	persistent_static_addr_clear(uint32_t oid);
void		persistent_static_addr_lock(void);
void		persistent_static_addr_unlock(void);
boolean_t	persistent_isns_addr_set(entry_t *e);
boolean_t	persistent_isns_addr_next(void **v, entry_t *e);
boolean_t	persistent_isns_addr_clear(entry_t *e);
void		persistent_isns_addr_lock(void);
void		persistent_isns_addr_unlock(void);
boolean_t	persistent_disc_addr_set(entry_t *e);
boolean_t	persistent_disc_addr_next(void **v, entry_t *e);
boolean_t	persistent_disc_addr_clear(entry_t *e);
void		persistent_disc_addr_lock(void);
void		persistent_disc_addr_unlock(void);
boolean_t	persistent_param_set(char *node, persistent_param_t *param);
boolean_t	persistent_param_get(char *node, persistent_param_t *param);
boolean_t	persistent_param_next(void **v, char *node,
		    persistent_param_t *param);
boolean_t	persistent_param_clear(char *node);
void		persistent_param_lock(void);
void		persistent_param_unlock(void);
boolean_t	persistent_chap_set(char *node, iscsi_chap_props_t *chap);
boolean_t	persistent_chap_get(char *node, iscsi_chap_props_t *chap);
boolean_t	persistent_chap_next(void **v,  char *node,
		    iscsi_chap_props_t *chap);
boolean_t	persistent_chap_clear(char *node);
void		persistent_chap_lock(void);
void		persistent_chap_unlock(void);
boolean_t	persistent_radius_set(iscsi_radius_props_t *radius);
iscsi_nvfile_status_t	persistent_radius_get(iscsi_radius_props_t *radius);
boolean_t	persistent_auth_set(char *node, iscsi_auth_props_t *auth);
boolean_t	persistent_auth_get(char *node, iscsi_auth_props_t *auth);
boolean_t	persistent_auth_next(void **v, char *node,
		    iscsi_auth_props_t *auth);
boolean_t	persistent_auth_clear(char *node);
void		persistent_auth_lock(void);
void		persistent_auth_unlock(void);
void		persistent_dump_data(void);
boolean_t	persistent_set_config_session(char *node,
		    iscsi_config_sess_t *ics);
boolean_t	persistent_get_config_session(char *node,
		    iscsi_config_sess_t *ics);


#ifdef __cplusplus
}
#endif

#endif /* _PERSISTENT_H */
