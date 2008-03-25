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

#ifndef	_MGMT_SCF_H
#define	_MGMT_SCF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	_cplusplus
extern "C" {
#endif

#include <libscf.h>
#include <iscsitgt_impl.h>
#include <ucred.h>

#define	SA_TARGET_SVC_NAME		"system/iscsitgt"
#define	SA_TARGET_SVC_INSTANCE_FMRI	"svc:/system/iscsitgt:default"

#define	ISCSI_READ_AUTHNAME		"read_authorization"
#define	ISCSI_MODIFY_AUTHNAME		"modify_authorization"
#define	ISCSI_VALUE_AUTHNAME		"value_authorization"

#define	ISCSI_AUTH_READ			"solaris.smf.read.iscsitgt"
#define	ISCSI_AUTH_MANAGE		"solaris.smf.manage.iscsitgt"
#define	ISCSI_AUTH_MODIFY		"solaris.smf.modify.iscsitgt"
#define	ISCSI_AUTH_VALUE		"solaris.smf.value.iscsitgt"

typedef enum {
	CONVERT_OK = 0,
	CONVERT_INIT_NEW,
	CONVERT_FAIL
} convert_ret_t;

typedef struct {
	scf_handle_t		*t_handle;
	scf_scope_t		*t_scope;
	scf_service_t		*t_service;
	scf_propertygroup_t	*t_pg;
	scf_instance_t		*t_instance;
	scf_transaction_t	*t_trans;
} targ_scf_t;

typedef	struct secret_list {
	char	*name;
	char	*secret;
	struct	secret_list *next;
} secret_list_t;

Boolean_t mgmt_scf_init();
void mgmt_scf_fini();

targ_scf_t *mgmt_handle_init(void);
Boolean_t mgmt_transaction_start(targ_scf_t *h, char *pg, char *prop);
Boolean_t mgmt_transaction_end(targ_scf_t *h);
void mgmt_transaction_abort(targ_scf_t *h);

Boolean_t mgmt_get_main_config(tgt_node_t **node);
Boolean_t mgmt_config_save2scf();

Boolean_t mgmt_param_save2scf(tgt_node_t *node, char *target_name, int lun);
Boolean_t mgmt_get_param(tgt_node_t **node, char *target_name, int lun);
Boolean_t mgmt_param_remove(char *target_name, int lun);
convert_ret_t mgmt_convert_conf();

Boolean_t check_auth_modify(ucred_t *cred);
Boolean_t check_auth_addremove(ucred_t *cred);

int get_zfs_shareiscsi(char *, tgt_node_t **, uint64_t *, ucred_t *);
int put_zfs_shareiscsi(char *, tgt_node_t *);
#define	ZFS_PROP_SIZE	(2 * 1024)


#ifdef __cplusplus
}
#endif

#endif /* _MGMT_SCF_H */
