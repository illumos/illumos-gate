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
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * basic API declarations for share management
 */

#ifndef _LIBSHARE_SMBFS_H
#define	_LIBSHARE_SMBFS_H

#ifdef	__cplusplus
extern "C" {
#endif

struct smbclnt_proto_option_defs {
	char *name;	/* display name -- remove protocol identifier */
	char *value;
	int index;
	int flags;
	int32_t minval;
	int32_t maxval; /* In case of length of string this should be max */
	int (*validator)(int, char *, char *);
};

extern struct smbclnt_proto_option_defs smbclnt_proto_options[];

#define	PROTO_OPT_SECTION		0
#define	PROTO_OPT_ADDR			1
#define	PROTO_OPT_MINAUTH		2
#define	PROTO_OPT_NBNS_BROADCAST	3
#define	PROTO_OPT_NBNS_ENABLE		4
#define	PROTO_OPT_NBNSADDR		5
#define	PROTO_OPT_PASSWORD		6
#define	PROTO_OPT_TIMEOUT		7
#define	PROTO_OPT_USER			8
#define	PROTO_OPT_DOMAIN		9
#define	PROTO_OPT_WORKGROUP		10
#define	PROTO_OPT_SIGNING		11
#define	PROTO_OPT_MIN_PROTOCOL		12
#define	PROTO_OPT_MAX_PROTOCOL		13

#define	SMBC_OPT_MAX	PROTO_OPT_MAX_PROTOCOL

/*
 * Flags values
 */
#define	SMBC_MODIFIED			0x01

/* Max value length of all SMB properties */
#define	MAX_VALUE_BUFLEN	600

/*
 * SMF access
 */

#define	SMBC_FMRI_PREFIX		"network/smb/client"
#define	SMBC_DEFAULT_INSTANCE_FMRI	"svc:/network/smb/client:default"
#define	SMBC_PG_PREFIX			"S-"
#define	SMBC_PG_PREFIX_LEN		2
#define	SMBC_PG_INSTANCE		"default"

#define	SMBC_SMF_OK		0
#define	SMBC_SMF_NO_MEMORY	1	/* no memory for data structures */
#define	SMBC_SMF_SYSTEM_ERR	2	/* system error, use errno */
#define	SMBC_SMF_NO_PERMISSION	3	/* no permission for operation */

#define	SCH_STATE_UNINIT	0
#define	SCH_STATE_INITIALIZING	1
#define	SCH_STATE_INIT		2

typedef struct smb_scfhandle {
	scf_handle_t		*scf_handle;
	int			scf_state;
	scf_service_t		*scf_service;
	scf_scope_t		*scf_scope;
	scf_transaction_t	*scf_trans;
	scf_transaction_entry_t	*scf_entry;
	scf_propertygroup_t	*scf_pg;
	scf_instance_t		*scf_instance;
	scf_iter_t		*scf_inst_iter;
	scf_iter_t		*scf_pg_iter;
} smb_scfhandle_t;

extern void smb_smf_scf_fini(smb_scfhandle_t *);
extern smb_scfhandle_t *smb_smf_scf_init(char *);
extern int smb_smf_get_instance(smb_scfhandle_t *, char *);
extern int smb_smf_create_instance(smb_scfhandle_t *, char *);
extern int smb_smf_start_transaction(smb_scfhandle_t *);
extern int smb_smf_end_transaction(smb_scfhandle_t *);

extern int smb_smf_set_string_property(smb_scfhandle_t *, char *, char *);
extern int smb_smf_get_string_property(smb_scfhandle_t *, char *,
    char *, size_t);
extern int smb_smf_set_integer_property(smb_scfhandle_t *, char *, int64_t);
extern int smb_smf_get_integer_property(smb_scfhandle_t *, char *, int64_t *);
extern int smb_smf_set_boolean_property(smb_scfhandle_t *, char *, uint8_t);
extern int smb_smf_get_boolean_property(smb_scfhandle_t *, char *, uint8_t *);
extern int smb_smf_set_opaque_property(smb_scfhandle_t *, char *,
    void *, size_t);
extern int smb_smf_get_opaque_property(smb_scfhandle_t *, char *,
    void *, size_t);

extern int smb_smf_create_service_pgroup(smb_scfhandle_t *, char *);
extern int smb_smf_delete_service_pgroup(smb_scfhandle_t *, char *);
extern int smb_smf_create_instance_pgroup(smb_scfhandle_t *, char *);
extern int smb_smf_delete_instance_pgroup(smb_scfhandle_t *, char *);
extern int smb_smf_delete_property(smb_scfhandle_t *, char *);
extern int smb_smf_instance_exists(smb_scfhandle_t *, char *);
extern int smb_smf_instance_create(smb_scfhandle_t *, char *, char *);
extern int smb_smf_instance_delete(smb_scfhandle_t *, char *);
extern smb_scfhandle_t *smb_smf_get_iterator(char *);

#ifdef	__cplusplus
}
#endif

#endif /* _LIBSHARE_SMBFS_H */
