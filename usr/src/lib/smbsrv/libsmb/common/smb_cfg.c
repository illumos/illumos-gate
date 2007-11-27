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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * CIFS configuration management library
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <synch.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/types.h>
#include <libscf.h>
#include <smbsrv/libsmb.h>

typedef struct smb_cfg_param {
	char *sc_pg;
	char *sc_name;
	int sc_type;
	char *sc_value;
	uint32_t sc_flags;
} smb_cfg_param_t;

/*
 * config parameter flags
 */
#define	SMB_CF_NOTINIT		0x00	/* Not initialized yet */
#define	SMB_CF_DEFINED		0x01	/* Defined/read from env */
#define	SMB_CF_MODIFIED		0x02	/* Has been modified */
#define	SMB_CF_SYSTEM		0x04    /* system; not part of cifs config */

#define	SMB_CL_NONE	0
#define	SMB_CL_READ	1
#define	SMB_CL_WRITE    2

/* idmap SMF fmri and Property Group */
#define	IDMAP_FMRI_PREFIX		"system/idmap"
#define	MACHINE_SID			"machine_sid"
#define	IDMAP_DOMAIN			"domain_name"
#define	IDMAP_PG_NAME			"config"

#define	SMB_SECMODE_WORKGRP_STR 	"workgroup"
#define	SMB_SECMODE_DOMAIN_STR  	"domain"

#define	SMB_ENC_LEN	1024
#define	SMB_DEC_LEN	256

static char *b64_data =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static rwlock_t smb_cfg_rwlk;
static int lock_type = SMB_CL_NONE;

/*
 * IMPORTANT: any changes to the order of this table's entries
 * need to be reflected in smb_cfg_id_t enum in libsmb.h
 */
static smb_cfg_param_t smb_cfg_table[] =
{
	/* Redirector configuration, User space */
	{SMBD_PG_NAME, SMB_CD_RDR_IPCMODE, SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},
	{SMBD_PROTECTED_PG_NAME, SMB_CD_RDR_IPCUSER,
	    SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},
	{SMBD_PROTECTED_PG_NAME, SMB_CD_RDR_IPCPWD,
	    SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},

	/* Oplock configuration, Kernel Only */
	{SMBD_PG_NAME, SMB_CD_OPLOCK_ENABLE,
	    SCF_TYPE_BOOLEAN, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_OPLOCK_TIMEOUT,
	    SCF_TYPE_INTEGER, 0, SMB_CF_NOTINIT},

	/* Autohome configuration */
	{SMBD_PG_NAME, SMB_CD_AUTOHOME_MAP,
	    SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},

	/* Domain/PDC configuration */
	{SMBD_PG_NAME, SMB_CD_DOMAIN_SID, SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_DOMAIN_MEMB, SCF_TYPE_BOOLEAN, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_DOMAIN_NAME, SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_DOMAIN_SRV, SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},

	/* WINS configuration */
	{SMBD_PG_NAME, SMB_CD_WINS_SRV1, SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_WINS_SRV2, SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_WINS_EXCL, SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},

	/* RPC services configuration */
	{SMBD_PG_NAME, SMB_CD_SRVSVC_SHRSET_ENABLE,
	    SCF_TYPE_BOOLEAN, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_LOGR_ENABLE, SCF_TYPE_BOOLEAN, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_MLRPC_KALIVE,
	    SCF_TYPE_INTEGER, 0, SMB_CF_NOTINIT},

	/* Kmod specific configuration */
	{SMBD_PG_NAME, SMB_CD_MAX_BUFSIZE, SCF_TYPE_INTEGER, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_MAX_WORKERS, SCF_TYPE_INTEGER, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_MAX_CONNECTIONS,
	    SCF_TYPE_INTEGER, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_KEEPALIVE, SCF_TYPE_INTEGER, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_RESTRICT_ANON,
	    SCF_TYPE_BOOLEAN, 0, SMB_CF_NOTINIT},

	{SMBD_PG_NAME, SMB_CD_SIGNING_ENABLE,
	    SCF_TYPE_BOOLEAN, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_SIGNING_REQD,
	    SCF_TYPE_BOOLEAN, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_SIGNING_CHECK,
	    SCF_TYPE_BOOLEAN, 0, SMB_CF_NOTINIT},

	/* Kmod tuning configuration */
	{SMBD_PG_NAME, SMB_CD_FLUSH_REQUIRED,
	    SCF_TYPE_BOOLEAN, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_SYNC_ENABLE, SCF_TYPE_BOOLEAN, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_DIRSYMLINK_DISABLE,
	    SCF_TYPE_BOOLEAN, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_ANNONCE_QUOTA,
	    SCF_TYPE_BOOLEAN, 0, SMB_CF_NOTINIT},

	/* SMBd configuration */
	{SMBD_PG_NAME, SMB_CD_SECURITY,	SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_NBSCOPE, SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_SYS_CMNT,	SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_LM_LEVEL,	SCF_TYPE_INTEGER, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_MSDCS_DISABLE,
	    SCF_TYPE_BOOLEAN, 0, SMB_CF_NOTINIT},

	/* ADS Configuration */
	{SMBD_PG_NAME, SMB_CD_ADS_ENABLE, SCF_TYPE_BOOLEAN, 0, SMB_CF_NOTINIT},
	{SMBD_PROTECTED_PG_NAME, SMB_CD_ADS_USER,
	    SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},
	{SMBD_PROTECTED_PG_NAME, SMB_CD_ADS_PASSWD,
	    SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_ADS_DOMAIN, SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_ADS_USER_CONTAINER,
	    SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_ADS_SITE,	SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_ADS_IPLOOKUP,
	    SCF_TYPE_BOOLEAN, 0, SMB_CF_NOTINIT},

	/* Dynamic DNS */
	{SMBD_PG_NAME, SMB_CD_DYNDNS_ENABLE,
	    SCF_TYPE_BOOLEAN, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_DYNDNS_RETRY_COUNT,
	    SCF_TYPE_INTEGER, 0, SMB_CF_NOTINIT},
	{SMBD_PG_NAME, SMB_CD_DYNDNS_RETRY_SEC,
	    SCF_TYPE_INTEGER, 0, SMB_CF_NOTINIT},

	{SMBD_PROTECTED_PG_NAME, SMB_CD_MACHINE_PASSWD,
	    SCF_TYPE_ASTRING, 0, SMB_CF_NOTINIT}
	/* SMB_CI_MAX */
};

static boolean_t smb_is_base64(unsigned char c);
static char *smb_base64_encode(char *str_to_encode);
static char *smb_base64_decode(char *encoded_str);
static int smb_config_update(smb_cfg_param_t *cfg, char *value);
static int smb_config_save_all();
static int smb_config_save(char *pgname);

static boolean_t
smb_is_base64(unsigned char c)
{
	return (isalnum(c) || (c == '+') || (c == '/'));
}

/*
 * smb_base64_encode
 *
 * Encode a string using base64 algorithm.
 * Caller should free the returned buffer when done.
 */
static char *
smb_base64_encode(char *str_to_encode)
{
	int ret_cnt = 0;
	int i = 0, j = 0;
	char arr_3[3], arr_4[4];
	int len = strlen(str_to_encode);
	char *ret = malloc(SMB_ENC_LEN);

	if (ret == NULL) {
		return (NULL);
	}

	while (len--) {
		arr_3[i++] = *(str_to_encode++);
		if (i == 3) {
			arr_4[0] = (arr_3[0] & 0xfc) >> 2;
			arr_4[1] = ((arr_3[0] & 0x03) << 4) +
			    ((arr_3[1] & 0xf0) >> 4);
			arr_4[2] = ((arr_3[1] & 0x0f) << 2) +
			    ((arr_3[2] & 0xc0) >> 6);
			arr_4[3] = arr_3[2] & 0x3f;

			for (i = 0; i < 4; i++)
				ret[ret_cnt++] = b64_data[arr_4[i]];
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 3; j++)
			arr_3[j] = '\0';

		arr_4[0] = (arr_3[0] & 0xfc) >> 2;
		arr_4[1] = ((arr_3[0] & 0x03) << 4) +
		    ((arr_3[1] & 0xf0) >> 4);
		arr_4[2] = ((arr_3[1] & 0x0f) << 2) +
		    ((arr_3[2] & 0xc0) >> 6);
		arr_4[3] = arr_3[2] & 0x3f;

		for (j = 0; j < (i + 1); j++)
			ret[ret_cnt++] = b64_data[arr_4[j]];

		while (i++ < 3)
			ret[ret_cnt++] = '=';
	}

	ret[ret_cnt++] = '\0';
	return (ret);
}

/*
 * smb_base64_decode
 *
 * Decode using base64 algorithm.
 * Caller should free the returned buffer when done.
 */
static char *
smb_base64_decode(char *encoded_str)
{
	int len = strlen(encoded_str);
	int i = 0, j = 0;
	int en_ind = 0;
	char arr_4[4], arr_3[3];
	int ret_cnt = 0;
	char *ret = malloc(SMB_DEC_LEN);
	char *p;

	if (ret == NULL) {
		return (NULL);
	}

	while (len-- && (encoded_str[en_ind] != '=') &&
	    smb_is_base64(encoded_str[en_ind])) {
		arr_4[i++] = encoded_str[en_ind];
		en_ind++;
		if (i == 4) {
			for (i = 0; i < 4; i++) {
				if ((p = strchr(b64_data, arr_4[i])) == NULL)
					return (NULL);

				arr_4[i] = (int)(p - b64_data);
			}

			arr_3[0] = (arr_4[0] << 2) +
			    ((arr_4[1] & 0x30) >> 4);
			arr_3[1] = ((arr_4[1] & 0xf) << 4) +
			    ((arr_4[2] & 0x3c) >> 2);
			arr_3[2] = ((arr_4[2] & 0x3) << 6) +
			    arr_4[3];

			for (i = 0; i < 3; i++)
				ret[ret_cnt++] = arr_3[i];

			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; j++)
			arr_4[j] = 0;

		for (j = 0; j < 4; j++) {
			if ((p = strchr(b64_data, arr_4[j])) == NULL)
				return (NULL);

			arr_4[j] = (int)(p - b64_data);
		}
		arr_3[0] = (arr_4[0] << 2) +
		    ((arr_4[1] & 0x30) >> 4);
		arr_3[1] = ((arr_4[1] & 0xf) << 4) +
		    ((arr_4[2] & 0x3c) >> 2);
		arr_3[2] = ((arr_4[2] & 0x3) << 6) +
		    arr_4[3];
		for (j = 0; j < (i - 1); j++)
			ret[ret_cnt++] = arr_3[j];
	}

	ret[ret_cnt++] = '\0';
	return (ret);
}

/*
 * Basically commit the transaction.
 */
static int
smb_config_saveenv(smb_scfhandle_t *handle)
{
	int ret = 0;

	ret = smb_smf_end_transaction(handle);

	smb_smf_scf_fini(handle);
	return (ret);
}

/*
 * smb_config_getenv
 *
 * Get the property value from SMF.
 */
char *
smb_config_getenv(smb_cfg_id_t id)
{
	smb_scfhandle_t *handle;
	char *value;

	if ((value = malloc(MAX_VALUE_BUFLEN * sizeof (char))) == NULL)
		return (NULL);

	handle = smb_smf_scf_init(SMBD_FMRI_PREFIX);
	if (handle == NULL) {
		free(value);
		return (NULL);
	}

	(void) smb_smf_create_service_pgroup(handle, smb_cfg_table[id].sc_pg);

	if (smb_smf_get_property(handle, smb_cfg_table[id].sc_type,
	    smb_cfg_table[id].sc_name, value,
	    sizeof (char) * MAX_VALUE_BUFLEN) != 0) {
		smb_smf_scf_fini(handle);
		free(value);
		return (NULL);
	}

	smb_smf_scf_fini(handle);
	return (value);
}

/*
 * smb_config_getenv_dec
 *
 * For protected property, the value obtained from SMF will be decoded.
 * The decoded property value will be returned.
 *
 * This function should only be called by smb_config_load to populate
 * the SMB config cache.
 */
static char *
smb_config_getenv_dec(smb_cfg_id_t id)
{
	smb_scfhandle_t *handle;
	char *value;
	char *dec;

	if ((value = malloc(MAX_VALUE_BUFLEN * sizeof (char))) == NULL)
		return (NULL);

	handle = smb_smf_scf_init(SMBD_FMRI_PREFIX);
	if (handle == NULL) {
		free(value);
		return (NULL);
	}

	(void) smb_smf_create_service_pgroup(handle, smb_cfg_table[id].sc_pg);

	if (smb_smf_get_property(handle, smb_cfg_table[id].sc_type,
	    smb_cfg_table[id].sc_name, value,
	    sizeof (char) * MAX_VALUE_BUFLEN) != 0) {
		smb_smf_scf_fini(handle);
		free(value);
		return (NULL);
	}
	smb_smf_scf_fini(handle);
	if (strcmp(smb_cfg_table[id].sc_pg, SMBD_PROTECTED_PG_NAME))
		return (value);

	if (!value)
		return (NULL);

	if (*value == '\0') {
		free(value);
		return (NULL);
	}

	dec = smb_base64_decode(value);
	free(value);
	return (dec);
}

static char *
smb_config_getenv_generic(char *name, char *svc_fmri_prefix, char *svc_propgrp)
{
	smb_scfhandle_t *handle;
	char *value;

	if ((value = malloc(MAX_VALUE_BUFLEN * sizeof (char))) == NULL)
		return (NULL);

	handle = smb_smf_scf_init(svc_fmri_prefix);
	if (handle == NULL) {
		free(value);
		return (NULL);
	}

	(void) smb_smf_create_service_pgroup(handle, svc_propgrp);

	if (smb_smf_get_string_property(handle, name, value,
	    sizeof (char) * MAX_VALUE_BUFLEN) != 0) {
		smb_smf_scf_fini(handle);
		free(value);
		return (NULL);
	}

	smb_smf_scf_fini(handle);
	return (value);

}

int
smb_config_setenv_generic(char *svc_fmri_prefix, char *svc_propgrp,
    char *name, char *value)
{
	smb_scfhandle_t *handle = NULL;
	int rc = 0;


	handle = smb_smf_scf_init(svc_fmri_prefix);
	if (handle == NULL) {
		return (1);
	}

	(void) smb_smf_create_service_pgroup(handle, svc_propgrp);

	if (smb_smf_start_transaction(handle) != SMBD_SMF_OK) {
		smb_smf_scf_fini(handle);
		return (1);
	}

	if (smb_smf_set_string_property(handle, name, value) != SMBD_SMF_OK)
		rc = 1;

	if (smb_smf_end_transaction(handle) != SMBD_SMF_OK)
		rc = 1;

	smb_smf_scf_fini(handle);
	return (rc);
}

/*
 * smb_config_setenv
 *
 * For protected properties, the value will be encoded using base64
 * algorithm. The encoded string will be stored in SMF.
 */
int
smb_config_setenv(smb_cfg_id_t id, char *value)
{
	smb_scfhandle_t *handle = NULL;
	char *enc = NULL;
	int is_protected = 0;

	if ((id >= SMB_CI_MAX) || (id < 0)) {
		return (1);
	}

	handle = smb_smf_scf_init(SMBD_FMRI_PREFIX);
	if (handle == NULL) {
		return (1);
	}

	(void) smb_smf_create_service_pgroup(handle, smb_cfg_table[id].sc_pg);

	if (smb_smf_start_transaction(handle) != SMBD_SMF_OK) {
		smb_smf_scf_fini(handle);
		return (1);
	}

	if (strcmp(smb_cfg_table[id].sc_pg, SMBD_PROTECTED_PG_NAME) == 0) {
		if ((value == NULL) || (*value == '\0')) {
			(void) smb_smf_end_transaction(handle);
			smb_smf_scf_fini(handle);
			return (1);
		}

		if ((enc = smb_base64_encode(value)) == NULL) {
			(void) smb_smf_end_transaction(handle);
			smb_smf_scf_fini(handle);
			return (1);
		}

		is_protected = 1;
	}

	if (smb_smf_set_property(handle, smb_cfg_table[id].sc_type,
	    smb_cfg_table[id].sc_name, is_protected ? enc : value)
	    != SMBD_SMF_OK) {
		if (enc)
			free(enc);
		(void) smb_smf_end_transaction(handle);
		smb_smf_scf_fini(handle);
		return (1);
	}

	if (enc)
		free(enc);

	if (smb_smf_end_transaction(handle) != SMBD_SMF_OK) {
		smb_smf_scf_fini(handle);
		return (1);
	}

	smb_smf_scf_fini(handle);
	return (0);
}

static void
smb_config_setenv_trans(smb_scfhandle_t *handle, int type,
    char *name, char *value)
{
	if (smb_smf_set_property(handle, type, name, value) != SMBD_SMF_OK) {
		syslog(LOG_ERR, "Failed to save service property %s", name);
	}
}

/*
 * smb_config_setenv_trans_protected
 *
 * This function should only be called to set protected properties
 * in SMF. The argument 'value' will be encoded using base64 algorithm.
 * The encoded string will be stored in SMF.
 */
static void
smb_config_setenv_trans_protected(smb_scfhandle_t *handle, char *name,
    char *value)
{
	char *enc;

	if ((value == NULL) || (*value == '\0'))
		return;

	if ((enc = smb_base64_encode(value)) == NULL)
		return;

	if (smb_smf_set_string_property(handle, name, enc) != SMBD_SMF_OK) {
		syslog(LOG_ERR, "Failed to save service protected property"
		    " %s", name);
	}

	free(enc);
}

int
smb_config_unsetenv(smb_cfg_id_t id)
{
	smb_scfhandle_t *handle = NULL;
	int ret = 1;

	handle = smb_smf_scf_init(SMBD_FMRI_PREFIX);
	if (handle == NULL) {
		return (ret);
	}

	(void) smb_smf_create_service_pgroup(handle, smb_cfg_table[id].sc_pg);
	if (smb_smf_start_transaction(handle) != SMBD_SMF_OK) {
		smb_smf_scf_fini(handle);
		return (ret);
	}
	ret = smb_smf_delete_property(handle, smb_cfg_table[id].sc_name);
	(void) smb_smf_end_transaction(handle);

	smb_smf_scf_fini(handle);
	return (ret);
}

static int
smb_config_unsetenv_trans(smb_scfhandle_t *handle, char *name)
{
	return (smb_smf_delete_property(handle, name));
}

/*
 * smb_config_load
 *
 * Loads all the CIFS configuration parameters and sets up the
 * config table.
 */
int
smb_config_load()
{
	smb_cfg_id_t id;
	smb_cfg_param_t *cfg;
	char *value;

	(void) rw_rdlock(&smb_cfg_rwlk);
	for (id = 0; id < SMB_CI_MAX; id++) {
		value = smb_config_getenv_dec(id);
		cfg = &smb_cfg_table[id];
		/*
		 * enval == 0 could mean two things, either the
		 * config param is not defined, or it has been
		 * removed. If the variable has already been defined
		 * and now enval is 0, it should be removed, otherwise
		 * we don't need to do anything in this case.
		 */
		if ((cfg->sc_flags & SMB_CF_DEFINED) || value) {
			if (smb_config_update(cfg, value) != 0) {
				(void) rw_unlock(&smb_cfg_rwlk);
				if (value)
					free(value);
				return (1);
			}
		}
		if (value) {
			free(value);
		}
	}

	(void) rw_unlock(&smb_cfg_rwlk);

	return (0);
}

/*
 * smb_config_get
 *
 * Returns value of the specified config param.
 * The return value is a string pointer to the locally
 * allocated memory if the config param is defined
 * otherwise it would be NULL.
 *
 * This function MUST be called after a smb_config_rd/wrlock
 * function. Caller MUST NOT modify the returned buffer directly.
 */
char *
smb_config_get(smb_cfg_id_t id)
{
	if (id < SMB_CI_MAX)
		return (smb_cfg_table[id].sc_value);

	return (0);
}

/*
 * smb_config_getstr
 *
 * Returns value of the specified config param.
 * The returned pointer never will be NULL if the given
 * 'id' is valid. If the config param is not defined its
 * default value will be returned.
 *
 * This function MUST be called after a smb_config_rd/wrlock
 * function. Caller MUST NOT modify the returned buffer directly.
 */
char *
smb_config_getstr(smb_cfg_id_t id)
{
	smb_cfg_param_t *cfg;

	if (id < SMB_CI_MAX) {
		cfg = &smb_cfg_table[id];
		if (cfg->sc_value)
			return (cfg->sc_value);
	}

	return (NULL);
}

/*
 * smb_config_getnum
 *
 * Returns the value of a numeric config param.
 * If the config param is not defined it'll return the
 * default value.
 *
 * This function MUST be called after a smb_config_rd/wrlock
 * function.
 */
uint32_t
smb_config_getnum(smb_cfg_id_t id)
{
	smb_cfg_param_t *cfg;
	char *strval = NULL;

	if (id < SMB_CI_MAX) {
		cfg = &smb_cfg_table[id];
		if (cfg->sc_value)
			strval = cfg->sc_value;

		if (strval)
			return (strtol(strval, 0, 10));
	}

	return (0);
}

/*
 * smb_config_getyorn
 *
 * Returns the value of a yes/no config param.
 * Returns 1 is config is set to "yes", otherwise 0.
 *
 * This function MUST be called after a smb_config_rd/wrlock
 * function.
 */
int
smb_config_getyorn(smb_cfg_id_t id)
{
	char *val;

	val = smb_config_get(id);
	if (val) {
		if (strcasecmp(val, "true") == 0)
			return (1);
	}

	return (0);
}

/*
 * smb_config_set
 *
 * Set/update the specified config param with the given
 * value. If the value is NULL the config param will be
 * unset as if it is not defined.
 *
 * This function MUST be called after a smb_config_wrlock
 * function.
 */
int
smb_config_set(smb_cfg_id_t id, char *value)
{
	smb_cfg_param_t *cfg;
	int rc = 0;

	if (id < SMB_CI_MAX) {
		cfg = &smb_cfg_table[id];
		rc = smb_config_update(cfg, value);
		if (rc == 0)
			cfg->sc_flags |= SMB_CF_MODIFIED;
		return (rc);
	}

	return (1);
}

/*
 * smb_config_setnum
 *
 * Set/update the specified config param with the given
 * value. This is used for numeric config params. The given
 * number will be converted to string before setting the
 * config param.
 *
 * This function MUST be called after a smb_config_wrlock
 * function.
 */
int
smb_config_setnum(smb_cfg_id_t id, uint32_t num)
{
	smb_cfg_param_t *cfg;
	char value[32];
	int rc = 0;

	if (id < SMB_CI_MAX) {
		cfg = &smb_cfg_table[id];
		(void) snprintf(value, sizeof (value), "%u", num);
		rc = smb_config_update(cfg, value);
		if (rc == 0)
			cfg->sc_flags |= SMB_CF_MODIFIED;
		return (rc);
	}

	return (1);
}

/*
 * smb_config_rdlock
 *
 * Lock the config table for read access.
 * This function MUST be called before any kind of
 * read access to the config table i.e. all flavors of
 * smb_config_get function
 */
void
smb_config_rdlock()
{
	(void) rw_rdlock(&smb_cfg_rwlk);
	lock_type = SMB_CL_READ;
}

/*
 * smb_config_wrlock
 *
 * Lock the config table for write access.
 * This function MUST be called before any kind of
 * write access to the config table i.e. all flavors of
 * smb_config_set function
 */
void
smb_config_wrlock()
{
	(void) rw_wrlock(&smb_cfg_rwlk);
	lock_type = SMB_CL_WRITE;
}

/*
 * smb_config_wrlock
 *
 * Unlock the config table.
 * If the config table has been locked for write access
 * smb_config_save_all() will be called to save the changes
 * before unlocking the table.
 *
 * This function MUST be called after smb_config_rd/wrlock
 */
void
smb_config_unlock()
{
	if (lock_type == SMB_CL_WRITE)
		(void) smb_config_save_all();
	(void) rw_unlock(&smb_cfg_rwlk);
}

/*
 * smb_config_save_all
 *
 * Save all modified parameters to SMF.
 */
static int
smb_config_save_all()
{
	int rc;

	if ((rc = smb_config_save(SMBD_PG_NAME)) != 0)
		return (rc);

	return (smb_config_save(SMBD_PROTECTED_PG_NAME));
}

/*
 * smb_config_save
 *
 * Scan the config table and call smb_config_setenv/smb_config_unsetenv
 * for params in the specified property group that has been modified.
 * When the scan is finished, smb_config_saveenv() will be called to
 * make the changes persistent.
 */
static int
smb_config_save(char *pgname)
{
	smb_cfg_id_t id;
	smb_cfg_param_t *cfg;
	smb_scfhandle_t *handle = NULL;
	int dorefresh = 0;

	handle = smb_smf_scf_init(SMBD_FMRI_PREFIX);
	if (handle == NULL) {
		syslog(LOG_ERR, "smbd: cannot save configuration");
		return (1);
	}

	(void) smb_smf_create_service_pgroup(handle, pgname);
	if (smb_smf_start_transaction(handle) != SMBD_SMF_OK) {
		syslog(LOG_ERR, "smbd: cannot save configuration");
		return (1);
	}

	for (id = 0; id < SMB_CI_MAX; id++) {
		cfg = &smb_cfg_table[id];
		if (strcmp(cfg->sc_pg, pgname))
			continue;

		if (cfg->sc_flags & SMB_CF_MODIFIED) {
			if (cfg->sc_value) {
				if (strcmp(pgname, SMBD_PG_NAME) == 0)
					smb_config_setenv_trans(handle,
					    cfg->sc_type, cfg->sc_name,
					    cfg->sc_value);
				else
					smb_config_setenv_trans_protected(
					    handle, cfg->sc_name,
					    cfg->sc_value);
			} else {
				(void) smb_config_unsetenv_trans(handle,
				    cfg->sc_name);
			}
			cfg->sc_flags &= ~SMB_CF_MODIFIED;
			dorefresh = 1;
		}
	}

	if (smb_config_saveenv(handle) != 0) {
		syslog(LOG_ERR, "smbd: cannot save configuration");
		return (1);
	}
	if (dorefresh)
		(void) smf_refresh_instance(SMBD_DEFAULT_INSTANCE_FMRI);
	return (0);
}

/*
 * smb_config_update
 *
 * Updates the specified config param with the given value.
 * This function is called both on (re)load and set.
 */
static int
smb_config_update(smb_cfg_param_t *cfg, char *value)
{
	char *curval;
	int rc = 0;
	int len;

	if (value) {
		len = strlen(value);
		if (cfg->sc_value) {
			curval = (char *)realloc(cfg->sc_value,
			    (len + 1));
		} else {
			curval = (char *)malloc(len + 1);
		}

		if (curval) {
			cfg->sc_value = curval;
			(void) strcpy(cfg->sc_value, value);
			cfg->sc_flags |= SMB_CF_DEFINED;
		} else {
			rc = 1;
		}
	} else if (cfg->sc_value) {
		free(cfg->sc_value);
		cfg->sc_value = NULL;
		cfg->sc_flags &= ~SMB_CF_DEFINED;
	}

	return (rc);
}

uint8_t
smb_config_get_fg_flag()
{
	uint8_t run_fg = 0; /* Default is to run in daemon mode */
	smb_scfhandle_t *handle = NULL;

	handle = smb_smf_scf_init(SMBD_FMRI_PREFIX);
	if (handle == NULL) {
		return (run_fg);
	}

	if (smb_smf_create_service_pgroup(handle,
	    SMBD_PG_NAME) != SMBD_SMF_OK) {
		smb_smf_scf_fini(handle);
		return (run_fg);
	}

	if (smb_smf_get_boolean_property(handle, "run_fg", &run_fg) != 0) {
		smb_smf_scf_fini(handle);
		return (run_fg);
	}

	smb_smf_scf_fini(handle);

	return (run_fg);
}

/*
 * smb_config_get_localsid
 *
 * Returns value of the "config/machine_sid" parameter
 * from the IDMAP SMF configuration repository.
 *
 */
char *
smb_config_get_localsid(void)
{
	return (smb_config_getenv_generic(MACHINE_SID, IDMAP_FMRI_PREFIX,
	    IDMAP_PG_NAME));
}

/*
 * smb_config_set_idmap_domain
 *
 * Set the "config/domain_name" parameter from IDMAP SMF repository.
 */
int
smb_config_set_idmap_domain(char *value)
{
	return (smb_config_setenv_generic(IDMAP_FMRI_PREFIX, IDMAP_PG_NAME,
	    IDMAP_DOMAIN, value));
}

/*
 * smb_config_refresh_idmap
 *
 * Refresh IDMAP SMF service after making changes to its configuration.
 */
int
smb_config_refresh_idmap(void)
{
	char instance[32];

	(void) snprintf(instance, sizeof (instance), "%s:default",
	    IDMAP_FMRI_PREFIX);
	return (smf_refresh_instance(instance));
}

/*
 * smb_config_refresh
 *
 * Refresh SMB SMF service.
 */
int
smb_config_refresh(void)
{
	return (smf_refresh_instance(SMBD_DEFAULT_INSTANCE_FMRI));
}

int
smb_config_secmode_fromstr(char *secmode)
{
	if (secmode == NULL)
		return (SMB_SECMODE_WORKGRP);

	if (strcasecmp(secmode, SMB_SECMODE_DOMAIN_STR) == 0)
		return (SMB_SECMODE_DOMAIN);

	return (SMB_SECMODE_WORKGRP);
}

char *
smb_config_secmode_tostr(int secmode)
{
	if (secmode == SMB_SECMODE_DOMAIN)
		return (SMB_SECMODE_DOMAIN_STR);

	return (SMB_SECMODE_WORKGRP_STR);
}

int
smb_config_get_secmode()
{
	char *p;

	p = smb_config_getstr(SMB_CI_SECURITY);
	return (smb_config_secmode_fromstr(p));
}

int
smb_config_set_secmode(int secmode)
{
	char *p;

	p = smb_config_secmode_tostr(secmode);
	return (smb_config_set(SMB_CI_SECURITY, p));
}
