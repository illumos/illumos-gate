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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

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
#include <assert.h>
#include <uuid/uuid.h>
#include <smbsrv/libsmb.h>

typedef struct smb_cfg_param {
	smb_cfg_id_t sc_id;
	char *sc_name;
	int sc_type;
	uint32_t sc_flags;
} smb_cfg_param_t;

/*
 * config parameter flags
 */
#define	SMB_CF_PROTECTED	0x01
#define	SMB_CF_EXEC		0x02

/* idmap SMF fmri and Property Group */
#define	IDMAP_FMRI_PREFIX		"system/idmap"
#define	MACHINE_SID			"machine_sid"
#define	MACHINE_UUID			"machine_uuid"
#define	IDMAP_DOMAIN			"domain_name"
#define	IDMAP_PG_NAME			"config"

#define	SMB_SECMODE_WORKGRP_STR 	"workgroup"
#define	SMB_SECMODE_DOMAIN_STR  	"domain"

#define	SMB_ENC_LEN	1024
#define	SMB_DEC_LEN	256

static char *b64_data =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static smb_cfg_param_t smb_cfg_table[] =
{
	{SMB_CI_VERSION, "sv_version", SCF_TYPE_ASTRING, 0},

	/* Oplock configuration, Kernel Only */
	{SMB_CI_OPLOCK_ENABLE, "oplock_enable", SCF_TYPE_BOOLEAN, 0},

	/* Autohome configuration */
	{SMB_CI_AUTOHOME_MAP, "autohome_map", SCF_TYPE_ASTRING, 0},

	/* Domain/PDC configuration */
	{SMB_CI_DOMAIN_SID, "domain_sid", SCF_TYPE_ASTRING, 0},
	{SMB_CI_DOMAIN_MEMB, "domain_member", SCF_TYPE_BOOLEAN, 0},
	{SMB_CI_DOMAIN_NAME, "domain_name", SCF_TYPE_ASTRING, 0},
	{SMB_CI_DOMAIN_FQDN, "fqdn", SCF_TYPE_ASTRING, 0},
	{SMB_CI_DOMAIN_FOREST, "forest", SCF_TYPE_ASTRING, 0},
	{SMB_CI_DOMAIN_GUID, "domain_guid", SCF_TYPE_ASTRING, 0},
	{SMB_CI_DOMAIN_SRV, "pdc", SCF_TYPE_ASTRING, 0},

	/* WINS configuration */
	{SMB_CI_WINS_SRV1, "wins_server_1", SCF_TYPE_ASTRING, 0},
	{SMB_CI_WINS_SRV2, "wins_server_2", SCF_TYPE_ASTRING, 0},
	{SMB_CI_WINS_EXCL, "wins_exclude", SCF_TYPE_ASTRING, 0},

	/* Kmod specific configuration */
	{SMB_CI_MAX_WORKERS, "max_workers", SCF_TYPE_INTEGER, 0},
	{SMB_CI_MAX_CONNECTIONS, "max_connections", SCF_TYPE_INTEGER, 0},
	{SMB_CI_KEEPALIVE, "keep_alive", SCF_TYPE_INTEGER, 0},
	{SMB_CI_RESTRICT_ANON, "restrict_anonymous", SCF_TYPE_BOOLEAN, 0},

	{SMB_CI_SIGNING_ENABLE, "signing_enabled", SCF_TYPE_BOOLEAN, 0},
	{SMB_CI_SIGNING_REQD, "signing_required", SCF_TYPE_BOOLEAN, 0},

	/* Kmod tuning configuration */
	{SMB_CI_SYNC_ENABLE, "sync_enable", SCF_TYPE_BOOLEAN, 0},

	/* SMBd configuration */
	{SMB_CI_SECURITY, "security", SCF_TYPE_ASTRING, 0},
	{SMB_CI_NETBIOS_ENABLE, "netbios_enable", SCF_TYPE_BOOLEAN, 0},
	{SMB_CI_NBSCOPE, "netbios_scope", SCF_TYPE_ASTRING, 0},
	{SMB_CI_SYS_CMNT, "system_comment", SCF_TYPE_ASTRING, 0},
	{SMB_CI_LM_LEVEL, "lmauth_level", SCF_TYPE_INTEGER, 0},

	/* ADS Configuration */
	{SMB_CI_ADS_SITE, "ads_site", SCF_TYPE_ASTRING, 0},

	/* Dynamic DNS */
	{SMB_CI_DYNDNS_ENABLE, "ddns_enable", SCF_TYPE_BOOLEAN, 0},

	{SMB_CI_MACHINE_PASSWD, "machine_passwd", SCF_TYPE_ASTRING,
	    SMB_CF_PROTECTED},

	{SMB_CI_MACHINE_UUID, "machine_uuid", SCF_TYPE_ASTRING, 0},
	{SMB_CI_KPASSWD_SRV, "kpasswd_server", SCF_TYPE_ASTRING, 0},
	{SMB_CI_KPASSWD_DOMAIN, "kpasswd_domain", SCF_TYPE_ASTRING, 0},
	{SMB_CI_KPASSWD_SEQNUM, "kpasswd_seqnum", SCF_TYPE_INTEGER, 0},
	{SMB_CI_NETLOGON_SEQNUM, "netlogon_seqnum", SCF_TYPE_INTEGER, 0},
	{SMB_CI_IPV6_ENABLE, "ipv6_enable", SCF_TYPE_BOOLEAN, 0},
	{SMB_CI_PRINT_ENABLE, "print_enable", SCF_TYPE_BOOLEAN, 0},
	{SMB_CI_MAP, "map", SCF_TYPE_ASTRING, SMB_CF_EXEC},
	{SMB_CI_UNMAP, "unmap", SCF_TYPE_ASTRING, SMB_CF_EXEC},
	{SMB_CI_DISPOSITION, "disposition", SCF_TYPE_ASTRING, SMB_CF_EXEC},
	{SMB_CI_DFS_STDROOT_NUM, "dfs_stdroot_num", SCF_TYPE_INTEGER, 0},
	{SMB_CI_TRAVERSE_MOUNTS, "traverse_mounts", SCF_TYPE_BOOLEAN, 0},

	/* SMB_CI_MAX */
};

static smb_cfg_param_t *smb_config_getent(smb_cfg_id_t);

static boolean_t smb_is_base64(unsigned char c);
static char *smb_base64_encode(char *str_to_encode);
static char *smb_base64_decode(char *encoded_str);

char *
smb_config_getname(smb_cfg_id_t id)
{
	smb_cfg_param_t *cfg;
	cfg = smb_config_getent(id);
	return (cfg->sc_name);
}

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

static int
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
 * smb_config_getstr
 *
 * Fetch the specified string configuration item from SMF
 */
int
smb_config_getstr(smb_cfg_id_t id, char *cbuf, int bufsz)
{
	smb_scfhandle_t *handle;
	smb_cfg_param_t *cfg;
	int rc = SMBD_SMF_OK;
	char *pg;
	char protbuf[SMB_ENC_LEN];
	char *tmp;

	*cbuf = '\0';
	cfg = smb_config_getent(id);
	assert(cfg->sc_type == SCF_TYPE_ASTRING);

	handle = smb_smf_scf_init(SMBD_FMRI_PREFIX);
	if (handle == NULL)
		return (SMBD_SMF_SYSTEM_ERR);

	if (cfg->sc_flags & SMB_CF_PROTECTED) {
		if ((rc = smb_smf_create_service_pgroup(handle,
		    SMBD_PROTECTED_PG_NAME)) != SMBD_SMF_OK)
			goto error;

		if ((rc = smb_smf_get_string_property(handle, cfg->sc_name,
		    protbuf, sizeof (protbuf))) != SMBD_SMF_OK)
			goto error;

		if (*protbuf != '\0') {
			tmp = smb_base64_decode(protbuf);
			(void) strlcpy(cbuf, tmp, bufsz);
			free(tmp);
		}
	} else {
		pg = (cfg->sc_flags & SMB_CF_EXEC) ? SMBD_EXEC_PG_NAME :
		    SMBD_PG_NAME;
		rc = smb_smf_create_service_pgroup(handle, pg);
		if (rc == SMBD_SMF_OK)
			rc = smb_smf_get_string_property(handle, cfg->sc_name,
			    cbuf, bufsz);
	}

error:
	smb_smf_scf_fini(handle);
	return (rc);
}

/*
 * Translate the value of an astring SMF property into a binary
 * IP address. If the value is neither a valid IPv4 nor IPv6
 * address, attempt to look it up as a hostname using the
 * configured address type.
 */
int
smb_config_getip(smb_cfg_id_t sc_id, smb_inaddr_t *ipaddr)
{
	int rc, error;
	int a_family;
	char ipstr[MAXHOSTNAMELEN];
	struct hostent *h;
	smb_cfg_param_t *cfg;

	if (ipaddr == NULL)
		return (SMBD_SMF_INVALID_ARG);

	bzero(ipaddr, sizeof (smb_inaddr_t));
	rc = smb_config_getstr(sc_id, ipstr, sizeof (ipstr));
	if (rc == SMBD_SMF_OK) {
		if (*ipstr == '\0')
			return (SMBD_SMF_INVALID_ARG);

		if (inet_pton(AF_INET, ipstr, &ipaddr->a_ipv4) == 1) {
			ipaddr->a_family = AF_INET;
			return (SMBD_SMF_OK);
		}

		if (inet_pton(AF_INET6, ipstr, &ipaddr->a_ipv6) == 1) {
			ipaddr->a_family = AF_INET6;
			return (SMBD_SMF_OK);
		}

		/*
		 * The value is neither an IPv4 nor IPv6 address;
		 * so check if it's a hostname.
		 */
		a_family = smb_config_getbool(SMB_CI_IPV6_ENABLE) ?
		    AF_INET6 : AF_INET;
		h = getipnodebyname(ipstr, a_family, AI_DEFAULT,
		    &error);
		if (h != NULL) {
			bcopy(*(h->h_addr_list), &ipaddr->a_ip,
			    h->h_length);
			ipaddr->a_family = a_family;
			freehostent(h);
			rc = SMBD_SMF_OK;
		} else {
			cfg = smb_config_getent(sc_id);
			syslog(LOG_ERR, "smbd/%s: %s unable to get %s "
			    "address: %d", cfg->sc_name, ipstr,
			    a_family == AF_INET ?  "IPv4" : "IPv6", error);
			rc = SMBD_SMF_INVALID_ARG;
		}
	}

	return (rc);
}

/*
 * smb_config_getnum
 *
 * Returns the value of a numeric config param.
 */
int
smb_config_getnum(smb_cfg_id_t id, int64_t *cint)
{
	smb_scfhandle_t *handle;
	smb_cfg_param_t *cfg;
	int rc = SMBD_SMF_OK;

	*cint = 0;
	cfg = smb_config_getent(id);
	assert(cfg->sc_type == SCF_TYPE_INTEGER);

	handle = smb_smf_scf_init(SMBD_FMRI_PREFIX);
	if (handle == NULL)
		return (SMBD_SMF_SYSTEM_ERR);

	rc = smb_smf_create_service_pgroup(handle, SMBD_PG_NAME);
	if (rc == SMBD_SMF_OK)
		rc = smb_smf_get_integer_property(handle, cfg->sc_name, cint);
	smb_smf_scf_fini(handle);

	return (rc);
}

/*
 * smb_config_getbool
 *
 * Returns the value of a boolean config param.
 */
boolean_t
smb_config_getbool(smb_cfg_id_t id)
{
	smb_scfhandle_t *handle;
	smb_cfg_param_t *cfg;
	int rc = SMBD_SMF_OK;
	uint8_t vbool;

	cfg = smb_config_getent(id);
	assert(cfg->sc_type == SCF_TYPE_BOOLEAN);

	handle = smb_smf_scf_init(SMBD_FMRI_PREFIX);
	if (handle == NULL)
		return (B_FALSE);

	rc = smb_smf_create_service_pgroup(handle, SMBD_PG_NAME);
	if (rc == SMBD_SMF_OK)
		rc = smb_smf_get_boolean_property(handle, cfg->sc_name, &vbool);
	smb_smf_scf_fini(handle);

	return ((rc == SMBD_SMF_OK) ? (vbool == 1) : B_FALSE);
}

/*
 * smb_config_get
 *
 * This function returns the value of the requested config
 * iterm regardless of its type in string format. This should
 * be used when the config item type is not known by the caller.
 */
int
smb_config_get(smb_cfg_id_t id, char *cbuf, int bufsz)
{
	smb_cfg_param_t *cfg;
	int64_t cint;
	int rc;

	cfg = smb_config_getent(id);
	switch (cfg->sc_type) {
	case SCF_TYPE_ASTRING:
		return (smb_config_getstr(id, cbuf, bufsz));

	case SCF_TYPE_INTEGER:
		rc = smb_config_getnum(id, &cint);
		if (rc == SMBD_SMF_OK)
			(void) snprintf(cbuf, bufsz, "%lld", cint);
		return (rc);

	case SCF_TYPE_BOOLEAN:
		if (smb_config_getbool(id))
			(void) strlcpy(cbuf, "true", bufsz);
		else
			(void) strlcpy(cbuf, "false", bufsz);
		return (SMBD_SMF_OK);
	}

	return (SMBD_SMF_INVALID_ARG);
}

/*
 * smb_config_setstr
 *
 * Set the specified config param with the given
 * value.
 */
int
smb_config_setstr(smb_cfg_id_t id, char *value)
{
	smb_scfhandle_t *handle;
	smb_cfg_param_t *cfg;
	int rc = SMBD_SMF_OK;
	boolean_t protected;
	char *tmp = NULL;
	char *pg;

	cfg = smb_config_getent(id);
	assert(cfg->sc_type == SCF_TYPE_ASTRING);

	protected = B_FALSE;

	switch (cfg->sc_flags) {
	case SMB_CF_PROTECTED:
		protected = B_TRUE;
		pg = SMBD_PROTECTED_PG_NAME;
		break;
	case SMB_CF_EXEC:
		pg = SMBD_EXEC_PG_NAME;
		break;
	default:
		pg = SMBD_PG_NAME;
		break;
	}

	handle = smb_smf_scf_init(SMBD_FMRI_PREFIX);
	if (handle == NULL)
		return (SMBD_SMF_SYSTEM_ERR);

	rc = smb_smf_create_service_pgroup(handle, pg);
	if (rc == SMBD_SMF_OK)
		rc = smb_smf_start_transaction(handle);

	if (rc != SMBD_SMF_OK) {
		smb_smf_scf_fini(handle);
		return (rc);
	}

	if (protected && value && (*value != '\0')) {
		if ((tmp = smb_base64_encode(value)) == NULL) {
			(void) smb_smf_end_transaction(handle);
			smb_smf_scf_fini(handle);
			return (SMBD_SMF_NO_MEMORY);
		}

		value = tmp;
	}

	rc = smb_smf_set_string_property(handle, cfg->sc_name, value);

	free(tmp);
	(void) smb_smf_end_transaction(handle);
	smb_smf_scf_fini(handle);
	return (rc);
}

/*
 * smb_config_setnum
 *
 * Sets a numeric configuration iterm
 */
int
smb_config_setnum(smb_cfg_id_t id, int64_t value)
{
	smb_scfhandle_t *handle;
	smb_cfg_param_t *cfg;
	int rc = SMBD_SMF_OK;

	cfg = smb_config_getent(id);
	assert(cfg->sc_type == SCF_TYPE_INTEGER);

	handle = smb_smf_scf_init(SMBD_FMRI_PREFIX);
	if (handle == NULL)
		return (SMBD_SMF_SYSTEM_ERR);

	rc = smb_smf_create_service_pgroup(handle, SMBD_PG_NAME);
	if (rc == SMBD_SMF_OK)
		rc = smb_smf_start_transaction(handle);

	if (rc != SMBD_SMF_OK) {
		smb_smf_scf_fini(handle);
		return (rc);
	}

	rc = smb_smf_set_integer_property(handle, cfg->sc_name, value);

	(void) smb_smf_end_transaction(handle);
	smb_smf_scf_fini(handle);
	return (rc);
}

/*
 * smb_config_setbool
 *
 * Sets a boolean configuration iterm
 */
int
smb_config_setbool(smb_cfg_id_t id, boolean_t value)
{
	smb_scfhandle_t *handle;
	smb_cfg_param_t *cfg;
	int rc = SMBD_SMF_OK;

	cfg = smb_config_getent(id);
	assert(cfg->sc_type == SCF_TYPE_BOOLEAN);

	handle = smb_smf_scf_init(SMBD_FMRI_PREFIX);
	if (handle == NULL)
		return (SMBD_SMF_SYSTEM_ERR);

	rc = smb_smf_create_service_pgroup(handle, SMBD_PG_NAME);
	if (rc == SMBD_SMF_OK)
		rc = smb_smf_start_transaction(handle);

	if (rc != SMBD_SMF_OK) {
		smb_smf_scf_fini(handle);
		return (rc);
	}

	rc = smb_smf_set_boolean_property(handle, cfg->sc_name, value);

	(void) smb_smf_end_transaction(handle);
	smb_smf_scf_fini(handle);
	return (rc);
}

/*
 * smb_config_set
 *
 * This function sets the value of the specified config
 * iterm regardless of its type in string format. This should
 * be used when the config item type is not known by the caller.
 */
int
smb_config_set(smb_cfg_id_t id, char *value)
{
	smb_cfg_param_t *cfg;
	int64_t cint;

	cfg = smb_config_getent(id);
	switch (cfg->sc_type) {
	case SCF_TYPE_ASTRING:
		return (smb_config_setstr(id, value));

	case SCF_TYPE_INTEGER:
		cint = atoi(value);
		return (smb_config_setnum(id, cint));

	case SCF_TYPE_BOOLEAN:
		return (smb_config_setbool(id, strcasecmp(value, "true") == 0));
	}

	return (SMBD_SMF_INVALID_ARG);
}

int
smb_config_get_debug()
{
	int64_t val64;
	int val = 0;	/* default */
	smb_scfhandle_t *handle = NULL;

	handle = smb_smf_scf_init(SMBD_FMRI_PREFIX);
	if (handle == NULL) {
		return (val);
	}

	if (smb_smf_create_service_pgroup(handle,
	    SMBD_PG_NAME) != SMBD_SMF_OK) {
		smb_smf_scf_fini(handle);
		return (val);
	}

	if (smb_smf_get_integer_property(handle, "debug", &val64) != 0) {
		smb_smf_scf_fini(handle);
		return (val);
	}
	val = (int)val64;

	smb_smf_scf_fini(handle);

	return (val);
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
 * smb_config_get_ads_enable
 *
 * Returns value of the "config/use_ads" parameter
 * from the IDMAP SMF configuration repository.
 *
 */
boolean_t
smb_config_get_ads_enable(void)
{
	smb_scfhandle_t *handle = NULL;
	uint8_t vbool;
	int rc = 0;

	handle = smb_smf_scf_init(IDMAP_FMRI_PREFIX);
	if (handle == NULL)
		return (B_FALSE);

	rc = smb_smf_create_service_pgroup(handle, IDMAP_PG_NAME);
	if (rc == SMBD_SMF_OK)
		rc = smb_smf_get_boolean_property(handle, "use_ads", &vbool);
	smb_smf_scf_fini(handle);

	return ((rc == SMBD_SMF_OK) ? (vbool == 1) : B_FALSE);
}

/*
 * smb_config_get_localsid
 *
 * Returns value of the "config/machine_sid" parameter
 * from the IDMAP SMF configuration repository.
 * Result is allocated; caller should free.
 */
char *
smb_config_get_localsid(void)
{
	return (smb_config_getenv_generic(MACHINE_SID, IDMAP_FMRI_PREFIX,
	    IDMAP_PG_NAME));
}

/*
 * smb_config_get_localuuid
 *
 * Returns value of the "config/machine_uuid" parameter
 * from the IDMAP SMF configuration repository.
 *
 */
int
smb_config_get_localuuid(uuid_t uu)
{
	char *s;

	uuid_clear(uu);
	s = smb_config_getenv_generic(MACHINE_UUID, IDMAP_FMRI_PREFIX,
	    IDMAP_PG_NAME);
	if (s == NULL)
		return (-1);

	if (uuid_parse(s, uu) < 0) {
		free(s);
		return (-1);
	}

	return (0);
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
	char p[16];

	(void) smb_config_getstr(SMB_CI_SECURITY, p, sizeof (p));
	return (smb_config_secmode_fromstr(p));
}

int
smb_config_set_secmode(int secmode)
{
	char *p;

	p = smb_config_secmode_tostr(secmode);
	return (smb_config_setstr(SMB_CI_SECURITY, p));
}

void
smb_config_getdomaininfo(char *domain, char *fqdn, char *sid, char *forest,
    char *guid)
{
	if (domain)
		(void) smb_config_getstr(SMB_CI_DOMAIN_NAME, domain,
		    NETBIOS_NAME_SZ);

	if (fqdn)
		(void) smb_config_getstr(SMB_CI_DOMAIN_FQDN, fqdn,
		    MAXHOSTNAMELEN);

	if (sid)
		(void) smb_config_getstr(SMB_CI_DOMAIN_SID, sid,
		    SMB_SID_STRSZ);

	if (forest)
		(void) smb_config_getstr(SMB_CI_DOMAIN_FOREST, forest,
		    MAXHOSTNAMELEN);

	if (guid)
		(void) smb_config_getstr(SMB_CI_DOMAIN_GUID, guid,
		    UUID_PRINTABLE_STRING_LENGTH);
}

void
smb_config_setdomaininfo(char *domain, char *fqdn, char *sid, char *forest,
    char *guid)
{
	if (domain)
		(void) smb_config_setstr(SMB_CI_DOMAIN_NAME, domain);
	if (fqdn)
		(void) smb_config_setstr(SMB_CI_DOMAIN_FQDN, fqdn);
	if (sid)
		(void) smb_config_setstr(SMB_CI_DOMAIN_SID, sid);
	if (forest)
		(void) smb_config_setstr(SMB_CI_DOMAIN_FOREST, forest);
	if (guid)
		(void) smb_config_setstr(SMB_CI_DOMAIN_GUID, guid);
}

/*
 * The version stored in SMF in string format as N.N where
 * N is a number defined by Microsoft. The first number represents
 * the major version and the second number is the minor version.
 * Current defined values can be found here in 'ver_table'.
 *
 * This function reads the SMF string value and converts it to
 * two numbers returned in the given 'version' structure.
 * Current default version number is 5.0 which is for Windows 2000.
 */
void
smb_config_get_version(smb_version_t *version)
{
	smb_version_t tmpver;
	char verstr[SMB_VERSTR_LEN];
	char *p;
	int rc, i;
	static smb_version_t ver_table [] = {
		{ 0, SMB_MAJOR_NT,	SMB_MINOR_NT,		1381,	0 },
		{ 0, SMB_MAJOR_2000,	SMB_MINOR_2000,		2195,	0 },
		{ 0, SMB_MAJOR_XP,	SMB_MINOR_XP,		2196,	0 },
		{ 0, SMB_MAJOR_2003,	SMB_MINOR_2003,		2196,	0 },
		{ 0, SMB_MAJOR_VISTA,	SMB_MINOR_VISTA,	6000,	0 },
		{ 0, SMB_MAJOR_2008,	SMB_MINOR_2008,		6000,	0 },
		{ 0, SMB_MAJOR_2008R2,	SMB_MINOR_2008R2,	7007,	0 },
		{ 0, SMB_MAJOR_7,	SMB_MINOR_7,		7007,	0 }
	};

	*version = ver_table[1];
	version->sv_size = sizeof (smb_version_t);

	rc = smb_config_getstr(SMB_CI_VERSION, verstr, sizeof (verstr));
	if (rc != SMBD_SMF_OK)
		return;

	if ((p = strchr(verstr, '.')) == NULL)
		return;

	*p = '\0';
	tmpver.sv_major = (uint8_t)atoi(verstr);
	tmpver.sv_minor = (uint8_t)atoi(p + 1);

	for (i = 0; i < sizeof (ver_table)/sizeof (ver_table[0]); ++i) {
		if ((tmpver.sv_major == ver_table[i].sv_major) &&
		    (tmpver.sv_minor == ver_table[i].sv_minor)) {
			*version = ver_table[i];
			version->sv_size = sizeof (smb_version_t);
			break;
		}
	}
}

/*
 * Reads share exec script properties
 */
uint32_t
smb_config_get_execinfo(char *map, char *unmap, size_t bufsz)
{
	char buf[MAXPATHLEN];
	uint32_t flags = 0;

	if (map == NULL) {
		map = buf;
		bufsz = MAXPATHLEN;
	}

	*map = '\0';
	(void) smb_config_getstr(SMB_CI_MAP, map, bufsz);
	if (*map != '\0')
		flags |= SMB_EXEC_MAP;

	if (unmap == NULL) {
		unmap = buf;
		bufsz = MAXPATHLEN;
	}

	*unmap = '\0';
	(void) smb_config_getstr(SMB_CI_UNMAP, unmap, bufsz);
	if (*unmap != '\0')
		flags |= SMB_EXEC_UNMAP;

	*buf = '\0';
	(void) smb_config_getstr(SMB_CI_DISPOSITION, buf, sizeof (buf));
	if (*buf != '\0')
		if (strcasecmp(buf, SMB_EXEC_DISP_TERMINATE) == 0)
			flags |= SMB_EXEC_TERM;

	return (flags);
}

static smb_cfg_param_t *
smb_config_getent(smb_cfg_id_t id)
{
	int i;

	for (i = 0; i < SMB_CI_MAX; i++)
		if (smb_cfg_table[i].sc_id == id)
			return (&smb_cfg_table[id]);

	assert(0);
	return (NULL);
}
