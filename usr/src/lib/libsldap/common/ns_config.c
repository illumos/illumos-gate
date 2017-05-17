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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * libsldap - library side configuration components
 * Routines to manage the config structure
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <libintl.h>
#include <locale.h>
#include <thread.h>
#include <synch.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <crypt.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/systeminfo.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <limits.h>
#include "ns_sldap.h"
#include "ns_internal.h"
#include "ns_cache_door.h"
#include "ns_connmgmt.h"

#pragma fini(__s_api_shutdown_conn_mgmt, \
	_free_config, __ns_ldap_doorfd_close)

static mutex_t		ns_parse_lock = DEFAULTMUTEX;
static mutex_t		ns_loadrefresh_lock = DEFAULTMUTEX;
static ns_config_t	*current_config = NULL;

static int		cache_server = FALSE;
extern thread_key_t	ns_cmgkey;

/*
 * Parameter Index Type validation routines
 */
static int
__s_val_postime(ParamIndexType i, ns_default_config *def,
    ns_param_t *param, char *errbuf);
static int
__s_val_basedn(ParamIndexType i, ns_default_config *def,
    ns_param_t *param, char *errbuf);

static int
__s_val_binddn(ParamIndexType i, ns_default_config *def,
    ns_param_t *param, char *errbuf);

static int
__s_val_bindpw(ParamIndexType i, ns_default_config *def,
    ns_param_t *param, char *errbuf);

static int
__s_val_serverList(ParamIndexType i, ns_default_config *def,
    ns_param_t *param, char *errbuf);

/*
 * Forward declarations
 */

static ns_parse_status
verify_value(ns_config_t *cfg, char *name, char *value, char *errstr);

static int
set_default_value(ns_config_t *configptr, char *name, char *value,
    ns_ldap_error_t **error);

static void
set_curr_config(ns_config_t *ptr);

static int
__door_getldapconfig(char **buffer, int *buflen, ns_ldap_error_t **error);

static ns_config_t *
SetDoorInfo(char *buffer, ns_ldap_error_t **errorp);

static boolean_t
timetorefresh(ns_config_t *cfg);

static ns_config_t *
LoadCacheConfiguration(ns_config_t *, ns_ldap_error_t **error);

static void **
dupParam(ns_param_t *ptr);

static time_t
conv_time(char *s);

/*
 * Structures used in enum <-> string mapping routines
 */

static ns_enum_map ns_auth_enum_v1[] = {
	{ ENUM2INT(NS_LDAP_EA_NONE), "NS_LDAP_AUTH_NONE" },
	{ ENUM2INT(NS_LDAP_EA_SIMPLE), "NS_LDAP_AUTH_SIMPLE" },
	{ ENUM2INT(NS_LDAP_EA_SASL_CRAM_MD5), "NS_LDAP_AUTH_SASL_CRAM_MD5" },
	{ -1, NULL },
};

static ns_enum_map ns_auth_enum_v2[] = {
	{ ENUM2INT(NS_LDAP_EA_NONE), "none" },
	{ ENUM2INT(NS_LDAP_EA_SIMPLE), "simple" },
	{ ENUM2INT(NS_LDAP_EA_SASL_CRAM_MD5), "sasl/CRAM-MD5" },
	{ ENUM2INT(NS_LDAP_EA_SASL_DIGEST_MD5), "sasl/DIGEST-MD5" },
	{ ENUM2INT(NS_LDAP_EA_SASL_DIGEST_MD5_INT),
			"sasl/DIGEST-MD5:auth-int" },
	{ ENUM2INT(NS_LDAP_EA_SASL_DIGEST_MD5_CONF),
			"sasl/DIGEST-MD5:auth-conf" },
	{ ENUM2INT(NS_LDAP_EA_SASL_EXTERNAL), "sasl/EXTERNAL" },
	{ ENUM2INT(NS_LDAP_EA_SASL_GSSAPI), "sasl/GSSAPI" },
	{ ENUM2INT(NS_LDAP_EA_TLS_NONE), "tls:none" },
	{ ENUM2INT(NS_LDAP_EA_TLS_SIMPLE), "tls:simple" },
	{ ENUM2INT(NS_LDAP_EA_TLS_SASL_CRAM_MD5), "tls:sasl/CRAM-MD5" },
	{ ENUM2INT(NS_LDAP_EA_TLS_SASL_DIGEST_MD5), "tls:sasl/DIGEST-MD5" },
	{ ENUM2INT(NS_LDAP_EA_TLS_SASL_DIGEST_MD5_INT),
			"tls:sasl/DIGEST-MD5:auth-int" },
	{ ENUM2INT(NS_LDAP_EA_TLS_SASL_DIGEST_MD5_CONF),
			"tls:sasl/DIGEST-MD5:auth-conf" },
	{ ENUM2INT(NS_LDAP_EA_TLS_SASL_EXTERNAL), "tls:sasl/EXTERNAL" },
	{ -1, NULL },
};

	/* V1 ONLY */
static ns_enum_map ns_sec_enum_v1[] = {
	{ ENUM2INT(NS_LDAP_TLS_NONE), "NS_LDAP_SEC_NONE" },
	{ -1, NULL },
};

	/* V2 ONLY */
static ns_enum_map ns_cred_enum_v2[] = {
	{ ENUM2INT(NS_LDAP_CRED_ANON), "anonymous" },
	{ ENUM2INT(NS_LDAP_CRED_PROXY), "proxy" },
	{ ENUM2INT(NS_LDAP_CRED_SELF), "self" },
	{ -1, NULL },
};

static ns_enum_map ns_ref_enum_v1[] = {
	{ ENUM2INT(NS_LDAP_FOLLOWREF), "NS_LDAP_FOLLOWREF" },
	{ ENUM2INT(NS_LDAP_NOREF), "NS_LDAP_NOREF" },
	{ -1, NULL },
};

static ns_enum_map ns_ref_enum_v2[] = {
	{ ENUM2INT(NS_LDAP_FOLLOWREF), "TRUE" },
	{ ENUM2INT(NS_LDAP_NOREF), "FALSE" },
	{ -1, NULL },
};

static ns_enum_map ns_scope_enum_v1[] = {
	{ ENUM2INT(NS_LDAP_SCOPE_BASE), "NS_LDAP_SCOPE_BASE" },
	{ ENUM2INT(NS_LDAP_SCOPE_ONELEVEL), "NS_LDAP_SCOPE_ONELEVEL" },
	{ ENUM2INT(NS_LDAP_SCOPE_SUBTREE), "NS_LDAP_SCOPE_SUBTREE" },
	{ -1, NULL },
};

static ns_enum_map ns_scope_enum_v2[] = {
	{ ENUM2INT(NS_LDAP_SCOPE_BASE), "base" },
	{ ENUM2INT(NS_LDAP_SCOPE_ONELEVEL), "one" },
	{ ENUM2INT(NS_LDAP_SCOPE_SUBTREE), "sub" },
	{ -1, NULL },
};

static ns_enum_map ns_pref_enum[] = {
	{ ENUM2INT(NS_LDAP_PREF_FALSE), "NS_LDAP_FALSE" },
	{ ENUM2INT(NS_LDAP_PREF_TRUE), "NS_LDAP_TRUE" },
	{ -1, NULL },
};

static ns_enum_map ns_shadow_update_enum[] = {
	{ ENUM2INT(NS_LDAP_ENABLE_SHADOW_UPDATE_FALSE), "FALSE" },
	{ ENUM2INT(NS_LDAP_ENABLE_SHADOW_UPDATE_TRUE), "TRUE" },
	{ -1, NULL },
};

static int	ns_def_auth_v1[] = {
	ENUM2INT(NS_LDAP_EA_NONE),
	0
};

static int	ns_def_auth_v2[] = {
	ENUM2INT(NS_LDAP_EA_NONE),
	0
};

static int	ns_def_cred_v1[] = {
	ENUM2INT(NS_LDAP_CRED_PROXY),
	0
};

static int	ns_def_cred_v2[] = {
	ENUM2INT(NS_LDAP_CRED_ANON),
	0
};

/*
 * The next macro places an integer in the first sizeof(int) bytes of a
 * void pointer location. For 32-bit, it is the same as "(void *) i". It
 * is used to solve a problem found during 64-bit testing.  The problem
 * was that for a configuration parameter such as NS_LDAP_SEARCH_REF_P,
 * which is of type INT and has defined default value, an int
 * variable(ns_param.ns_pu.i) defined inside an union(ns_pu) structure, is
 * used to access the defined default value. This requires the default
 * value to be in the first sizeof(int) bytes of the union element.  If
 * just using "(void *) intval" to declare the default value in the
 * following defconfig[] structure, the intval data will be placed is the
 * last sizeof(int) bytes. In which case, when accessing via ns_pu_i in
 * a 64-bit system, ZERO will be returned as the default value, not the
 * defined one.
 *
 * Note since amd64 is little-endian, the problem is not an issue.
 * INT2VOIDPTR will just leave the data (i) unchanged.
 */
#if defined(__amd64)
#define	INT2VOIDPTR(i)	(void *)i
#else
#define	INT2VOIDPTR(i)	\
	(void *)(((long)(i))<<(8*(sizeof (void *) - sizeof (int))))
#endif
/*
 * The default configuration table
 * Version 1 entries are first, V2 entries follow.
 */
static ns_default_config defconfig[] = {
	/* optional V1 profile */
	{"NS_LDAP_FILE_VERSION", NS_LDAP_FILE_VERSION_P,
		CLIENTCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V1,
		NULL,	/* No version number defined in V1 */
		{ CHARPTR, 0, (void *)NS_LDAP_VERSION_1 },
		NULL, NULL },

	/* ---------- V1 profile ---------- */
	{"NS_LDAP_BINDDN", NS_LDAP_BINDDN_P,
		CREDCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V1,
		_P1_BINDDN,
		{ CHARPTR, 0, NULL },
		__s_val_binddn, NULL },

	{"NS_LDAP_BINDPASSWD", NS_LDAP_BINDPASSWD_P,
		CREDCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V1,
		_P1_BINDPASSWORD,
		{ CHARPTR, 0, NULL },
		__s_val_bindpw, NULL },

	{"NS_LDAP_SERVERS", NS_LDAP_SERVERS_P,
		SERVERCONFIG,	ARRAYCP,	FALSE,	NS_LDAP_V1,
		_P1_SERVERS,
		{ ARRAYCP, 0, NULL },
		__s_val_serverList, NULL },

	{"NS_LDAP_SEARCH_BASEDN", NS_LDAP_SEARCH_BASEDN_P,
		SERVERCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V1,
		_P1_SEARCHBASEDN,
		{ CHARPTR, 0, NULL },
		__s_val_basedn, NULL },

	{"NS_LDAP_AUTH", NS_LDAP_AUTH_P,
		CLIENTCONFIG,	ARRAYAUTH,	FALSE,	NS_LDAP_V1,
		_P1_AUTHMETHOD,
		{ ARRAYAUTH, 1, (void *)&ns_def_auth_v1[0] },
		NULL, ns_auth_enum_v1 },

	{"NS_LDAP_TRANSPORT_SEC", NS_LDAP_TRANSPORT_SEC_P,
		CLIENTCONFIG,	INT,		TRUE,	NS_LDAP_V1,
		_P1_TRANSPORTSECURITY,
		{ INT, 0, INT2VOIDPTR(NS_LDAP_TLS_NONE) },
		NULL, ns_sec_enum_v1 },

	{"NS_LDAP_SEARCH_REF", NS_LDAP_SEARCH_REF_P,
		CLIENTCONFIG,	INT,		TRUE,	NS_LDAP_V1,
		_P1_SEARCHREFERRAL,
		{ INT, 0, INT2VOIDPTR(NS_LDAP_FOLLOWREF) },
		NULL, ns_ref_enum_v1 },

	{"NS_LDAP_DOMAIN", NS_LDAP_DOMAIN_P,
		CLIENTCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V1,
		NULL,	/* not defined in the Profile */
		{ CHARPTR, 0, NULL },
		NULL, NULL },

	{"NS_LDAP_EXP", NS_LDAP_EXP_P,
		SERVERCONFIG,	TIMET,		TRUE,	NS_LDAP_V1,
		NULL,	/* initialized by code to time+NS_LDAP_CACHETTL */
		{ INT, 0, 0 },
		NULL, NULL },

	{"NS_LDAP_CERT_PATH", NS_LDAP_CERT_PATH_P,
		CREDCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V1,
		_P1_CERTIFICATEPATH,
		{ CHARPTR, 0, NULL },
		NULL, NULL },

	{"NS_LDAP_CERT_PASS", NS_LDAP_CERT_PASS_P,
		CREDCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V1,
		_P1_CERTIFICATEPASSWORD,
		{ CHARPTR, 0, NULL },
		NULL, NULL },

	{"NS_LDAP_SEARCH_DN", NS_LDAP_SEARCH_DN_P,
		CLIENTCONFIG,	SSDLIST,	FALSE,	NS_LDAP_V1,
		_P1_DATASEARCHDN,
		{ SSDLIST, 0, NULL },
		NULL, NULL },

	{"NS_LDAP_SEARCH_SCOPE", NS_LDAP_SEARCH_SCOPE_P,
		CLIENTCONFIG,	INT,		TRUE,	NS_LDAP_V1,
		_P1_SEARCHSCOPE,
		{ INT, 0, INT2VOIDPTR(NS_LDAP_SCOPE_ONELEVEL) },
		NULL, ns_scope_enum_v1 },

	{"NS_LDAP_SEARCH_TIME", NS_LDAP_SEARCH_TIME_P,
		CLIENTCONFIG,	INT,		TRUE,	NS_LDAP_V1,
		_P1_SEARCHTIMELIMIT,
		{ INT, 0, INT2VOIDPTR(NS_DEFAULT_SEARCH_TIMEOUT) },
		NULL, NULL },

	{"NS_LDAP_SERVER_PREF", NS_LDAP_SERVER_PREF_P,
		CLIENTCONFIG,	ARRAYCP,	FALSE,	NS_LDAP_V1,
		_P1_PREFERREDSERVER,
		{ ARRAYCP, 0, NULL },
		__s_val_serverList, NULL },

	{"NS_LDAP_PREF_ONLY", NS_LDAP_PREF_ONLY_P,
		CLIENTCONFIG,	INT,		TRUE,	NS_LDAP_V1,
		_P1_PREFERREDSERVERONLY,
		{ INT, 0, INT2VOIDPTR(NS_LDAP_PREF_FALSE) },
		NULL, ns_pref_enum },

	{"NS_LDAP_CACHETTL", NS_LDAP_CACHETTL_P,
		CLIENTCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V1,
		_P1_CACHETTL,
		{ CHARPTR, 0, (void *)EXP_DEFAULT_TTL },
		__s_val_postime, NULL },

	{"NS_LDAP_PROFILE", NS_LDAP_PROFILE_P,
		CLIENTCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V1,
		_P_CN,
		{ CHARPTR, 0, (void *)DEFAULTCONFIGNAME },
		NULL, NULL },

	{"NS_LDAP_BIND_TIME", NS_LDAP_BIND_TIME_P,
		CLIENTCONFIG,	INT,		TRUE,	NS_LDAP_V1,
		_P1_BINDTIMELIMIT,
		{ INT, 0, INT2VOIDPTR(NS_DEFAULT_BIND_TIMEOUT) },
		NULL, NULL },

	/* This configuration option is not visible in V1 */
	{"NS_LDAP_CREDENTIAL_LEVEL", NS_LDAP_CREDENTIAL_LEVEL_P,
		CLIENTCONFIG,	ARRAYCRED,	TRUE,	NS_LDAP_V1,
		NULL,	/* No version defined in V1 */
		{ ARRAYCRED, 0, (void *)&ns_def_cred_v1[0] },
		NULL, NULL },

	/* ---------- V2 profile ---------- */
	{"NS_LDAP_FILE_VERSION", NS_LDAP_FILE_VERSION_P,
		CLIENTCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V2,
		NULL,	/* No version number defined in V1 */
		{ CHARPTR, 0, (void *)NS_LDAP_VERSION_2 },
		NULL, NULL },

	{"NS_LDAP_BINDDN", NS_LDAP_BINDDN_P,
		CREDCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V2,
		NULL,	/* not defined in the Profile */
		{ CHARPTR, 0, NULL },
		__s_val_binddn, NULL },

	{"NS_LDAP_BINDPASSWD", NS_LDAP_BINDPASSWD_P,
		CREDCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V2,
		NULL,	/* not defined in the Profile */
		{ CHARPTR, 0, NULL },
		__s_val_bindpw, NULL },

	{"NS_LDAP_ENABLE_SHADOW_UPDATE", NS_LDAP_ENABLE_SHADOW_UPDATE_P,
		CREDCONFIG,	INT,	TRUE,	NS_LDAP_V2,
		NULL,	/* not defined in the Profile */
		{ INT, 0, INT2VOIDPTR(NS_LDAP_ENABLE_SHADOW_UPDATE_FALSE) },
		NULL, ns_shadow_update_enum },

	{"NS_LDAP_ADMIN_BINDDN", NS_LDAP_ADMIN_BINDDN_P,
		CREDCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V2,
		NULL,	/* not defined in the Profile */
		{ CHARPTR, 0, NULL },
		__s_val_binddn, NULL },

	{"NS_LDAP_ADMIN_BINDPASSWD", NS_LDAP_ADMIN_BINDPASSWD_P,
		CREDCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V2,
		NULL,	/* not defined in the Profile */
		{ CHARPTR, 0, NULL },
		__s_val_bindpw, NULL },

	{"NS_LDAP_EXP", NS_LDAP_EXP_P,
		SERVERCONFIG,	TIMET,		TRUE,	NS_LDAP_V2,
		NULL,	/* initialized by code to time+NS_LDAP_CACHETTL */
		{ INT, 0, 0 },
		NULL, NULL },

	{"NS_LDAP_SERVER_PREF", NS_LDAP_SERVER_PREF_P,
		CLIENTCONFIG,	SERVLIST,	FALSE,	NS_LDAP_V2,
		_P2_PREFERREDSERVER,
		{ SERVLIST, 0, NULL },
		__s_val_serverList, NULL },

	{"NS_LDAP_SERVERS", NS_LDAP_SERVERS_P,
		SERVERCONFIG,	SERVLIST,	FALSE,	NS_LDAP_V2,
		_P2_DEFAULTSERVER,
		{ SERVLIST, 0, NULL },
		__s_val_serverList, NULL },

	{"NS_LDAP_SEARCH_BASEDN", NS_LDAP_SEARCH_BASEDN_P,
		SERVERCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V2,
		_P2_SEARCHBASEDN,
		{ CHARPTR, 0, NULL },
		__s_val_basedn, NULL },

	{"NS_LDAP_SEARCH_SCOPE", NS_LDAP_SEARCH_SCOPE_P,
		CLIENTCONFIG,	INT,		TRUE,	NS_LDAP_V2,
		_P2_SEARCHSCOPE,
		{ INT, 0, INT2VOIDPTR(NS_LDAP_SCOPE_ONELEVEL) },
		NULL, ns_scope_enum_v2 },

	{"NS_LDAP_AUTH", NS_LDAP_AUTH_P,
		CLIENTCONFIG,	ARRAYAUTH,	FALSE,	NS_LDAP_V2,
		_P2_AUTHMETHOD,
		{ ARRAYAUTH, 2, (void *)&ns_def_auth_v2[0] },
		NULL, ns_auth_enum_v2 },

	{"NS_LDAP_CREDENTIAL_LEVEL", NS_LDAP_CREDENTIAL_LEVEL_P,
		CLIENTCONFIG,	ARRAYCRED,	FALSE,	NS_LDAP_V2,
		_P2_CREDENTIALLEVEL,
		{ ARRAYCRED, 0, (void *)&ns_def_cred_v2[0] },
		NULL, ns_cred_enum_v2 },

	{"NS_LDAP_SERVICE_SEARCH_DESC", NS_LDAP_SERVICE_SEARCH_DESC_P,
		CLIENTCONFIG,	SSDLIST,	FALSE,	NS_LDAP_V2,
		_P2_SERVICESEARCHDESC,
		{ SSDLIST, 0, NULL },
		NULL, NULL },

	{"NS_LDAP_SEARCH_TIME", NS_LDAP_SEARCH_TIME_P,
		CLIENTCONFIG,	INT,		TRUE,	NS_LDAP_V2,
		_P2_SEARCHTIMELIMIT,
		{ INT, 0, INT2VOIDPTR(NS_DEFAULT_SEARCH_TIMEOUT) },
		NULL, NULL },

	{"NS_LDAP_BIND_TIME", NS_LDAP_BIND_TIME_P,
		CLIENTCONFIG,	INT,		TRUE,	NS_LDAP_V2,
		_P2_BINDTIMELIMIT,
		{ INT, 0, INT2VOIDPTR(NS_DEFAULT_BIND_TIMEOUT) },
		NULL, NULL },

	{"NS_LDAP_SEARCH_REF", NS_LDAP_SEARCH_REF_P,
		CLIENTCONFIG,	INT,		TRUE,	NS_LDAP_V2,
		_P2_FOLLOWREFERRALS,
		{ INT, 0, INT2VOIDPTR(NS_LDAP_FOLLOWREF) },
		NULL, ns_ref_enum_v2 },

	{"NS_LDAP_CACHETTL", NS_LDAP_CACHETTL_P,
		CLIENTCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V2,
		_P2_PROFILETTL,
		{ CHARPTR, 0, (void *)EXP_DEFAULT_TTL },
		__s_val_postime, NULL },

	{"NS_LDAP_ATTRIBUTEMAP", NS_LDAP_ATTRIBUTEMAP_P,
		CLIENTCONFIG,	ATTRMAP,	FALSE,	NS_LDAP_V2,
		_P2_ATTRIBUTEMAP,
		{ ATTRMAP, 0, NULL },
		NULL, NULL },

	{"NS_LDAP_OBJECTCLASSMAP", NS_LDAP_OBJECTCLASSMAP_P,
		CLIENTCONFIG,	OBJMAP,		FALSE,	NS_LDAP_V2,
		_P2_OBJECTCLASSMAP,
		{ OBJMAP, 0, NULL },
		NULL, NULL },

	{"NS_LDAP_PROFILE", NS_LDAP_PROFILE_P,
		CLIENTCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V2,
		_P_CN,
		{ CHARPTR, 0, (void *)DEFAULTCONFIGNAME },
		NULL, NULL },

	{"NS_LDAP_SERVICE_AUTH_METHOD", NS_LDAP_SERVICE_AUTH_METHOD_P,
		CLIENTCONFIG,	SAMLIST,	FALSE,	NS_LDAP_V2,
		_P2_SERVICEAUTHMETHOD,
		{ SAMLIST, 0, NULL },
		NULL, NULL },

	{"NS_LDAP_SERVICE_CRED_LEVEL", NS_LDAP_SERVICE_CRED_LEVEL_P,
		CLIENTCONFIG,	SCLLIST,	FALSE,	NS_LDAP_V2,
		_P2_SERVICECREDLEVEL,
		{ SCLLIST, 0, NULL },
		NULL, NULL },

	{"NS_LDAP_HOST_CERTPATH", NS_LDAP_HOST_CERTPATH_P,
		CREDCONFIG,	CHARPTR,	TRUE,	NS_LDAP_V2,
		NULL,	/* not defined in the Profile */
		{ CHARPTR, 0, (void *)NSLDAPDIRECTORY },
		NULL, NULL },

	/* array terminator [not an entry] */
	{NULL, NS_LDAP_FILE_VERSION_P,
		CLIENTCONFIG,	NS_UNKNOWN,	TRUE,	NULL,
		NULL,
		{ NS_UNKNOWN, 0, NULL },
		NULL, NULL },
};

static char *
__getdomainname()
{
	/*
	 * The sysinfo man page recommends using a buffer size
	 * of 257 bytes. MAXHOSTNAMELEN is 256. So add 1 here.
	 */
	char	buf[MAXHOSTNAMELEN + 1];
	int	status;

	status = sysinfo(SI_SRPC_DOMAIN, buf, MAXHOSTNAMELEN);
	if (status < 0)
		return (NULL);
	/* error: not enough space to hold returned value */
	if (status > sizeof (buf))
		return (NULL);
	return (strdup(buf));
}

void
__ns_ldap_setServer(int set)
{
	cache_server = set;
}

static boolean_t
timetorefresh(ns_config_t *cfg)
{
	struct timeval	tp;
	static time_t	expire = 0;

	if (cfg == NULL || gettimeofday(&tp, NULL) == -1)
		return (B_TRUE);

	if (cfg->paramList[NS_LDAP_EXP_P].ns_ptype == TIMET)
		expire = cfg->paramList[NS_LDAP_EXP_P].ns_tm;
	else
		return (B_TRUE);

	return (expire != 0 && tp.tv_sec > expire);
}

int
__s_get_enum_value(ns_config_t *ptr, char *value, ParamIndexType i)
{
	register ns_enum_map	*mapp;
	char			*pstart = value;
	char			*pend;
	int			len;

	if (pstart == NULL)
		return (-1);

	/* skip leading spaces */
	while (*pstart == SPACETOK)
		pstart++;
	/* skip trailing spaces */
	pend = pstart + strlen(pstart) - 1;
	for (; pend >= pstart && *pend == SPACETOK; pend--)
		;
	len = pend - pstart + 1;
	if (len == 0)
		return (-1);

	switch (i) {
	case NS_LDAP_AUTH_P:
		if (ptr->version == NS_LDAP_V1)
			mapp = &ns_auth_enum_v1[0];
		else
			mapp = &ns_auth_enum_v2[0];
		break;
	case NS_LDAP_TRANSPORT_SEC_P:
		return (-1);
	case NS_LDAP_SEARCH_SCOPE_P:
		if (ptr->version == NS_LDAP_V1)
			mapp = &ns_scope_enum_v1[0];
		else
			mapp = &ns_scope_enum_v2[0];
		break;
	case NS_LDAP_SEARCH_REF_P:
		if (ptr->version == NS_LDAP_V1)
			mapp = &ns_ref_enum_v1[0];
		else
			mapp = &ns_ref_enum_v2[0];
		break;
	case NS_LDAP_PREF_ONLY_P:
		mapp = &ns_pref_enum[0];
		break;
	case NS_LDAP_ENABLE_SHADOW_UPDATE_P:
		mapp = &ns_shadow_update_enum[0];
		break;
	case NS_LDAP_CREDENTIAL_LEVEL_P:
		if (ptr->version == NS_LDAP_V1)
			return (-1);
		else
			mapp = &ns_cred_enum_v2[0];
		break;
	case NS_LDAP_SERVICE_AUTH_METHOD_P:
		mapp = &ns_auth_enum_v2[0];
		break;
	case NS_LDAP_SERVICE_CRED_LEVEL_P:
		mapp = &ns_cred_enum_v2[0];
		break;
	default:
		return (-1);
	}

	for (; mapp->name != NULL; mapp++) {
		if (strncasecmp(pstart, mapp->name, len) == 0 &&
		    (strlen(mapp->name) == len)) {
			return (mapp->value);
		}
	}
	return (-1);
}

char *
__s_get_auth_name(ns_config_t *ptr, AuthType_t type)
{
	register ns_enum_map	*mapp;

	if (ptr->version == NS_LDAP_V1)
		mapp = &ns_auth_enum_v1[0];
	else
		mapp = &ns_auth_enum_v2[0];

	for (; mapp->name != NULL; mapp++) {
		if (type == INT2AUTHENUM(mapp->value)) {
			return (mapp->name);
		}
	}
	return ("Unknown AuthType_t type specified");
}


char *
__s_get_security_name(ns_config_t *ptr, TlsType_t type)
{
	register ns_enum_map	*mapp;

	if (ptr->version == NS_LDAP_V1) {
		mapp = &ns_sec_enum_v1[0];

		for (; mapp->name != NULL; mapp++) {
			if (type == INT2SECENUM(mapp->value)) {
				return (mapp->name);
			}
		}
	}
	return ("Unknown TlsType_t type specified");
}


char *
__s_get_scope_name(ns_config_t *ptr, ScopeType_t type)
{
	register ns_enum_map	*mapp;

	if (ptr->version == NS_LDAP_V1)
		mapp = &ns_scope_enum_v1[0];
	else
		mapp = &ns_scope_enum_v2[0];

	for (; mapp->name != NULL; mapp++) {
		if (type == INT2SCOPEENUM(mapp->value)) {
			return (mapp->name);
		}
	}
	return ("Unknown ScopeType_t type specified");
}


char *
__s_get_pref_name(PrefOnly_t type)
{
	register ns_enum_map	*mapp = &ns_pref_enum[0];

	for (; mapp->name != NULL; mapp++) {
		if (type == INT2PREFONLYENUM(mapp->value)) {
			return (mapp->name);
		}
	}
	return ("Unknown PrefOnly_t type specified");
}

char *
__s_get_searchref_name(ns_config_t *ptr, SearchRef_t type)
{
	register ns_enum_map	*mapp;

	if (ptr->version == NS_LDAP_V1)
		mapp = &ns_ref_enum_v1[0];
	else
		mapp = &ns_ref_enum_v2[0];

	for (; mapp->name != NULL; mapp++) {
		if (type == INT2SEARCHREFENUM(mapp->value)) {
			return (mapp->name);
		}
	}
	return ("Unknown SearchRef_t type specified");
}

char *
__s_get_shadowupdate_name(enableShadowUpdate_t type)
{
	register ns_enum_map	*mapp;

	mapp = &ns_shadow_update_enum[0];

	for (; mapp->name != NULL; mapp++) {
		if (type == INT2SHADOWUPDATENUM(mapp->value)) {
			return (mapp->name);
		}
	}
	return ("Unknown enableShadowUpdate_t type specified");
}

static char *
__s_get_credlvl_name(ns_config_t *ptr, CredLevel_t type)
{
	register ns_enum_map	*mapp;

	if (ptr->version == NS_LDAP_V2) {
		mapp = &ns_cred_enum_v2[0];
		for (; mapp->name != NULL; mapp++) {
			if (type == INT2CREDLEVELENUM(mapp->value)) {
				return (mapp->name);
			}
		}
	}
	return ("Unknown CredLevel_t type specified");
}

static void
destroy_param(ns_config_t *ptr, ParamIndexType type)
{
	int	i, j;
	char	**ppc;

	if (ptr == NULL)
		return;

	/*
	 * This routine is not lock protected because
	 * the config param it may be destroying is not
	 * necessarily THE config.  Mutex protect elsewhere.
	 */
	switch (ptr->paramList[type].ns_ptype) {
	case CHARPTR:
		if (ptr->paramList[type].ns_pc) {
			free(ptr->paramList[type].ns_pc);
			ptr->paramList[type].ns_pc = NULL;
		}
		break;
	case SAMLIST:
	case SCLLIST:
	case SSDLIST:
	case ARRAYCP:
	case SERVLIST:
		if (ptr->paramList[type].ns_ppc) {
			ppc = ptr->paramList[type].ns_ppc;
			j = ptr->paramList[type].ns_acnt;
			for (i = 0; i < j && ppc[i] != NULL; i++) {
				free((void *)ppc[i]);
			}
			free((void *)ppc);
			ptr->paramList[type].ns_ppc = NULL;
		}
		break;
	case ARRAYAUTH:
	case ARRAYCRED:
		if (ptr->paramList[type].ns_pi) {
			free(ptr->paramList[type].ns_pi);
			ptr->paramList[type].ns_pi = NULL;
		}
		break;
	case INT:
		ptr->paramList[type].ns_i = 0;
		break;
	case ATTRMAP:
		break;
	case OBJMAP:
		break;
	default:
		break;
	}
	ptr->paramList[type].ns_ptype = NS_UNKNOWN;
}

static void
destroy_config(ns_config_t *ptr)
{
	ParamIndexType	i;

	if (ptr != NULL) {
		if (ptr == current_config)
			current_config = NULL;
		free(ptr->domainName);
		ptr->domainName = NULL;
		for (i = 0; i <= LAST_VALUE; i++) {
			destroy_param(ptr, i);
		}
		__s_api_destroy_hash(ptr);
		free(ptr);
	}
}

/*
 * Marks the ns_config_t to be deleted and then releases it. (If no other
 * caller is using, then __s_api_release_config will destroy it.)
 *
 * Note that __s_api_destroy_config should only be called if the caller has
 * created the ns_config_t with __s_api_create_config (with the exception
 * of set_curr_config). The ns_config_t should be private to the caller.
 *
 * This function should not be called with the current_config except by
 * set_curr_config which locks ns_parse_lock to ensure that no thread
 * will be waiting on current_config->config_mutex. This ensures that
 * no caller with be waiting on cfg->config_mutex while it is being
 * destroyed by __s_api_release_config.
 */

void
__s_api_destroy_config(ns_config_t *cfg)
{
	if (cfg != NULL) {
		(void) mutex_lock(&cfg->config_mutex);
		cfg->delete = TRUE;
		(void) mutex_unlock(&cfg->config_mutex);
		__s_api_release_config(cfg);
	}
}


/*
 * Increment the configuration use count by one - assumes ns_parse_lock has
 * been obtained.
 */

static ns_config_t *
get_curr_config_unlocked(ns_config_t *cfg, boolean_t global)
{
	ns_config_t *ret;

	ret = cfg;
	if (cfg != NULL) {
		(void) mutex_lock(&cfg->config_mutex);
		/*
		 * allow access to per connection management (non-global)
		 * config so operations on connection being closed can still
		 * be completed
		 */
		if (cfg->delete && global == B_TRUE)
			ret = NULL;
		else
			cfg->nUse++;
		(void) mutex_unlock(&cfg->config_mutex);
	}
	return (ret);
}

/*
 * set_curr_config_global sets the current global config to the
 * specified ns_config_t. Note that this function is similar
 * to the project private function __s_api_init_config_global
 * except that it does not release the new ns_config_t.
 */
static void
set_curr_config_global(ns_config_t *ptr)
{
	ns_config_t	*cfg;
	ns_config_t	*cur_cfg;

	(void) mutex_lock(&ns_parse_lock);
	cur_cfg = current_config;
	cfg = get_curr_config_unlocked(cur_cfg, B_TRUE);
	if (cfg != ptr) {
		__s_api_destroy_config(cfg);
		current_config = ptr;
	}
	(void) mutex_unlock(&ns_parse_lock);
}


/*
 * set_curr_config sets the current config or the per connection
 * management one to the specified ns_config_t. Note that this function
 * is similar to the project private function __s_api_init_config
 * except that it does not release the new ns_config_t. Also note
 * that if there's no per connection management one to set, the
 * global current config will be set.
 */

static void
set_curr_config(ns_config_t *ptr)
{
	ns_config_t	*cfg;
	ns_config_t	*cur_cfg;
	ns_conn_mgmt_t	*cmg;
	int		rc;

	rc = thr_getspecific(ns_cmgkey, (void **)&cmg);

	/* set the per connection management config if possible */
	if (rc == 0 && cmg != NULL && cmg->config != NULL) {
		(void) mutex_lock(&cmg->cfg_lock);
		cur_cfg = cmg->config;
		cfg = get_curr_config_unlocked(cur_cfg, B_FALSE);
		if (cfg != ptr) {
			__s_api_destroy_config(cfg);
			cmg->config = ptr;
		}
		(void) mutex_unlock(&cmg->cfg_lock);
		return;
	}

	/* else set the global current config */
	set_curr_config_global(ptr);
}

/*
 * Decrements the ns_config_t usage count by one. Delete if delete flag
 * is set and no other callers are using.
 */

void
__s_api_release_config(ns_config_t *cfg)
{
	if (cfg != NULL) {
		(void) mutex_lock(&cfg->config_mutex);
		cfg->nUse--;
		if (cfg->nUse == 0 && cfg->delete) {
			destroy_config(cfg);
		} else
			(void) mutex_unlock(&cfg->config_mutex);
	}
}

/*
 * __s_api_init_config function destroys the previous global configuration
 * sets the new global configuration and then releases it
 */
void
__s_api_init_config_global(ns_config_t *ptr)
{
	set_curr_config_global(ptr);
	__s_api_release_config(ptr);
}

/*
 * __s_api_init_config function destroys the previous configuration
 * sets the new configuration and then releases it. The configuration
 * may be the global one or the per connection management one.
 */
void
__s_api_init_config(ns_config_t *ptr)
{
	set_curr_config(ptr);
	__s_api_release_config(ptr);
}


/*
 * Create an ns_config_t, set the usage count to one
 */

ns_config_t *
__s_api_create_config(void)
{
	ns_config_t	*ret;
	ret = (ns_config_t *)calloc(1, sizeof (ns_config_t));
	if (ret == NULL)
		return (NULL);

	ret->domainName = __getdomainname();
	if (ret->domainName == NULL) {
		free(ret);
		return (NULL);
	}
	ret->version = NS_LDAP_V1;
	(void) mutex_init(&ret->config_mutex, USYNC_THREAD, NULL);
	ret->nUse = 1;
	ret->delete = B_FALSE;
	return (ret);
}

/*
 * __s_api_get_default_config_global returns the current global config
 */
ns_config_t *
__s_api_get_default_config_global(void)
{
	ns_config_t	*cfg;
	ns_config_t	*cur_cfg;

	(void) mutex_lock(&ns_parse_lock);
	cur_cfg = current_config;
	cfg = get_curr_config_unlocked(cur_cfg, B_TRUE);
	(void) mutex_unlock(&ns_parse_lock);

	return (cfg);
}

/*
 * __s_api_get_default_config returns the current global config or the
 * per connection management one.
 */
ns_config_t *
__s_api_get_default_config(void)
{
	ns_config_t	*cfg;
	ns_config_t	*cur_cfg;
	ns_conn_mgmt_t	*cmg;
	int		rc;

	rc = thr_getspecific(ns_cmgkey, (void **)&cmg);

	/* get the per connection management config if available */
	if (rc == 0 && cmg != NULL && cmg->config != NULL) {
		(void) mutex_lock(&cmg->cfg_lock);
		cur_cfg = cmg->config;
		cfg = get_curr_config_unlocked(cur_cfg, B_FALSE);
		(void) mutex_unlock(&cmg->cfg_lock);
		return (cfg);
	}

	/* else get the global current config */
	return (__s_api_get_default_config_global());
}

static char *
stripdup(const char *instr)
{
	char	*pstart = (char *)instr;
	char	*pend, *ret;
	int	len;

	if (pstart == NULL)
		return (NULL);
	/* remove leading spaces */
	while (*pstart == SPACETOK)
		pstart++;
	/* remove trailing spaces */
	pend = pstart + strlen(pstart) - 1;
	for (; pend >= pstart && *pend == SPACETOK; pend--)
		;
	len = pend - pstart + 1;
	if ((ret = malloc(len + 1)) == NULL)
		return (NULL);
	if (len != 0) {
		(void) strncpy(ret, pstart, len);
	}
	ret[len] = '\0';
	return (ret);
}

/*
 * Note that __s_api_crosscheck is assumed to be called with an ns_config_t
 * that is properly protected - so that it will not change during the
 * duration of the call
 */

/* Size of errstr needs to be MAXERROR */
ns_parse_status
__s_api_crosscheck(ns_config_t *ptr, char *errstr, int check_dn)
{
	int		value, j;
	time_t		tm;
	const char	*str, *str1;
	int		i, cnt;
	int		self, gssapi;

	if (ptr == NULL)
		return (NS_SUCCESS);

	/* check for no server specified */
	if (ptr->paramList[NS_LDAP_SERVERS_P].ns_ppc == NULL) {
		if (ptr->version == NS_LDAP_V1) {
			str = NULL_OR_STR(__s_api_get_configname(
			    NS_LDAP_SERVERS_P));
			(void) snprintf(errstr, MAXERROR,
			    gettext("Configuration Error: No entry for "
			    "'%s' found"), str);
			return (NS_PARSE_ERR);
		} else if (ptr->paramList[NS_LDAP_SERVER_PREF_P].ns_ppc ==
		    NULL) {
			str = NULL_OR_STR(__s_api_get_configname(
			    NS_LDAP_SERVERS_P));
			str1 = NULL_OR_STR(__s_api_get_configname(
			    NS_LDAP_SERVER_PREF_P));
			(void) snprintf(errstr, MAXERROR,
			    gettext("Configuration Error: "
			    "Neither '%s' nor '%s' is defined"), str, str1);
			return (NS_PARSE_ERR);
		}
	}
	if (ptr->paramList[NS_LDAP_CERT_PASS_P].ns_pc != NULL &&
	    ptr->paramList[NS_LDAP_CERT_PATH_P].ns_pc == NULL) {
			str = NULL_OR_STR(__s_api_get_configname(
			    NS_LDAP_CERT_PASS_P));
			str1 = NULL_OR_STR(__s_api_get_configname(
			    NS_LDAP_CERT_PATH_P));
			(void) snprintf(errstr, MAXERROR,
			gettext("Configuration Error: %s specified "
			    "but no value for '%s' found"), str, str1);
		return (NS_PARSE_ERR);
	}
	if (ptr->paramList[NS_LDAP_CERT_PASS_P].ns_pc == NULL &&
	    ptr->paramList[NS_LDAP_CERT_PATH_P].ns_pc != NULL) {
			str = NULL_OR_STR(__s_api_get_configname(
			    NS_LDAP_CERT_PATH_P));
			str1 = NULL_OR_STR(__s_api_get_configname(
			    NS_LDAP_CERT_PASS_P));
			(void) snprintf(errstr, MAXERROR,
			gettext("Configuration Error: %s specified "
			    "but no value for '%s' found"), str, str1);
		return (NS_PARSE_ERR);
	}
	/* check if search basedn has been specified */
	if (ptr->paramList[NS_LDAP_SEARCH_BASEDN_P].ns_ppc == NULL) {
		str = NULL_OR_STR(__s_api_get_configname(
		    NS_LDAP_SEARCH_BASEDN_P));
		(void) snprintf(errstr, MAXERROR,
		    gettext("Configuration Error: No entry for "
		    "'%s' found"), str);
		return (NS_PARSE_ERR);
	}

	if (check_dn) {
	    /* check for auth value....passwd/bindn if necessary */

		for (j = 0; ptr->paramList[NS_LDAP_AUTH_P].ns_pi != NULL &&
		    ptr->paramList[NS_LDAP_AUTH_P].ns_pi[j] != NULL; j++) {
		value = ptr->paramList[NS_LDAP_AUTH_P].ns_pi[j];
		switch (value) {
		case NS_LDAP_EA_SIMPLE:
		case NS_LDAP_EA_SASL_CRAM_MD5:
		case NS_LDAP_EA_SASL_DIGEST_MD5:
		case NS_LDAP_EA_SASL_DIGEST_MD5_INT:
		case NS_LDAP_EA_SASL_DIGEST_MD5_CONF:
		case NS_LDAP_EA_TLS_SIMPLE:
		case NS_LDAP_EA_TLS_SASL_CRAM_MD5:
		case NS_LDAP_EA_TLS_SASL_DIGEST_MD5:
		case NS_LDAP_EA_TLS_SASL_DIGEST_MD5_INT:
		case NS_LDAP_EA_TLS_SASL_DIGEST_MD5_CONF:
			if (ptr->paramList[NS_LDAP_BINDDN_P].ns_ppc == NULL) {
				str = NULL_OR_STR(__s_api_get_configname(
				    NS_LDAP_BINDDN_P));
				(void) snprintf(errstr, MAXERROR,
				gettext("Configuration Error: No entry for "
				    "'%s' found"), str);
				return (NS_PARSE_ERR);
			}
			if (ptr->paramList[NS_LDAP_BINDPASSWD_P].ns_ppc
			    == NULL) {
				str = NULL_OR_STR(__s_api_get_configname(
				    NS_LDAP_BINDPASSWD_P));
				(void) snprintf(errstr, MAXERROR,
				gettext("Configuration Error: No entry for "
				    "'%s' found"), str);
				return (NS_PARSE_ERR);
			}
			break;
		}
		}
	}

	/*
	 * If NS_LDAP_CACHETTL is not specified,
	 * init NS_LDAP_EXP_P here. Otherwise,
	 * ldap_cachemgr will never refresh the profile.
	 * Set it to current time + default
	 * NS_LDAP_CACHETTL
	 */
	if (ptr->paramList[NS_LDAP_CACHETTL_P].ns_pc == NULL) {
		tm = conv_time(
		    defconfig[NS_LDAP_CACHETTL_P].defval.ns_pc);
		ptr->paramList[NS_LDAP_EXP_P].ns_ptype = TIMET;
		if (tm != 0) {
			tm += time(NULL);
		}
		ptr->paramList[NS_LDAP_EXP_P].ns_tm = tm;
	}
	/*
	 * If credential level self is defined, there should be
	 * at least an auth method sasl/GSSAPI and vice versa.
	 */
	self = 0;
	cnt = ptr->paramList[NS_LDAP_CREDENTIAL_LEVEL_P].ns_acnt;
	for (i = 0; i < cnt; i++) {
		if (ptr->paramList[NS_LDAP_CREDENTIAL_LEVEL_P].ns_pi[i] ==
		    NS_LDAP_CRED_SELF)
			self++;
	}
	gssapi = 0;
	cnt = ptr->paramList[NS_LDAP_AUTH_P].ns_acnt;
	for (i = 0; i < cnt; i++) {
		if (ptr->paramList[NS_LDAP_AUTH_P].ns_pi[i] ==
		    NS_LDAP_EA_SASL_GSSAPI)
			gssapi++;
	}
	if (gssapi == 0 && self > 0) {
		(void) snprintf(errstr, MAXERROR,
		    gettext("Configuration Error: "
		    "Credential level self requires "
		    "authentication method sasl/GSSAPI"));
		return (NS_PARSE_ERR);
	}
	if (gssapi > 0 && self == 0) {
		(void) snprintf(errstr, MAXERROR,
		    gettext("Configuration Error: "
		    "Authentication method sasl/GSSAPI "
		    "requires credential level self"));
		return (NS_PARSE_ERR);
	}
	return (NS_SUCCESS);
}


int
__s_api_get_type(const char *value, ParamIndexType *type)
{
	int	i;

	for (i = 0; defconfig[i].name != NULL; i++) {
		if (strcasecmp(defconfig[i].name, value) == 0) {
			*type = defconfig[i].index;
			return (0);
		}
	}
	return (-1);
}

/*
 * Externally defined version of get_type.
 * Includes extra error checking
 */

int
__ns_ldap_getParamType(const char *value, ParamIndexType *type)
{
	if (value == NULL || type == NULL)
		return (-1);
	return (__s_api_get_type(value, type));
}

int
__s_api_get_versiontype(ns_config_t *ptr, char *value, ParamIndexType *type)
{
	ns_version_t	ver;
	int		i;

	if (ptr == NULL)
		return (-1);

	ver = ptr->version;

	for (i = 0; defconfig[i].name != NULL; i++) {
		if (strcasecmp(defconfig[i].name, value) == 0) {
			if (defconfig[i].version == ver) {
				*type = defconfig[i].index;
				return (0);
			}
		}
	}
	return (-1);
}

int
__s_api_get_profiletype(char *value, ParamIndexType *type)
{
	int	i;

	for (i = 0; defconfig[i].name != NULL; i++) {
		if (defconfig[i].profile_name == NULL)
			continue;
		if (strcasecmp(defconfig[i].profile_name, value) == 0) {
			*type = defconfig[i].index;
			return (0);
		}
	}
	return (-1);
}

int
__s_api_get_configtype(ParamIndexType type)
{
	int i;

	for (i = 0; defconfig[i].name != NULL; i++) {
		if (defconfig[i].index == type) {
			return (defconfig[i].config_type);
		}
	}
	return (-1);
}

const char *
__s_api_get_configname(ParamIndexType type)
{
	int i;

	for (i = 0; defconfig[i].name != NULL; i++) {
		if (defconfig[i].index == type) {
			if (defconfig[i].name[0] == '\0')
				return (NULL);
			else
				return (defconfig[i].name);
		}
	}
	return (NULL);
}

static ns_default_config *
get_defconfig(ns_config_t *ptr, ParamIndexType type)
{
	ns_version_t	ver;
	int		i;

	ver = ptr->version;

	for (i = 0; defconfig[i].name != NULL; i++) {
		if (defconfig[i].index == type &&
		    defconfig[i].version == ver) {
			return (&defconfig[i]);
		}
	}
	return (NULL);
}

static int
set_default_value(ns_config_t *configptr, char *name,
    char *value, ns_ldap_error_t **error)
{
	ParamIndexType	i;
	int		ret;
	char		errstr[MAXERROR];

	if (__s_api_get_type(name, &i) < 0) {
		(void) snprintf(errstr, sizeof (errstr), gettext(
		    "Illegal type name (%s).\n"), name);
		MKERROR(LOG_ERR, *error, NS_CONFIG_SYNTAX, strdup(errstr),
		    NULL);
		return (NS_LDAP_CONFIG);
	}

	if (i != NS_LDAP_SERVERS_P &&
	    i != NS_LDAP_SERVICE_AUTH_METHOD_P &&
	    i != NS_LDAP_SERVICE_CRED_LEVEL_P &&
	    i != NS_LDAP_SERVICE_SEARCH_DESC_P &&
	    i != NS_LDAP_SERVER_PREF_P &&
	    i != NS_LDAP_SEARCH_DN_P) {
		if (configptr->paramList[i].ns_ptype != NS_UNKNOWN) {
			destroy_param(configptr, i);
		}
	}

	ret = __ns_ldap_setParamValue(configptr, i, value, error);
	return (ret);
}


/*
 * Initialize config to a default state
 * By default leave configuration empty
 * getParam will automatically get the
 * appropriate default value if none exists
 */

void
__ns_ldap_default_config()
{
	ns_config_t	*ptr;

	ptr = __s_api_create_config();
	if (ptr == NULL)
		return;

	set_curr_config(ptr);
	__s_api_release_config(ptr);
}

/*
 * Get the current configuration pointer and return it.
 * If necessary initialize or refresh the current
 * configuration as applicable. If global is set, returns
 * the global one.
 */

static ns_config_t *
loadrefresh_config(boolean_t global)
{
	ns_config_t		*cfg;
	ns_config_t		*new_cfg;
	ns_ldap_error_t		*errorp;

	/* We want to refresh only one configuration at a time */
	(void) mutex_lock(&ns_loadrefresh_lock);
	if (global == B_TRUE)
		cfg = __s_api_get_default_config_global();
	else
		cfg = __s_api_get_default_config();

	/* (re)initialize configuration if necessary */
	if (!__s_api_isStandalone() && timetorefresh(cfg)) {
		new_cfg = LoadCacheConfiguration(cfg, &errorp);
		if (new_cfg != NULL && new_cfg != cfg) {
			__s_api_release_config(cfg);
			if (global == B_TRUE)
				set_curr_config_global(new_cfg);
			else
				set_curr_config(new_cfg);
			cfg = new_cfg;
		}
		if (errorp != NULL)
			(void) __ns_ldap_freeError(&errorp);
	}
	(void) mutex_unlock(&ns_loadrefresh_lock);
	return (cfg);
}

/*
 * Get the current global configuration pointer and return it.
 * If necessary initialize or refresh the current
 * configuration as applicable.
 */

ns_config_t *
__s_api_loadrefresh_config_global()
{
	return (loadrefresh_config(B_TRUE));
}

/*
 * Get the current configuration pointer and return it.
 * If necessary initialize or refresh the current
 * configuration as applicable. The configuration may
 * be the global one or the per connection management one.
 */

ns_config_t *
__s_api_loadrefresh_config()
{
	return (loadrefresh_config(B_FALSE));
}

/*
 * In general this routine is not very usefull. Individual routines can be
 * created to do this job.  Once that is done, this function can be removed.
 * Size of errstr buffer needs to be MAXERROR.
 */
static ns_parse_status
verify_value(ns_config_t *cfg, char *name, char *value, char *errstr)
{
	ParamIndexType	index = 0;
	int		found = 0, j;
	char		*ptr = NULL, *strptr = NULL, buffer[BUFSIZE];
	char		*rest;
	ns_default_config	*def = NULL;

	if (__s_api_get_type(name, &index) != 0) {
		(void) snprintf(errstr, MAXERROR,
		    gettext("Unknown keyword encountered '%s'."), name);
		return (NS_PARSE_ERR);
	}

	def = get_defconfig(cfg, index);

	/* eat up beginning quote, if any */
	while (value != NULL && (*value == QUOTETOK || *value == SPACETOK))
		value++;

	/* eat up space/quote at end of value */
	if (strlen(value) > 0)
		ptr = value + strlen(value) - 1;
	else
		ptr = value;
	for (; ptr != value && (*ptr == SPACETOK || *ptr == QUOTETOK); ptr--) {
		*ptr = '\0';
	}

	switch (index) {
	case NS_LDAP_EXP_P:
	case NS_LDAP_CACHETTL_P:
	case NS_LDAP_CERT_PATH_P:
	case NS_LDAP_CERT_PASS_P:
	case NS_LDAP_CERT_NICKNAME_P:
	case NS_LDAP_BINDDN_P:
	case NS_LDAP_BINDPASSWD_P:
	case NS_LDAP_ADMIN_BINDDN_P:
	case NS_LDAP_ADMIN_BINDPASSWD_P:
	case NS_LDAP_DOMAIN_P:
	case NS_LDAP_SEARCH_BASEDN_P:
	case NS_LDAP_SEARCH_TIME_P:
	case NS_LDAP_PROFILE_P:
	case NS_LDAP_AUTH_P:
	case NS_LDAP_SEARCH_SCOPE_P:
	case NS_LDAP_CREDENTIAL_LEVEL_P:
	case NS_LDAP_SERVICE_SEARCH_DESC_P:
	case NS_LDAP_BIND_TIME_P:
	case NS_LDAP_ATTRIBUTEMAP_P:
	case NS_LDAP_OBJECTCLASSMAP_P:
	case NS_LDAP_SERVICE_AUTH_METHOD_P:
	case NS_LDAP_SERVICE_CRED_LEVEL_P:
	case NS_LDAP_HOST_CERTPATH_P:
		break;
	case NS_LDAP_SEARCH_DN_P:
		/* depreciated because of service descriptors */
		/* Parse as appropriate at descriptor create time */
		break;
	case NS_LDAP_FILE_VERSION_P:
		if (value != NULL &&
		    strcasecmp(value, NS_LDAP_VERSION_1) != 0 &&
		    strcasecmp(value, NS_LDAP_VERSION_2) != 0) {
			(void) snprintf(errstr, MAXERROR,
			    gettext("Version mismatch, expected "
			    "cache version '%s' or '%s' but "
			    "encountered version '%s'."),
			    NS_LDAP_VERSION_1,
			    NS_LDAP_VERSION_2, value);
				return (NS_PARSE_ERR);
		}
		break;
	case NS_LDAP_SERVERS_P:
	case NS_LDAP_SERVER_PREF_P:
		(void) strcpy(buffer, value);
		strptr = strtok_r(buffer, ",", &rest);
		while (strptr != NULL) {
			char	*tmp = NULL;
			tmp = stripdup(strptr);
			if (tmp == NULL || (strchr(tmp, ' ') != NULL)) {
				(void) snprintf(errstr, MAXERROR,
				    gettext("Invalid parameter values "
				    "'%s' specified for keyword '%s'."),
				    tmp, name);
				free(tmp);
				return (NS_PARSE_ERR);
			}
			free(tmp);
			strptr = strtok_r(NULL, ",", &rest);
		}
		break;
	default:
		found = 0; j = 0;
		while (def->allowed != NULL &&
		    def->allowed[j].name != NULL && j < DEFMAX) {
			if (strcmp(def->allowed[j].name,
			    value) == 0) {
				found = 1;
				break;
			}
			j++;
		}
		if (!found) {
			(void) snprintf(errstr, MAXERROR,
			    gettext("Invalid option specified for "
			    "'%s' keyword. '%s' is not a recognized "
			    "keyword value."), name, value);
			return (NS_PARSE_ERR);
		}
	}

	return (NS_SUCCESS);
}

void
__s_api_split_key_value(char *buffer, char **name, char **value)
{
	char	*ptr;

	*name = buffer;
	/* split into name value pair */
	if ((ptr = strchr(buffer, TOKENSEPARATOR)) != NULL) {
		*ptr = '\0';
		ptr++;
		/* trim whitespace */
		while (*ptr == SPACETOK)
			ptr++;
		*value = ptr;
	}
}

/*
 * Set a parameter value in a generic configuration structure
 * Assume any necessary locks are in place.  This routine would
 * be better named: __ns_ldap_translateString2Param
 *
 * This routine translates external string format into internal
 * param format and saves the result in the param table.
 */
int
__ns_ldap_setParamValue(ns_config_t *ptr, const ParamIndexType type,
    const void *data, ns_ldap_error_t **error)
{
	ns_default_config	*def = NULL;
	ns_param_t		conf;
	ns_mapping_t		*map, *rmap;
	int			i, j, len;
	char			*cp, *cp2, *end;
	char			*tcp = NULL;
	char			errstr[2 * MAXERROR];
	char			tbuf[100], *ptbuf;
	char			*sid, *origA, **mapA;
	char			**attr;
	time_t			tm;
	int 			free_memory, exitrc;
	char			**p;

	/* Find ParamIndexType default configuration data */
	def = get_defconfig(ptr, type);
	if (def == NULL) {
		(void) snprintf(errstr, sizeof (errstr),
		    gettext("Unable to set value: "
		    "invalid ParamIndexType (%d)"), type);
		MKERROR(LOG_ERR, *error, NS_CONFIG_SYNTAX, strdup(errstr),
		    NULL);
		return (NS_LDAP_CONFIG);
	}

	(void) memset(&conf, 0, sizeof (conf));

	/* data is actually const char */
	cp = (char *)data;

	/* eat up beginning quote, if any */
	while (cp && (*cp == QUOTETOK || *cp == SPACETOK))
		cp++;

	/* eat up space/quote at end of value */
	end = cp2 = cp + strlen(cp) - 1;
	for (; cp2 > cp && (*cp2 == SPACETOK || *cp2 == QUOTETOK); cp2--)
		;
	/* data is const, must duplicate */
	if (cp2 != end) {
		tcp = (char *)calloc((int)(cp2 - cp + 2), sizeof (char));
		if (tcp == NULL)
			return (NS_LDAP_MEMORY);
		end = cp2;
		cp2 = tcp;
		while (cp <= end) {
			*cp2++ = *cp++;
		}
		*cp2 = '\0';
		cp = tcp;
	}

	/* Parse data according to type */
	switch (def->data_type) {
	case INT:
		switch (def->index) {
		case NS_LDAP_PREF_ONLY_P:
		case NS_LDAP_SEARCH_REF_P:
		case NS_LDAP_SEARCH_SCOPE_P:
		case NS_LDAP_ENABLE_SHADOW_UPDATE_P:
			i = __s_get_enum_value(ptr, cp, def->index);
			if (i < 0) {
				(void) snprintf(errstr, sizeof (errstr),
				    gettext("Unable to set value: "
				    "invalid %s (%d)"), def->name,
				    def->index);
				MKERROR(LOG_ERR, *error, NS_CONFIG_SYNTAX,
				    strdup(errstr), NULL);
				if (tcp != NULL)
					free(tcp);
				return (NS_LDAP_CONFIG);
			}
			conf.ns_i = i;
			break;
		case NS_LDAP_TRANSPORT_SEC_P:	/* ignore TRANSPORT_SEC */
			break;
		default:
			cp2 = cp;
			if ((*cp2 == '+') || (*cp2 == '-'))
				cp2++;
			for (/* empty */; *cp2; cp2++) {
				if (isdigit(*cp2))
					continue;

				(void) snprintf(errstr, sizeof (errstr),
				    gettext("Unable to set value: "
				    "invalid %s (%d)"), def->name,
				    def->index);
				MKERROR(LOG_ERR, *error, NS_CONFIG_SYNTAX,
				    strdup(errstr), NULL);
				if (tcp != NULL)
					free(tcp);
				return (NS_LDAP_CONFIG);
			}
			i = atoi(cp);
			conf.ns_i = i;
			break;
		}
		break;
	case TIMET:
		/* Do nothing with a TIMET.  Initialize it below */
		break;
	case CHARPTR:
		conf.ns_pc = (char *)strdup(cp);
		if (conf.ns_pc == NULL) {
			if (tcp != NULL)
				free(tcp);
			return (NS_LDAP_MEMORY);
		}
		break;
	case SAMLIST:
		/* first check to see if colon (:) is there */
		if ((strchr(cp, COLONTOK)) == NULL) {
			(void) snprintf(errstr, sizeof (errstr),
			    gettext("Unable to set value: "
			    "invalid serviceAuthenticationMethod (%s)"),
			    cp);
			MKERROR(LOG_ERR, *error, NS_CONFIG_SYNTAX,
			    strdup(errstr), NULL);
			if (tcp != NULL)
				free(tcp);
			return (NS_LDAP_CONFIG);
		}
		/* Appends an entry to the existing list */
		if (ptr->paramList[type].ns_ptype != SAMLIST) {
			conf.ns_ppc = (char **)calloc(2, sizeof (char *));
			if (conf.ns_ppc == NULL) {
				if (tcp != NULL)
					free(tcp);
				return (NS_LDAP_MEMORY);
			}
			conf.ns_acnt = 1;
			conf.ns_ppc[0] = (char *)strdup(cp);
			if (conf.ns_ppc[0] == NULL) {
				free(conf.ns_ppc);
				if (tcp != NULL)
					free(tcp);
				return (NS_LDAP_MEMORY);
			}
		} else {
			char *dp, *dpend;
			int fnd = 0;

			/* Attempt to replace if possible */
			dpend = strchr(cp, COLONTOK);
			len = dpend - cp;
			dp = (char *)malloc(len+1);
			if (dp == NULL) {
				if (tcp != NULL)
					free(tcp);
				return (NS_LDAP_MEMORY);
			}
			(void) strlcpy(dp, cp, len+1);
			fnd = 0;
			for (j = 0; j < ptr->paramList[type].ns_acnt; j++) {
				dpend = strchr(ptr->paramList[type].ns_ppc[j],
				    COLONTOK);
				if (dpend == NULL)
					continue;
				i = dpend - ptr->paramList[type].ns_ppc[j];
				if (i != len)
					continue;
				if (strncmp(ptr->paramList[type].ns_ppc[j],
				    dp, len) == 0) {
					conf.ns_acnt =
					    ptr->paramList[type].ns_acnt;
					conf.ns_ppc =
					    ptr->paramList[type].ns_ppc;
					ptr->paramList[type].ns_ppc = NULL;
					free(conf.ns_ppc[j]);
					conf.ns_ppc[j] = (char *)strdup(cp);
					if (conf.ns_ppc[j] == NULL) {
						free(dp);
						__s_api_free2dArray
						    (conf.ns_ppc);
						if (tcp != NULL)
							free(tcp);
						return (NS_LDAP_MEMORY);
					}
					fnd = 1;
					break;
				}
			}
			free(dp);

			if (fnd)
				break;	/* Replaced completed */

			/* Append */
			len = ptr->paramList[type].ns_acnt + 1;
			if (len > 1) {
				p = (char **)dupParam(&ptr->paramList[type]);
				if (p == NULL) {
					if (tcp != NULL)
						free(tcp);
					return (NS_LDAP_MEMORY);
				}
			} else
				p = NULL;
			conf.ns_ppc =
			    (char **)realloc(p, (len+1) * sizeof (char *));
			if (conf.ns_ppc == NULL) {
				__s_api_free2dArray(p);
				if (tcp != NULL)
					free(tcp);
				return (NS_LDAP_MEMORY);
			}
			conf.ns_acnt = len;
			conf.ns_ppc[len-1] = (char *)strdup(cp);
			if (conf.ns_ppc[len-1] == NULL) {
				__s_api_free2dArray(conf.ns_ppc);
				if (tcp != NULL)
					free(tcp);
				return (NS_LDAP_MEMORY);
			}
			conf.ns_ppc[len] = NULL;
		}
		break;
	case SCLLIST:
		/* first check to see if colon (:) is there */
		if ((strchr(cp, COLONTOK)) == NULL) {
			(void) snprintf(errstr, sizeof (errstr),
			    gettext("Unable to set value: "
			    "invalid serviceCredentialLevel (%s)"),
			    cp);
			MKERROR(LOG_ERR, *error, NS_CONFIG_SYNTAX,
			    strdup(errstr), NULL);
			if (tcp != NULL)
				free(tcp);
			return (NS_LDAP_CONFIG);
		}
		/* Appends an entry to the existing list */
		if (ptr->paramList[type].ns_ptype != SCLLIST) {
			conf.ns_ppc = (char **)calloc(2, sizeof (char *));
			if (conf.ns_ppc == NULL) {
				if (tcp != NULL)
					free(tcp);
				return (NS_LDAP_MEMORY);
			}
			conf.ns_acnt = 1;
			conf.ns_ppc[0] = (char *)strdup(cp);
			if (conf.ns_ppc[0] == NULL) {
				free(conf.ns_ppc);
				if (tcp != NULL)
					free(tcp);
				return (NS_LDAP_MEMORY);
			}
		} else {
			char *dp, *dpend;
			int fnd = 0;

			/* Attempt to replace if possible */
			dpend = strchr(cp, COLONTOK);
			len = dpend - cp;
			dp = (char *)malloc(len+1);
			if (dp == NULL) {
				if (tcp != NULL)
					free(tcp);
				return (NS_LDAP_MEMORY);
			}
			(void) strlcpy(dp, cp, len+1);
			fnd = 0;
			for (j = 0; j < ptr->paramList[type].ns_acnt; j++) {
				dpend = strchr(ptr->paramList[type].ns_ppc[j],
				    COLONTOK);
				if (dpend == NULL)
					continue;
				i = dpend - ptr->paramList[type].ns_ppc[j];
				if (i != len)
					continue;
				if (strncmp(ptr->paramList[type].ns_ppc[j],
				    dp, len) == 0) {
					conf.ns_acnt =
					    ptr->paramList[type].ns_acnt;
					conf.ns_ppc =
					    ptr->paramList[type].ns_ppc;
					ptr->paramList[type].ns_ppc = NULL;
					free(conf.ns_ppc[j]);
					conf.ns_ppc[j] = (char *)strdup(cp);
					if (conf.ns_ppc[j] == NULL) {
						free(dp);
						__s_api_free2dArray
						    (conf.ns_ppc);
						if (tcp != NULL)
							free(tcp);
						return (NS_LDAP_MEMORY);
					}
					fnd = 1;
					break;
				}
			}
			free(dp);

			if (fnd)
				break;	/* Replaced completed */

			/* Append */
			len = ptr->paramList[type].ns_acnt + 1;
			if (len > 1) {
				p = (char **)dupParam(&ptr->paramList[type]);
				if (p == NULL) {
					if (tcp != NULL)
						free(tcp);
					return (NS_LDAP_MEMORY);
				}
			} else
				p = NULL;
			conf.ns_ppc =
			    (char **)realloc(p, (len+1) * sizeof (char *));
			if (conf.ns_ppc == NULL) {
				__s_api_free2dArray(p);
				if (tcp != NULL)
					free(tcp);
				return (NS_LDAP_MEMORY);
			}
			conf.ns_acnt = len;
			conf.ns_ppc[len-1] = (char *)strdup(cp);
			if (conf.ns_ppc[len-1] == NULL) {
				__s_api_free2dArray(conf.ns_ppc);
				if (tcp != NULL)
					free(tcp);
				return (NS_LDAP_MEMORY);
			}
			conf.ns_ppc[len] = NULL;
		}
		break;
	case SSDLIST:
		/*
		 * first check to see if colon (:) is there,
		 * if so, make sure the serviceId is specified,
		 * i.e., colon is not the first character
		 */
		if ((strchr(cp, COLONTOK)) == NULL || *cp == COLONTOK) {
			(void) snprintf(errstr, sizeof (errstr),
			    gettext("Unable to set value: "
			    "invalid serviceSearchDescriptor (%s)"),
			    cp);
			MKERROR(LOG_ERR, *error, NS_CONFIG_SYNTAX,
			    strdup(errstr), NULL);
			if (tcp != NULL)
				free(tcp);
			return (NS_LDAP_CONFIG);
		}
		/* Appends an entry to the existing list */
		if (ptr->paramList[type].ns_ptype != SSDLIST) {
			conf.ns_ppc = (char **)calloc(2, sizeof (char *));
			if (conf.ns_ppc == NULL) {
				if (tcp != NULL)
					free(tcp);
				return (NS_LDAP_MEMORY);
			}
			conf.ns_acnt = 1;
			conf.ns_ppc[0] = (char *)strdup(cp);
			if (conf.ns_ppc[0] == NULL) {
				free(conf.ns_ppc);
				if (tcp != NULL)
					free(tcp);
				return (NS_LDAP_MEMORY);
			}
		} else {
			char *dp, *dpend;
			int fnd = 0;

			/* Attempt to replace if possible */
			dpend = strchr(cp, COLONTOK);
			len = dpend - cp;
			dp = (char *)malloc(len+1);
			if (dp == NULL) {
				if (tcp != NULL)
					free(tcp);
				return (NS_LDAP_MEMORY);
			}
			(void) strlcpy(dp, cp, len+1);
			fnd = 0;
			for (j = 0; j < ptr->paramList[type].ns_acnt; j++) {
				dpend = strchr(ptr->paramList[type].ns_ppc[j],
				    COLONTOK);
				if (dpend == NULL)
					continue;
				i = dpend - ptr->paramList[type].ns_ppc[j];
				if (i != len)
					continue;
				if (strncmp(ptr->paramList[type].ns_ppc[j],
				    dp, len) == 0) {
					conf.ns_acnt =
					    ptr->paramList[type].ns_acnt;
					conf.ns_ppc =
					    ptr->paramList[type].ns_ppc;
					ptr->paramList[type].ns_ppc = NULL;
					free(conf.ns_ppc[j]);
					conf.ns_ppc[j] = (char *)strdup(cp);
					if (conf.ns_ppc[j] == NULL) {
						free(dp);
						__s_api_free2dArray
						    (conf.ns_ppc);
						if (tcp != NULL)
							free(tcp);
						return (NS_LDAP_MEMORY);
					}
					fnd = 1;
					break;
				}
			}
			free(dp);

			if (fnd)
				break;	/* Replaced completed */

			/* Append */
			len = ptr->paramList[type].ns_acnt + 1;
			if (len > 1) {
				p = (char **)dupParam(&ptr->paramList[type]);
				if (p == NULL) {
					if (tcp != NULL)
						free(tcp);
					return (NS_LDAP_MEMORY);
				}
			} else
				p = NULL;
			conf.ns_ppc =
			    (char **)realloc(p, (len+1) * sizeof (char *));
			if (conf.ns_ppc == NULL) {
				__s_api_free2dArray(p);
				if (tcp != NULL)
					free(tcp);
				return (NS_LDAP_MEMORY);
			}
			conf.ns_acnt = len;
			conf.ns_ppc[len-1] = (char *)strdup(cp);
			if (conf.ns_ppc[len-1] == NULL) {
				__s_api_free2dArray(conf.ns_ppc);
				if (tcp != NULL)
					free(tcp);
				return (NS_LDAP_MEMORY);
			}
			conf.ns_ppc[len] = NULL;
		}
		break;
	case ARRAYCP:
		len = 0;
		for (cp2 = cp; *cp2; cp2++) {
			if (*cp2 == COMMATOK)
				len++;
		}
		if (cp != cp2)
			len++;
		if (len == 0) {
			conf.ns_ppc = (char **)NULL;
			conf.ns_acnt = 0;
			break;
		}
		conf.ns_ppc = (char **)calloc(len + 1, sizeof (char *));
		if (conf.ns_ppc == NULL) {
			if (tcp != NULL)
				free(tcp);
			return (NS_LDAP_MEMORY);
		}
		conf.ns_acnt = len;
		i = 0;
		for (cp2 = cp; *cp2; cp2++) {
			if (*cp2 == COMMATOK) {
				j = cp2 - cp + 1;
				conf.ns_ppc[i] = (char *)malloc(j + 1);
				if (conf.ns_ppc[i] == NULL) {
					__s_api_free2dArray(conf.ns_ppc);
					if (tcp != NULL)
						free(tcp);
					return (NS_LDAP_MEMORY);
				}
				(void) strlcpy(conf.ns_ppc[i], cp, j);
				cp = cp2+1;
				while (*cp == SPACETOK || *cp == COMMATOK)
					cp++;
				cp2 = cp - 1;
				i++;
			}
		}
		j = cp2 - cp + 1;
		conf.ns_ppc[i] = (char *)malloc(j + 1);
		if (conf.ns_ppc[i] == NULL) {
			__s_api_free2dArray(conf.ns_ppc);
			if (tcp != NULL)
				free(tcp);
			return (NS_LDAP_MEMORY);
		}
		(void) strlcpy(conf.ns_ppc[i], cp, j);
		break;
	case SERVLIST:
		len = 0;
		for (cp2 = cp; *cp2; cp2++) {
			if (*cp2 == SPACETOK || *cp2 == COMMATOK) {
				len++;
				for (; *(cp2 + 1) == SPACETOK ||
				    *(cp2 +1) == COMMATOK; cp2++)
					;
			}
		}
		if (cp != cp2)
			len++;
		if (len == 0) {
			conf.ns_ppc = (char **)NULL;
			conf.ns_acnt = 0;
			break;
		}
		conf.ns_ppc = (char **)calloc(len + 1, sizeof (char *));
		if (conf.ns_ppc == NULL) {
			if (tcp != NULL)
				free(tcp);
			return (NS_LDAP_MEMORY);
		}
		conf.ns_acnt = len;
		i = 0;
		for (cp2 = cp; *cp2; cp2++) {
			if (*cp2 == SPACETOK || *cp2 == COMMATOK) {
				j = cp2 - cp + 1;
				conf.ns_ppc[i] = (char *)malloc(j + 1);
				if (conf.ns_ppc[i] == NULL) {
					__s_api_free2dArray(conf.ns_ppc);
					if (tcp != NULL)
						free(tcp);
					return (NS_LDAP_MEMORY);
				}
				(void) strlcpy(conf.ns_ppc[i], cp, j);
				cp = cp2+1;
				while (*cp == SPACETOK || *cp == COMMATOK)
					cp++;
				cp2 = cp - 1;
				i++;
			}
		}
		j = cp2 - cp + 1;
		conf.ns_ppc[i] = (char *)malloc(j + 1);
		if (conf.ns_ppc[i] == NULL) {
			__s_api_free2dArray(conf.ns_ppc);
			if (tcp != NULL)
				free(tcp);
			return (NS_LDAP_MEMORY);
		}
		(void) strlcpy(conf.ns_ppc[i], cp, j);
		break;
	case ARRAYAUTH:
		len = 0;
		for (cp2 = cp; *cp2; cp2++) {
			if (*cp2 == SEMITOK || *cp2 == COMMATOK)
				len++;
		}
		if (cp != cp2)
			len++;
		if (len == 0) {
			conf.ns_pi = (int *)NULL;
			conf.ns_acnt = 0;
			break;
		}
		conf.ns_pi = (int *)calloc(len + 1, sizeof (int));
		if (conf.ns_pi == NULL) {
			if (tcp != NULL)
				free(tcp);
			return (NS_LDAP_MEMORY);
		}
		conf.ns_acnt = len;
		i = 0;
		for (cp2 = cp; *cp2; cp2++) {
			if (*cp2 == SEMITOK || *cp2 == COMMATOK) {
				j = cp2 - cp + 1;
				if (j > sizeof (tbuf)) {
					j = -1;
					ptbuf = cp;
				} else {
					(void) strlcpy(tbuf, cp, j);
					j = __s_get_enum_value(ptr, tbuf,
					    def->index);
					ptbuf = tbuf;
				}
				if (j < 0) {
					(void) snprintf(errstr, sizeof (errstr),
					    gettext("Unable to set value: "
					    "invalid "
					    "authenticationMethod (%s)"),
					    ptbuf);
					MKERROR(LOG_ERR, *error,
					    NS_CONFIG_SYNTAX,
					    strdup(errstr), NULL);
					free(conf.ns_pi);
					if (tcp != NULL)
						free(tcp);
					return (NS_LDAP_CONFIG);
				}
				conf.ns_pi[i] = j;
				cp = cp2+1;
				i++;
			}
		}
		j = cp2 - cp + 1;
		if (j > sizeof (tbuf)) {
			j = -1;
			ptbuf = cp;
		} else {
			(void) strlcpy(tbuf, cp, j);
			j = __s_get_enum_value(ptr, tbuf, def->index);
			ptbuf = tbuf;
		}
		if (j < 0) {
			(void) snprintf(errstr, sizeof (errstr),
			    gettext("Unable to set value: "
			    "invalid authenticationMethod (%s)"), ptbuf);
			MKERROR(LOG_ERR, *error, NS_CONFIG_SYNTAX,
			    strdup(errstr), NULL);
			if (tcp != NULL)
				free(tcp);
			return (NS_LDAP_CONFIG);
		}
		conf.ns_pi[i] = j;
		break;
	case ARRAYCRED:
		len = 0;
		for (cp2 = cp; *cp2; cp2++) {
			if (*cp2 == SPACETOK)
				len++;
		}
		if (cp != cp2)
			len++;
		if (len == 0) {
			conf.ns_pi = (int *)NULL;
			conf.ns_acnt = 0;
			break;
		}
		conf.ns_pi = (int *)calloc(len + 1, sizeof (int));
		if (conf.ns_pi == NULL) {
			if (tcp != NULL)
				free(tcp);
			return (NS_LDAP_MEMORY);
		}
		conf.ns_acnt = len;
		i = 0;
		for (cp2 = cp; *cp2; cp2++) {
			if (*cp2 == SPACETOK) {
				j = cp2 - cp + 1;
				if (j > sizeof (tbuf)) {
					j = -1;
					ptbuf = cp;
				} else {
					(void) strlcpy(tbuf, cp, j);
					j = __s_get_enum_value(ptr, tbuf,
					    def->index);
					ptbuf = tbuf;
				}
				if (j < 0) {
					(void) snprintf(errstr, sizeof (errstr),
					    gettext("Unable to set value: "
					    "invalid credentialLevel (%s)"),
					    ptbuf);
					MKERROR(LOG_ERR, *error,
					    NS_CONFIG_SYNTAX,
					    strdup(errstr), NULL);
					free(conf.ns_pi);
					if (tcp != NULL)
						free(tcp);
					return (NS_LDAP_CONFIG);
				}
				conf.ns_pi[i] = j;
				cp = cp2+1;
				i++;
			}
		}
		j = cp2 - cp + 1;
		if (j > sizeof (tbuf)) {
			j = -1;
			ptbuf = cp;
		} else {
			(void) strlcpy(tbuf, cp, j);
			j = __s_get_enum_value(ptr, tbuf, def->index);
			ptbuf = tbuf;
		}
		if (j < 0) {
			(void) snprintf(errstr, sizeof (errstr),
			    gettext("Unable to set value: "
			    "invalid credentialLevel (%s)"), ptbuf);
			MKERROR(LOG_ERR, *error, NS_CONFIG_SYNTAX,
			    strdup(errstr), NULL);
			if (tcp != NULL)
				free(tcp);
			return (NS_LDAP_CONFIG);
		}
		conf.ns_pi[i] = j;
		break;
	case ATTRMAP:
	case OBJMAP:
		i = __s_api_parse_map(cp, &sid, &origA, &mapA);
		if (i != NS_HASH_RC_SUCCESS) {
			if (i == NS_HASH_RC_NO_MEMORY) {
				exitrc = NS_LDAP_MEMORY;
			} else {
				(void) snprintf(errstr, sizeof (errstr),
				gettext("Unable to set value: "
				"invalid schema mapping (%s)"), cp);
				exitrc = NS_LDAP_CONFIG;
				MKERROR(LOG_ERR, *error, NS_CONFIG_SYNTAX,
				    strdup(errstr), NULL);
			}
			if (tcp)
				free(tcp);
			return (exitrc);
		}

		/*
		 * Add reverse map first.
		 * There could be more than one.
		 */
		for (attr = mapA; *attr; attr++) {

			free_memory = 1;
			exitrc = NS_LDAP_MEMORY;

			rmap = (ns_mapping_t *)calloc(1,
			    sizeof (ns_mapping_t));
			if (rmap) {
				rmap->service = strdup(sid);
				if (rmap->service) {
					rmap->orig = strdup(*attr);
					if (rmap->orig) {
						rmap->map = (char **)calloc(2,
						    sizeof (char *));
						if (rmap->map) {
							(rmap->map)[0] =
							    strdup(origA);
							if ((rmap->map)[0])
								free_memory = 0;
						}
					}
				}
			}

			if (free_memory == 0) {
				if (def->data_type == ATTRMAP) {
					rmap->type = NS_ATTR_MAP;
					i = __s_api_add_map2hash(ptr,
					    NS_HASH_RAMAP, rmap);
				} else {
					rmap->type = NS_OBJ_MAP;
					i = __s_api_add_map2hash(ptr,
					    NS_HASH_ROMAP, rmap);
				}

				if (i != NS_HASH_RC_SUCCESS) {
					switch (i) {
					case NS_HASH_RC_CONFIG_ERROR:
						exitrc = NS_LDAP_INTERNAL;
						(void) snprintf(errstr,
						    sizeof (errstr),
						    gettext(
						    "Unable to set value: "
						    "no configuration info "
						    "for schema map "
						    "update (%s)"), cp);
						MKERROR(LOG_ERR, *error,
						    NS_LDAP_INTERNAL,
						    strdup(errstr),
						    NULL);
						break;
					case NS_HASH_RC_EXISTED:
						exitrc = NS_LDAP_CONFIG;
						(void) snprintf(errstr,
						    sizeof (errstr),
						    gettext(
						    "Unable to set value: "
						    "schema map "
						    "already existed for "
						    "(%s, %s)."),
						    *attr, origA);
						MKERROR(LOG_ERR, *error,
						    NS_CONFIG_SYNTAX,
						    strdup(errstr),
						    NULL);
						break;
					case NS_HASH_RC_NO_MEMORY:
						exitrc = NS_LDAP_MEMORY;
						break;
					}
					free_memory = 1;
				}
			}

			if (free_memory) {
				if (tcp)
					free(tcp);
				free(sid);
				free(origA);
				__s_api_free2dArray(mapA);
				if (rmap) {
					if (rmap->service)
						free(rmap->service);
					if (rmap->orig)
						free(rmap->orig);
					if (rmap->map) {
						if ((rmap->map)[0])
							free((rmap->map)[0]);
						free(rmap->map);
					}
					free(rmap);
				}
				return (exitrc);
			}
		}

		/*
		 * For performance gain,
		 * add a "schema mapping existed" indicator
		 * for the given service if not already added.
		 * This dummy map needs not be removed, if
		 * the next real map add operation fails.
		 * since the caller, e.g. ldap_cachemgr.
		 * should exit anyway.
		 */
		free_memory = 1;
		exitrc = NS_LDAP_MEMORY;

		map = (ns_mapping_t *)calloc(1,
		    sizeof (ns_mapping_t));
		if (map) {
			map->service = strdup(sid);
			if (map->service) {
				map->orig = strdup(
				    NS_HASH_SCHEMA_MAPPING_EXISTED);
				if (map->orig) {
					map->map = (char **)calloc(2,
					    sizeof (char *));
					if (map->map) {
						(map->map)[0] =
						    strdup(sid);
						if ((map->map)[0])
							free_memory = 0;
					}
				}
			}
		}

		if (free_memory == 0) {
			map->type = NS_ATTR_MAP;
			/*
			 * add to reverse map,
			 * so that "ldapclient list"
			 * would not show it
			 */
			i = __s_api_add_map2hash(ptr,
			    NS_HASH_RAMAP, map);

			/*
			 * ignore "map already existed" error,
			 * just need one per service.
			 * Need however to free memory allocated
			 * for map.
			 */
			if (i != NS_HASH_RC_SUCCESS &&
			    i != NS_HASH_RC_EXISTED) {
				switch (i) {
				case NS_HASH_RC_CONFIG_ERROR:
					exitrc = NS_LDAP_INTERNAL;
					(void) snprintf(errstr,
					    sizeof (errstr),
					    gettext(
					    "Unable to set value: "
					    "no configuration info "
					    "for schema map "
					    "update (%s)"), cp);
					MKERROR(LOG_ERR, *error,
					    NS_LDAP_INTERNAL,
					    strdup(errstr),
					    NULL);
					break;
				case NS_HASH_RC_NO_MEMORY:
					exitrc = NS_LDAP_MEMORY;
					break;
				}
				free_memory = 1;
			} else if (i == NS_HASH_RC_EXISTED) {
				if (map->service)
					free(map->service);
				if (map->orig)
					free(map->orig);
				if (map->map) {
					if ((map->map)[0])
						free((map->map)[0]);
					free(map->map);
				}
				free(map);
				map = NULL;
			}
		}

		if (free_memory) {
			if (tcp)
				free(tcp);
			free(sid);
			free(origA);
			__s_api_free2dArray(mapA);
			if (map) {
				if (map->service)
					free(map->service);
				if (map->orig)
					free(map->orig);
				if (map->map) {
					if ((map->map)[0])
						free((map->map)[0]);
					free(map->map);
				}
				free(map);
			}
			return (exitrc);
		}

		/*
		 * add the real schema map
		 */
		free_memory = 1;
		exitrc = NS_LDAP_MEMORY;
		map = (ns_mapping_t *)calloc(1, sizeof (ns_mapping_t));
		if (map) {
			map->service = sid;
			map->orig = origA;
			map->map = mapA;

			if (def->data_type == ATTRMAP) {
				map->type = NS_ATTR_MAP;
				i = __s_api_add_map2hash(ptr,
				    NS_HASH_AMAP, map);
			} else {
				map->type = NS_OBJ_MAP;
				i = __s_api_add_map2hash(ptr,
				    NS_HASH_OMAP, map);
			}

			if (i != NS_HASH_RC_SUCCESS) {
				switch (i) {
				case NS_HASH_RC_CONFIG_ERROR:
					exitrc = NS_LDAP_INTERNAL;
					(void) snprintf(errstr,
					    sizeof (errstr),
					    gettext(
					    "Unable to set value: "
					    "no configuration info "
					    "for schema map "
					    "update (%s)"), cp);
					MKERROR(LOG_ERR, *error,
					    NS_LDAP_INTERNAL,
					    strdup(errstr),
					    NULL);
					break;
				case NS_HASH_RC_EXISTED:
					exitrc = NS_LDAP_CONFIG;
					(void) snprintf(errstr,
					    sizeof (errstr),
					    gettext(
					    "Unable to set value: "
					    "schema map "
					    "already existed for "
					    "'%s'."), origA);
					MKERROR(LOG_ERR, *error,
					    NS_CONFIG_SYNTAX,
					    strdup(errstr),
					    NULL);
					break;
				case NS_HASH_RC_NO_MEMORY:
					exitrc = NS_LDAP_MEMORY;
					break;
				}
				free_memory = 1;
			} else
				free_memory = 0;
		}

		if (free_memory) {
			if (tcp)
				free(tcp);
			free(sid);
			free(origA);
			__s_api_free2dArray(mapA);
			if (map)
				free(map);
			return (exitrc);
		}

		break;
	default:
		/* This should never happen. */
		(void) snprintf(errstr, sizeof (errstr),
		    gettext("Unable to set value: invalid configuration "
		    "type (%d)"), def->data_type);
		MKERROR(LOG_ERR, *error, NS_CONFIG_SYNTAX, strdup(errstr),
		    NULL);
		if (tcp != NULL)
			free(tcp);
		return (NS_LDAP_CONFIG);
	}
	conf.ns_ptype = def->data_type;
	if (tcp != NULL)
		free(tcp);

	/* Individually written verify routines here can replace */
	/* verify_value.  Verify conf (data) as appropriate here */
	if (def->ns_verify != NULL) {
		if ((*def->ns_verify)(type, def, &conf, errstr) != NS_SUCCESS) {
			ns_param_t sav_conf;

			(void) snprintf(errstr, sizeof (errstr),
			    gettext("%s"), errstr);
			MKERROR(LOG_WARNING, *error, NS_CONFIG_SYNTAX,
			    strdup(errstr), NULL);

			sav_conf = ptr->paramList[type];
			ptr->paramList[type] = conf;
			destroy_param(ptr, type);
			ptr->paramList[type] = sav_conf;

			return (NS_LDAP_CONFIG);
		}
	}

	/* post evaluate the data */

	/*
	 * if this is for setting a password,
	 * encrypt the password first.
	 * NOTE evalue() is smart and will just return
	 * the value passed if it is already encrypted.
	 *
	 * Init NS_LDAP_EXP_P here when CACHETTL is updated
	 */
	if (type == NS_LDAP_BINDPASSWD_P ||
	    type == NS_LDAP_ADMIN_BINDPASSWD_P) {
		cp = conf.ns_pc;
		cp2 = evalue((char *)cp);
		conf.ns_pc = cp2;
		free(cp);
		cp = NULL;
	} else if (type == NS_LDAP_FILE_VERSION_P) {
		ptr->version = NS_LDAP_V1;
		if (strcasecmp(conf.ns_pc, NS_LDAP_VERSION_2) == 0) {
			ptr->version = NS_LDAP_V2;
		}
	} else if (type == NS_LDAP_CACHETTL_P) {
		cp = conf.ns_pc;
		tm = conv_time(cp);
		ptr->paramList[NS_LDAP_EXP_P].ns_ptype = TIMET;
		if (tm != 0) {
			tm += time(NULL);
		}
		ptr->paramList[NS_LDAP_EXP_P].ns_tm = tm;
	}

	/* Everything checks out move new values into param */
	destroy_param(ptr, type);
	/* Assign new/updated value into paramList */
	ptr->paramList[type] = conf;

	return (NS_LDAP_SUCCESS);
}


/*
 * Set a parameter value in the 'config' configuration structure
 * Lock as appropriate
 */

int
__ns_ldap_setParam(const ParamIndexType type,
    const void *data, ns_ldap_error_t **error)
{
	ns_ldap_error_t		*errorp;
	int			ret;
	char			errstr[2 * MAXERROR];
	ns_config_t		*cfg;
	ns_config_t		*cfg_g = (ns_config_t *)-1;
	ns_config_t		*new_cfg;
	boolean_t		reinit_connmgmt = B_FALSE;

	/* We want to refresh only one configuration at a time */
	(void) mutex_lock(&ns_loadrefresh_lock);
	cfg = __s_api_get_default_config();

	if (cache_server == TRUE) {
		if (cfg == NULL) {
			__ns_ldap_default_config();
			cfg = __s_api_get_default_config();
			if (cfg == NULL) {
				(void) mutex_unlock(&ns_loadrefresh_lock);
				return (NS_LDAP_MEMORY);
			}
		}
	} else {
		/*
		 * This code always return error here on client side,
		 * this needs to change once libsldap is used by more
		 * applications that need to set parameters.
		 */
		(void) snprintf(errstr, sizeof (errstr),
		    gettext("Unable to set parameter from a client in "
		    "__ns_ldap_setParam()"));
		MKERROR(LOG_WARNING, *error, NS_CONFIG_SYNTAX, strdup(errstr),
		    NULL);
		if (cfg != NULL)
			__s_api_release_config(cfg);
		(void) mutex_unlock(&ns_loadrefresh_lock);
		return (NS_LDAP_CONFIG);
	}

	/* (re)initialize configuration if necessary */
	if (!__s_api_isStandalone() &&
	    cache_server == FALSE && timetorefresh(cfg))
		cfg_g = __s_api_get_default_config_global();
	/* only (re)initialize the global configuration */
	if (cfg == cfg_g) {
		if (cfg_g != NULL)
			__s_api_release_config(cfg_g);
		new_cfg = LoadCacheConfiguration(cfg, &errorp);
		if (new_cfg != cfg)
			__s_api_release_config(cfg);
		if (new_cfg == NULL) {
			(void) snprintf(errstr, sizeof (errstr),
			    gettext("Unable to load configuration '%s' "
			    "('%s')."), NSCONFIGFILE,
			    errorp != NULL && errorp->message != NULL ?
			    errorp->message : "");
			MKERROR(LOG_WARNING, *error, NS_CONFIG_NOTLOADED,
			    strdup(errstr), NULL);
			if (errorp != NULL)
				(void) __ns_ldap_freeError(&errorp);
			(void) mutex_unlock(&ns_loadrefresh_lock);
			return (NS_LDAP_CONFIG);
		}
		if (new_cfg != cfg) {
			set_curr_config_global(new_cfg);
			cfg = new_cfg;
			reinit_connmgmt = B_TRUE;
		}
	}
	(void) mutex_unlock(&ns_loadrefresh_lock);

	if (reinit_connmgmt == B_TRUE)
		__s_api_reinit_conn_mgmt_new_config(cfg);

	/* translate input and save in the parameter list */
	ret = __ns_ldap_setParamValue(cfg, type, data, error);

	__s_api_release_config(cfg);

	return (ret);
}


/*
 * Make a copy of a parameter entry
 */

static void **
dupParam(ns_param_t *ptr)
{
	int		count, i;
	void		**dupdata, *ret;
	int		*intptr;
	char		*cp, tmbuf[32];
	static time_t	expire = 0;
	ns_auth_t	*ap;

	switch (ptr->ns_ptype) {
	case ARRAYAUTH:
	case ARRAYCRED:
	case SAMLIST:
	case SCLLIST:
	case SSDLIST:
	case SERVLIST:
	case ARRAYCP:
		count = ptr->ns_acnt;
		if (count == 0)
			return (NULL);
		break;
	case CHARPTR:
	case INT:
	case TIMET:
		count = 1;
	}

	dupdata = (void **)calloc((count + 1), sizeof (void *));
	if (dupdata == NULL)
		return (NULL);

	switch (ptr->ns_ptype) {
	case ARRAYAUTH:
		for (i = 0; i < count; i++) {
			ap = __s_api_AuthEnumtoStruct(
			    (EnumAuthType_t)ptr->ns_pi[i]);
			if (ap == NULL) {
				free(dupdata);
				return (NULL);
			}
			dupdata[i] = ap;
		}
		break;
	case ARRAYCRED:
		for (i = 0; i < count; i++) {
			intptr = (int *)malloc(sizeof (int));
			if (intptr == NULL) {
				free(dupdata);
				return (NULL);
			}
			dupdata[i] = (void *)intptr;
			*intptr = ptr->ns_pi[i];
		}
		break;
	case SAMLIST:
	case SCLLIST:
	case SSDLIST:
	case SERVLIST:
	case ARRAYCP:
		for (i = 0; i < count; i++) {
			ret = (void *)strdup(ptr->ns_ppc[i]);
			if (ret == NULL) {
				free(dupdata);
				return (NULL);
			}
			dupdata[i] = ret;
		}
		break;
	case CHARPTR:
		if (ptr->ns_pc == NULL) {
			free(dupdata);
			return (NULL);
		}
		ret = (void *)strdup(ptr->ns_pc);
		if (ret == NULL) {
			free(dupdata);
			return (NULL);
		}
		dupdata[0] = ret;
		break;
	case INT:
		intptr = (int *)malloc(sizeof (int));
		if (intptr == NULL) {
			free(dupdata);
			return (NULL);
		}
		*intptr = ptr->ns_i;
		dupdata[0] = (void *)intptr;
		break;
	case TIMET:
		expire = ptr->ns_tm;
		tmbuf[31] = '\0';
		cp = lltostr((long)expire, &tmbuf[31]);
		ret = (void *)strdup(cp);
		if (ret == NULL) {
			free(dupdata);
			return (NULL);
		}
		dupdata[0] = ret;
		break;
	}
	return (dupdata);
}

int
__ns_ldap_freeParam(void ***data)
{
	void	**tmp;
	int	i = 0;

	if (*data == NULL)
		return (NS_LDAP_SUCCESS);

	for (i = 0, tmp = *data; tmp[i] != NULL; i++)
		free(tmp[i]);

	free(*data);

	*data = NULL;

	return (NS_LDAP_SUCCESS);
}

/*
 * Get the internal format for a parameter value.  This
 * routine makes a copy of an internal param value from
 * the currently active parameter list and returns it.
 */

int
__ns_ldap_getParam(const ParamIndexType Param,
    void ***data, ns_ldap_error_t **error)
{
	char			errstr[2 * MAXERROR];
	ns_ldap_error_t		*errorp;
	ns_default_config	*def;
	ns_config_t		*cfg;
	ns_config_t		*cfg_g = (ns_config_t *)-1;
	ns_config_t		*new_cfg;
	boolean_t		reinit_connmgmt = B_FALSE;

	if (data == NULL)
		return (NS_LDAP_INVALID_PARAM);

	*data = NULL;

	/* We want to refresh only one configuration at a time */
	(void) mutex_lock(&ns_loadrefresh_lock);
	cfg = __s_api_get_default_config();

	/* (re)initialize configuration if necessary */
	if (!__s_api_isStandalone() &&
	    cache_server == FALSE && timetorefresh(cfg))
		cfg_g = __s_api_get_default_config_global();
	/* only (re)initialize the global configuration */
	if (cfg == cfg_g) {
		if (cfg_g != NULL)
			__s_api_release_config(cfg_g);
		new_cfg = LoadCacheConfiguration(cfg, &errorp);
		if (new_cfg != cfg)
			__s_api_release_config(cfg);
		if (new_cfg == NULL) {
			(void) snprintf(errstr, sizeof (errstr),
			    gettext("Unable to load configuration "
			    "'%s' ('%s')."),
			    NSCONFIGFILE,
			    errorp != NULL && errorp->message != NULL ?
			    errorp->message : "");
			MKERROR(LOG_WARNING, *error, NS_CONFIG_NOTLOADED,
			    strdup(errstr), NULL);
			if (errorp != NULL)
				(void) __ns_ldap_freeError(&errorp);
			(void) mutex_unlock(&ns_loadrefresh_lock);
			return (NS_LDAP_CONFIG);
		}
		if (new_cfg != cfg) {
			set_curr_config_global(new_cfg);
			cfg = new_cfg;
			reinit_connmgmt = B_TRUE;
		}
	}
	(void) mutex_unlock(&ns_loadrefresh_lock);

	if (reinit_connmgmt == B_TRUE)
		__s_api_reinit_conn_mgmt_new_config(cfg);

	if (cfg == NULL) {
		(void) snprintf(errstr, sizeof (errstr),
		    gettext("No configuration information available."));
		MKERROR(LOG_ERR, *error, NS_CONFIG_NOTLOADED,
		    strdup(errstr), NULL);
		return (NS_LDAP_CONFIG);
	}

	if (Param == NS_LDAP_DOMAIN_P) {
		*data = (void **)calloc(2, sizeof (void *));
		if (*data == NULL) {
			__s_api_release_config(cfg);
			return (NS_LDAP_MEMORY);
		}
		(*data)[0] = (void *)strdup(cfg->domainName);
		if ((*data)[0] == NULL) {
			free(*data);
			__s_api_release_config(cfg);
			return (NS_LDAP_MEMORY);
		}
	} else if (cfg->paramList[Param].ns_ptype == NS_UNKNOWN) {
		/* get default */
		def = get_defconfig(cfg, Param);
		if (def != NULL)
			*data = dupParam(&def->defval);
	} else {
		*data = dupParam(&(cfg->paramList[Param]));
	}
	__s_api_release_config(cfg);

	return (NS_LDAP_SUCCESS);
}

/*
 * This routine takes a parameter in internal format and
 * translates it into a variety of string formats for various
 * outputs (doors/file/ldif).  This routine would be better
 * named: __ns_ldap_translateParam2String
 */

char *
__s_api_strValue(ns_config_t *cfg, ParamIndexType index, ns_strfmt_t fmt)
{
	ns_default_config *def = NULL;
	ns_param_t	*ptr;
	ns_hash_t	*hptr;
	ns_mapping_t	*mptr;
	char		ibuf[14];
	char		abuf[64], **cpp;
	int		count, i;
	boolean_t	first = B_TRUE;
	LineBuf		lbuf;
	LineBuf		*buffer = &lbuf;
	char		*retstring;
	char		*sepstr;

	if (cfg == NULL)
		return (NULL);

	/* NS_LDAP_EXP and TRANSPORT_SEC are not exported externally */
	if (index == NS_LDAP_EXP_P || index == NS_LDAP_TRANSPORT_SEC_P)
		return (NULL);

	/* Return nothing if the value is the default */
	if (cfg->paramList[index].ns_ptype == NS_UNKNOWN)
		return (NULL);

	(void) memset((char *)buffer, 0, sizeof (LineBuf));

	ptr = &(cfg->paramList[index]);

	abuf[0] = '\0';

	/* get default */
	def = get_defconfig(cfg, index);
	if (def == NULL)
		return (NULL);

	switch (fmt) {
	case NS_DOOR_FMT:
		(void) strlcpy(abuf, def->name, sizeof (abuf));
		(void) strlcat(abuf, EQUALSEP, sizeof (abuf));
		break;
	case NS_FILE_FMT:
		(void) strlcpy(abuf, def->name, sizeof (abuf));
		(void) strlcat(abuf, EQUSPSEP, sizeof (abuf));
		break;
	case NS_LDIF_FMT:
		/* If no LDIF attr exists ignore the entry */
		if (def->profile_name == NULL)
			return (NULL);
		(void) strlcpy(abuf, def->profile_name, sizeof (abuf));
		(void) strlcat(abuf, COLSPSEP, sizeof (abuf));
		break;
	default:
		break;
	}

	if (__print2buf(buffer, abuf, NULL))
		goto strValueError;

	switch (ptr->ns_ptype) {
	case ARRAYAUTH:
		count = ptr->ns_acnt;
		for (i = 0; i < count; i++) {
			sepstr = NULL;
			if (i != count-1) {
				if (cfg->version == NS_LDAP_V1) {
					sepstr = COMMASEP;
				} else {
					sepstr = SEMISEP;
				}
			}
			if (__print2buf(buffer, __s_get_auth_name(cfg,
			    (AuthType_t)(ptr->ns_pi[i])), sepstr))
				goto strValueError;
		}
		break;
	case ARRAYCRED:
		count = ptr->ns_acnt;
		for (i = 0; i < count; i++) {
			sepstr = NULL;
			if (i != count-1) {
				sepstr = SPACESEP;
			}
			if (__print2buf(buffer, __s_get_credlvl_name(cfg,
			    (CredLevel_t)ptr->ns_pi[i]), sepstr))
				goto strValueError;
		}
		break;
	case SAMLIST:
	case SCLLIST:
	case SSDLIST:
		count = ptr->ns_acnt;
		for (i = 0; i < count; i++) {
			if (__print2buf(buffer, ptr->ns_ppc[i], NULL))
				goto strValueError;

			if (i == count-1)
				continue;

			/* Separate items */
			switch (fmt) {
			case NS_DOOR_FMT:
				if (__print2buf(buffer, DOORLINESEP, NULL) ||
				    __print2buf(buffer, def->name, EQUALSEP))
					goto strValueError;
				break;
			case NS_FILE_FMT:
				if (__print2buf(buffer, "\n", NULL) ||
				    __print2buf(buffer, def->name, EQUSPSEP))
					goto strValueError;
				break;
			case NS_LDIF_FMT:
				if (__print2buf(buffer, "\n", NULL) ||
				    __print2buf(buffer, def->profile_name,
				    COLSPSEP))
					goto strValueError;
				break;
			}
		}
		break;
	case ARRAYCP:
		count = ptr->ns_acnt;
		for (i = 0; i < count; i++) {
			sepstr = NULL;
			if (i != count-1) {
				sepstr = COMMASEP;
			}
			if (__print2buf(buffer, ptr->ns_ppc[i], sepstr))
				goto strValueError;
		}
		break;
	case SERVLIST:
		count = ptr->ns_acnt;
		for (i = 0; i < count; i++) {
			sepstr = NULL;
			if (i != count-1) {
				if (fmt == NS_LDIF_FMT) {
					sepstr = SPACESEP;
				} else {
					sepstr = COMMASEP;
				}
			}
			if (__print2buf(buffer, ptr->ns_ppc[i], sepstr))
				goto strValueError;
		}
		break;
	case CHARPTR:
		if (ptr->ns_pc == NULL)
			break;
		if (__print2buf(buffer, ptr->ns_pc, NULL))
			goto strValueError;
		break;
	case INT:
		switch (def->index) {
		case NS_LDAP_PREF_ONLY_P:
			if (__print2buf(buffer,
			    __s_get_pref_name((PrefOnly_t)ptr->ns_i), NULL))
				goto strValueError;
			break;
		case NS_LDAP_SEARCH_REF_P:
			if (__print2buf(buffer, __s_get_searchref_name(cfg,
			    (SearchRef_t)ptr->ns_i), NULL))
				goto strValueError;
			break;
		case NS_LDAP_SEARCH_SCOPE_P:
			if (__print2buf(buffer,  __s_get_scope_name(cfg,
			    (ScopeType_t)ptr->ns_i), NULL))
				goto strValueError;
			break;
		case NS_LDAP_ENABLE_SHADOW_UPDATE_P:
			if (__print2buf(buffer, __s_get_shadowupdate_name(
			    (enableShadowUpdate_t)ptr->ns_i), NULL))
				goto strValueError;
			break;
		default:
			(void) snprintf(ibuf, sizeof (ibuf),
			    "%d", ptr->ns_i);
			if (__print2buf(buffer, ibuf, NULL))
				goto strValueError;
			break;
		}
		break;
	case ATTRMAP:
		for (hptr = cfg->llHead; hptr; hptr = hptr->h_llnext) {
			if (hptr->h_type != NS_HASH_AMAP) {
				continue;
			}
			if (!first) {
				/* print abuf as "separator" */
				if (fmt == NS_DOOR_FMT) {
					if (__print2buf(buffer, DOORLINESEP,
					    abuf))
						goto strValueError;
				} else {
					if (__print2buf(buffer, "\n", abuf))
						goto strValueError;
				}
			}
			mptr = hptr->h_map;
			if (__print2buf(buffer, mptr->service, COLONSEP) ||
			    __print2buf(buffer, mptr->orig, EQUALSEP))
				goto strValueError;
			for (cpp = mptr->map; cpp && *cpp; cpp++) {
				/* print *cpp as "separator" */
				sepstr = "";
				if (cpp != mptr->map)
					sepstr = SPACESEP;
				if (__print2buf(buffer, sepstr, *cpp))
					goto strValueError;
			}
			first = B_FALSE;
		}
		break;
	case OBJMAP:
		for (hptr = cfg->llHead; hptr; hptr = hptr->h_llnext) {
			if (hptr->h_type != NS_HASH_OMAP) {
				continue;
			}
			if (!first) {
				/* print abuf as "separator" */
				if (fmt == NS_DOOR_FMT) {
					if (__print2buf(buffer, DOORLINESEP,
					    abuf))
						goto strValueError;
				} else {
					if (__print2buf(buffer, "\n", abuf))
						goto strValueError;
				}
			}
			mptr = hptr->h_map;
			if (__print2buf(buffer, mptr->service, COLONSEP) ||
			    __print2buf(buffer, mptr->orig, EQUALSEP))
				goto strValueError;
			for (cpp = mptr->map; cpp && *cpp; cpp++) {
				/* print *cpp as "separator" */
				sepstr = "";
				if (cpp != mptr->map)
					sepstr = SPACESEP;
				if (__print2buf(buffer, sepstr, *cpp))
					goto strValueError;
			}
			first = B_FALSE;
		}
		break;
	}

	retstring = buffer->str;
	return (retstring);

strValueError:
	if (buffer->len > 0)
		free(buffer->str);
	return (NULL);
}

/* shared by __door_getldapconfig() and __door_getadmincred() */
int
__door_getconf(char **buffer, int *buflen, ns_ldap_error_t **error,
    int callnumber)
{
	typedef union {
		ldap_data_t	s_d;
		char		s_b[DOORBUFFERSIZE];
	} space_t;
	space_t			*space;

	ldap_data_t		*sptr;
	int			ndata;
	int			adata;
	char			errstr[MAXERROR];
	char			*domainname;
	ns_ldap_return_code	retCode;
	ldap_config_out_t	*cfghdr;

	*error = NULL;

	domainname = __getdomainname();
	if (domainname == NULL || buffer == NULL || buflen == NULL ||
	    (strlen(domainname) >= (sizeof (space_t)
	    - sizeof (space->s_d.ldap_call.ldap_callnumber)))) {
		return (NS_LDAP_OP_FAILED);
	}

	space = (space_t *)calloc(1, sizeof (space_t));
	if (space == NULL)
		return (NS_LDAP_MEMORY);

	adata = (sizeof (ldap_call_t) + strlen(domainname) +1);
	ndata = sizeof (space_t);
	space->s_d.ldap_call.ldap_callnumber = callnumber;
	(void) strcpy(space->s_d.ldap_call.ldap_u.domainname, domainname);
	free(domainname);
	domainname = NULL;
	sptr = &space->s_d;

	switch (__ns_ldap_trydoorcall(&sptr, &ndata, &adata)) {
	case NS_CACHE_SUCCESS:
		break;
	case NS_CACHE_NOTFOUND:
		(void) snprintf(errstr, sizeof (errstr),
		    gettext("Door call to "
		    "ldap_cachemgr failed - error: %d."),
		    space->s_d.ldap_ret.ldap_errno);
		MKERROR(LOG_WARNING, *error, NS_CONFIG_CACHEMGR,
		    strdup(errstr), NULL);
		free(space);
		return (NS_LDAP_OP_FAILED);
	default:
		free(space);
		return (NS_LDAP_OP_FAILED);
	}

	retCode = NS_LDAP_SUCCESS;

	/* copy info from door call to buffer here */
	cfghdr = &sptr->ldap_ret.ldap_u.config_str;
	*buflen = offsetof(ldap_config_out_t, config_str) +
	    cfghdr->data_size + 1;
	*buffer = calloc(*buflen, sizeof (char));
	if (*buffer == NULL) {
		retCode = NS_LDAP_MEMORY;
	} else
		(void) memcpy(*buffer, cfghdr, *buflen - 1);

	if (sptr != &space->s_d) {
		(void) munmap((char *)sptr, ndata);
	}
	free(space);

	return (retCode);
}

static int
__door_getldapconfig(char **buffer, int *buflen, ns_ldap_error_t **error)
{
	return (__door_getconf(buffer, buflen, error, GETLDAPCONFIGV1));
}

/*
 * SetDoorInfoToUnixCred parses ldapcachemgr configuration information
 * for Admin credentials.
 */
int
SetDoorInfoToUnixCred(char *buffer, ns_ldap_error_t **errorp,
    UnixCred_t **cred)
{
	UnixCred_t	*ptr;
	char		errstr[MAXERROR];
	char		*name, *value, valbuf[BUFSIZE];
	char		*bufptr = buffer;
	char		*strptr;
	char		*rest;
	ParamIndexType	index = 0;
	ldap_config_out_t	*cfghdr;

	if (errorp == NULL || cred == NULL || *cred == NULL)
		return (NS_LDAP_INVALID_PARAM);
	*errorp = NULL;

	ptr = *cred;

	cfghdr = (ldap_config_out_t *)bufptr;
	bufptr = (char *)cfghdr->config_str;

	strptr = (char *)strtok_r(bufptr, DOORLINESEP, &rest);
	for (; ; ) {
		if (strptr == NULL)
			break;
		(void) strlcpy(valbuf, strptr, sizeof (valbuf));
		__s_api_split_key_value(valbuf, &name, &value);
		if (__ns_ldap_getParamType(name, &index) != 0) {
			(void) snprintf(errstr, MAXERROR,
			    gettext("SetDoorInfoToUnixCred: "
			    "Unknown keyword encountered '%s'."), name);
			MKERROR(LOG_ERR, *errorp, NS_CONFIG_SYNTAX,
			    strdup(errstr), NULL);
			return (NS_LDAP_CONFIG);
		}
		switch (index) {
		case NS_LDAP_ADMIN_BINDDN_P:
			ptr->userID = (char *)strdup(value);
			break;
		case NS_LDAP_ADMIN_BINDPASSWD_P:
			ptr->passwd = (char *)strdup(value);
			break;
		default:
			(void) snprintf(errstr, MAXERROR,
			    gettext("SetDoorInfoToUnixCred: "
			    "Unknown index encountered '%d'."), index);
			MKERROR(LOG_ERR, *errorp, NS_CONFIG_SYNTAX,
			    strdup(errstr), NULL);
			return (NS_LDAP_CONFIG);
		}
		strptr = (char *)strtok_r(NULL, DOORLINESEP, &rest);
	}

	return (NS_LDAP_SUCCESS);
}

/*
 * SetDoorInfo parses ldapcachemgr configuration information
 * and verifies that the profile is version 1 or version 2 based.
 * version 2 profiles must have a version number as the first profile
 * attribute in the configuration.
 */
static ns_config_t *
SetDoorInfo(char *buffer, ns_ldap_error_t **errorp)
{
	ns_config_t	*ptr;
	char		errstr[MAXERROR], errbuf[MAXERROR];
	char		*name, *value, valbuf[BUFSIZE];
	char		*strptr;
	char		*rest;
	char		*bufptr = buffer;
	ParamIndexType	i;
	int		ret;
	int		first = 1;
	int		errfnd = 0;
	ldap_config_out_t *cfghdr;

	if (errorp == NULL)
		return (NULL);
	*errorp = NULL;

	ptr = __s_api_create_config();
	if (ptr == NULL) {
		return (NULL);
	}

	/* get config cookie from the header */
	cfghdr = (ldap_config_out_t *)bufptr;
	ptr->config_cookie = cfghdr->cookie;
	bufptr = (char *)cfghdr->config_str;

	strptr = (char *)strtok_r(bufptr, DOORLINESEP, &rest);
	for (; ; ) {
		if (strptr == NULL)
			break;
		(void) strlcpy(valbuf, strptr, sizeof (valbuf));
		__s_api_split_key_value(valbuf, &name, &value);
		/* Use get_versiontype and check for V1 vs V2 prototypes */
		if (__s_api_get_versiontype(ptr, name, &i) < 0) {
			(void) snprintf(errstr, sizeof (errstr),
			    "%s (%s)\n",
			    gettext("Illegal profile entry "
			    "line in configuration."),
			    name);
			errfnd++;
		/* Write verify routines and get rid of verify_value here */
		} else if (verify_value(ptr, name,
		    value, errbuf) != NS_SUCCESS) {
			(void) snprintf(errstr, sizeof (errstr),
			    gettext("%s\n"), errbuf);
			errfnd++;
		} else if (!first && i == NS_LDAP_FILE_VERSION_P) {
			(void) snprintf(errstr, sizeof (errstr),
			    gettext("Illegal NS_LDAP_FILE_VERSION "
			    "line in configuration.\n"));
			errfnd++;
		}
		if (errfnd) {
			MKERROR(LOG_ERR, *errorp, NS_CONFIG_SYNTAX,
			    strdup(errstr), NULL);
		} else {
			ret = set_default_value(ptr, name, value, errorp);
		}
		if (errfnd || ret != NS_SUCCESS) {
			__s_api_destroy_config(ptr);
			return (NULL);
		}
		first = 0;

		strptr = (char *)strtok_r(NULL, DOORLINESEP, &rest);
	}

	if (__s_api_crosscheck(ptr, errstr, B_TRUE) != NS_SUCCESS) {
		__s_api_destroy_config(ptr);
		MKERROR(LOG_WARNING, *errorp, NS_CONFIG_SYNTAX, strdup(errstr),
		    NULL);
		return (NULL);
	}

	return (ptr);
}

static ns_config_t *
LoadCacheConfiguration(ns_config_t *oldcfg, ns_ldap_error_t **error)
{
	char		*buffer = NULL;
	int		buflen = 0;
	int		ret;
	ns_config_t	*cfg;
	ldap_config_out_t *cfghdr;
	ldap_get_chg_cookie_t old_cookie;
	ldap_get_chg_cookie_t new_cookie;

	*error = NULL;
	ret = __door_getldapconfig(&buffer, &buflen, error);

	if (ret != NS_LDAP_SUCCESS) {
		if (*error != NULL && (*error)->message != NULL)
			syslog(LOG_WARNING, "libsldap: %s", (*error)->message);
		return (NULL);
	}

	/* No need to reload configuration if config cookie is the same */
	cfghdr = (ldap_config_out_t *)buffer;
	new_cookie = cfghdr->cookie;
	if (oldcfg != NULL)
		old_cookie = oldcfg->config_cookie;

	if (oldcfg != NULL && old_cookie.mgr_pid == new_cookie.mgr_pid &&
	    old_cookie.seq_num == new_cookie.seq_num) {
		free(buffer);
		return (oldcfg);
	}

	/* now convert from door format */
	cfg = SetDoorInfo(buffer, error);
	free(buffer);

	if (cfg == NULL && *error != NULL && (*error)->message != NULL)
		syslog(LOG_WARNING, "libsldap: %s", (*error)->message);
	return (cfg);
}

/*
 * converts the time string into seconds.  The time string can be specified
 * using one of the following time units:
 * 	#s (# of seconds)
 *	#m (# of minutes)
 *	#h (# of hours)
 *	#d (# of days)
 *	#w (# of weeks)
 * NOTE: you can only specify one the above.  No combination of the above
 * units is allowed.  If no unit specified, it will default to "seconds".
 */
static time_t
conv_time(char *s)
{
	time_t t;
	char c;
	int l, m;
	long tot;

	l = strlen(s);
	if (l == 0)
		return (0);
	c = s[--l];
	m = 0;
	switch (c) {
	case 'w': /* weeks */
		m = 604800;
		break;
	case 'd': /* days */
		m = 86400;
		break;
	case 'h': /* hours */
		m = 3600;
		break;
	case 'm': /* minutes */
		m = 60;
		break;
	case 's': /* seconds */
		m = 1;
		break;
	/* the default case is set to "second" */
	}
	if (m != 0)
		s[l] = '\0';
	else
		m = 1;
	errno = 0;
	tot = atol(s);
	if ((0 == tot) && (EINVAL == errno))
		return (0);
	if (((LONG_MAX == tot) || (LONG_MIN == tot)) && (EINVAL == errno))
		return (0);

	tot = tot * m;
	t = (time_t)tot;
	return (t);
}


ns_auth_t *
__s_api_AuthEnumtoStruct(const EnumAuthType_t i)
{
	ns_auth_t *ap;

	ap = (ns_auth_t *)calloc(1, sizeof (ns_auth_t));
	if (ap == NULL)
		return (NULL);
	switch (i) {
		case NS_LDAP_EA_NONE:
			break;
		case NS_LDAP_EA_SIMPLE:
			ap->type = NS_LDAP_AUTH_SIMPLE;
			break;
		case NS_LDAP_EA_SASL_CRAM_MD5:
			ap->type = NS_LDAP_AUTH_SASL;
			ap->saslmech = NS_LDAP_SASL_CRAM_MD5;
			break;
		case NS_LDAP_EA_SASL_DIGEST_MD5:
			ap->type = NS_LDAP_AUTH_SASL;
			ap->saslmech = NS_LDAP_SASL_DIGEST_MD5;
			break;
		case NS_LDAP_EA_SASL_DIGEST_MD5_INT:
			ap->type = NS_LDAP_AUTH_SASL;
			ap->saslmech = NS_LDAP_SASL_DIGEST_MD5;
			ap->saslopt = NS_LDAP_SASLOPT_INT;
			break;
		case NS_LDAP_EA_SASL_DIGEST_MD5_CONF:
			ap->type = NS_LDAP_AUTH_SASL;
			ap->saslmech = NS_LDAP_SASL_DIGEST_MD5;
			ap->saslopt = NS_LDAP_SASLOPT_PRIV;
			break;
		case NS_LDAP_EA_SASL_EXTERNAL:
			ap->type = NS_LDAP_AUTH_SASL;
			ap->saslmech = NS_LDAP_SASL_EXTERNAL;
			break;
		case NS_LDAP_EA_SASL_GSSAPI:
			ap->type = NS_LDAP_AUTH_SASL;
			ap->saslmech = NS_LDAP_SASL_GSSAPI;
			ap->saslopt = NS_LDAP_SASLOPT_INT |
			    NS_LDAP_SASLOPT_PRIV;
			break;
		case NS_LDAP_EA_TLS_NONE:
			ap->type = NS_LDAP_AUTH_TLS;
			ap->tlstype = NS_LDAP_TLS_NONE;
			break;
		case NS_LDAP_EA_TLS_SIMPLE:
			ap->type = NS_LDAP_AUTH_TLS;
			ap->tlstype = NS_LDAP_TLS_SIMPLE;
			break;
		case NS_LDAP_EA_TLS_SASL_CRAM_MD5:
			ap->type = NS_LDAP_AUTH_TLS;
			ap->tlstype = NS_LDAP_TLS_SASL;
			ap->saslmech = NS_LDAP_SASL_CRAM_MD5;
			break;
		case NS_LDAP_EA_TLS_SASL_DIGEST_MD5:
			ap->type = NS_LDAP_AUTH_TLS;
			ap->tlstype = NS_LDAP_TLS_SASL;
			ap->saslmech = NS_LDAP_SASL_DIGEST_MD5;
			break;
		case NS_LDAP_EA_TLS_SASL_DIGEST_MD5_INT:
			ap->type = NS_LDAP_AUTH_TLS;
			ap->tlstype = NS_LDAP_TLS_SASL;
			ap->saslmech = NS_LDAP_SASL_DIGEST_MD5;
			ap->saslopt = NS_LDAP_SASLOPT_INT;
			break;
		case NS_LDAP_EA_TLS_SASL_DIGEST_MD5_CONF:
			ap->type = NS_LDAP_AUTH_TLS;
			ap->tlstype = NS_LDAP_TLS_SASL;
			ap->saslmech = NS_LDAP_SASL_DIGEST_MD5;
			ap->saslopt = NS_LDAP_SASLOPT_PRIV;
			break;
		case NS_LDAP_EA_TLS_SASL_EXTERNAL:
			ap->type = NS_LDAP_AUTH_TLS;
			ap->tlstype = NS_LDAP_TLS_SASL;
			ap->saslmech = NS_LDAP_SASL_EXTERNAL;
			break;
		default:
			/* should never get here */
			free(ap);
			return (NULL);
	}
	return (ap);
}


/*
 * Parameter Index Type validation routines
 */

/* Validate a positive integer */
/* Size of errbuf needs to be MAXERROR */
/* ARGSUSED */
static int
__s_val_postime(ParamIndexType i, ns_default_config *def,
    ns_param_t *param, char *errbuf)
{
	char	*cp;
	long	tot;

	if (param && param->ns_ptype == CHARPTR && param->ns_pc) {
		for (cp = param->ns_pc; cp && *cp; cp++) {
			if (*cp >= '0' && *cp <= '9')
				continue;
			switch (*cp) {
			case 'w': /* weeks */
			case 'd': /* days */
			case 'h': /* hours */
			case 'm': /* minutes */
			case 's': /* seconds */
				if (*(cp+1) == '\0') {
					break;
				}
			default:
				(void) strcpy(errbuf, "Illegal time value");
				return (NS_PARSE_ERR);
			}
		}
		/* Valid form:  [0-9][0-9]*[wdhms]* */
		tot = atol(param->ns_pc);	/* check overflow */
		if (tot >= 0)
			return (NS_SUCCESS);
	}
	(void) snprintf(errbuf, MAXERROR,
	    gettext("Illegal time value in %s"), def->name);
	return (NS_PARSE_ERR);
}


/* Validate the Base DN */
/* It can be empty (RootDSE request) or needs to have an '=' */
/* Size of errbuf needs to be MAXERROR */
/* ARGSUSED */
static int
__s_val_basedn(ParamIndexType i, ns_default_config *def,
    ns_param_t *param, char *errbuf)
{
	if (param && param->ns_ptype == CHARPTR &&
	    i == NS_LDAP_SEARCH_BASEDN_P &&
	    ((param->ns_pc == NULL) || 		/* empty */
	    (*(param->ns_pc) == '\0') ||		/* empty */
	    (strchr(param->ns_pc, '=') != NULL)))	/* '=' */
	{
		return (NS_SUCCESS);
	}
	(void) snprintf(errbuf, MAXERROR,
	    gettext("Non-existent or invalid DN in %s"),
	    def->name);
	return (NS_PARSE_ERR);
}


/* Validate the serverList */
/* For each server in list, check if valid IP or hostname */
/* Size of errbuf needs to be MAXERROR */
/* ARGSUSED */
static int
__s_val_serverList(ParamIndexType i, ns_default_config *def,
    ns_param_t *param, char *errbuf)
{
	for (i = 0; i < param->ns_acnt; i++) {
		if ((__s_api_isipv4(param->ns_ppc[i])) ||
		    (__s_api_isipv6(param->ns_ppc[i])) ||
		    (__s_api_ishost(param->ns_ppc[i]))) {
			continue;
		}
		/* err */
		(void) snprintf(errbuf, MAXERROR,
		    gettext("Invalid server (%s) in %s"),
		    param->ns_ppc[i], def->name);
		return (NS_PARSE_ERR);
	}

	return (NS_SUCCESS);
}


/* Check for a BINDDN */
/* It can not be empty and needs to have an '=' */
/* Size of errbuf needs to be MAXERROR */
/* ARGSUSED */
static int
__s_val_binddn(ParamIndexType i, ns_default_config *def,
    ns_param_t *param, char *errbuf)
{
	char *dntype;

	if (param && param->ns_ptype == CHARPTR &&
	    (i == NS_LDAP_BINDDN_P || i == NS_LDAP_ADMIN_BINDDN_P) &&
	    ((param->ns_pc == NULL) ||
	    ((*(param->ns_pc) != '\0') &&
	    (strchr(param->ns_pc, '=') != NULL)))) {
		return (NS_SUCCESS);
	}
	if (i == NS_LDAP_BINDDN_P)
		dntype = "proxy";
	else
		dntype = "update";
	(void) snprintf(errbuf, MAXERROR,
	    gettext("NULL or invalid %s bind DN"), dntype);
	return (NS_PARSE_ERR);
}


/* Check for a BINDPASSWD */
/* The string can not be NULL or empty */
/* Size of errbuf needs to be MAXERROR */
/* ARGSUSED */
static int
__s_val_bindpw(ParamIndexType i, ns_default_config *def,
    ns_param_t *param, char *errbuf)
{
	char *pwtype;

	if (param && param->ns_ptype == CHARPTR &&
	    (i == NS_LDAP_BINDPASSWD_P || i == NS_LDAP_ADMIN_BINDPASSWD_P) &&
	    ((param->ns_pc == NULL) ||
	    (*(param->ns_pc) != '\0'))) {
		return (NS_SUCCESS);
	}
	if (i == NS_LDAP_BINDPASSWD_P)
		pwtype = "proxy";
	else
		pwtype = "admin";
	(void) snprintf(errbuf, MAXERROR,
	    gettext("NULL %s bind password"), pwtype);
	return (NS_PARSE_ERR);
}

/*
 * __s_get_hostcertpath returns either the configured host certificate path
 * or, if none, the default host certificate path (/var/ldap). Note that this
 * does not use __ns_ldap_getParam because it may be called during connection
 * setup. This can fail due to insufficient memory.
 */

char *
__s_get_hostcertpath(void)
{
	ns_config_t		*cfg;
	ns_param_t		*param;
	char			*ret = NULL;

	cfg = __s_api_get_default_config();
	if (cfg != NULL) {
		param = &cfg->paramList[NS_LDAP_HOST_CERTPATH_P];
		if (param->ns_ptype == CHARPTR)
			ret = strdup(param->ns_pc);
		__s_api_release_config(cfg);
	}
	if (ret == NULL)
		ret = strdup(NSLDAPDIRECTORY);
	return (ret);
}

static void
_free_config()
{
	if (current_config != NULL)
		destroy_config(current_config);

	current_config = NULL;
}
