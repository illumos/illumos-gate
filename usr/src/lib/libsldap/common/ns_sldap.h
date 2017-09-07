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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */


#ifndef	_NS_SLDAP_H
#define	_NS_SLDAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <sys/types.h>
#include <lber.h>
#include <ldap.h>

/*
 * Version
 */
#define	NS_LDAP_VERSION		NS_LDAP_VERSION_2
#define	NS_LDAP_VERSION_1	"1.0"
#define	NS_LDAP_VERSION_2	"2.0"

/*
 * Flags
 */
#define	NS_LDAP_HARD		  0x001
#define	NS_LDAP_ALL_RES		  0x002

/* Search Referral Option */
typedef enum SearchRef {
	NS_LDAP_FOLLOWREF	= 0x004,
	NS_LDAP_NOREF		= 0x008
} SearchRef_t;

typedef enum ScopeType {
	NS_LDAP_SCOPE_BASE	= 0x010,
	NS_LDAP_SCOPE_ONELEVEL	= 0x020,
	NS_LDAP_SCOPE_SUBTREE	= 0x040
} ScopeType_t;

/*
 * BE VERY CAREFUL. DO NOT USE FLAG NS_LDAP_KEEP_CONN UNLESS YOU MUST
 * IN libsldap.so.1 THERE IS NO CONNECTION GARBAGE COLLECTION AND IF
 * THIS FLAG GETS USED THERE MIGHT BE A CONNECTION LEAK. CURRENTLY THIS
 * IS ONLY SUPPORTED FOR LIST AND INTENDED FOR APPLICATIONS LIKE AUTOMOUNTER
 */

#define	NS_LDAP_KEEP_CONN	  0x080
#define	NS_LDAP_NEW_CONN	  0x400
#define	NS_LDAP_NOMAP		  0x800

#define	NS_LDAP_PAGE_CTRL	  0x1000
#define	NS_LDAP_NO_PAGE_CTRL	  0x0000

/*
 * NS_LDAP_NOT_CVT_DN is needed when attribute mapping is used
 * to retrieve the DN in LDAP and DN is not to be converted when
 * being passed back to the application. See __ns_ldap_uid2dn()
 * and __ns_ldap_host2dn() for such usage.
 */
#define	NS_LDAP_NOT_CVT_DN	0x2000

/*
 * NS_LDAP_UPDATE_SHADOW is for a privileged caller of the
 * __ns_ldap_repAttr() to update the shadow database on the
 * LDAP server.
 */
#define	NS_LDAP_UPDATE_SHADOW	0x4000

/*
 * NS_LDAP_READ_SHADOW is for a privileged caller of __ns_ldap_list()
 * and __ns_ldap_firstEntry() to read the shadow database on the
 * LDAP server.
 */
#define	NS_LDAP_READ_SHADOW	0x8000

/*
 * Authentication Information
 */
typedef enum CredLevel {
	NS_LDAP_CRED_ANON	= 0,
	NS_LDAP_CRED_PROXY	= 1,
	NS_LDAP_CRED_SELF	= 2
} CredLevel_t;

typedef enum AuthType {
	NS_LDAP_AUTH_NONE	= 0,
	NS_LDAP_AUTH_SIMPLE	= 1,
	NS_LDAP_AUTH_SASL	= 2,
	NS_LDAP_AUTH_TLS	= 3,	/* implied SASL usage */
	NS_LDAP_AUTH_ATLS	= 4	/* implied SASL usage */
} AuthType_t;

typedef enum TlsType {
	NS_LDAP_TLS_NONE	= 0,
	NS_LDAP_TLS_SIMPLE	= 1,
	NS_LDAP_TLS_SASL	= 2
} TlsType_t;

typedef enum SaslMech {
	NS_LDAP_SASL_NONE	= 0,	/* No SASL mechanism */
	NS_LDAP_SASL_CRAM_MD5	= 1,
	NS_LDAP_SASL_DIGEST_MD5	= 2,
	NS_LDAP_SASL_EXTERNAL	= 3,	/* currently not supported */
	NS_LDAP_SASL_GSSAPI	= 4,
	NS_LDAP_SASL_SPNEGO	= 5	/* currently not supported */
} SaslMech_t;

typedef enum SaslOpt {
	NS_LDAP_SASLOPT_NONE	= 0,
	NS_LDAP_SASLOPT_INT	= 1,
	NS_LDAP_SASLOPT_PRIV	= 2
} SaslOpt_t;

typedef enum PrefOnly {
	NS_LDAP_PREF_FALSE	= 0,
	NS_LDAP_PREF_TRUE	= 1
} PrefOnly_t;

typedef enum enableShadowUpdate {
	NS_LDAP_ENABLE_SHADOW_UPDATE_FALSE	= 0,
	NS_LDAP_ENABLE_SHADOW_UPDATE_TRUE	= 1
} enableShadowUpdate_t;

typedef struct UnixCred {
	char	*userID;	/* Unix ID number */
	char	*passwd;	/* password */
} UnixCred_t;

typedef struct CertCred {
	char	*path;		/* certificate path */
	char	*passwd;	/* password */
	char	*nickname;	/* nickname */
} CertCred_t;

typedef struct ns_auth {
	AuthType_t	type;
	TlsType_t	tlstype;
	SaslMech_t	saslmech;
	SaslOpt_t	saslopt;
} ns_auth_t;

typedef struct ns_cred {
	ns_auth_t	auth;
	char		*hostcertpath;
	union {
		UnixCred_t	unix_cred;
		CertCred_t	cert_cred;
	} cred;
} ns_cred_t;


typedef struct LineBuf {
	char *str;
	int len;
	int alloc;
} LineBuf;

/*
 * Configuration Information
 */

typedef enum {
	NS_LDAP_FILE_VERSION_P		= 0,
	NS_LDAP_BINDDN_P		= 1,
	NS_LDAP_BINDPASSWD_P		= 2,
	NS_LDAP_SERVERS_P		= 3,
	NS_LDAP_SEARCH_BASEDN_P		= 4,
	NS_LDAP_AUTH_P			= 5,
/*
 * NS_LDAP_TRANSPORT_SEC_P is only left in for backward compatibility
 * with version 1 clients and their configuration files.  The only
 * supported value is NS_LDAP_SEC_NONE.  No application should be
 * using this parameter type (either through getParam or setParam.
 */
	NS_LDAP_TRANSPORT_SEC_P		= 6,
	NS_LDAP_SEARCH_REF_P		= 7,
	NS_LDAP_DOMAIN_P		= 8,
	NS_LDAP_EXP_P			= 9,
	NS_LDAP_CERT_PATH_P		= 10,
	NS_LDAP_CERT_PASS_P		= 11,
	NS_LDAP_SEARCH_DN_P		= 12,
	NS_LDAP_SEARCH_SCOPE_P		= 13,
	NS_LDAP_SEARCH_TIME_P		= 14,
	NS_LDAP_SERVER_PREF_P		= 15,
	NS_LDAP_PREF_ONLY_P		= 16,
	NS_LDAP_CACHETTL_P		= 17,
	NS_LDAP_PROFILE_P		= 18,
	NS_LDAP_CREDENTIAL_LEVEL_P	= 19,
	NS_LDAP_SERVICE_SEARCH_DESC_P	= 20,
	NS_LDAP_BIND_TIME_P		= 21,
	NS_LDAP_ATTRIBUTEMAP_P		= 22,
	NS_LDAP_OBJECTCLASSMAP_P	= 23,
	NS_LDAP_CERT_NICKNAME_P		= 24,
	NS_LDAP_SERVICE_AUTH_METHOD_P	= 25,
	NS_LDAP_SERVICE_CRED_LEVEL_P	= 26,
	NS_LDAP_HOST_CERTPATH_P		= 27,
	NS_LDAP_ENABLE_SHADOW_UPDATE_P	= 28,
	NS_LDAP_ADMIN_BINDDN_P		= 29,
	NS_LDAP_ADMIN_BINDPASSWD_P	= 30,
/*
 * The following entry (max ParamIndexType) is an internal
 * placeholder.  It must be the last (and highest value)
 * entry in this eNum.  Please update accordingly.
 */
	NS_LDAP_MAX_PIT_P		= 31

} ParamIndexType;

/*
 * NONE - No self / SASL/GSSAPI configured
 * ONLY - Only self / SASL/GSSAPI configured
 * MIXED - self / SASL/GSSAPI is mixed with other types of configuration
 */
typedef enum {
	NS_LDAP_SELF_GSSAPI_CONFIG_NONE = 0,
	NS_LDAP_SELF_GSSAPI_CONFIG_ONLY = 1,
	NS_LDAP_SELF_GSSAPI_CONFIG_MIXED = 2
} ns_ldap_self_gssapi_config_t;

/*
 * __ns_ldap_*() return codes
 */
typedef enum {
	NS_LDAP_SUCCESS		= 0, /* success, no info in errorp */
	NS_LDAP_OP_FAILED	= 1, /* failed operation, no info in errorp */
	NS_LDAP_NOTFOUND	= 2, /* entry not found, no info in errorp */
	NS_LDAP_MEMORY		= 3, /* memory failure, no info in errorp */
	NS_LDAP_CONFIG		= 4, /* config problem, detail in errorp */
	NS_LDAP_PARTIAL		= 5, /* partial result, detail in errorp */
	NS_LDAP_INTERNAL	= 7, /* LDAP error, detail in errorp */
	NS_LDAP_INVALID_PARAM	= 8, /* LDAP error, no info in errorp */
	NS_LDAP_SUCCESS_WITH_INFO
				= 9  /* success, with info in errorp */
} ns_ldap_return_code;

/*
 * Detailed error code for NS_LDAP_CONFIG
 */
typedef enum {
	NS_CONFIG_SYNTAX	= 0,	/* syntax error */
	NS_CONFIG_NODEFAULT	= 1,	/* no default value */
	NS_CONFIG_NOTLOADED	= 2,	/* configuration not loaded */
	NS_CONFIG_NOTALLOW	= 3,	/* operation requested not allowed */
	NS_CONFIG_FILE		= 4,	/* configuration file problem */
	NS_CONFIG_CACHEMGR	= 5	/* error with door to ldap_cachemgr */
} ns_ldap_config_return_code;

/*
 * Detailed error code for NS_LDAP_PARTIAL
 */
typedef enum {
	NS_PARTIAL_TIMEOUT	= 0,	/* partial results due to timeout */
	NS_PARTIAL_OTHER	= 1	/* error encountered */
} ns_ldap_partial_return_code;

/*
 * For use by __ns_ldap_addTypedEntry() for publickey serivicetype
 */
typedef enum {
	NS_HOSTCRED_FALSE = 0,
	NS_HOSTCRED_TRUE  = 1
} hostcred_t;

/*
 * Detailed password status
 */
typedef enum {
	NS_PASSWD_GOOD			= 0,	/* password is good */
	NS_PASSWD_ABOUT_TO_EXPIRE	= 1,	/* password is good but */
						/* about to expire */
	NS_PASSWD_CHANGE_NEEDED		= 2,	/* good but need to be */
						/* changed immediately */
	NS_PASSWD_EXPIRED		= 3,	/* password expired */
	NS_PASSWD_RETRY_EXCEEDED	= 4,	/* exceed retry limit; */
						/* account is locked */
	NS_PASSWD_CHANGE_NOT_ALLOWED	= 5,	/* can only be changed */
						/* by the administrator */
	NS_PASSWD_INVALID_SYNTAX	= 6,	/* can not be changed: */
						/* new password has */
						/* invalid syntax -- */
						/* trivial password: same */
						/* value as attr, cn, sn, */
						/* uid, etc. */
						/* or strong password */
						/* policies check */
	NS_PASSWD_TOO_SHORT		= 7,	/* can not be changed: */
						/* new password has */
						/* less chars than */
						/* required */
	NS_PASSWD_IN_HISTORY		= 8,	/* can not be changed: */
						/* reuse old password  */
	NS_PASSWD_WITHIN_MIN_AGE	= 9 	/* can not be changed: */
						/* within minimum age  */
} ns_ldap_passwd_status_t;

/*
 * Password management information structure
 *
 * This structure is different from AcctUsableResponse_t structure in
 * that this structure holds result of users account mgmt information when
 * an ldap bind is done with user name and user password.
 */
typedef struct ns_ldap_passwd_mgmt {
	ns_ldap_passwd_status_t
		status;			/* password status */
	int	sec_until_expired;	/* seconds until expired, */
					/* valid if status is */
					/* NS_PASSWD_ABOUT_TO_EXPIRE */
} ns_ldap_passwd_mgmt_t;

/*
 * LDAP V3 control flag for account management - Used for account management
 * when no password is provided
 */
#define	NS_LDAP_ACCOUNT_USABLE_CONTROL	"1.3.6.1.4.1.42.2.27.9.5.8"

/*
 * Structure for holding the response returned by server for
 * NS_LDAP_ACCOUNT_USABLE_CONTROL control when account is not available.
 */
typedef struct AcctUsableMoreInfo {
	int inactive;
	int reset;
	int expired;
	int rem_grace;
	int sec_b4_unlock;
} AcctUsableMoreInfo_t;

/*
 * Structure used to hold the response from the server for
 * NS_LDAP_ACCOUNT_USABLE_CONTROL control. The ASN1 notation is as below:
 *
 * ACCOUNT_USABLE_RESPONSE::= CHOICE {
 * is_available		[0] INTEGER, seconds before expiration
 * is_not_available	[1] More_info
 * }
 *
 * More_info::= SEQUENCE {
 * inactive		[0] BOOLEAN DEFAULT FALSE,
 * reset		[1] BOOLEAN DEFAULT FALSE,
 * expired		[2] BOOLEAN DEFAULT FALSE,
 * remaining_grace	[3] INTEGER OPTIONAL,
 * seconds_before_unlock[4] INTEGER OPTIONAL
 * }
 *
 * This structure is different from ns_ldap_passwd_mgmt_t structure in
 * that this structure holds result of users account mgmt information when
 * pam_ldap doesn't have the users password and proxy agent is used for
 * obtaining the account management information.
 */
typedef struct AcctUsableResponse {
	int choice;
	union {
		int seconds_before_expiry;
		AcctUsableMoreInfo_t more_info;
	} AcctUsableResp;
} AcctUsableResponse_t;

/*
 * Simplified LDAP Naming API result structure
 */
typedef struct ns_ldap_error {
	int	status;				/* LDAP error code */
	char	*message;			/* LDAP error message */
	ns_ldap_passwd_mgmt_t	pwd_mgmt;	/* LDAP password */
						/* management info */
} ns_ldap_error_t;

typedef struct	 ns_ldap_attr {
	char	*attrname;			/* attribute name */
	uint_t	value_count;
	char	**attrvalue;			/* attribute values */
} ns_ldap_attr_t;

typedef struct ns_ldap_entry {
	uint_t		attr_count;		/* number of attributes */
	ns_ldap_attr_t	**attr_pair;		/* attributes pairs */
	struct ns_ldap_entry *next;		/* next entry */
} ns_ldap_entry_t;

typedef struct ns_ldap_result {
	uint_t	entries_count;		/* number of entries */
	ns_ldap_entry_t	*entry;		/* data */
} ns_ldap_result_t;

/*
 * structures for the conversion routines used by typedAddEntry()
 */

typedef struct _ns_netgroups {
	char  *name;
	char  **triplet;
	char  **netgroup;
} _ns_netgroups_t;

typedef struct _ns_netmasks {
	char *netnumber;
	char *netmask;
} _ns_netmasks_t;

typedef struct _ns_bootp {
	char *name;
	char **param;
} _ns_bootp_t;

typedef struct _ns_ethers {
	char *name;
	char *ether;
} _ns_ethers_t;

typedef struct _ns_pubkey {
	char *name;
	hostcred_t hostcred;
	char *pubkey;
	char *privkey;
} _ns_pubkey_t;

typedef struct _ns_alias {
	char *alias;
	char **member;
} _ns_alias_t;

typedef struct _ns_automount {
	char *mapname;
	char *key;
	char *value;
} _ns_automount_t;

/*
 * return values for the callback function in __ns_ldap_list()
 */
#define	NS_LDAP_CB_NEXT	0	/* get the next entry */
#define	NS_LDAP_CB_DONE	1	/* done */

/*
 * Input values for the type specified in __ns_ldap_addTypedEntry()
 * and __ns_ldap_delTypedEntry()
 */

#define	NS_LDAP_TYPE_PASSWD	"passwd"
#define	NS_LDAP_TYPE_GROUP	"group"
#define	NS_LDAP_TYPE_HOSTS	"hosts"
#define	NS_LDAP_TYPE_IPNODES	"ipnodes"
#define	NS_LDAP_TYPE_PROFILE	"prof_attr"
#define	NS_LDAP_TYPE_RPC	"rpc"
#define	NS_LDAP_TYPE_PROTOCOLS	"protocols"
#define	NS_LDAP_TYPE_NETWORKS	"networks"
#define	NS_LDAP_TYPE_NETGROUP	"netgroup"
#define	NS_LDAP_TYPE_ALIASES	"aliases"
#define	NS_LDAP_TYPE_SERVICES	"services"
#define	NS_LDAP_TYPE_ETHERS	"ethers"
#define	NS_LDAP_TYPE_SHADOW	"shadow"
#define	NS_LDAP_TYPE_NETMASKS	"netmasks"
#define	NS_LDAP_TYPE_AUTHATTR	"auth_attr"
#define	NS_LDAP_TYPE_EXECATTR	"exec_attr"
#define	NS_LDAP_TYPE_USERATTR	"user_attr"
#define	NS_LDAP_TYPE_PROJECT	"project"
#define	NS_LDAP_TYPE_PUBLICKEY	"publickey"
#define	NS_LDAP_TYPE_AUUSER	"audit_user"
#define	NS_LDAP_TYPE_BOOTPARAMS "bootparams"
#define	NS_LDAP_TYPE_AUTOMOUNT  "auto_"
#define	NS_LDAP_TYPE_TNRHDB	"tnrhdb"
#define	NS_LDAP_TYPE_TNRHTP	"tnrhtp"

/*
 * service descriptor/attribute mapping structure
 */

typedef struct ns_ldap_search_desc {
	char		*basedn;	/* search base dn */
	ScopeType_t	scope;		/* search scope */
	char		*filter;	/* search filter */
} ns_ldap_search_desc_t;

typedef struct ns_ldap_attribute_map {
	char		*origAttr;	/* original attribute */
	char		**mappedAttr;	/* mapped attribute(s) */
} ns_ldap_attribute_map_t;

typedef struct ns_ldap_objectclass_map {
	char		*origOC;	/* original objectclass */
	char		*mappedOC;	/* mapped objectclass */
} ns_ldap_objectclass_map_t;

/*
 * Value of the userPassword attribute representing NO Unix password
 */
#define	NS_LDAP_NO_UNIX_PASSWORD	"<NO UNIX PASSWORD>"

/* Opaque handle for batch API */
typedef struct ns_ldap_list_batch ns_ldap_list_batch_t;

/*
 * The type of standalone configuration specified by a client application.
 * The meaning of the requests is as follows:
 *
 * NS_CACHEMGR:    libsldap will request all the configuration via door_call(3C)
 *                 to ldap_cachemgr.
 * NS_LDAP_SERVER: the consumer application has specified a directory server
 *                 to communicate to.
 * NS_PREDEFINED:  reserved for internal use
 */
typedef enum {
	NS_CACHEMGR = 0,
	NS_LDAP_SERVER
} ns_standalone_request_type_t;

/*
 * This structure describes an LDAP server specified by a client application.
 */
typedef struct ns_dir_server {
	char *server;			/* A directory server's IP */
	uint16_t port;			/* A directory server's port. */
					/* Default value is 389 */
	char *domainName;		/* A domain name being served */
					/* by the specified server. */
					/* Default value is the local */
					/* domain's name */
	char *profileName;		/* A DUAProfile's name. */
					/* Default value is 'default' */
	ns_auth_t *auth;		/* Authentication information used */
					/* during subsequent connections */
	char *cred;			/* A credential level to be used */
					/* along with the authentication info */
	char *host_cert_path;		/* A path to the certificate database */
					/* Default is '/vat/ldap' */
	char *bind_dn;			/* A bind DN to be used during */
					/* subsequent LDAP Bind requests */
	char *bind_passwd;		/* A bind password to be used during */
					/* subsequent LDAP Bind requests */
} ns_dir_server_t;

/*
 * This structure contains information describing an LDAP server.
 */
typedef struct ns_standalone_conf {
	union {
		ns_dir_server_t server;
		void *predefined_conf;	/* Reserved for internal use */
	} ds_profile;			/* A type of the configuration */

#define	SA_SERVER	ds_profile.server.server
#define	SA_PORT		ds_profile.server.port
#define	SA_DOMAIN	ds_profile.server.domainName
#define	SA_PROFILE_NAME	ds_profile.server.profileName
#define	SA_AUTH		ds_profile.server.auth
#define	SA_CRED		ds_profile.server.cred
#define	SA_CERT_PATH	ds_profile.server.host_cert_path
#define	SA_BIND_DN	ds_profile.server.bind_dn
#define	SA_BIND_PWD	ds_profile.server.bind_passwd

	ns_standalone_request_type_t type;
} ns_standalone_conf_t;

/*
 * This function "informs" libsldap that a client application has specified
 * a directory to use. The function obtains a DUAProfile, credentials,
 * and naming context. During all further operations on behalf
 * of the application requested a standalone schema libsldap will use
 * the information obtained by __ns_ldap_initStandalone() instead of
 * door_call(3C)ing ldap_cachemgr(1M).
 *
 * conf
 * 	A structure describing where and in which way to obtain all the
 * 	configuration describing how to communicate to a choosen LDAP directory.
 *
 * errorp
 * 	An error object describing an error occured.
 */
ns_ldap_return_code __ns_ldap_initStandalone(
	const ns_standalone_conf_t *conf,
	ns_ldap_error_t	**errorp);

/*
 * This function obtains the directory's base DN and a DUAProfile
 * from a specified server.
 *
 * server
 * 	Specifies the selected directory sever.
 *
 * cred
 * 	Contains an authentication information and credential required to
 * 	establish a connection.
 *
 * config
 * 	If not NULL, a new configuration basing on a DUAProfile specified in the
 * 	server parameter will be create and returned.
 *
 * baseDN
 * 	If not NULL, the directory's base DN will be returned.
 *
 * error
 * 	Describes an error, if any.
 */
ns_ldap_return_code __ns_ldap_getConnectionInfoFromDUA(
	const ns_dir_server_t *server,
	const ns_cred_t *cred,
	char **config,	char **baseDN,
	ns_ldap_error_t **error);

#define	SA_PROHIBIT_FALLBACK 0
#define	SA_ALLOW_FALLBACK 1

#define	DONT_SAVE_NSCONF 0
#define	SAVE_NSCONF 1

/*
 * This function obtains the root DSE from a specified server.
 *
 * server_addr
 * 	An adress of a server to be connected to.
 *
 * rootDSE
 * 	A buffer containing the root DSE in the ldap_cachmgr door call format.
 *
 * errorp
 * 	Describes an error, if any.
 *
 * anon_fallback
 * 	If set to 1 and establishing a connection fails, __s_api_getRootDSE()
 * 	will try once again using anonymous credentials.
 */
ns_ldap_return_code __ns_ldap_getRootDSE(
	const char *server_addr,
	char **rootDSE,
	ns_ldap_error_t **errorp,
	int anon_fallback);

/*
 * This function iterates through the list of the configured LDAP servers
 * and "pings" those which are marked as removed or if any error occurred
 * during the previous receiving of the server's root DSE. If the
 * function is able to reach such a server and get its root DSE, it
 * marks the server as on-line. Otherwise, the server's status is set
 * to "Error".
 * For each server the function tries to connect to, it fires up
 * a separate thread and then waits until all the threads finish.
 * The function returns NS_LDAP_INTERNAL if the Standalone mode was not
 * initialized or was canceled prior to an invocation of
 * __ns_ldap_pingOfflineServers().
 */
ns_ldap_return_code __ns_ldap_pingOfflineServers(void);

/*
 * This function cancels the Standalone mode and destroys the list of root DSEs.
 */
void __ns_ldap_cancelStandalone(void);
/*
 * This function initializes an ns_auth_t structure provided by a caller
 * according to a specified authentication mechanism.
 */
ns_ldap_return_code __ns_ldap_initAuth(const char *auth_mech,
	ns_auth_t *auth,
	ns_ldap_error_t **errorp);

/*
 * Simplified LDAP Naming APIs
 */
int __ns_ldap_list(
	const char *service,
	const char *filter,
	int (*init_filter_cb)(const ns_ldap_search_desc_t *desc,
			char **realfilter, const void *userdata),
	const char * const *attribute,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_result_t ** result,
	ns_ldap_error_t ** errorp,
	int (*callback)(const ns_ldap_entry_t *entry, const void *userdata),
	const void *userdata);


int __ns_ldap_list_sort(
	const char *service,
	const char *filter,
	const char *sortattr,
	int (*init_filter_cb)(const ns_ldap_search_desc_t *desc,
			char **realfilter, const void *userdata),
	const char * const *attribute,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_result_t ** result,
	ns_ldap_error_t ** errorp,
	int (*callback)(const ns_ldap_entry_t *entry, const void *userdata),
	const void *userdata);

int __ns_ldap_list_batch_start(
	ns_ldap_list_batch_t **batch);

int __ns_ldap_list_batch_add(
	ns_ldap_list_batch_t *batch,
	const char *service,
	const char *filter,
	int (*init_filter_cb)(const ns_ldap_search_desc_t *desc,
			char **realfilter, const void *userdata),
	const char * const *attribute,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_result_t ** result,
	ns_ldap_error_t ** errorp,
	int *rcp,
	int (*callback)(const ns_ldap_entry_t *entry, const void *userdata),
	const void *userdata);

int __ns_ldap_list_batch_end(
	ns_ldap_list_batch_t *batch);

void __ns_ldap_list_batch_release(
	ns_ldap_list_batch_t *batch);

int  __ns_ldap_addAttr(
	const char *service,
	const char *dn,
	const ns_ldap_attr_t * const *attr,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_error_t **errorp);

int __ns_ldap_delAttr(
	const char *service,
	const char *dn,
	const ns_ldap_attr_t * const *attr,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_error_t **errorp);

int  __ns_ldap_repAttr(
	const char *service,
	const char *dn,
	const ns_ldap_attr_t * const *attr,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_error_t **errorp);

int  __ns_ldap_addEntry(
	const char *service,
	const char *dn,
	const ns_ldap_entry_t *entry,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_error_t **errorp);

int  __ns_ldap_addTypedEntry(
	const char *servicetype,
	const char *basedn,
	const void *data,
	const int  create,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_error_t **errorp);

int __ns_ldap_delEntry(
	const char *service,
	const char *dn,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_error_t **errorp);

int __ns_ldap_firstEntry(
	const char *service,
	const char *filter,
	const char *sortattr,
	int (*init_filter_cb)(const ns_ldap_search_desc_t *desc,
			char **realfilter, const void *userdata),
	const char * const *attribute,
	const ns_cred_t *cred,
	const int flags,
	void **cookie,
	ns_ldap_result_t ** result,
	ns_ldap_error_t **errorp,
	const void *userdata);

int  __ns_ldap_nextEntry(
	void *cookie,
	ns_ldap_result_t ** result,
	ns_ldap_error_t **errorp);

int  __ns_ldap_endEntry(
	void **cookie,
	ns_ldap_error_t **errorp);

int __ns_ldap_freeResult(
	ns_ldap_result_t **result);

int __ns_ldap_freeError(
	ns_ldap_error_t **errorp);

int  __ns_ldap_uid2dn(
	const char *uid,
	char **userDN,
	const ns_cred_t *cred,
	ns_ldap_error_t ** errorp);

int  __ns_ldap_dn2uid(
	const char *dn,
	char **userID,
	const ns_cred_t *cred,
	ns_ldap_error_t ** errorp);

int  __ns_ldap_host2dn(
	const char *host,
	const char *domain,
	char **hostDN,
	const ns_cred_t *cred,
	ns_ldap_error_t ** errorp);

int  __ns_ldap_dn2domain(
	const char *dn,
	char **domain,
	const ns_cred_t *cred,
	ns_ldap_error_t ** errorp);

int __ns_ldap_auth(
	const ns_cred_t *cred,
	const int flag,
	ns_ldap_error_t **errorp,
	LDAPControl **serverctrls,
	LDAPControl **clientctrls);

int __ns_ldap_freeCred(
	ns_cred_t **credp);

int __ns_ldap_err2str(
	int err,
	char **strmsg);

int __ns_ldap_setParam(
	const ParamIndexType type,
	const void *data,
	ns_ldap_error_t **errorp);

int __ns_ldap_getParam(
	const ParamIndexType type,
	void ***data,
	ns_ldap_error_t **errorp);

int __ns_ldap_freeParam(
	void ***data);

char **__ns_ldap_getAttr(
	const ns_ldap_entry_t *entry,
	const char *attrname);

ns_ldap_attr_t	*__ns_ldap_getAttrStruct(
	const ns_ldap_entry_t *entry,
	const char *attrname);

int __ns_ldap_getServiceAuthMethods(
	const char *service,
	ns_auth_t ***auth,
	ns_ldap_error_t **errorp);

int __ns_ldap_getSearchDescriptors(
	const char *service,
	ns_ldap_search_desc_t ***desc,
	ns_ldap_error_t **errorp);

int __ns_ldap_freeSearchDescriptors(
	ns_ldap_search_desc_t ***desc);

int __ns_ldap_getAttributeMaps(
	const char *service,
	ns_ldap_attribute_map_t ***maps,
	ns_ldap_error_t **errorp);

int __ns_ldap_freeAttributeMaps(
	ns_ldap_attribute_map_t ***maps);

char **__ns_ldap_getMappedAttributes(
	const char *service,
	const char *origAttribute);

char **__ns_ldap_getOrigAttribute(
	const char *service,
	const char *mappedAttribute);

int __ns_ldap_getObjectClassMaps(
	const char *service,
	ns_ldap_objectclass_map_t ***maps,
	ns_ldap_error_t **errorp);

int __ns_ldap_freeObjectClassMaps(
	ns_ldap_objectclass_map_t ***maps);

char **__ns_ldap_getMappedObjectClass(
	const char *service,
	const char *origObjectClass);

char **__ns_ldap_getOrigObjectClass(
	const char *service,
	const char *mappedObjectClass);

int __ns_ldap_getParamType(
	const char *value,
	ParamIndexType *type);

int __ns_ldap_getAcctMgmt(
	const char *user,
	AcctUsableResponse_t *acctResp);

boolean_t __ns_ldap_is_shadow_update_enabled(void);

void
__ns_ldap_self_gssapi_only_set(
	int flag);
int
__ns_ldap_self_gssapi_config(
	ns_ldap_self_gssapi_config_t *config);
#ifdef __cplusplus
}
#endif

#endif /* _NS_SLDAP_H */
