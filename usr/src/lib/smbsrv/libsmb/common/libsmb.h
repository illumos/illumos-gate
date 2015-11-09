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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_LIBSMB_H
#define	_LIBSMB_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/list.h>
#include <sys/avl.h>
#include <arpa/inet.h>
#include <net/if.h>	/* LIFNAMSIZ */
#include <netdb.h>
#include <stdlib.h>
#include <libscf.h>
#include <libshare.h>
#include <uuid/uuid.h>
#include <synch.h>
#include <stdarg.h>

#include <smbsrv/string.h>
#include <smbsrv/smb_idmap.h>
#include <smbsrv/netbios.h>
#include <smbsrv/smb_share.h>
#include <smb/nterror.h>
#include <smb/ntstatus.h>
#include <smbsrv/smb_door.h>
#include <smbsrv/alloc.h>
#include <smbsrv/hash_table.h>
#include <smbsrv/msgbuf.h>
#include <smbsrv/wintypes.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/ntifs.h>

#define	SMB_VARSMB_DIR "/var/smb"
#define	SMB_VARRUN_DIR "/var/run/smb"
#define	SMB_CCACHE_FILE "ccache"
#define	SMB_CCACHE_PATH SMB_VARRUN_DIR "/" SMB_CCACHE_FILE


/* Max value length of all SMB properties */
#define	MAX_VALUE_BUFLEN	512

#define	SMBD_FMRI_PREFIX		"network/smb/server"
#define	SMBD_DEFAULT_INSTANCE_FMRI	"svc:/network/smb/server:default"
#define	SMBD_PG_NAME			"smbd"
#define	SMBD_PROTECTED_PG_NAME		"read"
#define	SMBD_EXEC_PG_NAME		"exec"

#define	SMBD_SMF_OK		0
#define	SMBD_SMF_NO_MEMORY	1	/* no memory for data structures */
#define	SMBD_SMF_SYSTEM_ERR	2	/* system error, use errno */
#define	SMBD_SMF_NO_PERMISSION	3	/* no permission for operation */
#define	SMBD_SMF_INVALID_ARG	4

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

/*
 * CIFS Configuration Management
 */
typedef enum {
	SMB_CI_VERSION = 0,
	SMB_CI_OPLOCK_ENABLE,

	SMB_CI_AUTOHOME_MAP,

	SMB_CI_DOMAIN_SID,
	SMB_CI_DOMAIN_MEMB,
	SMB_CI_DOMAIN_NAME,
	SMB_CI_DOMAIN_FQDN,
	SMB_CI_DOMAIN_FOREST,
	SMB_CI_DOMAIN_GUID,
	SMB_CI_DOMAIN_SRV,

	SMB_CI_WINS_SRV1,
	SMB_CI_WINS_SRV2,
	SMB_CI_WINS_EXCL,

	SMB_CI_MAX_WORKERS,
	SMB_CI_MAX_CONNECTIONS,
	SMB_CI_KEEPALIVE,
	SMB_CI_RESTRICT_ANON,

	SMB_CI_SIGNING_ENABLE,
	SMB_CI_SIGNING_REQD,

	SMB_CI_SYNC_ENABLE,

	SMB_CI_SECURITY,
	SMB_CI_NETBIOS_ENABLE,
	SMB_CI_NBSCOPE,
	SMB_CI_SYS_CMNT,
	SMB_CI_LM_LEVEL,

	SMB_CI_ADS_SITE,

	SMB_CI_DYNDNS_ENABLE,

	SMB_CI_MACHINE_PASSWD,
	SMB_CI_MACHINE_UUID,
	SMB_CI_KPASSWD_SRV,
	SMB_CI_KPASSWD_DOMAIN,
	SMB_CI_KPASSWD_SEQNUM,
	SMB_CI_NETLOGON_SEQNUM,
	SMB_CI_IPV6_ENABLE,
	SMB_CI_PRINT_ENABLE,
	SMB_CI_MAP,
	SMB_CI_UNMAP,
	SMB_CI_DISPOSITION,
	SMB_CI_DFS_STDROOT_NUM,
	SMB_CI_TRAVERSE_MOUNTS,
	SMB_CI_SMB2_ENABLE_OLD, /* obsolete */
	SMB_CI_INITIAL_CREDITS,
	SMB_CI_MAXIMUM_CREDITS,
	SMB_CI_MAX_PROTOCOL,

	SMB_CI_MAX
} smb_cfg_id_t;

/* SMF helper functions */
extern smb_scfhandle_t *smb_smf_scf_init(char *);
extern void smb_smf_scf_fini(smb_scfhandle_t *);
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
extern int smb_smf_delete_property(smb_scfhandle_t *, char *);
extern int smb_smf_restart_service(void);
extern int smb_smf_maintenance_mode(void);

/* ZFS interface */
int smb_getdataset(const char *, char *, size_t);

/* Configuration management functions  */
extern int smb_config_get(smb_cfg_id_t, char *, int);
extern char *smb_config_getname(smb_cfg_id_t);
extern int smb_config_getstr(smb_cfg_id_t, char *, int);
extern int smb_config_getnum(smb_cfg_id_t, int64_t *);
extern boolean_t smb_config_getbool(smb_cfg_id_t);

extern int smb_config_set(smb_cfg_id_t, char *);
extern int smb_config_setstr(smb_cfg_id_t, char *);
extern int smb_config_setnum(smb_cfg_id_t, int64_t);
extern int smb_config_setbool(smb_cfg_id_t, boolean_t);

extern boolean_t smb_config_get_ads_enable(void);
extern int smb_config_get_debug(void);
extern uint8_t smb_config_get_fg_flag(void);
extern char *smb_config_get_localsid(void);
extern int smb_config_get_localuuid(uuid_t);
extern int smb_config_secmode_fromstr(char *);
extern char *smb_config_secmode_tostr(int);
extern int smb_config_get_secmode(void);
extern int smb_config_set_secmode(int);
extern int smb_config_set_idmap_domain(char *);
extern int smb_config_refresh_idmap(void);
extern int smb_config_getip(smb_cfg_id_t, smb_inaddr_t *);
extern void smb_config_get_version(smb_version_t *);
uint32_t smb_config_get_execinfo(char *, char *, size_t);
extern void smb_config_get_negtok(uchar_t *, uint32_t *);

extern int smb_config_check_protocol(char *);
extern uint32_t smb_config_get_max_protocol(void);
extern void smb_config_upgrade(void);

extern void smb_load_kconfig(smb_kmod_cfg_t *kcfg);
extern uint32_t smb_crc_gen(uint8_t *, size_t);

extern boolean_t smb_match_netlogon_seqnum(void);
extern int smb_setdomainprops(char *, char *, char *);
extern void smb_update_netlogon_seqnum(void);

/* maximum password length on Windows 2000 and above */
#define	SMB_PASSWD_MAXLEN	127
#define	SMB_USERNAME_MAXLEN	40

/* See also: smb_joininfo_xdr() */
typedef struct smb_joininfo {
	char domain_name[MAXHOSTNAMELEN];
	char domain_username[SMB_USERNAME_MAXLEN + 1];
	char domain_passwd[SMB_PASSWD_MAXLEN + 1];
	uint32_t mode;
} smb_joininfo_t;

/* See also: smb_joinres_xdr() */
typedef struct smb_joinres {
	uint32_t status;
	int join_err;
	char dc_name[MAXHOSTNAMELEN];
} smb_joinres_t;

/* APIs to communicate with SMB daemon via door calls */
int smb_join(smb_joininfo_t *, smb_joinres_t *info);
bool_t smb_joininfo_xdr(XDR *, smb_joininfo_t *);
bool_t smb_joinres_xdr(XDR *, smb_joinres_t *);
boolean_t smb_find_ads_server(char *, char *, int);
void smb_notify_dc_changed(void);

extern void smb_config_getdomaininfo(char *, char *, char *, char *, char *);
extern void smb_config_setdomaininfo(char *, char *, char *, char *, char *);
extern uint32_t smb_get_dcinfo(char *, uint32_t, smb_inaddr_t *);

/*
 * buffer context structure. This is used to keep track of the buffer
 * context.
 *
 * basep:  points to the beginning of the buffer
 * curp:   points to the current offset
 * endp:   points to the limit of the buffer
 */
typedef struct {
	unsigned char *basep;
	unsigned char *curp;
	unsigned char *endp;
} smb_ctxbuf_t;

extern int smb_ctxbuf_init(smb_ctxbuf_t *ctx, unsigned char *buf,
    size_t buflen);
extern int smb_ctxbuf_len(smb_ctxbuf_t *ctx);
extern int smb_ctxbuf_printf(smb_ctxbuf_t *ctx, const char *fmt, ...);

void smb_idmap_check(const char *, idmap_stat);

/* Miscellaneous functions */
extern void hexdump(unsigned char *, int);
extern size_t bintohex(const char *, size_t, char *, size_t);
extern size_t hextobin(const char *, size_t, char *, size_t);
extern char *strstrip(char *, const char *);
extern char *strtrim(char *, const char *);
extern char *trim_whitespace(char *);
extern void randomize(char *, unsigned);
extern void rand_hash(unsigned char *, size_t, unsigned char *, size_t);

extern int smb_getdomainname(char *, size_t);
extern int smb_getfqdomainname(char *, size_t);

typedef enum smb_caseconv {
	SMB_CASE_PRESERVE = 0,
	SMB_CASE_UPPER,
	SMB_CASE_LOWER
} smb_caseconv_t;

extern int smb_gethostname(char *, size_t, smb_caseconv_t);
extern int smb_getfqhostname(char *, size_t);
extern int smb_getnetbiosname(char *, size_t);
extern struct hostent *smb_gethostbyname(const char *, int *);
extern struct hostent *smb_gethostbyaddr(const char *, int, int, int *);

#define	SMB_SAMACCT_MAXLEN	(NETBIOS_NAME_SZ + 1)
extern int smb_getsamaccount(char *, size_t);

extern int smb_get_nameservers(smb_inaddr_t *, int);
extern void smb_tonetbiosname(char *, char *, char);

extern int smb_chk_hostaccess(smb_inaddr_t *, char *);

extern int smb_getnameinfo(smb_inaddr_t *, char *, int, int);

void smb_trace(const char *s);
void smb_tracef(const char *fmt, ...);

const char *xlate_nt_status(unsigned int);

void libsmb_redirect_syslog(__FILE_TAG *fp, int priority);

/*
 * Authentication
 */

#define	SMBAUTH_LM_MAGIC_STR	"KGS!@#$%"

#define	SMBAUTH_HASH_SZ		16	/* also LM/NTLM/NTLMv2 Hash size */
#define	SMBAUTH_LM_RESP_SZ	24	/* also NTLM Response size */
#define	SMBAUTH_LM_PWD_SZ	14	/* LM password size */
#define	SMBAUTH_CHAL_SZ		 8	/* both LMv2 and NTLMv2 */
#define	SMBAUTH_SESSION_KEY_SZ	SMBAUTH_HASH_SZ
#define	SMBAUTH_HEXHASH_SZ	(SMBAUTH_HASH_SZ * 2)

#define	SMBAUTH_FAILURE		1
#define	SMBAUTH_SUCCESS		0
#define	MD_DIGEST_LEN		16

/*
 * Name Types
 *
 * The list of names near the end of the data blob (i.e. the ndb_names
 * field of the smb_auth_data_blob_t data structure) can be classify into
 * the following types:
 *
 * 0x0000 Indicates the end of the list.
 * 0x0001 The name is a NetBIOS machine name (e.g. server name)
 * 0x0002 The name is an NT Domain NetBIOS name.
 * 0x0003 The name is the server's DNS hostname.
 * 0x0004 The name is a W2K Domain name (a DNS name).
 */
#define	SMBAUTH_NAME_TYPE_LIST_END		0x0000
#define	SMBAUTH_NAME_TYPE_SERVER_NETBIOS 	0x0001
#define	SMBAUTH_NAME_TYPE_DOMAIN_NETBIOS 	0x0002
#define	SMBAUTH_NAME_TYPE_SERVER_DNS		0x0003
#define	SMBAUTH_NAME_TYPE_DOMAIN_DNS 		0x0004

/*
 * smb_auth_name_entry_t
 *
 * Each name entry in the data blob consists of the following 3 fields:
 *
 * nne_type - name type
 * nne_len  - the length of the name
 * nne_name - the name, in uppercase UCS-2LE Unicode format
 */
typedef struct smb_auth_name_entry {
	unsigned short nne_type;
	unsigned short nne_len;
	smb_wchar_t nne_name[SMB_PI_MAX_DOMAIN * 2];
} smb_auth_name_entry_t;

/*
 * smb_auth_data_blob
 *
 * The format of this NTLMv2 data blob structure is as follow:
 *
 *	- Blob Signature 0x01010000 (4 bytes)
 * - Reserved (0x00000000) (4 bytes)
 * - Timestamp Little-endian, 64-bit signed value representing
 *   the number of tenths of a microsecond since January 1, 1601.
 *   (8 bytes)
 * - Client Challenge (8 bytes)
 * - Unknown1 (4 bytes)
 * - List of Target Information (variable length)
 * - Unknown2 (4 bytes)
 */
typedef struct smb_auth_data_blob {
	unsigned char ndb_signature[4];
	unsigned char ndb_reserved[4];
	uint64_t ndb_timestamp;
	unsigned char ndb_clnt_challenge[SMBAUTH_CHAL_SZ];
	unsigned char ndb_unknown[4];
	smb_auth_name_entry_t ndb_names[2];
	unsigned char ndb_unknown2[4];
} smb_auth_data_blob_t;

#define	SMBAUTH_BLOB_MAXLEN (sizeof (smb_auth_data_blob_t))
#define	SMBAUTH_CI_MAXLEN   SMBAUTH_LM_RESP_SZ
#define	SMBAUTH_CS_MAXLEN   (SMBAUTH_BLOB_MAXLEN + SMBAUTH_HASH_SZ)

/*
 * smb_auth_info_t
 *
 * The structure contains all the authentication information
 * needed for the preparaton of the SMBSessionSetupAndx request
 * and the user session key.
 *
 * hash      - NTLM hash
 * hash_v2   - NTLMv2 hash
 * ci_len    - the length of the case-insensitive password
 * ci        - case-insensitive password
 *             (If NTLMv2 authentication mechanism is used, it
 *              represents the LMv2 response. Otherwise, it
 *              is empty.)
 * cs_len    - the length of the case-sensitive password
 * cs        - case-sensitive password
 *             (If NTLMv2 authentication mechanism is used, it
 *              represents the NTLMv2 response. Otherwise, it
 *              represents the NTLM response.)
 * data_blob - NTLMv2 data blob
 */
typedef struct smb_auth_info {
	unsigned char hash[SMBAUTH_HASH_SZ];
	unsigned char hash_v2[SMBAUTH_HASH_SZ];
	unsigned short ci_len;
	unsigned char ci[SMBAUTH_CI_MAXLEN];
	unsigned short cs_len;
	unsigned char cs[SMBAUTH_CS_MAXLEN];
	int lmcompatibility_lvl;
	smb_auth_data_blob_t data_blob;
} smb_auth_info_t;

/*
 * SMB password management
 */

#define	SMB_PWF_LM	0x01	/* LM hash is present */
#define	SMB_PWF_NT	0x02	/* NT hash is present */
#define	SMB_PWF_DISABLE	0x04	/* Account is disabled */

typedef struct smb_passwd {
	uid_t		pw_uid;
	uint32_t	pw_flags;
	char		pw_name[SMB_USERNAME_MAXLEN];
	uint8_t		pw_lmhash[SMBAUTH_HASH_SZ];
	uint8_t		pw_nthash[SMBAUTH_HASH_SZ];
} smb_passwd_t;

/*
 * Control flags passed to smb_pwd_setcntl
 */
#define	SMB_PWC_DISABLE	0x01
#define	SMB_PWC_ENABLE	0x02
#define	SMB_PWC_NOLM	0x04

#define	SMB_PWE_SUCCESS		0
#define	SMB_PWE_USER_UNKNOWN	1
#define	SMB_PWE_USER_DISABLE	2
#define	SMB_PWE_CLOSE_FAILED	3
#define	SMB_PWE_OPEN_FAILED	4
#define	SMB_PWE_WRITE_FAILED	6
#define	SMB_PWE_UPDATE_FAILED	7
#define	SMB_PWE_STAT_FAILED	8
#define	SMB_PWE_BUSY		9
#define	SMB_PWE_DENIED		10
#define	SMB_PWE_SYSTEM_ERROR	11
#define	SMB_PWE_INVALID_PARAM	12
#define	SMB_PWE_NO_MEMORY	13
#define	SMB_PWE_MAX		14

typedef struct smb_pwditer {
	void *spi_next;
} smb_pwditer_t;

typedef struct smb_luser {
	char *su_name;
	char *su_fullname;
	char *su_desc;
	uint32_t su_rid;
	uint32_t su_ctrl;
} smb_luser_t;

extern void smb_pwd_init(boolean_t);
extern void smb_pwd_fini(void);
extern smb_passwd_t *smb_pwd_getpwnam(const char *, smb_passwd_t *);
extern smb_passwd_t *smb_pwd_getpwuid(uid_t, smb_passwd_t *);
extern int smb_pwd_setpasswd(const char *, const char *);
extern int smb_pwd_setcntl(const char *, int);

extern int smb_pwd_iteropen(smb_pwditer_t *);
extern smb_luser_t *smb_pwd_iterate(smb_pwditer_t *);
extern void smb_pwd_iterclose(smb_pwditer_t *);

extern int smb_auth_qnd_unicode(smb_wchar_t *, const char *, int);
extern int smb_auth_hmac_md5(unsigned char *, int, unsigned char *, int,
    unsigned char *);

/*
 * A variation on HMAC-MD5 known as HMACT64 is used by Windows systems.
 * The HMACT64() function is the same as the HMAC-MD5() except that
 * it truncates the input key to 64 bytes rather than hashing it down
 * to 16 bytes using the MD5() function.
 */
#define	SMBAUTH_HMACT64(D, Ds, K, Ks, digest) \
	smb_auth_hmac_md5(D, Ds, K, (Ks > 64) ? 64 : Ks, digest)

extern int smb_auth_DES(unsigned char *, int, unsigned char *, int,
    unsigned char *, int);
extern int smb_auth_RC4(unsigned char *, int, unsigned char *, int,
    unsigned char *, int);

extern int smb_auth_md4(unsigned char *, unsigned char *, int);
extern int smb_auth_lm_hash(const char *, unsigned char *);
extern int smb_auth_ntlm_hash(const char *, unsigned char *);
extern void smb_auth_ntlm2_mkchallenge(char *, const char *, const char *);
extern void smb_auth_ntlm2_kxkey(unsigned char *, const char *, const char *,
    unsigned char *);

extern int smb_auth_set_info(char *, char *,
    unsigned char *, char *, unsigned char *,
    int, int, smb_auth_info_t *);

extern int smb_auth_ntlmv2_hash(unsigned char *,
	char *, char *, unsigned char *);

boolean_t smb_auth_validate(smb_passwd_t *, char *, char *,
    uchar_t *, uint_t, uchar_t *, uint_t, uchar_t *, uint_t, uchar_t *);

int smb_gen_random_passwd(char *passwd, size_t bufsz);

/*
 * SMB authenticated IPC
 */
extern void smb_ipc_commit(void);
extern void smb_ipc_get_user(char *, size_t);
extern void smb_ipc_get_passwd(uint8_t *, size_t);
extern void smb_ipc_init(void);
extern void smb_ipc_rollback(void);
extern void smb_ipc_set(char *, uint8_t *);

/*
 * Signing flags:
 *
 * SMB_SCF_ENABLE                 Signing is enabled.
 *
 * SMB_SCF_REQUIRED               Signing is enabled and required.
 *                                This flag shouldn't be set if
 *                                SMB_SCF_ENABLE isn't set.
 *
 * SMB_SCF_STARTED                Signing will start after receiving
 *                                the first non-anonymous SessionSetup
 *                                request.
 *
 * SMB_SCF_KEY_ISSET_THIS_LOGON   Indicates whether the MAC key has just
 *                                been set for this logon. (prior to
 *                                sending the SMBSessionSetup request)
 *
 */
#define	SMB_SCF_ENABLE		0x01
#define	SMB_SCF_REQUIRED	0x02
#define	SMB_SCF_STARTED		0x04
#define	SMB_SCF_KEY_ISSET_THIS_LOGON	0x08

/*
 * Each domain is categorized using the enum values below.
 * The local domain refers to the local machine and is named
 * after the local hostname. The primary domain is the domain
 * that the system joined. All other domains are either
 * trusted or untrusted, as defined by the primary domain PDC.
 */
typedef enum smb_domain_type {
	SMB_DOMAIN_NULL,
	SMB_DOMAIN_BUILTIN,
	SMB_DOMAIN_LOCAL,
	SMB_DOMAIN_PRIMARY,
	SMB_DOMAIN_ACCOUNT,
	SMB_DOMAIN_TRUSTED,
	SMB_DOMAIN_UNTRUSTED,
	SMB_DOMAIN_NUM_TYPES
} smb_domain_type_t;

/*
 * Information specific to trusted domains
 */
typedef struct smb_domain_trust {
	uint32_t		dti_trust_direction;
	uint32_t		dti_trust_type;
	uint32_t		dti_trust_attrs;
} smb_domain_trust_t;

/*
 * DNS information for domain types that this info is
 * obtained/available. Currently this is only obtained
 * for the primary domain.
 */
typedef struct smb_domain_dns {
	char			ddi_forest[MAXHOSTNAMELEN];
	char			ddi_guid[UUID_PRINTABLE_STRING_LENGTH];
} smb_domain_dns_t;

/*
 * This is the information that is held about each domain.
 */
typedef struct smb_domain {
	list_node_t		di_lnd;
	smb_domain_type_t	di_type;
	char			di_sid[SMB_SID_STRSZ];
	char			di_nbname[NETBIOS_NAME_SZ];
	char			di_fqname[MAXHOSTNAMELEN];
	smb_sid_t		*di_binsid;
	union {
		smb_domain_dns_t	di_dns;
		smb_domain_trust_t	di_trust;
	} di_u;
} smb_domain_t;

typedef struct smb_trusted_domains {
	uint32_t	td_num;
	smb_domain_t	*td_domains;
} smb_trusted_domains_t;

#define	SMB_DOMAIN_SUCCESS		0
#define	SMB_DOMAIN_NOMACHINE_SID	1
#define	SMB_DOMAIN_NODOMAIN_SID		2
#define	SMB_DOMAIN_NODOMAIN_NAME	3
#define	SMB_DOMAIN_INTERNAL_ERR		4
#define	SMB_DOMAIN_INVALID_ARG		5
#define	SMB_DOMAIN_NO_MEMORY		6
#define	SMB_DOMAIN_NO_CACHE		7

typedef struct smb_dcinfo {
	char			dc_name[MAXHOSTNAMELEN];
	smb_inaddr_t		dc_addr;
} smb_dcinfo_t;

/*
 * This structure could contain information about
 * the primary domain the name of selected domain controller
 * for the primary domain and a list of trusted domains if
 * any. The "ex" in the structure name stands for extended.
 * This is to differentiate this structure from smb_domain_t
 * which only contains information about a single domain.
 */
typedef struct smb_domainex {
	smb_dcinfo_t		d_dci;
	smb_domain_t		d_primary;
	smb_trusted_domains_t	d_trusted;
} smb_domainex_t;

int smb_domain_init(uint32_t);
void smb_domain_fini(void);
void smb_domain_show(void);
void smb_domain_save(void);
boolean_t smb_domain_lookup_name(char *, smb_domain_t *);
boolean_t smb_domain_lookup_sid(smb_sid_t *, smb_domain_t *);
boolean_t smb_domain_lookup_type(smb_domain_type_t, smb_domain_t *);
boolean_t smb_domain_getinfo(smb_domainex_t *);
void smb_domain_update(smb_domainex_t *);
uint32_t smb_domain_start_update(void);
void smb_domain_end_update(void);
void smb_domain_set_basic_info(char *, char *, char *, smb_domain_t *);
void smb_domain_set_dns_info(char *, char *, char *, char *, char *,
    smb_domain_t *);
void smb_domain_set_trust_info(char *, char *, char *,
    uint32_t, uint32_t, uint32_t, smb_domain_t *);
void smb_domain_current_dc(smb_dcinfo_t *);

typedef struct smb_gsid {
	smb_sid_t *gs_sid;
	uint16_t gs_type;
} smb_gsid_t;

struct sqlite_vm;
struct sqlite;

typedef struct smb_giter {
	struct sqlite_vm	*sgi_vm;
	struct sqlite		*sgi_db;
	uint32_t		sgi_nerr;
} smb_giter_t;

typedef struct smb_group {
	char			*sg_name;
	char			*sg_cmnt;
	uint32_t		sg_attr;
	uint32_t		sg_rid;
	smb_gsid_t		sg_id;
	smb_domain_type_t	sg_domain;
	smb_privset_t		*sg_privs;
	uint32_t		sg_nmembers;
	smb_gsid_t		*sg_members;
} smb_group_t;

int smb_lgrp_start(void);
void smb_lgrp_stop(void);
int smb_lgrp_add(char *, char *);
int smb_lgrp_rename(char *, char *);
int smb_lgrp_delete(char *);
int smb_lgrp_setcmnt(char *, char *);
int smb_lgrp_getcmnt(char *, char **);
int smb_lgrp_getpriv(char *, uint8_t, boolean_t *);
int smb_lgrp_setpriv(char *, uint8_t, boolean_t);
int smb_lgrp_add_member(char *, smb_sid_t *, uint16_t);
int smb_lgrp_del_member(char *, smb_sid_t *, uint16_t);
int smb_lgrp_getbyname(char *, smb_group_t *);
int smb_lgrp_getbyrid(uint32_t, smb_domain_type_t, smb_group_t *);
void smb_lgrp_free(smb_group_t *);
uint32_t smb_lgrp_err_to_ntstatus(uint32_t);
boolean_t smb_lgrp_is_member(smb_group_t *, smb_sid_t *);
char *smb_lgrp_strerror(int);
int smb_lgrp_iteropen(smb_giter_t *);
void smb_lgrp_iterclose(smb_giter_t *);
boolean_t smb_lgrp_itererror(smb_giter_t *);
int smb_lgrp_iterate(smb_giter_t *, smb_group_t *);

int smb_lookup_sid(const char *, lsa_account_t *);
int smb_lookup_name(const char *, sid_type_t, lsa_account_t *);

#define	SMB_LGRP_SUCCESS		0
#define	SMB_LGRP_INVALID_ARG		1
#define	SMB_LGRP_INVALID_MEMBER		2
#define	SMB_LGRP_INVALID_NAME		3
#define	SMB_LGRP_NOT_FOUND		4
#define	SMB_LGRP_EXISTS			5
#define	SMB_LGRP_NO_SID			6
#define	SMB_LGRP_NO_LOCAL_SID		7
#define	SMB_LGRP_SID_NOTLOCAL		8
#define	SMB_LGRP_WKSID			9
#define	SMB_LGRP_NO_MEMORY		10
#define	SMB_LGRP_DB_ERROR		11
#define	SMB_LGRP_DBINIT_ERROR		12
#define	SMB_LGRP_INTERNAL_ERROR		13
#define	SMB_LGRP_MEMBER_IN_GROUP	14
#define	SMB_LGRP_MEMBER_NOT_IN_GROUP	15
#define	SMB_LGRP_NO_SUCH_PRIV		16
#define	SMB_LGRP_NO_SUCH_DOMAIN		17
#define	SMB_LGRP_PRIV_HELD		18
#define	SMB_LGRP_PRIV_NOT_HELD		19
#define	SMB_LGRP_BAD_DATA		20
#define	SMB_LGRP_NO_MORE		21
#define	SMB_LGRP_DBOPEN_FAILED		22
#define	SMB_LGRP_DBEXEC_FAILED		23
#define	SMB_LGRP_DBINIT_FAILED		24
#define	SMB_LGRP_DOMLKP_FAILED		25
#define	SMB_LGRP_DOMINS_FAILED		26
#define	SMB_LGRP_INSERT_FAILED		27
#define	SMB_LGRP_DELETE_FAILED		28
#define	SMB_LGRP_UPDATE_FAILED		29
#define	SMB_LGRP_LOOKUP_FAILED		30
#define	SMB_LGRP_NOT_SUPPORTED		31
#define	SMB_LGRP_OFFLINE		32
#define	SMB_LGRP_POSIXCREATE_FAILED	33

#define	SMB_LGRP_COMMENT_MAX	256

/*
 * values for smb_nic_t.smbflags
 */
#define	SMB_NICF_NBEXCL		0x01	/* Excluded from Netbios activities */
#define	SMB_NICF_ALIAS		0x02	/* This is an alias */

/*
 * smb_nic_t
 *     nic_host		actual host name
 *     nic_nbname	16-byte NetBIOS host name
 */
typedef struct {
	char		nic_host[MAXHOSTNAMELEN];
	char		nic_nbname[NETBIOS_NAME_SZ];
	char		nic_cmnt[SMB_PI_MAX_COMMENT];
	char		nic_ifname[LIFNAMSIZ];
	smb_inaddr_t	nic_ip;
	uint32_t	nic_mask;
	uint32_t	nic_bcast;
	uint32_t	nic_smbflags;
	uint64_t	nic_sysflags;
} smb_nic_t;

typedef struct smb_niciter {
	smb_nic_t ni_nic;
	int ni_cookie;
	int ni_seqnum;
} smb_niciter_t;

/* NIC config functions */
int smb_nic_init(void);
void smb_nic_fini(void);
int smb_nic_getnum(char *);
int smb_nic_addhost(const char *, const char *, int, const char **);
int smb_nic_delhost(const char *);
int smb_nic_getfirst(smb_niciter_t *);
int smb_nic_getnext(smb_niciter_t *);
boolean_t smb_nic_is_local(smb_inaddr_t *);
boolean_t smb_nic_is_same_subnet(smb_inaddr_t *);

#define	SMB_NIC_SUCCESS			0
#define	SMB_NIC_INVALID_ARG		1
#define	SMB_NIC_NOT_FOUND		2
#define	SMB_NIC_NO_HOST			3
#define	SMB_NIC_NO_MEMORY		4
#define	SMB_NIC_DB_ERROR		5
#define	SMB_NIC_DBINIT_ERROR		6
#define	SMB_NIC_BAD_DATA		7
#define	SMB_NIC_NO_MORE			8
#define	SMB_NIC_DBOPEN_FAILED		9
#define	SMB_NIC_DBEXEC_FAILED		10
#define	SMB_NIC_DBINIT_FAILED		11
#define	SMB_NIC_INSERT_FAILED		12
#define	SMB_NIC_DELETE_FAILED		13
#define	SMB_NIC_SOCK			14
#define	SMB_NIC_IOCTL			15
#define	SMB_NIC_CHANGED			16

/*
 * Well-known account structure
 *
 * A security identifier (SID) is a unique value of variable length that
 * is used to identify a security principal or security group in
 * Windows. Well-known SIDs are a group of SIDs that identify generic
 * users or generic groups. Their values remain constant across all
 * operating systems.
 *
 * This structure is defined to store these SIDs and other related
 * information about them (e.g. account and domain names) in a
 * predefined table.
 */
typedef struct smb_wka {
	uint8_t		wka_domidx;
	char		*wka_sid;
	char		*wka_name;
	uint16_t	wka_type;
	uint16_t	wka_flags;
	char		*wka_desc;
	smb_sid_t	*wka_binsid;
} smb_wka_t;

/*
 * Defined values for smb_wka.wka_flags
 *
 * SMB_WKAFLG_LGRP_ENABLE		Can be added as local group
 */
#define	SMB_WKAFLG_LGRP_ENABLE	0x1

/*
 * Well-known account interfaces
 */
smb_wka_t *smb_wka_lookup_builtin(const char *);
smb_wka_t *smb_wka_lookup_name(const char *);
smb_wka_t *smb_wka_lookup_sid(smb_sid_t *);
smb_sid_t *smb_wka_get_sid(const char *);
char *smb_wka_get_domain(int);
uint32_t smb_wka_token_groups(uint32_t, smb_ids_t *);

/*
 * In memory account representation
 */
typedef struct smb_account {
	char		*a_name;
	char		*a_domain;
	uint16_t	a_type;
	smb_sid_t	*a_sid;
	smb_sid_t	*a_domsid;
	uint32_t	a_rid;
} smb_account_t;

uint32_t smb_sam_lookup_name(char *, char *, uint16_t, smb_account_t *);
uint32_t smb_sam_lookup_sid(smb_sid_t *, smb_account_t *);
int smb_sam_usr_cnt(void);
uint32_t smb_sam_usr_groups(smb_sid_t *, smb_ids_t *);
int smb_sam_grp_cnt(smb_domain_type_t);
void smb_account_free(smb_account_t *);
boolean_t smb_account_validate(smb_account_t *);

/*
 * Security Descriptor functions.
 */
uint32_t smb_sd_read(char *path, smb_sd_t *, uint32_t);
uint32_t smb_sd_write(char *path, smb_sd_t *, uint32_t);
uint32_t smb_sd_fromfs(smb_fssd_t *, smb_sd_t *);

/* Kernel Module Interface */
int smb_kmod_bind(void);
boolean_t smb_kmod_isbound(void);
int smb_kmod_setcfg(smb_kmod_cfg_t *);
int smb_kmod_setgmtoff(int32_t);
int smb_kmod_start(int, int, int);
void smb_kmod_stop(void);
int smb_kmod_event_notify(uint32_t);
void smb_kmod_unbind(void);
int smb_kmod_share(nvlist_t *);
int smb_kmod_unshare(nvlist_t *);
int smb_kmod_shareinfo(char *, boolean_t *);
int smb_kmod_get_open_num(smb_opennum_t *);
int smb_kmod_enum(smb_netsvc_t *);
smb_netsvc_t *smb_kmod_enum_init(smb_svcenum_t *);
void smb_kmod_enum_fini(smb_netsvc_t *);
int smb_kmod_session_close(const char *, const char *);
int smb_kmod_file_close(uint32_t);
int smb_kmod_get_spool_doc(uint32_t *, char *, char *, smb_inaddr_t *);

void smb_name_parse(char *, char **, char **);
uint32_t smb_name_validate_share(const char *);
uint32_t smb_name_validate_account(const char *);
uint32_t smb_name_validate_domain(const char *);
uint32_t smb_name_validate_nbdomain(const char *);
uint32_t smb_name_validate_workgroup(const char *);
uint32_t smb_name_validate_rpath(const char *);

/*
 * Interposer library validation
 */
#define	SMBEX_VERSION	1
#define	SMBEX_KEY	"82273fdc-e32a-18c3-3f78-827929dc23ea"
typedef struct smbex_version {
	uint32_t v_version;
	uuid_t v_uuid;
} smbex_version_t;
void *smb_dlopen(void);
void smb_dlclose(void *);

/*
 * General purpose multi-thread safe cache based on
 * AVL tree
 */
typedef struct smb_cache {
	avl_tree_t	ch_cache;
	rwlock_t	ch_cache_lck;
	uint32_t	ch_state;
	uint32_t	ch_nops;
	uint32_t	ch_wait;
	uint32_t	ch_sequence;
	size_t		ch_datasz;
	mutex_t		ch_mtx;
	cond_t		ch_cv;
	void		(*ch_free)(void *);
	void		(*ch_copy)(const void *, void *, size_t);
} smb_cache_t;

typedef struct smb_cache_node {
	avl_node_t	cn_link;
	void		*cn_data;
} smb_cache_node_t;

typedef struct smb_cache_cursor {
	void		*cc_next;
	uint32_t	cc_sequence;
} smb_cache_cursor_t;

/*
 * flags used with smb_cache_add()
 *
 * SMB_CACHE_ADD	If object doesn't exist add, otherwise fail
 * SMB_CACHE_REPLACE	If object doesn't exist add, otherwise replace
 */
#define	SMB_CACHE_ADD		1
#define	SMB_CACHE_REPLACE	2

void smb_cache_create(smb_cache_t *, uint32_t,
    int (*cmpfn) (const void *, const void *), void (*freefn)(void *),
    void (*copyfn)(const void *, void *, size_t), size_t);
void smb_cache_destroy(smb_cache_t *);
void smb_cache_flush(smb_cache_t *);
uint32_t smb_cache_num(smb_cache_t *);
int smb_cache_refreshing(smb_cache_t *);
void smb_cache_ready(smb_cache_t *);
int smb_cache_add(smb_cache_t *, const void *, int);
void smb_cache_remove(smb_cache_t *, const void *);
void smb_cache_iterinit(smb_cache_t *, smb_cache_cursor_t *);
boolean_t smb_cache_iterate(smb_cache_t *, smb_cache_cursor_t *, void *);

/*
 * Values returned by smb_reparse_stat()
 */
#define	SMB_REPARSE_NOTFOUND	1	/* object does not exist */
#define	SMB_REPARSE_NOTREPARSE	2	/* object is NOT a reparse point */
#define	SMB_REPARSE_ISREPARSE	3	/* object is a reparse point */

/*
 * Reparse Point API
 */
int smb_reparse_stat(const char *, uint32_t *);
int smb_reparse_svcadd(const char *, const char *, const char *);
int smb_reparse_svcdel(const char *, const char *);
int smb_reparse_svcget(const char *, const char *, char **);

uint32_t smb_get_txid(void);

void smb_syslog(int, const char *, ...);
void smb_vsyslog(int, const char *, va_list ap);
char *smb_syslog_fmt_m(char *, int, const char *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSMB_H */
