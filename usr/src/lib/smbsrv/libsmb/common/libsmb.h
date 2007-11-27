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

#ifndef	_LIBSMB_H
#define	_LIBSMB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <libscf.h>
#include <libshare.h>

#include <smbsrv/smb_idmap.h>

/*
 * XXX - These header files are here, only because other libraries
 * can compile. Move the header files in to the internal header files
 * of other libraries, once the restructure is complete. libsmb.h does not
 * need these header files.
 */
#include <smbsrv/lmshare.h>
#include <smbsrv/lmshare_door.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/smb_door_svc.h>
#include <smbsrv/alloc.h>
#include <smbsrv/codepage.h>
#include <smbsrv/crypt.h>
#include <smbsrv/ctype.h>
#include <smbsrv/hash_table.h>
#include <smbsrv/msgbuf.h>
#include <smbsrv/oem.h>
#include <smbsrv/string.h>
#include <smbsrv/smb_i18n.h>
#include <smbsrv/wintypes.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/smbinfo.h>
/* End of header files to be removed. */

/* Max value length of all SMB properties */
#define	MAX_VALUE_BUFLEN	512
#define	SMB_PI_MAX_DOMAIN_U	48

#define	SMBD_FMRI_PREFIX		"network/smb/server"
#define	SMBD_DEFAULT_INSTANCE_FMRI	"svc:/network/smb/server:default"
#define	SMBD_PG_NAME			"smbd"
#define	SMBD_PROTECTED_PG_NAME		"read"

#define	SMBD_SMF_OK		0
#define	SMBD_SMF_NO_MEMORY	1	/* no memory for data structures */
#define	SMBD_SMF_SYSTEM_ERR	2	/* system error, use errno */
#define	SMBD_SMF_NO_PERMISSION	3	/* no permission for operation */

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

/* macros for the description of all config params */
#define	SMB_CD_RDR_IPCMODE		"rdr_ipcmode"
#define	SMB_CD_RDR_IPCUSER 		"rdr_ipcuser"
#define	SMB_CD_RDR_IPCPWD		"rdr_ipcpasswd"

#define	SMB_CD_OPLOCK_ENABLE		"oplock_enable"
#define	SMB_CD_OPLOCK_TIMEOUT		"oplock_timeout"

#define	SMB_CD_AUTOHOME_MAP		"autohome_map"

#define	SMB_CD_DOMAIN_SID		"domain_sid"
#define	SMB_CD_DOMAIN_MEMB		"domain_member"
#define	SMB_CD_DOMAIN_NAME		"domain_name"
#define	SMB_CD_DOMAIN_SRV		"pdc"

#define	SMB_CD_WINS_SRV1		"wins_server_1"
#define	SMB_CD_WINS_SRV2		"wins_server_2"
#define	SMB_CD_WINS_EXCL		"wins_exclude"

#define	SMB_CD_SRVSVC_SHRSET_ENABLE	"srvsvc_sharesetinfo_enable"
#define	SMB_CD_LOGR_ENABLE		"logr_enable"
#define	SMB_CD_MLRPC_KALIVE		"mlrpc_keep_alive_interval"

#define	SMB_CD_MAX_BUFSIZE		"max_bufsize"
#define	SMB_CD_MAX_WORKERS		"max_workers"
#define	SMB_CD_MAX_CONNECTIONS		"max_connections"
#define	SMB_CD_KEEPALIVE		"keep_alive"
#define	SMB_CD_RESTRICT_ANON		"restrict_anonymous"

#define	SMB_CD_SIGNING_ENABLE		"signing_enabled"
#define	SMB_CD_SIGNING_REQD		"signing_required"
#define	SMB_CD_SIGNING_CHECK		"signing_check"

#define	SMB_CD_FLUSH_REQUIRED		"flush_required"
#define	SMB_CD_SYNC_ENABLE		"sync_enable"
#define	SMB_CD_DIRSYMLINK_DISABLE	"dir_symlink_disable"
#define	SMB_CD_ANNONCE_QUOTA		"announce_quota"

#define	SMB_CD_SECURITY			"security"
#define	SMB_CD_NBSCOPE			"netbios_scope"
#define	SMB_CD_SYS_CMNT			"system_comment"
#define	SMB_CD_LM_LEVEL			"lmauth_level"
#define	SMB_CD_MSDCS_DISABLE		"msdcs_disable"

#define	SMB_CD_ADS_ENABLE		"ads_enable"
#define	SMB_CD_ADS_USER			"ads_user"
#define	SMB_CD_ADS_PASSWD		"ads_passwd"
#define	SMB_CD_ADS_DOMAIN		"ads_domain"
#define	SMB_CD_ADS_USER_CONTAINER	"ads_user_container"
#define	SMB_CD_ADS_SITE			"ads_site"
#define	SMB_CD_ADS_IPLOOKUP		"ads_ip_lookup"

#define	SMB_CD_DYNDNS_ENABLE		"ddns_enable"
#define	SMB_CD_DYNDNS_RETRY_COUNT	"ddns_retry_cnt"
#define	SMB_CD_DYNDNS_RETRY_SEC		"ddns_retry_sec"

#define	SMB_CD_MACHINE_PASSWD		"machine_passwd"

/* configuration identifier */
typedef enum {
	SMB_CI_RDR_IPCMODE = 0,
	SMB_CI_RDR_IPCUSER,
	SMB_CI_RDR_IPCPWD,

	SMB_CI_OPLOCK_ENABLE,
	SMB_CI_OPLOCK_TIMEOUT,

	SMB_CI_AUTOHOME_MAP,

	SMB_CI_DOMAIN_SID,
	SMB_CI_DOMAIN_MEMB,
	SMB_CI_DOMAIN_NAME,
	SMB_CI_DOMAIN_SRV,

	SMB_CI_WINS_SRV1,
	SMB_CI_WINS_SRV2,
	SMB_CI_WINS_EXCL,

	SMB_CI_SRVSVC_SHRSET_ENABLE,
	SMB_CI_LOGR_ENABLE,
	SMB_CI_MLRPC_KALIVE,

	SMB_CI_MAX_BUFSIZE,
	SMB_CI_MAX_WORKERS,
	SMB_CI_MAX_CONNECTIONS,
	SMB_CI_KEEPALIVE,
	SMB_CI_RESTRICT_ANON,

	SMB_CI_SIGNING_ENABLE,
	SMB_CI_SIGNING_REQD,
	SMB_CI_SIGNING_CHECK,

	SMB_CI_FLUSH_REQUIRED,
	SMB_CI_SYNC_ENABLE,
	SMB_CI_DIRSYMLINK_DISABLE,
	SMB_CI_ANNONCE_QUOTA,

	SMB_CI_SECURITY,
	SMB_CI_NBSCOPE,
	SMB_CI_SYS_CMNT,
	SMB_CI_LM_LEVEL,
	SMB_CI_MSDCS_DISABLE,

	SMB_CI_ADS_ENABLE,
	SMB_CI_ADS_USER,
	SMB_CI_ADS_PASSWD,
	SMB_CI_ADS_DOMAIN,
	SMB_CI_ADS_USER_CONTAINER,
	SMB_CI_ADS_SITE,
	SMB_CI_ADS_IPLOOKUP,

	SMB_CI_DYNDNS_ENABLE,
	SMB_CI_DYNDNS_RETRY_COUNT,
	SMB_CI_DYNDNS_RETRY_SEC,

	SMB_CI_MACHINE_PASSWD,
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
extern int smb_smf_delete_service_pgroup(smb_scfhandle_t *, char *);
extern int smb_smf_create_instance_pgroup(smb_scfhandle_t *, char *);
extern int smb_smf_delete_instance_pgroup(smb_scfhandle_t *, char *);
extern int smb_smf_delete_property(smb_scfhandle_t *, char *);
extern int smb_smf_instance_exists(smb_scfhandle_t *, char *);
extern int smb_smf_instance_create(smb_scfhandle_t *, char *, char *);
extern int smb_smf_instance_delete(smb_scfhandle_t *, char *);
extern smb_scfhandle_t *smb_smf_get_iterator(char *);
extern int smb_smf_get_property(smb_scfhandle_t *, int, char *, char *,
    size_t);
extern int smb_smf_set_property(smb_scfhandle_t *, int, char *, char *);

/* Configuration management functions  */
extern int smb_config_load(void);
extern void smb_config_rdlock(void);
extern void smb_config_wrlock(void);
extern void smb_config_unlock(void);
extern char *smb_config_get(smb_cfg_id_t);
extern char *smb_config_getstr(smb_cfg_id_t);
extern int smb_config_getyorn(smb_cfg_id_t);
extern uint32_t smb_config_getnum(smb_cfg_id_t);

/*
 * smb_config_getenv
 *
 * Retrieves the property value from SMF.
 * Caller must free the returned buffer.
 *
 */
extern char *smb_config_getenv(smb_cfg_id_t id);

extern int smb_config_set(smb_cfg_id_t, char *);
extern int smb_config_setnum(smb_cfg_id_t, uint32_t);
extern uint8_t smb_config_get_fg_flag(void);
extern int smb_config_setenv(smb_cfg_id_t id, char *);
extern char *smb_config_get_localsid(void);
extern int smb_config_secmode_fromstr(char *secmode);
extern char *smb_config_secmode_tostr(int secmode);
extern int smb_config_get_secmode(void);
extern int smb_config_set_secmode(int secmode);
extern int smb_config_set_idmap_domain(char *value);
extern int smb_config_set_idmap_gc(char *value);
extern int smb_config_refresh_idmap(void);
extern int smb_config_refresh(void);

/* smb_door_client.c */
typedef struct smb_joininfo {
	char domain_name[SMB_PI_MAX_DOMAIN];
	char domain_username[BUF_LEN + 1];
	char domain_passwd[BUF_LEN + 1];
	uint32_t mode;
} smb_joininfo_t;

/* APIs to communicate with SMB daemon via door calls */
extern int smbd_set_param(smb_cfg_id_t, char *);
extern int smbd_get_param(smb_cfg_id_t, char *);
extern int smbd_get_security_mode(int *);
extern int smb_set_machine_pwd(char *);
extern int smbd_netbios_reconfig(void);
extern uint32_t smb_join(smb_joininfo_t *info);
extern int smb_ads_domain_change_notify(char *);


#define	SMB_DOMAIN_NOMACHINE_SID	-1
#define	SMB_DOMAIN_NODOMAIN_SID		-2

extern int nt_domain_init(char *resource_domain, uint32_t secmode);

/* Following set of functions, manipulate WINS server configuration */
extern int smb_wins_allow_list(char *config_list, char *allow_list);
extern int smb_wins_exclude_list(char *config_list, char *exclude_list);
extern boolean_t smb_wins_is_excluded(in_addr_t ipaddr,
    ipaddr_t *exclude_list, int nexclude);
extern void smb_wins_build_list(char *buf, uint32_t iplist[], int max_naddr);
extern int smb_wins_iplist(char *list, uint32_t iplist[], int max_naddr);

/*
 * Information on a particular domain: the domain name, the
 * name of a controller (PDC or BDC) and it's ip address.
 */
typedef struct smb_ntdomain {
	char domain[SMB_PI_MAX_DOMAIN_U];
	char server[SMB_PI_MAX_DOMAIN_U];
	uint32_t ipaddr;
} smb_ntdomain_t;

/* SMB domain information management functions */
extern void smb_purge_domain_info(void);
extern int smb_is_domain_member(void);
extern uint8_t smb_get_fg_flag(void);
extern void smb_set_domain_member(int set);
extern smb_ntdomain_t *smb_getdomaininfo(uint32_t timeout);
extern void smb_setdomaininfo(char *domain, char *server, uint32_t ipaddr);
extern void smb_logdomaininfo(smb_ntdomain_t *di);
extern uint32_t smb_get_security_mode(void);

extern int nt_priv_presentable_num(void);

/*
 * Following set of function, handle calls to SMB Kernel driver, via
 * Kernel doors interface.
 */
extern uint64_t smb_dwncall_user_num(void);
extern int smb_dwncall_share(int, char *, char *);

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

/* Functions to handle SMB daemon communications with idmap service */
extern int smb_idmap_start(void);
extern void smb_idmap_stop(void);
extern int smb_idmap_restart(void);

/* Miscellaneous functions */
extern void hexdump(unsigned char *, int);
extern size_t bintohex(const char *, size_t, char *, size_t);
extern size_t hextobin(const char *, size_t, char *, size_t);
extern char *trim_whitespace(char *buf);
extern void randomize(char *, unsigned);
extern void rand_hash(unsigned char *, size_t, unsigned char *, size_t);

extern int smb_getdomainname(char *, size_t);
extern int smb_getfqhostname(char *, size_t);
extern int smb_gethostname(char *, size_t, int);
extern int smb_getnetbiosname(char *, size_t);

void smb_trace(const char *s);
void smb_tracef(const char *fmt, ...);

/*
 * Authentication
 */

#define	SMBAUTH_LM_MAGIC_STR	"KGS!@#$%"

#define	SMBAUTH_HASH_SZ		16	/* also LM/NTLM/NTLMv2 Hash size */
#define	SMBAUTH_LM_RESP_SZ	24	/* also NTLM Response size */
#define	SMBAUTH_LM_PWD_SZ	14	/* LM password size */
#define	SMBAUTH_V2_CLNT_CHALLENGE_SZ 8	/* both LMv2 and NTLMv2 */
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
	mts_wchar_t nne_name[SMB_PI_MAX_DOMAIN * 2];
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
	unsigned char ndb_clnt_challenge[SMBAUTH_V2_CLNT_CHALLENGE_SZ];
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

extern int smb_getdomainname(char *, size_t);
extern int smb_getfqhostname(char *, size_t);
extern int smb_gethostname(char *, size_t, int);
extern int smb_getnetbiosname(char *, size_t);

void smb_trace(const char *s);
void smb_tracef(const char *fmt, ...);

/*
 * SMB password management
 */

#define	SMB_PWF_LM	0x01	/* LM hash is present */
#define	SMB_PWF_NT	0x02	/* NT hash is present */
#define	SMB_PWF_DISABLE	0x04	/* Account is disabled */

typedef struct smb_passwd {
	uid_t pw_uid;
	uint32_t pw_flags;
	unsigned char pw_lmhash[SMBAUTH_HASH_SZ];
	unsigned char pw_nthash[SMBAUTH_HASH_SZ];
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
#define	SMB_PWE_MAX		12

extern smb_passwd_t *smb_pwd_getpasswd(const char *, smb_passwd_t *);
extern int smb_pwd_setpasswd(const char *, const char *);
extern int smb_pwd_setcntl(const char *, int);

extern int smb_auth_qnd_unicode(mts_wchar_t *dst, char *src, int length);
extern int smb_auth_hmac_md5(unsigned char *data, int data_len,
    unsigned char *key, int key_len, unsigned char *digest);

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

extern int smb_auth_md4(unsigned char *, unsigned char *, int);
extern int smb_auth_lm_hash(char *, unsigned char *);
extern int smb_auth_ntlm_hash(char *, unsigned char *);

extern int smb_auth_set_info(char *, char *,
    unsigned char *, char *, unsigned char *,
    int, int, smb_auth_info_t *);

extern int smb_auth_gen_session_key(smb_auth_info_t *, unsigned char *);

boolean_t smb_auth_validate_lm(unsigned char *, uint32_t, smb_passwd_t *,
    unsigned char *, int, char *);
boolean_t smb_auth_validate_nt(unsigned char *, uint32_t, smb_passwd_t *,
    unsigned char *, int, char *);

/*
 * SMB MAC Signing
 */

#define	SMB_MAC_KEY_SZ	(SMBAUTH_SESSION_KEY_SZ + SMBAUTH_CS_MAXLEN)
#define	SMB_SIG_OFFS	14	/* signature field offset within header */
#define	SMB_SIG_SIZE	8	/* SMB signature size */

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
 * smb_sign_ctx
 *
 * SMB signing context.
 *
 *	ssc_seqnum				sequence number
 *	ssc_keylen				mac key length
 *	ssc_mid					multiplex id - reserved
 *	ssc_flags				flags
 *	ssc_mackey				mac key
 *	ssc_sign				mac signature
 *
 */
typedef struct smb_sign_ctx {
	unsigned int ssc_seqnum;
	unsigned short ssc_keylen;
	unsigned short ssc_mid;
	unsigned int ssc_flags;
	unsigned char ssc_mackey[SMB_MAC_KEY_SZ];
	unsigned char ssc_sign[SMB_SIG_SIZE];
} smb_sign_ctx_t;

extern int smb_mac_init(smb_sign_ctx_t *sign_ctx, smb_auth_info_t *auth);
extern int smb_mac_calc(smb_sign_ctx_t *sign_ctx,
    const unsigned char *buf, size_t buf_len, unsigned char *mac_sign);
extern int smb_mac_chk(smb_sign_ctx_t *sign_ctx,
    const unsigned char *buf, size_t buf_len);
extern int smb_mac_sign(smb_sign_ctx_t *sign_ctx,
    unsigned char *buf, size_t buf_len);
extern void smb_mac_inc_seqnum(smb_sign_ctx_t *sign_ctx);
extern void smb_mac_dec_seqnum(smb_sign_ctx_t *sign_ctx);

/*
 * Each domain is categorized using the enum values below.
 * The local domain refers to the local machine and is named
 * after the local hostname. The primary domain is the domain
 * that the system joined. All other domains are either
 * trusted or untrusted, as defined by the primary domain PDC.
 *
 * This enum must be kept in step with the table of strings
 * in ntdomain.c.
 */
typedef enum nt_domain_type {
	NT_DOMAIN_NULL,
	NT_DOMAIN_BUILTIN,
	NT_DOMAIN_LOCAL,
	NT_DOMAIN_PRIMARY,
	NT_DOMAIN_ACCOUNT,
	NT_DOMAIN_TRUSTED,
	NT_DOMAIN_UNTRUSTED,
	NT_DOMAIN_NUM_TYPES
} nt_domain_type_t;


/*
 * This is the information that is held about each domain. The database
 * is a linked list that is threaded through the domain structures. As
 * the number of domains in the database should be small (32 max), this
 * should be sufficient.
 */
typedef struct nt_domain {
	struct nt_domain *next;
	nt_domain_type_t type;
	char *name;
	nt_sid_t *sid;
} nt_domain_t;

nt_domain_t *nt_domain_new(nt_domain_type_t type, char *name, nt_sid_t *sid);
void nt_domain_delete(nt_domain_t *domain);
nt_domain_t *nt_domain_add(nt_domain_t *new_domain);
void nt_domain_remove(nt_domain_t *domain);
void nt_domain_flush(nt_domain_type_t domain_type);
void nt_domain_sync(void);
char *nt_domain_xlat_type(nt_domain_type_t domain_type);
nt_domain_type_t nt_domain_xlat_type_name(char *type_name);
nt_domain_t *nt_domain_lookup_name(char *domain_name);
nt_domain_t *nt_domain_lookup_sid(nt_sid_t *domain_sid);
nt_domain_t *nt_domain_lookupbytype(nt_domain_type_t type);
nt_sid_t *nt_domain_local_sid(void);

#define	SMB_GROUP_PER_LIST	5

/*
 * This structure takes different args passed from the client/server routines
 * of the SMB local group door service. Extend this structure if a new type
 * client paramater needs to be passed.
 */
typedef struct ntgrp_dr_arg {
	char *gname;
	char *desc;
	char *member;
	char *newgname;
	uint32_t privid;
	uint32_t priv_attr;
	int offset;
	char *scope;
	int type;
	int count;
	uint32_t ntstatus;
} ntgrp_dr_arg_t;

typedef struct ntgrp {
	DWORD rid;	/* Rid of the group */
	char *name;	/* Name of the group */
	char *desc;	/* Desc of gruup */
	char *type;	/* sid_name_use */
	char *sid;	/* Sid */
	DWORD attr;	/* Attribute */
} ntgrp_t;

typedef struct ntgrp_list {
	int cnt;
	ntgrp_t groups[SMB_GROUP_PER_LIST];
} ntgrp_list_t;

typedef char *members_list;
typedef struct ntgrp_member_list {
	DWORD rid;	/* Rid of the group in which members belong */
	int cnt;	/* members */
	members_list members[SMB_GROUP_PER_LIST];
} ntgrp_member_list_t;

typedef struct ntpriv {
	DWORD id;		/* Id of priv */
	char *name;	/* Name of priv */
} ntpriv_t;
typedef ntpriv_t *privs_t;

typedef struct ntpriv_list {
	int cnt;		/* Number of privs */
	privs_t	privs[ANY_SIZE_ARRAY];	/* privs only presentable ones */
} ntpriv_list_t;


/* the xdr functions */
extern bool_t xdr_ntgrp_dr_arg_t(XDR *, ntgrp_dr_arg_t *);
extern bool_t xdr_ntgrp_t(XDR *, ntgrp_t *);
extern bool_t xdr_ntgrp_list_t(XDR *, ntgrp_list_t *);
extern bool_t xdr_members_list(XDR *, members_list *);
extern bool_t xdr_ntgrp_member_list_t(XDR *, ntgrp_member_list_t *);
extern bool_t xdr_ntpriv_t(XDR *, ntpriv_t *);
extern bool_t xdr_privs_t(XDR *, privs_t *);
extern bool_t xdr_ntpriv_list_t(XDR *, ntpriv_list_t *);

extern void smb_group_free_memberlist(ntgrp_member_list_t *, int);
extern void smb_group_free_list(ntgrp_list_t *, int);
extern void smb_group_free_privlist(ntpriv_list_t *, int);

extern uint32_t smb_group_add(char *, char *);
extern uint32_t smb_group_modify(char *, char *, char *);
extern uint32_t smb_group_delete(char *);
extern uint32_t smb_group_member_remove(char *, char *);
extern uint32_t smb_group_member_add(char *, char *);
extern uint32_t smb_group_priv_num(int *);
extern uint32_t smb_group_priv_list(ntpriv_list_t **);
extern uint32_t smb_group_priv_get(char *, uint32_t, uint32_t *);
extern uint32_t smb_group_priv_set(char *, uint32_t, uint32_t);
extern uint32_t smb_group_count(int *);
extern uint32_t smb_group_list(int, ntgrp_list_t **, char *, int);
extern uint32_t smb_group_member_count(char *, int *);
extern uint32_t smb_group_member_list(char *, int, ntgrp_member_list_t **);

extern char *smb_dr_encode_grp_privlist(uint32_t, ntpriv_list_t *, size_t *);
extern ntpriv_list_t *smb_dr_decode_grp_privlist(char *, size_t);

extern char *smb_dr_encode_grp_list(uint32_t, ntgrp_list_t *, size_t *);
extern ntgrp_list_t *smb_dr_decode_grp_list(char *, size_t);

extern char *smb_dr_encode_grp_memberlist(uint32_t, ntgrp_member_list_t *,
    size_t *);
extern ntgrp_member_list_t *smb_dr_decode_grp_memberlist(char *buf, size_t len);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSMB_H */
