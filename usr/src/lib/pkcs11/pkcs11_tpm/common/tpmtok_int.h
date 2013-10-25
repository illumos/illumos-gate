/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright(C) 2005 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or(at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */

/* (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2005 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _TPMTOK_INT_H
#define	_TPMTOK_INT_H

#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <strings.h>
#include <md5.h>
#include <sha1.h>
#include <limits.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/byteorder.h>
#include <security/cryptoki.h>

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>

#define	VERSION_MAJOR 2
#define	VERSION_MINOR 1

#define	MAX_SESSION_COUNT	64
#define	MAX_PIN_LEN	256
#define	MIN_PIN_LEN	1

#define	MAX_SLOT_ID	10

#ifndef MIN
#define	MIN(a, b)  ((a) < (b) ? (a) : (b))
#endif

#define	MODE_COPY	(1 << 0)
#define	MODE_CREATE	(1 << 1)
#define	MODE_KEYGEN	(1 << 2)
#define	MODE_MODIFY	(1 << 3)
#define	MODE_DERIVE	(1 << 4)
#define	MODE_UNWRAP	(1 << 5)

// RSA block formatting types
//
#define	PKCS_BT_1	1
#define	PKCS_BT_2	2

#define	OP_ENCRYPT_INIT 1
#define	OP_DECRYPT_INIT 2
#define	OP_WRAP		3
#define	OP_UNWRAP	4
#define	OP_SIGN_INIT	5
#define	OP_VERIFY_INIT	6

enum {
	STATE_INVALID = 0,
	STATE_ENCR,
	STATE_DECR,
	STATE_DIGEST,
	STATE_SIGN,
	STATE_VERIFY
};

#define	SHA1_BLOCK_SIZE 64
#define	SHA1_BLOCK_SIZE_MASK (SHA1_BLOCK_SIZE - 1)

#define	RSA_BLOCK_SIZE 256

#ifndef PATH_MAX
#define	PATH_MAX MAXPATHLEN
#endif

#ifndef PACK_DATA
#define	PACK_DATA
#endif

#define	MD5_BLOCK_SIZE  64

#define	DSA_SIGNATURE_SIZE  40

#define	DEFAULT_SO_PIN  "87654321"

typedef enum {
	ALL = 1,
	PRIVATE,
	PUBLIC
} SESS_OBJ_TYPE;

typedef struct _DL_NODE
{
	struct _DL_NODE	*next;
	struct _DL_NODE	*prev;
	void  *data;
} DL_NODE;

#define	TOKEN_DATA_FILE	"token.dat"
#define	TOKEN_OBJ_DIR	"objects"
#define	TOKEN_OBJ_INDEX_FILE "obj.idx"

#define	TPMTOK_UUID_INDEX_FILENAME "uuids.idx"

/*
 * Filenames used to store migration data.
 */
#define	SO_MAKEY_FILENAME	"so_makey.dat"
#define	USER_MAKEY_FILENAME	"user_makey.dat"
#define	SO_KEYBLOB_FILENAME	"so_blob.dat"
#define	USER_KEYBLOB_FILENAME	"user_blob.dat"

#define	__FUNCTION__ __func__

//
// Both of the strings below have a length of 32 chars and must be
// padded with spaces, and non - null terminated.
//
#define	PKW_CRYPTOKI_VERSION_MAJOR	2
#define	PKW_CRYPTOKI_VERSION_MINOR	1
#define	PKW_CRYPTOKI_MANUFACTURER	"Sun Microsystems, Inc.	  "
#define	PKW_CRYPTOKI_LIBDESC	    "PKCS#11 Interface for TPM	"
#define	PKW_CRYPTOKI_LIB_VERSION_MAJOR  1
#define	PKW_CRYPTOKI_LIB_VERSION_MINOR  0
#define	PKW_MAX_DEVICES		 10

#define	MAX_TOK_OBJS  2048
#define	NUMBER_SLOTS_MANAGED 1
#define	TPM_SLOTID 1

/*
 * CKA_HIDDEN will be used to filter return results on
 * a C_FindObjects call. Used for objects internal to the
 * TPM token for management
 */
/* custom attributes for the TPM token */
#define	CKA_HIDDEN	CKA_VENDOR_DEFINED + 0x01
#define	CKA_IBM_OPAQUE	CKA_VENDOR_DEFINED + 0x02
/*
 * CKA_ENC_AUTHDATA will be used to store the encrypted SHA-1
 * hashes of auth data passed in for TPM keys. The authdata
 * will be encrypted using either the public
 * leaf key or the private leaf key
 */
#define	CKA_ENC_AUTHDATA CKA_VENDOR_DEFINED + 0x03

/* custom return codes for the TPM token */
#define	CKR_KEY_NOT_FOUND	CKR_VENDOR_DEFINED + 0x01
#define	CKR_FILE_NOT_FOUND	CKR_VENDOR_DEFINED + 0x02

typedef struct {
	CK_SLOT_ID  slotID;
	CK_SESSION_HANDLE  sessionh;
} ST_SESSION_T;

typedef ST_SESSION_T ST_SESSION_HANDLE;

typedef struct {
	void *Previous;
	void *Next;
	CK_SLOT_ID   SltId;
	CK_SESSION_HANDLE  RealHandle;
} Session_Struct_t;

typedef Session_Struct_t *SessStructP;

typedef struct {
	pid_t Pid;
	pthread_mutex_t  ProcMutex;
	Session_Struct_t *SessListBeg;
	Session_Struct_t *SessListEnd;
	pthread_mutex_t  SessListMutex;
} API_Proc_Struct_t;




enum {
	PRF_DUMMYFUNCTION = 1,
	PRF_FCVFUNCTION,
	PRF_INITIALIZE,
	PRF_FINALIZE,
	PRF_GETINFO,
	PRF_GETFUNCTIONLIST,
	PRF_GETSLOTLIST,
	PRF_GETSLOTINFO,
	PRF_GETTOKENINFO,
	PRF_GETMECHLIST,
	PRF_GETMECHINFO,
	PRF_INITTOKEN,
	PRF_INITPIN,
	PRF_SETPIN,
	PRF_OPENSESSION,
	PRF_CLOSESESSION,
	PRF_CLOSEALLSESSIONS,
	PRF_GETSESSIONINFO,
	PRF_GETOPERATIONSTATE,
	PRF_SETOPERATIONSTATE,
	PRF_LOGIN,
	PRF_LOGOUT,
	PRF_CREATEOBJECT,
	PRF_COPYOBJECT,
	PRF_DESTROYOBJECT,
	PRF_GETOBJECTSIZE,
	PRF_GETATTRIBUTEVALUE,
	PRF_SETATTRIBUTEVALUE,
	PRF_FINDOBJECTSINIT,
	PRF_FINDOBJECTS,
	PRF_FINDOBJECTSFINAL,
	PRF_ENCRYPTINIT,
	PRF_ENCRYPT,
	PRF_ENCRYPTUPDATE,
	PRF_ENCRYPTFINAL,
	PRF_DECRYPTINIT,
	PRF_DECRYPT,
	PRF_DECRYPTUPDATE,
	PRF_DECRYPTFINAL,
	PRF_DIGESTINIT,
	PRF_DIGEST,
	PRF_DIGESTUPDATE,
	PRF_DIGESTKEY,
	PRF_DIGESTFINAL,
	PRF_SIGNINIT,
	PRF_SIGN,
	PRF_SIGNUPDATE,
	PRF_SIGNFINAL,
	PRF_SIGNRECOVERINIT,
	PRF_SIGNRECOVER,
	PRF_VERIFYINIT,
	PRF_VERIFY,
	PRF_VERIFYUPDATE,
	PRF_VERIFYFINAL,
	PRF_VERIFYRECOVERINIT,
	PRF_VERIFYRECOVER,
	PRF_GENKEY,
	PRF_GENKEYPAIR,
	PRF_WRAPKEY,
	PRF_UNWRAPKEY,
	PRF_DERIVEKEY,
	PRF_GENRND,
	PRF_LASTENTRY
};

typedef struct _ENCR_DECR_CONTEXT
{
	CK_OBJECT_HANDLE  key;
	CK_MECHANISM mech;
	CK_BYTE	  *context;
	CK_ULONG  context_len;
	CK_BBOOL  multi;
	CK_BBOOL  active;
} ENCR_DECR_CONTEXT;

typedef struct _DIGEST_CONTEXT
{
	CK_MECHANISM   mech;
	union {
		MD5_CTX *md5ctx;
		SHA1_CTX *sha1ctx;
		void *ref; /* reference ptr for the union */
	} context;
	CK_ULONG context_len;
	CK_BBOOL multi;
	CK_BBOOL active;
} DIGEST_CONTEXT;

typedef struct _SIGN_VERIFY_CONTEXT
{
	CK_OBJECT_HANDLE key;
	CK_MECHANISM	mech;	// current sign mechanism
	void	 *context;  // temporary work area
	CK_ULONG context_len;
	CK_BBOOL multi;    // is this a multi - part operation?
	CK_BBOOL recover;  // are we in recover mode?
	CK_BBOOL active;
} SIGN_VERIFY_CONTEXT;

typedef struct _SESSION
{
	CK_SESSION_HANDLE    handle;
	CK_SESSION_INFO	session_info;

	CK_OBJECT_HANDLE    *find_list;	// array of CK_OBJECT_HANDLE
	CK_ULONG	find_count;    // # handles in the list
	CK_ULONG	find_len;	// max # of handles in the list
	CK_ULONG	find_idx;	// current position
	CK_BBOOL	find_active;

	ENCR_DECR_CONTEXT    encr_ctx;
	ENCR_DECR_CONTEXT    decr_ctx;
	DIGEST_CONTEXT	digest_ctx;
	SIGN_VERIFY_CONTEXT  sign_ctx;
	SIGN_VERIFY_CONTEXT  verify_ctx;

	TSS_HCONTEXT	hContext;
} SESSION;

typedef struct _TEMPLATE
{
	DL_NODE  *attribute_list;
} TEMPLATE;

typedef struct _OBJECT
{
	CK_OBJECT_CLASS   class;
	CK_BYTE	 name[8];   // for token objects

	SESSION	 *session;   // creator; only for session objects
	TEMPLATE *template;
	CK_ULONG count_hi;  // only significant for token objects
	CK_ULONG count_lo;  // only significant for token objects
	CK_ULONG index;
} OBJECT;

typedef struct _OBJECT_MAP
{
	CK_OBJECT_HANDLE	handle;
	CK_BBOOL is_private;
	CK_BBOOL is_session_obj;
	SESSION	 *session;
	OBJECT   *ptr;
} OBJECT_MAP;

typedef struct _ATTRIBUTE_PARSE_LIST
{
	CK_ATTRIBUTE_TYPE type;
	void		*ptr;
	CK_ULONG	  len;
	CK_BBOOL	  found;
} ATTRIBUTE_PARSE_LIST;

typedef struct _OP_STATE_DATA
{
	CK_STATE    session_state;
	CK_ULONG    active_operation;
	CK_ULONG    data_len;
} OP_STATE_DATA;

typedef struct _TWEAK_VEC
{
	int   allow_key_mods;
} TWEAK_VEC;

typedef struct _TOKEN_DATA
{
	CK_TOKEN_INFO token_info;
	CK_BYTE   user_pin_sha[SHA1_DIGEST_LENGTH];
	CK_BYTE   so_pin_sha[SHA1_DIGEST_LENGTH];
	CK_BYTE   next_token_object_name[8];
	TWEAK_VEC tweak_vector;
} TOKEN_DATA;

typedef struct _RSA_DIGEST_CONTEXT {
	DIGEST_CONTEXT hash_context;
	CK_BBOOL	flag;
} RSA_DIGEST_CONTEXT;

typedef struct _MECH_LIST_ELEMENT
{
	CK_MECHANISM_TYPE    mech_type;
	CK_MECHANISM_INFO    mech_info;
} MECH_LIST_ELEMENT;

struct mech_list_item;

struct mech_list_item {
	struct mech_list_item *next;
	MECH_LIST_ELEMENT element;
};

struct mech_list_item *
find_mech_list_item_for_type(CK_MECHANISM_TYPE type,
	struct mech_list_item *head);

typedef struct _TOK_OBJ_ENTRY
{
	CK_BBOOL  deleted;
	char	name[8];
	CK_ULONG  count_lo;
	CK_ULONG  count_hi;
} TOK_OBJ_ENTRY;

typedef struct _LW_SHM_TYPE
{
	pthread_mutex_t	mutex;
	TOKEN_DATA	nv_token_data;
	CK_ULONG	num_priv_tok_obj;
	CK_ULONG	num_publ_tok_obj;
	CK_BBOOL	priv_loaded;
	CK_BBOOL	publ_loaded;
	CK_BBOOL	token_available;
	TOK_OBJ_ENTRY  publ_tok_objs[ MAX_TOK_OBJS ];
	TOK_OBJ_ENTRY  priv_tok_objs[ MAX_TOK_OBJS ];
} LW_SHM_TYPE;

typedef unsigned int CK_ULONG_32;
typedef CK_ULONG_32 CK_OBJECT_CLASS_32;
typedef CK_ULONG_32 CK_ATTRIBUTE_TYPE_32;

typedef struct CK_ATTRIBUTE_32 {
	CK_ATTRIBUTE_TYPE_32 type;
	CK_ULONG_32 pValue;
	CK_ULONG_32 ulValueLen;
} CK_ATTRIBUTE_32;

char *get_tpm_keystore_path();

struct messages {
	char *msg;
};

struct token_specific_struct {
	CK_BYTE  token_debug_tag[MAXPATHLEN];

	CK_RV  (*t_init)(char *, CK_SLOT_ID, TSS_HCONTEXT *);
	int  (*t_slot2local)();

	CK_RV  (*t_rng)(TSS_HCONTEXT, CK_BYTE *, CK_ULONG);
	CK_RV  (*t_session)(CK_SLOT_ID);
	CK_RV  (*t_final)(TSS_HCONTEXT);
	CK_RV (*t_rsa_decrypt)(TSS_HCONTEXT, CK_BYTE *,
		CK_ULONG, CK_BYTE *, CK_ULONG *, OBJECT *);

	CK_RV (*t_rsa_encrypt)(
		TSS_HCONTEXT,
		CK_BYTE *, CK_ULONG, CK_BYTE *,
		CK_ULONG *, OBJECT *);

	CK_RV (*t_rsa_sign)(TSS_HCONTEXT,
		CK_BYTE *,
		CK_ULONG,
		CK_BYTE *,
		CK_ULONG *,
		OBJECT *);

	CK_RV (*t_rsa_verify)(TSS_HCONTEXT,
		CK_BYTE *,
		CK_ULONG,
		CK_BYTE *,
		CK_ULONG,
		OBJECT *);

	CK_RV (*t_rsa_generate_keypair)(TSS_HCONTEXT, TEMPLATE *, TEMPLATE *);

	CK_RV (*t_sha_init)(DIGEST_CONTEXT *);

	CK_RV (*t_sha_update)(
		DIGEST_CONTEXT *,
		CK_BYTE	*,
		CK_ULONG);

	CK_RV (*t_sha_final)(
		DIGEST_CONTEXT *,
		CK_BYTE *,
		CK_ULONG *);
	CK_RV (*t_login)(TSS_HCONTEXT, CK_USER_TYPE, CK_BYTE *, CK_ULONG);
	CK_RV (*t_logout)(TSS_HCONTEXT);
	CK_RV (*t_init_pin)(TSS_HCONTEXT, CK_BYTE *, CK_ULONG);
	CK_RV (*t_set_pin)(ST_SESSION_HANDLE, CK_BYTE *,
		CK_ULONG, CK_BYTE *, CK_ULONG);
	CK_RV (*t_verify_so_pin)(TSS_HCONTEXT, CK_BYTE *, CK_ULONG);
};

typedef  struct token_specific_struct token_spec_t;

/*
 * Global Variables
 */
extern void copy_slot_info(CK_SLOT_ID, CK_SLOT_INFO_PTR);

extern struct messages err_msg[];

extern token_spec_t token_specific;
extern CK_BBOOL initialized;
extern char *card_function_names[];
extern char *total_function_names[];

extern MECH_LIST_ELEMENT mech_list[];
extern CK_ULONG mech_list_len;

extern pthread_mutex_t native_mutex;

extern void *xproclock;

extern pthread_mutex_t pkcs_mutex, obj_list_mutex,
	sess_list_mutex, login_mutex;

extern DL_NODE *sess_list;
extern DL_NODE *sess_obj_list;
extern DL_NODE *publ_token_obj_list;
extern DL_NODE *priv_token_obj_list;
extern DL_NODE *object_map;

extern CK_BYTE so_pin_md5[MD5_DIGEST_LENGTH];
extern CK_BYTE user_pin_md5[MD5_DIGEST_LENGTH];

extern CK_BYTE default_user_pin_sha[SHA1_DIGEST_LENGTH];
extern CK_BYTE default_so_pin_sha[SHA1_DIGEST_LENGTH];
extern CK_BYTE default_so_pin_md5[MD5_DIGEST_LENGTH];

extern LW_SHM_TYPE *global_shm;

extern TOKEN_DATA *nv_token_data;

extern CK_ULONG next_object_handle;
extern CK_ULONG next_session_handle;

extern CK_STATE global_login_state;

extern CK_BYTE	ber_AlgIdRSAEncryption[];
extern CK_ULONG	ber_AlgIdRSAEncryptionLen;
extern CK_BYTE	ber_rsaEncryption[];
extern CK_ULONG	ber_rsaEncryptionLen;
extern CK_BYTE	ber_idDSA[];
extern CK_ULONG	ber_idDSALen;

extern CK_BYTE ber_md5WithRSAEncryption[];
extern CK_ULONG ber_md5WithRSAEncryptionLen;
extern CK_BYTE ber_sha1WithRSAEncryption[];
extern CK_ULONG ber_sha1WithRSAEncryptionLen;
extern CK_BYTE ber_AlgMd5[];
extern CK_ULONG ber_AlgMd5Len;
extern CK_BYTE ber_AlgSha1[];
extern CK_ULONG ber_AlgSha1Len;

extern CK_C_INITIALIZE_ARGS cinit_args;

/*
 * Function Prototypes
 */
void *attach_shared_memory();
void  detach_shared_memory(char *);

int API_Initialized();
void Terminate_All_Process_Sessions();
int API_Register();
void API_UnRegister();

void CreateXProcLock(void *);
int XProcLock(void *);
int XProcUnLock(void *);

void loginit();
void logterm();
void logit(int, char *, ...);
void AddToSessionList(Session_Struct_t *);
void RemoveFromSessionList(Session_Struct_t *);

int Valid_Session(Session_Struct_t *, ST_SESSION_T *);

CK_BBOOL pin_expired(CK_SESSION_INFO *, CK_FLAGS);
CK_BBOOL pin_locked(CK_SESSION_INFO *, CK_FLAGS);
void set_login_flags(CK_USER_TYPE, CK_FLAGS *);

extern void init_slot_info(TOKEN_DATA *);

CK_RV update_migration_data(TSS_HCONTEXT,
	TSS_HKEY, TSS_HKEY, char *, char *, BYTE *, BYTE *);
CK_RV token_rng(TSS_HCONTEXT, CK_BYTE *, CK_ULONG);

TSS_RESULT set_public_modulus(TSS_HCONTEXT, TSS_HKEY,
    unsigned long, unsigned char *);
TSS_RESULT open_tss_context(TSS_HCONTEXT *);
CK_RV token_get_tpm_info(TSS_HCONTEXT, TOKEN_DATA *);

CK_RV clock_set_default_attributes(TEMPLATE *);
CK_RV clock_check_required_attributes(TEMPLATE *, CK_ULONG);
CK_RV clock_validate_attribute(TEMPLATE *, CK_ATTRIBUTE *, CK_ULONG);

CK_RV counter_set_default_attributes(TEMPLATE *);
CK_RV counter_check_required_attributes(TEMPLATE *, CK_ULONG);
CK_RV counter_validate_attribute(TEMPLATE *, CK_ATTRIBUTE *, CK_ULONG);

CK_RV compute_next_token_obj_name(CK_BYTE *, CK_BYTE *);

CK_RV save_token_object(TSS_HCONTEXT, OBJECT *);
CK_RV save_public_token_object(OBJECT *);
CK_RV save_private_token_object(TSS_HCONTEXT, OBJECT *);

CK_RV load_public_token_objects(void);
CK_RV load_private_token_objects(TSS_HCONTEXT);

CK_RV reload_token_object(TSS_HCONTEXT, OBJECT *);

CK_RV delete_token_object(OBJECT *);

CK_RV init_token_data(TSS_HCONTEXT, TOKEN_DATA *);
CK_RV load_token_data(TSS_HCONTEXT, TOKEN_DATA *);
CK_RV save_token_data(TOKEN_DATA *);
void copy_slot_info(CK_SLOT_ID, CK_SLOT_INFO_PTR);

CK_RV compute_sha(CK_BYTE *, CK_ULONG_32, CK_BYTE *);

CK_RV parity_is_odd(CK_BYTE);

CK_RV build_attribute(CK_ATTRIBUTE_TYPE,
	CK_BYTE *, CK_ULONG, CK_ATTRIBUTE **);

CK_RV add_pkcs_padding(CK_BYTE *, UINT32, UINT32, UINT32);

CK_RV strip_pkcs_padding(CK_BYTE *, UINT32, UINT32 *);

CK_RV remove_leading_zeros(CK_ATTRIBUTE *);

CK_RV rsa_pkcs_encrypt(
	SESSION *,
	CK_BBOOL,
	ENCR_DECR_CONTEXT *,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG *);

CK_RV rsa_pkcs_decrypt(SESSION *,
	CK_BBOOL,
	ENCR_DECR_CONTEXT *,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG *);

CK_RV rsa_pkcs_sign(SESSION *,
	CK_BBOOL,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG *);

CK_RV rsa_pkcs_verify(SESSION *,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG);

CK_RV rsa_pkcs_verify_recover(SESSION *,
	CK_BBOOL,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG *);

CK_RV rsa_hash_pkcs_sign(SESSION *,
	CK_BBOOL,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG *);

CK_RV rsa_hash_pkcs_verify(SESSION *,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG);

CK_RV rsa_hash_pkcs_sign_update(SESSION *,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG);

CK_RV rsa_hash_pkcs_verify_update(SESSION *,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG);

CK_RV rsa_hash_pkcs_sign_final(SESSION *,
	CK_BBOOL,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG *);

CK_RV rsa_hash_pkcs_verify_final(SESSION *,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG);


CK_RV ckm_rsa_key_pair_gen(TSS_HCONTEXT, TEMPLATE *, TEMPLATE *);

CK_RV sha1_hash(SESSION *, CK_BBOOL,
	DIGEST_CONTEXT *,
	CK_BYTE *, CK_ULONG,
	CK_BYTE *, CK_ULONG *);

CK_RV sha1_hmac_sign(SESSION *, CK_BBOOL,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG *);

CK_RV sha1_hmac_verify(SESSION *,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG);

CK_RV md5_hash(SESSION *, CK_BBOOL,
	DIGEST_CONTEXT *,
	CK_BYTE *, CK_ULONG,
	CK_BYTE *, CK_ULONG *);

CK_RV md5_hmac_sign(SESSION *, CK_BBOOL,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG *);

CK_RV md5_hmac_verify(SESSION *,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG);

DL_NODE *dlist_add_as_first(DL_NODE *, void *);
DL_NODE *dlist_add_as_last(DL_NODE *, void *);
DL_NODE *dlist_find(DL_NODE *, void *);
DL_NODE *dlist_get_first(DL_NODE *);
DL_NODE *dlist_get_last(DL_NODE *);
	CK_ULONG dlist_length(DL_NODE *);
DL_NODE *dlist_next(DL_NODE *);
DL_NODE *dlist_prev(DL_NODE *);
void dlist_purge(DL_NODE *);
DL_NODE *dlist_remove_node(DL_NODE *, DL_NODE *);

CK_RV attach_shm(void);
CK_RV detach_shm(void);

// encryption manager routines
//
CK_RV encr_mgr_init(SESSION *,
	ENCR_DECR_CONTEXT *,
	CK_ULONG,
	CK_MECHANISM *,
	CK_OBJECT_HANDLE);

CK_RV encr_mgr_cleanup(ENCR_DECR_CONTEXT *);

CK_RV encr_mgr_encrypt(SESSION *, CK_BBOOL,
	ENCR_DECR_CONTEXT *,
	CK_BYTE *, CK_ULONG,
	CK_BYTE *, CK_ULONG *);

CK_RV decr_mgr_init(SESSION *,
	ENCR_DECR_CONTEXT *,
	CK_ULONG,
	CK_MECHANISM *,
	CK_OBJECT_HANDLE);

CK_RV decr_mgr_cleanup(ENCR_DECR_CONTEXT *);

CK_RV decr_mgr_decrypt(SESSION *, CK_BBOOL,
	ENCR_DECR_CONTEXT *,
	CK_BYTE *, CK_ULONG,
	CK_BYTE *, CK_ULONG *);

CK_RV digest_mgr_cleanup(DIGEST_CONTEXT *);

CK_RV digest_mgr_init(SESSION *,
	DIGEST_CONTEXT *,
	CK_MECHANISM *);

CK_RV digest_mgr_digest(SESSION *, CK_BBOOL,
	DIGEST_CONTEXT *,
	CK_BYTE *, CK_ULONG,
	CK_BYTE *, CK_ULONG *);

CK_RV digest_mgr_digest_update(SESSION *,
	DIGEST_CONTEXT *,
	CK_BYTE *, CK_ULONG);

CK_RV digest_mgr_digest_key(SESSION *,
	DIGEST_CONTEXT *,
	CK_OBJECT_HANDLE);

CK_RV digest_mgr_digest_final(SESSION *,
	DIGEST_CONTEXT *,
	CK_BYTE *, CK_ULONG *);

CK_RV key_mgr_generate_key_pair(SESSION *,
	CK_MECHANISM *,
	CK_ATTRIBUTE *, CK_ULONG,
	CK_ATTRIBUTE *, CK_ULONG,
	CK_OBJECT_HANDLE *,
	CK_OBJECT_HANDLE *);

CK_RV key_mgr_wrap_key(SESSION *,
	CK_BBOOL,
	CK_MECHANISM *,
	CK_OBJECT_HANDLE,
	CK_OBJECT_HANDLE,
	CK_BYTE *,
	CK_ULONG *);

CK_RV key_mgr_unwrap_key(SESSION *,
	CK_MECHANISM *,
	CK_ATTRIBUTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG,
	CK_OBJECT_HANDLE,
	CK_OBJECT_HANDLE *);

CK_RV sign_mgr_init(SESSION *,
	SIGN_VERIFY_CONTEXT *,
	CK_MECHANISM *,
	CK_BBOOL,
	CK_OBJECT_HANDLE);

CK_RV sign_mgr_cleanup(SIGN_VERIFY_CONTEXT *);

CK_RV sign_mgr_sign(SESSION *,
	CK_BBOOL,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG *);

CK_RV sign_mgr_sign_recover(SESSION *,
	CK_BBOOL,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG *);

CK_RV sign_mgr_sign_final(SESSION *,
	CK_BBOOL,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG *);

CK_RV sign_mgr_sign_update(SESSION *,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG);

CK_RV verify_mgr_init(SESSION *,
	SIGN_VERIFY_CONTEXT *,
	CK_MECHANISM *,
	CK_BBOOL,
	CK_OBJECT_HANDLE);

CK_RV verify_mgr_cleanup(SIGN_VERIFY_CONTEXT *);

CK_RV verify_mgr_verify(SESSION *,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG);

CK_RV verify_mgr_verify_recover(SESSION *,
	CK_BBOOL,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG *);

CK_RV verify_mgr_verify_update(SESSION *,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG);

CK_RV verify_mgr_verify_final(SESSION *,
	SIGN_VERIFY_CONTEXT *,
	CK_BYTE *,
	CK_ULONG);


// session manager routines
//
CK_RV session_mgr_close_all_sessions(void);
CK_RV session_mgr_close_session(SESSION *);
SESSION *session_mgr_find(CK_SESSION_HANDLE);
CK_RV session_mgr_login_all(CK_USER_TYPE);
CK_RV session_mgr_logout_all(void);
CK_RV session_mgr_new(CK_ULONG, SESSION **);

CK_BBOOL session_mgr_readonly_exists(void);
CK_BBOOL session_mgr_so_session_exists(void);
CK_BBOOL session_mgr_user_session_exists(void);
CK_BBOOL session_mgr_public_session_exists(void);

CK_RV session_mgr_get_op_state(SESSION *, CK_BBOOL,
	CK_BYTE *, CK_ULONG *);

CK_RV session_mgr_set_op_state(SESSION *,
	CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE *);

CK_RV object_mgr_add(SESSION *,
	CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *);

CK_RV object_mgr_add_to_map(SESSION *, OBJECT *, CK_OBJECT_HANDLE *);

CK_RV object_mgr_add_to_shm(OBJECT *);
CK_RV object_mgr_del_from_shm(OBJECT *);

CK_RV object_mgr_copy(SESSION *,
	CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE,
	CK_OBJECT_HANDLE *);

CK_RV object_mgr_create_final(SESSION *,
	OBJECT *, CK_OBJECT_HANDLE *);

CK_RV object_mgr_create_skel(SESSION *,
	CK_ATTRIBUTE *, CK_ULONG, CK_ULONG,
	CK_ULONG, CK_ULONG, OBJECT **);

CK_RV object_mgr_destroy_object(SESSION *, CK_OBJECT_HANDLE);

CK_RV object_mgr_destroy_token_objects(TSS_HCONTEXT);

CK_RV object_mgr_find_in_map1(TSS_HCONTEXT, CK_OBJECT_HANDLE, OBJECT **);

CK_RV object_mgr_find_in_map2(TSS_HCONTEXT, OBJECT *, CK_OBJECT_HANDLE *);

CK_RV object_mgr_find_init(SESSION *, CK_ATTRIBUTE *, CK_ULONG);

CK_RV object_mgr_find_build_list(SESSION *,
	CK_ATTRIBUTE *,
	CK_ULONG,
	DL_NODE *,
	CK_BBOOL public_only);

CK_RV object_mgr_find_final(SESSION *);

CK_RV object_mgr_get_attribute_values(SESSION *,
	CK_OBJECT_HANDLE,
	CK_ATTRIBUTE *,
	CK_ULONG);

CK_RV object_mgr_get_object_size(TSS_HCONTEXT, CK_OBJECT_HANDLE,
	CK_ULONG *);

CK_BBOOL object_mgr_invalidate_handle1(CK_OBJECT_HANDLE handle);

CK_BBOOL object_mgr_invalidate_handle2(OBJECT *);

CK_BBOOL object_mgr_purge_session_objects(SESSION *, SESS_OBJ_TYPE);

CK_BBOOL object_mgr_purge_token_objects(TSS_HCONTEXT);

CK_BBOOL object_mgr_purge_private_token_objects(TSS_HCONTEXT);

CK_RV object_mgr_remove_from_map(CK_OBJECT_HANDLE);

CK_RV object_mgr_restore_obj(CK_BYTE *, OBJECT *);

CK_RV object_mgr_set_attribute_values(SESSION *,
	CK_OBJECT_HANDLE,
	CK_ATTRIBUTE *,
	CK_ULONG);

CK_BBOOL object_mgr_purge_map(SESSION *, SESS_OBJ_TYPE);

CK_RV object_create(CK_ATTRIBUTE *, CK_ULONG, OBJECT **);

CK_RV object_create_skel(CK_ATTRIBUTE *,
	CK_ULONG,
	CK_ULONG,
	CK_ULONG,
	CK_ULONG,
	OBJECT **);

CK_RV object_copy(CK_ATTRIBUTE *,
	CK_ULONG,
	OBJECT *,
	OBJECT **);

CK_RV object_flatten(OBJECT *,
	CK_BYTE **,
	CK_ULONG_32 *);

CK_BBOOL object_free(OBJECT *);

CK_RV object_get_attribute_values(OBJECT *,
	CK_ATTRIBUTE *,
	CK_ULONG);

CK_ULONG object_get_size(OBJECT *);

CK_RV object_restore(CK_BYTE *,
	OBJECT **,
	CK_BBOOL replace);

CK_RV object_set_attribute_values(OBJECT *,
	CK_ATTRIBUTE *,
	CK_ULONG);

CK_BBOOL object_is_modifiable(OBJECT *);
CK_BBOOL object_is_private(OBJECT *);
CK_BBOOL object_is_public(OBJECT *);
CK_BBOOL object_is_token_object(OBJECT *);
CK_BBOOL object_is_session_object(OBJECT *);

CK_BBOOL is_attribute_defined(CK_ATTRIBUTE_TYPE);

CK_RV template_add_attributes(TEMPLATE *,
	CK_ATTRIBUTE *, CK_ULONG);

CK_RV template_add_default_attributes(TEMPLATE *,
	CK_ULONG,
	CK_ULONG,
	CK_ULONG);

CK_BBOOL template_attribute_find(TEMPLATE *,
	CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE **);

void template_attribute_find_multiple(TEMPLATE *,
	ATTRIBUTE_PARSE_LIST *,
	CK_ULONG);

CK_BBOOL template_check_exportability(TEMPLATE *, CK_ATTRIBUTE_TYPE type);

CK_RV template_check_required_attributes(TEMPLATE *,
	CK_ULONG, CK_ULONG, CK_ULONG);

CK_RV template_check_required_base_attributes(TEMPLATE *,
	CK_ULONG);

CK_BBOOL template_compare(CK_ATTRIBUTE *,
	CK_ULONG, TEMPLATE *);

CK_RV template_copy(TEMPLATE *, TEMPLATE *);

CK_RV template_flatten(TEMPLATE *, CK_BYTE *);

CK_RV template_free(TEMPLATE *);

CK_BBOOL template_get_class(TEMPLATE *, CK_ULONG *, CK_ULONG *);

CK_ULONG template_get_count(TEMPLATE *);

CK_ULONG template_get_size(TEMPLATE *);
CK_ULONG template_get_compressed_size(TEMPLATE *);

CK_RV template_set_default_common_attributes(TEMPLATE *);

CK_RV template_merge(TEMPLATE *, TEMPLATE **);

CK_RV template_update_attribute(TEMPLATE *, CK_ATTRIBUTE *);

CK_RV template_unflatten(TEMPLATE **, CK_BYTE *, CK_ULONG);

CK_RV template_validate_attribute(TEMPLATE *,
	CK_ATTRIBUTE *, CK_ULONG, CK_ULONG, CK_ULONG);

CK_RV template_validate_attributes(TEMPLATE *,
	CK_ULONG, CK_ULONG, CK_ULONG);

CK_RV template_validate_base_attribute(TEMPLATE *,
	CK_ATTRIBUTE *, CK_ULONG);


// DATA OBJECT ROUTINES
//
CK_RV data_object_check_required_attributes(TEMPLATE *, CK_ULONG);
CK_RV data_object_set_default_attributes(TEMPLATE *, CK_ULONG);
CK_RV data_object_validate_attribute(TEMPLATE *, CK_ATTRIBUTE *, CK_ULONG);

// CERTIFICATE ROUTINES
CK_RV cert_validate_attribute(TEMPLATE *, CK_ATTRIBUTE *, CK_ULONG);

CK_RV cert_x509_check_required_attributes(TEMPLATE *, CK_ULONG);
CK_RV cert_x509_set_default_attributes(TEMPLATE *, CK_ULONG);
CK_RV cert_x509_validate_attribute(TEMPLATE *, CK_ATTRIBUTE *, CK_ULONG);
CK_RV cert_vendor_check_required_attributes(TEMPLATE *, CK_ULONG);
CK_RV cert_vendor_validate_attribute(TEMPLATE *, CK_ATTRIBUTE *, CK_ULONG);

//
// KEY ROUTINES
//
CK_RV key_object_check_required_attributes(TEMPLATE *, CK_ULONG);
CK_RV key_object_set_default_attributes(TEMPLATE *, CK_ULONG);
CK_RV key_object_validate_attribute(TEMPLATE *, CK_ATTRIBUTE *, CK_ULONG);

CK_RV publ_key_check_required_attributes(TEMPLATE *, CK_ULONG);
CK_RV publ_key_set_default_attributes(TEMPLATE *, CK_ULONG);
CK_RV publ_key_validate_attribute(TEMPLATE *, CK_ATTRIBUTE *, CK_ULONG);

CK_RV priv_key_check_required_attributes(TEMPLATE *, CK_ULONG);
CK_RV priv_key_set_default_attributes(TEMPLATE *, CK_ULONG);
CK_RV priv_key_unwrap(TEMPLATE *, CK_ULONG, CK_BYTE *, CK_ULONG);
CK_RV priv_key_validate_attribute(TEMPLATE *, CK_ATTRIBUTE *, CK_ULONG);

	CK_BBOOL secret_key_check_exportability(CK_ATTRIBUTE_TYPE type);
CK_RV secret_key_check_required_attributes(TEMPLATE *, CK_ULONG);
CK_RV secret_key_set_default_attributes(TEMPLATE *, CK_ULONG);
CK_RV secret_key_unwrap(TEMPLATE *, CK_ULONG, CK_BYTE *, CK_ULONG,
	CK_BBOOL fromend);
CK_RV secret_key_validate_attribute(TEMPLATE *, CK_ATTRIBUTE *,
	CK_ULONG);

// rsa routines
//
CK_RV rsa_publ_check_required_attributes(TEMPLATE *, CK_ULONG);
CK_RV rsa_publ_validate_attribute(TEMPLATE *, CK_ATTRIBUTE *, CK_ULONG);
CK_RV rsa_publ_set_default_attributes(TEMPLATE *, CK_ULONG);
	CK_BBOOL rsa_priv_check_exportability(CK_ATTRIBUTE_TYPE type);
CK_RV rsa_priv_check_required_attributes(TEMPLATE *, CK_ULONG);
CK_RV rsa_priv_set_default_attributes(TEMPLATE *, CK_ULONG);
CK_RV rsa_priv_validate_attribute(TEMPLATE *, CK_ATTRIBUTE *, CK_ULONG);
CK_RV rsa_priv_wrap_get_data(TEMPLATE *, CK_BBOOL, CK_BYTE **, CK_ULONG *);
CK_RV rsa_priv_unwrap(TEMPLATE *, CK_BYTE *, CK_ULONG);

// Generic secret key routines
CK_RV generic_secret_check_required_attributes(TEMPLATE *, CK_ULONG);
CK_RV generic_secret_set_default_attributes(TEMPLATE *, CK_ULONG);
CK_RV generic_secret_validate_attribute(TEMPLATE *, CK_ATTRIBUTE *, CK_ULONG);
CK_RV generic_secret_wrap_get_data(TEMPLATE *, CK_BBOOL,
	CK_BYTE **, CK_ULONG *);

CK_RV generic_secret_unwrap(TEMPLATE *, CK_BYTE *, CK_ULONG, CK_BBOOL fromend);

CK_RV tpm_encrypt_data(TSS_HCONTEXT,
	TSS_HKEY, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);

CK_RV tpm_decrypt_data(TSS_HCONTEXT,
	TSS_HKEY, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);

CK_ULONG ber_encode_INTEGER(CK_BBOOL,
	CK_BYTE **, CK_ULONG *, CK_BYTE *, CK_ULONG);

CK_RV ber_decode_INTEGER(CK_BYTE *,
	CK_BYTE **, CK_ULONG *, CK_ULONG *);

CK_RV ber_encode_OCTET_STRING(CK_BBOOL,
	CK_BYTE **, CK_ULONG *, CK_BYTE *, CK_ULONG);

CK_RV ber_decode_OCTET_STRING(CK_BYTE *,
	CK_BYTE **, CK_ULONG *, CK_ULONG *);

CK_RV ber_encode_SEQUENCE(CK_BBOOL,
	CK_BYTE **, CK_ULONG *, CK_BYTE *, CK_ULONG);

CK_RV ber_decode_SEQUENCE(CK_BYTE *,
	CK_BYTE **, CK_ULONG *, CK_ULONG *);

CK_RV ber_encode_PrivateKeyInfo(CK_BBOOL,
	CK_BYTE **, CK_ULONG *, CK_BYTE *,
	CK_ULONG, CK_BYTE *, CK_ULONG);

CK_RV ber_decode_PrivateKeyInfo(CK_BYTE *,
	CK_ULONG, CK_BYTE **, CK_ULONG *, CK_BYTE **);

CK_RV ber_encode_RSAPrivateKey(CK_BBOOL,
	CK_BYTE **, CK_ULONG *, CK_ATTRIBUTE *,
	CK_ATTRIBUTE *, CK_ATTRIBUTE *, CK_ATTRIBUTE *,
	CK_ATTRIBUTE *, CK_ATTRIBUTE *, CK_ATTRIBUTE *,
	CK_ATTRIBUTE *);

CK_RV ber_decode_RSAPrivateKey(CK_BYTE *,
	CK_ULONG, CK_ATTRIBUTE **, CK_ATTRIBUTE **,
	CK_ATTRIBUTE **, CK_ATTRIBUTE **, CK_ATTRIBUTE **,
	CK_ATTRIBUTE **, CK_ATTRIBUTE **, CK_ATTRIBUTE **);


CK_RV ber_encode_DSAPrivateKey(CK_BBOOL,
	CK_BYTE **, CK_ULONG *, CK_ATTRIBUTE *,
	CK_ATTRIBUTE *, CK_ATTRIBUTE *, CK_ATTRIBUTE *);

CK_RV ber_decode_DSAPrivateKey(CK_BYTE *,
	CK_ULONG, CK_ATTRIBUTE **, CK_ATTRIBUTE **,
	CK_ATTRIBUTE **, CK_ATTRIBUTE **);

#define	APPID	"TPM_STDLL"

/* log to stdout */
#define	LogMessage(dest, priority, layer, fmt, ...) \
	(void) fprintf(dest, "%s %s %s:%d " fmt "\n", (char *)priority, \
		(char *)layer, (char *)__FILE__,\
		(int)__LINE__, __VA_ARGS__);

#define	LogMessage1(dest, priority, layer, data) \
	(void) fprintf(dest, "%s %s %s:%d %s\n", priority, layer, __FILE__, \
	__LINE__, data);

/* Debug logging */
#ifdef DEBUG
#define	LogDebug(fmt, ...) LogMessage(stdout, "LOG_DEBUG", APPID, \
	fmt, __VA_ARGS__)

#define	LogDebug1(data) LogMessage1(stdout, "LOG_DEBUG", APPID, data)

/* Error logging */
#define	LogError(fmt, ...) LogMessage(stderr, "LOG_ERR", APPID,\
	"ERROR: " fmt, __VA_ARGS__)

#define	LogError1(data) LogMessage1(stderr, "LOG_ERR", APPID,\
	"ERROR: " data)

/* Warn logging */
#define	LogWarn(fmt, ...) LogMessage(stdout, "LOG_WARNING", APPID,\
	"WARNING: " fmt, __VA_ARGS__)

#define	LogWarn1(data) LogMessage1(stdout, "LOG_WARNING", APPID,\
	"WARNING: " data)

/* Info Logging */
#define	LogInfo(fmt, ...) LogMessage(stdout, "LOG_INFO", APPID,\
	fmt, __VA_ARGS__)

#define	LogInfo1(data) LogMessage1(stdout, "LOG_INFO", APPID, data)

#define	st_err_log(...) LogMessage(stderr, "ST MSG", APPID,\
	"", __VA_ARGS__)
#else
#define	LogDebug(...)
#define	LogDebug1(...)
#define	LogBlob(...)
#define	LogError(...)
#define	LogError1(...)
#define	LogWarn(...)
#define	LogWarn1(...)
#define	LogInfo(...)
#define	LogInfo1(...)
#define	st_err_log(...)
#endif

/*
 * CK_FUNCTION_LIST is a structure holding a Cryptoki spec
 * version and pointers of appropriate types to all the
 * Cryptoki functions
 */

/* CK_FUNCTION_LIST is new for v2.0 */

typedef CK_RV
	(CK_PTR ST_C_Initialize)
	(void *ppFunctionList, CK_SLOT_ID slotID, CK_CHAR_PTR pCorrelator);
typedef CK_RV
	(CK_PTR  ST_C_Finalize)
	(CK_VOID_PTR pReserved);
typedef CK_RV
	(CK_PTR  ST_C_Terminate)();
typedef CK_RV
	(CK_PTR  ST_C_GetInfo)
	(CK_INFO_PTR pInfo);
typedef CK_RV
	(CK_PTR  ST_C_GetFunctionList)
	(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
typedef CK_RV
	(CK_PTR  ST_C_GetSlotList)
	(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
	CK_ULONG_PTR pusCount);
typedef CK_RV
	(CK_PTR  ST_C_GetSlotInfo)
	(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
typedef CK_RV
	(CK_PTR  ST_C_GetTokenInfo)
	(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
typedef CK_RV
	(CK_PTR  ST_C_GetMechanismList)
	(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
	CK_ULONG_PTR pusCount);
typedef CK_RV
	(CK_PTR  ST_C_GetMechanismInfo)
	(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
	CK_MECHANISM_INFO_PTR pInfo);
typedef CK_RV
	(CK_PTR  ST_C_InitToken)
	(CK_SLOT_ID slotID, CK_CHAR_PTR pPin, CK_ULONG usPinLen,
	CK_CHAR_PTR pLabel);
typedef CK_RV
	(CK_PTR  ST_C_InitPIN)
	(ST_SESSION_T hSession, CK_CHAR_PTR pPin,
	CK_ULONG usPinLen);
typedef CK_RV
	(CK_PTR  ST_C_SetPIN)
	(ST_SESSION_T hSession, CK_CHAR_PTR pOldPin,
	CK_ULONG usOldLen, CK_CHAR_PTR pNewPin,
	CK_ULONG usNewLen);

typedef CK_RV
	(CK_PTR  ST_C_OpenSession)
	(CK_SLOT_ID slotID, CK_FLAGS flags,
	CK_SESSION_HANDLE_PTR phSession);

typedef CK_RV
	(CK_PTR  ST_C_CloseSession)
	(ST_SESSION_T hSession);
typedef CK_RV
	(CK_PTR  ST_C_CloseAllSessions)
	(CK_SLOT_ID slotID);
typedef CK_RV
	(CK_PTR  ST_C_GetSessionInfo)
	(ST_SESSION_T hSession, CK_SESSION_INFO_PTR pInfo);
typedef CK_RV
	(CK_PTR  ST_C_GetOperationState)
	(ST_SESSION_T hSession, CK_BYTE_PTR pOperationState,
	CK_ULONG_PTR pulOperationStateLen);
typedef CK_RV
	(CK_PTR  ST_C_SetOperationState)
	(ST_SESSION_T hSession, CK_BYTE_PTR pOperationState,
	CK_ULONG ulOperationStateLen,
	CK_OBJECT_HANDLE hEncryptionKey,
	CK_OBJECT_HANDLE hAuthenticationKey);
typedef CK_RV
	(CK_PTR  ST_C_Login)(ST_SESSION_T hSession,
	CK_USER_TYPE userType, CK_CHAR_PTR pPin,
	CK_ULONG usPinLen);
typedef CK_RV
	(CK_PTR  ST_C_Logout)(ST_SESSION_T hSession);
typedef CK_RV
	(CK_PTR  ST_C_CreateObject)
	(ST_SESSION_T hSession, CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG usCount, CK_OBJECT_HANDLE_PTR phObject);

typedef CK_RV
	(CK_PTR  ST_C_CopyObject)
	(ST_SESSION_T hSession, CK_OBJECT_HANDLE hObject,
	CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount,
	CK_OBJECT_HANDLE_PTR phNewObject);
typedef CK_RV
	(CK_PTR  ST_C_DestroyObject)
	(ST_SESSION_T hSession, CK_OBJECT_HANDLE hObject);
typedef CK_RV
	(CK_PTR  ST_C_GetObjectSize)
	(ST_SESSION_T hSession, CK_OBJECT_HANDLE hObject,
	CK_ULONG_PTR pusSize);
typedef CK_RV
	(CK_PTR  ST_C_GetAttributeValue)
	(ST_SESSION_T hSession, CK_OBJECT_HANDLE hObject,
	CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount);
typedef CK_RV
	(CK_PTR  ST_C_SetAttributeValue)
	(ST_SESSION_T hSession, CK_OBJECT_HANDLE hObject,
	CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount);
typedef CK_RV
	(CK_PTR  ST_C_FindObjectsInit)
	(ST_SESSION_T hSession, CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG usCount);
typedef CK_RV
	(CK_PTR  ST_C_FindObjects)
	(ST_SESSION_T hSession,
	CK_OBJECT_HANDLE_PTR phObject, CK_ULONG usMaxObjectCount,
	CK_ULONG_PTR pusObjectCount);
typedef CK_RV
	(CK_PTR  ST_C_FindObjectsFinal)
	(ST_SESSION_T hSession);
typedef CK_RV
	(CK_PTR  ST_C_EncryptInit)
	(ST_SESSION_T hSession, CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey);
typedef CK_RV
	(CK_PTR  ST_C_Encrypt)
	(ST_SESSION_T hSession, CK_BYTE_PTR pData,
	CK_ULONG usDataLen, CK_BYTE_PTR pEncryptedData,
	CK_ULONG_PTR pusEncryptedDataLen);
typedef CK_RV
	(CK_PTR  ST_C_EncryptUpdate)
	(ST_SESSION_T hSession, CK_BYTE_PTR pPart,
	CK_ULONG usPartLen, CK_BYTE_PTR pEncryptedPart,
	CK_ULONG_PTR pusEncryptedPartLen);
typedef CK_RV
	(CK_PTR  ST_C_EncryptFinal)
	(ST_SESSION_T hSession,
	CK_BYTE_PTR pLastEncryptedPart,
	CK_ULONG_PTR pusLastEncryptedPartLen);
typedef CK_RV
	(CK_PTR  ST_C_DecryptInit)
	(ST_SESSION_T hSession, CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey);
typedef CK_RV
	(CK_PTR  ST_C_Decrypt)
	(ST_SESSION_T hSession, CK_BYTE_PTR pEncryptedData,
	CK_ULONG usEncryptedDataLen, CK_BYTE_PTR pData,
	CK_ULONG_PTR pusDataLen);
typedef CK_RV
	(CK_PTR  ST_C_DecryptUpdate)
	(ST_SESSION_T hSession, CK_BYTE_PTR pEncryptedPart,
	CK_ULONG usEncryptedPartLen, CK_BYTE_PTR pPart,
	CK_ULONG_PTR pusPartLen);
typedef CK_RV
	(CK_PTR  ST_C_DecryptFinal)
	(ST_SESSION_T hSession, CK_BYTE_PTR pLastPart,
	CK_ULONG_PTR pusLastPartLen);
typedef CK_RV
	(CK_PTR  ST_C_DigestInit)
	(ST_SESSION_T hSession,
	CK_MECHANISM_PTR pMechanism);
typedef CK_RV
	(CK_PTR  ST_C_Digest)
	(ST_SESSION_T hSession, CK_BYTE_PTR pData,
	CK_ULONG usDataLen, CK_BYTE_PTR pDigest,
	CK_ULONG_PTR pusDigestLen);
typedef CK_RV
	(CK_PTR  ST_C_DigestUpdate)
	(ST_SESSION_T hSession, CK_BYTE_PTR pPart,
	CK_ULONG usPartLen);
typedef CK_RV
	(CK_PTR  ST_C_DigestKey)
	(ST_SESSION_T hSession, CK_OBJECT_HANDLE hKey);
typedef CK_RV
	(CK_PTR  ST_C_DigestFinal)
	(ST_SESSION_T hSession, CK_BYTE_PTR pDigest,
	CK_ULONG_PTR pusDigestLen);
typedef CK_RV
	(CK_PTR  ST_C_SignInit)
	(ST_SESSION_T hSession, CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey);
typedef CK_RV
	(CK_PTR  ST_C_Sign)
	(ST_SESSION_T hSession, CK_BYTE_PTR pData,
	CK_ULONG usDataLen, CK_BYTE_PTR pSignature,
	CK_ULONG_PTR pusSignatureLen);
typedef CK_RV
	(CK_PTR  ST_C_SignUpdate)
	(ST_SESSION_T hSession, CK_BYTE_PTR pPart,
	CK_ULONG usPartLen);
typedef CK_RV
	(CK_PTR  ST_C_SignFinal)
	(ST_SESSION_T hSession, CK_BYTE_PTR pSignature,
	CK_ULONG_PTR pusSignatureLen);
typedef CK_RV
	(CK_PTR  ST_C_SignRecoverInit)
	(ST_SESSION_T hSession, CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey);
typedef CK_RV
	(CK_PTR  ST_C_SignRecover)
	(ST_SESSION_T hSession, CK_BYTE_PTR pData,
	CK_ULONG usDataLen, CK_BYTE_PTR pSignature,
	CK_ULONG_PTR pusSignatureLen);
typedef CK_RV
	(CK_PTR  ST_C_VerifyInit)
	(ST_SESSION_T hSession, CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey);
typedef CK_RV
	(CK_PTR  ST_C_Verify)
	(ST_SESSION_T hSession, CK_BYTE_PTR pData,
	CK_ULONG usDataLen, CK_BYTE_PTR pSignature,
	CK_ULONG usSignatureLen);
typedef CK_RV
	(CK_PTR  ST_C_VerifyUpdate)
	(ST_SESSION_T hSession, CK_BYTE_PTR pPart,
	CK_ULONG usPartLen);
typedef CK_RV
	(CK_PTR  ST_C_VerifyFinal)
	(ST_SESSION_T hSession, CK_BYTE_PTR pSignature,
	CK_ULONG usSignatureLen);
typedef CK_RV
	(CK_PTR  ST_C_VerifyRecoverInit)
	(ST_SESSION_T hSession, CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey);
typedef CK_RV
	(CK_PTR  ST_C_VerifyRecover)
	(ST_SESSION_T hSession, CK_BYTE_PTR pSignature,
	CK_ULONG usSignatureLen, CK_BYTE_PTR pData,
	CK_ULONG_PTR pusDataLen);
typedef CK_RV
	(CK_PTR  ST_C_DigestEncryptUpdate)
	(ST_SESSION_T hSession, CK_BYTE_PTR pPart,
	CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
	CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV
	(CK_PTR  ST_C_DecryptDigestUpdate)
	(ST_SESSION_T hSession, CK_BYTE_PTR pEncryptedPart,
	CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
	CK_ULONG_PTR pulPartLen);
typedef CK_RV
	(CK_PTR  ST_C_SignEncryptUpdate)
	(ST_SESSION_T hSession, CK_BYTE_PTR pPart,
	CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
	CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV
	(CK_PTR  ST_C_DecryptVerifyUpdate)
	(ST_SESSION_T hSession, CK_BYTE_PTR pEncryptedPart,
	CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
	CK_ULONG_PTR pulPartLen);
typedef CK_RV
	(CK_PTR  ST_C_GenerateKey)
	(ST_SESSION_T hSession, CK_MECHANISM_PTR pMechanism,
	CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount,
	CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV
	(CK_PTR  ST_C_GenerateKeyPair)
	(ST_SESSION_T hSession, CK_MECHANISM_PTR pMechanism,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG usPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG usPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_OBJECT_HANDLE_PTR phPublicKey);
typedef CK_RV
	(CK_PTR  ST_C_WrapKey)
	(ST_SESSION_T hSession, CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
	CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pusWrappedKeyLen);
typedef CK_RV
	(CK_PTR  ST_C_UnwrapKey)
	(ST_SESSION_T hSession, CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
	CK_ULONG usWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG usAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV
	(CK_PTR  ST_C_DeriveKey)
	(ST_SESSION_T hSession, CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG usAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV
	(CK_PTR  ST_C_SeedRandom)
	(ST_SESSION_T hSession, CK_BYTE_PTR pSeed,
	CK_ULONG usSeedLen);
typedef CK_RV
	(CK_PTR  ST_C_GenerateRandom)
	(ST_SESSION_T hSession, CK_BYTE_PTR pRandomData,
	CK_ULONG usRandomLen);
typedef CK_RV
	(CK_PTR  ST_C_GetFunctionStatus)
	(ST_SESSION_T hSession);
typedef CK_RV
	(CK_PTR  ST_C_CancelFunction)
	(ST_SESSION_T hSession);
typedef CK_RV
	(CK_PTR  ST_Notify)
	(ST_SESSION_T hSession, CK_NOTIFICATION event,
	CK_VOID_PTR pApplication);
typedef CK_RV
	(CK_PTR  ST_C_WaitForSlotEvent)
	(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
	CK_VOID_PTR pReserved);



struct ST_FCN_LIST {

	ST_C_Initialize ST_Initialize;
	ST_C_Finalize ST_Finalize;

	ST_C_GetTokenInfo ST_GetTokenInfo;
	ST_C_GetMechanismList ST_GetMechanismList;
	ST_C_GetMechanismInfo ST_GetMechanismInfo;
	ST_C_InitToken ST_InitToken;
	ST_C_InitPIN ST_InitPIN;
	ST_C_SetPIN ST_SetPIN;

	ST_C_OpenSession ST_OpenSession;
	ST_C_CloseSession ST_CloseSession;
	ST_C_GetSessionInfo ST_GetSessionInfo;
	ST_C_GetOperationState ST_GetOperationState;
	ST_C_SetOperationState ST_SetOperationState;
	ST_C_Login ST_Login;
	ST_C_Logout ST_Logout;

	ST_C_CreateObject ST_CreateObject;
	ST_C_CopyObject ST_CopyObject;
	ST_C_DestroyObject ST_DestroyObject;
	ST_C_GetObjectSize ST_GetObjectSize;
	ST_C_GetAttributeValue ST_GetAttributeValue;
	ST_C_SetAttributeValue ST_SetAttributeValue;
	ST_C_FindObjectsInit ST_FindObjectsInit;
	ST_C_FindObjects ST_FindObjects;
	ST_C_FindObjectsFinal ST_FindObjectsFinal;


	ST_C_EncryptInit ST_EncryptInit;
	ST_C_Encrypt ST_Encrypt;
	ST_C_EncryptUpdate ST_EncryptUpdate;
	ST_C_EncryptFinal ST_EncryptFinal;
	ST_C_DecryptInit ST_DecryptInit;
	ST_C_Decrypt ST_Decrypt;
	ST_C_DecryptUpdate ST_DecryptUpdate;
	ST_C_DecryptFinal ST_DecryptFinal;
	ST_C_DigestInit ST_DigestInit;
	ST_C_Digest ST_Digest;
	ST_C_DigestUpdate ST_DigestUpdate;
	ST_C_DigestKey ST_DigestKey;
	ST_C_DigestFinal ST_DigestFinal;
	ST_C_SignInit ST_SignInit;
	ST_C_Sign ST_Sign;
	ST_C_SignUpdate ST_SignUpdate;
	ST_C_SignFinal ST_SignFinal;
	ST_C_SignRecoverInit ST_SignRecoverInit;
	ST_C_SignRecover ST_SignRecover;
	ST_C_VerifyInit ST_VerifyInit;
	ST_C_Verify ST_Verify;
	ST_C_VerifyUpdate ST_VerifyUpdate;
	ST_C_VerifyFinal ST_VerifyFinal;
	ST_C_VerifyRecoverInit ST_VerifyRecoverInit;
	ST_C_VerifyRecover ST_VerifyRecover;
	ST_C_DigestEncryptUpdate ST_DigestEncryptUpdate;
	ST_C_DecryptDigestUpdate ST_DecryptDigestUpdate;
	ST_C_SignEncryptUpdate ST_SignEncryptUpdate;
	ST_C_DecryptVerifyUpdate ST_DecryptVerifyUpdate;
	ST_C_GenerateKey ST_GenerateKey;
	ST_C_GenerateKeyPair ST_GenerateKeyPair;
	ST_C_WrapKey ST_WrapKey;
	ST_C_UnwrapKey ST_UnwrapKey;
	ST_C_DeriveKey ST_DeriveKey;
	ST_C_SeedRandom ST_SeedRandom;
	ST_C_GenerateRandom ST_GenerateRandom;
	ST_C_GetFunctionStatus ST_GetFunctionStatus;
	ST_C_CancelFunction ST_CancelFunction;
};

typedef struct ST_FCN_LIST  STDLL_FcnList_t;

#endif /* _TPMTOK_INT_H */
