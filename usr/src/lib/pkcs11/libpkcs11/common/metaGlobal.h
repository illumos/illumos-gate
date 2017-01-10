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

#ifndef _METAGLOBAL_H
#define	_METAGLOBAL_H


/*
 * This file contains all the data structures used for the meta slot
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <assert.h>
#include <pthread.h>
#include <synch.h>
#include <unistd.h>
#include <security/cryptoki.h>
#include <stdio.h>
#include <cryptoutil.h>
#include <pkcs11Session.h>
#include <pkcs11Slot.h>
#include <sys/crypto/ioctl.h>

/*
 * In "generic_attr_t", attributes that are not CK_BBOOL and
 * CK_ULONG, the data will be stored in generic_data.
 * Currently, 16 bytes will be pre-allocated for this.
 * This is just a _WILD_ guess.  If actual
 * experience shows that 16 bytes is too small for most of the
 * data that will be stored here, and cause this
 * memory to be reallocated all the time, this should be increased.
 */
#define	INITIAL_ATTR_LEN	16

/* We provide one slot, with the following arbitrary identifier. */
#define	METASLOT_SLOTID	42

/* Metaslot is always the first slot in the framdwork, with slotID=0 */
#define	METASLOT_FRAMEWORK_ID	0

/*
 * These are the 2 acceptable string values for ${METASLOT_ENABLE} and
 * ${METASLOT_AUTO_KEY_MIGRATE} environment variable
 */
#define	TRUE_STRING	"true"
#define	FALSE_STRING	"false"

/* Magic values for different data structures */
#define	METASLOT_SESSION_MAGIC		0xECF00004
#define	METASLOT_SESSION_BADMAGIC	0xBAD00004
#define	METASLOT_OBJECT_MAGIC		0xECF0B004
#define	METASLOT_OBJECT_BADMAGIC	0xBAD0B004
#define	METASLOT_OPSTATE_MAGIC		0xECF09004
#define	METASLOT_OPSTATE_BADMAGIC	0xBAD09004

#define	IS_READ_ONLY_SESSION(session_flag) \
	(!(session_flag & CKF_RW_SESSION))

/*
 * Operation modes passed to meta_do_operation()
 * MODE_UPDATE_WITHKEY is only used for C_DigestKey.
 */
#define	MODE_SINGLE		0x0100
#define	MODE_UPDATE		0x0200
#define	MODE_UPDATE_WITHKEY	0x0400
#define	MODE_FINAL		0x1000


/* CK_INFO: Information about cryptoki */
#define	METASLOT_CRYPTOKI_VERSION_MAJOR	2
#define	METASLOT_CRYPTOKI_VERSION_MINOR	40
#define	METASLOT_MANUFACTURER_ID	"Sun Microsystems, Inc.          "
#define	METASLOT_LIBRARY_DESCRIPTION	"Sun Metaslot                    "
#define	METASLOT_LIBRARY_VERSION_MAJOR	1
#define	METASLOT_LIBRARY_VERSION_MINOR	1

/* CK_SLOT_INFO */
#define	METASLOT_SLOT_DESCRIPTION	"Sun Metaslot                    " \
				"                                "
#define	METASLOT_HARDWARE_VERSION_MAJOR	0
#define	METASLOT_HARDWARE_VERSION_MINOR	0
#define	METASLOT_FIRMWARE_VERSION_MAJOR	0
#define	METASLOT_FIRMWARE_VERSION_MINOR	0

/* CK_TOKEN_INFO: More information about token */
#define	METASLOT_TOKEN_LABEL		"Sun Metaslot                    "
#define	METASLOT_TOKEN_MODEL		"1.0             "

/*
 * Maximum number of objects and sessions to queue up before actually
 * freeing them using the free() system.  This is necessary to workaround
 * a problem in which applications re-uses handles that are no longer valid
 */
#define	MAX_OBJ_TO_BE_FREED	300
#define	MAX_SESSION_TO_BE_FREED	300

/*
 * The following 2 functions deals with inserting and deleting
 * from double linked lists.  It can work with any data structure
 * that have "prev" and "next" defined.
 */

/* This always inserts into the head of the list */
#define	INSERT_INTO_LIST(list, item)			\
{							\
	if ((list) == NULL) {				\
		(item)->prev = NULL;			\
		(item)->next = NULL;			\
		(list) = (item);			\
	} else {					\
		(item)->next = (list);			\
		(item)->prev = NULL;			\
		(list)->prev = (item);			\
		(list) = (item);			\
	}						\
}


/*
 * Remove item from list
 */
#define	REMOVE_FROM_LIST(list, item) 				\
{								\
	/* item is at the beginning of the list */		\
	if ((list) == item) {					\
		if ((item)->next == NULL) {			\
			(list) = NULL;				\
		} else {					\
			(item)->next->prev = NULL;		\
			(list) = (item)->next;			\
		}						\
	} else {						\
		/*						\
		 * let the items which are initialized and not	\
		 * connected to the list trip over the asserts	\
		 */						\
		if ((item)->next) {				\
			(item)->next->prev = item->prev;	\
			assert((item)->prev != NULL);		\
			(item)->prev->next = (item)->next;	\
		} else {					\
			assert((item)->prev != NULL);		\
			(item)->prev->next = NULL;		\
		}						\
	}							\
}

/*
 * OBJRELEASE
 *
 * Signal that a metaobject is no longer in use (but is still valid).
 */
#define	OBJRELEASE(object)						\
	if (object != NULL) {						\
		(void) pthread_rwlock_unlock(&object->object_lock);	\
	}

/*
 * REFRELEASE
 *
 * Signal that a metasession is no longer in use (but is still valid).
 *
 */
#define	REFRELEASE(session)						\
	if (session != NULL) {						\
		(void) pthread_rwlock_unlock(&session->session_lock);	\
	}

/* FreeObject/FreeToken Enumeration */
typedef enum {
	FREE_UNCHECKED = 0,	/* Has not been checked */
	FREE_DISABLED = 1,	/* No supported provider or key type */
	FREE_ALLOWED_KEY = 2,	/* Supported key type */
	FREE_ENABLED = 3	/* FreeObject/Token enabled */
} freeobject_state_t;


/* Generic attribute type, for storing and managing PKCS#11 attributes. */
typedef struct _attr {
	CK_ATTRIBUTE attribute;

	boolean_t isMalloced;

	/* attr is necessary for creating a clone of the object */
	boolean_t isCloneAttr;

	/*
	 * depends on the PKCS#11 implementation, this attr might or might
	 * not have a value.  It's OK for it to not have a value
	 * (ie: the default value is empty)
	 */
	boolean_t canBeEmptyValue;

	boolean_t hasValueForClone;

	CK_BBOOL generic_bbool;
	CK_ULONG generic_ulong;
	CK_BYTE generic_data[INITIAL_ATTR_LEN];
} generic_attr_t;

/*
 * These need to be defined here before the actual structures are defined
 * because they are used in some of the structure definitions.
 */
typedef struct slotobject slot_object_t;
typedef struct metasession meta_session_t;
typedef struct metaobject meta_object_t;
typedef struct metaopstate meta_opstate_t;

/*
 * slot_session_t
 *
 * Wrapper for a session on a provider. This structure is only used internally
 * in metaslot; it is never revealed to applications.
 */
typedef struct slotsession {
	CK_ULONG slotnum;
	CK_SLOT_ID fw_st_id; /* used for accessing framework's slottable */
	CK_SESSION_HANDLE hSession;

	boolean_t is_dualop_capable;
	CK_FLAGS session_flags;	/* what type of session */

	struct slotsession *next;
	struct slotsession *prev;

	pthread_rwlock_t object_list_lock;
	slot_object_t *object_list_head;
} slot_session_t;


/*
 * slot_object_t
 *
 * Wrapper for an object on a provider. This structure is only used internally
 * in metaslot; it is never revealed to applications.
 */
struct slotobject {
	CK_OBJECT_HANDLE hObject;

	struct slotobject *next;
	struct slotobject *prev;

	slot_session_t *creator_session;

	boolean_t isToken;
};


/*
 * mechinfo_t
 *
 * A mechinfo_t is created for each mechanism on a slot.
 *
 * This information is used for selecting which slots support the given
 * mechanism for a crypto operation.
 *
 */
typedef struct mechinfo {
	CK_ULONG slotnum;

	boolean_t initialized;
	boolean_t supported;
	CK_MECHANISM_INFO mechanism_info;
} mechinfo_t;


/*
 * operation_info_t
 *
 * Part of a meta_session_t, used to track active operations.
 */
typedef struct opinfo {
	CK_FLAGS type;
	slot_session_t *session;
	mechinfo_t *stats;
} operation_info_t;

typedef struct find_objs_info {
	boolean_t op_active;	/* Indicate whether FindObjects is active */
	meta_object_t **matched_objs;
	int num_matched_objs;
	int next_result_index;	/* index of next object to be returned */
} find_objs_info_t;

typedef struct mech_support_info {
	CK_MECHANISM_TYPE mech;
	/* Array of mechinfo_t allocated based on number of slots */
	mechinfo_t **supporting_slots;
	unsigned long num_supporting_slots;
} mech_support_info_t;

typedef struct	crypto_init {
	CK_FLAGS optype;		/* place holder for init parameters */
	struct metasession *session;	/* place holder for init parameters */
	CK_MECHANISM *pMech;		/* place holder for init parameters */
	struct metaobject *key;		/* place holder for init parameters */
	CK_ULONG slotnum;	/* slot where the init operation took place */
	boolean_t done;		/* set when the real init is done */
	boolean_t app;		/* set when C_xxxInit is called by app */
} crypto_init_t;

/*
 * meta_session_t
 *
 * The internal state for a meta-session is kept here. The session handles
 * given to applications are always pointers to a structure of this type.
 *
 */
struct metasession {
	ulong_t magic_marker;
	pthread_rwlock_t session_lock;

	pthread_mutex_t isClosingSession_lock;
	boolean_t isClosingSession;

	struct metasession *next;
	struct metasession *prev;

	CK_FLAGS session_flags;

	/*
	 * Could have just declared this as "op", but declaring it as
	 * op1 so that "op2" can be easily added when dual-op support
	 * is implemented in the future
	 */
	operation_info_t op1;

	/*
	 * This is for keeping track of which slots support a particular
	 * mechanism.  This information doesn't
	 * have to be kept on a per session bases, but having the
	 * memory pre-allocated per session would make things much simpiler,
	 * because memory doesn't need to be allocated/deallocated everytime
	 * we do an operation.
	 */
	mech_support_info_t mech_support_info;


	/* Session objects created by this session. */
	pthread_rwlock_t object_list_lock;
	meta_object_t *object_list_head;

	/* C_FindObjects support. */
	find_objs_info_t find_objs_info;

	/* deferred init to be used by digest, encrypt, decrypt */
	crypto_init_t	init;
};


/*
 * meta_object_t
 *
 * The internal state for a meta-object is kept here. The object handles
 * given to applications are always pointers to a structure of this type.
 */
struct metaobject {
	ulong_t magic_marker;
	pthread_rwlock_t object_lock;

	pthread_mutex_t isClosingObject_lock;
	boolean_t isClosingObject;

	struct metaobject *next;
	struct metaobject *prev;

	meta_session_t *creator_session; /* Only set for session objects */

	boolean_t isToken;		/* alias for CKA_TOKEN */
	boolean_t isPrivate;		/* alias for CKA_PRIVATE */
	boolean_t isSensitive;		/* alias for CKA_SENSITIVE */
	boolean_t isExtractable;	/* alias for CKA_EXTRACTABLE */

	freeobject_state_t isFreeToken;
	freeobject_state_t isFreeObject;

	CK_ULONG master_clone_slotnum; /* set when object is created */
	slot_object_t **clones;
	/* indicate if tried to create clone object in a slot */
	boolean_t	*tried_create_clone;

	pthread_rwlock_t attribute_lock;
	size_t num_attributes;
	generic_attr_t *attributes;

	pthread_mutex_t clone_create_lock;
	size_t clone_template_size;	/* 0 if not yet known. */
	CK_ATTRIBUTE *clone_template; /* NULL if not yet known. */
};


/*
 * struct metaopstate
 *
 * Used as the format for the operation state returned via
 * C_GetOperationState.
 */
typedef struct opstate_data {
	CK_FLAGS	op_type;
	CK_ULONG	op_slotnum;
	CK_ULONG	op_state_len;
	boolean_t	op_init_app;
	boolean_t	op_init_done;
} opstate_data_t;

struct metaopstate {
	ulong_t magic_marker;
	/*
	 * Could have just declared this as "state", but declaring it like this
	 * so that when dual-op support is implemented in the future, the
	 * changes will be simplier.
	 */
	struct opstate_data state[1];
};


/*
 * session_pool_t
 *
 * Used to cache open sessions in a slot.
 */
typedef struct sessionpool {
	pthread_mutex_t list_lock;

	/* list of sessions that's currently in use */
	slot_session_t *active_list_head;

	/*
	 * list of sessions that are not in use, but can't be deleted because
	 * either session/token objects are created using these sessions
	 * or we need to have one session left with the provider to maintain
	 * the logged in state.  Any of these sessions could be re-used if
	 * a session is needed to be established with a provider.
	 */
	slot_session_t *persist_list_head;

	/*
	 * List of sessions that are not in use at the moment.  We keep
	 * a list of sessions with a particular provider instead of
	 * creating a new session everytime for efficiency
	 */
	slot_session_t *idle_list_head;
	boolean_t keep_one_alive;
	int num_idle_sessions; /* number of sessions in "idle_list_head" */
} session_pool_t;


/*
 * slot_data_t
 *
 * Each slot has a session pool, a collection of persistant sessions to
 * allow for more efficient operation. Specifically, to allow reuse of
 * previously session objects (which need the creating session to stick
 * around), as well as being frugal with creating/closing sessions.
 */
typedef struct slotdata {
	CK_SLOT_ID fw_st_id; /* framework slot table ID */

	session_pool_t session_pool;

	pthread_rwlock_t tokenobject_list_lock;
	slot_object_t *tokenobject_list_head;
} slot_data_t;


typedef enum {
	ALL_TOKEN = 0,
	PUBLIC_TOKEN = 1,
	PRIVATE_TOKEN = 2
} token_obj_type_t;

/*
 * metaslot_config_t
 *
 * This holds the configuration information for meta slot.
 * It will first be filled with values that users defined
 * in environment variables.  Any value not defined by the user
 * will be filled with values from the system wide configuration file.
 */
typedef struct _metaslot_config {
	/* token to be used as the keystore for metaslot */
	boolean_t keystore_token_specified;
	CK_UTF8CHAR keystore_token[TOKEN_LABEL_SIZE + 1];

	/* slot to be used as the keystore for metaslot */
	boolean_t keystore_slot_specified;
	CK_UTF8CHAR keystore_slot[SLOT_DESCRIPTION_SIZE + 1];

	/* should meta slot be enabled or not */
	boolean_t enabled_specified;
	boolean_t enabled;

	/* should auto migration of sensitive token objects be enabled or not */
	boolean_t auto_key_migrate_specified;
	boolean_t auto_key_migrate;
} metaslot_config_t;

/*
 * The following 2 structures are used to link the to-be-freed
 * meta sessions and meta objects into linked lists.
 * The items on these linked list have not yet been freed via free(); instead
 * they are added to this list. The actual free will take place when
 * the number of objects queued reaches MAX_OBJ_TO_BE_FREED or
 * MAX_SESSION_TO_BE_FREED, at which time the first object in the
 * list will be freed.
 */
typedef struct obj_to_be_freed_list {
	meta_object_t   *first; /* points to first obj in the list */
	meta_object_t   *last;  /* points to last obj in the list */
	uint32_t	count;  /* current total objs in the list */
	pthread_mutex_t	obj_to_be_free_mutex;
} object_to_be_freed_list_t;

typedef struct ses_to_be_freed_list {
	meta_session_t *first; /* points to first session in the list */
	meta_session_t *last;  /* points to last session in the list */
	uint32_t	count;  /* current total session in the list */
	pthread_mutex_t ses_to_be_free_mutex;
} ses_to_be_freed_list_t;

typedef struct cipher_mechs_threshold {
	int		mech_type;
	uint32_t	mech_threshold;
} cipher_mechs_threshold_t;

/* Global variables */
extern metaslot_config_t metaslot_config;
extern boolean_t metaslot_enabled;
extern CK_SLOT_ID metaslot_keystore_slotid;
extern boolean_t metaslot_auto_key_migrate;
extern struct CK_FUNCTION_LIST metaslot_functionList;
extern pthread_mutex_t initmutex;

extern ses_to_be_freed_list_t ses_delay_freed;
extern object_to_be_freed_list_t obj_delay_freed;
extern void (*Tmp_GetThreshold)(void *);

extern CK_BBOOL falsevalue;
extern CK_BBOOL truevalue;

/* --- Prototypes --- */

CK_RV meta_slotManager_initialize();
void meta_slotManager_finalize();
void meta_slotManager_find_object_token();
CK_RV meta_get_slot_session(CK_ULONG slotnum, slot_session_t **session,
    CK_FLAGS flags);
void meta_release_slot_session(slot_session_t *session);

CK_RV meta_mechManager_initialize();
void meta_mechManager_finalize();
CK_RV meta_mechManager_get_mechs(CK_MECHANISM_TYPE *list, CK_ULONG *listsize);
CK_RV meta_mechManager_get_slots(mech_support_info_t  *mech_support_info,
    boolean_t force_update, CK_MECHANISM_INFO *mech_info);
CK_RV meta_mechManager_slot_supports_mech(CK_MECHANISM_TYPE mechanism,
    CK_ULONG slotnum, boolean_t *supports, mechinfo_t **slot_info,
    boolean_t force_update, CK_MECHANISM_INFO *mech_info);

CK_RV meta_operation_init(CK_FLAGS optype, meta_session_t *session,
    CK_MECHANISM *pMechanism, meta_object_t *key);
CK_RV meta_operation_init_defer(CK_FLAGS optype, meta_session_t *session,
    CK_MECHANISM *pMechanism, meta_object_t *key);
CK_RV meta_do_operation(CK_FLAGS optype, int mode,
    meta_session_t *session, meta_object_t *object,
    CK_BYTE *in, CK_ULONG inLen, CK_BYTE *out, CK_ULONG *outLen);

void meta_operation_cleanup(meta_session_t *session, CK_FLAGS optype,
    boolean_t finished_normally);

CK_RV meta_generate_keys(meta_session_t *session, CK_MECHANISM *pMechanism,
    CK_ATTRIBUTE *k1Template, CK_ULONG k1AttrCount, meta_object_t *key1,
    CK_ATTRIBUTE *k2Template, CK_ULONG k2AttrCount, meta_object_t *key2);

CK_RV meta_wrap_key(meta_session_t *session,
    CK_MECHANISM *pMechanism, meta_object_t *wrappingkey,
    meta_object_t *inputkey,
    CK_BYTE *wrapped_key, CK_ULONG *wrapped_key_len);

CK_RV meta_unwrap_key(meta_session_t *session,
    CK_MECHANISM *pMechanism, meta_object_t *unwrapping_key,
    CK_BYTE *wrapped_key, CK_ULONG wrapped_key_len,
    CK_ATTRIBUTE *template, CK_ULONG template_size,
    meta_object_t *unwrapped_key);

CK_RV meta_derive_key(meta_session_t *session, CK_MECHANISM *pMech,
    meta_object_t *basekey1, meta_object_t *basekey2,
    CK_OBJECT_HANDLE *phBaseKey2,
    CK_ATTRIBUTE *pTemplate, CK_ULONG ulAttributeCount,
    meta_object_t *newKey1, meta_object_t *newKey2,
    meta_object_t *newKey3, meta_object_t *newKey4);

void get_user_metaslot_config();

CK_RV meta_sessionManager_initialize();
void meta_sessionManager_finalize();
CK_RV meta_handle2session(CK_SESSION_HANDLE hSession,
    meta_session_t **session_p);
CK_RV meta_session_alloc(meta_session_t **newSession);
CK_RV meta_session_activate(meta_session_t *session);
CK_RV meta_session_deactivate(meta_session_t *session,
    boolean_t have_sessionlist_lock);
void meta_session_dealloc(meta_session_t *session);
void meta_session_delay_free(meta_session_t *sp);

CK_RV meta_objectManager_initialize();
void meta_objectManager_finalize();
CK_RV meta_handle2object(CK_OBJECT_HANDLE hObject, meta_object_t **object);
CK_RV meta_object_alloc(meta_session_t *session, meta_object_t **object);
CK_RV meta_object_get_attr(slot_session_t *slot_session,
    CK_OBJECT_HANDLE hObject, meta_object_t *object);
void meta_object_activate(meta_object_t *object);
CK_RV meta_object_deactivate(meta_object_t *object, boolean_t have_list_lock,
    boolean_t have_object_lock);
CK_RV meta_object_dealloc(meta_session_t *session, meta_object_t *object,
    boolean_t nukeSourceObj);
CK_RV meta_slot_object_alloc(slot_object_t **object);
void meta_slot_object_activate(slot_object_t *object, slot_session_t *session,
	boolean_t isToken);
void meta_slot_object_deactivate(slot_object_t *object);
void meta_slot_object_dealloc(slot_object_t *object);
CK_RV meta_object_copyin(meta_object_t *object);
CK_RV meta_object_get_clone(meta_object_t *object,
	CK_ULONG slot_num, slot_session_t *slot_session,
	slot_object_t **clone);
meta_object_t *meta_object_find_by_handle(CK_OBJECT_HANDLE hObject,
	CK_ULONG slotnum, boolean_t token_only);
CK_RV meta_token_object_deactivate(token_obj_type_t token_type);
void meta_object_delay_free(meta_object_t *objp);
boolean_t meta_freeobject_set(meta_object_t *object, CK_ATTRIBUTE *tmpl,
    CK_ULONG tmpl_len, boolean_t create);
CK_RV meta_freetoken_set(CK_ULONG slot_num, CK_BBOOL *current_value,
    CK_ATTRIBUTE *tmpl, CK_ULONG tmpl_len);
boolean_t meta_freeobject_check(meta_session_t *session, meta_object_t *obj,
    CK_MECHANISM *pMech, CK_ATTRIBUTE *tmpl, CK_ULONG tmpl_len,
    CK_KEY_TYPE keytype);
boolean_t meta_freeobject_clone(meta_session_t *session, meta_object_t *object);

CK_RV get_master_attributes_by_object(slot_session_t *session,
    slot_object_t *slot_object, generic_attr_t **attributes,
    size_t *num_attributes);
CK_RV get_master_attributes_by_template(
	CK_ATTRIBUTE *template, CK_ULONG template_size,
	generic_attr_t **attributes, size_t *num_attributes);
CK_RV get_master_template_by_type(CK_OBJECT_CLASS class, CK_ULONG subtype,
	generic_attr_t **attributes, size_t *num_attributes);
CK_RV get_master_attributes_by_type(CK_OBJECT_CLASS class, CK_ULONG subtype,
	generic_attr_t **attributes, size_t *num_attributes);
CK_RV get_master_attributes_by_duplication(
	generic_attr_t *src_attrs, size_t num_src_attrs,
	generic_attr_t **dst_attrs, size_t *num_dst_attrs);
void dealloc_attributes(generic_attr_t *attributes, size_t num_attributes);
CK_RV attribute_set_value(CK_ATTRIBUTE *new_attr,
	generic_attr_t *attributes, size_t num_attributes);
boolean_t get_template_ulong(CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE *attributes,
	CK_ULONG num_attributes, CK_ULONG *result);
boolean_t get_template_boolean(CK_ATTRIBUTE_TYPE type,
    CK_ATTRIBUTE *attributes, CK_ULONG num_attributes, boolean_t *result);
int set_template_boolean(CK_ATTRIBUTE_TYPE type,
    CK_ATTRIBUTE *attributes, CK_ULONG num_attributes, boolean_t local,
    CK_BBOOL *value);
CK_ULONG get_keystore_slotnum(void);
CK_ULONG get_softtoken_slotnum(void);
CK_SLOT_ID meta_slotManager_get_framework_table_id(CK_ULONG slotnum);
CK_ULONG meta_slotManager_get_slotcount(void);
boolean_t meta_slotManager_token_write_protected(void);
boolean_t metaslot_logged_in();
void metaslot_set_logged_in_flag(boolean_t value);

/*
 * Prototypes for the various meta_Foo implementations of C_Foo.
 *
 */
CK_RV meta_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
CK_RV meta_Initialize(CK_VOID_PTR pInitArgs);
CK_RV meta_Finalize(CK_VOID_PTR pReserved);
CK_RV meta_GetInfo(CK_INFO_PTR pInfo);
CK_RV meta_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
    CK_ULONG_PTR pulCount);
CK_RV meta_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
CK_RV meta_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
CK_RV meta_GetMechanismList(CK_SLOT_ID slotID,
    CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
CK_RV meta_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
    CK_MECHANISM_INFO_PTR pInfo);
CK_RV meta_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
CK_RV meta_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen);
CK_RV meta_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
    CK_ULONG ulOldPinLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewPinLen);
CK_RV meta_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
    CK_VOID_PTR pApplication, CK_NOTIFY Notify,
    CK_SESSION_HANDLE_PTR phSession);
CK_RV meta_CloseSession(CK_SESSION_HANDLE hSession);
CK_RV meta_CloseAllSessions(CK_SLOT_ID slotID);
CK_RV meta_GetSessionInfo(CK_SESSION_HANDLE hSession,
    CK_SESSION_INFO_PTR pInfo);
CK_RV meta_GetOperationState(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
CK_RV meta_SetOperationState(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen,
    CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
CK_RV meta_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
    CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_RV meta_Logout(CK_SESSION_HANDLE hSession);
CK_RV meta_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
CK_RV meta_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phNewObject);
CK_RV meta_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
CK_RV meta_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ULONG_PTR pulSize);
CK_RV meta_GetAttributeValue(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV meta_SetAttributeValue(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV meta_FindObjectsInit(CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV meta_FindObjects(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
    CK_ULONG_PTR pulObjectCount);
CK_RV meta_FindObjectsFinal(CK_SESSION_HANDLE hSession);
CK_RV meta_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey);
CK_RV meta_Encrypt(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
CK_RV meta_EncryptUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
CK_RV meta_EncryptFinal(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen);
CK_RV meta_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey);
CK_RV meta_Decrypt(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
    CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
CK_RV meta_DecryptUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
CK_RV meta_DecryptFinal(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);
CK_RV meta_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
CK_RV meta_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
CK_RV meta_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen);
CK_RV meta_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
CK_RV meta_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
    CK_ULONG_PTR pulDigestLen);
CK_RV meta_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey);
CK_RV meta_Sign(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
CK_RV meta_SignUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
CK_RV meta_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen);
CK_RV meta_SignRecoverInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV meta_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
CK_RV meta_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey);
CK_RV meta_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
CK_RV meta_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen);
CK_RV meta_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen);
CK_RV meta_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV meta_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
CK_RV meta_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen);
CK_RV meta_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
CK_RV meta_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen);
CK_RV meta_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
CK_RV meta_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
CK_RV meta_GenerateKeyPair(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate,
    CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
    CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey,
    CK_OBJECT_HANDLE_PTR phPrivateKey);
CK_RV meta_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
    CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
CK_RV meta_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
    CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
CK_RV meta_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
CK_RV meta_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
    CK_ULONG ulSeedLen);
CK_RV meta_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData,
    CK_ULONG ulRandomLen);
CK_RV meta_GetFunctionStatus(CK_SESSION_HANDLE hSession);
CK_RV meta_CancelFunction(CK_SESSION_HANDLE hSession);
CK_RV meta_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
    CK_VOID_PTR pReserved);

#ifdef	__cplusplus
}
#endif

#endif /* _METAGLOBAL_H */
