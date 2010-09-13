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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SOFTKEYSTOREUTIL_H
#define	_SOFTKEYSTOREUTIL_H

/*
 * Structures and function prototypes for the keystore
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/* Keystore State values */
#define	KEYSTORE_UNINITIALIZED	0
#define	KEYSTORE_PRESENT	1
#define	KEYSTORE_LOAD		2
#define	KEYSTORE_INITIALIZED	3
#define	KEYSTORE_UNAVAILABLE	4

typedef enum {
	ALL_TOKENOBJS = 0,
	PUB_TOKENOBJS = 1,
	PRI_TOKENOBJS = 2
} ks_search_type_t;

typedef struct ks_obj_handle {
	unsigned char name[256]; /* obj[monotonic-counter] */
	boolean_t public;	/* true if public obj, false for private obj */
} ks_obj_handle_t;

typedef struct ks_obj {

	/* handle for accessing this object */
	ks_obj_handle_t ks_handle;

	/* version number of object file */
	uint_t obj_version;

	/* contains decrypted binary data for obj */
	uchar_t *buf;

	/* size of binary data */
	size_t size;

	/* pointer to next item in list */
	struct ks_obj *next;
} ks_obj_t;

/*
 * Prototype for functions in softKeystore.c
 */
int soft_keystore_readlock(boolean_t set_lock);
int soft_keystore_writelock(boolean_t set_lock);
int soft_keystore_lock_object(ks_obj_handle_t *ks_handle, boolean_t read_lock);
int soft_keystore_unlock_object(int fd);
int soft_keystore_get_version(uint_t *version, boolean_t lock_held);
int soft_keystore_get_object_version(ks_obj_handle_t *ks_handle,
    uint_t *version, boolean_t lock_held);
int soft_keystore_getpin(char **hashed_pin, boolean_t lock_held);
int soft_keystore_setpin(uchar_t *oldpin, uchar_t *newpin, boolean_t lock_held);
int soft_keystore_authpin(uchar_t *pin);
CK_RV soft_keystore_get_objs(ks_search_type_t search_type,
    ks_obj_t **result_objs, boolean_t lock_held);
CK_RV soft_keystore_get_single_obj(ks_obj_handle_t *ks_handle,
    ks_obj_t **result_obj, boolean_t lock_held);
int soft_keystore_put_new_obj(uchar_t *buf, size_t len, boolean_t public,
    boolean_t lock_held, ks_obj_handle_t *keyhandle);
int soft_keystore_modify_obj(ks_obj_handle_t *ks_handle, uchar_t *buf,
    size_t len, boolean_t lock_held);
int soft_keystore_del_obj(ks_obj_handle_t *ks_handle, boolean_t lock_held);
int soft_keystore_get_pin_salt(char **salt);
CK_RV soft_keystore_pin_initialized(boolean_t *initialized, char **hashed_pin,
    boolean_t lock_held);
boolean_t soft_keystore_status(int desired_state);
int soft_keystore_init(int desired_state);
int create_keystore();

#ifdef __cplusplus
}
#endif

#endif /* _SOFTKEYSTOREUTIL_H */
