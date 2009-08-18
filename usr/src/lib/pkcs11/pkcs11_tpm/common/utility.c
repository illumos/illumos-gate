/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
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

#include "tpmtok_int.h"

static CK_SLOT_INFO    slot_info;

// Function:  dlist_add_as_first()
//
// Adds the specified node to the start of the list
//
// Returns:  pointer to the start of the list
//
DL_NODE *
dlist_add_as_first(DL_NODE *list, void *data)
{
	DL_NODE *node = NULL;

	if (! data)
		return (list);
	node = (DL_NODE *)malloc(sizeof (DL_NODE));
	if (! node)
		return (NULL);
	node->data = data;
	node->prev = NULL;
	node->next = list;
	if (list)
		list->prev = node;

	return (node);
}


// Function:  dlist_add_as_last()
//
// Adds the specified node to the end of the list
//
// Returns:  pointer to the start of the list
//
DL_NODE *
dlist_add_as_last(DL_NODE *list, void *data) {
	DL_NODE *node = NULL;

	if (! data)
		return (list);
	node = (DL_NODE *)malloc(sizeof (DL_NODE));
	if (! node)
		return (NULL);
	node->data = data;
	node->next = NULL;

	if (! list) {
		node->prev = NULL;
		return (node);
	} else {
		DL_NODE *temp = dlist_get_last(list);
		temp->next = node;
		node->prev = temp;

		return (list);
	}
}


// Function:  dlist_find()
//
DL_NODE *
dlist_find(DL_NODE *list, void *data)
{
	DL_NODE *node = list;

	while (node && node->data != data)
	node = node->next;

	return (node);
}


// Function:  dlist_get_first()
//
// Returns the last node in the list or NULL if list is empty
//
DL_NODE *
dlist_get_first(DL_NODE *list) {
	DL_NODE *temp = list;

	if (! list)
		return (NULL);
	while (temp->prev != NULL)
	temp = temp->prev;

	return (temp);
}


// Function:  dlist_get_last()
//
// Returns the last node in the list or NULL if list is empty
//
DL_NODE *
dlist_get_last(DL_NODE *list) {
	DL_NODE *temp = list;

	if (! list)
		return (NULL);
	while (temp->next != NULL)
	temp = temp->next;

	return (temp);
}


//
//
CK_ULONG
dlist_length(DL_NODE *list) {
	DL_NODE  *temp = list;
	CK_ULONG  len  = 0;

	while (temp) {
		len++;
		temp = temp->next;
	}

	return (len);
}


//
//
DL_NODE *
dlist_next(DL_NODE *node)
{
	if (! node)
		return (NULL);
	return (node->next);
}


//
//
DL_NODE *
dlist_prev(DL_NODE *node) {
	if (! node)
		return (NULL);
	return (node->prev);
}


//
//
void
dlist_purge(DL_NODE *list) {
	DL_NODE *node;

	if (! list)
		return;
	do {
		node = list->next;
		free(list);
		list = node;
	} while (list);
}

// Function:  dlist_remove_node()
//
// Attempts to remove the specified node from the list.  The caller is
// responsible for freeing the data associated with the node prior to
// calling this routine
//
DL_NODE *
dlist_remove_node(DL_NODE *list, DL_NODE *node) {
	DL_NODE *temp  = list;

	if (! list || ! node)
		return (NULL);
	// special case:  removing head of the list
	//
	if (list == node) {
		temp = list->next;
		if (temp)
			temp->prev = NULL;

		free(list);
		return (temp);
	}

	// we have no guarantee that the node is in the list
	// so search through the list to find it
	//
	while ((temp != NULL) && (temp->next != node))
	temp = temp->next;

	if (temp != NULL) {
		DL_NODE *next = node->next;

		temp->next = next;
		if (next)
			next->prev = temp;

		free(node);
	}

	return (list);
}

extern void set_perm(int);

void
CreateXProcLock(void *xproc)
{
	pthread_mutexattr_t  mtxattr;

	(void) pthread_mutexattr_init(&mtxattr);
	(void) pthread_mutexattr_setpshared(&mtxattr, PTHREAD_PROCESS_SHARED);
	(void) pthread_mutex_init((pthread_mutex_t *)xproc, &mtxattr);
}

int
DestroyXProcLock(void *xproc)
{
	return (pthread_mutex_destroy((pthread_mutex_t *)xproc));
}

int
XProcLock(void *xproc)
{
	return (pthread_mutex_lock((pthread_mutex_t *)xproc));
}

int
XProcUnLock(void *xproc)
{
	return (pthread_mutex_unlock((pthread_mutex_t *)xproc));
}

//
//
// is_attribute_defined()
//
// determine whether the specified attribute is defined by Cryptoki
//
CK_BBOOL
is_attribute_defined(CK_ATTRIBUTE_TYPE type)
{
	if (type >= CKA_VENDOR_DEFINED)
		return (TRUE);
	switch (type) {
		case  CKA_CLASS:
		case  CKA_TOKEN:
		case  CKA_PRIVATE:
		case  CKA_LABEL:
		case  CKA_APPLICATION:
		case  CKA_VALUE:
		case  CKA_CERTIFICATE_TYPE:
		case  CKA_ISSUER:
		case  CKA_SERIAL_NUMBER:
		case  CKA_KEY_TYPE:
		case  CKA_SUBJECT:
		case  CKA_ID:
		case  CKA_SENSITIVE:
		case  CKA_ENCRYPT:
		case  CKA_DECRYPT:
		case  CKA_WRAP:
		case  CKA_UNWRAP:
		case  CKA_SIGN:
		case  CKA_SIGN_RECOVER:
		case  CKA_VERIFY:
		case  CKA_VERIFY_RECOVER:
		case  CKA_DERIVE:
		case  CKA_START_DATE:
		case  CKA_END_DATE:
		case  CKA_MODULUS:
		case  CKA_MODULUS_BITS:
		case  CKA_PUBLIC_EXPONENT:
		case  CKA_PRIVATE_EXPONENT:
		case  CKA_PRIME_1:
		case  CKA_PRIME_2:
		case  CKA_EXPONENT_1:
		case  CKA_EXPONENT_2:
		case  CKA_COEFFICIENT:
		case  CKA_PRIME:
		case  CKA_SUBPRIME:
		case  CKA_BASE:
		case  CKA_VALUE_BITS:
		case  CKA_VALUE_LEN:
		case  CKA_EXTRACTABLE:
		case  CKA_LOCAL:
		case  CKA_NEVER_EXTRACTABLE:
		case  CKA_ALWAYS_SENSITIVE:
		case  CKA_MODIFIABLE:
		case  CKA_ECDSA_PARAMS:
		case  CKA_EC_POINT:
		case  CKA_HW_FEATURE_TYPE:
		case  CKA_HAS_RESET:
		case  CKA_RESET_ON_INIT:
		case  CKA_KEY_GEN_MECHANISM:
		case  CKA_PRIME_BITS:
		case  CKA_SUBPRIME_BITS:
		case  CKA_OBJECT_ID:
		case  CKA_AC_ISSUER:
		case  CKA_OWNER:
		case  CKA_ATTR_TYPES:
		case  CKA_TRUSTED:
		return (TRUE);
	}

	return (FALSE);
}

void
init_slot_info(TOKEN_DATA *td)
{
	/*
	 * Much of the token info is pulled from the TPM itself when
	 * C_Initialize is called.
	 */
	(void) (void) memset(&slot_info.slotDescription, ' ',
	    sizeof (slot_info.slotDescription) - 1);
	(void) (void) memset(&slot_info.manufacturerID,  ' ',
	    sizeof (slot_info.manufacturerID) - 1);

	(void) (void) memcpy(&slot_info.slotDescription,
	    "PKCS#11 Interface for TPM",
	    strlen("PKCS#11 Interface for TPM"));

	(void) (void) memcpy(&slot_info.manufacturerID,
	    td->token_info.manufacturerID,
	    strlen((char *)td->token_info.manufacturerID));

	slot_info.hardwareVersion = nv_token_data->token_info.hardwareVersion;
	slot_info.firmwareVersion = nv_token_data->token_info.firmwareVersion;
	slot_info.flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
}

/*ARGSUSED*/
void
copy_slot_info(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR sinfo)
{
	if (sinfo != NULL)
		(void) memcpy(sinfo, &slot_info, sizeof (slot_info));
}

static void
init_token_info(TOKEN_DATA *td)
{
	CK_TOKEN_INFO    *token_info = NULL;

	token_info = &td->token_info;

	(void) memset(token_info->model, ' ',
	    sizeof (token_info->model));
	(void) memset(token_info->serialNumber, ' ',
	    sizeof (token_info->serialNumber));

	//
	// I don't see any API support for changing the clock so
	// we will use the system clock for the token's clock.
	//
	token_info->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_CLOCK_ON_TOKEN |
	    CKF_SO_PIN_TO_BE_CHANGED;

	if (memcmp(td->user_pin_sha, "00000000000000000000",
	    SHA1_DIGEST_LENGTH) != 0)
		token_info->flags |= CKF_USER_PIN_INITIALIZED;
	else
		token_info->flags |= CKF_USER_PIN_TO_BE_CHANGED;

	// For the release, we made these
	// values as CK_UNAVAILABLE_INFORMATION
	//
	token_info->ulMaxSessionCount    = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
	token_info->ulSessionCount	= (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
	token_info->ulMaxRwSessionCount  = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
	token_info->ulRwSessionCount	= (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
	token_info->ulMaxPinLen	  = MAX_PIN_LEN;
	token_info->ulMinPinLen	  = MIN_PIN_LEN;
	token_info->ulTotalPublicMemory  = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
	token_info->ulFreePublicMemory   = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
	token_info->ulTotalPrivateMemory = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
	token_info->ulFreePrivateMemory  = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;

	(void) memset(token_info->utcTime, ' ', sizeof (token_info->utcTime));
}

CK_RV
init_token_data(TSS_HCONTEXT hContext, TOKEN_DATA *td) {
	CK_RV rc;

	(void) memset((char *)td, 0, sizeof (nv_token_data));
	//
	// the normal USER pin is not set when the token is initialized
	//
	(void) memcpy(td->user_pin_sha, "00000000000000000000",
	    SHA1_DIGEST_LENGTH);
	(void) memcpy(td->so_pin_sha, default_so_pin_sha,
	    SHA1_DIGEST_LENGTH);

	(void) memset(user_pin_md5, 0x0, MD5_DIGEST_LENGTH);
	(void) memcpy(so_pin_md5, default_so_pin_md5, MD5_DIGEST_LENGTH);

	(void) memcpy(td->next_token_object_name, "00000000", 8);

	td->tweak_vector.allow_key_mods   = TRUE;

	init_token_info(td);

	rc = token_get_tpm_info(hContext, td);
	if (rc != CKR_OK)
		return (rc);

	rc = save_token_data(td);

	return (rc);
}

// Function:  compute_next_token_obj_name()
//
// Given a token object name (8 bytes in the range [0 - 9A - Z])
// increment by one adjusting as necessary
//
// This gives us a namespace of 36^8 = 2, 821, 109, 907, 456
// objects before wrapping around.
//
CK_RV
compute_next_token_obj_name(CK_BYTE *current, CK_BYTE *next) {
	int val[8];
	int i;

	if (! current || ! next) {
		return (CKR_FUNCTION_FAILED);
	}
	// Convert to integral base 36
	//
	for (i = 0; i < 8; i++) {
		if (current[i] >= '0' && current[i] <= '9')
			val[i] = current[i] - '0';

		if (current[i] >= 'A' && current[i] <= 'Z')
			val[i] = current[i] - 'A' + 10;
	}

	val[0]++;

	i = 0;

	while (val[i] > 35) {
		val[i] = 0;

		if (i + 1 < 8) {
			val[i + 1]++;
			i++;
		} else {
			val[0]++;
			i = 0;   // start pass 2
		}
	}

	// now, convert back to [0 - 9A - Z]
	//
	for (i = 0; i < 8; i++) {
		if (val[i] < 10)
			next[i] = '0' + val[i];
		else
			next[i] = 'A' + val[i] - 10;
	}

	return (CKR_OK);
}


//
//
CK_RV
build_attribute(CK_ATTRIBUTE_TYPE  type,
	CK_BYTE	   *data,
	CK_ULONG	   data_len,
	CK_ATTRIBUTE	**attrib) {
	CK_ATTRIBUTE *attr = NULL;

	attr = (CK_ATTRIBUTE *)malloc(sizeof (CK_ATTRIBUTE) + data_len);
	if (! attr) {
		return (CKR_DEVICE_MEMORY);
	}
	attr->type  = type;
	attr->ulValueLen = data_len;

	if (data_len > 0) {
		attr->pValue = (CK_BYTE *)attr + sizeof (CK_ATTRIBUTE);
		(void) memcpy(attr->pValue, data, data_len);
	}
	else
		attr->pValue = NULL;

	 *attrib = attr;

	return (CKR_OK);
}

CK_RV
add_pkcs_padding(CK_BYTE  * ptr,
	UINT32   block_size,
	UINT32   data_len,
	UINT32   total_len)
{
	UINT32 i, pad_len;
	CK_BYTE  pad_value;

	pad_len = block_size - (data_len % block_size);
	pad_value = (CK_BYTE)pad_len;

	if (data_len + pad_len > total_len) {
		return (CKR_FUNCTION_FAILED);
	}
	for (i = 0; i < pad_len; i++)
		ptr[i] = pad_value;

	return (CKR_OK);
}

CK_RV
strip_pkcs_padding(
	CK_BYTE *ptr,
	UINT32  total_len,
	UINT32  *data_len)
{
	CK_BYTE  pad_value;

	pad_value = ptr[total_len - 1];

	/* We have 'pad_value' bytes of 'pad_value' appended to the end */
	*data_len = total_len - pad_value;

	return (CKR_OK);
}

CK_RV
remove_leading_zeros(CK_ATTRIBUTE *attr)
{
	CK_BYTE   *ptr = NULL;
	CK_ULONG   new_len, i;

	ptr = attr->pValue;

	for (i = 0; i < attr->ulValueLen; i++) {
		if (ptr[i] != 0x0)
			break;
	}

	new_len = attr->ulValueLen - i;

	(void) memcpy(ptr, ptr + i, new_len);
	attr->ulValueLen = new_len;

	return (CKR_OK);
}

CK_RV
parity_is_odd(CK_BYTE b) {
	b = ((b >> 4) ^ b) & 0x0f;
	b = ((b >> 2) ^ b) & 0x03;
	b = ((b >> 1) ^ b) & 0x01;

	if (b == 1)
		return (TRUE);
	else
		return (FALSE);
}

CK_RV
attach_shm() {
	if (global_shm != NULL)
		return (CKR_OK);

	global_shm = (LW_SHM_TYPE *)calloc(1, sizeof (LW_SHM_TYPE));
	if (global_shm == NULL) {
		return (CKR_HOST_MEMORY);
	}
	CreateXProcLock(&global_shm->mutex);

	xproclock = (void *)&global_shm->mutex;
	(void) XProcLock(xproclock);

	(void) XProcUnLock(xproclock);

	return (CKR_OK);
}

CK_RV
detach_shm()
{
	if (global_shm != NULL) {
		free(global_shm);
		global_shm = NULL;
	}

	return (CKR_OK);
}

CK_RV
compute_sha(CK_BYTE  *data,
	CK_ULONG_32   len,
	CK_BYTE  * hash)
{
	SHA1_CTX	ctx;

	SHA1Init(&ctx);

	SHA1Update(&ctx, data, len);

	SHA1Final(hash, &ctx);
	return (CKR_OK);
}
