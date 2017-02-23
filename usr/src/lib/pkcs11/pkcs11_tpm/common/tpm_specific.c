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
/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <pthread.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <uuid/uuid.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <syslog.h>

#include <openssl/rsa.h>

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_error.h>
#include <tss/tcs_error.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>

#include "tpmtok_int.h"
#include "tpmtok_defs.h"

#define	MAX_RSA_KEYLENGTH 512

extern void stlogit(char *fmt, ...);

CK_RV token_rng(TSS_HCONTEXT, CK_BYTE *,  CK_ULONG);
int tok_slot2local(CK_SLOT_ID);
CK_RV token_specific_session(CK_SLOT_ID);
CK_RV token_specific_final(TSS_HCONTEXT);

CK_RV
token_specific_rsa_decrypt(
	TSS_HCONTEXT,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG *,
	OBJECT *);

CK_RV
token_specific_rsa_encrypt(
	TSS_HCONTEXT,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG *,
	OBJECT *);

CK_RV
token_specific_rsa_sign(
	TSS_HCONTEXT,
	CK_BYTE *,
	CK_ULONG,
	CK_BYTE *,
	CK_ULONG *,
	OBJECT *);

CK_RV
token_specific_rsa_verify(TSS_HCONTEXT, CK_BYTE *,
    CK_ULONG, CK_BYTE *, CK_ULONG, OBJECT *);

CK_RV
token_specific_rsa_generate_keypair(TSS_HCONTEXT,
	TEMPLATE *,
	TEMPLATE *);

CK_RV
token_specific_sha_init(DIGEST_CONTEXT *);

CK_RV
token_specific_sha_update(DIGEST_CONTEXT *,
	CK_BYTE *,
	CK_ULONG);

CK_RV
token_specific_sha_final(DIGEST_CONTEXT *,
	CK_BYTE *,
	CK_ULONG *);

CK_RV token_specific_login(TSS_HCONTEXT, CK_USER_TYPE, CK_CHAR_PTR, CK_ULONG);
CK_RV token_specific_logout(TSS_HCONTEXT);
CK_RV token_specific_init_pin(TSS_HCONTEXT, CK_CHAR_PTR, CK_ULONG);
CK_RV token_specific_set_pin(ST_SESSION_HANDLE, CK_CHAR_PTR,
	CK_ULONG, CK_CHAR_PTR, CK_ULONG);
CK_RV token_specific_verify_so_pin(TSS_HCONTEXT, CK_CHAR_PTR, CK_ULONG);

static CK_RV
token_specific_init(char *, CK_SLOT_ID, TSS_HCONTEXT *);

struct token_specific_struct token_specific = {
	"TPM_Debug",
	&token_specific_init,
	NULL,
	&token_rng,
	&token_specific_session,
	&token_specific_final,
	&token_specific_rsa_decrypt,
	&token_specific_rsa_encrypt,
	&token_specific_rsa_sign,
	&token_specific_rsa_verify,
	&token_specific_rsa_generate_keypair,
	NULL,
	NULL,
	NULL,
	&token_specific_login,
	&token_specific_logout,
	&token_specific_init_pin,
	&token_specific_set_pin,
	&token_specific_verify_so_pin
};

/* The context we'll use globally to connect to the TSP */

/* TSP key handles */
TSS_HKEY hPublicRootKey = NULL_HKEY;
TSS_HKEY hPublicLeafKey = NULL_HKEY;
TSS_HKEY hPrivateRootKey = NULL_HKEY;
TSS_HKEY hPrivateLeafKey = NULL_HKEY;

TSS_UUID publicRootKeyUUID;
TSS_UUID publicLeafKeyUUID;
TSS_UUID privateRootKeyUUID;
TSS_UUID privateLeafKeyUUID;

/* TSP policy handles */
TSS_HPOLICY hDefaultPolicy = NULL_HPOLICY;

/* PKCS#11 key handles */
int not_initialized = 0;

CK_BYTE current_user_pin_sha[SHA1_DIGEST_LENGTH];
CK_BYTE current_so_pin_sha[SHA1_DIGEST_LENGTH];

static TPM_CAP_VERSION_INFO tpmvinfo;

static CK_RV
verify_user_pin(TSS_HCONTEXT, CK_BYTE *);

static TSS_RESULT
tss_assign_secret_key_policy(TSS_HCONTEXT, TSS_FLAG, TSS_HKEY, CK_CHAR *);

static TSS_RESULT
set_legacy_key_params(TSS_HKEY);

static void
local_uuid_clear(TSS_UUID *uuid)
{
	if (uuid == NULL)
		return;
	(void) memset(uuid, 0, sizeof (TSS_UUID));
}


/* convert from TSS_UUID to uuid_t */
static void
tss_uuid_convert_from(TSS_UUID *uu, uuid_t ptr)
{
	uint_t		tmp;
	uchar_t		*out = ptr;

	tmp = ntohl(uu->ulTimeLow);
	out[3] = (uchar_t)tmp;
	tmp >>= 8;
	out[2] = (uchar_t)tmp;
	tmp >>= 8;
	out[1] = (uchar_t)tmp;
	tmp >>= 8;
	out[0] = (uchar_t)tmp;

	tmp = ntohs(uu->usTimeMid);
	out[5] = (uchar_t)tmp;
	tmp >>= 8;
	out[4] = (uchar_t)tmp;

	tmp = ntohs(uu->usTimeHigh);
	out[7] = (uchar_t)tmp;
	tmp >>= 8;
	out[6] = (uchar_t)tmp;

	tmp = uu->bClockSeqHigh;
	out[8] = (uchar_t)tmp;
	tmp = uu->bClockSeqLow;
	out[9] = (uchar_t)tmp;

	(void) memcpy(out+10, uu->rgbNode, 6);
}

/* convert from uuid_t to TSS_UUID */
static void
tss_uuid_convert_to(TSS_UUID *uuid, uuid_t in)
{
	uchar_t		*ptr;
	uint32_t	ltmp;
	uint16_t	stmp;

	ptr = in;

	ltmp = *ptr++;
	ltmp = (ltmp << 8) | *ptr++;
	ltmp = (ltmp << 8) | *ptr++;
	ltmp = (ltmp << 8) | *ptr++;
	uuid->ulTimeLow = ntohl(ltmp);

	stmp = *ptr++;
	stmp = (stmp << 8) | *ptr++;
	uuid->usTimeMid = ntohs(stmp);

	stmp = *ptr++;
	stmp = (stmp << 8) | *ptr++;
	uuid->usTimeHigh = ntohs(stmp);

	uuid->bClockSeqHigh = *ptr++;

	uuid->bClockSeqLow = *ptr++;

	(void) memcpy(uuid->rgbNode, ptr, 6);
}

static void
local_uuid_copy(TSS_UUID *dst, TSS_UUID *src)
{
	uuid_t udst, usrc;

	tss_uuid_convert_from(dst, udst);
	tss_uuid_convert_from(src, usrc);

	uuid_copy(udst, usrc);

	tss_uuid_convert_to(dst, udst);
}

static void
local_uuid_generate(TSS_UUID *uu)
{
	uuid_t newuuid;

	uuid_generate(newuuid);

	tss_uuid_convert_to(uu, newuuid);
}

static int
local_copy_file(char *dst, char *src)
{
	FILE *fdest, *fsrc;
	char line[BUFSIZ];

	fdest = fopen(dst, "w");
	if (fdest == NULL)
		return (-1);

	fsrc = fopen(src, "r");
	if (fsrc == NULL) {
		(void) fclose(fdest);
		return (-1);
	}

	while (fread(line, sizeof (line), 1, fsrc))
		(void) fprintf(fdest, "%s\n", line);
	(void) fclose(fsrc);
	(void) fclose(fdest);
	return (0);
}

static int
remove_uuid(char *keyname)
{
	int ret = 0;
	FILE *fp, *newfp;
	char fname[MAXPATHLEN];
	char line[BUFSIZ], key[BUFSIZ], idstr[BUFSIZ];
	char *tmpfname;
	char *p = get_tpm_keystore_path();

	if (p == NULL)
		return (-1);

	(void) snprintf(fname, sizeof (fname),
	    "%s/%s", p, TPMTOK_UUID_INDEX_FILENAME);

	fp = fopen(fname, "r");
	if (fp == NULL) {
		return (-1);
	}

	tmpfname = tempnam("/tmp", "tpmtok");
	newfp = fopen(tmpfname, "w+");
	if (newfp == NULL) {
		free(tmpfname);
		(void) fclose(fp);
		return (-1);
	}

	while (!feof(fp)) {
		(void) fgets(line, sizeof (line), fp);
		if (sscanf(line, "%1024s %1024s", key, idstr) == 2) {
			if (strcmp(key, keyname))
				(void) fprintf(newfp, "%s\n", line);
		}
	}

	(void) fclose(fp);
	(void) fclose(newfp);
	if (local_copy_file(fname, tmpfname) == 0)
		(void) unlink(tmpfname);

	free(tmpfname);

	return (ret);
}

static int
find_uuid(char *keyname, TSS_UUID *uu)
{
	int ret = 0, found = 0;
	FILE *fp = NULL;
	char fname[MAXPATHLEN];
	char line[BUFSIZ], key[BUFSIZ], idstr[BUFSIZ];
	uuid_t uuid;
	char *p = get_tpm_keystore_path();

	if (p == NULL)
		return (-1);

	tss_uuid_convert_from(uu, uuid);

	(void) snprintf(fname, sizeof (fname),
	    "%s/%s", p, TPMTOK_UUID_INDEX_FILENAME);

	/* Open UUID Index file */
	fp = fopen(fname, "r");
	if (fp == NULL) {
		if (errno == ENOENT) {
			/* initialize the file */
			fp = fopen(fname, "w");
			if (fp != NULL)
				(void) fclose(fp);
		}
		return (-1);
	}

	while (!feof(fp)) {
		(void) fgets(line, sizeof (line), fp);
		if (sscanf(line, "%1024s %1024s", key, idstr) == 2) {
			if (strcmp(key, keyname) == 0) {
				ret = uuid_parse(idstr, uuid);
				if (ret == 0) {
					found = 1;
					tss_uuid_convert_to(uu,
					    uuid);
				}
				break;
			}
		}
	}
	(void) fclose(fp);

	if (!found)
		ret = -1;
	return (ret);
}

static int
local_uuid_is_null(TSS_UUID *uu)
{
	uuid_t uuid;
	int nulluuid;

	tss_uuid_convert_from(uu, uuid);

	nulluuid = uuid_is_null(uuid);
	return (nulluuid);
}

static int
add_uuid(char *keyname, TSS_UUID *uu)
{
	FILE *fp = NULL;
	char fname[MAXPATHLEN];
	char idstr[BUFSIZ];
	uuid_t uuid;
	char *p = get_tpm_keystore_path();

	if (p == NULL)
		return (-1);

	tss_uuid_convert_from(uu, uuid);

	if (uuid_is_null(uuid))
		return (-1);

	uuid_unparse(uuid, idstr);

	(void) snprintf(fname, sizeof (fname),
	    "%s/%s", p, TPMTOK_UUID_INDEX_FILENAME);

	fp = fopen(fname, "a");
	if (fp == NULL)
		return (-1);

	(void) fprintf(fp, "%s %s\n", keyname, idstr);
	(void) fclose(fp);

	return (0);
}


static UINT32
util_get_keysize_flag(CK_ULONG size)
{
	switch (size) {
		case 512:
			return (TSS_KEY_SIZE_512);
		case 1024:
			return (TSS_KEY_SIZE_1024);
		case 2048:
			return (TSS_KEY_SIZE_2048);
		default:
			break;
	}

	return (0);
}

/* make sure the public exponent attribute is 65537 */
static CK_ULONG
util_check_public_exponent(TEMPLATE *tmpl)
{
	CK_BBOOL flag;
	CK_ATTRIBUTE *publ_exp_attr;
	CK_BYTE pubexp_bytes[] = { 1, 0, 1 };
	CK_ULONG publ_exp, rc = 1;

	flag = template_attribute_find(tmpl, CKA_PUBLIC_EXPONENT,
	    &publ_exp_attr);
	if (!flag) {
		LogError1("Couldn't find public exponent attribute");
		return (CKR_TEMPLATE_INCOMPLETE);
	}

	switch (publ_exp_attr->ulValueLen) {
		case 3:
			rc = memcmp(pubexp_bytes, publ_exp_attr->pValue, 3);
			break;
		case sizeof (CK_ULONG):
			publ_exp = *((CK_ULONG *)publ_exp_attr->pValue);
			if (publ_exp == 65537)
				rc = 0;
			break;
		default:
			break;
	}

	return (rc);
}

TSS_RESULT
set_public_modulus(TSS_HCONTEXT hContext, TSS_HKEY hKey,
	unsigned long size_n, unsigned char *n)
{
	UINT64 offset;
	UINT32 blob_size;
	BYTE *blob, pub_blob[1024];
	TCPA_PUBKEY pub_key;
	TSS_RESULT result;

	/* Get the TCPA_PUBKEY blob from the key object. */
	result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
	    TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, &blob_size, &blob);
	if (result != TSS_SUCCESS) {
		stlogit("Tspi_GetAttribData failed: rc=0x%0x - %s\n",
		    result, Trspi_Error_String(result));
		return (result);
	}

	offset = 0;
	result = Trspi_UnloadBlob_PUBKEY(&offset, blob, &pub_key);
	if (result != TSS_SUCCESS) {
		stlogit("Trspi_UnloadBlob_PUBKEY failed: rc=0x%0x - %s\n",
		    result, Trspi_Error_String(result));
		return (result);
	}

	Tspi_Context_FreeMemory(hContext, blob);
	/* Free the first dangling reference, putting 'n' in its place */
	free(pub_key.pubKey.key);
	pub_key.pubKey.keyLength = size_n;
	pub_key.pubKey.key = n;

	offset = 0;
	Trspi_LoadBlob_PUBKEY(&offset, pub_blob, &pub_key);

	/* Free the second dangling reference */
	free(pub_key.algorithmParms.parms);

	/* set the public key data in the TSS object */
	result = Tspi_SetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
	    TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, (UINT32)offset, pub_blob);
	if (result != TSS_SUCCESS) {
		stlogit("Tspi_SetAttribData failed: rc=0x%0x - %s\n",
		    result, Trspi_Error_String(result));
		return (result);
	}

	return (result);
}

/*
 * Get details about the TPM to put into the token_info structure.
 */
CK_RV
token_get_tpm_info(TSS_HCONTEXT hContext, TOKEN_DATA *td)
{
	TSS_RESULT result;
	TPM_CAPABILITY_AREA capArea = TSS_TPMCAP_VERSION_VAL;
	UINT32 datalen;
	BYTE *data;
	TSS_HTPM hTPM;

	if ((result = Tspi_Context_GetTpmObject(hContext, &hTPM))) {
		stlogit("Tspi_Context_GetTpmObject: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}
	if ((result = Tspi_TPM_GetCapability(hTPM,
	    capArea, 0, NULL, &datalen, &data)) != 0 || datalen == 0 ||
	    data == NULL) {
		stlogit("Tspi_Context_GetCapability: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}
	if (datalen > sizeof (tpmvinfo)) {
		Tspi_Context_FreeMemory(hContext, data);
		return (CKR_FUNCTION_FAILED);
	}

	(void) memcpy(&tpmvinfo, (void *)data, datalen);

	bzero(td->token_info.manufacturerID,
	    sizeof (td->token_info.manufacturerID));

	(void) memset(td->token_info.manufacturerID,  ' ',
	    sizeof (td->token_info.manufacturerID) - 1);

	(void) memcpy(td->token_info.manufacturerID,
	    tpmvinfo.tpmVendorID, sizeof (tpmvinfo.tpmVendorID));

	(void) memset(td->token_info.label, ' ',
	    sizeof (td->token_info.label) - 1);

	(void) memcpy(td->token_info.label, "TPM", 3);

	td->token_info.hardwareVersion.major = tpmvinfo.version.major;
	td->token_info.hardwareVersion.minor = tpmvinfo.version.minor;
	td->token_info.firmwareVersion.major = tpmvinfo.version.revMajor;
	td->token_info.firmwareVersion.minor = tpmvinfo.version.revMinor;

	Tspi_Context_FreeMemory(hContext, data);
	return (CKR_OK);
}

/*ARGSUSED*/
CK_RV
token_specific_session(CK_SLOT_ID  slotid)
{
	return (CKR_OK);
}

CK_RV
token_rng(TSS_HCONTEXT hContext, CK_BYTE *output, CK_ULONG bytes)
{
	TSS_RESULT rc;
	TSS_HTPM hTPM;
	BYTE *random_bytes = NULL;

	if ((rc = Tspi_Context_GetTpmObject(hContext, &hTPM))) {
		stlogit("Tspi_Context_GetTpmObject: 0x%0x - %s",
		    rc, Trspi_Error_String(rc));
		return (CKR_FUNCTION_FAILED);
	}

	if ((rc = Tspi_TPM_GetRandom(hTPM, bytes, &random_bytes))) {
		stlogit("Tspi_TPM_GetRandom: 0x%0x - %s",
		    rc, Trspi_Error_String(rc));
		return (CKR_FUNCTION_FAILED);
	}

	(void) memcpy(output, random_bytes, bytes);
	Tspi_Context_FreeMemory(hContext, random_bytes);

	return (CKR_OK);
}

TSS_RESULT
open_tss_context(TSS_HCONTEXT *pContext)
{
	TSS_RESULT result;

	if ((result = Tspi_Context_Create(pContext))) {
		stlogit("Tspi_Context_Create: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}

	if ((result = Tspi_Context_Connect(*pContext, NULL))) {
		stlogit("Tspi_Context_Connect: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		Tspi_Context_Close(*pContext);
		*pContext = 0;
		return (CKR_FUNCTION_FAILED);
	}
	return (result);
}

/*ARGSUSED*/
static CK_RV
token_specific_init(char *Correlator, CK_SLOT_ID SlotNumber,
    TSS_HCONTEXT *hContext)
{
	TSS_RESULT result;

	result = open_tss_context(hContext);
	if (result)
		return (CKR_FUNCTION_FAILED);

	if ((result = Tspi_Context_GetDefaultPolicy(*hContext,
	    &hDefaultPolicy))) {
		stlogit("Tspi_Context_GetDefaultPolicy: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}

	local_uuid_clear(&publicRootKeyUUID);
	local_uuid_clear(&privateRootKeyUUID);
	local_uuid_clear(&publicLeafKeyUUID);
	local_uuid_clear(&privateLeafKeyUUID);

	result = token_get_tpm_info(*hContext, nv_token_data);
	return (result);
}

/*
 * Given a modulus and prime from an RSA key, create a TSS_HKEY object by
 * wrapping the RSA key with a key from the TPM (SRK or other previously stored
 * key).
 */
static CK_RV
token_wrap_sw_key(
	TSS_HCONTEXT hContext,
	int size_n,
	unsigned char *n,
	int size_p,
	unsigned char *p,
	TSS_HKEY hParentKey,
	TSS_FLAG initFlags,
	TSS_HKEY *phKey)
{
	TSS_RESULT result;
	UINT32 key_size;

	key_size = util_get_keysize_flag(size_n * 8);
	if (initFlags == 0) {
		return (CKR_FUNCTION_FAILED);
	}

	/* create the TSS key object */
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
	    TSS_KEY_MIGRATABLE | initFlags | key_size, phKey);
	if (result != TSS_SUCCESS) {
		stlogit("Tspi_Context_CreateObject: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}

	result = set_public_modulus(hContext, *phKey, size_n, n);
	if (result != TSS_SUCCESS) {
		Tspi_Context_CloseObject(hContext, *phKey);
		*phKey = NULL_HKEY;
		return (CKR_FUNCTION_FAILED);
	}

	/* set the private key data in the TSS object */
	result = Tspi_SetAttribData(*phKey, TSS_TSPATTRIB_KEY_BLOB,
	    TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY, size_p, p);
	if (result != TSS_SUCCESS) {
		stlogit("Tspi_SetAttribData: 0x%x - %s",
		    result, Trspi_Error_String(result));
		Tspi_Context_CloseObject(hContext, *phKey);
		*phKey = NULL_HKEY;
		return (CKR_FUNCTION_FAILED);
	}

	result = tss_assign_secret_key_policy(hContext, TSS_POLICY_MIGRATION,
	    *phKey, NULL);

	if (TPMTOK_TSS_KEY_TYPE(initFlags) == TSS_KEY_TYPE_LEGACY) {
		if ((result = Tspi_SetAttribUint32(*phKey,
		    TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
		    TSS_ES_RSAESPKCSV15))) {
			stlogit("Tspi_SetAttribUint32: 0x%0x - %s\n",
			    result, Trspi_Error_String(result));
			Tspi_Context_CloseObject(hContext, *phKey);
			return (CKR_FUNCTION_FAILED);
		}

		if ((result = Tspi_SetAttribUint32(*phKey,
		    TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
		    TSS_SS_RSASSAPKCS1V15_DER))) {
			stlogit("Tspi_SetAttribUint32: 0x%0x - %s\n",
			    result, Trspi_Error_String(result));
			Tspi_Context_CloseObject(hContext, *phKey);
			return (CKR_FUNCTION_FAILED);
		}
	}

	result = Tspi_Key_WrapKey(*phKey, hParentKey, NULL_HPCRS);
	if (result != TSS_SUCCESS) {
		stlogit("Tspi_Key_WrapKey: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		Tspi_Context_CloseObject(hContext, *phKey);
		*phKey = NULL_HKEY;
		return (CKR_FUNCTION_FAILED);
	}

	return (CKR_OK);
}

/*
 * Create a TPM key blob for an imported key. This function is only called when
 * a key is in active use, so any failure should trickle through.
 */
static CK_RV
token_wrap_key_object(TSS_HCONTEXT hContext,
	CK_OBJECT_HANDLE ckObject,
	TSS_HKEY hParentKey, TSS_HKEY *phKey)
{
	CK_RV		rc = CKR_OK;
	CK_ATTRIBUTE	*attr = NULL, *new_attr, *prime_attr;
	CK_ULONG	class, key_type;
	OBJECT		*obj;

	TSS_RESULT	result;
	TSS_FLAG	initFlags = 0;
	BYTE		*rgbBlob;
	UINT32		ulBlobLen;

	if ((rc = object_mgr_find_in_map1(hContext, ckObject, &obj))) {
		return (rc);
	}

	/* if the object isn't a key, fail */
	if (template_attribute_find(obj->template, CKA_KEY_TYPE,
	    &attr) == FALSE) {
		return (CKR_TEMPLATE_INCOMPLETE);
	}

	key_type = *((CK_ULONG *)attr->pValue);

	if (key_type != CKK_RSA) {
		return (CKR_TEMPLATE_INCONSISTENT);
	}

	if (template_attribute_find(obj->template, CKA_CLASS,
	    &attr) == FALSE) {
		return (CKR_TEMPLATE_INCOMPLETE);
	}

	class = *((CK_ULONG *)attr->pValue);

	if (class == CKO_PRIVATE_KEY) {
		/*
		 * In order to create a full TSS key blob using a PKCS#11
		 * private key object, we need one of the two primes, the
		 * modulus and the private exponent and we need the public
		 * exponent to be correct.
		 */

		/*
		 * Check the least likely attribute to exist first, the
		 * primes.
		 */
		if (template_attribute_find(obj->template, CKA_PRIME_1,
		    &prime_attr) == FALSE) {
			if (template_attribute_find(obj->template,
			    CKA_PRIME_2, &prime_attr) == FALSE) {
				return (CKR_TEMPLATE_INCOMPLETE);
			}
		}

		/* Make sure the public exponent is usable */
		if ((rc = util_check_public_exponent(obj->template))) {
			return (CKR_TEMPLATE_INCONSISTENT);
		}

		/* get the modulus */
		if (template_attribute_find(obj->template, CKA_MODULUS,
		    &attr) == FALSE) {
			return (CKR_TEMPLATE_INCOMPLETE);
		}

		/* make sure the key size is usable */
		initFlags = util_get_keysize_flag(attr->ulValueLen * 8);
		if (initFlags == 0) {
			return (CKR_TEMPLATE_INCONSISTENT);
		}

		/* generate the software based key */
		if ((rc = token_wrap_sw_key(hContext,
		    (int)attr->ulValueLen, attr->pValue,
		    (int)prime_attr->ulValueLen, prime_attr->pValue,
		    hParentKey, TSS_KEY_TYPE_LEGACY | TSS_KEY_NO_AUTHORIZATION,
		    phKey))) {
			return (rc);
		}
	} else if (class == CKO_PUBLIC_KEY) {
		/* Make sure the public exponent is usable */
		if ((util_check_public_exponent(obj->template))) {
			return (CKR_TEMPLATE_INCONSISTENT);
		}

		/* grab the modulus to put into the TSS key object */
		if (template_attribute_find(obj->template,
		    CKA_MODULUS, &attr) == FALSE) {
			return (CKR_TEMPLATE_INCONSISTENT);
		}

		/* make sure the key size is usable */
		initFlags = util_get_keysize_flag(attr->ulValueLen * 8);
		if (initFlags == 0) {
			return (CKR_TEMPLATE_INCONSISTENT);
		}

		initFlags |= TSS_KEY_MIGRATABLE | TSS_KEY_NO_AUTHORIZATION |
		    TSS_KEY_TYPE_LEGACY;

		if ((result = Tspi_Context_CreateObject(hContext,
		    TSS_OBJECT_TYPE_RSAKEY, initFlags, phKey))) {
			stlogit("Tspi_Context_CreateObject: 0x%0x - %s",
			    result, Trspi_Error_String(result));
			return (result);
		}

		if ((result = set_public_modulus(hContext, *phKey,
		    attr->ulValueLen, attr->pValue))) {
			Tspi_Context_CloseObject(hContext, *phKey);
			*phKey = NULL_HKEY;
			return (CKR_FUNCTION_FAILED);
		}
		result = tss_assign_secret_key_policy(hContext,
		    TSS_POLICY_MIGRATION, *phKey, NULL);
		if (result) {
			Tspi_Context_CloseObject(hContext, *phKey);
			*phKey = NULL_HKEY;
			return (CKR_FUNCTION_FAILED);
		}

		result = set_legacy_key_params(*phKey);
		if (result) {
			Tspi_Context_CloseObject(hContext, *phKey);
			*phKey = NULL_HKEY;
			return (CKR_FUNCTION_FAILED);
		}
	} else {
		return (CKR_FUNCTION_FAILED);
	}

	/* grab the entire key blob to put into the PKCS#11 object */
	if ((result = Tspi_GetAttribData(*phKey, TSS_TSPATTRIB_KEY_BLOB,
	    TSS_TSPATTRIB_KEYBLOB_BLOB, &ulBlobLen, &rgbBlob))) {
		stlogit("Tspi_GetAttribData: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}

	/* insert the key blob into the object */
	if ((rc = build_attribute(CKA_IBM_OPAQUE, rgbBlob, ulBlobLen,
	    &new_attr))) {
		Tspi_Context_FreeMemory(hContext, rgbBlob);
		return (rc);
	}
	(void) template_update_attribute(obj->template, new_attr);
	Tspi_Context_FreeMemory(hContext, rgbBlob);

	/*
	 * If this is a token object, save it with the new attribute
	 * so that we don't have to go down this path again.
	 */
	if (!object_is_session_object(obj)) {
		rc = save_token_object(hContext, obj);
	}

	return (rc);
}

static TSS_RESULT
tss_assign_secret_key_policy(TSS_HCONTEXT hContext, TSS_FLAG policyType,
    TSS_HKEY hKey, CK_CHAR *passHash)
{
	TSS_RESULT result;
	TSS_HPOLICY hPolicy;

	if ((result = Tspi_Context_CreateObject(hContext,
	    TSS_OBJECT_TYPE_POLICY, policyType, &hPolicy))) {
		stlogit("Tspi_Context_CreateObject: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (result);
	}
	if ((result = Tspi_Policy_AssignToObject(hPolicy, hKey))) {
		stlogit("Tspi_Policy_AssignToObject: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		goto done;
	}
	if (passHash == NULL) {
		result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_NONE,
		    0, NULL);
	} else {
		result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1,
		    SHA1_DIGEST_LENGTH, passHash);
	}
	if (result != TSS_SUCCESS) {
		stlogit("Tspi_Policy_SetSecret: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		goto done;
	}
done:
	if (result != TSS_SUCCESS)
		Tspi_Context_CloseObject(hContext, hPolicy);
	return (result);
}

/*
 * Take a key from the TSS store (on-disk) and load it into the TPM, wrapped
 * by an already TPM-resident key and protected with a PIN (optional).
 */
static CK_RV
token_load_key(
	TSS_HCONTEXT hContext,
	CK_OBJECT_HANDLE ckKey,
	TSS_HKEY hParentKey,
	CK_CHAR_PTR passHash,
	TSS_HKEY *phKey)
{
	TSS_RESULT result;
	CK_RV rc;

	/*
	 * The key blob wasn't found, load the parts of the key
	 * from the object DB and create a new key object that
	 * gets loaded into the TPM, wrapped with the parent key.
	 */
	if ((rc = token_wrap_key_object(hContext, ckKey,
	    hParentKey, phKey))) {
		return (rc);
	}

	/*
	 * Assign the PIN hash (optional) to the newly loaded key object,
	 * if this PIN is incorrect, the TPM will not be able to decrypt
	 * the private key and use it.
	 */
	result = tss_assign_secret_key_policy(hContext, TSS_POLICY_USAGE,
	    *phKey, passHash);

	return (result);
}

/*
 * Load the SRK into the TPM by referencing its well-known UUID and using the
 * default SRK PIN (20 bytes of 0x00).
 *
 * NOTE - if the SRK PIN is changed by an administrative tool, this code will
 * fail because it assumes that the well-known PIN is still being used.
 */
static TSS_RESULT
token_load_srk(TSS_HCONTEXT hContext, TSS_HKEY *hSRK)
{
	TSS_HPOLICY hPolicy;
	TSS_RESULT result;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;
	BYTE wellKnown[] = TSS_WELL_KNOWN_SECRET;
	TSS_HTPM hTPM;

	if ((result = Tspi_Context_GetTpmObject(hContext, &hTPM))) {
		stlogit("Tspi_Context_GetTpmObject: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}

	/* load the SRK */
	if ((result = Tspi_Context_LoadKeyByUUID(hContext,
	    TSS_PS_TYPE_SYSTEM, SRK_UUID, hSRK))) {
		stlogit("Tspi_Context_LoadKeyByUUID: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		goto done;
	}
	if ((result = Tspi_GetPolicyObject(*hSRK, TSS_POLICY_USAGE,
	    &hPolicy))) {
		stlogit("Tspi_GetPolicyObject: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		goto done;
	}
	if ((result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1,
	    sizeof (wellKnown), wellKnown))) {
		stlogit("Tspi_Policy_SetSecret: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		goto done;
	}

done:
	return (result);
}

static TSS_RESULT
tss_find_and_load_key(TSS_HCONTEXT hContext,
	char *keyid, TSS_UUID *uuid, TSS_HKEY hParent,
	BYTE *hash, TSS_HKEY *hKey)
{
	TSS_RESULT result;

	if (local_uuid_is_null(uuid) &&
	    find_uuid(keyid, uuid)) {
		/* The UUID was not created or saved yet */
		return (1);
	}
	result = Tspi_Context_GetKeyByUUID(hContext,
	    TSS_PS_TYPE_USER, *uuid, hKey);
	if (result) {
		stlogit("Tspi_Context_GetKeyByUUID: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (result);
	}

	if (hash != NULL) {
		result = tss_assign_secret_key_policy(hContext,
		    TSS_POLICY_USAGE, *hKey, (CK_BYTE *)hash);
		if (result)
			return (result);
	}

	result = Tspi_Key_LoadKey(*hKey, hParent);
	if (result)
		stlogit("Tspi_Key_LoadKey: 0x%0x - %s",
		    result, Trspi_Error_String(result));

	return (result);
}

static TSS_RESULT
token_load_public_root_key(TSS_HCONTEXT hContext)
{
	TSS_RESULT result;
	TSS_HKEY hSRK;

	if (hPublicRootKey != NULL_HKEY)
		return (TSS_SUCCESS);

	if ((result = token_load_srk(hContext, &hSRK))) {
		return (result);
	}

	result = tss_find_and_load_key(hContext,
	    TPMTOK_PUBLIC_ROOT_KEY_ID,
	    &publicRootKeyUUID, hSRK, NULL, &hPublicRootKey);
	if (result)
		return (result);

	return (result);
}

static TSS_RESULT
set_legacy_key_params(TSS_HKEY hKey)
{
	TSS_RESULT result;

	if ((result = Tspi_SetAttribUint32(hKey,
	    TSS_TSPATTRIB_KEY_INFO,
	    TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
	    TSS_ES_RSAESPKCSV15))) {
		stlogit("Tspi_SetAttribUint32: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (result);
	}

	if ((result = Tspi_SetAttribUint32(hKey,
	    TSS_TSPATTRIB_KEY_INFO,
	    TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
	    TSS_SS_RSASSAPKCS1V15_DER))) {
		stlogit("Tspi_SetAttribUint32: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (result);
	}

	return (result);
}

static TSS_RESULT
tss_generate_key(TSS_HCONTEXT hContext, TSS_FLAG initFlags, BYTE *passHash,
	TSS_HKEY hParentKey, TSS_HKEY *phKey)
{
	TSS_RESULT	result;
	TSS_HPOLICY	hMigPolicy;

	if ((result = Tspi_Context_CreateObject(hContext,
	    TSS_OBJECT_TYPE_RSAKEY, initFlags, phKey))) {
		stlogit("Tspi_Context_CreateObject: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (result);
	}
	result = tss_assign_secret_key_policy(hContext, TSS_POLICY_USAGE,
	    *phKey, passHash);

	if (result) {
		Tspi_Context_CloseObject(hContext, *phKey);
		return (result);
	}

	if (TPMTOK_TSS_KEY_MIG_TYPE(initFlags) == TSS_KEY_MIGRATABLE) {
		if ((result = Tspi_Context_CreateObject(hContext,
		    TSS_OBJECT_TYPE_POLICY, TSS_POLICY_MIGRATION,
		    &hMigPolicy))) {
			stlogit("Tspi_Context_CreateObject: 0x%0x - %s",
			    result, Trspi_Error_String(result));
			Tspi_Context_CloseObject(hContext, *phKey);
			return (result);
		}

		if (passHash == NULL) {
			result = Tspi_Policy_SetSecret(hMigPolicy,
			    TSS_SECRET_MODE_NONE, 0, NULL);
		} else {
			result = Tspi_Policy_SetSecret(hMigPolicy,
			    TSS_SECRET_MODE_SHA1, 20, passHash);
		}

		if (result != TSS_SUCCESS) {
			stlogit("Tspi_Policy_SetSecret: 0x%0x - %s",
			    result, Trspi_Error_String(result));
			Tspi_Context_CloseObject(hContext, *phKey);
			Tspi_Context_CloseObject(hContext, hMigPolicy);
			return (result);
		}

		if ((result = Tspi_Policy_AssignToObject(hMigPolicy, *phKey))) {
			stlogit("Tspi_Policy_AssignToObject: 0x%0x - %s",
			    result, Trspi_Error_String(result));
			Tspi_Context_CloseObject(hContext, *phKey);
			Tspi_Context_CloseObject(hContext, hMigPolicy);
			return (result);
		}
	}

	if (TPMTOK_TSS_KEY_TYPE(initFlags) == TSS_KEY_TYPE_LEGACY) {
		result = set_legacy_key_params(*phKey);
		if (result) {
			Tspi_Context_CloseObject(hContext, *phKey);
			Tspi_Context_CloseObject(hContext, hMigPolicy);
			return (result);
		}
	}

	if ((result = Tspi_Key_CreateKey(*phKey, hParentKey, 0))) {
		stlogit("Tspi_Key_CreateKey: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		Tspi_Context_CloseObject(hContext, *phKey);
		Tspi_Context_CloseObject(hContext, hMigPolicy);
	}

	return (result);
}

static TSS_RESULT
tss_change_auth(
	TSS_HCONTEXT hContext,
	TSS_HKEY hObjectToChange, TSS_HKEY hParentObject,
	TSS_UUID objUUID, TSS_UUID parentUUID,
	CK_CHAR *passHash)
{
	TSS_RESULT result;
	TSS_HPOLICY hPolicy;
	TSS_HKEY oldkey;

	if ((result = Tspi_Context_CreateObject(hContext,
	    TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hPolicy))) {
		stlogit("Tspi_Context_CreateObject: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (result);
	}

	if ((result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1,
	    SHA1_DIGEST_LENGTH, passHash))) {
		stlogit("Tspi_Policy_SetSecret: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (result);
	}

	if ((result = Tspi_ChangeAuth(hObjectToChange, hParentObject,
	    hPolicy))) {
		stlogit("Tspi_ChangeAuth: 0x%0x - %s",
		    result, Trspi_Error_String(result));
	}
	/*
	 * Update the PS key by unregistering the key UUID and then
	 * re-registering with the same UUID.  This forces the updated
	 * auth data associated with the key to be stored in PS so
	 * the new PIN can be used next time.
	 */
	if ((result = Tspi_Context_UnregisterKey(hContext,
	    TSS_PS_TYPE_USER, objUUID, &oldkey)))
		stlogit("Tspi_Context_UnregisterKey: 0x%0x - %s",
		    result, Trspi_Error_String(result));

	if ((result = Tspi_Context_RegisterKey(hContext, hObjectToChange,
	    TSS_PS_TYPE_USER, objUUID, TSS_PS_TYPE_USER, parentUUID)))
		stlogit("Tspi_Context_RegisterKey: 0x%0x - %s",
		    result, Trspi_Error_String(result));

	return (result);
}

static CK_RV
token_generate_leaf_key(TSS_HCONTEXT hContext,
	int key_type, CK_CHAR_PTR passHash, TSS_HKEY *phKey)
{
	CK_RV		rc = CKR_FUNCTION_FAILED;
	TSS_RESULT	result;
	TSS_HKEY	hParentKey;
	TSS_UUID	newuuid, parentUUID;
	char		*keyid;
	TSS_FLAG	initFlags = TSS_KEY_MIGRATABLE |
	    TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048  | TSS_KEY_AUTHORIZATION;

	switch (key_type) {
		case TPMTOK_PUBLIC_LEAF_KEY:
			hParentKey = hPublicRootKey;
			keyid = TPMTOK_PUBLIC_LEAF_KEY_ID;
			local_uuid_copy(&parentUUID, &publicRootKeyUUID);
			break;
		case TPMTOK_PRIVATE_LEAF_KEY:
			hParentKey = hPrivateRootKey;
			keyid = TPMTOK_PRIVATE_LEAF_KEY_ID;
			local_uuid_copy(&parentUUID, &privateRootKeyUUID);
			break;
		default:
			stlogit("Unknown key type 0x%0x", key_type);
			goto done;
	}

	if (result = tss_generate_key(hContext, initFlags, passHash,
	    hParentKey, phKey)) {
		return (rc);
	}

	/*
	 * - generate newUUID
	 * - Tspi_Context_RegisterKey(hContext, hPrivateRootKey,
	 *   USER, newUUID, USER, parentUUID);
	 * - store newUUID
	 */
	(void) local_uuid_generate(&newuuid);

	result = Tspi_Context_RegisterKey(hContext, *phKey,
	    TSS_PS_TYPE_USER, newuuid,
	    TSS_PS_TYPE_USER, parentUUID);
	if (result == TSS_SUCCESS) {
		int ret;
		/*
		 * Add the UUID to the token UUID index.
		 */
		ret = add_uuid(keyid, &newuuid);

		if (ret)
			result = Tspi_Context_UnregisterKey(hContext,
			    TSS_PS_TYPE_USER, newuuid, phKey);
		else
			rc = CKR_OK;
	}

done:
	return (rc);
}

/*
 * PINs are verified by attempting to bind/unbind random data using a
 * TPM resident key that has the PIN being tested assigned as its "secret".
 * If the PIN is incorrect, the unbind operation will fail.
 */
static CK_RV
token_verify_pin(TSS_HCONTEXT hContext, TSS_HKEY hKey)
{
	TSS_HENCDATA hEncData;
	UINT32 ulUnboundDataLen;
	BYTE *rgbUnboundData = NULL;
	BYTE rgbData[16];
	TSS_RESULT result;
	CK_RV rc = CKR_FUNCTION_FAILED;

	if ((result = Tspi_Context_CreateObject(hContext,
	    TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_BIND, &hEncData))) {
		stlogit("Tspi_Context_CreateObject: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		goto done;
	}

	/* Use some random data */
	rc = token_rng(hContext, rgbData, sizeof (rgbData));
	if (rc)
		goto done;

	if ((result = Tspi_Data_Bind(hEncData, hKey,
	    sizeof (rgbData), rgbData))) {
		stlogit("Tspi_Data_Bind: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		goto done;
	}

	/* unbind the junk data to test the key's auth data */
	result = Tspi_Data_Unbind(hEncData, hKey, &ulUnboundDataLen,
	    &rgbUnboundData);
	if (result == TPM_E_AUTHFAIL) {
		rc = CKR_PIN_INCORRECT;
		stlogit("Tspi_Data_Unbind: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		goto done;
	} else if (result != TSS_SUCCESS) {
		stlogit("Tspi_Data_Unbind: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	if (memcmp(rgbUnboundData, rgbData, ulUnboundDataLen))
		rc = CKR_PIN_INCORRECT;
	else
		rc = CKR_OK;

done:
	if (rgbUnboundData != NULL)
		Tspi_Context_FreeMemory(hContext, rgbUnboundData);
	Tspi_Context_CloseObject(hContext, hEncData);
	return (rc);
}

static CK_RV
token_create_private_tree(TSS_HCONTEXT hContext, CK_BYTE *pinHash)
{
	CK_RV		rc;
	TSS_RESULT	result;
	int		ret;
	TSS_FLAG initFlags = TSS_KEY_SIZE_2048 |
	    TSS_KEY_NO_AUTHORIZATION | TSS_KEY_TYPE_STORAGE;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;
	TSS_HKEY hSRK;

	if (token_load_srk(hContext, &hSRK))
		return (CKR_FUNCTION_FAILED);

	/*
	 * - create UUID privateRootKeyUUID
	 * - Tspi_Context_RegisterKey(hContext, hPrivateRootKey,
	 *   USER, privateRootKeyUUID, system, UUID_SRK);
	 * - store privateRootKeyUUID in users private token space.
	 */
	if ((result = tss_generate_key(hContext, initFlags, NULL, hSRK,
	    &hPrivateRootKey))) {
		return (result);
	}
	if (local_uuid_is_null(&privateRootKeyUUID))
		local_uuid_generate(&privateRootKeyUUID);

	result = Tspi_Context_RegisterKey(hContext, hPrivateRootKey,
	    TSS_PS_TYPE_USER, privateRootKeyUUID,
	    TSS_PS_TYPE_SYSTEM, SRK_UUID);

	if (result) {
		local_uuid_clear(&privateRootKeyUUID);
		return (result);
	}

	ret = add_uuid(TPMTOK_PRIVATE_ROOT_KEY_ID, &privateRootKeyUUID);
	if (ret) {
		result = Tspi_Context_UnregisterKey(hContext,
		    TSS_PS_TYPE_USER, privateRootKeyUUID,
		    &hPrivateRootKey);
		return (CKR_FUNCTION_FAILED);
	}

	if ((result = Tspi_Key_LoadKey(hPrivateRootKey, hSRK))) {
		stlogit("Tspi_Key_LoadKey: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		Tspi_Context_CloseObject(hContext, hPrivateRootKey);

		(void) remove_uuid(TPMTOK_PRIVATE_ROOT_KEY_ID);
		local_uuid_clear(&privateRootKeyUUID);

		hPrivateRootKey = NULL_HKEY;
		return (CKR_FUNCTION_FAILED);
	}


	/* generate the private leaf key */
	if ((rc = token_generate_leaf_key(hContext,
	    TPMTOK_PRIVATE_LEAF_KEY,
	    pinHash, &hPrivateLeafKey))) {
		return (rc);
	}

	if ((result = Tspi_Key_LoadKey(hPrivateLeafKey, hPrivateRootKey))) {
		stlogit("Tspi_Key_LoadKey: 0x%0x - %s",
		    result, Trspi_Error_String(result));

		(void) Tspi_Context_UnregisterKey(hContext,
		    TSS_PS_TYPE_USER, privateLeafKeyUUID,
		    &hPrivateLeafKey);
		(void) remove_uuid(TPMTOK_PRIVATE_LEAF_KEY_ID);
		local_uuid_clear(&privateLeafKeyUUID);

		(void) Tspi_Context_UnregisterKey(hContext,
		    TSS_PS_TYPE_USER, privateRootKeyUUID,
		    &hPrivateRootKey);
		(void) remove_uuid(TPMTOK_PRIVATE_ROOT_KEY_ID);
		local_uuid_clear(&privateRootKeyUUID);

		Tspi_Context_CloseObject(hContext, hPrivateRootKey);
		hPrivateRootKey = NULL_HKEY;

		Tspi_Context_CloseObject(hContext, hPrivateLeafKey);
		hPrivateRootKey = NULL_HKEY;

		return (CKR_FUNCTION_FAILED);
	}
	return (rc);
}

static CK_RV
token_create_public_tree(TSS_HCONTEXT hContext, CK_BYTE *pinHash)
{
	CK_RV		rc;
	TSS_RESULT	result;
	int		ret;
	TSS_FLAG initFlags = TSS_KEY_SIZE_2048 |
	    TSS_KEY_NO_AUTHORIZATION | TSS_KEY_TYPE_STORAGE;
	TSS_UUID srk_uuid = TSS_UUID_SRK;
	TSS_HKEY hSRK;

	if (token_load_srk(hContext, &hSRK))
		return (CKR_FUNCTION_FAILED);

	/*
	 * - create publicRootKeyUUID
	 * - Tspi_Context_RegisterKey(hContext, hPublicRootKey,
	 *   USER, publicRootKeyUUID, system, UUID_SRK);
	 * - store publicRootKeyUUID in users private token space.
	 */
	if ((result = tss_generate_key(hContext, initFlags, NULL, hSRK,
	    &hPublicRootKey))) {
		return (CKR_FUNCTION_FAILED);
	}
	if (local_uuid_is_null(&publicRootKeyUUID))
		local_uuid_generate(&publicRootKeyUUID);

	result = Tspi_Context_RegisterKey(hContext, hPublicRootKey,
	    TSS_PS_TYPE_USER, publicRootKeyUUID,
	    TSS_PS_TYPE_SYSTEM, srk_uuid);

	if (result) {
		local_uuid_clear(&publicRootKeyUUID);
		return (CKR_FUNCTION_FAILED);
	}

	ret = add_uuid(TPMTOK_PUBLIC_ROOT_KEY_ID, &publicRootKeyUUID);
	if (ret) {
		result = Tspi_Context_UnregisterKey(hContext,
		    TSS_PS_TYPE_USER, publicRootKeyUUID,
		    &hPublicRootKey);
		/* does result matter here? */
		return (CKR_FUNCTION_FAILED);
	}

	/* Load the newly created publicRootKey into the TPM using the SRK */
	if ((result = Tspi_Key_LoadKey(hPublicRootKey, hSRK))) {
		stlogit("Tspi_Key_LoadKey: 0x%x - %s", result,
		    Trspi_Error_String(result));
		Tspi_Context_CloseObject(hContext, hPublicRootKey);
		hPublicRootKey = NULL_HKEY;
		return (CKR_FUNCTION_FAILED);
	}

	/* create the SO's leaf key */
	if ((rc = token_generate_leaf_key(hContext, TPMTOK_PUBLIC_LEAF_KEY,
	    pinHash, &hPublicLeafKey))) {
		return (rc);
	}

	if ((result = Tspi_Key_LoadKey(hPublicLeafKey, hPublicRootKey))) {
		stlogit("Tspi_Key_LoadKey: 0x%0x - %s",
		    result, Trspi_Error_String(result));

		/* Unregister keys and clear UUIDs */
		(void) Tspi_Context_UnregisterKey(hContext,
		    TSS_PS_TYPE_USER, publicLeafKeyUUID,
		    &hPublicLeafKey);
		(void) remove_uuid(TPMTOK_PUBLIC_LEAF_KEY_ID);

		(void) Tspi_Context_UnregisterKey(hContext,
		    TSS_PS_TYPE_USER, publicRootKeyUUID,
		    &hPublicRootKey);
		(void) remove_uuid(TPMTOK_PUBLIC_ROOT_KEY_ID);

		Tspi_Context_CloseObject(hContext, hPublicRootKey);
		hPublicRootKey = NULL_HKEY;

		Tspi_Context_CloseObject(hContext, hPublicLeafKey);
		hPublicLeafKey = NULL_HKEY;

		return (CKR_FUNCTION_FAILED);
	}

	return (rc);
}

CK_RV
token_specific_login(
	TSS_HCONTEXT hContext,
	CK_USER_TYPE userType,
	CK_CHAR_PTR pPin,
	CK_ULONG ulPinLen)
{
	CK_RV rc;
	CK_BYTE hash_sha[SHA1_DIGEST_LENGTH];
	TSS_RESULT result;
	TSS_HKEY hSRK;

	/* Make sure the SRK is loaded into the TPM */
	if ((result = token_load_srk(hContext, &hSRK))) {
		return (CKR_FUNCTION_FAILED);
	}

	if ((rc = compute_sha(pPin, ulPinLen, hash_sha))) {
		return (CKR_FUNCTION_FAILED);
	}

	if (userType == CKU_USER) {
		/*
		 * If the public root key doesn't exist yet,
		 * the SO hasn't init'd the token.
		 */
		if ((result = token_load_public_root_key(hContext))) {
			if (result == TPM_E_DECRYPT_ERROR) {
				return (CKR_USER_PIN_NOT_INITIALIZED);
			}
		}

		/*
		 * - find privateRootKeyUUID
		 * - load by UUID (SRK parent)
		 */
		if (local_uuid_is_null(&privateRootKeyUUID) &&
		    find_uuid(TPMTOK_PRIVATE_ROOT_KEY_ID,
		    &privateRootKeyUUID)) {
				if (memcmp(hash_sha,
				    default_user_pin_sha,
				    SHA1_DIGEST_LENGTH))
					return (CKR_PIN_INCORRECT);

				not_initialized = 1;
				return (CKR_OK);
		}

		if ((rc = verify_user_pin(hContext, hash_sha))) {
			return (rc);
		}

		(void) memcpy(current_user_pin_sha, hash_sha,
		    SHA1_DIGEST_LENGTH);

		rc = load_private_token_objects(hContext);
		if (rc == CKR_OK) {
			(void) XProcLock(xproclock);
			global_shm->priv_loaded = TRUE;
			(void) XProcUnLock(xproclock);
		}
	} else {
		/*
		 * SO login logic:
		 *
		 * - find publicRootKey UUID
		 * - load by UUID wrap with hSRK from above
		 */
		if (local_uuid_is_null(&publicRootKeyUUID) &&
		    find_uuid(TPMTOK_PUBLIC_ROOT_KEY_ID,
		    &publicRootKeyUUID)) {
				if (memcmp(hash_sha,
				    default_so_pin_sha,
				    SHA1_DIGEST_LENGTH))
					return (CKR_PIN_INCORRECT);

				not_initialized = 1;
				return (CKR_OK);

		}
		if (hPublicRootKey == NULL_HKEY) {
			result = tss_find_and_load_key(
			    hContext,
			    TPMTOK_PUBLIC_ROOT_KEY_ID,
			    &publicRootKeyUUID, hSRK, NULL,
			    &hPublicRootKey);

			if (result)
				return (CKR_FUNCTION_FAILED);
		}

		/* find, load the public leaf key */
		if (hPublicLeafKey == NULL_HKEY) {
			result = tss_find_and_load_key(
			    hContext,
			    TPMTOK_PUBLIC_LEAF_KEY_ID,
			    &publicLeafKeyUUID, hPublicRootKey, hash_sha,
			    &hPublicLeafKey);
			if (result)
				return (CKR_FUNCTION_FAILED);
		}

		if ((rc = token_verify_pin(hContext, hPublicLeafKey))) {
			return (rc);
		}

		(void) memcpy(current_so_pin_sha, hash_sha, SHA1_DIGEST_LENGTH);
	}

	return (rc);
}

CK_RV
token_specific_logout(TSS_HCONTEXT hContext)
{
	if (hPrivateLeafKey != NULL_HKEY) {
		Tspi_Key_UnloadKey(hPrivateLeafKey);
		hPrivateLeafKey = NULL_HKEY;
	} else if (hPublicLeafKey != NULL_HKEY) {
		Tspi_Key_UnloadKey(hPublicLeafKey);
		hPublicLeafKey = NULL_HKEY;
	}

	local_uuid_clear(&publicRootKeyUUID);
	local_uuid_clear(&publicLeafKeyUUID);
	local_uuid_clear(&privateRootKeyUUID);
	local_uuid_clear(&privateLeafKeyUUID);

	(void) memset(current_so_pin_sha, 0, SHA1_DIGEST_LENGTH);
	(void) memset(current_user_pin_sha, 0, SHA1_DIGEST_LENGTH);

	(void) object_mgr_purge_private_token_objects(hContext);

	return (CKR_OK);
}

/*ARGSUSED*/
CK_RV
token_specific_init_pin(TSS_HCONTEXT hContext,
	CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	/*
	 * Since the SO must log in before calling C_InitPIN, we will
	 * be able to return (CKR_OK) automatically here.
	 * This is because the USER key structure is created at the
	 * time of their first login, not at C_InitPIN time.
	 */
	return (CKR_OK);
}

static CK_RV
check_pin_properties(CK_USER_TYPE userType, CK_BYTE *pinHash,
	CK_ULONG ulPinLen)
{
	/* make sure the new PIN is different */
	if (userType == CKU_USER) {
		if (!memcmp(pinHash, default_user_pin_sha,
		    SHA1_DIGEST_LENGTH)) {
			LogError1("new PIN must not be the default");
			return (CKR_PIN_INVALID);
		}
	} else {
		if (!memcmp(pinHash, default_so_pin_sha,
		    SHA1_DIGEST_LENGTH)) {
			LogError1("new PIN must not be the default");
			return (CKR_PIN_INVALID);
		}
	}

	if (ulPinLen > MAX_PIN_LEN || ulPinLen < MIN_PIN_LEN) {
		LogError1("New PIN is out of size range");
		return (CKR_PIN_LEN_RANGE);
	}

	return (CKR_OK);
}

/*
 * This function is called from set_pin only, where a non-logged-in public
 * session can provide the user pin which must be verified. This function
 * assumes that the pin has already been set once, so there's no migration
 * path option or checking of the default user pin.
 */
static CK_RV
verify_user_pin(TSS_HCONTEXT hContext, CK_BYTE *hash_sha)
{
	CK_RV rc;
	TSS_RESULT result;
	TSS_HKEY hSRK;

	if (token_load_srk(hContext, &hSRK))
		return (CKR_FUNCTION_FAILED);

	/*
	 * Verify the user by loading the privateLeafKey
	 * into the TPM (if it's not already) and then
	 * call the verify_pin operation.
	 *
	 * The hashed PIN is assigned to the private leaf key.
	 * If it is incorrect (not the same as the one originally
	 * used when the key was created), the verify operation
	 * will fail.
	 */
	if (hPrivateRootKey == NULL_HKEY) {
		result = tss_find_and_load_key(
		    hContext,
		    TPMTOK_PRIVATE_ROOT_KEY_ID,
		    &privateRootKeyUUID, hSRK, NULL, &hPrivateRootKey);
		if (result)
			return (CKR_FUNCTION_FAILED);
	}

	if (hPrivateLeafKey == NULL_HKEY) {
		result = tss_find_and_load_key(
		    hContext,
		    TPMTOK_PRIVATE_LEAF_KEY_ID,
		    &privateLeafKeyUUID, hPrivateRootKey, hash_sha,
		    &hPrivateLeafKey);

		if (result)
			return (CKR_FUNCTION_FAILED);
	}

	/*
	 * Verify that the PIN is correct by attempting to wrap/unwrap some
	 * random data.
	 */
	if ((rc = token_verify_pin(hContext, hPrivateLeafKey))) {
		return (rc);
	}

	return (CKR_OK);
}

CK_RV
token_specific_set_pin(ST_SESSION_HANDLE session,
	CK_CHAR_PTR pOldPin, CK_ULONG ulOldPinLen,
	CK_CHAR_PTR pNewPin, CK_ULONG ulNewPinLen)
{
	SESSION		*sess = session_mgr_find(session.sessionh);
	CK_BYTE		oldpin_hash[SHA1_DIGEST_LENGTH];
	CK_BYTE		newpin_hash[SHA1_DIGEST_LENGTH];
	CK_RV		rc;
	TSS_HKEY	hSRK;

	if (!sess) {
		return (CKR_SESSION_HANDLE_INVALID);
	}

	if ((rc = compute_sha(pOldPin, ulOldPinLen, oldpin_hash))) {
		return (CKR_FUNCTION_FAILED);
	}
	if ((rc = compute_sha(pNewPin, ulNewPinLen, newpin_hash))) {
		return (CKR_FUNCTION_FAILED);
	}

	if (token_load_srk(sess->hContext, &hSRK)) {
		return (CKR_FUNCTION_FAILED);
	}

	/*
	 * From the PKCS#11 2.20 spec: "C_SetPIN modifies the PIN of
	 * the user that is currently logged in, or the CKU_USER PIN
	 * if the session is not logged in."
	 * A non R/W session fails with CKR_SESSION_READ_ONLY.
	 */
	if (sess->session_info.state == CKS_RW_USER_FUNCTIONS ||
	    sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
		if (not_initialized) {
			if (memcmp(oldpin_hash, default_user_pin_sha,
			    SHA1_DIGEST_LENGTH)) {
				return (CKR_PIN_INCORRECT);
			}

			if ((rc = check_pin_properties(CKU_USER, newpin_hash,
			    ulNewPinLen))) {
				return (rc);
			}

			if ((rc = token_create_private_tree(sess->hContext,
			    newpin_hash))) {
				return (CKR_FUNCTION_FAILED);
			}

			nv_token_data->token_info.flags &=
			    ~(CKF_USER_PIN_TO_BE_CHANGED);
			nv_token_data->token_info.flags |=
			    CKF_USER_PIN_INITIALIZED;

			nv_token_data->token_info.flags &=
			    ~(CKF_USER_PIN_TO_BE_CHANGED);
			nv_token_data->token_info.flags |=
			    CKF_USER_PIN_INITIALIZED;

			return (save_token_data(nv_token_data));
		}

		if (sess->session_info.state == CKS_RW_USER_FUNCTIONS) {
			/* if we're already logged in, just verify the hash */
			if (memcmp(current_user_pin_sha, oldpin_hash,
			    SHA1_DIGEST_LENGTH)) {
				return (CKR_PIN_INCORRECT);
			}
		} else {
			if ((rc = verify_user_pin(sess->hContext,
			    oldpin_hash))) {
				return (rc);
			}
		}

		if ((rc = check_pin_properties(CKU_USER, newpin_hash,
		    ulNewPinLen)))
			return (rc);

		/* change the auth on the TSS object */
		if (tss_change_auth(sess->hContext,
		    hPrivateLeafKey, hPrivateRootKey,
		    privateLeafKeyUUID, privateRootKeyUUID,
		    newpin_hash))
			return (CKR_FUNCTION_FAILED);

	} else if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
		if (not_initialized) {
			if (memcmp(default_so_pin_sha, oldpin_hash,
			    SHA1_DIGEST_LENGTH))
				return (CKR_PIN_INCORRECT);

			if ((rc = check_pin_properties(CKU_SO,
			    newpin_hash, ulNewPinLen)))
				return (rc);

			if ((rc = token_create_public_tree(sess->hContext,
			    newpin_hash)))
				return (CKR_FUNCTION_FAILED);

			nv_token_data->token_info.flags &=
			    ~(CKF_SO_PIN_TO_BE_CHANGED);

			return (save_token_data(nv_token_data));
		}

		if (memcmp(current_so_pin_sha, oldpin_hash,
		    SHA1_DIGEST_LENGTH))
			return (CKR_PIN_INCORRECT);

		if ((rc = check_pin_properties(CKU_SO, newpin_hash,
		    ulNewPinLen)))
			return (rc);

		/* change auth on the SO's leaf key */
		if (tss_change_auth(sess->hContext,
		    hPublicLeafKey, hPublicRootKey,
		    publicLeafKeyUUID, publicRootKeyUUID,
		    newpin_hash))
			return (CKR_FUNCTION_FAILED);

	} else {
		rc = CKR_SESSION_READ_ONLY;
	}

	return (rc);
}

/* only called at token init time */
CK_RV
token_specific_verify_so_pin(TSS_HCONTEXT hContext, CK_CHAR_PTR pPin,
    CK_ULONG ulPinLen)
{
	CK_BYTE hash_sha[SHA1_DIGEST_LENGTH];
	CK_RV rc;
	TSS_RESULT result;
	TSS_HKEY hSRK;

	if ((rc = compute_sha(pPin, ulPinLen, hash_sha))) {
		return (CKR_FUNCTION_FAILED);
	}
	if ((rc = token_load_srk(hContext, &hSRK))) {
		return (CKR_FUNCTION_FAILED);
	}

	/*
	 * TRYME INSTEAD:
	 * - find publicRootKeyUUID
	 * - Load publicRootKey by UUID (SRK parent)
	 * - find publicLeafKeyUUID
	 * - Load publicLeafKey by UUID (publicRootKey parent)
	 * - set password policy on publicLeafKey
	 */
	if (local_uuid_is_null(&publicRootKeyUUID) &&
	    find_uuid(TPMTOK_PUBLIC_ROOT_KEY_ID, &publicRootKeyUUID)) {
		/*
		 * The SO hasn't set their PIN yet, compare the
		 * login pin with the hard-coded value.
		 */
		if (memcmp(default_so_pin_sha, hash_sha,
		    SHA1_DIGEST_LENGTH)) {
			return (CKR_PIN_INCORRECT);
		}
		return (CKR_OK);
	}

	result = Tspi_Context_GetKeyByUUID(hContext,
	    TSS_PS_TYPE_USER, publicRootKeyUUID, &hPublicRootKey);

	if (result)
		return (CKR_FUNCTION_FAILED);

	result = Tspi_Key_LoadKey(hPublicRootKey, hSRK);
	if (result)
		return (CKR_FUNCTION_FAILED);

	if (local_uuid_is_null(&publicLeafKeyUUID) &&
	    find_uuid(TPMTOK_PUBLIC_LEAF_KEY_ID, &publicLeafKeyUUID))
		return (CKR_FUNCTION_FAILED);

	result = Tspi_Context_GetKeyByUUID(hContext,
	    TSS_PS_TYPE_USER, publicLeafKeyUUID, &hPublicLeafKey);
	if (result)
		return (CKR_FUNCTION_FAILED);

	result = tss_assign_secret_key_policy(hContext, TSS_POLICY_USAGE,
	    hPublicLeafKey, hash_sha);
	if (result)
		return (CKR_FUNCTION_FAILED);

	result = Tspi_Key_LoadKey(hPublicLeafKey, hPublicRootKey);
	if (result)
		return (CKR_FUNCTION_FAILED);

	/* If the hash given is wrong, the verify will fail */
	if ((rc = token_verify_pin(hContext, hPublicLeafKey))) {
		return (rc);
	}

	return (CKR_OK);
}

CK_RV
token_specific_final(TSS_HCONTEXT hContext)
{
	if (hPublicRootKey != NULL_HKEY) {
		Tspi_Context_CloseObject(hContext, hPublicRootKey);
		hPublicRootKey = NULL_HKEY;
	}
	if (hPublicLeafKey != NULL_HKEY) {
		Tspi_Context_CloseObject(hContext, hPublicLeafKey);
		hPublicLeafKey = NULL_HKEY;
	}
	if (hPrivateRootKey != NULL_HKEY) {
		Tspi_Context_CloseObject(hContext, hPrivateRootKey);
		hPrivateRootKey = NULL_HKEY;
	}
	if (hPrivateLeafKey != NULL_HKEY) {
		Tspi_Context_CloseObject(hContext, hPrivateLeafKey);
		hPrivateLeafKey = NULL_HKEY;
	}
	return (CKR_OK);
}

/*
 * Wrap the 20 bytes of auth data and store in an attribute of the two
 * keys.
 */
static CK_RV
token_wrap_auth_data(TSS_HCONTEXT hContext,
	CK_BYTE *authData, TEMPLATE *publ_tmpl,
	TEMPLATE *priv_tmpl)
{
	CK_RV		rc;
	CK_ATTRIBUTE	*new_attr;

	TSS_RESULT	ret;
	TSS_HKEY	hParentKey;
	TSS_HENCDATA	hEncData;
	BYTE		*blob;
	UINT32		blob_size;

	if ((hPrivateLeafKey == NULL_HKEY) && (hPublicLeafKey == NULL_HKEY)) {
		return (CKR_FUNCTION_FAILED);
	} else if (hPublicLeafKey != NULL_HKEY) {
		hParentKey = hPublicLeafKey;
	} else {
		hParentKey = hPrivateLeafKey;
	}

	/* create the encrypted data object */
	if ((ret = Tspi_Context_CreateObject(hContext,
	    TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_BIND, &hEncData))) {
		stlogit("Tspi_Context_CreateObject: 0x%0x - %s",
		    ret, Trspi_Error_String(ret));
		return (CKR_FUNCTION_FAILED);
	}

	if ((ret = Tspi_Data_Bind(hEncData, hParentKey, SHA1_DIGEST_LENGTH,
	    authData))) {
		stlogit("Tspi_Data_Bind: 0x%0x - %s",
		    ret, Trspi_Error_String(ret));
		return (CKR_FUNCTION_FAILED);
	}

	/* pull the encrypted data out of the encrypted data object */
	if ((ret = Tspi_GetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB,
	    TSS_TSPATTRIB_ENCDATABLOB_BLOB, &blob_size, &blob))) {
		stlogit("Tspi_SetAttribData: 0x%0x - %s",
		    ret, Trspi_Error_String(ret));
		return (CKR_FUNCTION_FAILED);
	}

	if ((rc = build_attribute(CKA_ENC_AUTHDATA, blob, blob_size,
	    &new_attr))) {
		return (rc);
	}
	(void) template_update_attribute(publ_tmpl, new_attr);

	if ((rc = build_attribute(CKA_ENC_AUTHDATA, blob,
	    blob_size, &new_attr))) {
		return (rc);
	}
	(void) template_update_attribute(priv_tmpl, new_attr);

	return (rc);
}

static CK_RV
token_unwrap_auth_data(TSS_HCONTEXT hContext, CK_BYTE *encAuthData,
	CK_ULONG encAuthDataLen, TSS_HKEY hKey,
	BYTE **authData)
{
	TSS_RESULT	result;
	TSS_HENCDATA	hEncData;
	BYTE		*buf;
	UINT32		buf_size;

	if ((result = Tspi_Context_CreateObject(hContext,
	    TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_BIND, &hEncData))) {
		stlogit("Tspi_Context_CreateObject: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}

	if ((result = Tspi_SetAttribData(hEncData,
	    TSS_TSPATTRIB_ENCDATA_BLOB, TSS_TSPATTRIB_ENCDATABLOB_BLOB,
	    encAuthDataLen, encAuthData))) {
		stlogit("Tspi_SetAttribData: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}

	/* unbind the data, receiving the plaintext back */
	if ((result = Tspi_Data_Unbind(hEncData, hKey, &buf_size, &buf))) {
		stlogit("Tspi_Data_Unbind: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}

	if (buf_size != SHA1_DIGEST_LENGTH) {
		return (CKR_FUNCTION_FAILED);
	}

	*authData = buf;

	return (CKR_OK);
}

CK_RV
token_specific_rsa_generate_keypair(
	TSS_HCONTEXT hContext,
	TEMPLATE  *publ_tmpl,
	TEMPLATE  *priv_tmpl)
{
	CK_ATTRIBUTE	*attr = NULL;
	CK_ULONG	mod_bits = 0;
	CK_BBOOL	flag;
	CK_RV		rc;

	TSS_FLAG	initFlags = 0;
	BYTE		authHash[SHA1_DIGEST_LENGTH];
	BYTE		*authData = NULL;
	TSS_HKEY	hKey = NULL_HKEY;
	TSS_HKEY	hParentKey = NULL_HKEY;
	TSS_RESULT	result;
	UINT32		ulBlobLen;
	BYTE		*rgbBlob;

	/* Make sure the public exponent is usable */
	if ((util_check_public_exponent(publ_tmpl))) {
		return (CKR_TEMPLATE_INCONSISTENT);
	}

	flag = template_attribute_find(publ_tmpl, CKA_MODULUS_BITS, &attr);
	if (!flag) {
		return (CKR_TEMPLATE_INCOMPLETE);
	}
	mod_bits = *(CK_ULONG *)attr->pValue;

	if ((initFlags = util_get_keysize_flag(mod_bits)) == 0) {
		return (CKR_KEY_SIZE_RANGE);
	}

	/*
	 * If we're not logged in, hPrivateLeafKey and hPublicLeafKey
	 * should be NULL.
	 */
	if ((hPrivateLeafKey == NULL_HKEY) &&
	    (hPublicLeafKey == NULL_HKEY)) {
		/* public session, wrap key with the PRK */
		initFlags |= TSS_KEY_TYPE_LEGACY |
		    TSS_KEY_NO_AUTHORIZATION | TSS_KEY_MIGRATABLE;

		if ((result = token_load_public_root_key(hContext))) {
			return (CKR_FUNCTION_FAILED);
		}

		hParentKey = hPublicRootKey;
	} else if (hPrivateLeafKey != NULL_HKEY) {
		/* logged in USER session */
		initFlags |= TSS_KEY_TYPE_LEGACY |
		    TSS_KEY_AUTHORIZATION | TSS_KEY_MIGRATABLE;

		/* get a random SHA1 hash for the auth data */
		if ((rc = token_rng(hContext, authHash, SHA1_DIGEST_LENGTH))) {
			return (CKR_FUNCTION_FAILED);
		}

		authData = authHash;
		hParentKey = hPrivateRootKey;
	} else {
		/* logged in SO session */
		initFlags |= TSS_KEY_TYPE_LEGACY |
		    TSS_KEY_AUTHORIZATION | TSS_KEY_MIGRATABLE;

		/* get a random SHA1 hash for the auth data */
		if ((rc = token_rng(hContext, authHash, SHA1_DIGEST_LENGTH))) {
			return (CKR_FUNCTION_FAILED);
		}

		authData = authHash;
		hParentKey = hPublicRootKey;
	}

	if ((result = tss_generate_key(hContext, initFlags, authData,
	    hParentKey, &hKey))) {
		return (result);
	}

	if ((result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
	    TSS_TSPATTRIB_KEYBLOB_BLOB, &ulBlobLen, &rgbBlob))) {
		stlogit("Tspi_GetAttribData: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}

	if ((rc = build_attribute(CKA_IBM_OPAQUE, rgbBlob,
	    ulBlobLen, &attr))) {
		Tspi_Context_FreeMemory(hContext, rgbBlob);
		return (rc);
	}
	(void) template_update_attribute(priv_tmpl, attr);
	if ((rc = build_attribute(CKA_IBM_OPAQUE, rgbBlob,
	    ulBlobLen, &attr))) {
		Tspi_Context_FreeMemory(hContext, rgbBlob);
		return (rc);
	}
	(void) template_update_attribute(publ_tmpl, attr);

	Tspi_Context_FreeMemory(hContext, rgbBlob);

	/* grab the public key to put into the public key object */
	if ((result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_RSAKEY_INFO,
	    TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &ulBlobLen, &rgbBlob))) {
		stlogit("Tspi_GetAttribData: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (result);
	}

	/* add the public key blob to the object template */
	if ((rc = build_attribute(CKA_MODULUS, rgbBlob, ulBlobLen, &attr))) {
		Tspi_Context_FreeMemory(hContext, rgbBlob);
		return (rc);
	}
	(void) template_update_attribute(publ_tmpl, attr);

	/* add the public key blob to the object template */
	if ((rc = build_attribute(CKA_MODULUS, rgbBlob, ulBlobLen, &attr))) {
		Tspi_Context_FreeMemory(hContext, rgbBlob);
		return (rc);
	}
	(void) template_update_attribute(priv_tmpl, attr);
	Tspi_Context_FreeMemory(hContext, rgbBlob);

	/* wrap the authdata and put it into an object */
	if (authData != NULL) {
		rc = token_wrap_auth_data(hContext, authData, publ_tmpl,
		    priv_tmpl);
	}

	return (rc);
}

static CK_RV
token_rsa_load_key(
	TSS_HCONTEXT hContext,
	OBJECT *key_obj,
	TSS_HKEY *phKey)
{
	TSS_RESULT result;
	TSS_HPOLICY hPolicy = NULL_HPOLICY;
	TSS_HKEY	hParentKey;
	BYTE		*authData = NULL;
	CK_ATTRIBUTE	*attr;
	CK_RV		rc;
	CK_OBJECT_HANDLE handle;
	CK_ULONG	class;

	if (hPrivateLeafKey != NULL_HKEY) {
		hParentKey = hPrivateRootKey;
	} else {
		if ((result = token_load_public_root_key(hContext)))
			return (CKR_FUNCTION_FAILED);

		hParentKey = hPublicRootKey;
	}

	*phKey = NULL;
	if (template_attribute_find(key_obj->template, CKA_CLASS,
	    &attr) == FALSE) {
		return (CKR_TEMPLATE_INCOMPLETE);
	}
	class = *((CK_ULONG *)attr->pValue);

	rc = template_attribute_find(key_obj->template,
	    CKA_IBM_OPAQUE, &attr);
	/*
	 * A public key cannot use the OPAQUE data attribute so they
	 * must be created in software.  A private key may not yet
	 * have its "opaque" data defined and needs to be created
	 * and loaded so it can be used inside the TPM.
	 */
	if (class == CKO_PUBLIC_KEY || rc == FALSE) {
		rc = object_mgr_find_in_map2(hContext, key_obj, &handle);
		if (rc != CKR_OK)
			return (CKR_FUNCTION_FAILED);

		if ((rc = token_load_key(hContext,
		    handle, hParentKey, NULL, phKey))) {
			return (rc);
		}
	}
	/*
	 * If this is a private key, get the blob and load it in the TPM.
	 * If it is public, the key is already loaded in software.
	 */
	if (class == CKO_PRIVATE_KEY) {
		/* If we already have a handle, just load it */
		if (*phKey != NULL) {
			result = Tspi_Key_LoadKey(*phKey, hParentKey);
			if (result) {
				stlogit("Tspi_Context_LoadKeyByBlob: "
				    "0x%0x - %s",
				    result, Trspi_Error_String(result));
				return (CKR_FUNCTION_FAILED);
			}
		} else {
			/* try again to get the CKA_IBM_OPAQUE attr */
			if ((rc = template_attribute_find(key_obj->template,
			    CKA_IBM_OPAQUE, &attr)) == FALSE) {
				return (rc);
			}
			if ((result = Tspi_Context_LoadKeyByBlob(hContext,
			    hParentKey, attr->ulValueLen, attr->pValue,
			    phKey))) {
				stlogit("Tspi_Context_LoadKeyByBlob: "
				    "0x%0x - %s",
				    result, Trspi_Error_String(result));
				return (CKR_FUNCTION_FAILED);
			}
		}
	}

	/* auth data may be required */
	if (template_attribute_find(key_obj->template, CKA_ENC_AUTHDATA,
	    &attr) == TRUE && attr) {
		if ((hPrivateLeafKey == NULL_HKEY) &&
		    (hPublicLeafKey == NULL_HKEY)) {
			return (CKR_FUNCTION_FAILED);
		} else if (hPublicLeafKey != NULL_HKEY) {
			hParentKey = hPublicLeafKey;
		} else {
			hParentKey = hPrivateLeafKey;
		}

		if ((result = token_unwrap_auth_data(hContext,
		    attr->pValue, attr->ulValueLen,
		    hParentKey, &authData))) {
			return (CKR_FUNCTION_FAILED);
		}

		if ((result = Tspi_GetPolicyObject(*phKey,
		    TSS_POLICY_USAGE, &hPolicy))) {
			stlogit("Tspi_GetPolicyObject: 0x%0x - %s",
			    result, Trspi_Error_String(result));
			return (CKR_FUNCTION_FAILED);
		}

		/*
		 * If the policy handle returned is the same as the
		 * context's default policy, then a new policy must
		 * be created and assigned to the key. Otherwise, just set the
		 * secret in the policy.
		 */
		if (hPolicy == hDefaultPolicy) {
			if ((result = Tspi_Context_CreateObject(hContext,
			    TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE,
			    &hPolicy))) {
				stlogit("Tspi_Context_CreateObject: "
				    "0x%0x - %s",
				    result, Trspi_Error_String(result));
				return (CKR_FUNCTION_FAILED);
			}

			if ((result = Tspi_Policy_SetSecret(hPolicy,
			    TSS_SECRET_MODE_SHA1,
			    SHA1_DIGEST_LENGTH, authData))) {
				stlogit("Tspi_Policy_SetSecret: "
				    "0x%0x - %s",
				    result, Trspi_Error_String(result));
				return (CKR_FUNCTION_FAILED);
			}

			if ((result = Tspi_Policy_AssignToObject(hPolicy,
			    *phKey))) {
				stlogit("Tspi_Policy_AssignToObject: "
				    "0x%0x - %s",
				    result, Trspi_Error_String(result));
				return (CKR_FUNCTION_FAILED);
			}
		} else if ((result = Tspi_Policy_SetSecret(hPolicy,
		    TSS_SECRET_MODE_SHA1, SHA1_DIGEST_LENGTH, authData))) {
			stlogit("Tspi_Policy_SetSecret: 0x%0x - %s",
			    result, Trspi_Error_String(result));
			return (CKR_FUNCTION_FAILED);
		}

		Tspi_Context_FreeMemory(hContext, authData);
	}

	return (CKR_OK);
}

CK_RV
tpm_decrypt_data(
	TSS_HCONTEXT hContext,
	TSS_HKEY    hKey,
	CK_BYTE   * in_data,
	CK_ULONG    in_data_len,
	CK_BYTE   * out_data,
	CK_ULONG  * out_data_len)
{
	TSS_RESULT result;
	TSS_HENCDATA	hEncData = NULL_HENCDATA;
	UINT32		buf_size = 0, modLen;
	BYTE		*buf = NULL, *modulus = NULL;
	CK_ULONG	chunklen, remain, outlen;

	/* push the data into the encrypted data object */
	if ((result = Tspi_Context_CreateObject(hContext,
	    TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_BIND, &hEncData))) {
		stlogit("Tspi_Context_CreateObject: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}

	/*
	 * Figure out the modulus size so we can break the data
	 * into smaller chunks if necessary.
	 */
	if ((result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_RSAKEY_INFO,
	    TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &modLen, &modulus))) {
		stlogit("Tspi_GetAttribData: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (result);
	}
	/* we don't need the actual modulus */
	Tspi_Context_FreeMemory(hContext, modulus);

	chunklen = (in_data_len > modLen ? modLen : in_data_len);
	remain = in_data_len;
	outlen = 0;

	while (remain > 0) {
		if ((result = Tspi_SetAttribData(hEncData,
		    TSS_TSPATTRIB_ENCDATA_BLOB,
		    TSS_TSPATTRIB_ENCDATABLOB_BLOB,
		    chunklen, in_data))) {
			stlogit("Tspi_SetAttribData: 0x%0x - %s",
			    result, Trspi_Error_String(result));
			return (CKR_FUNCTION_FAILED);
		}

		/* unbind the data, receiving the plaintext back */
		if ((result = Tspi_Data_Unbind(hEncData, hKey,
		    &buf_size, &buf))) {
			stlogit("Tspi_Data_Unbind: 0x%0x - %s",
			    result, Trspi_Error_String(result));
			return (CKR_FUNCTION_FAILED);
		}

		if (*out_data_len < buf_size + outlen) {
			Tspi_Context_FreeMemory(hContext, buf);
			return (CKR_BUFFER_TOO_SMALL);
		}

		(void) memcpy(out_data + outlen, buf, buf_size);

		outlen += buf_size;
		in_data += chunklen;
		remain -= chunklen;

		Tspi_Context_FreeMemory(hContext, buf);
		if (chunklen > remain)
			chunklen = remain;
	}
	*out_data_len = outlen;
	return (CKR_OK);
}

CK_RV
token_specific_rsa_decrypt(
	TSS_HCONTEXT hContext,
	CK_BYTE   * in_data,
	CK_ULONG    in_data_len,
	CK_BYTE   * out_data,
	CK_ULONG  * out_data_len,
	OBJECT	  * key_obj)
{
	CK_RV		rc;
	TSS_HKEY	hKey;

	if ((rc = token_rsa_load_key(hContext, key_obj, &hKey))) {
		return (rc);
	}

	rc = tpm_decrypt_data(hContext, hKey, in_data, in_data_len,
	    out_data, out_data_len);

	return (rc);
}

CK_RV
token_specific_rsa_verify(
	TSS_HCONTEXT hContext,
	CK_BYTE   * in_data,
	CK_ULONG    in_data_len,
	CK_BYTE   * sig,
	CK_ULONG    sig_len,
	OBJECT	  * key_obj)
{
	TSS_RESULT	result;
	TSS_HHASH	hHash;
	TSS_HKEY	hKey;
	CK_RV		rc;

	if ((rc = token_rsa_load_key(hContext, key_obj, &hKey))) {
		return (rc);
	}

	/* Create the hash object we'll use to sign */
	if ((result = Tspi_Context_CreateObject(hContext,
	    TSS_OBJECT_TYPE_HASH, TSS_HASH_OTHER, &hHash))) {
		stlogit("Tspi_Context_CreateObject: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}

	/* Insert the data into the hash object */
	if ((result = Tspi_Hash_SetHashValue(hHash, in_data_len,
	    in_data))) {
		stlogit("Tspi_Hash_SetHashValue: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}

	/* Verify */
	result = Tspi_Hash_VerifySignature(hHash, hKey, sig_len, sig);
	if (result != TSS_SUCCESS &&
	    TPMTOK_TSS_ERROR_CODE(result) != TSS_E_FAIL) {
		stlogit("Tspi_Hash_VerifySignature: 0x%0x - %s",
		    result, Trspi_Error_String(result));
	}

	if (TPMTOK_TSS_ERROR_CODE(result) == TSS_E_FAIL) {
		rc = CKR_SIGNATURE_INVALID;
	} else {
		rc = CKR_OK;
	}

	return (rc);
}

CK_RV
token_specific_rsa_sign(
	TSS_HCONTEXT hContext,
	CK_BYTE   * in_data,
	CK_ULONG    in_data_len,
	CK_BYTE   * out_data,
	CK_ULONG  * out_data_len,
	OBJECT	  * key_obj)
{
	TSS_RESULT	result;
	TSS_HHASH	hHash;
	BYTE		*sig;
	UINT32		sig_len;
	TSS_HKEY	hKey;
	CK_RV		rc;

	if ((rc = token_rsa_load_key(hContext, key_obj, &hKey))) {
		return (rc);
	}

	/* Create the hash object we'll use to sign */
	if ((result = Tspi_Context_CreateObject(hContext,
	    TSS_OBJECT_TYPE_HASH, TSS_HASH_OTHER, &hHash))) {
		stlogit("Tspi_Context_CreateObject: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}

	/* Insert the data into the hash object */
	if ((result = Tspi_Hash_SetHashValue(hHash, in_data_len,
	    in_data))) {
		stlogit("Tspi_Hash_SetHashValue: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}

	/* Sign */
	if ((result = Tspi_Hash_Sign(hHash, hKey, &sig_len, &sig))) {
		stlogit("Tspi_Hash_Sign: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_DATA_LEN_RANGE);
	}

	if (sig_len > *out_data_len) {
		Tspi_Context_FreeMemory(hContext, sig);
		return (CKR_BUFFER_TOO_SMALL);
	}

	(void) memcpy(out_data, sig, sig_len);
	*out_data_len = sig_len;
	Tspi_Context_FreeMemory(hContext, sig);

	return (CKR_OK);
}

CK_RV
tpm_encrypt_data(
	TSS_HCONTEXT hContext,
	TSS_HKEY hKey,
	CK_BYTE *in_data,
	CK_ULONG in_data_len,
	CK_BYTE *out_data,
	CK_ULONG *out_data_len)
{
	TSS_RESULT	result;
	TSS_HENCDATA	hEncData;
	BYTE		*dataBlob, *modulus;
	UINT32		dataBlobSize, modLen;
	CK_ULONG	chunklen, remain;
	CK_ULONG	outlen;
	UINT32		keyusage, scheme, maxsize;

	if ((result = Tspi_Context_CreateObject(hContext,
	    TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_BIND, &hEncData))) {
		stlogit("Tspi_Context_CreateObject: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}
	/*
	 * Figure out the modulus size so we can break the data
	 * into smaller chunks if necessary.
	 */
	if ((result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_RSAKEY_INFO,
	    TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &modLen, &modulus))) {
		stlogit("Tspi_GetAttribData: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (result);
	}
	/* we don't need the actual modulus */
	Tspi_Context_FreeMemory(hContext, modulus);

	/*
	 * According to TSS spec for Tspi_Data_Bind (4.3.4.21.5),
	 * Max input data size varies depending on the key type and
	 * encryption scheme.
	 */
	if ((result = Tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
	    TSS_TSPATTRIB_KEYINFO_USAGE, &keyusage))) {
		stlogit("Cannot find USAGE: %s\n",
		    Trspi_Error_String(result));
		return (result);
	}
	if ((result = Tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
	    TSS_TSPATTRIB_KEYINFO_ENCSCHEME, &scheme))) {
		stlogit("Cannot find ENCSCHEME: %s\n",
		    Trspi_Error_String(result));
		return (result);
	}
	switch (scheme) {
		case TSS_ES_RSAESPKCSV15:
			if (keyusage == TSS_KEYUSAGE_BIND)
				maxsize = 16;
			else /* legacy */
				maxsize = 11;
			break;
		case TSS_ES_RSAESOAEP_SHA1_MGF1:
			maxsize = 47;
			break;
		default:
			maxsize = 0;
	}

	modLen -= maxsize;

	chunklen = (in_data_len > modLen ? modLen : in_data_len);
	remain = in_data_len;
	outlen = 0;
	while (remain > 0) {
		if ((result = Tspi_Data_Bind(hEncData, hKey,
		    chunklen, in_data))) {
			stlogit("Tspi_Data_Bind: 0x%0x - %s",
			    result, Trspi_Error_String(result));
			return (CKR_FUNCTION_FAILED);
		}

		if ((result = Tspi_GetAttribData(hEncData,
		    TSS_TSPATTRIB_ENCDATA_BLOB,
		    TSS_TSPATTRIB_ENCDATABLOB_BLOB,
		    &dataBlobSize, &dataBlob))) {
			stlogit("Tspi_GetAttribData: 0x%0x - %s",
			    result, Trspi_Error_String(result));
			return (CKR_FUNCTION_FAILED);
		}

		if (outlen + dataBlobSize > *out_data_len) {
			Tspi_Context_FreeMemory(hContext, dataBlob);
			return (CKR_DATA_LEN_RANGE);
		}

		(void) memcpy(out_data + outlen,
		    dataBlob, dataBlobSize);

		outlen += dataBlobSize;
		in_data += chunklen;
		remain -= chunklen;

		if (chunklen > remain)
			chunklen = remain;

		Tspi_Context_FreeMemory(hContext, dataBlob);
	}
	*out_data_len = outlen;

	return (CKR_OK);
}

CK_RV
token_specific_rsa_encrypt(
	TSS_HCONTEXT hContext,
	CK_BYTE   * in_data,
	CK_ULONG    in_data_len,
	CK_BYTE   * out_data,
	CK_ULONG  * out_data_len,
	OBJECT	  * key_obj)
{
	TSS_HKEY	hKey;
	CK_RV		rc;

	if ((rc = token_rsa_load_key(hContext, key_obj, &hKey))) {
		return (rc);
	}

	rc  = tpm_encrypt_data(hContext, hKey, in_data, in_data_len,
	    out_data, out_data_len);

	return (rc);
}

/*
 * RSA Verify Recover
 *
 * Public key crypto is done in software, not by the TPM.
 * We bypass the TSPI library here in favor of calls directly
 * to OpenSSL because we don't want to add any padding, the in_data (signature)
 * already contains the data stream to be decrypted and is already
 * padded and formatted correctly.
 */
CK_RV
token_specific_rsa_verify_recover(
	TSS_HCONTEXT	hContext,
	CK_BYTE		*in_data,	/* signature */
	CK_ULONG	in_data_len,
	CK_BYTE		*out_data,	/* decrypted */
	CK_ULONG	*out_data_len,
	OBJECT		*key_obj)
{
	TSS_HKEY	hKey;
	TSS_RESULT	result;
	CK_RV		rc;
	BYTE		*modulus;
	UINT32		modLen;
	RSA		*rsa = NULL;
	uchar_t		exp[] = { 0x01, 0x00, 0x01 };
	int		sslrv, num;
	BYTE		temp[MAX_RSA_KEYLENGTH];
	BYTE		outdata[MAX_RSA_KEYLENGTH];
	int		i;

	if ((rc = token_rsa_load_key(hContext, key_obj, &hKey))) {
		return (rc);
	}

	if ((result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_RSAKEY_INFO,
	    TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &modLen, &modulus))) {
		stlogit("Tspi_GetAttribData: 0x%0x - %s",
		    result, Trspi_Error_String(result));
		return (CKR_FUNCTION_FAILED);
	}

	if (in_data_len != modLen) {
		rc = CKR_SIGNATURE_LEN_RANGE;
		goto end;
	}

	rsa = RSA_new();
	if (rsa == NULL) {
		rc = CKR_HOST_MEMORY;
		goto end;
	}

	rsa->n = BN_bin2bn(modulus, modLen, rsa->n);
	rsa->e = BN_bin2bn(exp, sizeof (exp), rsa->e);
	if (rsa->n == NULL || rsa->e == NULL) {
		rc = CKR_HOST_MEMORY;
		goto end;
	}

	rsa->flags |= RSA_FLAG_SIGN_VER;

	/* use RSA_NO_PADDING because the data is already padded (PKCS1) */
	sslrv = RSA_public_encrypt(in_data_len, in_data, outdata,
	    rsa, RSA_NO_PADDING);
	if (sslrv == -1) {
		rc = CKR_FUNCTION_FAILED;
		goto end;
	}

	/* Strip leading 0's before stripping the padding */
	for (i = 0; i < sslrv; i++)
		if (outdata[i] != 0)
			break;

	num = BN_num_bytes(rsa->n);

	/* Use OpenSSL function for stripping PKCS#1 padding */
	sslrv = RSA_padding_check_PKCS1_type_1(temp, sizeof (temp),
	    &outdata[i], sslrv - i, num);

	if (sslrv < 0) {
		rc = CKR_FUNCTION_FAILED;
		goto end;
	}

	if (*out_data_len < sslrv) {
		rc = CKR_BUFFER_TOO_SMALL;
		*out_data_len = 0;
		goto end;
	}

	/* The return code indicates the number of bytes remaining */
	(void) memcpy(out_data, temp, sslrv);
	*out_data_len = sslrv;
end:
	Tspi_Context_FreeMemory(hContext, modulus);
	if (rsa)
		RSA_free(rsa);

	return (rc);
}
