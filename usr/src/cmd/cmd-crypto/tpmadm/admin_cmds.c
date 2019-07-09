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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <sha1.h>
#include <uuid/uuid.h>
#include <sys/stat.h>
#include <libintl.h>

#include <tss/tss_defines.h>
#include <tss/tspi.h>

#include "tpmadm.h"

int cmd_status(TSS_HCONTEXT hContext, TSS_HTPM hTPM, int argc, char *argv[]);
int cmd_init(TSS_HCONTEXT hContext, TSS_HTPM hTPM, int argc, char *argv[]);
int cmd_clear(TSS_HCONTEXT hContext, TSS_HTPM hTPM, int argc, char *argv[]);
int cmd_auth(TSS_HCONTEXT hContext, TSS_HTPM hTPM, int argc, char *argv[]);
int cmd_keyinfo(TSS_HCONTEXT hContext, TSS_HTPM hTPM, int argc, char *argv[]);
int cmd_deletekey(TSS_HCONTEXT hContext, TSS_HTPM hTPM, int argc, char *argv[]);

cmdtable_t commands[] = {
	{ "status", "", cmd_status },
	{ "init", "", cmd_init },
	{ "clear", "[owner | lock]", cmd_clear },
	{ "auth", "", cmd_auth },
	{ "keyinfo", "[uuid]", cmd_keyinfo },
	{ "deletekey", "uuid", cmd_deletekey },
	{ NULL, NULL, NULL },
};

BYTE well_known[] = TSS_WELL_KNOWN_SECRET;
TSS_UUID srk_uuid = TSS_UUID_SRK;


/*
 * TPM status
 */

static int
print_tpm_version(TSS_HCONTEXT hContext, TSS_HOBJECT hTPM)
{
	struct {
		TPM_CAP_VERSION_INFO vers_info;
		char extra[20]; /* vendor extensions */
	} info;

	if (get_tpm_capability(hContext, hTPM, TSS_TPMCAP_VERSION_VAL,
	    0, &info, sizeof (info)))
		return (ERR_FAIL);

	(void) printf(gettext("TPM Version: %d.%d (%c%c%c%c Rev: %d.%d, "
	    "SpecLevel: %d, ErrataRev: %d)\n"),
	    info.vers_info.version.major,
	    info.vers_info.version.minor,
	    info.vers_info.tpmVendorID[0],
	    info.vers_info.tpmVendorID[1],
	    info.vers_info.tpmVendorID[2],
	    info.vers_info.tpmVendorID[3],
	    info.vers_info.version.revMajor,
	    info.vers_info.version.revMinor,
	    (int)ntohs(info.vers_info.specLevel),
	    info.vers_info.errataRev);

	return (0);
}

static int
tpm_is_owned(TSS_HCONTEXT hContext, TSS_HOBJECT hTPM)
{
	BYTE owned;

	if (get_tpm_capability(hContext, hTPM, TSS_TPMCAP_PROPERTY,
	    TSS_TPMCAP_PROP_OWNER, &owned, sizeof (owned)))
		return (0);

	return (owned);
}

static int
print_tpm_resources(TSS_HCONTEXT hContext, TSS_HOBJECT hTPM)
{
	UINT32 avail, max;

	(void) printf(gettext("TPM resources\n"));

	if (get_tpm_capability(hContext, hTPM, TSS_TPMCAP_PROPERTY,
	    TSS_TPMCAP_PROP_MAXCONTEXTS, &max, sizeof (max)))
		return (ERR_FAIL);
	if (get_tpm_capability(hContext, hTPM, TSS_TPMCAP_PROPERTY,
	    TSS_TPMCAP_PROP_CONTEXTS, &avail, sizeof (avail)))
		return (ERR_FAIL);
	(void) printf(gettext("\tContexts: %d/%d available\n"), avail, max);

	if (get_tpm_capability(hContext, hTPM, TSS_TPMCAP_PROPERTY,
	    TSS_TPMCAP_PROP_MAXSESSIONS, &max, sizeof (max)))
		return (ERR_FAIL);
	if (get_tpm_capability(hContext, hTPM, TSS_TPMCAP_PROPERTY,
	    TSS_TPMCAP_PROP_SESSIONS, &avail, sizeof (avail)))
		return (ERR_FAIL);
	(void) printf(gettext("\tSessions: %d/%d available\n"), avail, max);

	if (get_tpm_capability(hContext, hTPM, TSS_TPMCAP_PROPERTY,
	    TSS_TPMCAP_PROP_MAXAUTHSESSIONS, &max, sizeof (max)))
		return (ERR_FAIL);
	if (get_tpm_capability(hContext, hTPM, TSS_TPMCAP_PROPERTY,
	    TSS_TPMCAP_PROP_AUTHSESSIONS, &avail, sizeof (avail)))
		return (ERR_FAIL);
	(void) printf(gettext("\tAuth Sessions: %d/%d available\n"),
	    avail, max);

	if (get_tpm_capability(hContext, hTPM, TSS_TPMCAP_PROPERTY,
	    TSS_TPMCAP_PROP_MAXKEYS, &max, sizeof (max)))
		return (ERR_FAIL);
	if (get_tpm_capability(hContext, hTPM, TSS_TPMCAP_PROPERTY,
	    TSS_TPMCAP_PROP_KEYS, &avail, sizeof (avail)))
		return (ERR_FAIL);
	(void) printf(gettext("\tLoaded Keys: %d/%d available\n"), avail, max);

	return (0);
}

static int
print_tpm_pcrs(TSS_HCONTEXT hContext, TSS_HOBJECT hTPM)
{
	UINT32 num_pcrs;
	int i;

	if (get_tpm_capability(hContext, hTPM, TSS_TPMCAP_PROPERTY,
	    TSS_TPMCAP_PROP_PCR, &num_pcrs, sizeof (num_pcrs)))
		return (ERR_FAIL);
	(void) printf(gettext("Platform Configuration Registers (%u)\n"),
	    num_pcrs);

	/* Print each PCR */
	for (i = 0; i < num_pcrs; i++) {
		TSS_RESULT ret;
		UINT32 datalen;
		BYTE *data;

		ret = Tspi_TPM_PcrRead(hTPM, i, &datalen, &data);
		if (ret) {
			print_error(ret, gettext("Read PCR"));
			return (ret);
		}

		(void) printf("\tPCR %u:\t", i);
		print_bytes(data, datalen, FALSE);

		ret = Tspi_Context_FreeMemory(hContext, data);
		if (ret) {
			print_error(ret, gettext("Free PCR memory"));
			return (ret);
		}
	}
	return (0);
}

/*ARGSUSED*/
int
cmd_status(TSS_HCONTEXT hContext, TSS_HTPM hTPM, int argc, char *argv[])
{
	if (set_object_policy(hTPM, TSS_SECRET_MODE_POPUP, NULL, 0, NULL))
		return (ERR_FAIL);

	(void) print_tpm_version(hContext, hTPM);
	if (tpm_is_owned(hContext, hTPM)) {
		(void) print_tpm_resources(hContext, hTPM);
		(void) print_tpm_pcrs(hContext, hTPM);
	} else {
		(void) printf(gettext("No TPM owner installed.\n"));
	}

	return (0);
}


/*
 * Key Information
 */

typedef struct {
	UINT32 code;
	char *str;
} decode_map_t;

decode_map_t key_usage[] = {
	{ TSS_KEYUSAGE_SIGN, "Signing" },
	{ TSS_KEYUSAGE_STORAGE, "Storage" },
	{ TSS_KEYUSAGE_IDENTITY, "Identity" },
	{ TSS_KEYUSAGE_AUTHCHANGE, "Authchange" },
	{ TSS_KEYUSAGE_BIND, "Bind" },
	{ TSS_KEYUSAGE_LEGACY, "Legacy" },
	{ TSS_KEYUSAGE_MIGRATE, "Migrate" },
	{ 0, NULL },
};

decode_map_t key_algorithm[] = {
	{ TSS_ALG_RSA, "RSA" },
	{ TSS_ALG_DES, "DES" },
	{ TSS_ALG_3DES, "3-DES" },
	{ TSS_ALG_SHA, "SHA" },
	{ TSS_ALG_HMAC, "HMAC" },
	{ TSS_ALG_AES, "AES" },
	{ TSS_ALG_MGF1, "MGF1" },
	{ TSS_ALG_AES192, "AES192" },
	{ TSS_ALG_AES256, "AES256" },
	{ TSS_ALG_XOR, "XOR" },
	{ 0, NULL },
};

decode_map_t key_sigscheme[] = {
	{ TSS_SS_NONE, "None" },
	{ TSS_SS_RSASSAPKCS1V15_SHA1, "RSASSAPKCS1v15_SHA1" },
	{ TSS_SS_RSASSAPKCS1V15_DER, "RSASSAPKCS1v15_DER" },
	{ 0, NULL },
};

decode_map_t key_encscheme[] = {
	{ TSS_ES_NONE, "None" },
	{ TSS_ES_RSAESPKCSV15, "RSAESPKCSv15" },
	{ TSS_ES_RSAESOAEP_SHA1_MGF1, "RSAESOAEP_SHA1_MGF1" },
	{ TSS_ES_SYM_CNT, "SYM_CNT" },
	{ TSS_ES_SYM_OFB, "SYM_OFB" },
	{ 0, NULL },
};

static char *
decode(decode_map_t *table, UINT32 code)
{
	static char buf[20];
	int i;

	for (i = 0; table[i].str != NULL; i++) {
		if (table[i].code == code)
			return (table[i].str);
	}

	(void) snprintf(buf, sizeof (buf), gettext("Unknown (%u)"), code);
	return (buf);
}

static void
print_key_info(TSS_HCONTEXT hContext, TSS_HOBJECT hKey)
{
	TSS_RESULT ret;
	UINT32 attrib;
	UINT32 keyInfoSize;
	BYTE *keyInfo;

	/* Key size */
	ret = Tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
	    TSS_TSPATTRIB_KEYINFO_SIZE, &attrib);
	if (ret) {
		print_error(ret, gettext("Get key size"));
	}
	(void) printf(gettext("Key Size: %d bits\n"), attrib);

	/* Key usage */
	ret = Tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
	    TSS_TSPATTRIB_KEYINFO_USAGE, &attrib);
	if (ret) {
		print_error(ret, gettext("Get key usage"));
	}
	(void) printf(gettext("Key Usage: %s\n"), decode(key_usage, attrib));

	/* Algorithm */
	ret = Tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
	    TSS_TSPATTRIB_KEYINFO_ALGORITHM, &attrib);
	if (ret) {
		print_error(ret, gettext("Get key algorithm"));
	}
	(void) printf(gettext("Algorithm: %s\n"),
	    decode(key_algorithm, attrib));

	/* Authorization required */
	ret = Tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
	    TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, &attrib);
	if (ret) {
		print_error(ret, gettext("Get key authusage"));
	}
	(void) printf(gettext("Authorization required: %s\n"),
	    attrib ? gettext("Yes") : gettext("No"));

	/* Signature scheme */
	ret = Tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
	    TSS_TSPATTRIB_KEYINFO_SIGSCHEME, &attrib);
	if (ret) {
		print_error(ret, gettext("Get key signature scheme"));
	}
	(void) printf(gettext("Signature scheme: %s\n"),
	    decode(key_sigscheme, attrib));

	/* Encoding scheme */
	ret = Tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
	    TSS_TSPATTRIB_KEYINFO_ENCSCHEME, &attrib);
	if (ret) {
		print_error(ret, gettext("Get key encoding scheme"));
	}
	(void) printf(gettext("Encoding scheme: %s\n"),
	    decode(key_encscheme, attrib));

	/* Key blob */
	ret = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
	    TSS_TSPATTRIB_KEYBLOB_BLOB, &keyInfoSize, &keyInfo);
	if (ret) {
		print_error(ret, gettext("Get key blob"));
	}
	(void) printf(gettext("TPM Key Blob:\n"));
	print_bytes(keyInfo, keyInfoSize, TRUE);
	ret = Tspi_Context_FreeMemory(hContext, keyInfo);
	if (ret) {
		print_error(ret, gettext("Free key info buffer"));
	}
}

typedef struct hash_node {
	struct hash_node *next, *sibling, *child;
	TSS_UUID uuid;
	TSS_KM_KEYINFO2 *key_data;
} hash_node_t;

#define	HASHSIZE 17
hash_node_t *hash_table[HASHSIZE];

static hash_node_t *
hash_insert(TSS_UUID uuid, TSS_KM_KEYINFO2 *key_data)
{
	UINT32 i, index = 0;
	hash_node_t *node;
	char *cp;

	cp = (char *)&uuid;
	for (i = 0; i < sizeof (TSS_UUID); i++)
		index += cp[i];
	index = index % HASHSIZE;

	for (node = hash_table[index]; node != NULL; node = node->next) {
		if (memcmp(&(node->uuid), &uuid, sizeof (TSS_UUID)) == 0)
			break;
	}

	if (node == NULL) {
		node = calloc(1, sizeof (hash_node_t));
		node->uuid = uuid;
		node->next = hash_table[index];
		hash_table[index] = node;
	}
	if (node->key_data == NULL)
		node->key_data = key_data;

	return (node);
}

static void
add_child(hash_node_t *parent, hash_node_t *child)
{
	hash_node_t *node;

	for (node = parent->child; node != NULL; node = node->next) {
		if (node == child)
			return;
	}

	child->sibling = parent->child;
	parent->child = child;
}

static void
print_all(hash_node_t *parent, int indent)
{
	char uuidstr[UUID_PRINTABLE_STRING_LENGTH];
	hash_node_t *node;
	char *type, *loaded;

	uuid_unparse(*(uuid_t *)&parent->uuid, uuidstr);
	type = (parent->key_data->persistentStorageType == TSS_PS_TYPE_USER) ?
	    "USER" : "SYSTEM";
	loaded = parent->key_data->fIsLoaded ? "(loaded)" : "";
	(void) printf("%*s[%s] %s %s\n", indent, "",
	    type, uuidstr, loaded);

	for (node = parent->child; node != NULL; node = node->sibling)
		print_all(node, indent + 4);
}

/*ARGSUSED*/
int
cmd_keyinfo(TSS_HCONTEXT hContext, TSS_HTPM hTPM, int argc, char *argv[])
{
	TSS_RESULT ret;
	UINT32 i, num_keys;
	TSS_KM_KEYINFO2 *keys;
	hash_node_t *parent, *child, *srk = NULL;
	TSS_HKEY hKey;
	union {
		uuid_t arr_uuid;
		TSS_UUID tss_uuid;
	} uuid;

	switch (argc) {
	case 1:
		/* Print key hierarchy */
		ret = Tspi_Context_GetRegisteredKeysByUUID2(hContext,
		    TSS_PS_TYPE_USER, NULL, &num_keys, &keys);
		if (ret) {
			print_error(ret, gettext("Get key hierarchy"));
			return (ERR_FAIL);
		}

		for (i = 0; i < num_keys; i++) {
			parent = hash_insert(keys[i].parentKeyUUID, NULL);
			child = hash_insert(keys[i].keyUUID, &keys[i]);
			add_child(parent, child);
			if (memcmp(&(keys[i].keyUUID), &srk_uuid,
			    sizeof (TSS_UUID)) == 0)
				srk = child;
		}

		if (srk != NULL)
			print_all(srk, 0);
		ret = Tspi_Context_FreeMemory(hContext, (BYTE *) keys);
		if (ret) {
			print_error(ret, gettext("Free key list"));
			return (ERR_FAIL);
		}
		return (0);

	case 2:
		/* Print detailed info about a single key */
		if (uuid_parse(argv[1], uuid.arr_uuid))
			return (ERR_FAIL);
		ret = Tspi_Context_GetKeyByUUID(hContext, TSS_PS_TYPE_USER,
		    uuid.tss_uuid, &hKey);
		if (ret == TSP_ERROR(TSS_E_PS_KEY_NOTFOUND)) {
			ret = Tspi_Context_GetKeyByUUID(hContext,
			    TSS_PS_TYPE_SYSTEM, uuid.tss_uuid, &hKey);
		}
		if (ret) {
			print_error(ret, gettext("Get key by UUID"));
			return (ERR_FAIL);
		}
		print_key_info(hContext, hKey);
		return (0);

	default:
		(void) fprintf(stderr, gettext("Usage:\n"));
		(void) fprintf(stderr, "\tkeyinfo [uuid]\n");
		return (ERR_USAGE);
	}
}

/*ARGSUSED*/
int
cmd_deletekey(TSS_HCONTEXT hContext, TSS_HTPM hTPM, int argc, char *argv[])
{
	TSS_RESULT ret;
	TSS_HOBJECT hKey;
	union {
		uuid_t arr_uuid;
		TSS_UUID tss_uuid;
	} uuid;

	if (argc < 2) {
		(void) fprintf(stderr, gettext("Usage:\n"));
		(void) fprintf(stderr, "\tdeletekey [uuid]\n");
		return (ERR_USAGE);
	}
	if (uuid_parse(argv[1], uuid.arr_uuid))
		return (ERR_FAIL);
	ret = Tspi_Context_UnregisterKey(hContext, TSS_PS_TYPE_USER,
	    uuid.tss_uuid, &hKey);
	if (ret == TSP_ERROR(TSS_E_PS_KEY_NOTFOUND)) {
		ret = Tspi_Context_UnregisterKey(hContext, TSS_PS_TYPE_SYSTEM,
		    uuid.tss_uuid, &hKey);
	}
	if (ret) {
		print_error(ret, gettext("Unregister key"));
		return (ERR_FAIL);
	}
	return (0);
}

/*
 * Clear
 */

static int
clearowner(TSS_HTPM hTPM)
{
	TSS_RESULT ret;

	if (set_object_policy(hTPM, TSS_SECRET_MODE_POPUP,
	    gettext("= TPM owner passphrase ="), 0, NULL))
		return (ERR_FAIL);

	ret = Tspi_TPM_ClearOwner(hTPM, FALSE);
	if (ret) {
		print_error(ret, gettext("Clear TPM owner"));
		return (ERR_FAIL);
	}
	return (0);
}

static int
resetlock(TSS_HTPM hTPM)
{
	TSS_RESULT ret;

	if (set_object_policy(hTPM, TSS_SECRET_MODE_POPUP,
	    gettext("= TPM owner passphrase ="), 0, NULL))
		return (ERR_FAIL);

	ret = Tspi_TPM_SetStatus(hTPM, TSS_TPMSTATUS_RESETLOCK, TRUE);
	if (ret) {
		print_error(ret, gettext("Reset Lock"));
		return (ERR_FAIL);
	}
	return (0);
}

/*ARGSUSED*/
int
cmd_clear(TSS_HCONTEXT hContext, TSS_HTPM hTPM, int argc, char *argv[])
{
	char *subcmd = argv[1];

	if (subcmd && strcmp(subcmd, "lock") == 0) {
		return (resetlock(hTPM));
	} else if (subcmd && strcmp(subcmd, "owner") == 0) {
		return (clearowner(hTPM));
	} else {
		(void) fprintf(stderr, gettext("Usage:\n"));
		(void) fprintf(stderr, "\tclear owner\n");
		(void) fprintf(stderr, "\tclear lock\n");
		return (ERR_USAGE);
	}
}


/*
 * TPM initialization
 */

static int
get_random(UINT32 size,	BYTE *randomBytes)
{
	int fd, len;
	BYTE *buf;

	fd = open("/dev/random", O_RDONLY);
	if (fd == -1) {
		(void) fprintf(stderr, gettext("Unable to open /dev/random"));
		return (-1);
	}

	buf = randomBytes;
	while (size > 0) {
		len = read(fd, buf, size);
		if (len <= 0) {
			(void) close(fd);
			(void) fprintf(stderr,
			    gettext("Error reading /dev/random"));
			return (-1);
		}
		size -= len;
		buf += len;
	}

	(void) close(fd);
	return (0);
}

static int
createek(TSS_HCONTEXT hContext, TSS_HTPM hTPM)
{
	TSS_RESULT ret;
	TSS_HOBJECT hKeyEK;
	TSS_VALIDATION ValidationData;
	TPM_NONCE nonce;
	TPM_DIGEST digest;

	/* Create the empty key struct for EK */
	ret = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
	    (TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NON_VOLATILE |
	    TSS_KEY_NOT_MIGRATABLE | TSS_KEY_TYPE_STORAGE |
	    TSS_KEY_SIZE_2048 | TSS_KEY_NOT_CERTIFIED_MIGRATABLE |
	    TSS_KEY_STRUCT_KEY12 | TSS_KEY_EMPTY_KEY),
	    &hKeyEK);
	if (ret) {
		print_error(ret, gettext("Create endorsement key object"));
		return (ERR_FAIL);
	}

	ValidationData.ulExternalDataLength = sizeof (nonce);
	ValidationData.rgbExternalData = (BYTE *) &nonce;
	ret = get_random(sizeof (nonce), (BYTE *) &nonce);
	if (ret)
		return (ERR_FAIL);
	ValidationData.ulValidationDataLength = sizeof (digest);
	ValidationData.rgbValidationData = (BYTE *) &digest;

	ret = Tspi_TPM_CreateEndorsementKey(hTPM, hKeyEK, &ValidationData);
	if (ret) {
		print_error(ret, gettext("Create endorsement key"));
		return (ERR_FAIL);
	}

	return (0);
}

/*ARGSUSED*/
int
cmd_init(TSS_HCONTEXT hContext, TSS_HTPM hTPM, int argc, char *argv[])
{
	TSS_RESULT ret;
	TSS_HOBJECT hKeySRK;

	if (set_object_policy(hTPM, TSS_SECRET_MODE_POPUP,
	    gettext("= TPM owner passphrase ="), 0, NULL))
		return (ERR_FAIL);

	ret = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
	    TSS_KEY_TSP_SRK | TSS_KEY_AUTHORIZATION, &hKeySRK);
	if (ret) {
		print_error(ret, gettext("Create storage root key"));
		return (ERR_FAIL);
	}

	if (set_object_policy(hKeySRK, TSS_SECRET_MODE_SHA1, NULL,
	    sizeof (well_known), well_known))
		return (ERR_FAIL);

	ret = Tspi_TPM_TakeOwnership(hTPM, hKeySRK, 0);
	if (ret == TPM_E_NO_ENDORSEMENT) {
		if (createek(hContext, hTPM))
			return (ERR_FAIL);
		ret = Tspi_TPM_TakeOwnership(hTPM, hKeySRK, 0);
	}
	if (ret) {
		print_error(ret, gettext("Take ownership"));
		return (ERR_FAIL);
	}

	return (0);
}

/*
 * Auth
 */

/*ARGSUSED*/
int
cmd_auth(TSS_HCONTEXT hContext, TSS_HTPM hTPM, int argc, char *argv[])
{
	TSS_RESULT ret;
	TSS_HPOLICY hNewPolicy;

	if (set_object_policy(hTPM, TSS_SECRET_MODE_POPUP,
	    gettext("= TPM owner passphrase ="), 0, NULL))
		return (ERR_FAIL);

	/* policy object for new passphrase */
	ret = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
	    TSS_POLICY_USAGE, &hNewPolicy);
	if (ret) {
		print_error(ret, gettext("Create policy object"));
		return (ERR_FAIL);
	}
	if (set_policy_options(hNewPolicy, TSS_SECRET_MODE_POPUP,
	    gettext("= New TPM owner passphrase ="), 0, NULL))
		return (ERR_FAIL);

	ret = Tspi_ChangeAuth(hTPM, 0, hNewPolicy);
	if (ret && ret != TSP_ERROR(TSS_E_POLICY_NO_SECRET)) {
		print_error(ret, gettext("Change authorization"));
		return (ERR_FAIL);
	}

	return (0);
}
