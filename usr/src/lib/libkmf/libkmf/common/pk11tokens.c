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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <security/cryptoki.h>
#include <kmfapi.h>
#include <kmfapiP.h>
#include <cryptoutil.h>

/*
 * memcmp_pad_max() is a specialized version of memcmp() which
 * compares two pieces of data up to a maximum length.  If the
 * the two data match up the maximum length, they are considered
 * matching.  Trailing blanks do not cause the match to fail if
 * one of the data is shorted.
 *
 * Examples of matches:
 *	"one"           |
 *	"one      "     |
 *	                ^maximum length
 *
 *	"Number One     |  X"	(X is beyond maximum length)
 *	"Number One   " |
 *	                ^maximum length
 *
 * Examples of mismatches:
 *	" one"
 *	"one"
 *
 *	"Number One    X|"
 *	"Number One     |"
 *	                ^maximum length
 */
static int
memcmp_pad_max(void *d1, uint_t d1_len, void *d2, uint_t d2_len, uint_t max_sz)
{
	uint_t		len, extra_len;
	char		*marker;

	/* No point in comparing anything beyond max_sz */
	if (d1_len > max_sz)
		d1_len = max_sz;
	if (d2_len > max_sz)
		d2_len = max_sz;

	/* Find shorter of the two data. */
	if (d1_len <= d2_len) {
		len = d1_len;
		extra_len = d2_len;
		marker = d2;
	} else {	/* d1_len > d2_len */
		len = d2_len;
		extra_len = d1_len;
		marker = d1;
	}

	/* Have a match in the shortest length of data? */
	if (memcmp(d1, d2, len) != 0)
		/* CONSTCOND */
		return (1);

	/* If the rest of longer data is nulls or blanks, call it a match. */
	while (len < extra_len && marker[len])
		if (!isspace(marker[len++]))
			/* CONSTCOND */
			return (1);
	return (0);
}

static KMF_RETURN
kmf_get_token_slots(KMF_HANDLE *handle, CK_SLOT_ID_PTR *slot_list,
    CK_ULONG *slot_count)
{

	KMF_RETURN	kmf_rv = KMF_OK;
	CK_RV		ck_rv = CKR_OK;
	CK_ULONG	tmp_count = 0;
	CK_SLOT_ID_PTR	tmp_list = NULL_PTR, tmp2_list = NULL_PTR;

	ck_rv = C_GetSlotList(1, NULL_PTR, &tmp_count);
	if (ck_rv == CKR_CRYPTOKI_NOT_INITIALIZED) {
		ck_rv = C_Initialize(NULL);
		if ((ck_rv != CKR_OK) &&
		    (ck_rv != CKR_CRYPTOKI_ALREADY_INITIALIZED))
			return (KMF_ERR_UNINITIALIZED);
		if (ck_rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
			ck_rv = CKR_OK;

		ck_rv = C_GetSlotList(1, NULL_PTR, &tmp_count);
	}
	if (ck_rv != CKR_OK) {
		if (handle != NULL) {
			handle->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
			handle->lasterr.errcode = ck_rv;
		}
		return (KMF_ERR_INTERNAL);
	}

	if (tmp_count == 0) {
		*slot_list = NULL_PTR;
		*slot_count = 0;
		return (KMF_OK);
	}

	/* Allocate initial space for the slot list. */
	if ((tmp_list = (CK_SLOT_ID_PTR) malloc(tmp_count *
	    sizeof (CK_SLOT_ID))) == NULL)
		return (KMF_ERR_MEMORY);

	/* Then get the slot list itself. */
	for (;;) {
		ck_rv = C_GetSlotList(1, tmp_list, &tmp_count);
		if (ck_rv == CKR_OK) {
			*slot_list = tmp_list;
			*slot_count = tmp_count;
			kmf_rv = KMF_OK;
			break;
		}

		if (ck_rv != CKR_BUFFER_TOO_SMALL) {
			free(tmp_list);
			if (handle != NULL) {
				handle->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
				handle->lasterr.errcode = ck_rv;
			}
			kmf_rv = KMF_ERR_INTERNAL;
			break;
		}

		/*
		 * If the number of slots grew, try again. This
		 * is to be consistent with pktool in ONNV.
		 */
		if ((tmp2_list = (CK_SLOT_ID_PTR) realloc(tmp_list,
		    tmp_count * sizeof (CK_SLOT_ID))) == NULL) {
			free(tmp_list);
			kmf_rv = KMF_ERR_MEMORY;
			break;
		}
		tmp_list = tmp2_list;
	}

	return (kmf_rv);
}

/*
 * Returns pointer to either null-terminator or next unescaped colon.  The
 * string to be extracted starts at the beginning and goes until one character
 * before this pointer.  If NULL is returned, the string itself is NULL.
 */
static char *
find_unescaped_colon(char *str)
{
	char *end;

	if (str == NULL)
		return (NULL);

	while ((end = strchr(str, ':')) != NULL) {
		if (end != str && *(end-1) != '\\')
			return (end);
		str = end + 1;		/* could point to null-terminator */
	}
	if (end == NULL)
		end = strchr(str, '\0');
	return (end);
}

/*
 * Compresses away any characters escaped with backslash from given string.
 * The string is altered in-place.  Example, "ab\:\\e" becomes "ab:\e".
 */
static void
unescape_str(char *str)
{
	boolean_t	escaped = B_FALSE;
	char		*mark;

	if (str == NULL)
		return;

	for (mark = str; *str != '\0'; str++) {
		if (*str != '\\' || escaped == B_TRUE) {
			*mark++ = *str;
			escaped = B_FALSE;
		} else {
			escaped = B_TRUE;
		}
	}
	*mark = '\0';
}


/*
 * Given a colon-separated token specifier, this functions splits it into
 * its label, manufacturer ID (if any), and serial number (if any).  Literal
 * colons within the label/manuf/serial can be escaped with a backslash.
 * Fields can left blank and trailing colons can be omitted, however leading
 * colons are required as placeholders.  For example, these are equivalent:
 *	(a) "lbl", "lbl:", "lbl::"	(b) "lbl:man", "lbl:man:"
 * but these are not:
 *	(c) "man", ":man"	(d) "ser", "::ser"
 * Furthermore, the token label is required always.
 *
 * The buffer containing the token specifier is altered by replacing the
 * colons to null-terminators, and pointers returned are pointers into this
 * string.  No new memory is allocated.
 */
static int
parse_token_spec(char *token_spec, char **token_name, char **manuf_id,
	char **serial_no)
{
	char	*mark;

	if (token_spec == NULL || *token_spec == '\0') {
		return (-1);
	}

	*token_name = NULL;
	*manuf_id = NULL;
	*serial_no = NULL;

	/* Token label (required) */
	mark = find_unescaped_colon(token_spec);
	*token_name = token_spec;
	if (*mark != '\0')
		*mark++ = '\0';		/* mark points to next field, if any */
	unescape_str(*token_name);

	if (*(*token_name) == '\0') {	/* token label is required */
		return (-1);
	}

	if (*mark == '\0' || *(mark+1) == '\0')		/* no more fields */
		return (0);
	token_spec = mark;

	/* Manufacturer identifier (optional) */
	mark = find_unescaped_colon(token_spec);
	*manuf_id = token_spec;
	if (*mark != '\0')
		*mark++ = '\0';		/* mark points to next field, if any */
	unescape_str(*manuf_id);

	if (*mark == '\0' || *(mark+1) == '\0')		/* no more fields */
		return (0);
	token_spec = mark;

	/* Serial number (optional) */
	mark = find_unescaped_colon(token_spec);
	*serial_no = token_spec;
	if (*mark != '\0')
		*mark++ = '\0';		/* null-terminate, just in case */
	unescape_str(*serial_no);

	return (0);
}

/*
 * Find slots that match a token identifier.  Token labels take the
 * form of:
 *	token_name:manufacturer:serial_number
 * manufacterer and serial number are optional.  If used, the fields
 * are delimited by the colon ':' character.
 */
KMF_RETURN
kmf_pk11_token_lookup(KMF_HANDLE_T handle, char *label, CK_SLOT_ID *slot_id)
{
	KMF_RETURN	kmf_rv = KMF_OK;
	CK_RV		rv;
	CK_SLOT_ID_PTR	slot_list = NULL;
	CK_TOKEN_INFO	token_info;
	CK_ULONG	slot_count = 0;
	int		i;
	uint_t		len, max_sz;
	boolean_t 	metaslot_status_enabled;
	boolean_t 	metaslot_migrate_enabled;
	char	*metaslot_slot_info;
	char	*metaslot_token_info;
	char	*tmplabel = NULL;
	char	*token_name = NULL;
	char	*manuf_id = NULL;
	char	*serial_no = NULL;
	boolean_t	tok_match = B_FALSE;
	boolean_t	man_match = B_FALSE;
	boolean_t	ser_match = B_FALSE;

	if (slot_id == NULL || label == NULL || !strlen(label))
		return (KMF_ERR_BAD_PARAMETER);

	if (handle == NULL) {
		rv = C_Initialize(NULL);
		if ((rv != CKR_OK) &&
		    (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
			return (KMF_ERR_UNINITIALIZED);
		}
	}

	/*
	 * Parse token specifier into token_name, manuf_id, serial_no.
	 * Token_name is required; manuf_id and serial_no are optional.
	 */
	tmplabel = strdup(label);
	if (tmplabel == NULL)
		return (KMF_ERR_MEMORY);

	if (parse_token_spec(tmplabel, &token_name, &manuf_id,
	    &serial_no) < 0) {
		free(tmplabel);
		return (KMF_ERR_BAD_PARAMETER);
	}

	/* Get a list of all slots with tokens present. */
	kmf_rv = kmf_get_token_slots(handle, &slot_list, &slot_count);
	if (kmf_rv != KMF_OK) {
		free(tmplabel);
		return (kmf_rv);
	}

	/* If there are no such slots, the desired token won't be found. */
	if (slot_count == 0) {
		free(tmplabel);
		return (KMF_ERR_TOKEN_NOT_PRESENT);
	}

	/* Search the slot list for the token. */
	for (i = 0; i < slot_count; i++) {
		if (C_GetTokenInfo(slot_list[i], &token_info) != CKR_OK) {
			continue;
		}

		/* See if the token label matches. */
		len = strlen(token_name);
		max_sz = sizeof (token_info.label);
		if (memcmp_pad_max(&(token_info.label), max_sz, token_name,
		    len, max_sz) == 0)
			tok_match = B_TRUE;
		/*
		 * If manufacturer id was given, see if it actually matches.
		 * If no manufacturer id was given, assume match is true.
		 */
		if (manuf_id) {
			len = strlen(manuf_id);
			max_sz = sizeof ((char *)(token_info.manufacturerID));
			if (memcmp_pad_max(&(token_info.manufacturerID), max_sz,
			    manuf_id, len, max_sz) == 0)
				man_match = B_TRUE;
		} else {
			man_match = B_TRUE;
		}

		/*
		 * If serial number was given, see if it actually matches.
		 * If no serial number was given, assume match is true.
		 */
		if (serial_no) {
			len = strlen(serial_no);
			max_sz = sizeof ((char *)(token_info.serialNumber));
			if (memcmp_pad_max(&(token_info.serialNumber), max_sz,
			    serial_no, len, max_sz) == 0)
				ser_match = B_TRUE;
		} else {
			ser_match = B_TRUE;
		}

		if (tok_match && man_match && ser_match)
			break;		/* found it! */
	}

	if (i < slot_count) {
		/* found the desired token from the slotlist */
		*slot_id = slot_list[i];
		free(slot_list);
		free(tmplabel);
		return (KMF_OK);
	}

	/*
	 * If we didn't find the token from the slotlist, check if this token
	 * is the one currently hidden by the metaslot. If that's case,
	 * we can just use the metaslot, the slot 0.
	 */
	kmf_rv = get_metaslot_info(&metaslot_status_enabled,
	    &metaslot_migrate_enabled, &metaslot_slot_info,
	    &metaslot_token_info);
	if (kmf_rv) {
		/*
		 * Failed to get the metaslot info.  This usually means that
		 * metaslot is disabled from the system.
		 */
		kmf_rv = KMF_ERR_TOKEN_NOT_PRESENT;
	} else {
		max_sz = strlen(metaslot_token_info);
		if (memcmp_pad_max(metaslot_token_info, max_sz, token_name, len,
		    max_sz) == 0) {
			*slot_id = slot_list[0];
		} else {
			kmf_rv = KMF_ERR_TOKEN_NOT_PRESENT;
		}
		free(metaslot_slot_info);
		free(metaslot_token_info);
	}

	free(slot_list);
	free(tmplabel);
	return (kmf_rv);
}

KMF_RETURN
kmf_set_token_pin(KMF_HANDLE_T handle,
	int num_attr,
	KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_PLUGIN *plugin;
	KMF_ATTRIBUTE_TESTER required_attrs[] = {
		{KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)},
		{KMF_CREDENTIAL_ATTR, FALSE, sizeof (KMF_CREDENTIAL),
			sizeof (KMF_CREDENTIAL)},
		{KMF_NEWPIN_ATTR, FALSE, sizeof (KMF_CREDENTIAL),
			sizeof (KMF_CREDENTIAL)},
	};

	int num_req_attrs = sizeof (required_attrs) /
	    sizeof (KMF_ATTRIBUTE_TESTER);
	uint32_t len;
	KMF_KEYSTORE_TYPE kstype;

	if (handle == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	ret = test_attributes(num_req_attrs, required_attrs,
	    0, NULL, num_attr, attrlist);
	if (ret != KMF_OK)
		return (ret);

	len = sizeof (kstype);
	ret = kmf_get_attr(KMF_KEYSTORE_TYPE_ATTR, attrlist, num_attr,
	    &kstype, &len);
	if (ret != KMF_OK)
		return (ret);

	plugin = FindPlugin(handle, kstype);
	if (plugin != NULL) {
		if (plugin->funclist->SetTokenPin != NULL)
			return (plugin->funclist->SetTokenPin(handle, num_attr,
			    attrlist));
		else
			return (KMF_ERR_FUNCTION_NOT_FOUND);
	}
	return (KMF_ERR_PLUGIN_NOTFOUND);
}

/*
 * Name: kmf_select_token
 *
 * Description:
 *   This function enables the user of PKCS#11 plugin to select a
 *   particular PKCS#11 token. Valid token label are required in order to
 *   successfully complete this function.
 *   All subsequent KMF APIs, which specify PKCS#11 keystore as
 *   the backend, will be performed at the selected token.
 *
 * Parameters:
 *   label(input) - pointer to the token label
 *
 * Returns:
 *   A KMF_RETURN value indicating success or specifying a particular
 *   error condition.
 *   The value KMF_OK indicates success. All other values represent
 *   an error condition.
 */
KMF_RETURN
kmf_select_token(KMF_HANDLE_T handle, char *label, int readonly)
{
	KMF_RETURN kmf_rv = KMF_OK;
	CK_RV ck_rv = CKR_OK;
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE hSession;
	CK_FLAGS 	openflags;

	CLEAR_ERROR(handle, kmf_rv);
	if (kmf_rv != KMF_OK)
		return (kmf_rv);

	if (label == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	kmf_rv = init_pk11();
	if (kmf_rv != KMF_OK) {
		return (kmf_rv);
	}

	/* Only one token can be active per thread */
	if (handle->pk11handle != 0) {
		return (KMF_ERR_TOKEN_SELECTED);
	}

	/* Find the token with matching label */
	kmf_rv = kmf_pk11_token_lookup(handle, label, &slot_id);
	if (kmf_rv != KMF_OK) {
		return (kmf_rv);
	}

	openflags = CKF_SERIAL_SESSION;
	if (!readonly)
		openflags |= CKF_RW_SESSION;

	/* Open a session then log the user into the token */
	ck_rv = C_OpenSession(slot_id, openflags, NULL, NULL, &hSession);
	if (ck_rv != CKR_OK) {
		handle->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
		handle->lasterr.errcode = ck_rv;
		return (KMF_ERR_INTERNAL);
	}

	handle->pk11handle = hSession;

	return (kmf_rv);
}

CK_SESSION_HANDLE
kmf_get_pk11_handle(KMF_HANDLE_T kmfh)
{
	return (kmfh->pk11handle);
}

KMF_RETURN
kmf_pk11_init_token(KMF_HANDLE_T handle,
	char *currlabel, char *newlabel,
	CK_UTF8CHAR_PTR sopin, CK_ULONG sopinlen)
{
	KMF_RETURN ret = KMF_OK;
	CK_RV ckrv;
	CK_SLOT_ID slot_id = 0;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	/*
	 * It is best to try and lookup tokens by label.
	 */
	if (currlabel != NULL) {
		ret = kmf_pk11_token_lookup(handle, currlabel, &slot_id);
		if (ret != KMF_OK)
			return (ret);
	} else {
		/* We can't determine which slot to initialize */
		return (KMF_ERR_TOKEN_NOT_PRESENT);
	}

	/* Initialize and set the new label (if given) */
	ckrv = C_InitToken(slot_id, sopin, sopinlen,
	    (CK_UTF8CHAR_PTR)(newlabel ? newlabel : currlabel));

	if (ckrv != CKR_OK) {
		if (ckrv == CKR_PIN_INCORRECT)
			return (KMF_ERR_AUTH_FAILED);
		else
			return (KMF_ERR_INTERNAL);
	}

	return (ret);
}
