/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the functions that are shared among
 * the various services this tool will ultimately provide.
 * The functions in this file return PKCS#11 CK_RV errors.
 * Only one session and one login per token is supported
 * at this time.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include "common.h"
#include "biginteger.h"

/* True and false for attribute templates. */
CK_BBOOL	pk_true = B_TRUE;
CK_BBOOL	pk_false = B_FALSE;

/* Local status variables. */
static boolean_t	initialized = B_FALSE;
static boolean_t	session_opened = B_FALSE;
static boolean_t	session_writable = B_FALSE;
static boolean_t	logged_in = B_FALSE;

/*
 * Perform PKCS#11 setup here.  Currently only C_Initialize is required,
 * along with setting/resetting state variables.
 */
CK_RV
init_pk11(void)
{
	CK_RV		rv = CKR_OK;

	cryptodebug("inside init_pk11");

	/* If C_Initialize() already called, nothing to do here. */
	if (initialized == B_TRUE)
		return (CKR_OK);

	/* Reset state variables because C_Initialize() not yet done. */
	session_opened = B_FALSE;
	session_writable = B_FALSE;
	logged_in = B_FALSE;

	/* Initialize PKCS#11 library. */
	cryptodebug("calling C_Initialize()");
	if ((rv = C_Initialize(NULL_PTR)) != CKR_OK &&
	    rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		return (rv);
	}

	initialized = B_TRUE;
	return (CKR_OK);
}

/*
 * Finalize PKCS#11 library and reset state variables.  Open sessions,
 * if any, are closed, and thereby any logins are logged out also.
 */
void
final_pk11(CK_SESSION_HANDLE sess)
{
	cryptodebug("inside final_pk11");

	/* If the library wasn't initialized, nothing to do here. */
	if (!initialized)
		return;

	/* Make sure the sesion is closed first. */
	close_sess(sess);

	cryptodebug("calling C_Finalize()");
	(void) C_Finalize(NULL);
	initialized = B_FALSE;
}

/*
 * Create a PKCS#11 session on the given slot, and set state information.
 * If session is already open, check that the read-only/read-write state
 * requested matches that of the session.  If it doesn't, make it so.
 */
CK_RV
open_sess(CK_SLOT_ID slot_id, CK_FLAGS sess_flags, CK_SESSION_HANDLE_PTR sess)
{
	CK_RV		rv = CKR_OK;

	cryptodebug("inside open_sess");

	/* If the session is already open, check the session flags. */
	if (session_opened) {
		/*
		 * If requesting R/W session and it is currently R/O,
		 * need to close the session and reopen it R/W.  The
		 * other cases are considered acceptable:
		 *	sess_flags		current state
		 *	----------		-------------
		 *	~CKF_RW_SESSION		!session_writable
		 *	~CKF_RW_SESSION		session_writable
		 *	CKF_RW_SESSION		session_writable
		 */
		if ((sess_flags & CKF_RW_SESSION) && !session_writable)
			close_sess(*sess);
		else
			return (CKR_OK);
	}

	/* Make sure the PKCS#11 is already initialized. */
	if (!initialized)
		if ((rv = init_pk11()) != CKR_OK)
			return (rv);

	/* Create a session for subsequent operations. */
	cryptodebug("calling C_OpenSession()");
	if ((rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION|sess_flags,
	    NULL, NULL, sess)) != CKR_OK)
		return (rv);
	session_opened = B_TRUE;
	session_writable = (sess_flags & CKF_RW_SESSION) ? B_TRUE : B_FALSE;
	return (CKR_OK);
}

/*
 * Close PKCS#11 session and reset state variables.  Any logins are
 * logged out.
 */
void
close_sess(CK_SESSION_HANDLE sess)
{
	cryptodebug("inside close_sess");

	if (sess == NULL) {
		cryptodebug("session handle is null");
		return;
	}

	/* If session is already closed, nothing to do here. */
	session_writable = B_FALSE;
	if (!session_opened)
		return;

	/* Make sure user is logged out of token. */
	logout_token(sess);

	cryptodebug("calling C_CloseSession()");
	(void) C_CloseSession(sess);
	session_opened = B_FALSE;
}

/*
 * Log user into token in given slot.  If this first login ever for this
 * token, the initial PIN is "changeme", C_Login() will succeed, but all
 * PKCS#11 calls following the C_Login() will fail with CKR_PIN_EXPIRED.
 */
CK_RV
login_token(CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR pin, CK_ULONG pinlen,
	    CK_SESSION_HANDLE_PTR sess)
{
	CK_RV		rv = CKR_OK;

	cryptodebug("inside login_token");

	/* If already logged in, nothing to do here. */
	if (logged_in)
		return (CKR_OK);

	/* Make sure we have a session first, assume R/O is enough. */
	if (!session_opened)
		if ((rv = open_sess(slot_id, CKF_SERIAL_SESSION, sess)) !=
		    CKR_OK)
			return (rv);

	/* Log the user into the token. */
	cryptodebug("calling C_Login()");
	if ((rv = C_Login(*sess, CKU_USER, pin, pinlen)) != CKR_OK) {
		cryptodebug("C_Login returns %s", pkcs11_strerror(rv));
		return (rv);
	}

	logged_in = B_TRUE;
	return (CKR_OK);
}

/*
 * Log user out of token and reset status variable.
 */
void
logout_token(CK_SESSION_HANDLE sess)
{
	cryptodebug("inside logout_token");

	if (sess == NULL) {
		cryptodebug("session handle is null");
		return;
	}

	/* If already logged out, nothing to do here. */
	if (!logged_in)
		return;

	cryptodebug("calling C_Logout()");
	(void) C_Logout(sess);
	logged_in = B_FALSE;
}

/*
 * Shortcut function to get from an uninitialized state to user logged in.
 * If the library is already initialized, the session is already opened,
 * or the user is already logged in, those steps are skipped and the next
 * step is checked.
 */
CK_RV
quick_start(CK_SLOT_ID slot_id, CK_FLAGS sess_flags, CK_UTF8CHAR_PTR pin,
	    CK_ULONG pinlen, CK_SESSION_HANDLE_PTR sess)
{
	CK_RV		rv = CKR_OK;

	cryptodebug("inside quick_start");

	/* Call open_sess() explicitly if R/W session is needed. */
	if (sess_flags & CKF_RW_SESSION)
		if ((rv = open_sess(slot_id, sess_flags, sess)) != CKR_OK)
			return (rv);

	if ((rv = login_token(slot_id, pin, pinlen, sess)) != CKR_OK)
		return (rv);

	return (CKR_OK);
}

/*
 * Shortcut function to go from any state to uninitialized PKCS#11 library.
 */
void
quick_finish(CK_SESSION_HANDLE sess)
{
	cryptodebug("inside quick_finish");

	/* All the needed calls are done implicitly. */
	final_pk11(sess);
}

/*
 * Gets PIN from user.  Caller needs to free the returned PIN when done.
 * If two prompts are given, the PIN is confirmed with second prompt.
 * Note that getphassphrase() may return data in static memory area.
 */
CK_RV
get_pin(char *prompt1, char *prompt2, CK_UTF8CHAR_PTR *pin, CK_ULONG *pinlen)
{
	char		*save_phrase, *phrase1, *phrase2;

	cryptodebug("inside get_pin");

	/* Prompt user for a PIN. */
	if (prompt1 == NULL) {
		cryptodebug("no passphrase prompt given");
		return (CKR_ARGUMENTS_BAD);
	}
	if ((phrase1 = getpassphrase(prompt1)) == NULL) {
		cryptodebug("getpassphrase() failed");
		return (CKR_FUNCTION_FAILED);
	}

	/* Duplicate 1st PIN in separate chunk of memory. */
	if ((save_phrase = strdup(phrase1)) == NULL)
		return (CKR_HOST_MEMORY);

	/* If second prompt given, PIN confirmation is requested. */
	if (prompt2 != NULL) {
		if ((phrase2 = getpassphrase(prompt2)) == NULL) {
			cryptodebug("getpassphrase() confirmation failed");
			free(save_phrase);
			return (CKR_FUNCTION_FAILED);
		}
		if (strcmp(save_phrase, phrase2) != 0) {
			cryptodebug("passphrases do not match");
			free(save_phrase);
			return (CKR_PIN_INCORRECT);
		}
	}

	*pin = (CK_UTF8CHAR_PTR)save_phrase;
	*pinlen = strlen(save_phrase);
	return (CKR_OK);
}

/*
 * Gets yes/no response from user.  If either no prompt is supplied, a
 * default prompt is used.  If not message for invalid input is supplied,
 * a default will not be provided.  If the user provides no response,
 * the input default B_TRUE == yes, B_FALSE == no is returned.
 * Otherwise, B_TRUE is returned for yes, and B_FALSE for no.
 */
boolean_t
yesno(char *prompt, char *invalid, boolean_t dflt)
{
	char		*response, buf[1024];
	char		*yes = gettext("yes");
	char		*no = gettext("no");

	cryptodebug("inside yesno");

	if (prompt == NULL)
		prompt = gettext("Enter (y)es or (n)o? ");

	for (;;) {
		/* Prompt user. */
		(void) printf("%s", prompt);
		(void) fflush(stdout);

		/* Get the response. */
		if ((response = fgets(buf, sizeof (buf), stdin)) == NULL)
			break;		/* go to default response */

		/* Skip any leading white space. */
		while (isspace(*response))
			response++;
		if (*response == '\0')
			break;		/* go to default response */

		/* Is it valid input?  Return appropriately. */
		if (strncasecmp(response, yes, 1) == 0)
			return (B_TRUE);
		if (strncasecmp(response, no, 1) == 0)
			return (B_FALSE);

		/* Indicate invalid input, and try again. */
		if (invalid != NULL)
		    (void) printf("%s", invalid);
	}
	return (dflt);
}

/*
 * Gets the list of slots which have tokens in them.  Keeps adjusting
 * the size of the slot list buffer until the call is successful or an
 * irrecoverable error occurs.
 */
CK_RV
get_token_slots(CK_SLOT_ID_PTR *slot_list, CK_ULONG *slot_count)
{
	CK_ULONG	tmp_count = 0;
	CK_SLOT_ID_PTR	tmp_list = NULL_PTR, tmp2_list = NULL_PTR;
	int		rv = CKR_OK;

	cryptodebug("inside get_token_slots");

	if (!initialized)
		if ((rv = init_pk11()) != CKR_OK)
			return (rv);

	/*
	 * Get the slot count first because we don't know how many
	 * slots there are and how many of those slots even have tokens.
	 * Don't specify an arbitrary buffer size for the slot list;
	 * it may be too small (see section 11.5 of PKCS#11 spec).
	 * Also select only those slots that have tokens in them,
	 * because this tool has no need to know about empty slots.
	 */
	cryptodebug("calling C_GetSlotList() for slot count");
	if ((rv = C_GetSlotList(1, NULL_PTR, &tmp_count)) != CKR_OK)
		return (rv);

	if (tmp_count == 0) {
		cryptodebug("no slots with tokens found");
		*slot_list = NULL_PTR;
		*slot_count = 0;
		return (CKR_OK);
	}

	/* Allocate initial space for the slot list. */
	if ((tmp_list = (CK_SLOT_ID_PTR) malloc(tmp_count *
	    sizeof (CK_SLOT_ID))) == NULL)
		return (CKR_HOST_MEMORY);

	/* Then get the slot list itself. */
	for (;;) {
		cryptodebug("calling C_GetSlotList()");
		if ((rv = C_GetSlotList(1, tmp_list, &tmp_count)) == CKR_OK) {
			*slot_list = tmp_list;
			*slot_count = tmp_count;
			break;
		}

		if (rv != CKR_BUFFER_TOO_SMALL) {
			free(tmp_list);
			break;
		}

		/* If the number of slots grew, try again. */
		cryptodebug("number of tokens present increased");
		if ((tmp2_list = (CK_SLOT_ID_PTR) realloc(tmp_list,
		    tmp_count * sizeof (CK_SLOT_ID))) == NULL) {
			free(tmp_list);
			rv = CKR_HOST_MEMORY;
			break;
		}
		tmp_list = tmp2_list;
	}

	return (rv);
}

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
		return (!0);

	/* If the rest of longer data is nulls or blanks, call it a match. */
	while (len < extra_len)
		if (!isspace(marker[len++]))
			/* CONSTCOND */
			return (!0);
	return (0);
}

/*
 * Locate a token slot whose token matches the label, manufacturer ID, and
 * serial number given.  Token label must be specified, manufacturer ID and
 * serial number are optional.  When the token is located, the PIN state
 * is also returned to determine if it still has the default PIN.
 */
CK_RV
find_token_slot(char *token_name, char *manuf_id, char *serial_no,
		CK_SLOT_ID *slot_id, CK_FLAGS *pin_state)
{
	CK_SLOT_ID_PTR	slot_list;
	CK_TOKEN_INFO	token_info;
	CK_ULONG	slot_count = 0;
	int		rv = CKR_OK;
	int		i;
	uint_t		len, max_sz;
	boolean_t	tok_match = B_FALSE,
			man_match = B_FALSE,
			ser_match = B_FALSE;

	cryptodebug("inside find_token_slot");

	if (token_name == NULL)
		return (CKR_ARGUMENTS_BAD);

	/* Get a list of all slots with tokens present. */
	if ((rv = get_token_slots(&slot_list, &slot_count)) != CKR_OK)
		return (rv);

	/* If there are no such slots, the desired token won't be found. */
	if (slot_count == 0)
		return (CKR_TOKEN_NOT_PRESENT);

	/* Search the slot list for the token. */
	for (i = 0; i < slot_count; i++) {
		cryptodebug("calling C_GetTokenInfo()");
		if ((rv = C_GetTokenInfo(slot_list[i], &token_info)) !=
		    CKR_OK) {
			cryptodebug("token in slot %d returns %s", i,
			    pkcs11_strerror(rv));
			continue;
		}

		/* See if the token label matches. */
		len = strlen(token_name);
		max_sz = sizeof (token_info.label);
		if (memcmp_pad_max(&(token_info.label), max_sz, token_name, len,
		    max_sz) == 0)
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
		} else
			man_match = B_TRUE;

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
		} else
			ser_match = B_TRUE;

		cryptodebug("slot %d:", i);
		cryptodebug("\tlabel = \"%.32s\"%s", token_info.label,
		    tok_match ? " match" : "");
		cryptodebug("\tmanuf = \"%.32s\"%s", token_info.manufacturerID,
		    man_match ? " match" : "");
		cryptodebug("\tserno = \"%.16s\"%s", token_info.serialNumber,
		    ser_match ? " match" : "");
		cryptodebug("\tmodel = \"%.16s\"", token_info.model);

		cryptodebug("\tCKF_USER_PIN_INITIALIZED = %s",
		    (token_info.flags & CKF_USER_PIN_INITIALIZED) ?
		    "true" : "false");
		cryptodebug("\tCKF_USER_PIN_TO_BE_CHANGED = %s",
		    (token_info.flags & CKF_USER_PIN_TO_BE_CHANGED) ?
		    "true" : "false");

		if (tok_match && man_match && ser_match)
			break;		/* found it! */
	}

	/* Scanned the whole list without finding the token. */
	if (i == slot_count) {
		cryptodebug("token not found");
		free(slot_list);
		return (CKR_TOKEN_NOT_PRESENT);
	}

	/* Return slot id where token was found and its PIN state. */
	cryptodebug("token found at slot %d", i);
	*slot_id = slot_list[i];
	*pin_state = (token_info.flags & CKF_USER_PIN_TO_BE_CHANGED);
	free(slot_list);
	return (CKR_OK);
}

/*
 * Constructs a fully qualified token name from its label, manufacturer ID
 * (if any), and its serial number (if any).  Note that the given buf must
 * be big enough.  Do NOT i18n/l10n.
 *
 * FULL_NAME_LEN is defined in common.h to be 91 because a fully qualified
 * token name adds up this way:
 * =32(label) + 32(manuf) + 16(serial) + 4("", ) + 4("", ) + 3("" and nul)
 */
void
full_token_name(char *token_name, char *manuf_id, char *serial_no, char *buf)
{
	char		*marker = buf;
	int		n_written = 0;
	int		space_left = FULL_NAME_LEN;

	if (!token_name)
		return;

	n_written = sprintf(buf, "\"%.32s\"", token_name);
	marker += n_written;
	space_left -= n_written;

	n_written = sprintf(marker, ", \"%.32s\"", manuf_id ? manuf_id : "");
	marker += n_written;
	space_left -= n_written;

	n_written = sprintf(marker, ", \"%.16s\"", serial_no ? serial_no : "");
	marker += n_written;
	space_left -= n_written;

	/* space_left should always be >= 1 */
}

/*
 * Find how many token objects with the given label.
 */
CK_RV
find_obj_count(CK_SESSION_HANDLE sess, int obj_type, CK_BYTE *label,
    CK_ULONG *count)
{
	CK_RV			rv = CKR_OK;
	CK_ATTRIBUTE		attrs[4] = {
		{ CKA_TOKEN, &pk_true, sizeof (pk_true) },
		{ 0, NULL, 0 },
		{ 0, NULL, 0 },
		{ 0, NULL, 0 }
	    };
	CK_ULONG	num_attrs = sizeof (attrs) / sizeof (CK_ATTRIBUTE);
	CK_ULONG	cur_attr = 1;		/* CKA_TOKEN already set */
	CK_OBJECT_CLASS		obj_class;
	CK_OBJECT_HANDLE	tmp_obj;
	CK_ULONG		obj_count = 0;

	cryptodebug("inside find_obj_count");

	if (!session_opened || sess == NULL) {
		cryptodebug("session handle is null");
		return (CKR_SESSION_HANDLE_INVALID);
	}

	if (label) {
		cryptodebug("object label was specified");
		attrs[cur_attr].type = CKA_LABEL;
		attrs[cur_attr].pValue = label;
		attrs[cur_attr].ulValueLen = strlen((char *)label);
		cur_attr++;
	}

	if ((obj_type & PK_PRIVATE_OBJ) && !(obj_type & PK_PUBLIC_OBJ)) {
		cryptodebug("only searching for private objects");
		attrs[cur_attr].type = CKA_PRIVATE;
		attrs[cur_attr].pValue = &pk_true;
		attrs[cur_attr].ulValueLen = sizeof (pk_true);
		cur_attr++;
	}

	/*
	 * If "certs and all keys" is not specified, but at least either
	 * "certs" or some "keys" is specified, then go into this block.
	 * If all certs and keys were specified, there's no point in
	 * putting that fact in the attribute template -- leave that open,
	 * and all certs and keys will be matched automatically.
	 * In other words, only if at least one of 0x10,0x20,0x40,0x80
	 * bits is off, go into this code block.
	 *
	 * NOTE:  For now, only one of cert or key types is allowed.
	 * This needs to change in the future.
	 */
	if ((obj_type & (PK_CERT_OBJ|PK_KEY_OBJ)) != (PK_CERT_OBJ|PK_KEY_OBJ) &&
	    ((obj_type & PK_CERT_OBJ) || (obj_type & PK_KEY_OBJ))) {
		if (obj_type & PK_CERT_OBJ) {
			cryptodebug("only searching for certificates");
			obj_class = CKO_CERTIFICATE;
		} else if (obj_type & PK_PRIKEY_OBJ) {
			cryptodebug("only searching for private keys");
			obj_class = CKO_PRIVATE_KEY;
		} else if (obj_type & PK_PUBKEY_OBJ) {
			cryptodebug("only searching for public keys");
			obj_class = CKO_PUBLIC_KEY;
		} else if (obj_type & PK_SECKEY_OBJ) {
			cryptodebug("only searching for secret keys");
			obj_class = CKO_SECRET_KEY;
		}

		attrs[cur_attr].type = CKA_CLASS;
		attrs[cur_attr].pValue = &obj_class;
		attrs[cur_attr].ulValueLen = sizeof (CK_OBJECT_CLASS);
		cur_attr++;
	}

	/*
	 * This can't happen now.  When finding objects is enhanced in the
	 * future. this could lead to buffer overruns.
	 */
	if (cur_attr > num_attrs)
		cryptodebug("internal error:  attr template overrun");

	cryptodebug("calling C_FindObjectsInit");
	if ((rv = C_FindObjectsInit(sess, attrs, cur_attr)) != CKR_OK)
		return (rv);

	/* Look for the object, checking if there are more than one. */
	cryptodebug("calling C_FindObjects");
	for (*count = 0; /* empty */; (*count)++) {
		if ((rv = C_FindObjects(sess, &tmp_obj, 1, &obj_count)) !=
		    CKR_OK)
			break;

		/* No more found. */
		if (obj_count == 0)
			break;
	}

	cryptodebug("%d matching objects found", *count);

	cryptodebug("calling C_FindObjectsFinal");
	(void) C_FindObjectsFinal(sess);
	return (rv);
}

/*
 * Find the token object with the given label.
 */
CK_RV
find_objs(CK_SESSION_HANDLE sess, int obj_type, CK_BYTE *label,
    CK_OBJECT_HANDLE_PTR *obj, CK_ULONG *count)
{
	CK_RV			rv = CKR_OK;
	CK_ATTRIBUTE		attrs[4] = {
		{ CKA_TOKEN, &pk_true, sizeof (pk_true) },
		{ 0, NULL, 0 },
		{ 0, NULL, 0 },
		{ 0, NULL, 0 }
	    };
	CK_ULONG	num_attrs = sizeof (attrs) / sizeof (CK_ATTRIBUTE);
	CK_ULONG	cur_attr = 1;		/* CKA_TOKEN already set */
	CK_OBJECT_CLASS		obj_class;
	CK_OBJECT_HANDLE	tmp_obj;
	CK_ULONG		obj_count = 0;
	int			i;

	cryptodebug("inside find_obj");

	if ((rv = find_obj_count(sess, obj_type, label, count)) != CKR_OK)
		return (rv);

	if (*count == 0)
		return (CKR_OK);

	if ((*obj = (CK_OBJECT_HANDLE_PTR) malloc((*count) *
	    sizeof (CK_OBJECT_HANDLE))) == NULL) {
		cryptodebug("no memory for found object");
		return (CKR_HOST_MEMORY);
	}

	if (label) {
		cryptodebug("object label was specified");
		attrs[cur_attr].type = CKA_LABEL;
		attrs[cur_attr].pValue = label;
		attrs[cur_attr].ulValueLen = strlen((char *)label);
		cur_attr++;
	}

	if ((obj_type & PK_PRIVATE_OBJ) && !(obj_type & PK_PUBLIC_OBJ)) {
		cryptodebug("only searching for private objects");
		attrs[cur_attr].type = CKA_PRIVATE;
		attrs[cur_attr].pValue = &pk_true;
		attrs[cur_attr].ulValueLen = sizeof (pk_true);
		cur_attr++;
	}

	/*
	 * If "certs and all keys" is not specified, but at least either
	 * "certs" or some "keys" is specified, then go into this block.
	 * If all certs and keys were specified, there's no point in
	 * putting that fact in the attribute template -- leave that open,
	 * and all certs and keys will be matched automatically.
	 * In other words, only if at least one of 0x10,0x20,0x40,0x80
	 * bits is off, go into this code block.
	 *
	 * NOTE:  For now, only one of cert or key types is allowed.
	 * This needs to change in the future.
	 */
	if ((obj_type & (PK_CERT_OBJ|PK_KEY_OBJ)) != (PK_CERT_OBJ|PK_KEY_OBJ) &&
	    ((obj_type & PK_CERT_OBJ) || (obj_type & PK_KEY_OBJ))) {
		if (obj_type & PK_CERT_OBJ) {
			cryptodebug("only searching for certificates");
			obj_class = CKO_CERTIFICATE;
		} else if (obj_type & PK_PRIKEY_OBJ) {
			cryptodebug("only searching for private keys");
			obj_class = CKO_PRIVATE_KEY;
		} else if (obj_type & PK_PUBKEY_OBJ) {
			cryptodebug("only searching for public keys");
			obj_class = CKO_PUBLIC_KEY;
		} else if (obj_type & PK_SECKEY_OBJ) {
			cryptodebug("only searching for secret keys");
			obj_class = CKO_SECRET_KEY;
		}

		attrs[cur_attr].type = CKA_CLASS;
		attrs[cur_attr].pValue = &obj_class;
		attrs[cur_attr].ulValueLen = sizeof (CK_OBJECT_CLASS);
		cur_attr++;
	}

	/*
	 * This can't happen now.  When finding objects is enhanced in the
	 * future. this could lead to buffer overruns.
	 */
	if (cur_attr > num_attrs)
		cryptodebug("internal error:  attr template overrun");

	cryptodebug("calling C_FindObjectsInit");
	if ((rv = C_FindObjectsInit(sess, attrs, cur_attr)) != CKR_OK) {
		free(*obj);
		return (rv);
	}

	/*
	 * Find all the matching objects.  The loop goes 1 more beyond
	 * the number of objects found to determine if any new objects
	 * were created since the time the object count was done.
	 */
	cryptodebug("calling C_FindObjects");
	for (i = 0; i < (*count) + 1; i++) {
		if ((rv = C_FindObjects(sess, &tmp_obj, 1, &obj_count)) !=
		    CKR_OK)
			break;

		/* No more found. */
		if (obj_count == 0)
			break;

		/*
		 * Save the object in the list being created, as long as
		 * we don't overrun the size of the list.
		 */
		if (i < *count)
		    (*obj)[i] = tmp_obj;
		else
		    cryptodebug("number of objects changed since last count");
	}

	if (rv != CKR_OK) {
		free(*obj);
	} else {
		/*
		 * There are three cases to handle:  (1) fewer objects were
		 * found than originally counted => change *count to the
		 * smaller number; (2) the number of objects found matches
		 * the number originally counted => do nothing; (3) more
		 * objects found than originally counted => list passed
		 * in is too small to contain the extra object(s), flag
		 * that in the debug output but don't change number of
		 * objects returned.  The caller can double-check by
		 * calling find_obj_count() after this function to make
		 * sure the numbers match, if desired.
		 */
		/* Case 1:  Fewer objects. */
		if (i < *count) {
			cryptodebug("%d objects found, expected %d", i, *count);
			*count = i;
		/* Case 3:  More objects. */
		} else if (i > *count) {
			cryptodebug("at least %d objects found, expected %d",
			    i, *count);
		}
		/*
		 * Case 2:  Same number of objects.
		 *
		 * else if (i == *count)
		 *	;
		 */
	}

	cryptodebug("calling C_FindObjectsFinal");
	(void) C_FindObjectsFinal(sess);
	return (rv);
}

char *
class_str(CK_OBJECT_CLASS class)
{
	switch (class) {
	case CKO_DATA:		return (gettext("data"));
	case CKO_CERTIFICATE:	return (gettext("certificate"));
	case CKO_PUBLIC_KEY:	return (gettext("public key"));
	case CKO_PRIVATE_KEY:	return (gettext("private key"));
	case CKO_SECRET_KEY:	return (gettext("secret key"));
	case CKO_DOMAIN_PARAMETERS:	return (gettext("domain parameter"));
	default:		return (gettext("unknown object"));
	}
}

char *
keytype_str(CK_KEY_TYPE keytype)
{
	switch (keytype) {
	case CKK_RSA:		return (gettext("RSA"));
	case CKK_DSA:		return (gettext("DSA"));
	case CKK_DH:		return (gettext("Diffie-Hellman"));
	case CKK_X9_42_DH:	return (gettext("X9.42 Diffie-Hellman"));
	case CKK_GENERIC_SECRET:	return (gettext("generic"));
	case CKK_RC2:		return (gettext("RC2"));
	case CKK_RC4:		return (gettext("RC4"));
	case CKK_DES:		return (gettext("DES"));
	case CKK_DES2:		return (gettext("Double-DES"));
	case CKK_DES3:		return (gettext("Triple-DES"));
	case CKK_RC5:		return (gettext("RC5"));
	case CKK_AES:		return (gettext("AES"));
	default:		return (gettext("typeless"));
	}
}

char *
attr_str(CK_ATTRIBUTE_TYPE attrtype)
{
	switch (attrtype) {
	case CKA_PRIVATE:		return (gettext("private"));
	case CKA_LOCAL:			return (gettext("local"));
	case CKA_SENSITIVE:		return (gettext("sensitive"));
	case CKA_EXTRACTABLE:		return (gettext("extractable"));
	case CKA_ENCRYPT:		return (gettext("encrypt"));
	case CKA_DECRYPT:		return (gettext("decrypt"));
	case CKA_WRAP:			return (gettext("wrap"));
	case CKA_UNWRAP:		return (gettext("unwrap"));
	case CKA_SIGN:			return (gettext("sign"));
	case CKA_SIGN_RECOVER:		return (gettext("sign-recover"));
	case CKA_VERIFY:		return (gettext("verify"));
	case CKA_VERIFY_RECOVER:	return (gettext("verify-recover"));
	case CKA_DERIVE:		return (gettext("derive"));
	case CKA_ALWAYS_SENSITIVE:	return (gettext("always sensitive"));
	case CKA_NEVER_EXTRACTABLE:	return (gettext("never extractable"));
	default:		return (gettext("unknown capability"));
	}
}

/*
 * Convert a byte string into a string of octets formatted like this:
 *	oo oo oo oo oo ... oo
 * where each "oo" is an octet is space separated and in the form:
 *	[0-f][0-f] if the octet is a non-printable character
 *	<space><char> if the octet is a printable character
 *
 * Note:  octets_sz must be 3 * str_sz + 1, or at least as long as "blank"
 */
void
octetify(CK_BYTE *str, CK_ULONG str_sz, char *octets, int octets_sz,
    boolean_t stop_on_nul, boolean_t do_ascii, int limit, char *indent,
    char *blank)
{
	char		*marker;
	int		nc;
	int		newline;
	int		indent_len;
	boolean_t	first = B_TRUE;

	cryptodebug("inside octetify");

	cryptodebug(stop_on_nul ? "stopping on first nul found" :
	    "continuing to full length of buffer");
	cryptodebug(do_ascii ? "using ascii chars where printable" :
	    "using only hex octets");
	cryptodebug("every %d characters indent with \"%s\"\n ", limit, indent);
	cryptodebug("return \"%s\" if buffer is null or empty", blank);

	/* If string is empty, write as much of the blank string and leave. */
	if (str_sz == 0) {
		(void) snprintf(octets, octets_sz, "%s", blank);
		return;
	}

	/* If only limit or indent is set, pick default for the other. */
	if (limit > 0 && indent == NULL)
		indent = "\n";
	if (indent != NULL && limit == 0)
		limit = 60;
	indent_len = strlen(indent);

	for (marker = octets, newline = 0, first = B_TRUE;
	    (stop_on_nul && *str != '\0') ||
	    (!stop_on_nul && str_sz > 0 && octets_sz > 0);
	    str++, str_sz--, marker += nc, octets_sz -= nc) {
		if (!first) {
			if (limit > 0 && ((marker - octets) / limit) >
			    newline) {
				nc = snprintf(marker, indent_len, "%s", indent);
				newline++;
				continue;
			}
			nc = sprintf(marker,
			    ((do_ascii && isprint(*str) && !isspace(*str)) ?
			    "%s%c" : "%s%02x"), (do_ascii ? " " : ":"), *str);
		} else {
			nc = sprintf(marker,
			    ((do_ascii && isprint(*str) && !isspace(*str)) ?
			    "%c" : "%02x"), *str);
			first = B_FALSE;
		}
	}
	*marker = '\0';
}

/*
 * Copies a biginteger_t to a template attribute.
 * Should be a macro instead of a function.
 */
void
copy_bigint_to_attr(biginteger_t big, CK_ATTRIBUTE_PTR attr)
{
	attr->pValue = big.big_value;
	attr->ulValueLen = big.big_value_len;
}

/*
 * Copies a string and its length to a template attribute.
 * Should be a macro instead of a function.
 */
void
copy_string_to_attr(CK_BYTE *buf, CK_ULONG buflen, CK_ATTRIBUTE_PTR attr)
{
	attr->pValue = buf;
	attr->ulValueLen = buflen;
}

/*
 * Copies a template attribute to a biginteger_t.
 * Should be a macro instead of a function.
 */
void
copy_attr_to_bigint(CK_ATTRIBUTE_PTR attr, biginteger_t *big)
{
	big->big_value = attr->pValue;
	big->big_value_len = attr->ulValueLen;
}

/*
 * Copies a template attribute to a string and its length.
 * Should be a macro instead of a function.
 */
void
copy_attr_to_string(CK_ATTRIBUTE_PTR attr, CK_BYTE **buf, CK_ULONG *buflen)
{
	*buf = attr->pValue;
	*buflen = attr->ulValueLen;
}

/*
 * Copies a template attribute to a date and its length.
 * Should be a macro instead of a function.
 */
void
copy_attr_to_date(CK_ATTRIBUTE_PTR attr, CK_DATE **buf, CK_ULONG *buflen)
{
	*buf = (CK_DATE *)attr->pValue;
	*buflen = attr->ulValueLen;
}
