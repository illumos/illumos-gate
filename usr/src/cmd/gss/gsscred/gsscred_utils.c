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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 *  gsscred utility
 *  Manages mapping between a security principal name and unix uid
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "gsscred.h"

/* From g_glue.c */

extern int
get_der_length(unsigned char **, unsigned int, unsigned int *);

extern unsigned int
der_length_size(unsigned int);

extern int
put_der_length(unsigned int, unsigned char **, unsigned int);



/*
 * GSS export name constants
 */
static const char *expNameTokId = "\x04\x01";
static const int expNameTokIdLen = 2;
static const int mechOidLenLen = 2;
static const int mechOidTagLen = 1;


/*
 * Internal utility routines.
 */

/*
 * gsscred_read_config_file
 *
 * function to read the optional gsscred configuration file
 * which specifies which backend to use to store the gsscred
 * table.
 *
 * we now only support flat files (btw, this file for backend is Obsoleted
 * by PSARC)
 */
int
gsscred_read_config_file(void)
{
	return (GSSCRED_FLAT_FILE);
} /* gsscred_read_config_file */


/*
 * gsscred_MakeName
 *
 * construct a principal name in the GSS_C_NT_EXPORT_NAME format.
 */
int gsscred_MakeName(const gss_OID mechOid, const char *name,
		const char *nameOidStr, gss_buffer_t nameOut)
{
	gss_OID nameOid;
	gss_name_t intName;
	OM_uint32 minor, major;
	gss_buffer_desc aName = GSS_C_EMPTY_BUFFER, oidStr;

	nameOut->length = 0;
	nameOut->value = NULL;

	/* we need to import the name, then canonicalize it, then export it */
	if (nameOidStr == NULL)
		nameOid = (gss_OID)GSS_C_NT_USER_NAME;
	else {
		oidStr.length = strlen(nameOidStr);
		oidStr.value = (void *)nameOidStr;
		if (gss_str_to_oid(&minor, &oidStr, &nameOid) !=
			GSS_S_COMPLETE) {
			(void) fprintf(stderr,
				gettext("\nInvalid name oid supplied [%s].\n"),
				nameOidStr);
			return (0);
		}
	}

	/* first import the name */
	aName.length = strlen(name);
	aName.value = (void*)name;
	major = gss_import_name(&minor, &aName, nameOid, &intName);
	if (nameOidStr != NULL) {
		free(nameOid->elements);
		free(nameOid);
	}

	if (major != GSS_S_COMPLETE) {
		(void) fprintf(stderr,
			gettext("\nInternal error importing name [%s].\n"),
			name);
		return (0);
	}

	/* now canonicalize the name */
	if (gss_canonicalize_name(&minor, intName, mechOid, NULL)
	    != GSS_S_COMPLETE) {
		(void) fprintf(stderr,
			gettext("\nInternal error canonicalizing name"
				" [%s].\n"),
			name);
		(void) gss_release_name(&minor, &intName);
		return (0);
	}

	/* now convert to export format */
	if (gss_export_name(&minor, intName, nameOut) != GSS_S_COMPLETE) {
		(void) fprintf(stderr,
			gettext("\nInternal error exporting name [%s].\n"),
			name);
		(void) gss_release_name(&minor, &intName);
		return (0);
	}

	(void) gss_release_name(&minor, &intName);
	return (1);
} /* *******  makeName ****** */


/*
 * Constructs a part of the GSS_NT_EXPORT_NAME
 * Only the mechanism independent name part is created.
 */
int
gsscred_MakeNameHeader(const gss_OID mechOid, gss_buffer_t outNameHdr)
{
	unsigned char *buf = NULL;
	int mechOidDERLength, mechOidLength;

	/* determine the length of buffer needed */
	mechOidDERLength = der_length_size(mechOid->length);
	outNameHdr->length = mechOidLenLen + mechOidTagLen +
		mechOidDERLength + expNameTokIdLen + mechOid->length;
	if ((outNameHdr->value = (void*)malloc(outNameHdr->length)) == NULL) {
		outNameHdr->length = 0;
		return (0);
	}

	/* start by putting the token id */
	buf = (unsigned char *) outNameHdr->value;
	(void) memset(outNameHdr->value, '\0', outNameHdr->length);
	(void) memcpy(buf, expNameTokId, expNameTokIdLen);
	buf += expNameTokIdLen;

	/*
	 * next 2 bytes contain the mech oid length (includes
	 * DER encoding)
	 */
	mechOidLength =  mechOidTagLen + mechOidDERLength +
				mechOid->length;

	*buf++ = (mechOidLength & 0xFF00) >> 8;
	*buf++ = (mechOidLength & 0x00FF);
	*buf++ = 0x06;
	if (put_der_length(mechOid->length, &buf,
		mechOidDERLength) != 0) {
		/* free the buffer */
		free(outNameHdr->value);
		return (0);
	}

	/* now add the mechanism oid */
	(void) memcpy(buf, mechOid->elements, mechOid->length);

	/* we stop here because the rest is mechanism specific */
	return (1);
} /* gsscred_MakeNameHeader */


/*
 * Converts the supplied string to HEX.
 * The passed in buffer must be twice as long as the input buffer.
 * Long form is used (i.e. '\0' will become '00').  This is needed
 * to enable proper re-parsing of names.
 */
int
gsscred_AsHex(gss_buffer_t dataIn, gss_buffer_t dataOut)
{
	int i;
	char *out, *in;
	unsigned int tmp;

	if (dataOut->length < ((dataIn->length *2) + 1))
		return (0);

	out = (char *)dataOut->value;
	in = (char *)dataIn->value;
	dataOut->length = 0;

	for (i = 0; i < dataIn->length; i++) {
		tmp = (unsigned int)(*in++)&0xff;
		(void) sprintf(out, "%02X", tmp);
		out++;
		out++;
	}
	dataOut->length = out - (char *)dataOut->value;
	*out = '\0';

	return (1);
} /* ******* gsscred_AsHex ******* */


/*
 * GSS entry point for retrieving user uid mappings.
 * The name buffer contains a principal name in exported format.
 */
int
gss_getGssCredEntry(const gss_buffer_t expName, uid_t *uid)
{
	int tableSource;
	unsigned char *buf;
	gss_buffer_desc mechOidDesc = GSS_C_EMPTY_BUFFER,
		mechHexOidDesc = GSS_C_EMPTY_BUFFER,
		expNameHexDesc = GSS_C_EMPTY_BUFFER;
	char oidHexBuf[256], expNameHexBuf[1024];
	unsigned int dummy;
	int len;

	tableSource = gsscred_read_config_file();

	/*
	 * for xfn (ldap?), we must first construct, a hex mechansim oid string
	 */
	if (expName->length < (expNameTokIdLen + mechOidLenLen +
					mechOidTagLen))
	    return (0);

	buf = (unsigned char *)expName->value;
	buf += expNameTokIdLen;

	/* skip oid length - get to der */
	buf++;
	buf++;

	/* skip oid tag */
	buf++;

	/* get oid length */
	len = get_der_length(&buf,
			(expName->length - expNameTokIdLen
			- mechOidLenLen - mechOidTagLen), &dummy);
	if (len  == -1)
		return (0);
	else
		mechOidDesc.length = len;

	if (expName->length <
		(expNameTokIdLen + mechOidLenLen + mechOidDesc.length
			+  dummy+ mechOidTagLen))
		return (0);

	mechOidDesc.value = (void *)buf;

	/* convert the oid buffer to hex */
	mechHexOidDesc.value = (void*) oidHexBuf;
	mechHexOidDesc.length = sizeof (oidHexBuf);
	if (!gsscred_AsHex(&mechOidDesc, &mechHexOidDesc))
		return (0);

	/* also need to convert the name buffer into hex */
	expNameHexDesc.value = expNameHexBuf;
	expNameHexDesc.length = sizeof (expNameHexBuf);
	if (!gsscred_AsHex(expName, &expNameHexDesc))
		return (0);

	if (tableSource == GSSCRED_FLAT_FILE)
		return (file_getGssCredUid(&expNameHexDesc, uid));

	return (0);  /* XXX for new backends (ldap, dss), 0->1 probably */
} /* gss_getGssCredEntry */
