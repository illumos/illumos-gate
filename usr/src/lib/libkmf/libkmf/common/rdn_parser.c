/*
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are
 * Copyright (C) 1994-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable
 * instead of those above.  If you wish to allow use of your
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 *
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018, Joyent, Inc.
 *
 * File: rdn_parser.c
 */

#include <strings.h>
#include <stdlib.h>
#include <kmfapi.h>
#include <kmfapiP.h>
#include <ber_der.h>
#include <rdn_parser.h>
#include <stdio.h>
#include <values.h>
#include <libcustr.h>

/*
 * The order here is important.  The OIDs are arranged in order of
 * significance.  The CN is the most specific value, the C (country)
 * is less specific, etc.  Add to this list with care.
 */
static const struct NameToKind name2kinds[] = {
{ "CN",		OID_AVA_COMMON_NAME,	(KMF_OID *)&KMFOID_CommonName},
{ "SN",		OID_AVA_SURNAME,	(KMF_OID *)&KMFOID_Surname},
{ "GN",		OID_AVA_GIVEN_NAME,	(KMF_OID *)&KMFOID_GivenName},
{ "emailAddress", OID_PKCS9_EMAIL_ADDRESS, (KMF_OID *)&KMFOID_EmailAddress},
{ "E",		OID_PKCS9_EMAIL_ADDRESS, (KMF_OID *)&KMFOID_EmailAddress},
{ "MAIL",	OID_RFC1274_MAIL,	(KMF_OID *)&KMFOID_RFC822mailbox},
{ "STREET",	OID_AVA_STREET_ADDRESS, (KMF_OID *)&KMFOID_StreetAddress},
{ "UID",	OID_RFC1274_UID,	(KMF_OID *)&KMFOID_userid},
{ "OU",		OID_AVA_ORGANIZATIONAL_UNIT_NAME,
			(KMF_OID *)&KMFOID_OrganizationalUnitName},
{ "O",		OID_AVA_ORGANIZATION_NAME, (KMF_OID *)&KMFOID_OrganizationName},
{ "L",		OID_AVA_LOCALITY,	(KMF_OID *)&KMFOID_LocalityName},
{ "ST",		OID_AVA_STATE_OR_PROVINCE,
	(KMF_OID *)&KMFOID_StateProvinceName},
{ "C",		OID_AVA_COUNTRY_NAME,	(KMF_OID *)&KMFOID_CountryName},
{ "DC",		OID_AVA_DC,		(KMF_OID *)&KMFOID_domainComponent},
{ 0,		OID_UNKNOWN, NULL}
};

static KMF_BOOL
IsPrintable(unsigned char *data, unsigned len)
{
	unsigned char ch, *end;

	end = data + len;
	while (data < end) {
		ch = *data++;
		if (!IS_PRINTABLE(ch)) {
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

static KMF_BOOL
Is7Bit(unsigned char *data, unsigned len)
{
	unsigned char ch, *end;

	end = data + len;
	while (data < end) {
		ch = *data++;
		if ((ch & 0x80)) {
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

static void
skipSpace(char **pbp, char *endptr)
{
	char *bp = *pbp;
	while (bp < endptr && OPTIONAL_SPACE(*bp)) {
		bp++;
	}
	*pbp = bp;
}

static KMF_RETURN
scanTag(char **pbp, char *endptr, char *tagBuf, int tagBufSize)
{
	char *bp, *tagBufp;
	int taglen;

	if (tagBufSize <= 0)
		return (KMF_ERR_INTERNAL);

	/* skip optional leading space */
	skipSpace(pbp, endptr);
	if (*pbp == endptr) {
		/* nothing left */
		return (KMF_ERR_RDN_PARSER);
	}

	/* fill tagBuf */
	taglen = 0;
	bp = *pbp;
	tagBufp = tagBuf;
	while (bp < endptr && !OPTIONAL_SPACE(*bp) && (*bp != C_EQUAL)) {
		if (++taglen >= tagBufSize) {
			*pbp = bp;
			return (KMF_ERR_RDN_PARSER);
		}
		*tagBufp++ = *bp++;
	}
	/* null-terminate tagBuf -- guaranteed at least one space left */
	*tagBufp++ = 0;
	*pbp = bp;

	/*
	 * skip trailing spaces till we hit something - should be
	 * an equal sign
	 */
	skipSpace(pbp, endptr);
	if (*pbp == endptr) {
		/* nothing left */
		return (KMF_ERR_RDN_PARSER);
	}
	if (**pbp != C_EQUAL) {
		/* should be an equal sign */
		return (KMF_ERR_RDN_PARSER);
	}
	/* skip over the equal sign */
	(*pbp)++;

	return (KMF_OK);
}

static KMF_RETURN
scanVal(char **pbp, char *endptr, char *valBuf, int valBufSize)
{
	char *bp, *valBufp;
	int vallen;
	boolean_t isQuoted;

	if (valBufSize <= 0)
		return (KMF_ERR_INTERNAL);

	/* skip optional leading space */
	skipSpace(pbp, endptr);
	if (*pbp == endptr) {
		/* nothing left */
		return (KMF_ERR_RDN_PARSER);
	}

	bp = *pbp;

	/* quoted? */
	if (*bp == C_DOUBLE_QUOTE) {
		isQuoted = B_TRUE;
		/* skip over it */
		bp++;
	} else {
		isQuoted = B_FALSE;
	}

	valBufp = valBuf;
	vallen = 0;
	while (bp < endptr) {
		char c = *bp;
		if (c == C_BACKSLASH) {
			/* escape character */
			bp++;
			if (bp >= endptr) {
				/*
				 * escape charater must appear with paired char
				 */
				*pbp = bp;
				return (KMF_ERR_RDN_PARSER);
			}
		} else if (!isQuoted && SPECIAL_CHAR(c)) {
			/* unescaped special and not within quoted value */
			break;
		} else if (c == C_DOUBLE_QUOTE) {
			/* reached unescaped double quote */
			break;
		}
		/* append character */
		vallen++;
		if (vallen >= valBufSize) {
			*pbp = bp;
			return (KMF_ERR_RDN_PARSER);
		}
		*valBufp++ = *bp++;
	}

	/* stip trailing spaces from unquoted values */
	if (!isQuoted) {
		if (valBufp > valBuf) {
			valBufp--;
			while ((valBufp > valBuf) && OPTIONAL_SPACE(*valBufp)) {
				valBufp--;
			}
			valBufp++;
		}
	}

	if (isQuoted) {
		/* insist that we stopped on a double quote */
		if (*bp != C_DOUBLE_QUOTE) {
			*pbp = bp;
			return (KMF_ERR_RDN_PARSER);
		}
		/* skip over the quote and skip optional space */
		bp++;
		skipSpace(&bp, endptr);
	}

	*pbp = bp;

	if (valBufp == valBuf) {
		/* empty value -- not allowed */
		return (KMF_ERR_RDN_PARSER);
	}

	/* null-terminate valBuf -- guaranteed at least one space left */
	*valBufp++ = 0;

	return (KMF_OK);
}

static KMF_RETURN
CreateRDN(KMF_X509_TYPE_VALUE_PAIR *ava, KMF_X509_RDN *newrdn)
{
	/* Each RDN has 1 AttrTypeAndValue */
	(void) memset(newrdn, 0, sizeof (KMF_X509_RDN));
	newrdn->numberOfPairs = 1;
	newrdn->AttributeTypeAndValue = ava;

	return (KMF_OK);
}

static KMF_RETURN
copy_oid(KMF_OID *dst, KMF_OID *src)
{
	KMF_RETURN ret = KMF_OK;

	if (dst == NULL || src == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	dst->Data = malloc(src->Length);
	if (dst->Data == NULL)
		return (KMF_ERR_MEMORY);

	dst->Length = src->Length;
	(void) memcpy(dst->Data, src->Data, src->Length);

	return (ret);
}

static KMF_RETURN
CreateAVA(KMF_OID *oid, int valueType, char *value,
    KMF_X509_TYPE_VALUE_PAIR **newava)
{
	int rv = KMF_OK;
	KMF_X509_TYPE_VALUE_PAIR *ava = NULL;

	*newava = NULL;
	ava = (KMF_X509_TYPE_VALUE_PAIR*) malloc(
	    sizeof (KMF_X509_TYPE_VALUE_PAIR));
	if (ava == NULL) {
		return (KMF_ERR_MEMORY);
	} else {
		(void) memset(ava, 0, sizeof (KMF_X509_TYPE_VALUE_PAIR));
		ava->valueType = valueType;
		ava->value.Data = malloc(strlen(value));
		if (ava->value.Data == NULL) {
			free(ava);
			return (KMF_ERR_MEMORY);
		}
		(void) memcpy(ava->value.Data, value, strlen(value));
		ava->value.Length = strlen(value);

		rv = copy_oid(&ava->type, oid);
		if (rv != KMF_OK) {
			/* Illegal AVA type */
			free(ava->value.Data);
			free(ava);
			return (rv);
		}
	}
	*newava = ava;

	return (rv);
}

static KMF_RETURN
ParseRdnAttribute(char **pbp, char *endptr, boolean_t singleAVA,
    KMF_X509_TYPE_VALUE_PAIR **a)
{
	KMF_RETURN rv;
	const struct NameToKind *n2k;
	int vt;
	int valLen;
	char *bp;

	char tagBuf[32];
	char valBuf[384];

	rv = scanTag(pbp, endptr, tagBuf, sizeof (tagBuf));
	if (rv != KMF_OK)
		return (rv);
	rv = scanVal(pbp, endptr, valBuf, sizeof (valBuf));
	if (rv != KMF_OK)
		return (rv);

	/* insist that if we haven't finished we've stopped on a separator */
	bp = *pbp;
	if (bp < endptr) {
		if (singleAVA || (*bp != ',' && *bp != ';')) {
			*pbp = bp;
			return (KMF_ERR_RDN_ATTR);
		}
		/* ok, skip over separator */
		bp++;
	}
	*pbp = bp;

	for (n2k = name2kinds; n2k->name; n2k++) {
		if (strcasecmp(n2k->name, tagBuf) == 0) {
			valLen = strlen(valBuf);
			if (n2k->kind == OID_AVA_COUNTRY_NAME) {
				vt = BER_PRINTABLE_STRING;
				if (valLen != 2) {
					return (KMF_ERR_RDN_ATTR);
				}
				if (!IsPrintable((unsigned char *) valBuf, 2)) {
					return (KMF_ERR_RDN_ATTR);
				}
			} else if ((n2k->kind == OID_PKCS9_EMAIL_ADDRESS) ||
			    (n2k->kind == OID_RFC1274_MAIL)) {
				vt = BER_IA5STRING;
			} else {
				/*
				 * Hack -- for rationale see X.520
				 * DirectoryString defn
				 */
				if (IsPrintable((unsigned char *)valBuf,
				    valLen)) {
					vt = BER_PRINTABLE_STRING;
				} else if (Is7Bit((unsigned char *)valBuf,
				    valLen)) {
					vt = BER_T61STRING;
				}
			}
			rv = CreateAVA(n2k->OID, vt, (char *)valBuf, a);
			return (rv);
		}
	}
	/* matched no kind -- invalid tag */
	return (KMF_ERR_RDN_ATTR);
}

static int
rdnavcompare(const void *a, const void *b)
{
	KMF_X509_RDN *r1, *r2;
	KMF_X509_TYPE_VALUE_PAIR *av1, *av2;
	int i, p1, p2;
	const struct NameToKind *n2k;
	KMF_OID *oidrec;

	r1 = (KMF_X509_RDN *)a;
	r2 = (KMF_X509_RDN *)b;

	av1 = r1->AttributeTypeAndValue;
	av2 = r2->AttributeTypeAndValue;

	p1 = p2 = MAXINT;
	/*
	 * The "Name2Kinds" list is ordered by significance.
	 * Compare the "ranking" of each of the OIDs to determine
	 * the result.
	 */
	for (n2k = name2kinds, i = 0;
	    n2k->name && (p1 == MAXINT || p2 == MAXINT);
	    n2k++, i++) {
		oidrec = n2k->OID;
		if (oidrec != NULL) {
			if (IsEqualOid(&av1->type, oidrec))
				p1 = i;
			if (IsEqualOid(&av2->type, oidrec))
				p2 = i;
		}
	}

	if (p1 > p2)
		return (-1);
	else if (p1 < p2)
		return (1);
	else  /* If equal, treat as if it is less than */
		return (1);
}

static KMF_RETURN
ParseDistinguishedName(char *buf, int len, KMF_X509_NAME *name)
{
	KMF_RETURN rv = KMF_OK;
	char *bp, *e;
	KMF_X509_TYPE_VALUE_PAIR *ava = NULL;
	KMF_X509_RDN rdn;

	(void) memset(name, 0, sizeof (KMF_X509_NAME));
	e = buf + len;
	bp = buf;
	while (bp < e) {
		rv = ParseRdnAttribute(&bp, e, B_FALSE, &ava);
		if (rv != KMF_OK) goto loser;
		rv = CreateRDN(ava, &rdn);
		if (rv != KMF_OK) goto loser;
		if (AddRDN(name, &rdn) != KMF_OK) goto loser;
		skipSpace(&bp, e);
	}

	/*
	 * Canonicalize the DN by sorting the elements
	 * in little-endian order, as per RFC 1485:
	 * "The name is presented/input in a little-endian
	 * order (most significant component last)."
	 */
	qsort((void *)name->RelativeDistinguishedName,
	    name->numberOfRDNs, sizeof (KMF_X509_RDN), rdnavcompare);

	/* return result */
	return (rv);

loser:
	kmf_free_dn(name);
	return (rv);
}

static KMF_BOOL
IsEqualData(KMF_DATA *d1, KMF_DATA *d2)
{
	return ((d1->Length == d2->Length) &&
	    !memcmp(d1->Data, d2->Data, d1->Length));
}

/*
 * Generic routine to compare 2 RDN structures.
 *
 * Because the ordering of the AV pairs may not be
 * the same, we must compare each AV pair individually
 *
 * Return 0 if equal, 1 if not.
 */
int
kmf_compare_rdns(KMF_X509_NAME *name1, KMF_X509_NAME *name2)
{
	int i, j;
	boolean_t avfound;
	KMF_X509_RDN *r1, *r2;
	KMF_X509_TYPE_VALUE_PAIR *av1, *av2;

	if (name1 == NULL || name2 == NULL)
		return (1);

	if (name1->numberOfRDNs != name2->numberOfRDNs)
		return (1);

	for (i = 0; i < name1->numberOfRDNs; i++) {
		r1 = (KMF_X509_RDN *)&name1->RelativeDistinguishedName[i];
		av1 = (KMF_X509_TYPE_VALUE_PAIR *)r1->AttributeTypeAndValue;

		avfound = FALSE;
		for (j = 0; j < name2->numberOfRDNs && !avfound; j++) {
			r2 = (KMF_X509_RDN *)
			    &name2->RelativeDistinguishedName[j];
			av2 = (KMF_X509_TYPE_VALUE_PAIR *)
			    r2->AttributeTypeAndValue;

			avfound = (IsEqualOid(&av1->type, &av2->type) &&
			    IsEqualData(&av1->value, &av2->value));
		}
		/*
		 * If the current AV from name1 was not found in name2,
		 * we are done.
		 */
		if (!avfound)
			return (1);
	}

	/* If we got this far, it must be a match */
	return (0);
}

/*
 * kmf_dn_parser
 *
 * Public interface for parsing a Distinguished name in
 * human-readable format into a binary KMF_X509_NAME.
 */
KMF_RETURN
kmf_dn_parser(char *string, KMF_X509_NAME *name)
{
	KMF_RETURN err;

	if (string == NULL || name == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	err = ParseDistinguishedName(string, (int)strlen(string), name);
	return (err);
}

static const char hexdigits[] = "0123456789abcdef";

static KMF_RETURN
binvalue_to_string(KMF_DATA *data, custr_t *str)
{
	size_t i;
	uchar_t c;

	if (custr_appendc(str, '#') != 0)
		return (KMF_ERR_MEMORY);

	for (i = 0; i < data->Length; i++) {
		c = data->Data[i];
		if (custr_appendc(str, hexdigits[(c >> 4) & 0xf]) != 0 ||
		    custr_appendc(str, hexdigits[(c & 0xf)]) != 0) {
			return (KMF_ERR_MEMORY);
		}
	}

	return (KMF_OK);
}

/*
 * Convert an RDN value into a printable name with appropriate escaping.
 * The rules are taken from RFC4514.  While it is dealing with LDAP
 * distinguished names, both LDAP and x509 certificates are based on the
 * same underlying ITU standards, and as far as I can determine, the same
 * rules apply (or at least the rules for LDAP DNs apply the same to x509
 * DNs).
 */
static KMF_RETURN
value_to_string(KMF_DATA *data, custr_t *str)
{
	size_t i;
	uchar_t c;

	for (i = 0; i < data->Length; i++) {
		c = data->Data[i];

		/*
		 * While technically not required, it is suggested that
		 * printable non-ascii characters (e.g. multi-byte UTF-8
		 * characters) are converted as escaped hex (as well as
		 * unprintable characters).  AFAIK there is no one canonical
		 * string representation (e.g. attribute names are case
		 * insensitive, so 'CN=foo' and 'cn=foo' convert to the same
		 * binary representation, but there is nothing to say if
		 * either string form is canonical), so this shouldn't
		 * pose a problem.
		 */
		if (c < ' ' || c >= 0x7f) {
			/*
			 * RFC4514 specifies the hex form in a DN string as
			 * \{hex}{hex}. OpenSSL uses capitals for A-F so we
			 * do the same.
			 */
			if (custr_append_printf(str, "\\%02hhX", c) != 0)
				return (KMF_ERR_MEMORY);
			continue;
		}

		switch (c) {
		case '#':
			/* Escape # if at the start of a value */
			if (i != 0)
				break;
			/* FALLTHROUGH */
		case ' ':
			/* Escape ' ' if at the start or end of a value */
			if (i != 0 && i + 1 != data->Length)
				break;
			/* FALLTHROUGH */
		case '"':
		case '+':
		case ',':
		case ';':
		case '<':
		case '>':
		case '\\':
			/* Escape these */
			if (custr_appendc(str, '\\') != 0)
				return (KMF_ERR_MEMORY);
		}

		if (custr_appendc(str, c) != 0)
			return (KMF_ERR_MEMORY);
	}

	return (KMF_OK);
}

/*
 * Translate an attribute/value pair into a string.  If the attribute OID
 * is a well known OID (in name2kinds) we use the name instead of the OID.
 */
static KMF_RETURN
ava_to_string(KMF_X509_TYPE_VALUE_PAIR *tvp, custr_t *str)
{
	KMF_OID *kind_oid;
	KMF_OID *rdn_oid = &tvp->type;
	const char *attr = NULL;
	size_t i;
	KMF_RETURN ret = KMF_OK;
	boolean_t found = B_FALSE;

	for (i = 0; name2kinds[i].name != NULL; i++) {
		kind_oid = name2kinds[i].OID;

		if (!IsEqualOid(kind_oid, rdn_oid))
			continue;

		attr = name2kinds[i].name;
		found = B_TRUE;
		break;
	}

	if (!found && (attr = kmf_oid_to_string(rdn_oid)) == NULL) {
		ret = KMF_ERR_MEMORY;
		goto done;
	}
	if (custr_append(str, attr) != 0) {
		ret = KMF_ERR_MEMORY;
		goto done;
	}
	if (custr_appendc(str, '=') != 0) {
		ret = KMF_ERR_MEMORY;
		goto done;
	}

	/*
	 * RFC4514 indicates that an oid=value pair should have the value
	 * printed as #xxxxxx.  In addition, we also print as a binary
	 * value if the BER tag does not indicate the value is some sort
	 * of printable string.
	 */
	switch (tvp->valueType) {
	case BER_UTF8_STRING:
	case BER_PRINTABLE_STRING:
	case BER_T61STRING:
	case BER_IA5STRING:
		if (found) {
			ret = value_to_string(&tvp->value, str);
			break;
		}
		/*FALLTHROUGH*/
	default:
		ret = binvalue_to_string(&tvp->value, str);
		break;
	}

done:
	if (!found)
		free((void *)attr);

	return (ret);
}

static KMF_RETURN
rdn_to_string(KMF_X509_RDN *rdn, custr_t *str)
{
	KMF_RETURN ret;
	size_t i;

	for (i = 0; i < rdn->numberOfPairs; i++) {
		if (i > 0 && custr_appendc(str, '+') != 0)
			return (KMF_ERR_MEMORY);

		ret = ava_to_string(&rdn->AttributeTypeAndValue[i], str);
		if (ret != KMF_OK)
			return (ret);
	}

	return (KMF_OK);
}

/*
 * kmf_dn_to_string
 *
 * Take a binary KMF_X509_NAME and convert it into a human readable string.
 */
KMF_RETURN
kmf_dn_to_string(KMF_X509_NAME *name, char **string)
{
	custr_t *str = NULL;
	KMF_RETURN err = KMF_OK;
	size_t i;

	if (name == NULL || string == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	*string = NULL;

	if (custr_alloc(&str) != 0)
		return (KMF_ERR_MEMORY);

	for (i = 0; i < name->numberOfRDNs; i++) {
		KMF_X509_RDN *rdn = &name->RelativeDistinguishedName[i];

		if (i > 0 && custr_append(str, ", ") != 0) {
			err = KMF_ERR_MEMORY;
			goto done;
		}

		if ((err = rdn_to_string(rdn, str)) != KMF_OK)
			goto done;
	}

	if ((*string = strdup(custr_cstr(str))) == NULL)
		err = KMF_ERR_MEMORY;

done:
	custr_free(str);
	return (err);
}
