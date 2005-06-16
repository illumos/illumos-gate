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
 * derparse.c - Functions for parsing DER-encoded data
 *
 * NOTE:  This code was originally written by Cryptographic Products
 * Group at Sun Microsystems for the SCA 1000 "realmparse" program.
 * It is mostly intact except for necessary adaptaions to allow it to
 * compile in this environment.
 */

#include <errno.h>
#include <fcntl.h>
#include <lber.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cryptoutil.h>
#include "derparse.h"

/* I18N helpers. */
#include <libintl.h>
#include <locale.h>

/*
 * Some types that we need below.
 */
typedef struct oidinfo {
	uint8_t		*value;		/* OID value in bytes */
	size_t		length;		/* Length of OID */
	char		*strval;	/* String rep. for OID in RDN */
} oidinfo_t;

/*
 * X.509 Issuer OIDs as recommended by RFC 3280
 * We might see these in certificates in their subject an issuer names.
 */
static uint8_t common_name_oid[] =	{0x55, 0x04, 0x03};
static uint8_t surname_oid[] =		{0x55, 0x04, 0x04};
static uint8_t serial_number_oid[] =	{0x55, 0x04, 0x05};
static uint8_t country_name_oid[] =	{0x55, 0x04, 0x06};
static uint8_t locality_name_oid[] =	{0x55, 0x04, 0x07};
static uint8_t state_name_oid[] =	{0x55, 0x04, 0x08};
static uint8_t org_name_oid[] =		{0x55, 0x04, 0x0a};
static uint8_t org_unit_name_oid[] =	{0x55, 0x04, 0x0b};
static uint8_t title_oid[] =		{0x55, 0x04, 0x0c};
static uint8_t name_oid[] =		{0x55, 0x04, 0x29};
static uint8_t given_name_oid[] =	{0x55, 0x04, 0x2a};
static uint8_t initials_oid[] =		{0x55, 0x04, 0x2b};
static uint8_t gen_qual_oid[] =		{0x55, 0x04, 0x2c};
static uint8_t dn_qual_oid[] =		{0x55, 0x04, 0x2e};
static uint8_t pseudonym_oid[] =	{0x55, 0x04, 0x31};
static uint8_t uid_oid[] =
	{0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01};
static uint8_t domain_comp_oid[] =
	{0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19};
static uint8_t email_addr_oid[] =
	{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01};

/* Define this structure so we can match on a given oid */
static oidinfo_t	oids[] = {
	{common_name_oid, sizeof (common_name_oid), "CN"},
	{surname_oid, sizeof (surname_oid), "SN"},
	{serial_number_oid, sizeof (serial_number_oid), "SerialNum"},
	{country_name_oid, sizeof (country_name_oid), "C"},
	{locality_name_oid, sizeof (locality_name_oid), "L"},
	{state_name_oid, sizeof (state_name_oid), "ST"},
	{org_name_oid, sizeof (org_name_oid), "O"},
	{org_unit_name_oid, sizeof (org_unit_name_oid), "OU"},
	{title_oid, sizeof (title_oid), "Title"},
	{name_oid, sizeof (name_oid), "Name"},
	{given_name_oid, sizeof (given_name_oid), "GN"},
	{initials_oid, sizeof (initials_oid), "Initials"},
	{gen_qual_oid, sizeof (gen_qual_oid), "GenQual"},
	{dn_qual_oid, sizeof (dn_qual_oid), "DNQual"},
	{pseudonym_oid, sizeof (pseudonym_oid), "Pseudonym"},
	{uid_oid, sizeof (uid_oid), "UID"},
	{domain_comp_oid, sizeof (domain_comp_oid), "DC"},
	{email_addr_oid, sizeof (email_addr_oid), "E"}
};
static int	oidblocklen = sizeof (oids) / sizeof (oidinfo_t);

/* Local functions */
static int oid_to_str(uint8_t *, size_t, char *, size_t);
static int get_oid_type(char *);

/*
 * An RDNSequence is what is handed to us when we get attributes like
 * CKA_ISSUER and CKA_SUBJECT_NAME.  This function will take in a buffer
 * with the DER encoded bytes of an RDNSequence and print out the components.
 *
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 * RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
 *
 * AttributeTypeAndValue ::= SEQUENCE {
 *      type    AttributeType,
 *      value    AttributeValue
 * }
 *
 * AttributeType ::= OBJECT IDENTIFIER
 *
 * AttributeValue ::= ANY DEFINED BY AttributeType
 */
void
rdnseq_to_str(uchar_t *derdata, size_t dersz, char *out, size_t outsz)
{
#define	PKTOOL_LINEMAX		1024
	char			oidout[PKTOOL_LINEMAX];
	BerElement		*ber = NULL;
	BerValue		ber_rdns;
	int			tag;
	ber_len_t		size;
	char			*atv_type = NULL;	/* Attribute Type */
	ber_len_t		atv_type_size;
	char			*atv_value = NULL;	/* Attribute Value */
	ber_len_t		atv_value_size;
	char			*cookie = NULL;
	int			idx;
	char			*prndata = NULL;
	int			prnsz;
	int			offset = 0;
	boolean_t		first = B_TRUE;

	cryptodebug("inside rdnseq_to_str");

	if (derdata == NULL || dersz == 0) {
		cryptodebug("nothing to parse");
		return;
	}

	/* Take the raw bytes and stuff them into a BerValue structure */
	ber_rdns.bv_val = (char *)derdata;
	ber_rdns.bv_len = dersz;

	/* Allocate the BerElement */
	if ((ber = ber_init(&ber_rdns)) == NULLBER) {
		cryptodebug("ber_init failed to return ber element");
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to begin parsing RDNSequence."));
		return;
	}

	/* Begin by parsing out the outer sequence */
	tag = ber_next_element(ber, &size, cookie);
	if (tag != LBER_SEQUENCE) {
		cryptodebug("ber_next_element tag is not SEQUENCE");
		cryptoerror(LOG_STDERR, gettext(
		    "Expected RDNSequence SEQUENCE object, got tag [%02x]."),
		    tag);
		return;
	}
	tag = ber_scanf(ber, "{");

	/* Parse the sequence of RelativeDistinguishedName objects */
	while ((tag = ber_next_element(ber, &size, cookie)) != -1) {
		if (tag != LBER_SET) {
			cryptodebug("ber_next_element tag is not SET");
			cryptoerror(LOG_STDERR, gettext(
			    "Expected RelativeDistinguishedName SET object, "
			    "got tag [%02x]."), tag);
			return;
		}
		tag = ber_scanf(ber, "[");

		/* AttributeTypeAndValue */
		tag = ber_next_element(ber, &size, cookie);
		if (tag != LBER_SEQUENCE) {
			cryptodebug("ber_next_element tag is not SEQUENCE");
			cryptoerror(LOG_STDERR, gettext(
			    "Expected AttributeTypeAndValue SEQUENCE object, "
			    "got tag [%02x]."), tag);
			return;
		}
		tag = ber_scanf(ber, "{");

		/* AttributeType OID */
		tag = ber_next_element(ber, &atv_type_size, cookie);
		atv_type_size++;	/* Add room for null terminator */
		if (tag != LBER_OID) {
			cryptodebug("ber_next_element tag is not OID");
			cryptoerror(LOG_STDERR, gettext(
			    "Expected an OID, got tag [%02x]."), tag);
			return;
		}
		/* Note:  ber_scanf() allocates memory here for "a". */
		tag = ber_scanf(ber, "a", &atv_type, &atv_type_size);

		/* AttributeValue */
		tag = ber_next_element(ber, &atv_value_size, cookie);
		atv_value_size++;
		if ((tag != LBER_PRINTABLE_STRING) && (tag != LBER_IA5STRING)) {
			cryptodebug("ber_next_element tag is not "
			    "PRINTABLE_STRING/IA5STRING");
			cryptoerror(LOG_STDERR, gettext("Expected a STRING, "
			    "got tag [%02x]."), tag);
			free(atv_type);
			return;
		}
		/* Note:  ber_scanf() allocates memory here for "a". */
		tag = ber_scanf(ber, "a", &atv_value, &atv_value_size);

		/*
		 * Now go and turn the attribute type and value into
		 * some kind of meaningful output.
		 */
		if ((idx = get_oid_type(atv_type)) == -1) {
			if (oid_to_str((uint8_t *)atv_type, strlen(atv_type),
			    oidout, sizeof (oidout)) < 0) {
				cryptodebug("oid_to_str failed");
				cryptoerror(LOG_STDERR, gettext(
				    "Unable to convert OID to string."));
				free(atv_type);
				free(atv_value);
				return;
			}
			prndata = oidout;
		} else {
			prndata = oids[idx].strval;
		}

		if (!first)
			prnsz = snprintf(out + offset, outsz - offset,
			    ", %s = %s", prndata, atv_value);
		else {
			prnsz = snprintf(out + offset, outsz - offset,
			    "%s = %s", prndata, atv_value);
			first = B_FALSE;
		}

		free(atv_type);
		free(atv_value);
		atv_type = NULL;
		atv_value = NULL;

		offset += prnsz;
		if (offset >= outsz)
			break;
	}
}

/*
 * Convert OID to dotted notation string.
 */
static int
oid_to_str(uint8_t *oid, size_t oidlen, char *oidout, size_t oidout_len)
{
	int		count = 0;
	int		offset = 0;
	int		prnsz;
	uint_t		firstnum;
	uint_t		secondnum;
	uint64_t	nextnum = 0;

	cryptodebug("inside oid_to_str");

	if (oidlen == 0)
		return (-1);

	/*
	 * The first octet has a value of (40 x oidnum1) + oidnum2.  We
	 * will deconstruct it here and sanity check the result.  According
	 * to X.690, oidnum1 should never be more than 2 and oidnum2
	 * shouldn't be greater than 39 when oidnum1 = 0 or 1.
	 */
	firstnum = oid[count] / 40;
	if (firstnum > 2)		/* force remainder to be > 39 */
		firstnum = 2;
	secondnum = oid[count] - (firstnum * 40);

	(void) memset(oidout, 0, oidout_len);

	prnsz = snprintf(oidout, oidout_len, "%d.%d", firstnum, secondnum);
	offset += prnsz;
	if (offset >= oidout_len)
		return (0);

	/* Start at the second byte and move our way forward */
	for (count = 1; count < oidlen; count++) {
		/* ORIGINAL COMMENT */
		/*
		 * Each oid byte is taken as a 7-bit number.  If bit 8 is
		 * set, it means the next octet and this one are to be
		 * chained together as a single bit string, and so forth.
		 * We need to mask of bit 8, then shift over 7 bits in the
		 * resulting integer, and then stuff the new 7 bits in
		 * the low order byte, all the while making sure we don't
		 * stomp bit 1 from the previous octet.
		 * See X.690 or the layman's guide to ASN.1 for more.
		 */

		/*
		 * String together as many of the next octets if each of
		 * their high order bits is set to 1.  For example,
		 *	1 1010111, 1 0010100, 1 0010110, 0 1101111, ...
		 *	(3 8-bit octets)
		 * becomes
		 *	1010111 0010100 0010110, 1101111, ...
		 *	(one 21 bit integer)
		 * The high order bit functions as a "link" between octets.
		 * Note that if there are more than 9 octets with their
		 * high order bits set, it will overflow a 64-bit integer.
		 */
		for (nextnum = 0; (oid[count] & 0x80) && (count < oidlen);
		    count++) {
			nextnum <<= 7;
			nextnum |= (oid[count] & 0x7f);
		}
		if (count == oidlen)	/* last number not terminated? */
			return (-1);

		/* We're done with this oid number, write it and move on */
		prnsz = snprintf(oidout + offset, oidout_len - offset,
		    ".%lld", nextnum);
		offset += prnsz;
		if (offset >= oidout_len)
			return (0);
	}

	return (0);
}

/*
 * Returns the index in the oids[] array that matches the input type,
 * or -1 if it could not find a match.
 */
static int
get_oid_type(char *type)
{
	int		count;

	cryptodebug("inside get_oid_type");

	for (count = 0; count < oidblocklen; count++) {
		if (memcmp(oids[count].value, type, oids[count].length) == 0) {
			return (count);
		}
	}

	/* If we get here, we haven't found a match, so return -1 */
	return (-1);
}
