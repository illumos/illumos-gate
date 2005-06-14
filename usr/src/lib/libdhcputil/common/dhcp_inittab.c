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

#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <limits.h>
#include <ctype.h>
#include <libgen.h>
#include <sys/isa_defs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sysmacros.h>
#include <libinetutil.h>

#include "dhcp_symbol.h"
#include "dhcp_inittab.h"

static uint64_t		dhcp_htonll(uint64_t);
static uint64_t		dhcp_ntohll(uint64_t);
static void		inittab_msg(const char *, ...);
static uchar_t		category_to_code(const char *);
static boolean_t	encode_number(uint8_t, uint8_t, boolean_t, uint8_t,
			    const char *, uint8_t *, int *);
static boolean_t	decode_number(uint8_t, uint8_t, boolean_t, uint8_t,
			    const uint8_t *, char *, int *);
static dhcp_symbol_t	*inittab_lookup(uchar_t, char, const char *, int32_t,
			    size_t *);
static dsym_category_t	itabcode_to_dsymcode(uchar_t);
static boolean_t	parse_entry(char *, char **);

/*
 * forward declaration of our internal inittab_table[].  too bulky to put
 * up front -- check the end of this file for its definition.
 */
static dhcp_symbol_t	inittab_table[];

/*
 * the number of fields in the inittab and names for the fields.  note that
 * this order is meaningful to parse_entry(); other functions should just
 * use them as indexes into the array returned from parse_entry().
 */
#define	ITAB_FIELDS	7
enum { ITAB_NAME, ITAB_CODE, ITAB_TYPE, ITAB_GRAN, ITAB_MAX, ITAB_CONS,
    ITAB_CAT };

/*
 * the category_map_entry_t is used to map the inittab category codes to
 * the dsym codes.  the reason the codes are different is that the inittab
 * needs to have the codes be ORable such that queries can retrieve more
 * than one category at a time.  this map is also used to map the inittab
 * string representation of a category to its numerical code.
 */
typedef struct category_map_entry {
	dsym_category_t	cme_dsymcode;
	char		*cme_name;
	uchar_t		cme_itabcode;
} category_map_entry_t;

static category_map_entry_t category_map[] = {
	{ DSYM_STANDARD,	"STANDARD",	ITAB_CAT_STANDARD },
	{ DSYM_FIELD,		"FIELD",	ITAB_CAT_FIELD },
	{ DSYM_INTERNAL,	"INTERNAL",	ITAB_CAT_INTERNAL },
	{ DSYM_VENDOR,		"VENDOR",	ITAB_CAT_VENDOR },
	{ DSYM_SITE,		"SITE",		ITAB_CAT_SITE }
};

/*
 * inittab_load(): returns all inittab entries with the specified criteria
 *
 *   input: uchar_t: the categories the consumer is interested in
 *	    char: the consumer type of the caller
 *	    size_t *: set to the number of entries returned
 *  output: dhcp_symbol_t *: an array of dynamically allocated entries
 *	    on success, NULL upon failure
 */
dhcp_symbol_t	*
inittab_load(uchar_t categories, char consumer, size_t *n_entries)
{
	return (inittab_lookup(categories, consumer, NULL, -1, n_entries));
}

/*
 * inittab_getbyname(): returns an inittab entry with the specified criteria
 *
 *   input: int: the categories the consumer is interested in
 *	    char: the consumer type of the caller
 *	    char *: the name of the inittab entry the consumer wants
 *  output: dhcp_symbol_t *: a dynamically allocated dhcp_symbol structure
 *	    on success, NULL upon failure
 */
dhcp_symbol_t	*
inittab_getbyname(uchar_t categories, char consumer, const char *name)
{
	return (inittab_lookup(categories, consumer, name, -1, NULL));
}

/*
 * inittab_getbycode(): returns an inittab entry with the specified criteria
 *
 *   input: uchar_t: the categories the consumer is interested in
 *	    char: the consumer type of the caller
 *	    uint16_t: the code of the inittab entry the consumer wants
 *  output: dhcp_symbol_t *: a dynamically allocated dhcp_symbol structure
 *	    on success, NULL upon failure
 */
dhcp_symbol_t	*
inittab_getbycode(uchar_t categories, char consumer, uint16_t code)
{
	return (inittab_lookup(categories, consumer, NULL, code, NULL));
}

/*
 * inittab_lookup(): returns inittab entries with the specified criteria
 *
 *   input: uchar_t: the categories the consumer is interested in
 *	    char: the consumer type of the caller
 *	    const char *: the name of the entry the caller is interested
 *		in, or NULL if the caller doesn't care
 *	    int32_t: the code the caller is interested in, or -1 if the
 *		caller doesn't care
 *	    size_t *: set to the number of entries returned
 *  output: dhcp_symbol_t *: dynamically allocated dhcp_symbol structures
 *	    on success, NULL upon failure
 */
static dhcp_symbol_t *
inittab_lookup(uchar_t categories, char consumer, const char *name,
    int32_t code, size_t *n_entriesp)
{
	FILE			*inittab_fp;
	dhcp_symbol_t		*new_entries, *entries = NULL;
	dhcp_symbol_t		entry;
	char			buffer[ITAB_MAX_LINE_LEN];
	char			*fields[ITAB_FIELDS];
	unsigned long		line = 0;
	size_t			i, n_entries = 0;
	char			*inittab_path;
	uchar_t			category_code;
	dsym_cdtype_t		type;

	inittab_path = getenv("DHCP_INITTAB_PATH");
	if (inittab_path == NULL)
		inittab_path = ITAB_INITTAB_PATH;

	inittab_fp = fopen(inittab_path, "r");
	if (inittab_fp == NULL) {
		inittab_msg("inittab_lookup: fopen: %s: %s",
		    ITAB_INITTAB_PATH, strerror(errno));
		return (NULL);
	}

	(void) bufsplit(",\n", 0, NULL);
	while (fgets(buffer, sizeof (buffer), inittab_fp) != NULL) {

		line++;

		/*
		 * make sure the string didn't overflow our buffer
		 */
		if (strchr(buffer, '\n') == NULL) {
			inittab_msg("inittab_lookup: line %li: too long, "
			    "skipping", line);
			continue;
		}

		/*
		 * skip `pure comment' lines
		 */
		for (i = 0; buffer[i] != '\0'; i++)
			if (isspace(buffer[i]) == 0)
				break;

		if (buffer[i] == ITAB_COMMENT_CHAR || buffer[i] == '\0')
			continue;

		/*
		 * parse the entry out into fields.
		 */
		if (parse_entry(buffer, fields) == B_FALSE) {
			inittab_msg("inittab_lookup: line %li: syntax error, "
			    "skipping", line);
			continue;
		}

		/*
		 * validate the values in the entries; skip if invalid.
		 */
		if (atoi(fields[ITAB_GRAN]) > ITAB_GRAN_MAX) {
			inittab_msg("inittab_lookup: line %li: granularity `%s'"
			    " out of range, skipping", line, fields[ITAB_GRAN]);
			continue;
		}

		if (atoi(fields[ITAB_MAX]) > ITAB_MAX_MAX) {
			inittab_msg("inittab_lookup: line %li: maximum `%s' "
			    "out of range, skipping", line, fields[ITAB_MAX]);
			continue;
		}

		if (dsym_get_type_id(fields[ITAB_TYPE], &type, B_FALSE) !=
		    DSYM_SUCCESS) {
			inittab_msg("inittab_lookup: line %li: type `%s' "
			    "is invalid, skipping", line, fields[ITAB_TYPE]);
			continue;
		}

		/*
		 * find out whether this entry of interest to our consumer,
		 * and if so, throw it onto the set of entries we'll return.
		 * check categories last since it's the most expensive check.
		 */
		if (strchr(fields[ITAB_CONS], consumer) == NULL)
			continue;

		if (code != -1 && atoi(fields[ITAB_CODE]) != code)
			continue;

		if (name != NULL && strcasecmp(fields[ITAB_NAME], name) != 0)
			continue;

		category_code = category_to_code(fields[ITAB_CAT]);
		if ((category_code & categories) == 0)
			continue;

		/*
		 * looks like a match.  allocate an entry and fill it in
		 */
		new_entries = realloc(entries, (n_entries + 1) *
		    sizeof (dhcp_symbol_t));

		/*
		 * if we run out of memory, might as well return what we can
		 */
		if (new_entries == NULL) {
			inittab_msg("inittab_lookup: ran out of memory "
			    "allocating dhcp_symbol_t's");
			break;
		}

		entry.ds_max	  = atoi(fields[ITAB_MAX]);
		entry.ds_code	  = atoi(fields[ITAB_CODE]);
		entry.ds_type	  = type;
		entry.ds_gran	  = atoi(fields[ITAB_GRAN]);
		entry.ds_category = itabcode_to_dsymcode(category_code);
		entry.ds_classes.dc_cnt	  = 0;
		entry.ds_classes.dc_names = NULL;
		(void) strlcpy(entry.ds_name, fields[ITAB_NAME],
		    sizeof (entry.ds_name));

		entries = new_entries;
		entries[n_entries++] = entry;
	}

	if (ferror(inittab_fp) != 0) {
		inittab_msg("inittab_lookup: error on inittab stream");
		clearerr(inittab_fp);
	}

	(void) fclose(inittab_fp);

	if (n_entriesp != NULL)
		*n_entriesp = n_entries;

	return (entries);
}

/*
 * parse_entry(): parses an entry out into its constituent fields
 *
 *   input: char *: the entry
 *	    char **: an array of ITAB_FIELDS length which contains
 *		     pointers into the entry on upon return
 *  output: boolean_t: B_TRUE on success, B_FALSE on failure
 */
static boolean_t
parse_entry(char *entry, char **fields)
{
	char	*category, *spacep;
	size_t	n_fields, i;

	/*
	 * due to a mistake made long ago, the first and second fields of
	 * each entry are not separated by a comma, but rather by
	 * whitespace -- have bufsplit() treat the two fields as one, then
	 * pull them apart afterwards.
	 */
	n_fields = bufsplit(entry, ITAB_FIELDS - 1, fields);
	if (n_fields != (ITAB_FIELDS - 1))
		return (B_FALSE);

	/*
	 * pull the first and second fields apart.  this is complicated
	 * since the first field can contain embedded whitespace (so we
	 * must separate the two fields by the last span of whitespace).
	 *
	 * first, find the initial span of whitespace.  if there isn't one,
	 * then the entry is malformed.
	 */
	category = strpbrk(fields[ITAB_NAME], " \t");
	if (category == NULL)
		return (B_FALSE);

	/*
	 * find the last span of whitespace.
	 */
	do {
		while (isspace(*category))
			category++;

		spacep = strpbrk(category, " \t");
		if (spacep != NULL)
			category = spacep;
	} while (spacep != NULL);

	/*
	 * NUL-terminate the first byte of the last span of whitespace, so
	 * that the first field doesn't have any residual trailing
	 * whitespace.
	 */
	spacep = category - 1;
	while (isspace(*spacep))
		spacep--;

	if (spacep <= fields[0])
		return (B_FALSE);

	*++spacep = '\0';

	/*
	 * remove any whitespace from the fields.
	 */
	for (i = 0; i < n_fields; i++) {
		while (isspace(*fields[i]))
			fields[i]++;
	}
	fields[ITAB_CAT] = category;

	return (B_TRUE);
}

/*
 * inittab_verify(): verifies that a given inittab entry matches an internal
 *		     definition
 *
 *   input: dhcp_symbol_t *: the inittab entry to verify
 *	    dhcp_symbol_t *: if non-NULL, a place to store the internal
 *			       inittab entry upon return
 *  output: int: ITAB_FAILURE, ITAB_SUCCESS, or ITAB_UNKNOWN
 */
int
inittab_verify(dhcp_symbol_t *inittab_ent, dhcp_symbol_t *internal_ent)
{
	unsigned int	i;

	for (i = 0; inittab_table[i].ds_name[0] != '\0'; i++) {

		if (inittab_ent->ds_category != inittab_table[i].ds_category)
			continue;

		if (inittab_ent->ds_code == inittab_table[i].ds_code) {
			if (internal_ent != NULL)
				*internal_ent = inittab_table[i];

			if (inittab_table[i].ds_type != inittab_ent->ds_type ||
			    inittab_table[i].ds_gran != inittab_ent->ds_gran ||
			    inittab_table[i].ds_max  != inittab_ent->ds_max)
				return (ITAB_FAILURE);

			return (ITAB_SUCCESS);
		}
	}

	return (ITAB_UNKNOWN);
}

/*
 * inittab_encode_e(): converts a string representation of a given datatype into
 *		     binary; used for encoding ascii values into a form that
 *		     can be put in DHCP packets to be sent on the wire.
 *
 *   input: dhcp_symbol_t *: the entry describing the value option
 *	    const char *: the value to convert
 *	    uint16_t *: set to the length of the binary data returned
 *	    boolean_t: if false, return a full DHCP option
 *  output: uchar_t *: a dynamically allocated byte array with converted data
 */
uchar_t *
inittab_encode_e(dhcp_symbol_t *ie, const char *value, uint16_t *lengthp,
    boolean_t just_payload, int *ierrnop)
{
	uint16_t	length = 0;
	uchar_t		n_entries = 0;
	const char	*valuep;
	char		*currp;
	uchar_t		*result = NULL;
	unsigned int	i;
	uint8_t		type_size = inittab_type_to_size(ie);
	boolean_t	is_signed;
	uint_t		vallen, reslen;

	*ierrnop = 0;
	if (type_size == 0) {
		*ierrnop = ITAB_SYNTAX_ERROR;
		return (NULL);
	}

	if (ie->ds_type == DSYM_ASCII)
		n_entries = strlen(value);		/* no NUL */
	else if (ie->ds_type == DSYM_OCTET) {
		vallen = strlen(value);
		n_entries = vallen / 2;
		n_entries += vallen % 2;
	} else {
		/*
		 * figure out the number of entries by counting the spaces
		 * in the value string
		 */
		for (valuep = value; valuep++ != NULL; n_entries++)
			valuep = strchr(valuep, ' ');
	}

	/*
	 * if we're gonna return a complete option, then include the
	 * option length and code in the size of the packet we allocate
	 */
	if (just_payload == B_FALSE)
		length += 2;

	length += n_entries * type_size;
	if (length > 0)
		result = malloc(length);

	switch (ie->ds_type) {

	case DSYM_ASCII:

		if (result == NULL) {
			*ierrnop = ITAB_NOMEM;
			return (NULL);
		}

		if (strlen(value) > length) {
			free(result);
			*ierrnop = ITAB_BAD_STRING;
			return (NULL);
		}

		(void) memcpy(result, value, length);
		break;

	case DSYM_OCTET:

		if (result == NULL) {
			*ierrnop = ITAB_BAD_OCTET;
			return (NULL);
		}

		reslen = length;
		/* Call libinetutil function to decode */
		if (hexascii_to_octet(value, vallen, result, &reslen) != 0) {
			free(result);
			*ierrnop = ITAB_BAD_OCTET;
			return (NULL);
		}
		break;

	case DSYM_IP:

		if (result == NULL) {
			*ierrnop = ITAB_BAD_IPADDR;
			return (NULL);
		}
		if (n_entries % ie->ds_gran != 0) {
			*ierrnop = ITAB_BAD_GRAN;
			inittab_msg("inittab_encode: number of entries "
			    "not compatible with option granularity");
			free(result);
			return (NULL);
		}

		for (valuep = value, i = 0; i < n_entries; i++, valuep++) {

			currp = strchr(valuep, ' ');
			if (currp != NULL)
				*currp = '\0';
			if (inet_pton(AF_INET, valuep,
			    &result[i * sizeof (ipaddr_t)]) != 1) {
				*ierrnop = ITAB_BAD_IPADDR;
				inittab_msg("inittab_encode: bogus ip address");
				free(result);
				return (NULL);
			}

			valuep = currp;
			if (valuep == NULL) {
				if (i < (n_entries - 1)) {
					*ierrnop = ITAB_NOT_ENOUGH_IP;
					inittab_msg("inittab_encode: too few "
					    "ip addresses");
					free(result);
					return (NULL);
				}
				break;
			}
		}
		break;

	case DSYM_NUMBER:				/* FALLTHRU */
	case DSYM_UNUMBER8:				/* FALLTHRU */
	case DSYM_SNUMBER8:				/* FALLTHRU */
	case DSYM_UNUMBER16:				/* FALLTHRU */
	case DSYM_SNUMBER16:				/* FALLTHRU */
	case DSYM_UNUMBER32:				/* FALLTHRU */
	case DSYM_SNUMBER32:				/* FALLTHRU */
	case DSYM_UNUMBER64:				/* FALLTHRU */
	case DSYM_SNUMBER64:

		if (result == NULL) {
			*ierrnop = ITAB_BAD_NUMBER;
			return (NULL);
		}

		is_signed = (ie->ds_type == DSYM_SNUMBER64 ||
		    ie->ds_type == DSYM_SNUMBER32 ||
		    ie->ds_type == DSYM_SNUMBER16 ||
		    ie->ds_type == DSYM_SNUMBER8);

		if (encode_number(n_entries, type_size, is_signed, 0, value,
		    result, ierrnop) == B_FALSE) {
			free(result);
			return (NULL);
		}
		break;

	default:
		if (ie->ds_type == DSYM_BOOL)
			*ierrnop = ITAB_BAD_BOOLEAN;
		else
			*ierrnop = ITAB_SYNTAX_ERROR;

		inittab_msg("inittab_encode: unsupported type `%d'",
		    ie->ds_type);

		free(result);
		return (NULL);
	}

	/*
	 * if just_payload is false, then we need to slide the option
	 * code and length fields in. (length includes them in its
	 * count, so we have to subtract 2)
	 */
	if (just_payload == B_FALSE) {
		(void) memmove(result + 2, result, length - 2);
		result[0] = ie->ds_code;
		result[1] = length - 2;
	}

	if (lengthp != NULL)
		*lengthp = length;

	return (result);
}

/*
 * inittab_decode_e(): converts a binary representation of a given datatype into
 *		     a string; used for decoding DHCP options in a packet off
 *		     the wire into ascii
 *
 *   input: dhcp_symbol_t *: the entry describing the payload option
 *	    uchar_t *: the payload to convert
 *	    uint16_t: the payload length (only used if just_payload is true)
 *	    boolean_t: if false, payload is assumed to be a DHCP option
 *	    int *: set to extended error code if error occurs.
 *  output: char *: a dynamically allocated string containing the converted data
 */
char *
inittab_decode_e(dhcp_symbol_t *ie, uchar_t *payload, uint16_t length,
    boolean_t just_payload, int *ierrnop)
{
	char		*resultp, *end, *result = NULL;
	char		*currp;
	uchar_t		n_entries;
	struct in_addr	in_addr;
	uint8_t		type_size = inittab_type_to_size(ie);
	boolean_t	is_signed;

	*ierrnop = 0;
	if (type_size == 0) {
		*ierrnop = ITAB_SYNTAX_ERROR;
		return (NULL);
	}

	if (just_payload == B_FALSE) {
		length = payload[1];
		payload += 2;
	}

	/*
	 * figure out the number of elements to convert.  note that
	 * for ds_type NUMBER, the granularity is really 1 since the
	 * value of ds_gran is the number of bytes in the number.
	 */
	if (ie->ds_type == DSYM_NUMBER)
		n_entries = MIN(ie->ds_max, length / type_size);
	else
		n_entries = MIN(ie->ds_max * ie->ds_gran, length / type_size);

	if (n_entries == 0)
		n_entries = length / type_size;

	if ((length % type_size) != 0) {
		inittab_msg("inittab_decode: length of string not compatible "
		    "with option type `%i'", ie->ds_type);
		*ierrnop = ITAB_BAD_STRING;
		return (NULL);
	}

	switch (ie->ds_type) {

	case DSYM_ASCII:

		result = malloc(n_entries + 1);
		if (result == NULL) {
			*ierrnop = ITAB_NOMEM;
			return (NULL);
		}

		(void) memcpy(result, payload, n_entries);
		result[n_entries] = '\0';
		break;

	case DSYM_OCTET:

		result = malloc(n_entries * (sizeof ("0xNN") + 1));
		if (result == NULL) {
			*ierrnop = ITAB_NOMEM;
			return (NULL);
		}

		for (resultp = result; n_entries != 0; n_entries--) {
			currp = resultp;
			resultp += sprintf(resultp, "0x%02X ", *payload++);
			if (currp == resultp) {
				free(result);
				*ierrnop = ITAB_BAD_OCTET;
				return (NULL);
			}
		}

		resultp[-1] = '\0';
		break;

	case DSYM_IP:

		if ((length / sizeof (ipaddr_t)) % ie->ds_gran != 0) {
			*ierrnop = ITAB_BAD_GRAN;
			inittab_msg("inittab_decode: number of entries "
			    "not compatible with option granularity");
			return (NULL);
		}

		result = malloc(n_entries * (sizeof ("aaa.bbb.ccc.ddd") + 1));
		end = &result[n_entries * (sizeof ("aaa.bbb.ccc.ddd") + 1)];
		if (result == NULL) {
			*ierrnop = ITAB_NOMEM;
			return (NULL);
		}

		for (resultp = result; n_entries != 0; n_entries--) {
			(void) memcpy(&in_addr.s_addr, payload,
			    sizeof (ipaddr_t));
			currp = resultp;
			resultp += snprintf(resultp, end - resultp, "%s ",
			    inet_ntoa(in_addr));
			if (currp == resultp) {
				free(result);
				*ierrnop = ITAB_BAD_IPADDR;
				return (NULL);
			}
			payload += sizeof (ipaddr_t);
		}

		resultp[-1] = '\0';
		break;

	case DSYM_NUMBER:				/* FALLTHRU */
	case DSYM_UNUMBER8:				/* FALLTHRU */
	case DSYM_SNUMBER8:				/* FALLTHRU */
	case DSYM_UNUMBER16:				/* FALLTHRU */
	case DSYM_SNUMBER16:				/* FALLTHRU */
	case DSYM_UNUMBER32:				/* FALLTHRU */
	case DSYM_SNUMBER32:				/* FALLTHRU */
	case DSYM_UNUMBER64:				/* FALLTHRU */
	case DSYM_SNUMBER64:

		is_signed = (ie->ds_type == DSYM_SNUMBER64 ||
		    ie->ds_type == DSYM_SNUMBER32 ||
		    ie->ds_type == DSYM_SNUMBER16 ||
		    ie->ds_type == DSYM_SNUMBER8);

		result = malloc(n_entries * ITAB_MAX_NUMBER_LEN);
		if (result == NULL) {
			*ierrnop = ITAB_NOMEM;
			return (NULL);
		}

		if (decode_number(n_entries, type_size, is_signed, ie->ds_gran,
		    payload, result, ierrnop) == B_FALSE) {
			free(result);
			return (NULL);
		}
		break;

	default:
		inittab_msg("inittab_decode: unsupported type `%d'",
		    ie->ds_type);
		break;
	}

	return (result);
}

/*
 * inittab_encode(): converts a string representation of a given datatype into
 *		     binary; used for encoding ascii values into a form that
 *		     can be put in DHCP packets to be sent on the wire.
 *
 *   input: dhcp_symbol_t *: the entry describing the value option
 *	    const char *: the value to convert
 *	    uint16_t *: set to the length of the binary data returned
 *	    boolean_t: if false, return a full DHCP option
 *  output: uchar_t *: a dynamically allocated byte array with converted data
 */
uchar_t *
inittab_encode(dhcp_symbol_t *ie, const char *value, uint16_t *lengthp,
    boolean_t just_payload)
{
	int ierrno;

	return (inittab_encode_e(ie, value, lengthp, just_payload, &ierrno));
}

/*
 * inittab_decode(): converts a binary representation of a given datatype into
 *		     a string; used for decoding DHCP options in a packet off
 *		     the wire into ascii
 *
 *   input: dhcp_symbol_t *: the entry describing the payload option
 *	    uchar_t *: the payload to convert
 *	    uint16_t: the payload length (only used if just_payload is true)
 *	    boolean_t: if false, payload is assumed to be a DHCP option
 *  output: char *: a dynamically allocated string containing the converted data
 */
char *
inittab_decode(dhcp_symbol_t *ie, uchar_t *payload, uint16_t length,
    boolean_t just_payload)
{
	int ierrno;

	return (inittab_decode_e(ie, payload, length, just_payload, &ierrno));
}

/*
 * inittab_msg(): prints diagnostic messages if INITTAB_DEBUG is set
 *
 *	    const char *: a printf-like format string
 *	    ...: arguments to the format string
 *  output: void
 */
/*PRINTFLIKE1*/
static void
inittab_msg(const char *fmt, ...)
{
	enum { INITTAB_MSG_CHECK, INITTAB_MSG_RETURN, INITTAB_MSG_OUTPUT };

	va_list		ap;
	char		buf[512];
	static int	action = INITTAB_MSG_CHECK;

	/*
	 * check DHCP_INITTAB_DEBUG the first time in; thereafter, use
	 * the the cached result (stored in `action').
	 */
	switch (action) {

	case INITTAB_MSG_CHECK:

		if (getenv("DHCP_INITTAB_DEBUG") == NULL) {
			action = INITTAB_MSG_RETURN;
			return;
		}

		action = INITTAB_MSG_OUTPUT;

		/* FALLTHRU into INITTAB_MSG_OUTPUT */

	case INITTAB_MSG_OUTPUT:

		va_start(ap, fmt);

		(void) snprintf(buf, sizeof (buf), "inittab: %s\n", fmt);
		(void) vfprintf(stderr, buf, ap);

		va_end(ap);
		break;

	case INITTAB_MSG_RETURN:

		return;
	}
}

/*
 * decode_number(): decodes a sequence of numbers from binary into ascii;
 *		    binary is coming off of the network, so it is in nbo
 *
 *   input: uint8_t: the number of "granularity" numbers to decode
 *	    uint8_t: the length of each number
 *	    boolean_t: whether the numbers should be considered signed
 *	    uint8_t: the number of numbers per granularity
 *	    const uint8_t *: where to decode the numbers from
 *	    char *: where to decode the numbers to
 *  output: boolean_t: true on successful conversion, false on failure
 */
static boolean_t
decode_number(uint8_t n_entries, uint8_t size, boolean_t is_signed,
    uint8_t granularity, const uint8_t *from, char *to, int *ierrnop)
{
	uint16_t	uint16;
	uint32_t	uint32;
	uint64_t	uint64;

	if (granularity != 0) {
		if ((granularity % n_entries) != 0) {
			inittab_msg("decode_number: number of entries "
			    "not compatible with option granularity");
			*ierrnop = ITAB_BAD_GRAN;
			return (B_FALSE);
		}
	}

	for (; n_entries != 0; n_entries--, from += size) {

		switch (size) {

		case 1:
			to += sprintf(to, is_signed ? "%d " : "%u ", *from);
			break;

		case 2:
			(void) memcpy(&uint16, from, 2);
			to += sprintf(to, is_signed ? "%hd " : "%hu ",
			    ntohs(uint16));
			break;

		case 4:
			(void) memcpy(&uint32, from, 4);
			to += sprintf(to, is_signed ? "%ld " : "%lu ",
			    ntohl(uint32));
			break;

		case 8:
			(void) memcpy(&uint64, from, 8);
			to += sprintf(to, is_signed ? "%lld " : "%llu ",
			    dhcp_ntohll(uint64));
			break;

		default:
			*ierrnop = ITAB_BAD_NUMBER;
			inittab_msg("decode_number: unknown integer size `%d'",
			    size);
			return (B_FALSE);
		}
	}

	to[-1] = '\0';
	return (B_TRUE);
}

/*
 * encode_number(): encodes a sequence of numbers from ascii into binary;
 *		    number will end up on the wire so it needs to be in nbo
 *
 *   input: uint8_t: the number of "granularity" numbers to encode
 *	    uint8_t: the length of each number
 *	    boolean_t: whether the numbers should be considered signed
 *	    uint8_t: the number of numbers per granularity
 *	    const uint8_t *: where to encode the numbers from
 *	    char *: where to encode the numbers to
 *	    int *: set to extended error code if error occurs.
 *  output: boolean_t: true on successful conversion, false on failure
 */
static boolean_t /* ARGSUSED */
encode_number(uint8_t n_entries, uint8_t size, boolean_t is_signed,
    uint8_t granularity, const char *from, uint8_t *to, int *ierrnop)
{
	uint8_t		i;
	uint16_t	uint16;
	uint32_t	uint32;
	uint64_t	uint64;
	char		*endptr;

	if (granularity != 0) {
		if ((granularity % n_entries) != 0) {
			*ierrnop = ITAB_BAD_GRAN;
			inittab_msg("encode_number: number of entries "
			    "not compatible with option granularity");
			return (B_FALSE);
		}
	}

	for (i = 0; i < n_entries; i++, from++) {

		/*
		 * totally obscure c factoid: it is legal to pass a
		 * string representing a negative number to strtoul().
		 * in this case, strtoul() will return an unsigned
		 * long that if cast to a long, would represent the
		 * negative number.  we take advantage of this to
		 * cut down on code here.
		 */

		errno = 0;
		switch (size) {

		case 1:
			to[i] = strtoul(from, &endptr, 0);
			if (errno != 0 || from == endptr) {
				goto error;
			}
			break;

		case 2:
			uint16 = htons(strtoul(from, &endptr, 0));
			if (errno != 0 || from == endptr) {
				goto error;
			}
			(void) memcpy(to + (i * 2), &uint16, 2);
			break;

		case 4:
			uint32 = htonl(strtoul(from, &endptr, 0));
			if (errno != 0 || from == endptr) {
				goto error;
			}
			(void) memcpy(to + (i * 4), &uint32, 4);
			break;

		case 8:
			uint64 = dhcp_htonll(strtoull(from, &endptr, 0));
			if (errno != 0 || from == endptr) {
				goto error;
			}
			(void) memcpy(to + (i * 8), &uint64, 8);
			break;

		default:
			inittab_msg("encode_number: unsupported integer "
			    "size `%d'", size);
			return (B_FALSE);
		}

		from = strchr(from, ' ');
		if (from == NULL)
			break;
	}

	return (B_TRUE);

error:
	*ierrnop = ITAB_BAD_NUMBER;
	inittab_msg("encode_number: cannot convert to integer");
	return (B_FALSE);
}

/*
 * inittab_type_to_size(): given an inittab entry, returns size of one entry of
 *		      its type
 *
 *   input: dhcp_symbol_t *: an entry of the given type
 *  output: uint8_t: the size in bytes of an entry of that type
 */
uint8_t
inittab_type_to_size(dhcp_symbol_t *ie)
{
	switch (ie->ds_type) {

	case DSYM_ASCII:
	case DSYM_OCTET:
	case DSYM_SNUMBER8:
	case DSYM_UNUMBER8:

		return (1);

	case DSYM_SNUMBER16:
	case DSYM_UNUMBER16:

		return (2);

	case DSYM_SNUMBER32:
	case DSYM_UNUMBER32:
	case DSYM_IP:

		return (4);

	case DSYM_SNUMBER64:
	case DSYM_UNUMBER64:

		return (8);

	case DSYM_NUMBER:

		return (ie->ds_gran);
	}

	return (0);
}

/*
 * itabcode_to_dsymcode(): maps an inittab category code to its dsym
 *                         representation
 *
 *   input: uchar_t: the inittab category code
 *  output: dsym_category_t: the dsym category code
 */
static dsym_category_t
itabcode_to_dsymcode(uchar_t itabcode)
{

	unsigned int	i;

	for (i = 0; i < ITAB_CAT_COUNT; i++)
		if (category_map[i].cme_itabcode == itabcode)
			return (category_map[i].cme_dsymcode);

	return (DSYM_BAD_CAT);
}

/*
 * category_to_code(): maps a category name to its numeric representation
 *
 *   input: const char *: the category name
 *  output: uchar_t: its internal code (numeric representation)
 */
static uchar_t
category_to_code(const char *category)
{
	unsigned int	i;

	for (i = 0; i < ITAB_CAT_COUNT; i++)
		if (strcasecmp(category_map[i].cme_name, category) == 0)
			return (category_map[i].cme_itabcode);

	return (0);
}

/*
 * dhcp_htonll(): converts a 64-bit number from host to network byte order
 *
 *   input: uint64_t: the number to convert
 *  output: uint64_t: its value in network byte order
 */
static uint64_t
dhcp_htonll(uint64_t uint64_hbo)
{
	return (dhcp_ntohll(uint64_hbo));
}

/*
 * dhcp_ntohll(): converts a 64-bit number from network to host byte order
 *
 *   input: uint64_t: the number to convert
 *  output: uint64_t: its value in host byte order
 */
static uint64_t
dhcp_ntohll(uint64_t uint64_nbo)
{
#ifdef	_LITTLE_ENDIAN
	return ((uint64_t)ntohl(uint64_nbo & 0xffffffff) << 32 |
	    ntohl(uint64_nbo >> 32));
#else
	return (uint64_nbo);
#endif
}

/*
 * our internal table of DHCP option values, used by inittab_verify()
 */
static dhcp_symbol_t inittab_table[] =
{
{ DSYM_INTERNAL,	1024,	"Hostname",	DSYM_BOOL,	0,	0 },
{ DSYM_INTERNAL,	1025,	"LeaseNeg",	DSYM_BOOL,	0,	0 },
{ DSYM_INTERNAL,	1026,	"EchoVC",	DSYM_BOOL,	0,	0 },
{ DSYM_INTERNAL,	1027,	"BootPath",	DSYM_ASCII,	1,	128 },
{ DSYM_FIELD,		0,	"Opcode",	DSYM_UNUMBER8,	1,	1 },
{ DSYM_FIELD,		1,	"Htype",	DSYM_UNUMBER8,	1,	1 },
{ DSYM_FIELD,		2,	"HLen",		DSYM_UNUMBER8,	1,	1 },
{ DSYM_FIELD,		3,	"Hops",		DSYM_UNUMBER8,	1,	1 },
{ DSYM_FIELD,		4,	"Xid",		DSYM_UNUMBER32,	1,	1 },
{ DSYM_FIELD,		8,	"Secs",		DSYM_UNUMBER16,	1,	1 },
{ DSYM_FIELD,		10,	"Flags",	DSYM_OCTET,	1,	2 },
{ DSYM_FIELD,		12,	"Ciaddr",	DSYM_IP,	1,	1 },
{ DSYM_FIELD,		16,	"Yiaddr",	DSYM_IP,	1,	1 },
{ DSYM_FIELD,		20,	"BootSrvA",	DSYM_IP,	1,	1 },
{ DSYM_FIELD,		24,	"Giaddr",	DSYM_IP,	1,	1 },
{ DSYM_FIELD,		28,	"Chaddr",	DSYM_OCTET, 	1,	16 },
{ DSYM_FIELD,		44,	"BootSrvN",	DSYM_ASCII,	1,	64 },
{ DSYM_FIELD,		108,	"BootFile",	DSYM_ASCII,	1,	128 },
{ DSYM_FIELD,		236,	"Magic",	DSYM_OCTET,	1,	4 },
{ DSYM_FIELD,		240,	"Options",	DSYM_OCTET,	1,	60 },
{ DSYM_STANDARD,	1,	"Subnet",	DSYM_IP,	1,	1 },
{ DSYM_STANDARD,	2,	"UTCoffst",	DSYM_SNUMBER32,	1,	1 },
{ DSYM_STANDARD,	3,	"Router",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	4,	"Timeserv",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	5,	"IEN116ns",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	6,	"DNSserv",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	7,	"Logserv",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	8,	"Cookie",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	9,	"Lprserv",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	10,	"Impress",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	11,	"Resource",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	12,	"Hostname",	DSYM_ASCII,	1,	0 },
{ DSYM_STANDARD,	13,	"Bootsize",	DSYM_UNUMBER16,	1,	1 },
{ DSYM_STANDARD,	14,	"Dumpfile",	DSYM_ASCII,	1,	0 },
{ DSYM_STANDARD,	15,	"DNSdmain",	DSYM_ASCII,	1,	0 },
{ DSYM_STANDARD,	16,	"Swapserv",	DSYM_IP,	1,	1 },
{ DSYM_STANDARD,	17,	"Rootpath",	DSYM_ASCII,	1,	0 },
{ DSYM_STANDARD,	18,	"ExtendP",	DSYM_ASCII,	1,	0 },
{ DSYM_STANDARD,	19,	"IpFwdF",	DSYM_UNUMBER8,	1,	1 },
{ DSYM_STANDARD,	20,	"NLrouteF",	DSYM_UNUMBER8,	1,	1 },
{ DSYM_STANDARD,	21,	"PFilter",	DSYM_IP,	2,	0 },
{ DSYM_STANDARD,	22,	"MaxIpSiz",	DSYM_UNUMBER16,	1,	1 },
{ DSYM_STANDARD,	23,	"IpTTL",	DSYM_UNUMBER8,	1,	1 },
{ DSYM_STANDARD,	24,	"PathTO",	DSYM_UNUMBER32,	1,	1 },
{ DSYM_STANDARD,	25,	"PathTbl",	DSYM_UNUMBER16,	1,	0 },
{ DSYM_STANDARD,	26,	"MTU",		DSYM_UNUMBER16,	1,	1 },
{ DSYM_STANDARD,	27,	"SameMtuF",	DSYM_UNUMBER8,	1,	1 },
{ DSYM_STANDARD,	28,	"Broadcst",	DSYM_IP,	1,	1 },
{ DSYM_STANDARD,	29,	"MaskDscF",	DSYM_UNUMBER8,	1,	1 },
{ DSYM_STANDARD,	30,	"MaskSupF",	DSYM_UNUMBER8,	1,	1 },
{ DSYM_STANDARD,	31,	"RDiscvyF",	DSYM_UNUMBER8,	1,	1 },
{ DSYM_STANDARD,	32,	"RSolictS",	DSYM_IP,	1,	1 },
{ DSYM_STANDARD,	33,	"StaticRt",	DSYM_IP,	2,	0 },
{ DSYM_STANDARD,	34,	"TrailerF",	DSYM_UNUMBER8,	1,	1 },
{ DSYM_STANDARD,	35,	"ArpTimeO",	DSYM_UNUMBER32,	1,	1 },
{ DSYM_STANDARD,	36,	"EthEncap",	DSYM_UNUMBER8,	1,	1 },
{ DSYM_STANDARD,	37,	"TcpTTL",	DSYM_UNUMBER8,	1,	1 },
{ DSYM_STANDARD,	38,	"TcpKaInt",	DSYM_UNUMBER32,	1,	1 },
{ DSYM_STANDARD,	39,	"TcpKaGbF",	DSYM_UNUMBER8,	1,	1 },
{ DSYM_STANDARD,	40,	"NISdmain",	DSYM_ASCII,	1,	0 },
{ DSYM_STANDARD,	41,	"NISservs",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	42,	"NTPservs",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	43,	"Vendor",	DSYM_OCTET,	1,	0 },
{ DSYM_STANDARD,	44,	"NetBNms",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	45,	"NetBDsts",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	46,	"NetBNdT",	DSYM_UNUMBER8,	1,	1 },
{ DSYM_STANDARD,	47,	"NetBScop",	DSYM_ASCII,	1,	0 },
{ DSYM_STANDARD,	48,	"XFontSrv",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	49,	"XDispMgr",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	50,	"ReqIP",	DSYM_IP,	1,	1 },
{ DSYM_STANDARD,	51,	"LeaseTim",	DSYM_UNUMBER32,	1,	1 },
{ DSYM_STANDARD,	52,	"OptOvrld",	DSYM_UNUMBER8,	1,	1 },
{ DSYM_STANDARD,	53,	"DHCPType",	DSYM_UNUMBER8,	1,	1 },
{ DSYM_STANDARD,	54,	"ServerID",	DSYM_IP,	1,	1 },
{ DSYM_STANDARD,	55,	"ReqList",	DSYM_OCTET,	1,	0 },
{ DSYM_STANDARD,	56,	"Message",	DSYM_ASCII,	1,	0 },
{ DSYM_STANDARD,	57,	"DHCP_MTU",	DSYM_UNUMBER16,	1,	1 },
{ DSYM_STANDARD,	58,	"T1Time",	DSYM_UNUMBER32,	1,	1 },
{ DSYM_STANDARD,	59,	"T2Time",	DSYM_UNUMBER32,	1,	1 },
{ DSYM_STANDARD,	60,	"ClassID",	DSYM_ASCII,	1,	0 },
{ DSYM_STANDARD,	61,	"ClientID",	DSYM_OCTET,	1,	0 },
{ DSYM_STANDARD,	62,	"NW_dmain",	DSYM_ASCII,	1,	0 },
{ DSYM_STANDARD,	63,	"NWIPOpts",	DSYM_OCTET,	1,	128 },
{ DSYM_STANDARD,	64,	"NIS+dom",	DSYM_ASCII,	1,	0 },
{ DSYM_STANDARD,	65,	"NIS+serv",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	66,	"TFTPsrvN",	DSYM_ASCII,	1,	64 },
{ DSYM_STANDARD,	67,	"OptBootF",	DSYM_ASCII,	1,	128 },
{ DSYM_STANDARD,	68,	"MblIPAgt",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	69,	"SMTPserv",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	70,	"POP3serv",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	71,	"NNTPserv",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	72,	"WWWservs",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	73,	"Fingersv",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	74,	"IRCservs",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	75,	"STservs",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	76,	"STDAservs",	DSYM_IP,	1,	0 },
{ DSYM_STANDARD,	77,	"UserClas",	DSYM_ASCII,	1,	0 },
{ DSYM_STANDARD,	78,	"SLP_DA",	DSYM_OCTET,	1,	0 },
{ DSYM_STANDARD,	79,	"SLP_SS",	DSYM_OCTET,	1,	0 },
{ DSYM_STANDARD,	82,	"AgentOpt",	DSYM_OCTET,	1,	0 },
{ DSYM_STANDARD,	89,	"FQDN",		DSYM_OCTET,	1,	0 },
{ 0,			0,	"",		0,		0,	0 }
};
