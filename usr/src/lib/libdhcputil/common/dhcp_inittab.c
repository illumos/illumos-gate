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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sysmacros.h>
#include <libinetutil.h>
#include <libdlpi.h>
#include <netinet/dhcp6.h>

#include "dhcp_symbol.h"
#include "dhcp_inittab.h"

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
 *
 * Note: we have only an IPv4 version here.  The inittab_verify() function is
 * used by the DHCP server and manager.  We'll need a new function if the
 * server is extended to DHCPv6.
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
	const char		*inittab_path;
	uchar_t			category_code;
	dsym_cdtype_t		type;

	if (categories & ITAB_CAT_V6) {
		inittab_path = getenv("DHCP_INITTAB6_PATH");
		if (inittab_path == NULL)
			inittab_path = ITAB_INITTAB6_PATH;
	} else {
		inittab_path = getenv("DHCP_INITTAB_PATH");
		if (inittab_path == NULL)
			inittab_path = ITAB_INITTAB_PATH;
	}

	inittab_fp = fopen(inittab_path, "r");
	if (inittab_fp == NULL) {
		inittab_msg("inittab_lookup: fopen: %s: %s",
		    inittab_path, strerror(errno));
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
		entry.ds_dhcpv6	  = (categories & ITAB_CAT_V6) ? 1 : 0;

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
 *
 *   notes: IPv4 only
 */

int
inittab_verify(const dhcp_symbol_t *inittab_ent, dhcp_symbol_t *internal_ent)
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
 * get_hw_type(): interpret ",hwtype" in the input string, as part of a DUID.
 *		  The hwtype string is optional, and must be 0-65535 if
 *		  present.
 *
 *   input: char **: pointer to string pointer
 *	    int *: error return value
 *  output: int: hardware type, or -1 for empty, or -2 for error.
 */

static int
get_hw_type(char **strp, int *ierrnop)
{
	char *str = *strp;
	ulong_t hwtype;

	if (*str++ != ',') {
		*ierrnop = ITAB_BAD_NUMBER;
		return (-2);
	}
	if (*str == ',' || *str == '\0') {
		*strp = str;
		return (-1);
	}
	hwtype = strtoul(str, strp, 0);
	if (errno != 0 || *strp == str || hwtype > 65535) {
		*ierrnop = ITAB_BAD_NUMBER;
		return (-2);
	} else {
		return ((int)hwtype);
	}
}

/*
 * get_mac_addr(): interpret ",macaddr" in the input string, as part of a DUID.
 *		   The 'macaddr' may be a hex string (in any standard format),
 *		   or the name of a physical interface.  If an interface name
 *		   is given, then the interface type is extracted as well.
 *
 *   input: const char *: input string
 *	    int *: error return value
 *	    uint16_t *: hardware type output (network byte order)
 *	    int: hardware type input; -1 for empty
 *	    uchar_t *: output buffer for MAC address
 *  output: int: length of MAC address, or -1 for error
 */

static int
get_mac_addr(const char *str, int *ierrnop, uint16_t *hwret, int hwtype,
    uchar_t *outbuf)
{
	int maclen;
	int dig, val;
	dlpi_handle_t dh;
	dlpi_info_t dlinfo;
	char chr;

	if (*str != '\0') {
		if (*str++ != ',')
			goto failed;
		if (dlpi_open(str, &dh, 0) != DLPI_SUCCESS) {
			maclen = 0;
			dig = val = 0;
			/*
			 * Allow MAC addresses with separators matching regexp
			 * (:|-| *).
			 */
			while ((chr = *str++) != '\0') {
				if (isdigit(chr)) {
					val = (val << 4) + chr - '0';
				} else if (isxdigit(chr)) {
					val = (val << 4) + chr -
					    (isupper(chr) ? 'A' : 'a') + 10;
				} else if (isspace(chr) && dig == 0) {
					continue;
				} else if (chr == ':' || chr == '-' ||
				    isspace(chr)) {
					dig = 1;
				} else {
					goto failed;
				}
				if (++dig == 2) {
					*outbuf++ = val;
					maclen++;
					dig = val = 0;
				}
			}
		} else {
			if (dlpi_bind(dh, DLPI_ANY_SAP, NULL) !=
			    DLPI_SUCCESS || dlpi_info(dh, &dlinfo, 0) !=
			    DLPI_SUCCESS) {
				dlpi_close(dh);
				goto failed;
			}
			maclen = dlinfo.di_physaddrlen;
			(void) memcpy(outbuf, dlinfo.di_physaddr, maclen);
			dlpi_close(dh);
			if (hwtype == -1)
				hwtype = dlpi_arptype(dlinfo.di_mactype);
		}
	}
	if (hwtype == -1)
		goto failed;
	*hwret = htons(hwtype);
	return (maclen);

failed:
	*ierrnop = ITAB_BAD_NUMBER;
	return (-1);
}

/*
 * inittab_encode_e(): converts a string representation of a given datatype into
 *		     binary; used for encoding ascii values into a form that
 *		     can be put in DHCP packets to be sent on the wire.
 *
 *   input: const dhcp_symbol_t *: the entry describing the value option
 *	    const char *: the value to convert
 *	    uint16_t *: set to the length of the binary data returned
 *	    boolean_t: if false, return a full DHCP option
 *	    int *: error return value
 *  output: uchar_t *: a dynamically allocated byte array with converted data
 */

uchar_t *
inittab_encode_e(const dhcp_symbol_t *ie, const char *value, uint16_t *lengthp,
    boolean_t just_payload, int *ierrnop)
{
	int		hlen = 0;
	uint16_t	length;
	uchar_t		n_entries = 0;
	const char	*valuep;
	char		*currp;
	uchar_t		*result = NULL;
	uchar_t		*optstart;
	unsigned int	i;
	uint8_t		type_size = inittab_type_to_size(ie);
	boolean_t	is_signed;
	uint_t		vallen, reslen;
	dhcpv6_option_t	*d6o;
	int		type;
	char		*cp2;

	*ierrnop = 0;
	if (type_size == 0) {
		*ierrnop = ITAB_SYNTAX_ERROR;
		return (NULL);
	}

	switch (ie->ds_type) {
	case DSYM_ASCII:
		n_entries = strlen(value);		/* no NUL */
		break;

	case DSYM_OCTET:
		vallen = strlen(value);
		n_entries = vallen / 2;
		n_entries += vallen % 2;
		break;

	case DSYM_DOMAIN:
		/*
		 * Maximum (worst-case) encoded length is one byte more than
		 * the number of characters on input.
		 */
		n_entries = strlen(value) + 1;
		break;

	case DSYM_DUID:
		/* Worst case is ":::::" */
		n_entries = strlen(value);
		if (n_entries < DLPI_PHYSADDR_MAX)
			n_entries = DLPI_PHYSADDR_MAX;
		n_entries += sizeof (duid_llt_t);
		break;

	default:
		/*
		 * figure out the number of entries by counting the spaces
		 * in the value string
		 */
		for (valuep = value; valuep++ != NULL; n_entries++)
			valuep = strchr(valuep, ' ');
		break;
	}

	/*
	 * if we're gonna return a complete option, then include the
	 * option length and code in the size of the packet we allocate
	 */
	if (!just_payload)
		hlen = ie->ds_dhcpv6 ? sizeof (*d6o) : 2;

	length = n_entries * type_size;
	if (hlen + length > 0)
		result = malloc(hlen + length);

	if ((optstart = result) != NULL && !just_payload)
		optstart += hlen;

	switch (ie->ds_type) {

	case DSYM_ASCII:

		if (optstart == NULL) {
			*ierrnop = ITAB_NOMEM;
			return (NULL);
		}

		(void) memcpy(optstart, value, length);
		break;

	case DSYM_DOMAIN:
		if (optstart == NULL) {
			*ierrnop = ITAB_NOMEM;
			return (NULL);
		}

		/*
		 * Note that this encoder always presents the trailing 0-octet
		 * when dealing with a list.  This means that you can't have
		 * non-fully-qualified members anywhere but at the end of a
		 * list (or as the only member of the list).
		 */
		valuep = value;
		while (*valuep != '\0') {
			int dig, val, inchr;
			boolean_t escape;
			uchar_t *flen;

			/*
			 * Skip over whitespace that delimits list members.
			 */
			if (isascii(*valuep) && isspace(*valuep)) {
				valuep++;
				continue;
			}
			dig = val = 0;
			escape = B_FALSE;
			flen = optstart++;
			while ((inchr = *valuep) != '\0') {
				valuep++;
				/*
				 * Just copy non-ASCII text directly to the
				 * output string.  This simplifies the use of
				 * other ctype macros below, as, unlike the
				 * special isascii function, they don't handle
				 * non-ASCII.
				 */
				if (!isascii(inchr)) {
					escape = B_FALSE;
					*optstart++ = inchr;
					continue;
				}
				if (escape) {
					/*
					 * Handle any of \D, \DD, or \DDD for
					 * a digit escape.
					 */
					if (isdigit(inchr)) {
						val = val * 10 + inchr - '0';
						if (++dig == 3) {
							*optstart++ = val;
							dig = val = 0;
							escape = B_FALSE;
						}
						continue;
					} else if (dig > 0) {
						/*
						 * User terminated \D or \DD
						 * with non-digit.  An error,
						 * but we can assume he means
						 * to treat as \00D or \0DD.
						 */
						*optstart++ = val;
						dig = val = 0;
					}
					/* Fall through and copy character */
					escape = B_FALSE;
				} else if (inchr == '\\') {
					escape = B_TRUE;
					continue;
				} else if (inchr == '.') {
					/*
					 * End of component.  Write the length
					 * prefix.  If the component is zero
					 * length (i.e., ".."), the just omit
					 * it.
					 */
					*flen = (optstart - flen) - 1;
					if (*flen > 0)
						flen = optstart++;
					continue;
				} else if (isspace(inchr)) {
					/*
					 * Unescaped space; end of domain name
					 * in list.
					 */
					break;
				}
				*optstart++ = inchr;
			}
			/*
			 * Handle trailing escape sequence.  If string ends
			 * with \, then assume user wants \ at end of encoded
			 * string.  If it ends with \D or \DD, assume \00D or
			 * \0DD.
			 */
			if (escape)
				*optstart++ = dig > 0 ? val : '\\';
			*flen = (optstart - flen) - 1;
			/*
			 * If user specified FQDN with trailing '.', then above
			 * will result in zero for the last component length.
			 * We're done, and optstart already points to the start
			 * of the next in list.  Otherwise, we need to write a
			 * single zero byte to end the entry, if there are more
			 * entries that will be decoded.
			 */
			while (isascii(*valuep) && isspace(*valuep))
				valuep++;
			if (*flen > 0 && *valuep != '\0')
				*optstart++ = '\0';
		}
		length = (optstart - result) - hlen;
		break;

	case DSYM_DUID:
		if (optstart == NULL) {
			*ierrnop = ITAB_NOMEM;
			return (NULL);
		}

		errno = 0;
		type = strtoul(value, &currp, 0);
		if (errno != 0 || value == currp || type > 65535 ||
		    (*currp != ',' && *currp != '\0')) {
			free(result);
			*ierrnop = ITAB_BAD_NUMBER;
			return (NULL);
		}
		switch (type) {
		case DHCPV6_DUID_LLT: {
			duid_llt_t dllt;
			int hwtype;
			ulong_t tstamp;
			int maclen;

			if ((hwtype = get_hw_type(&currp, ierrnop)) == -2) {
				free(result);
				return (NULL);
			}
			if (*currp++ != ',') {
				free(result);
				*ierrnop = ITAB_BAD_NUMBER;
				return (NULL);
			}
			if (*currp == ',' || *currp == '\0') {
				tstamp = time(NULL) - DUID_TIME_BASE;
			} else {
				tstamp = strtoul(currp, &cp2, 0);
				if (errno != 0 || currp == cp2) {
					free(result);
					*ierrnop = ITAB_BAD_NUMBER;
					return (NULL);
				}
				currp = cp2;
			}
			maclen = get_mac_addr(currp, ierrnop,
			    &dllt.dllt_hwtype, hwtype,
			    optstart + sizeof (dllt));
			if (maclen == -1) {
				free(result);
				return (NULL);
			}
			dllt.dllt_dutype = htons(type);
			dllt.dllt_time = htonl(tstamp);
			(void) memcpy(optstart, &dllt, sizeof (dllt));
			length = maclen + sizeof (dllt);
			break;
		}
		case DHCPV6_DUID_EN: {
			duid_en_t den;
			ulong_t enterp;

			if (*currp++ != ',') {
				free(result);
				*ierrnop = ITAB_BAD_NUMBER;
				return (NULL);
			}
			enterp = strtoul(currp, &cp2, 0);
			DHCPV6_SET_ENTNUM(&den, enterp);
			if (errno != 0 || currp == cp2 ||
			    enterp != DHCPV6_GET_ENTNUM(&den) ||
			    (*cp2 != ',' && *cp2 != '\0')) {
				free(result);
				*ierrnop = ITAB_BAD_NUMBER;
				return (NULL);
			}
			if (*cp2 == ',')
				cp2++;
			vallen = strlen(cp2);
			reslen = (vallen + 1) / 2;
			if (hexascii_to_octet(cp2, vallen,
			    optstart + sizeof (den), &reslen) != 0) {
				free(result);
				*ierrnop = ITAB_BAD_NUMBER;
				return (NULL);
			}
			den.den_dutype = htons(type);
			(void) memcpy(optstart, &den, sizeof (den));
			length = reslen + sizeof (den);
			break;
		}
		case DHCPV6_DUID_LL: {
			duid_ll_t dll;
			int hwtype;
			int maclen;

			if ((hwtype = get_hw_type(&currp, ierrnop)) == -2) {
				free(result);
				return (NULL);
			}
			maclen = get_mac_addr(currp, ierrnop, &dll.dll_hwtype,
			    hwtype, optstart + sizeof (dll));
			if (maclen == -1) {
				free(result);
				return (NULL);
			}
			dll.dll_dutype = htons(type);
			(void) memcpy(optstart, &dll, sizeof (dll));
			length = maclen + sizeof (dll);
			break;
		}
		default:
			if (*currp == ',')
				currp++;
			vallen = strlen(currp);
			reslen = (vallen + 1) / 2;
			if (hexascii_to_octet(currp, vallen, optstart + 2,
			    &reslen) != 0) {
				free(result);
				*ierrnop = ITAB_BAD_NUMBER;
				return (NULL);
			}
			optstart[0] = type >> 8;
			optstart[1] = type;
			length = reslen + 2;
			break;
		}
		break;

	case DSYM_OCTET:

		if (optstart == NULL) {
			*ierrnop = ITAB_BAD_OCTET;
			return (NULL);
		}

		reslen = length;
		/* Call libinetutil function to decode */
		if (hexascii_to_octet(value, vallen, optstart, &reslen) != 0) {
			free(result);
			*ierrnop = ITAB_BAD_OCTET;
			return (NULL);
		}
		break;

	case DSYM_IP:
	case DSYM_IPV6:

		if (optstart == NULL) {
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
			if (inet_pton(ie->ds_type == DSYM_IP ? AF_INET :
			    AF_INET6, valuep, optstart) != 1) {
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
			optstart += type_size;
		}
		break;

	case DSYM_NUMBER:				/* FALLTHRU */
	case DSYM_UNUMBER8:				/* FALLTHRU */
	case DSYM_SNUMBER8:				/* FALLTHRU */
	case DSYM_UNUMBER16:				/* FALLTHRU */
	case DSYM_SNUMBER16:				/* FALLTHRU */
	case DSYM_UNUMBER24:				/* FALLTHRU */
	case DSYM_UNUMBER32:				/* FALLTHRU */
	case DSYM_SNUMBER32:				/* FALLTHRU */
	case DSYM_UNUMBER64:				/* FALLTHRU */
	case DSYM_SNUMBER64:

		if (optstart == NULL) {
			*ierrnop = ITAB_BAD_NUMBER;
			return (NULL);
		}

		is_signed = (ie->ds_type == DSYM_SNUMBER64 ||
		    ie->ds_type == DSYM_SNUMBER32 ||
		    ie->ds_type == DSYM_SNUMBER16 ||
		    ie->ds_type == DSYM_SNUMBER8);

		if (encode_number(n_entries, type_size, is_signed, 0, value,
		    optstart, ierrnop) == B_FALSE) {
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
	 * if just_payload is false, then we need to add the option
	 * code and length fields in.
	 */
	if (!just_payload) {
		if (ie->ds_dhcpv6) {
			/* LINTED: alignment */
			d6o = (dhcpv6_option_t *)result;
			d6o->d6o_code = htons(ie->ds_code);
			d6o->d6o_len = htons(length);
		} else {
			result[0] = ie->ds_code;
			result[1] = length;
		}
	}

	if (lengthp != NULL)
		*lengthp = length + hlen;

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
inittab_decode_e(const dhcp_symbol_t *ie, const uchar_t *payload,
    uint16_t length, boolean_t just_payload, int *ierrnop)
{
	char		*resultp, *result = NULL;
	uint_t		n_entries;
	struct in_addr	in_addr;
	in6_addr_t	in6_addr;
	uint8_t		type_size = inittab_type_to_size(ie);
	boolean_t	is_signed;
	int		type;

	*ierrnop = 0;
	if (type_size == 0) {
		*ierrnop = ITAB_SYNTAX_ERROR;
		return (NULL);
	}

	if (!just_payload) {
		if (ie->ds_dhcpv6) {
			dhcpv6_option_t d6o;

			(void) memcpy(&d6o, payload, sizeof (d6o));
			length = ntohs(d6o.d6o_len);
			payload += sizeof (d6o);
		} else {
			length = payload[1];
			payload += 2;
		}
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

	case DSYM_DOMAIN:

		/*
		 * A valid, decoded RFC 1035 domain string or sequence of
		 * strings is always the same size as the encoded form, but we
		 * allow for RFC 1035 \DDD and \\ and \. escaping.
		 *
		 * Decoding stops at the end of the input or the first coding
		 * violation.  Coding violations result in discarding the
		 * offending list entry entirely.  Note that we ignore the 255
		 * character overall limit on domain names.
		 */
		if ((result = malloc(4 * length + 1)) == NULL) {
			*ierrnop = ITAB_NOMEM;
			return (NULL);
		}
		resultp = result;
		while (length > 0) {
			char *dstart;
			int slen;

			dstart = resultp;
			while (length > 0) {
				slen = *payload++;
				length--;
				/* Upper two bits of length must be zero */
				if ((slen & 0xc0) != 0 || slen > length) {
					length = 0;
					resultp = dstart;
					break;
				}
				if (resultp != dstart)
					*resultp++ = '.';
				if (slen == 0)
					break;
				length -= slen;
				while (slen > 0) {
					if (!isascii(*payload) ||
					    !isgraph(*payload)) {
						(void) snprintf(resultp, 5,
						    "\\%03d",
						    *(unsigned char *)payload);
						resultp += 4;
						payload++;
					} else {
						if (*payload == '.' ||
						    *payload == '\\')
							*resultp++ = '\\';
						*resultp++ = *payload++;
					}
					slen--;
				}
			}
			if (resultp != dstart && length > 0)
				*resultp++ = ' ';
		}
		*resultp = '\0';
		break;

	case DSYM_DUID:

		/*
		 * First, determine the type of DUID.  We need at least two
		 * octets worth of data to grab the type code.  Once we have
		 * that, the number of octets required for representation
		 * depends on the type.
		 */

		if (length < 2) {
			*ierrnop = ITAB_BAD_GRAN;
			return (NULL);
		}
		type = (payload[0] << 8) + payload[1];
		switch (type) {
		case DHCPV6_DUID_LLT: {
			duid_llt_t dllt;

			if (length < sizeof (dllt)) {
				*ierrnop = ITAB_BAD_GRAN;
				return (NULL);
			}
			(void) memcpy(&dllt, payload, sizeof (dllt));
			payload += sizeof (dllt);
			length -= sizeof (dllt);
			n_entries = sizeof ("1,65535,4294967295,") +
			    length * 3;
			if ((result = malloc(n_entries)) == NULL) {
				*ierrnop = ITAB_NOMEM;
				return (NULL);
			}
			(void) snprintf(result, n_entries, "%d,%u,%u,", type,
			    ntohs(dllt.dllt_hwtype), ntohl(dllt.dllt_time));
			break;
		}
		case DHCPV6_DUID_EN: {
			duid_en_t den;

			if (length < sizeof (den)) {
				*ierrnop = ITAB_BAD_GRAN;
				return (NULL);
			}
			(void) memcpy(&den, payload, sizeof (den));
			payload += sizeof (den);
			length -= sizeof (den);
			n_entries = sizeof ("2,4294967295,") + length * 2;
			if ((result = malloc(n_entries)) == NULL) {
				*ierrnop = ITAB_NOMEM;
				return (NULL);
			}
			(void) snprintf(result, n_entries, "%d,%u,", type,
			    DHCPV6_GET_ENTNUM(&den));
			break;
		}
		case DHCPV6_DUID_LL: {
			duid_ll_t dll;

			if (length < sizeof (dll)) {
				*ierrnop = ITAB_BAD_GRAN;
				return (NULL);
			}
			(void) memcpy(&dll, payload, sizeof (dll));
			payload += sizeof (dll);
			length -= sizeof (dll);
			n_entries = sizeof ("3,65535,") + length * 3;
			if ((result = malloc(n_entries)) == NULL) {
				*ierrnop = ITAB_NOMEM;
				return (NULL);
			}
			(void) snprintf(result, n_entries, "%d,%u,", type,
			    ntohs(dll.dll_hwtype));
			break;
		}
		default:
			n_entries = sizeof ("0,") + length * 2;
			if ((result = malloc(n_entries)) == NULL) {
				*ierrnop = ITAB_NOMEM;
				return (NULL);
			}
			(void) snprintf(result, n_entries, "%d,", type);
			break;
		}
		resultp = result + strlen(result);
		n_entries -= strlen(result);
		if (type == DHCPV6_DUID_LLT || type == DHCPV6_DUID_LL) {
			if (length > 0) {
				resultp += snprintf(resultp, 3, "%02X",
				    *payload++);
				length--;
			}
			while (length-- > 0) {
				resultp += snprintf(resultp, 4, ":%02X",
				    *payload++);
			}
		} else {
			while (length-- > 0) {
				resultp += snprintf(resultp, 3, "%02X",
				    *payload++);
			}
		}
		break;

	case DSYM_OCTET:

		result = malloc(n_entries * (sizeof ("0xNN") + 1));
		if (result == NULL) {
			*ierrnop = ITAB_NOMEM;
			return (NULL);
		}

		result[0] = '\0';
		resultp = result;
		if (n_entries > 0) {
			resultp += sprintf(resultp, "0x%02X", *payload++);
			n_entries--;
		}
		while (n_entries-- > 0)
			resultp += sprintf(resultp, " 0x%02X", *payload++);

		break;

	case DSYM_IP:
	case DSYM_IPV6:
		if ((length / type_size) % ie->ds_gran != 0) {
			*ierrnop = ITAB_BAD_GRAN;
			inittab_msg("inittab_decode: number of entries "
			    "not compatible with option granularity");
			return (NULL);
		}

		result = malloc(n_entries * (ie->ds_type == DSYM_IP ?
		    INET_ADDRSTRLEN : INET6_ADDRSTRLEN));
		if (result == NULL) {
			*ierrnop = ITAB_NOMEM;
			return (NULL);
		}

		for (resultp = result; n_entries != 0; n_entries--) {
			if (ie->ds_type == DSYM_IP) {
				(void) memcpy(&in_addr.s_addr, payload,
				    sizeof (ipaddr_t));
				(void) strcpy(resultp, inet_ntoa(in_addr));
			} else {
				(void) memcpy(&in6_addr, payload,
				    sizeof (in6_addr));
				(void) inet_ntop(AF_INET6, &in6_addr, resultp,
				    INET6_ADDRSTRLEN);
			}
			resultp += strlen(resultp);
			if (n_entries > 1)
				*resultp++ = ' ';
			payload += type_size;
		}
		*resultp = '\0';
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
inittab_encode(const dhcp_symbol_t *ie, const char *value, uint16_t *lengthp,
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
inittab_decode(const dhcp_symbol_t *ie, const uchar_t *payload, uint16_t length,
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
			to += sprintf(to, is_signed ? "%d" : "%u", *from);
			break;

		case 2:
			(void) memcpy(&uint16, from, 2);
			to += sprintf(to, is_signed ? "%hd" : "%hu",
			    ntohs(uint16));
			break;

		case 3:
			uint32 = 0;
			(void) memcpy((uchar_t *)&uint32 + 1, from, 3);
			to += sprintf(to, is_signed ? "%ld" : "%lu",
			    ntohl(uint32));
			break;

		case 4:
			(void) memcpy(&uint32, from, 4);
			to += sprintf(to, is_signed ? "%ld" : "%lu",
			    ntohl(uint32));
			break;

		case 8:
			(void) memcpy(&uint64, from, 8);
			to += sprintf(to, is_signed ? "%lld" : "%llu",
			    ntohll(uint64));
			break;

		default:
			*ierrnop = ITAB_BAD_NUMBER;
			inittab_msg("decode_number: unknown integer size `%d'",
			    size);
			return (B_FALSE);
		}
		if (n_entries > 0)
			*to++ = ' ';
	}

	*to = '\0';
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

	for (i = 0; i < n_entries; i++, from++, to += size) {

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
			*to = strtoul(from, &endptr, 0);
			if (errno != 0 || from == endptr) {
				goto error;
			}
			break;

		case 2:
			uint16 = htons(strtoul(from, &endptr, 0));
			if (errno != 0 || from == endptr) {
				goto error;
			}
			(void) memcpy(to, &uint16, 2);
			break;

		case 3:
			uint32 = htonl(strtoul(from, &endptr, 0));
			if (errno != 0 || from == endptr) {
				goto error;
			}
			(void) memcpy(to, (uchar_t *)&uint32 + 1, 3);
			break;

		case 4:
			uint32 = htonl(strtoul(from, &endptr, 0));
			if (errno != 0 || from == endptr) {
				goto error;
			}
			(void) memcpy(to, &uint32, 4);
			break;

		case 8:
			uint64 = htonll(strtoull(from, &endptr, 0));
			if (errno != 0 || from == endptr) {
				goto error;
			}
			(void) memcpy(to, &uint64, 8);
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
inittab_type_to_size(const dhcp_symbol_t *ie)
{
	switch (ie->ds_type) {

	case DSYM_DUID:
	case DSYM_DOMAIN:
	case DSYM_ASCII:
	case DSYM_OCTET:
	case DSYM_SNUMBER8:
	case DSYM_UNUMBER8:

		return (1);

	case DSYM_SNUMBER16:
	case DSYM_UNUMBER16:

		return (2);

	case DSYM_UNUMBER24:

		return (3);

	case DSYM_SNUMBER32:
	case DSYM_UNUMBER32:
	case DSYM_IP:

		return (4);

	case DSYM_SNUMBER64:
	case DSYM_UNUMBER64:

		return (8);

	case DSYM_NUMBER:

		return (ie->ds_gran);

	case DSYM_IPV6:

		return (sizeof (in6_addr_t));
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
{ DSYM_FIELD,		28,	"Chaddr",	DSYM_OCTET,	1,	16 },
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
