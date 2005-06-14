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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <dhcpagent_ipc.h>
#include <dhcp_inittab.h>
#include <dhcp_symbol.h>

#define	DHCP_INFO_VENDOR_START	256

static void
usage(const char *program)
{
	(void) fprintf(stderr,
	    "usage: %s [-i interface] [-n limit] [-c] code\n"
	    "       %s [-i interface] [-n limit] [-c] identifier\n",
	    program, program);

	exit(DHCP_EXIT_BADARGS);
}

int
main(int argc, char **argv)
{
	ssize_t			max_lines = -1;
	size_t			gran, n_spaces = 0;
	dhcp_optnum_t		optnum;
	dhcp_ipc_request_t	*request;
	dhcp_ipc_reply_t	*reply;
	int			c, error, i;
	char			*ifname = "";
	char			*value, *valuep;
	dhcp_symbol_t		*entry;
	DHCP_OPT		*opt;
	size_t			opt_len;
	boolean_t		is_canonical = B_FALSE;

	while ((c = getopt(argc, argv, "cn:i:")) != EOF) {

		switch (c) {

		case 'c':
			is_canonical = B_TRUE;
			break;

		case 'i':
			ifname = optarg;
			break;

		case 'n':
			max_lines = strtoul(optarg, NULL, 0);
			break;

		case '?':
			usage(argv[0]);

		default:
			break;
		}
	}

	if (argc - optind != 1)
		usage(argv[0]);

	/*
	 * we either have a code or an identifer.  if we have a code,
	 * then values over 256 indicate a vendor option.  if we have
	 * an identifier, then use inittab_getbyname() to turn the
	 * identifier into a code, then send the request over the wire.
	 */

	if (isalpha(*argv[optind])) {

		entry = inittab_getbyname(ITAB_CAT_SITE|ITAB_CAT_STANDARD|
		    ITAB_CAT_VENDOR|ITAB_CAT_FIELD, ITAB_CONS_INFO,
		    argv[optind]);

		if (entry == NULL) {
			(void) fprintf(stderr, "%s: unknown identifier `%s'\n",
			    argv[0], argv[optind]);
			return (DHCP_EXIT_BADARGS);
		}

		optnum.code	= entry->ds_code;
		optnum.category = entry->ds_category;

	} else {

		optnum.code	= strtoul(argv[optind], 0, 0);
		optnum.category = ITAB_CAT_STANDARD|ITAB_CAT_SITE;

		/*
		 * sigh.  this is a hack, but it's needed for backward
		 * compatibility with the CA dhcpinfo program.
		 */

		if (optnum.code > DHCP_INFO_VENDOR_START) {
			optnum.code    -= DHCP_INFO_VENDOR_START;
			optnum.category = ITAB_CAT_VENDOR;
		}

		entry = inittab_getbycode(optnum.category, ITAB_CONS_INFO,
		    optnum.code);

		if (entry == NULL) {
			(void) fprintf(stderr, "%s: unknown code `%s'\n",
			    argv[0], argv[optind]);
			return (DHCP_EXIT_BADARGS);
		}
		optnum.category = entry->ds_category;
	}

	optnum.size = entry->ds_max * inittab_type_to_size(entry);

	/*
	 * send the request to the agent and reap the reply
	 */

	request = dhcp_ipc_alloc_request(DHCP_GET_TAG, ifname, &optnum,
	    sizeof (dhcp_optnum_t), DHCP_TYPE_OPTNUM);

	if (request == NULL)
		return (DHCP_EXIT_SYSTEM);

	error = dhcp_ipc_make_request(request, &reply, DHCP_IPC_WAIT_DEFAULT);
	if (error != 0 || reply->return_code != 0) {

		if (error == 0)
			error = reply->return_code;

		(void) fprintf(stderr, "%s: %s\n", argv[0],
		    dhcp_ipc_strerror(error));

		if (error == DHCP_IPC_E_TIMEOUT)
			return (DHCP_EXIT_TIMEOUT);

		return (DHCP_EXIT_FAILURE);
	}

	opt = dhcp_ipc_get_data(reply, &opt_len, NULL);

	/*
	 * no data means that the client has an ACK but has no information
	 * about the specified option; return success
	 */

	if (opt_len == 0)
		return (DHCP_EXIT_SUCCESS);

	/*
	 * check for protocol error
	 */

	if (opt_len < 2 || (opt_len - 2 != opt->len))
		return (DHCP_EXIT_FAILURE);

	if (is_canonical) {

		value = malloc(opt->len * (sizeof ("0xNN") + 1));
		if (value == NULL) {
			(void) fprintf(stderr, "%s: out of memory\n", argv[0]);
			return (DHCP_EXIT_FAILURE);
		}

		for (i = 0, valuep = value; i < opt->len; i++)
			valuep += sprintf(valuep, "0x%02X ", opt->value[i]);

		valuep[-1] = '\0';
		gran = 1;

	} else {

		value = inittab_decode(entry, opt->value, opt->len, B_TRUE);
		if (value == NULL) {
			(void) fprintf(stderr, "%s: cannot decode agent's "
			    "reply\n", argv[0]);
			return (DHCP_EXIT_FAILURE);
		}

		gran = entry->ds_gran;
	}

	/*
	 * now display `gran' items per line, printing at most `max_lines'.
	 */

	for (i = 0; value[i] != '\0'; i++) {
		if (value[i] == ' ') {
			if ((++n_spaces % gran) == 0) {
				value[i] = '\n';
				if (max_lines != -1 && --max_lines == 0) {
					value[i] = '\0';
					break;
				}
			}
		}
	}

	(void) printf("%s\n", value);

	return (DHCP_EXIT_SUCCESS);
}
