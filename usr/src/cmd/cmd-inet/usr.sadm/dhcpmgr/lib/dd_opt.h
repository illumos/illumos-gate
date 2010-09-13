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
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _DD_OPT_H
#define	_DD_OPT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* The different data types of options supported by the service */
enum option_type {
	ERROR_OPTION = -1,
	ASCII_OPTION,
	BOOLEAN_OPTION,
	IP_OPTION,
	NUMBER_OPTION,
	OCTET_OPTION
};

/* Structure returned by dd_getopt */
struct dhcp_option {
	int error_code;		/* Error indication; 0 == no error */
	union {
		char *msg;	/* Error message if error_code != 0 */
		struct {
			enum option_type datatype;	/* Type of option */
			ushort_t granularity;		/* How big is it */
			ushort_t count;			/* How many */
			union {	/* The data, depending on datatype */
				char **strings;
				boolean_t value;
				struct in_addr **addrs;
				int64_t *numbers;
				uchar_t **octets;
			} data;
		} ret;
	} u;
};

extern struct dhcp_option *dd_getopt(ushort_t, const char *, const char *);
extern void dd_freeopt(struct dhcp_option *);

#ifdef	__cplusplus
}
#endif

#endif	/* !_DD_OPT_H */
