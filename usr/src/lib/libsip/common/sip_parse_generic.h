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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SIP_PARSE_GENERIC_H
#define	_SIP_PARSE_GENERIC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sip.h>
#include <sys/types.h>

#include "sip_msg.h"

extern int		sip_atoi(_sip_header_t	*, int *);
extern int		sip_find_token(_sip_header_t  *, char);
extern int		sip_find_cr(_sip_header_t *);
extern int		sip_find_separator(_sip_header_t *, char, char, char,
			    boolean_t);
extern int		sip_find_white_space(_sip_header_t *);
extern int		sip_skip_white_space(_sip_header_t *);
extern int		sip_reverse_skip_white_space(_sip_header_t *);
extern int		sip_parse_goto_values(_sip_header_t  *);
extern int		sip_goto_next_value(_sip_header_t *);
extern int		sip_parse_params(_sip_header_t *, sip_param_t **);
extern int		sip_prim_parsers(_sip_header_t *,
			    sip_parsed_header_t **);
extern boolean_t	sip_is_empty_hdr(_sip_header_t *);
extern int		sip_parse_hdr_empty(_sip_header_t *,
			    sip_parsed_header_t **);
int			sip_get_protocol_version(_sip_header_t *,
			    sip_proto_version_t *sip_proto_version);
extern int		sip_parse_first_line(_sip_header_t *,
			    sip_message_type_t **);
extern int		sip_parse_hdr_parser1(_sip_header_t *,
			    sip_parsed_header_t **, char);
extern int		sip_parse_hdr_parser2(_sip_header_t *,
			    sip_parsed_header_t **, int);
extern int		sip_parse_hdr_parser3(_sip_header_t *,
			    sip_parsed_header_t **, int, boolean_t);
extern int		sip_parse_hdr_parser4(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_hdr_parser5(_sip_header_t *,
			    sip_parsed_header_t **, boolean_t);
#ifdef	__cplusplus
}
#endif

#endif	/* _SIP_PARSE_GENERIC_H */
