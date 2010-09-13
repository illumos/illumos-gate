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

#ifndef _CFGA_CONF_H
#define	_CFGA_CONF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* for ib.conf file support */

#define	IBCONF_FILE		"/kernel/drv/ib.conf"

/* type of variable entries read */
typedef struct ibcfg_var {
	char			*name;		/* service name */
	ib_service_type_t	type;		/* service type */
} ibcfg_var_t;

/* values returned during parsing */
typedef enum ib_parse_state_e {
	IB_NEWVAR,				/* new token seen */
	IB_CONFIG_VAR,				/* "name" token seen */
	IB_VAR_EQUAL,				/* "=" token seen */
	IB_VAR_VALUE,				/* "value" token seen */
	IB_ERROR				/* error seen */
} ib_parse_state_t;

/* service record for each entry read */
typedef struct ib_svc_rec_s {
	char			*name;		/* service name */
	ib_service_type_t	type;		/* service type */
	struct ib_svc_rec_s	*next;		/* next link */
} ib_svc_rec_t;


#define	isunary(ch)		((ch) == '~' || (ch) == '-')
#define	iswhite(ch)		((ch) == ' ' || (ch) == '\t')
#define	isnewline(ch)		((ch) == '\n' || (ch) == '\r' || (ch) == '\f')
#define	isalphanum(ch)		(isalpha(ch) || isdigit(ch))
#define	isnamechar(ch)		(isalphanum(ch) || (ch) == '_' || (ch) == '-')

#define	GETC(a, cntr)		a[cntr++]
#define	UNGETC(cntr)		cntr--
#define	MAXLINESIZE		132

/* string defines for conf file usage */
#define	IBCONF_PORT_SERVICE_HDR	"PORT communication services:\n"
#define	IBCONF_VPPA_SERVICE_HDR	"VPPA communication services:\n"
#define	IBCONF_HCA_SERVICE_HDR	"HCA communication services:\n"
#define	IBCONF_SERVICE_HDR_LEN	32

/* tokens as read from IBCONF_FILE */
typedef enum ib_token_e {
	EQUALS,
	AMPERSAND,
	BIT_OR,
	STAR,
	POUND,
	COLON,
	SEMICOLON,
	COMMA,
	SLASH,
	WHITE_SPACE,
	NEWLINE,
	E_O_F,
	STRING,			/* c */
	HEXVAL,
	DECVAL,
	NAME			/* f */
} ib_token_t;


#ifdef __cplusplus
}
#endif

#endif /* _CFGA_CONF_H */
