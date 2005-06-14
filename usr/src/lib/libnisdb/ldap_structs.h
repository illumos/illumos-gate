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
 * Copyright 2001, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LDAP_STRUCTS_H
#define	_LDAP_STRUCTS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/time.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Some functions accept a pointer to either a __nis_mapping_item_t, or
 * a __nis_value_t. This enum tells us which it is.
 */
typedef enum {fa_any, fa_item, fa_value} __nis_format_arg_t;

/*
 * A __nis_value_t contains either string (vt_string) or non-string
 * (vt_ber) values.
 */
typedef enum {vt_any, vt_string, vt_ber} __nis_value_type_t;

/* A single value. If the value is a (char *), the length includes the NUL */
typedef struct {
	int			length;
	void			*value;
} __nis_single_value_t;

/*
 * Holds multiple values of the specified type.
 */
typedef struct {
	__nis_value_type_t	type;
	int			repeat;		/* Should value be repeated ? */
	int			numVals;
	__nis_single_value_t	*val;
} __nis_value_t;

/* Structure used to build rule values */
typedef struct {
	int			numColumns;	/* Number of col names/vals */
	char			**colName;	/* Column names */
	__nis_value_t		*colVal;	/* Column values */
	int			numAttrs;	/* Number of attr names vals */
	char			**attrName;	/* Attribute names */
	__nis_value_t		*attrVal;	/* Attribute values */
} __nis_rule_value_t;

/* Structure containing information that ldap_search_s() wants */
typedef struct {
	unsigned char	useCon;	/* Should we use existing connection ? */
	char		*base;
	int		scope;
	int		numFilterComps;
	char		**filterComp;
	char		*filter;
	int		numAttrs;
	char		**attrs;
	int		attrsonly;
	int		isDN;
	struct timeval	timeout;
} __nis_ldap_search_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _LDAP_STRUCTS_H */
