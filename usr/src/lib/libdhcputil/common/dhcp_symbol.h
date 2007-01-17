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

#ifndef	_DHCP_SYMBOL_H
#define	_DHCP_SYMBOL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file, along with <dhcp_symbol_common.h>, contains the DHCP symbol
 * constants and the definitions for the external interfaces to the parsing
 * logic (contained in dhcp_symbol.c) for symbol definitions. These
 * definitions can and should be used by all consumers of DHCP symbols.
 */

#include <sys/types.h>
#include <dhcp_svc_private.h>
#include <dhcp_symbol_common.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Vendor class length (and implicitly, the number of classes)
 */
#define	DSYM_CLASS_SIZE		DSVC_MAX_MACSYM_LEN	/* Single class max */
#define	DSYM_MAX_CLASS_SIZE	(DSYM_CLASS_SIZE * 10)	/* At least 10 */

/*
 * Maximum symbol length is defined by the libdhcpsvc.
 */
#define	DSYM_MAX_SYM_LEN	DSVC_MAX_MACSYM_LEN

/*
 * symbol parsing error codes
 */
typedef enum {
	DSYM_SUCCESS,
	DSYM_SYNTAX_ERROR,
	DSYM_NULL_FIELD,
	DSYM_TOO_MANY_FIELDS,
	DSYM_CODE_OUT_OF_RANGE,
	DSYM_VALUE_OUT_OF_RANGE,
	DSYM_INVALID_CAT,
	DSYM_INVALID_TYPE,
	DSYM_EXCEEDS_CLASS_SIZE,
	DSYM_EXCEEDS_MAX_CLASS_SIZE,
	DSYM_NO_MEMORY,
	DSYM_INVALID_FIELD_NUM
} dsym_errcode_t;

/*
 * symbol fields
 */
#define	DSYM_CAT_FIELD		0
#define	DSYM_CODE_FIELD		1
#define	DSYM_TYPE_FIELD		2
#define	DSYM_GRAN_FIELD		3
#define	DSYM_MAX_FIELD		4
#define	DSYM_NUM_FIELDS		5
#define	DSYM_FIRST_FIELD	DSYM_CAT_FIELD

/*
 * This structure is used by the dhcp_symbol_t structure below
 * when the option being defined is a vendor option. In which case,
 * this structure contains the client classes for which the option
 * applies.
 */
typedef struct dhcp_classes {
	char		**dc_names;
	uint8_t		dc_cnt;
} dhcp_classes_t;

/*
 * This structure is used to define a DHCP symbol. The structure is
 * used by both the inittab parsing routines and by the dhcptab parsing
 * routines to define a symbol definition in either of those tables.
 * Note that ds_dhcpv6 is defined last so that it needn't be initialized
 * as part of the inittab_table[] definition.
 */
typedef struct dhcp_symbol {
	dsym_category_t	ds_category;			/* category */
	ushort_t	ds_code;			/* option code */
	char		ds_name[DSYM_MAX_SYM_LEN + 1];	/* option name */
	dsym_cdtype_t	ds_type;			/* type of parm */
	uchar_t		ds_gran;			/* granularity */
	uchar_t		ds_max;				/* maximum number */
	dhcp_classes_t	ds_classes;			/* client classes */
	uchar_t		ds_dhcpv6;			/* dhcpv6 flag */
} dhcp_symbol_t;

extern void dsym_free_fields(char **);
extern void dsym_free_classes(dhcp_classes_t *);
extern void dsym_close_parser(char **, dhcp_symbol_t *);
extern dsym_errcode_t dsym_init_parser(const char *, const char *, char ***,
    dhcp_symbol_t *);
extern dsym_errcode_t dsym_parse_field(int, char **, dhcp_symbol_t *);
extern dsym_errcode_t dsym_parser(char **, dhcp_symbol_t *, int *, boolean_t);
extern dsym_errcode_t dsym_get_cat_id(const char *, dsym_category_t *,
    boolean_t);
extern dsym_errcode_t dsym_get_code_ranges(const char *cat, ushort_t *,
    ushort_t *, boolean_t);
extern dsym_errcode_t dsym_get_type_id(const char *, dsym_cdtype_t *,
    boolean_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _DHCP_SYMBOL_H */
