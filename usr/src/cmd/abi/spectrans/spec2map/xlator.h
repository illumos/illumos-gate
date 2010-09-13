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

#ifndef	_XLATOR_H
#define	_XLATOR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <parser.h>
#include <errlog.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ARCHBUFLEN	80

/* Architecture Bitmap */
#define	XLATOR_SPARC	0x01
#define	XLATOR_SPARCV9	0x02
#define	XLATOR_I386	0x04
#define	XLATOR_IA64	0x08
#define	XLATOR_AMD64	0x10
#define	XLATOR_ALLARCH	0xFF

/* *_sanity() return codes */
#define	VS_OK	0
#define	VS_INVARCH	1
#define	VS_INVVERS	2
#define	VS_INVALID	3

typedef enum {
	NOTYPE,			/* A type has not yet been assigned */
				/* to the interface */
	FUNCTION = XLATOR_KW_FUNC,	/* Functional Interface */
	DATA = XLATOR_KW_DATA		/* Data Interface */
}    Iftype;

typedef enum {
	DEFAULT,		/* No special mapfile treatment */
	DIRECT,			/* Needs "<sym> DIRECT;" in mapfile */
	NODIRECT,		/* Needs "<sym> NODIRECT;" in mapfile */
	PROTECTED		/* Needs to be in a "protected:" section */
}    Ifbinding;

typedef struct Interface {
	char const *IF_name;		/* Name of interface */
	Iftype IF_type;		/* type: FUNCTION or DATA */
	char *IF_version;	/* Version information */
	char *IF_class;		/* public or private or some color */
	Ifbinding IF_binding;	/* direct or nodirect or protected */
	char *IF_filter;	/* path string for "filter" keyword */
	char *IF_auxiliary;	/* path string for "auxiliary" keyword */
}    Interface;

extern char *TargetArchStr;
extern int IsFilterLib;

extern int check_version(const int, const int, const char);
extern int parse_setfile(const char *);
extern int parse_versions(const char *);

extern int valid_version(const char *);
extern int valid_arch(const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _XLATOR_H */
