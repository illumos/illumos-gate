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

#ifndef _SYS_KICONV_H
#define	_SYS_KICONV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#ifdef	_KERNEL

/*
 * Supported fromcode/tocode values are saved in the following component type
 * of (name, id) pair. The id values of fromcode and tocode are used to
 * find out the corresponding code conversions.
 */
typedef struct {
	char		*name;
	size_t		id;
} kiconv_code_list_t;

/*
 * Each unique kiconv code conversion identified by tocode and fromcode ids
 * have corresponding module id and internal function pointers to open(),
 * kiconv(), close(), and kiconvstr().
 */
typedef struct {
	uint16_t	tid;		/* tocode id. */
	uint16_t	fid;		/* fromcode id. */
	uint16_t	mid;		/* module id. */
	void		*(*open)(void);
	size_t		(*kiconv)(void *, char **, size_t *, char **, size_t *,
			int *);
	int		(*close)(void *);
	size_t		(*kiconvstr)(char *, size_t *, char *, size_t *, int,
			int *);
} kiconv_conv_list_t;

/*
 * Each module id has a corresponding module name that is used to load
 * the module as needed and a reference counter.
 */
typedef struct {
	char		*name;
	uint_t		refcount;
} kiconv_mod_list_t;

/*
 * The following two data structures are being used to transfer information
 * on the supported kiconv code conversions from a module to the framework.
 *
 * Details can be found from kiconv_ops(9S) and kiconv_module_info(9S)
 * man pages at PSARC/2007/173.
 */
typedef struct {
	char		*tocode;
	char		*fromcode;
	void		*(*kiconv_open)(void);
	size_t		(*kiconv)(void *, char **, size_t *, char **, size_t *,
			int *);
	int		(*kiconv_close)(void *);
	size_t		(*kiconvstr)(char *, size_t *, char *, size_t *, int,
			int *);
} kiconv_ops_t;

typedef struct kiconv_mod_info {
	char		*module_name;
	size_t		kiconv_num_convs;
	kiconv_ops_t	*kiconv_ops_tbl;
	size_t		kiconv_num_aliases;
	char		**aliases;
	char		**canonicals;
	int		nowait;
} kiconv_module_info_t;

/* The kiconv code conversion descriptor data structure. */
typedef struct {
	void		*handle;	/* Handle from the actual open(). */
	size_t		id;		/* Index to the conv_list[]. */
} kiconv_data_t, *kiconv_t;

/* Common conversion state data structure. */
typedef struct {
	uint8_t		id;
	uint8_t		bom_processed;
} kiconv_state_data_t, *kiconv_state_t;

/* Common component types for possible code conversion mapping tables. */
typedef struct {
	uchar_t		u8[3];
} kiconv_to_utf8_tbl_comp_t;

typedef struct {
	uint32_t	u8:24;
	uint32_t	sb:8;
} kiconv_to_sb_tbl_comp_t;

/*
 * The maximum name length for any given codeset or alias names; the following
 * should be plenty big enough.
 */
#define	KICONV_MAX_CODENAME_LEN		63

/* The following characters do not exist in the normalized code names. */
#define	KICONV_SKIPPABLE_CHAR(c)	\
	((c) == '-' || (c) == '_' || (c) == '.' || (c) == '@')

/*
 * When we encounter non-identical characters, as like iconv(3C) we have,
 * map them into either one of the replacement characters based on what is
 * the current target tocde.
 *
 * The 0xefbfdb in UTF-8 is U+FFFD in Unicode scalar value.
 */
#define	KICONV_ASCII_REPLACEMENT_CHAR	('?')
#define	KICONV_UTF8_REPLACEMENT_CHAR	(0xefbfbd)

/* Numeric ids for kiconv modules. */
#define	KICONV_EMBEDDED			(0)
#define	KICONV_MODULE_ID_JA		(1)
#define	KICONV_MODULE_ID_SC		(2)
#define	KICONV_MODULE_ID_KO		(3)
#define	KICONV_MODULE_ID_TC		(4)
#define	KICONV_MODULE_ID_EMEA		(5)

#define	KICONV_MAX_MODULE_ID		KICONV_MODULE_ID_EMEA

/* Functions used in kiconv conversion and module management. */
extern void	kiconv_init();
extern int	kiconv_register_module(kiconv_module_info_t *);
extern int	kiconv_unregister_module(kiconv_module_info_t *);
extern size_t	kiconv_module_ref_count(size_t);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_KICONV_H */
