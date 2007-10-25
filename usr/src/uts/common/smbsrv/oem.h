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

/*
 * Support for oem <-> unicode translations.
 */

#ifndef	_SMBSRV_OEM_H
#define	_SMBSRV_OEM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <smbsrv/smb_i18n.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	oem_default_smb_cpid OEM_CP_IND_850
#define	oem_default_telnet_cpid OEM_CP_IND_1252
#define	oem_default_language "english"

/*
 * The id should corresponds to oemcp_table in os/library/oem.c.
 */
typedef enum codepage_id {
	OEM_CP_IND_850 = 0,
	OEM_CP_IND_950,
	OEM_CP_IND_1252,
	OEM_CP_IND_949,
	OEM_CP_IND_936,
	OEM_CP_IND_932,
	OEM_CP_IND_852,
	OEM_CP_IND_1250,
	OEM_CP_IND_1253,
	OEM_CP_IND_737,
	OEM_CP_IND_1254,
	OEM_CP_IND_857,
	OEM_CP_IND_1251,
	OEM_CP_IND_866,
	OEM_CP_IND_1255,
	OEM_CP_IND_862,
	OEM_CP_IND_1256,
	OEM_CP_IND_720,
	NO_OF_OEM_CP_INDS
} codepage_id_t;


typedef struct language {
    char *language;
    unsigned int smbIndex;
    unsigned int telnetIndex;
} language;


/*
 * cpid = the cpid of the oemcp_table that oempage_t belong to.
 * value = the conversion values
 */
typedef struct oempage_t {
	unsigned int cpid;
	mts_wchar_t *value;
} oempage_t;

/*
 * Private functions for opmlang.c
 */
extern int oem_codepage_init(unsigned int);
extern void oem_codepage_free(unsigned int);
extern language *oem_get_lang_table(void);
extern int oem_no_of_languages(void);
#define	NO_OF_LANGUAGES oem_no_of_languages()

/*
 * Public functions
 */
extern size_t unicodestooems(char *, const mts_wchar_t *, size_t, unsigned int);
extern size_t oemstounicodes(mts_wchar_t *, const char *, size_t, unsigned int);

#ifdef __cplusplus
}
#endif

#endif	/* _SMBSRV_OEM_H */
