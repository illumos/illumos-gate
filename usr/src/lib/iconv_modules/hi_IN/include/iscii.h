/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright(c) 2001 Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _ISCII_H_
#define _ISCII_H_

#include "iscii-bng.h"
#include "iscii-dev.h"
#include "iscii-gjr.h"
#include "iscii-gmk.h"
#include "iscii-knd.h"
#include "iscii-mlm.h"
#include "iscii-ori.h"
#include "iscii-tlg.h"
#include "iscii-tml.h"

#define get_script_types(ucs, type) \
    if ( ucs >= 0x0900 && ucs <= 0x097f ) \
        type = DEV; \
    else if ( ucs >= 0x0980 && ucs <= 0x09ff ) \
        type = BNG; \
    else if ( ucs >= 0x0a00 && ucs <= 0x0a7f ) \
        type = GMK; \
    else if ( ucs >= 0x0a80 && ucs <= 0x0aff ) \
        type = GJR; \
    else if ( ucs >= 0x0b00 && ucs <= 0x0b7f ) \
        type = ORI; \
    else if ( ucs >= 0x0b80 && ucs <= 0x0bff ) \
        type = TML; \
    else if ( ucs >= 0x0c00 && ucs <= 0x0c7f ) \
        type = TLG; \
    else if ( ucs >= 0x0c80 && ucs <= 0x0cff ) \
        type = KND; \
    else if ( ucs >= 0x0d00 && ucs <= 0x0d7f ) \
        type = MLM; \
    else \
        type = NUM_ISCII;

ISCII isc_TYPE[] = {
    DEV, /* 0x42 */
    BNG, /* 0x43 */
    TML, /* 0x44 */
    TLG, /* 0x45 */
    NUM_ISCII,/* 0x46 */
    ORI, /* 0x47 */
    KND, /* 0x48 */
    MLM, /* 0x49 */
    GJR, /* 0x4a */
    GMK  /* 0x4b */
};

int aTRs[NUM_ISCII] = {
    0x42, /* Devanagiri */
    0x43, /* Bengali */
    0x4b, /* Gurumukhi */
    0x4a, /* Gujarati */
    0x47, /* Oriya */
    0x44, /* Tamil */
    0x45, /* Telugu */
    0x48, /* Kannada */
    0x49 /* Malayalam */
};

typedef struct _Entries {
     Entry *entry;
     int   items;
} Entries;

Entries iscii_table[NUM_ISCII]= {
     { Devanagari_isc, sizeof(Devanagari_isc)/sizeof(Entry) },
     { Bengali_isc,  sizeof(Bengali_isc)/sizeof(Entry) },
     { Gurmukhi_isc,  sizeof(Gurmukhi_isc)/sizeof(Entry) },
     { Gujarati_isc,  sizeof(Gujarati_isc)/sizeof(Entry) },
     { Oriya_isc,  sizeof(Oriya_isc)/sizeof(Entry) },
     { Tamil_isc,  sizeof(Tamil_isc)/sizeof(Entry) },
     { Telugu_isc,  sizeof(Telugu_isc)/sizeof(Entry) },
     { Kannada_isc,  sizeof(Kannada_isc)/sizeof(Entry) },
     { Malayalam_isc,  sizeof(Malayalam_isc)/sizeof(Entry) }
};

Entries unicode_table[NUM_ISCII]= {
     { Devanagari_uni, sizeof(Devanagari_uni)/sizeof(Entry) },
     { Bengali_uni,  sizeof(Bengali_uni)/sizeof(Entry) },
     { Gurmukhi_uni,  sizeof(Gurmukhi_uni)/sizeof(Entry) },
     { Gujarati_uni,  sizeof(Gujarati_uni)/sizeof(Entry) },
     { Oriya_uni,  sizeof(Oriya_uni)/sizeof(Entry) },
     { Tamil_uni,  sizeof(Tamil_uni)/sizeof(Entry) },
     { Telugu_uni,  sizeof(Telugu_uni)/sizeof(Entry) },
     { Kannada_uni,  sizeof(Kannada_uni)/sizeof(Entry) },
     { Malayalam_uni,  sizeof(Malayalam_uni)/sizeof(Entry) }
};

int *nukta_type[NUM_ISCII] = {
    Devanagari_nukta_type,
    Bengali_nukta_type,
    Gurmukhi_nukta_type,
    NULL,
    Oriya_nukta_type,
    NULL,
    NULL,
    NULL,
    NULL
};

int *EXT_type[NUM_ISCII] = {
    Devanagari_EXT_type,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};
#endif
