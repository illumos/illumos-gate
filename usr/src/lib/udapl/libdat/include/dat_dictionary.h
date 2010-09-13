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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dat_dictionary.h
 *
 * PURPOSE: dictionary data structure
 *
 * $Id: dat_dictionary.h,v 1.6 2003/08/05 19:01:48 jlentini Exp $
 */

#ifndef _DAT_DICTIONARY_H_
#define	_DAT_DICTIONARY_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <dat_osd.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *
 * Typedefs
 *
 */

typedef struct DAT_DICTIONARY   DAT_DICTIONARY;
typedef	void			*DAT_DICTIONARY_DATA;
typedef	void			*DAT_DICTIONARY_ENTRY;


/*
 *
 * Function Prototypes
 *
 */

extern DAT_RETURN
dat_dictionary_create(
    OUT DAT_DICTIONARY **pp_dictionary);

extern DAT_RETURN
dat_dictionary_destroy(
    IN  DAT_DICTIONARY *p_dictionary);

extern DAT_RETURN
dat_dictionary_size(
    IN  DAT_DICTIONARY *p_dictionary,
    OUT DAT_COUNT *p_size);

extern DAT_RETURN
dat_dictionary_entry_create(
    OUT DAT_DICTIONARY_ENTRY *p_entry);

extern DAT_RETURN
dat_dictionary_entry_destroy(
    IN  DAT_DICTIONARY_ENTRY entry);

extern DAT_RETURN
dat_dictionary_insert(
    IN  DAT_DICTIONARY *p_dictionary,
    IN  DAT_DICTIONARY_ENTRY entry,
    IN  const DAT_PROVIDER_INFO *key,
    IN  DAT_DICTIONARY_DATA data);

extern DAT_RETURN
dat_dictionary_search(
    IN  DAT_DICTIONARY *p_dictionary,
    IN  const DAT_PROVIDER_INFO *key,
    OUT DAT_DICTIONARY_DATA *p_data);

extern DAT_RETURN
dat_dictionary_enumerate(
    IN  DAT_DICTIONARY *p_dictionary,
    IN  DAT_DICTIONARY_DATA array[],
    IN  DAT_COUNT array_size);


extern DAT_RETURN
dat_dictionary_remove(
    IN  DAT_DICTIONARY *p_dictionary,
    IN  DAT_DICTIONARY_ENTRY *p_entry,
    IN  const DAT_PROVIDER_INFO *key,
    OUT DAT_DICTIONARY_DATA *p_data);

#ifdef	__cplusplus
}
#endif

#endif /* _DAT_DICTIONARY_H_ */
