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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MANIFEST_HASH_H
#define	_MANIFEST_HASH_H


#include <sys/types.h>
#include <libscf.h>
#include <md5.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MHASH_SIZE	(MD5_DIGEST_LENGTH * 2)
#define	MHASH_SIZE_OLD	MD5_DIGEST_LENGTH
#define	MHASH_SVC	"smf/manifest"
#define	MHASH_PG_TYPE	"framework"
#define	MHASH_PG_FLAGS	0
#define	MHASH_PROP	"md5sum"

#define	MHASH_FORMAT_V1	"%llx%x%llx%lx"
#define	MHASH_FORMAT_V2	"%x%x%llx%lx"

#define	MHASH_NEWFILE		(0)
#define	MHASH_RECONCILED	(1)
#define	MHASH_FAILURE		(-1)

char *mhash_filename_to_propname(const char *, boolean_t);
int mhash_retrieve_entry(scf_handle_t *, const char *, uchar_t *);
int mhash_store_entry(scf_handle_t *, const char *, uchar_t *, char **);
int mhash_test_file(scf_handle_t *, const char *, uint_t, char **, uchar_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _MANIFEST_HASH_H */
