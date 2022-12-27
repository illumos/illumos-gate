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
 *
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * This is a private header file for the KMF certificate to name mapping
 * framework.
 */
#ifndef _KMFMAPPER_H
#define	_KMFMAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

#define	MAPPER_NAME_TEMPLATE "kmf_mapper_%s.so.1"

#define	MAPPER_ERROR_STRING_FUNCTION "mapper_get_error_str"
#define	MAP_CERT_TO_NAME_FUNCTION "mapper_map_cert_to_name"
#define	MATCH_CERT_TO_NAME_FUNCTION "mapper_match_cert_to_name"
#define	MAPPER_FINISH_FUNCTION "mapper_finalize"
#define	MAPPER_INIT_FUNCTION "mapper_initialize"

/* KMF mapper policy record. */
typedef struct {
	/*
	 * Those four attributes are initialized from the policy database and
	 * are not to be changed for the life of the KMF session.
	 */
	char *mapname;
	char *options;
	char *pathname;
	char *dir;
	/* Current mapper. */
	void *dldesc;
	/*
	 * The presently open mapper pathname and options. Can be based on the
	 * policy attributes or attributes provided directly to the
	 * kmf_cert_to_name_mapping_init(), thus overriding the policy settings.
	 */
	char *curpathname;
	char *curoptions;
} KMF_MAPPER_RECORD;

/* KMF mapper state record. */
typedef struct {
	/*
	 * (Processed) options. Transparent to KMF. Each mapper can store its
	 * data there since options can be unique to every KMF handle.
	 */
	void *options;
	/*
	 * If the mapper returns KMF_ERR_INTERNAL the application may ask for
	 * the internal mapper error string. That error code is stored here.
	 */
	uint32_t lastmappererr;
} KMF_MAPPER_STATE;

#ifdef __cplusplus
}
#endif
#endif /* _KMFMAPPER_H */
