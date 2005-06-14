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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _ANCESTOR_H
#define	_ANCESTOR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	__cplusplus
}
#endif

#include "libfru.h"
#include "libfrureg.h"
#include "fru_tag.h"
#include "Str.h"

// the object used to determine the ancestory of a particular element.
struct Ancestor
{
	Ancestor(Str field, fru_tag_t t, const fru_regdef_t *d);
	~Ancestor();

	void addInstance(const char *path, uint32_t offset);

	Str getFieldName(void);
	fru_tag_t getTag(void);

	const fru_regdef_t *getDef(void);

	int getNumInstances(void);
	uint32_t getInstOffset(int num);
	const char *getPath(int num);
/*
 *	void print(void);
 */

	// returns a NULL terminated list of Ancestor objects which contain
	// information about all the Ancestors of element.
	static Ancestor *listTaggedAncestors(char *element);

public:
	Ancestor *next;

private:
	Str field_name;
	fru_tag_t tag;
	const fru_regdef_t *def;
	int numInstances;
#define	ANCESTOR_INST_BUF_SIZE 256
	int numBufs;
	uint32_t *offsets;
	char **paths;

	// internal calls
	static Ancestor * createTaggedAncestor(const fru_regdef_t *def,
						Str element);
	static int definitionContains(const fru_regdef_t *def,
					const fru_regdef_t *parent_def,
					Str element,
					uint32_t offset,
					Ancestor *ant,
					Str path);

private:
	Ancestor(const Ancestor&);
	void operator=(const Ancestor&);
};

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _ANCESTOR_H */
