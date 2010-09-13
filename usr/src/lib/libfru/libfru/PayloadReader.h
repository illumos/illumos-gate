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

#ifndef	_PAYLOADREADER_H
#define	_PAYLOADREADER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	__cplusplus
}
#endif

#include "Parser.h"

#define	NORMAL_READ 0
#define	ITER_THERE_ONLY 1

struct PayloadReader
{
	// will send the data back in (data,dataLen)
	static fru_errno_t readData(PathDef *path, Ancestor *curDef,
				int instWICur,
				uint8_t *payload, size_t payloadLen,
				void **data, size_t *dataLen);

	// will update the data in payload which can then be written back.
	static fru_errno_t updateData(PathDef *path, Ancestor *curDef,
				int instWICur,
				uint8_t *payload, size_t payloadLen,
				void *data, size_t dataLen);

	// will return the nuber of iterations actually there.
	static fru_errno_t findIterThere(PathDef *path, Ancestor *curDef,
				int instWICur,
				uint8_t *payload, size_t payloadLen,
				int *numThere);

private:
	static int getIterationOffset(uint8_t *iter, int iterLen,
				PathDef *path, int *rcIterThere,
				fru_errno_t *err,
				int onlyFindingIterThereFlag);
	static int calcOffset(int iterType,
				uint8_t head, uint8_t tail,
				uint8_t iterThere, uint8_t iterPoss,
				size_t length, int index,
				fru_errno_t *err);

	static fru_errno_t readRecurse(PathDef *path,
				uint8_t *cur, size_t curLen,
				void **data, size_t *dataLen,
				int onlyFindingIterThereFlag);

	static fru_errno_t updateRecurse(PathDef *path,
				uint8_t *cur, size_t curLen,
				void *data, size_t dataLen);

	static int getOffsetIntoRecord(fru_regdef_t *recDef,
				fru_regdef_t *elemDef);

	PayloadReader();
	~PayloadReader();
	PayloadReader(const PayloadReader&);
	void operator=(const PayloadReader&);
};

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _PAYLOADREADER_H */
