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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <stdlib.h>

#include "PayloadReader.h"

#define	ITER_CONT_BYTE_LEN 4
#define	IS_ITERATED(pathDef) \
(pathDef->def->iterationType != FRU_NOT_ITERATED)

// functions to place bit data properly.
static fru_errno_t
writeBits(uint64_t bitData, size_t bitLength,
	uint8_t *data, size_t dataLength, size_t bitOffset)
{
	if ((bitLength > 64) &&
		(bitOffset > 64) &&
		(dataLength > 8) &&
		(bitOffset > (dataLength * 8)))
		return (FRU_FAILURE);
	// move the bit data into place
	bitData = (bitData << (64-bitLength));
	bitData = (bitData >> bitOffset);

	// create a mask to clear the old data.
	uint64_t mask = 0;
	for (size_t i = 0; i < bitLength; i++) {
		mask = ((mask << 1) + 1);
	}
	mask = (mask << (64-bitLength));
	mask = (mask >> bitOffset);
	mask = (mask ^ 0xFFFFFFFFFFFFFFFFULL);

	// get the data out of the byte array.
	uint64_t rd = 0;
	memcpy((void *)&rd, (void *)data, dataLength);

	// clear the old data
	rd = (rd & mask);
	// put in the new data.
	rd = (rd | bitData);

	// write the data back to the buffer.
	memcpy((void *)data, (void *)&rd, dataLength);
	return (FRU_SUCCESS);
}

static fru_errno_t
readBits(size_t bitLength, uint8_t *data,
	size_t dataLength, int bitOffset, uint64_t *ret)
{
	if ((bitLength > 64) ||
		(bitLength < 0) ||
		(bitOffset > 64) ||
		(dataLength > 8) ||
		(bitOffset > (dataLength * 8)))
		return (FRU_FAILURE);
	// get the data out of the byte array.
	uint64_t rc = 0;
	memcpy((void *)&rc, (void *)data, dataLength);

	rc = (rc << bitOffset);
	rc = (rc >> (64 - bitLength));
	*ret = rc;
	return (FRU_SUCCESS);
}

// ===========================================================================
// caller is to be sure elemDef is contained by recDef.
int
PayloadReader::getOffsetIntoRecord(fru_regdef_t *recDef,
				fru_regdef_t *elemDef)
{
	int rc = 0;
	for (int i = 0; i < recDef->enumCount; i++) {
		if (strcmp(recDef->enumTable[i].text, elemDef->name) == 0)
			return (rc);
		const fru_regdef_t *tmpDef = fru_reg_lookup_def_by_name(
					(char *)recDef->enumTable[i].text);
		rc += tmpDef->payloadLen;
	}
	return(0);
}

// ===========================================================================
// return -1 on error.
int
PayloadReader::calcOffset(int iterType,
			uint8_t head, uint8_t tail,
			uint8_t iterThere, uint8_t iterPoss,
			size_t length, int index,
			fru_errno_t *err)
{
	*err = FRU_SUCCESS;
	switch (iterType) {
		case FRU_FIFO:
		case FRU_Linear:
		{
			if (index == PathDef::lastIteration)
				return (length * tail);
			return (length * index);
		break;
		}
		case FRU_Circular:
		case FRU_LIFO:
		{
			if (index == PathDef::lastIteration) {
				if (iterType == FRU_LIFO)
					return (length * head);
				return (length * tail);
			}

			// For reading they are oposite.
			if (iterType == FRU_Circular) {
				return (length * ((head + index) % iterPoss));
			} else {
				int abs = tail - index;
				if (abs < 0)
					// abs is negative here
					abs = iterPoss + abs;
				return (length * abs);
			}
		break;
		}
	}
	*err = FRU_FAILURE;
	return (-1);
}

// ===========================================================================
// return -1 on error.
int
PayloadReader::getIterationOffset(uint8_t *iter, int iterLen,
				PathDef *path, int *rcIterThere,
				fru_errno_t *err,
				int onlyFindingIterThereFlag)
{
	int rc = 0;

	// read the iteration control bytes first because we may ONLY need
	// them.
	uint8_t head = iter[0];
	uint8_t tail = iter[1];
	uint8_t iterThere = iter[2];
	uint8_t iterPoss = iter[3];

	// the '+' symbol on anything is an error here
	if (path->iterIndex == PathDef::addIteration) {
		*err = FRU_INVALPATH;
		return (-1);
	}

	// check assumptions for next calls.
	if (iterPoss != path->def->iterationCount) {
		*err = FRU_DATACORRUPT;
		return (-1);
	}

	if (onlyFindingIterThereFlag == ITER_THERE_ONLY) {
		if (rcIterThere != NULL) {
			*rcIterThere = iterThere;
		}
		*err = FRU_SUCCESS;
		return (ITER_CONT_BYTE_LEN);
	}

	if ((path->iterIndex != PathDef::addIteration) &&
		(path->iterIndex != PathDef::lastIteration) &&
		(path->iterIndex >= iterThere)) {
		*err = FRU_DATANOTFOUND;
		return (-1);
	}

	// don't forget to skip the iteration control bytes!!!
	int length = ((path->def->payloadLen - ITER_CONT_BYTE_LEN)
			/path->def->iterationCount);

	rc = calcOffset(path->def->iterationType,
			head, tail, iterThere, iterPoss,
			length, path->iterIndex, err);
	if (rc == -1) {
		// error set by calcOffset
		return (-1);
	}

	*err = FRU_SUCCESS;
	return (ITER_CONT_BYTE_LEN + rc);
}

// ===========================================================================
// Iff onlyFindingIterThereFlag is set data is ignored and dataLen will be set
// to the number of iterations which are actually in the seeprom.
fru_errno_t
PayloadReader::readRecurse(PathDef *path,
			uint8_t *cur, size_t curLen,
			void **data, size_t *dataLen,
			int onlyFindingIterThereFlag)
{
	fru_errno_t rc = FRU_SUCCESS;
	size_t calc_data_len = 0;

	if (path->next == NULL) {

		// alway go ahead and do the iterated thing.  If we are not a
		// field then the onlyFindingIterThereFlag should be set.
		// Check this afterward.
		int offset = 0;
		int iterThere = 0;
		// zzz altering the length things again...
		if (IS_ITERATED(path)) {
			// we are iterated.
			calc_data_len = (path->def->payloadLen
						-ITER_CONT_BYTE_LEN)/
					path->def->iterationCount;
// zzz still have to figure out the bit offsets for bit iterations...
			offset = getIterationOffset(cur, curLen, path,
				&iterThere, &rc,
				onlyFindingIterThereFlag);
			if (offset == -1)
				return (rc);

			// done
			if (onlyFindingIterThereFlag) {
				*dataLen = iterThere;
				return (FRU_SUCCESS);
			}
		} else {
			// done but this thing was not an iteration!!!
			if (onlyFindingIterThereFlag) {
				return (FRU_INVALPATH);
			}

			calc_data_len = path->def->payloadLen;
			offset = 0;
		}
		// end zzz

		// now make sure we have a field.
		if (path->def->dataType == FDTYPE_Record) {
			return (FRU_NOTFIELD);
		}

		// allocate and copy.
		if (path->def->dataType == FDTYPE_Binary) {
			uint64_t *eData = (uint64_t *)malloc(sizeof (*eData));
			if (eData == NULL) {
				return (FRU_FAILURE);
			}

			int bitLength = path->def->dataLength;
			// iterated bit field adjust acordingly.
			if (IS_ITERATED(path)) {
				bitLength = (bitLength-(ITER_CONT_BYTE_LEN*8))/
					path->def->iterationCount;
			}

			rc = readBits(bitLength, &(cur[offset]),
					calc_data_len, 0, eData);
			if (rc != FRU_SUCCESS) {
				free(eData);
				return (rc);
			}
			*data = (void *)eData;
			*dataLen = sizeof (*eData);
		} else if (path->def->dataType == FDTYPE_Enumeration) {
			unsigned char *eData
				= (unsigned char *)malloc(sizeof (uint64_t));
			if (eData == NULL) {
				return (FRU_FAILURE);
			}
			/* copy the correct number of bytes to eData */
			memset(eData, 0x00, sizeof (uint64_t));
			memcpy(&(eData[(sizeof (uint64_t) - (calc_data_len))]),
				&(cur[offset]),
				(calc_data_len));
			*data = (void*)eData;
			*dataLen = sizeof (uint64_t);
		} else {
			void *rc_data = malloc(calc_data_len);
			if (rc_data == NULL) {
				return (FRU_FAILURE);
			}
			memcpy(rc_data, &(cur[offset]), calc_data_len);
			*data = rc_data;
			*dataLen = calc_data_len;
		}

		return (FRU_SUCCESS);
	}

	// At this point we know the entry is some sort of record.

	int newOffset = 0, newLength = 0;
	if (IS_ITERATED(path)) {

// zzz still have to figure out the bit offsets for bit iterations...
		newOffset = getIterationOffset(cur, curLen,
				path, NULL, &rc, NORMAL_READ);
		if (newOffset == -1)
			return (rc);
	}

	newOffset += getOffsetIntoRecord(path->def, path->next->def);
	newLength = path->next->def->payloadLen;

	return (readRecurse(path->next, &(cur[newOffset]), newLength,
		data, dataLen, onlyFindingIterThereFlag));
}

// ===========================================================================
// will send the data back in (data,dataLen)
fru_errno_t
PayloadReader::readData(PathDef *path, Ancestor *curDef,
			int instWICur,
			uint8_t *payload, size_t payloadLen,
			void **data, size_t *dataLen)
{
	int offset = curDef->getInstOffset(instWICur);
	return (readRecurse(path, &(payload[offset]), payloadLen-offset,
		data, dataLen, NORMAL_READ));
}

// ===========================================================================
fru_errno_t
PayloadReader::findIterThere(PathDef *path, Ancestor *curDef,
				int instWICur,
				uint8_t *payload, size_t payloadLen,
				int *numThere)
{
	int offset = curDef->getInstOffset(instWICur);
	size_t tmp_num = 0;
	fru_errno_t err = readRecurse(path, &(payload[offset]),
		payloadLen-offset, NULL, &tmp_num, ITER_THERE_ONLY);

	if (err == FRU_SUCCESS) {
		int tmp_num_there = (int)tmp_num;
		if (tmp_num_there != tmp_num) {
			return (FRU_FAILURE);
		}
		*numThere = tmp_num_there;
	}
	return (err);
}

static fru_errno_t
update_iter_cont_bytes(PathDef *path, uint8_t *cur, size_t curLen)
{
	// update the iteration control information
	uint8_t *head = &(cur[0]);
	uint8_t *tail = &(cur[1]);
	uint8_t *numThere = &(cur[2]);
	// This never changes.
	uint8_t numPoss = cur[3];

	if (numPoss != path->def->iterationCount) {
		return (FRU_DATACORRUPT);
	}

	// Remember that when the iteration is added the head and the tail both
	// equal 0 (ie point to 0).  So if we are empty when we are updating
	// then we don't have to alter the head or tail values.  We simply add
	// one to the numThere.
	if (*numThere != 0) {
		switch (path->def->iterationType) {
			case FRU_Linear:
				// this will flag an error when Linear can't
				// hold anymore.
				if ((*tail + 1) == numPoss)
					return (FRU_ITERFULL);
			/* Fall through */
			case FRU_FIFO:
				// if we are not at the end move the tail.
				if (*tail != (numPoss-1))
					*tail = *tail+1;
			break;

			case FRU_Circular:
			case FRU_LIFO:
				// this is the same except LIFO is read
				// BACKWARDS

				// move the tail.
				*tail = *tail + 1;
				// if the tail hits the end wrap around.
				if (*tail == numPoss)
					*tail = 0;
				// if tail catches head move the head.
				if (*tail == *head) {
					// if head hits the end wrap around.
					if (++(*head) == numPoss)
						*head = 0;
				}
			break;
		}
	}
	if ((*numThere) < numPoss) {
		// add one IFF we are not full
		*numThere = *numThere + 1;
	}

	return (FRU_SUCCESS);
}

// ===========================================================================
fru_errno_t
PayloadReader::updateRecurse(PathDef *path,
				uint8_t *cur, size_t curLen,
				void *data, size_t dataLen)
{
	fru_errno_t rc = FRU_SUCCESS;

	if (path->next == NULL) {

		// Delay checking for Records until after this which will
		// allow for [+] notation for Iterated Records.
		// if this is updating an iteration AND we are adding one...
		if (IS_ITERATED(path) &&
			(path->iterIndex == PathDef::addIteration)) {
			return (update_iter_cont_bytes(path, cur, curLen));
		}

		if (path->def->dataType == FDTYPE_Record) {
			return (FRU_NOTFIELD);
		}

		int offset = 0;
		int calcLen = 0;
		int dummy = 0;
		// zzz altering the length things again...
		if (IS_ITERATED(path)) {
			// we are iterated.
			calcLen = (path->def->payloadLen-ITER_CONT_BYTE_LEN)/
				path->def->iterationCount;
// zzz still have to figure out the bit offsets
			offset = getIterationOffset(cur, curLen,
				path, &dummy, &rc, NORMAL_READ);
			if (offset == -1)
				return (rc);
		} else {
			calcLen = path->def->payloadLen;
			offset = 0;
		}
		// end zzz

		// once again convert enums for the user again.
		if (path->def->dataType == FDTYPE_Binary) {
			int bitLength = path->def->dataLength;
			// iterated bit field adjust acordingly.
			if (path->def->iterationType != FRU_NOT_ITERATED) {
				bitLength = (bitLength - 32)/
					path->def->iterationCount;
			}

			rc = writeBits (*(uint64_t *)data, bitLength,
					&(cur[offset]), calcLen, 0);
			if (rc != FRU_SUCCESS)
				return (rc);
		} else if (path->def->dataType == FDTYPE_Enumeration) {
			unsigned char *tmp = (unsigned char *)data;
			memcpy(&(cur[offset]),
				&(tmp[(sizeof (uint64_t) - (calcLen))]),
				calcLen);
		} else {
			// copy into and return.
			memcpy(&(cur[offset]), data, dataLen);
		}

		return (FRU_SUCCESS);
	}

	int newOffset = 0, newLength = 0;
	int dummy = 0;
	if (path->def->iterationType != FRU_NOT_ITERATED) {

// zzz still have to figure out the bit offsets
		newOffset = getIterationOffset(cur, curLen, path,
					&dummy, &rc, NORMAL_READ);
		if (newOffset == -1)
			return (rc);
	}
	newOffset += getOffsetIntoRecord(path->def, path->next->def);
	newLength = path->next->def->payloadLen;

	return (updateRecurse(path->next, &(cur[newOffset]), newLength,
		data, dataLen));
}

// ===========================================================================
// will update the data in payload which can then be written back.
fru_errno_t
PayloadReader::updateData(PathDef *path, Ancestor *ancestorDef,
			int instWICur,
			uint8_t *payload, size_t payloadLen,
			void *data, size_t dataLen)
{
	// verify the user data first before doing any major work.
	int calcLen = 0;
	PathDef *prev = path;
	PathDef *cur = path;
	while (cur != NULL) {
		prev = cur;
		cur = cur->next;
	}

	// unless we are updateing with [+] symbol
	// (which means we don't have any data length at all.)
	if (prev->iterIndex != PathDef::addIteration) {
		if (IS_ITERATED(prev)) {
			calcLen = (prev->def->payloadLen-ITER_CONT_BYTE_LEN)/
				prev->def->iterationCount;
		} else {
				calcLen = prev->def->payloadLen;
		}
		// the sizeof the data for Binary or Enumeration MUST
		// be uint64_t
		if ((prev->def->dataType == FDTYPE_Enumeration) ||
			(prev->def->dataType == FDTYPE_Binary)) {
			if (dataLen != sizeof (uint64_t))
				return (FRU_INVALDATASIZE);
		// all others must be shorter than the space available.
		} else {
			if (dataLen > calcLen)
				return (FRU_INVALDATASIZE);
		}
	}

	int offset = ancestorDef->getInstOffset(instWICur);
	return (updateRecurse(path, &(payload[offset]), payloadLen-offset,
		data, dataLen));
}
