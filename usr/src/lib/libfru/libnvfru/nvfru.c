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
 * Copyright (c) 2014 Gary Mills
 *
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <strings.h>
#include <assert.h>
#include <pthread.h>
#include <sys/byteorder.h>
#include <sys/types.h>
#include <sys/nvpair.h>

#include "libfru.h"
#include "libfrup.h"
#include "fru_tag.h"
#include "libfrureg.h"
#include "nvfru.h"

#define	NUM_ITER_BYTES	4
#define	HEAD_ITER	0
#define	TAIL_ITER	1
#define	NUM_ITER	2
#define	MAX_ITER	3
#define	TIMESTRINGLEN	128

#define	PARSE_TIME	1

static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;



static void
convert_field(const uint8_t *field, const fru_regdef_t *def, const char *path,
    nvlist_t *nv)
{
	char timestring[TIMESTRINGLEN];
	int i;
	uint64_t value;
	time_t timefield;

	switch (def->dataType) {
	case FDTYPE_Binary:
		assert(def->payloadLen <= sizeof (value));
		switch (def->dispType) {
#if PARSE_TIME == 1
		case FDISP_Time:
			if (def->payloadLen > sizeof (timefield)) {
				/* too big for formatting */
				return;
			}
			(void) memcpy(&timefield, field, sizeof (timefield));
			timefield = BE_32(timefield);
			if (strftime(timestring, sizeof (timestring), "%c",
			    localtime(&timefield)) == 0) {
				/* buffer too small */
				return;
			}
			(void) nvlist_add_string(nv, path, timestring);
			return;
#endif

		case FDISP_Binary:
		case FDISP_Octal:
		case FDISP_Decimal:
		case FDISP_Hex:
		default:
			value = 0;
			(void) memcpy((((uint8_t *)&value) +
			    sizeof (value) - def->payloadLen),
			    field, def->payloadLen);
			value = BE_64(value);
			switch (def->payloadLen) {
			case 1:
				(void) nvlist_add_uint8(nv, path,
				    (uint8_t)value);
				break;
			case 2:
				(void) nvlist_add_uint16(nv, path,
				    (uint16_t)value);
				break;
			case 4:
				(void) nvlist_add_uint32(nv, path,
				    (uint32_t)value);
				break;
			default:
				(void) nvlist_add_uint64(nv, path, value);
			}
			return;
		}

	case FDTYPE_ASCII:
		(void) nvlist_add_string(nv, path, (char *)field);
		return;

	case FDTYPE_Enumeration:
		value = 0;
		(void) memcpy((((uint8_t *)&value) + sizeof (value) -
		    def->payloadLen), field, def->payloadLen);
		value = BE_64(value);
		for (i = 0; i < def->enumCount; i++) {
			if (def->enumTable[i].value == value) {
				(void) nvlist_add_string(nv, path,
				    def->enumTable[i].text);
				return;
			}
		}
	}

	/* nothing matched above, use byte array */
	(void) nvlist_add_byte_array(nv, path, (uchar_t *)field,
	    def->payloadLen);
}



static void
convert_element(const uint8_t *data, const fru_regdef_t *def, char *ppath,
    nvlist_t *nv, boolean_t from_iter)
{
	int i;
	char *path;

	/* construct path */
	if ((def->iterationCount == 0) &&
	    (def->iterationType != FRU_NOT_ITERATED)) {
		path = ppath;
	} else {
		path = (char *)def->name;
	}

	/* iteration, record and field */
	if (def->iterationCount) {
		int iterlen, n;
		uint8_t head, num;
		fru_regdef_t newdef;
		nvlist_t **nv_elems;
		char num_str[32];

		iterlen = (def->payloadLen - NUM_ITER_BYTES) /
		    def->iterationCount;

		/*
		 * make a new element definition to describe the components of
		 * the iteration.
		 */
		(void) memcpy(&newdef, def, sizeof (newdef));
		newdef.iterationCount = 0;
		newdef.payloadLen = iterlen;

		/* validate the content of the iteration control bytes */
		if ((data[HEAD_ITER] >= def->iterationCount) ||
		    (data[NUM_ITER] > def->iterationCount) ||
		    (data[MAX_ITER] != def->iterationCount)) {
			/* invalid. show all iterations */
			head = 0;
			num = def->iterationCount;
		} else {
			head = data[HEAD_ITER];
			num = data[NUM_ITER];
		}

		nv_elems = (nvlist_t **)malloc(num * sizeof (nvlist_t *));
		if (!nv_elems)
			return;
		for (i = head, n = 0, data += sizeof (uint32_t); n < num;
		    i = ((i + 1) % def->iterationCount), n++) {
			if (nvlist_alloc(&nv_elems[n], NV_UNIQUE_NAME, 0) != 0)
				return;
			(void) snprintf(num_str, sizeof (num_str), "%d", n);
			convert_element((data + i*iterlen), &newdef, num_str,
			    nv_elems[n], B_TRUE);
		}
		(void) nvlist_add_nvlist_array(nv, path, nv_elems, num);

	} else if (def->dataType == FDTYPE_Record) {
		const fru_regdef_t *component;
		nvlist_t *nv_record;

		if (!from_iter) {
			if (nvlist_alloc(&nv_record, NV_UNIQUE_NAME, 0) != 0) {
				return;
			}
		} else {
			nv_record = nv;
		}

		for (i = 0; i < def->enumCount; i++,
		    data += component->payloadLen) {
			component = fru_reg_lookup_def_by_name(
			    def->enumTable[i].text);
			convert_element(data, component, "", nv_record,
			    B_FALSE);
		}

		(void) nvlist_add_nvlist(nv, path, nv_record);

	} else {
		convert_field(data, def, path, nv);
	}
}


static fru_regdef_t *
alloc_unknown_fru_regdef(void)
{
	fru_regdef_t *p;

	p = malloc(sizeof (fru_regdef_t));
	if (!p) {
		return (NULL);
	}
	p->version = REGDEF_VERSION;
	p->name = NULL;
	p->tagType = -1;
	p->tagDense = -1;
	p->payloadLen = -1;
	p->dataLength = -1;
	p->dataType = FDTYPE_ByteArray;
	p->dispType = FDISP_Hex;
	p->purgeable = FRU_WHICH_UNDEFINED;
	p->relocatable = FRU_WHICH_UNDEFINED;
	p->enumCount = 0;
	p-> enumTable = NULL;
	p->iterationCount = 0;
	p->iterationType = FRU_NOT_ITERATED;
	p->exampleString = NULL;

	return (p);
}

static int
convert_packet(fru_tag_t *tag, uint8_t *payload, size_t length, void *args)
{
	int tag_type;
	size_t payload_length;
	const fru_regdef_t *def;
	nvlist_t *nv = (nvlist_t *)args;
	char tagname[sizeof ("?_0123456789_0123456789")];
	tag_type = get_tag_type(tag);
	payload_length = 0;

	/* check for unrecognized tag */
	if ((tag_type == -1) ||
	    ((payload_length = get_payload_length(tag)) != length)) {
		fru_regdef_t *unknown;

		unknown = alloc_unknown_fru_regdef();
		unknown->payloadLen = length;
		unknown->dataLength = unknown->payloadLen;

		if (tag_type == -1) {
			(void) snprintf(tagname, sizeof (tagname),
			    "INVALID");
		} else {
			(void) snprintf(tagname, sizeof (tagname),
			    "%s_%u_%u_%u", get_tagtype_str(tag_type),
			    get_tag_dense(tag), payload_length, length);
		}
		unknown->name = tagname;
		convert_element(payload, unknown, "", nv, B_FALSE);
		free(unknown);

	} else if ((def = fru_reg_lookup_def_by_tag(*tag)) == NULL) {
		fru_regdef_t *unknown;

		unknown = alloc_unknown_fru_regdef();
		unknown->payloadLen = length;
		unknown->dataLength = unknown->payloadLen;

		(void) snprintf(tagname, sizeof (tagname), "%s_%u_%u",
		    get_tagtype_str(tag_type),
		    unknown->tagDense, payload_length);

		unknown->name = tagname;
		convert_element(payload, unknown, "", nv, B_FALSE);
		free(unknown);

	} else {

		convert_element(payload, def, "", nv, B_FALSE);

	}

	return (FRU_SUCCESS);
}


static int
convert_packets_in_segment(fru_seghdl_t segment, void *args)
{
	char *name;
	int ret;
	nvlist_t *nv = (nvlist_t *)args;
	nvlist_t *nv_segment;

	ret = fru_get_segment_name(segment, &name);
	if (ret != FRU_SUCCESS) {
		return (ret);
	}

	/* create a new nvlist for each segment */
	ret = nvlist_alloc(&nv_segment, NV_UNIQUE_NAME, 0);
	if (ret) {
		free(name);
		return (FRU_FAILURE);
	}

	/* convert the segment to an nvlist */
	ret = fru_for_each_packet(segment, convert_packet, nv_segment);
	if (ret != FRU_SUCCESS) {
		nvlist_free(nv_segment);
		free(name);
		return (ret);
	}

	/* add the nvlist for this segment */
	(void) nvlist_add_nvlist(nv, name, nv_segment);

	free(name);

	return (FRU_SUCCESS);
}


static int
convert_fru(fru_nodehdl_t hdl, nvlist_t **nvlist)
{
	int err;
	nvlist_t *nv;
	fru_node_t fru_type;

	if (fru_get_node_type(hdl, &fru_type) != FRU_SUCCESS) {
		return (-1);
	}

	if (fru_type != FRU_NODE_CONTAINER) {
		return (-1);
	}

	err = nvlist_alloc(&nv, NV_UNIQUE_NAME, 0);
	if (err) {
		return (err);
	}

	if (fru_for_each_segment(hdl, convert_packets_in_segment, nv) !=
	    FRU_SUCCESS) {
		nvlist_free(nv);
		return (-1);
	}

	*nvlist = nv;

	return (0);
}


int
rawfru_to_nvlist(uint8_t *buffer, size_t bufsize, char *cont_type,
    nvlist_t **nvlist)
{
	fru_errno_t fru_err;
	fru_nodehdl_t hdl;
	int err;

	(void) pthread_mutex_lock(&gLock);
	fru_err = fru_open_data_source("raw", buffer, bufsize, cont_type,
	    NULL);
	if (fru_err != FRU_SUCCESS) {
		(void) pthread_mutex_unlock(&gLock);
		return (-1);
	}
	fru_err = fru_get_root(&hdl);
	if (fru_err != FRU_SUCCESS) {
		(void) pthread_mutex_unlock(&gLock);
		return (-1);
	}

	err = convert_fru(hdl, nvlist);

	fru_close_data_source();

	(void) pthread_mutex_unlock(&gLock);

	return (err);
}
