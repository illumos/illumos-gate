#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libnvpair/spec/nvpair.spec

function	nvlist_alloc
include		<libnvpair.h>
declaration	int nvlist_alloc(nvlist_t **nvlp, uint_t nvflag, int kmflag)
version		SUNW_1.1
end

function	nvlist_free
include		<libnvpair.h>
declaration	void nvlist_free(nvlist_t *nvl)
version		SUNW_1.1
end

function	nvlist_size
include		<libnvpair.h>
declaration	int nvlist_size(nvlist_t *nvl, size_t *size, int encoding)
version		SUNW_1.1
end

function	nvlist_pack
include		<libnvpair.h>
declaration	int nvlist_pack(nvlist_t *nvl, char **bufp, size_t *buflen, \
		int encoding, int kmflag)
version		SUNW_1.1
end

function	nvlist_unpack
include		<libnvpair.h>
declaration	int nvlist_unpack(char *buf, size_t buflen, nvlist_t **nvlp, \
		int kmflag)
version		SUNW_1.1
end

function	nvlist_dup
include		<libnvpair.h>
declaration	int nvlist_dup(nvlist_t *nvl, nvlist_t **nvlp, int kmflag)
version		SUNW_1.1
end

function	nvlist_remove
include		<libnvpair.h>
declaration	int nvlist_remove(nvlist_t *nvl, const char *name, \
		data_type_t type)
version		SUNW_1.2
end

function	nvlist_remove_all
include		<libnvpair.h>
declaration	int nvlist_remove_all(nvlist_t *nvl, const char *name)
version		SUNW_1.2
end

function	nv_alloc_init
include		<libnvpair.h>
declaration	int nv_alloc_init(nv_alloc_t *nva, const nv_alloc_ops_t *nvo, \
		/* args */ ...)
version		SUNW_1.2
end

function	nv_alloc_reset
include		<libnvpair.h>
declaration	void nv_alloc_reset(nv_alloc_t *nva)
version		SUNW_1.2
end

function	nv_alloc_fini
include		<libnvpair.h>
declaration	void nv_alloc_fini(nv_alloc_t *nva)
version		SUNW_1.2
end

function	nvlist_xalloc
include		<libnvpair.h>
declaration	int nvlist_xalloc(nvlist_t **nvlp, uint_t nvflag, \
		nv_alloc_t *nva)
version		SUNW_1.2
end

function	nvlist_xpack
include		<libnvpair.h>
declaration	int nvlist_xpack(nvlist_t *nvl, char **bufp, size_t *buflen, \
		int encoding, nv_alloc_t *nva)
version		SUNW_1.2
end

function	nvlist_xunpack
include		<libnvpair.h>
declaration	int nvlist_xunpack(char *buf, size_t buflen, \
		nvlist_t **nvlp, nv_alloc_t *nva)
version		SUNW_1.2
end

function	nvlist_xdup
include		<libnvpair.h>
declaration	int nvlist_xdup(nvlist_t *nvl, nvlist_t **nvlp, \
		nv_alloc_t *nva)
version		SUNW_1.2
end

function	nvlist_lookup_nv_alloc
include		<libnvpair.h>
declaration	nv_alloc_t *nvlist_lookup_nv_alloc(nvlist_t *nvl)
version		SUNW_1.2
end

function	nvlist_add_boolean
include		<libnvpair.h>
declaration	int nvlist_add_boolean(nvlist_t *nvl, const char *name)
version		SUNW_1.1
end

function	nvlist_add_boolean_value
include		<libnvpair.h>
declaration	int nvlist_add_boolean_value(nvlist_t *nvl, const char *name, \
		boolean_t val)
version		SUNW_1.2
end

function	nvlist_add_byte
include		<libnvpair.h>
declaration	int nvlist_add_byte(nvlist_t *nvl, const char *name, \
		uchar_t val)
version		SUNW_1.1
end

function	nvlist_add_int8
include		<libnvpair.h>
declaration	int nvlist_add_int8(nvlist_t *nvl, const char *name, int8_t val)
version		SUNW_1.2
end

function	nvlist_add_uint8
include		<libnvpair.h>
declaration	int nvlist_add_uint8(nvlist_t *nvl, const char *name, \
		uint8_t val)
version		SUNW_1.2
end

function	nvlist_add_int16
include		<libnvpair.h>
declaration	int nvlist_add_int16(nvlist_t *nvl, const char *name, \
		int16_t val)
version		SUNW_1.1
end

function	nvlist_add_uint16
include		<libnvpair.h>
declaration	int nvlist_add_uint16(nvlist_t *nvl, const char *name, \
		uint16_t val)
version		SUNW_1.1
end

function	nvlist_add_int32
include		<libnvpair.h>
declaration	int nvlist_add_int32(nvlist_t *nvl, const char *name, \
		int32_t val)
version		SUNW_1.1
end

function	nvlist_add_uint32
include		<libnvpair.h>
declaration	int nvlist_add_uint32(nvlist_t *nvl, const char *name, \
		uint32_t val)
version		SUNW_1.1
end

function	nvlist_add_int64
include		<libnvpair.h>
declaration	int nvlist_add_int64(nvlist_t *nvl, const char *name, \
		int64_t val)
version		SUNW_1.1
end

function	nvlist_add_uint64
include		<libnvpair.h>
declaration	int nvlist_add_uint64(nvlist_t *nvl, const char *name, \
		uint64_t val)
version		SUNW_1.1
end

function	nvlist_add_string
include		<libnvpair.h>
declaration	int nvlist_add_string(nvlist_t *nvl, const char *name, \
		const char *val)
version		SUNW_1.1
end

function	nvlist_add_nvlist
include		<libnvpair.h>
declaration	int nvlist_add_nvlist(nvlist_t *nvl, const char *name, \
		nvlist_t *val)
version		SUNW_1.1.1
end

function	nvlist_add_boolean_array
include		<libnvpair.h>
declaration	int nvlist_add_boolean_array(nvlist_t *nvl, const char *name, \
		boolean_t *val, uint_t nelem)
version		SUNW_1.2
end
function	nvlist_add_byte_array
include		<libnvpair.h>
declaration	int nvlist_add_byte_array(nvlist_t *nvl, const char *name, \
		uchar_t *val, uint_t nelem)
version		SUNW_1.1
end

function	nvlist_add_int8_array
include		<libnvpair.h>
declaration	int nvlist_add_int8_array(nvlist_t *nvl, const char *name, \
		int8_t *val, uint_t nelem)
version		SUNW_1.2
end

function	nvlist_add_uint8_array
include		<libnvpair.h>
declaration	int nvlist_add_uint8_array(nvlist_t *nvl, const char *name, \
		uint8_t *val, uint_t nelem)
version		SUNW_1.2
end

function	nvlist_add_int16_array
include		<libnvpair.h>
declaration	int nvlist_add_int16_array(nvlist_t *nvl, const char *name, \
		int16_t *val, uint_t nelem)
version		SUNW_1.1
end

function	nvlist_add_uint16_array
include		<libnvpair.h>
declaration	int nvlist_add_uint16_array(nvlist_t *nvl, const char *name, \
		uint16_t *val, uint_t nelem)
version		SUNW_1.1
end

function	nvlist_add_int32_array
include		<libnvpair.h>
declaration	int nvlist_add_int32_array(nvlist_t *nvl, const char *name, \
		int32_t *val, uint_t nelem)
version		SUNW_1.1
end

function	nvlist_add_uint32_array
include		<libnvpair.h>
declaration	int nvlist_add_uint32_array(nvlist_t *nvl, const char *name, \
		uint32_t *val, uint_t nelem)
version		SUNW_1.1
end

function	nvlist_add_int64_array
include		<libnvpair.h>
declaration	int nvlist_add_int64_array(nvlist_t *nvl, const char *name, \
		int64_t *val, uint_t nelem)
version		SUNW_1.1
end

function	nvlist_add_uint64_array
include		<libnvpair.h>
declaration	int nvlist_add_uint64_array(nvlist_t *nvl, const char *name, \
		uint64_t *val, uint_t nelem)
version		SUNW_1.1
end

function	nvlist_add_string_array
include		<libnvpair.h>
declaration	int nvlist_add_string_array(nvlist_t *nvl, const char *name, \
		char *const *val, uint_t nelem)
version		SUNW_1.1
end

function	nvlist_add_nvlist_array
include		<libnvpair.h>
declaration	int nvlist_add_nvlist_array(nvlist_t *nvl, const char *name, \
		nvlist_t **val, uint_t nelem)
version		SUNW_1.1.1
end

function	nvlist_add_hrtime
include		<libnvpair.h>
declaration	int nvlist_add_hrtime(nvlist_t *nvl, const char *name, \
		hrtime_t val)
version		SUNWprivate_1.1
end

function	nvlist_lookup_boolean
include		<libnvpair.h>
declaration	int nvlist_lookup_boolean(nvlist_t *nvl, const char *name)
version		SUNW_1.1
end

function	nvlist_lookup_boolean_value
include		<libnvpair.h>
declaration	int nvlist_lookup_boolean_value(nvlist_t *nvl, \
		const char *name, boolean_t *val)
version		SUNW_1.2
end

function	nvlist_lookup_byte
include		<libnvpair.h>
declaration	int nvlist_lookup_byte(nvlist_t *nvl, const char *name, \
		uchar_t *val)
version		SUNW_1.1
end

function	nvlist_lookup_int8
include		<libnvpair.h>
declaration	int nvlist_lookup_int8(nvlist_t *nvl, const char *name, \
		int8_t *val)
version		SUNW_1.2
end

function	nvlist_lookup_uint8
include		<libnvpair.h>
declaration	int nvlist_lookup_uint8(nvlist_t *nvl, const char *name, \
		uint8_t *val)
version		SUNW_1.2
end

function	nvlist_lookup_int16
include		<libnvpair.h>
declaration	int nvlist_lookup_int16(nvlist_t *nvl, const char *name, \
		int16_t *val)
version		SUNW_1.1
end

function	nvlist_lookup_uint16
include		<libnvpair.h>
declaration	int nvlist_lookup_uint16(nvlist_t *nvl, const char *name, \
		uint16_t *val)
version		SUNW_1.1
end

function	nvlist_lookup_int32
include		<libnvpair.h>
declaration	int nvlist_lookup_int32(nvlist_t *nvl, const char *name, \
		int32_t *val)
version		SUNW_1.1
end

function	nvlist_lookup_uint32
include		<libnvpair.h>
declaration	int nvlist_lookup_uint32(nvlist_t *nvl, const char *name, \
		uint32_t *val)
version		SUNW_1.1
end

function	nvlist_lookup_int64
include		<libnvpair.h>
declaration	int nvlist_lookup_int64(nvlist_t *nvl, const char *name, \
		int64_t *val)
version		SUNW_1.1
end

function	nvlist_lookup_uint64
include		<libnvpair.h>
declaration	int nvlist_lookup_uint64(nvlist_t *nvl, const char *name, \
		uint64_t *val)
version		SUNW_1.1
end

function	nvlist_lookup_string
include		<libnvpair.h>
declaration	int nvlist_lookup_string(nvlist_t *nvl, const char *name, \
		char **val)
version		SUNW_1.1
end

function	nvlist_lookup_nvlist
include		<libnvpair.h>
declaration	int nvlist_lookup_nvlist(nvlist_t *nvl, const char *name, \
		nvlist_t **val)
version		SUNW_1.1.1
end

function	nvlist_lookup_boolean_array
include		<libnvpair.h>
declaration	int nvlist_lookup_boolean_array(nvlist_t *nvl, \
		const char *name, boolean_t **val, uint_t *nelem)
version		SUNW_1.2
end

function	nvlist_lookup_byte_array
include		<libnvpair.h>
declaration	int nvlist_lookup_byte_array(nvlist_t *nvl, const char *name, \
		uchar_t **val, uint_t *nelem)
version		SUNW_1.1
end

function	nvlist_lookup_int8_array
include		<libnvpair.h>
declaration	int nvlist_lookup_int8_array(nvlist_t *nvl, const char *name, \
		int8_t **val, uint_t *nelem)
version		SUNW_1.2
end

function	nvlist_lookup_uint8_array
include		<libnvpair.h>
declaration	int nvlist_lookup_uint8_array(nvlist_t *nvl, const char *name, \
		uint8_t **val, uint_t *nelem)
version		SUNW_1.2
end

function	nvlist_lookup_int16_array
include		<libnvpair.h>
declaration	int nvlist_lookup_int16_array(nvlist_t *nvl, const char *name, \
		int16_t **val, uint_t *nelem)
version		SUNW_1.1
end

function	nvlist_lookup_uint16_array
include		<libnvpair.h>
declaration	int nvlist_lookup_uint16_array(nvlist_t *nvl, \
		const char *name, uint16_t **val, uint_t *nelem)
version		SUNW_1.1
end

function	nvlist_lookup_int32_array
include		<libnvpair.h>
declaration	int nvlist_lookup_int32_array(nvlist_t *nvl, const char *name, \
		int32_t **val, uint_t *nelem)
version		SUNW_1.1
end

function	nvlist_lookup_uint32_array
include		<libnvpair.h>
declaration	int nvlist_lookup_uint32_array(nvlist_t *nvl, \
		const char *name, uint32_t **val, uint_t *nelem)
version		SUNW_1.1
end

function	nvlist_lookup_int64_array
include		<libnvpair.h>
declaration	int nvlist_lookup_int64_array(nvlist_t *nvl, const char *name, \
		int64_t **val, uint_t *nelem)
version		SUNW_1.1
end

function	nvlist_lookup_uint64_array
include		<libnvpair.h>
declaration	int nvlist_lookup_uint64_array(nvlist_t *nvl, \
		const char *name, uint64_t **val, uint_t *nelem)
version		SUNW_1.1
end

function	nvlist_lookup_string_array
include		<libnvpair.h>
declaration	int nvlist_lookup_string_array(nvlist_t *nvl, \
		const char *name, char ***val, uint_t *nelem)
version		SUNW_1.1
end

function	nvlist_lookup_nvlist_array
include		<libnvpair.h>
declaration	int nvlist_lookup_nvlist_array(nvlist_t *nvl, \
		const char *name, nvlist_t ***val, uint_t *nelem)
version		SUNW_1.1.1
end

function	nvlist_lookup_hrtime
include		<libnvpair.h>
declaration	int nvlist_lookup_hrtime(nvlist_t *nvl, const char *name, \
		hrtime_t *val)
version		SUNWprivate_1.1
end

function	nvlist_lookup_pairs
include		<libnvpair.h>
declaration	int nvlist_lookup_pairs(nvlist_t *nvl, int flag, ...)
version		SUNW_1.2
end

function	nvlist_next_nvpair
include		<libnvpair.h>
declaration	nvpair_t *nvlist_next_nvpair(nvlist_t *nvl, nvpair_t *nvpair)
version		SUNW_1.1
end

function	nvpair_name
include		<libnvpair.h>
declaration	char *nvpair_name(nvpair_t *nvp)
version		SUNW_1.1
end

function	nvpair_type
include		<libnvpair.h>
declaration	data_type_t nvpair_type(nvpair_t *nvpair)
version		SUNW_1.1
end

function	nvpair_value_boolean_value
include		<libnvpair.h>
declaration	int nvpair_value_boolean_value(nvpair_t *nvpair, boolean_t *val)
version		SUNW_1.2
end

function	nvpair_value_byte
include		<libnvpair.h>
declaration	int nvpair_value_byte(nvpair_t *nvpair, uchar_t *val)
version		SUNW_1.1
end

function	nvpair_value_int8
include		<libnvpair.h>
declaration	int nvpair_value_int8(nvpair_t *nvpair, int8_t *val)
version		SUNW_1.2
end

function	nvpair_value_uint8
include		<libnvpair.h>
declaration	int nvpair_value_uint8(nvpair_t *nvpair, uint8_t *val)
version		SUNW_1.2
end

function	nvpair_value_int16
include		<libnvpair.h>
declaration	int nvpair_value_int16(nvpair_t *nvpair, int16_t *val)
version		SUNW_1.1
end

function	nvpair_value_uint16
include		<libnvpair.h>
declaration	int nvpair_value_uint16(nvpair_t *nvpair, uint16_t *val)
version		SUNW_1.1
end

function	nvpair_value_int32
include		<libnvpair.h>
declaration	int nvpair_value_int32(nvpair_t *nvpair, int32_t *val)
version		SUNW_1.1
end

function	nvpair_value_uint32
include		<libnvpair.h>
declaration	int nvpair_value_uint32(nvpair_t *nvpair, uint32_t *val)
version		SUNW_1.1
end

function	nvpair_value_int64
include		<libnvpair.h>
declaration	int nvpair_value_int64(nvpair_t *nvpair, int64_t *val)
version		SUNW_1.1
end

function	nvpair_value_uint64
include		<libnvpair.h>
declaration	int nvpair_value_uint64(nvpair_t *nvpair, uint64_t *val)
version		SUNW_1.1
end

function	nvpair_value_string
include		<libnvpair.h>
declaration	int nvpair_value_string(nvpair_t *nvpair, char **val)
version		SUNW_1.1
end

function	nvpair_value_nvlist
include		<libnvpair.h>
declaration	int nvpair_value_nvlist(nvpair_t *nvpair, nvlist_t **val)
version		SUNW_1.1.1
end

function	nvpair_value_boolean_array
include		<libnvpair.h>
declaration	int nvpair_value_boolean_array(nvpair_t *nvpair, \
		boolean_t **val, uint_t *nelem)
version		SUNW_1.2
end

function	nvpair_value_byte_array
include		<libnvpair.h>
declaration	int nvpair_value_byte_array(nvpair_t *nvpair, \
		uchar_t **val, uint_t *nelem)
version		SUNW_1.1
end

function	nvpair_value_int8_array
include		<libnvpair.h>
declaration	int nvpair_value_int8_array(nvpair_t *nvpair, \
		int8_t **val, uint_t *nelem)
version		SUNW_1.2
end

function	nvpair_value_uint8_array
include		<libnvpair.h>
declaration	int nvpair_value_uint8_array(nvpair_t *nvpair, \
		uint8_t **val, uint_t *nelem)
version		SUNW_1.2
end

function	nvpair_value_int16_array
include		<libnvpair.h>
declaration	int nvpair_value_int16_array(nvpair_t *nvpair, \
		int16_t **val, uint_t *nelem)
version		SUNW_1.1
end

function	nvpair_value_uint16_array
include		<libnvpair.h>
declaration	int nvpair_value_uint16_array(nvpair_t *nvpair, \
		uint16_t **val, uint_t *nelem)
version		SUNW_1.1
end

function	nvpair_value_int32_array
include		<libnvpair.h>
declaration	int nvpair_value_int32_array(nvpair_t *nvpair, \
		int32_t **val, uint_t *nelem)
version		SUNW_1.1
end

function	nvpair_value_uint32_array
include		<libnvpair.h>
declaration	int nvpair_value_uint32_array(nvpair_t *nvpair, \
		uint32_t **val, uint_t *nelem)
version		SUNW_1.1
end

function	nvpair_value_int64_array
include		<libnvpair.h>
declaration	int nvpair_value_int64_array(nvpair_t *nvpair, \
		int64_t **val, uint_t *nelem)
version		SUNW_1.1
end

function	nvpair_value_uint64_array
include		<libnvpair.h>
declaration	int nvpair_value_uint64_array(nvpair_t *nvpair, \
		uint64_t **val, uint_t *nelem)
version		SUNW_1.1
end

function	nvpair_value_string_array
include		<libnvpair.h>
declaration	int nvpair_value_string_array(nvpair_t *nvpair, \
		char ***val, uint_t *nelem)
version		SUNW_1.1
end

function	nvpair_value_nvlist_array
include		<libnvpair.h>
declaration	int nvpair_value_nvlist_array(nvpair_t *nvpair, \
		nvlist_t ***val, uint_t *nelem)
version		SUNW_1.1.1
end

function	nvlist_merge
include		<libnvpair.h>
declaration	int nvlist_merge(nvlist_t *dst, nvlist_t *nvl, int flag)
version		SUNW_1.2
end

function	nvlist_add_nvpair
include		<libnvpair.h>
declaration	int nvlist_add_nvpair(nvlist_t *nvlist, nvpair_t *nvpair)
version		SUNW_1.2
end

function	nvpair_value_hrtime
include		<libnvpair.h>
declaration	int nvpair_value_hrtime(nvpair_t *nvpair, hrtime_t *val)
version		SUNWprivate_1.1
end

function	nvlist_print
include		<libnvpair.h>
declaration	void nvlist_print(FILE *fp, nvlist_t *nvl)
version		SUNWprivate_1.1
end

data		nv_alloc_nosleep
version		SUNW_1.2
end

data		nv_fixed_ops
version		SUNW_1.2
end
