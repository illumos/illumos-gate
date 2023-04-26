/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _LIBJEDEC_SPD_H
#define	_LIBJEDEC_SPD_H

/*
 * This header contains all the library-specific definitions for SPD parsing
 * that are split up between different files. The protocol definitions are
 * rooted in spd_common.h and spd_<spec>.h (e.g. spd_ddr4.h).
 */

#include <stdint.h>
#include <stdbool.h>
#include <libjedec.h>
#include <sys/ccompile.h>
#include "spd_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	SPD_INFO_F_INCOMPLETE	= 1 << 0
} spd_info_flags_t;

typedef struct {
	const uint8_t *si_data;
	size_t si_nbytes;
	spd_dram_type_t	si_dram;
	spd_module_type_t si_type;
	uint32_t si_max_bytes;
	spd_error_t si_error;
	spd_info_flags_t si_flags;
	nvlist_t *si_nvl;
	nvlist_t *si_errs;
} spd_info_t;

typedef struct {
	/*
	 * Byte offset of this key we're going to parse.
	 */
	uint32_t sp_off;
	/*
	 * Length of the field we're parsing. If this is left as zero, we assume
	 * it is one. This is mostly used for string parsing logic as opposed to
	 * integer related pieces.
	 */
	uint32_t sp_len;
	/*
	 * An optional key-name. This is used when we're using a common parsing
	 * function ala manufacturing data as opposed to say parsing timing
	 * values that may look for multiple values.
	 */
	const char *sp_key;
	void (*sp_parse)(spd_info_t *, uint32_t, uint32_t, const char *);
} spd_parse_t;

/*
 * Many SPD keys map to a different enum of set of discrete values. The
 * following structures are used to create pairs of these that we will process
 * so that way we can have basic tables that are consumed and less switch
 * statements. The svm_spd value tracks the value in the spec. The svm_use is
 * the corresponding value that should be used in the system. Finally, the
 * svm_skip, is a way to indicate that a value is valid, but undefined and
 * therefore no entry should be created as opposed to being treated as an
 * invalid value.
 */
typedef struct {
	uint8_t svm_spd;
	uint32_t svm_use;
	bool svm_skip;
} spd_value_map_t;

typedef struct {
	uint8_t svm_spd;
	uint64_t svm_use;
	bool svm_skip;
} spd_value_map64_t;

typedef struct {
	uint8_t ssm_spd;
	const char *ssm_str;
	bool ssm_skip;
} spd_str_map_t;

typedef struct {
	uint32_t svr_min;
	uint32_t svr_max;
	uint32_t svr_base;
	uint32_t svr_mult;
} spd_value_range_t;

/*
 * Common routines for parsing and nvlist work.
 */
extern void spd_parse(spd_info_t *, const spd_parse_t *, size_t);
extern void spd_nvl_err(spd_info_t *, const char *, spd_error_kind_t,
    const char *, ...) __PRINTFLIKE(4);
extern void spd_nvl_insert_str(spd_info_t *, const char *, const char *);
extern void spd_nvl_insert_u32(spd_info_t *, const char *, uint32_t);
extern void spd_nvl_insert_u64(spd_info_t *, const char *, uint64_t);
extern void spd_nvl_insert_u32_array(spd_info_t *, const char *,
    uint32_t *, uint_t);
extern void spd_nvl_insert_key(spd_info_t *, const char *);

extern void spd_insert_map(spd_info_t *, const char *, uint8_t,
    const spd_value_map_t *, size_t);
extern void spd_insert_map64(spd_info_t *, const char *, uint8_t,
    const spd_value_map64_t *, size_t);
extern void spd_insert_str_map(spd_info_t *, const char *, uint8_t,
    const spd_str_map_t *, size_t);
extern void spd_insert_map_array(spd_info_t *, const char *, const uint8_t *,
    size_t, const spd_value_map_t *, size_t);
extern void spd_insert_range(spd_info_t *, const char *, uint8_t,
    const spd_value_range_t *);
extern void spd_upsert_flag(spd_info_t *, const char *, uint32_t);

extern void spd_parse_jedec_id(spd_info_t *, uint32_t, uint32_t, const char *);
extern void spd_parse_jedec_id_str(spd_info_t *, uint32_t, uint32_t,
    const char *);
extern void spd_parse_string(spd_info_t *, uint32_t, uint32_t, const char *);
extern void spd_parse_hex_string(spd_info_t *, uint32_t, uint32_t,
    const char *);
extern void spd_parse_hex_vers(spd_info_t *, uint32_t, uint32_t, const char *);
extern void spd_parse_raw_u8(spd_info_t *, uint32_t, uint32_t, const char *);
extern void spd_parse_dram_step(spd_info_t *, uint32_t, uint32_t, const char *);
extern void spd_parse_crc(spd_info_t *, uint32_t, uint32_t, const char *);
extern void spd_parse_rev(spd_info_t *, uint32_t, uint32_t, const char *);
extern void spd_parse_height(spd_info_t *, uint32_t, uint32_t, const char *);
extern void spd_parse_thickness(spd_info_t *, uint32_t, uint32_t, const char *);

/*
 * Protocol-specific entry points.
 */
extern void spd_parse_ddr4(spd_info_t *);
extern void spd_parse_ddr5(spd_info_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBJEDEC_SPD_H */
