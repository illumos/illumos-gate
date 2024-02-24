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
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _NVME_UNIT_H
#define	_NVME_UNIT_H

/*
 * Common definitions for our unit tests.
 */

#include <nvme_common.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	const char *nu_desc;
	const nvme_field_info_t *nu_fields;
	uint32_t nu_index;
	const nvme_valid_ctrl_data_t *nu_data;
	uint64_t nu_value;
	nvme_field_error_t nu_ret;
} nvme_unit_field_test_t;

extern bool nvme_unit_field_test(const nvme_unit_field_test_t *, size_t);

/*
 * Controllers defined in controllers.c for unit tests. See comments there for
 * what each one does and doesn't do.
 */
extern const nvme_valid_ctrl_data_t nvme_ctrl_base_1v0;
extern const nvme_valid_ctrl_data_t nvme_ctrl_health_1v0;
extern const nvme_valid_ctrl_data_t nvme_ctrl_base_1v1;
extern const nvme_valid_ctrl_data_t nvme_ctrl_base_1v2;
extern const nvme_valid_ctrl_data_t nvme_ctrl_base_2v0;
extern const nvme_valid_ctrl_data_t nvme_ctrl_ns_1v2;
extern const nvme_valid_ctrl_data_t nvme_ctrl_ns_1v3;
extern const nvme_valid_ctrl_data_t nvme_ctrl_ns_1v4;
extern const nvme_valid_ctrl_data_t nvme_ctrl_ns_2v0;
extern const nvme_valid_ctrl_data_t nvme_ctrl_nolpa_1v4;
extern const nvme_valid_ctrl_data_t nvme_ctrl_nons_1v3;
extern const nvme_valid_ctrl_data_t nvme_ctrl_nons_1v4;
extern const nvme_valid_ctrl_data_t nvme_ctrl_nons_2v0;
extern const nvme_valid_ctrl_data_t nvme_ctrl_nocmds_1v0;
extern const nvme_valid_ctrl_data_t nvme_ctrl_nogran_1v3;
extern const nvme_valid_ctrl_data_t nvme_ctrl_8kgran_1v3;

#ifdef __cplusplus
}
#endif

#endif /* _NVME_UNIT_H */
