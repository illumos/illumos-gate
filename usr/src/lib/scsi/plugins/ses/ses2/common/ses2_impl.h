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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2019 RackTop Systems
 */

#ifndef	_PLUGIN_SES_IMPL_H
#define	_PLUGIN_SES_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/impl/spc3_types.h>
#include <sys/ccompile.h>
#include <stdarg.h>
#include <libnvpair.h>

#include <scsi/libscsi.h>
#include <scsi/libses_plugin.h>

#pragma	pack(1)

/*
 * Generic IO timeout in seconds, from <sys/scsi/targets/ses.h>.
 */
#define	SES2_TIMEOUT	60

/*
 * SES-2 Enclosure Descriptor Header (Table 8, 6.1.2.2)
 */
typedef struct ses2_ed_hdr_impl {
	DECL_BITFIELD4(
	    sehi_n_esps		:3,
	    _reserved1		:1,
	    sehi_rel_esp_id	:3,
	    _reserved2		:1);
	uint8_t sehi_subenclosure_id;
	uint8_t sehi_n_etd_hdrs;
	uint8_t sehi_ed_len;
} ses2_ed_hdr_impl_t;

/*
 * SES-2 Enclosure Descriptor (Table 8, 6.1.2.2)
 */
typedef struct ses2_ed_impl {
	ses2_ed_hdr_impl_t st_hdr;
	spc3_naa_id_8_impl_t st_logical_id;
	char st_vendor_id[8];
	char st_product_id[16];
	char st_product_revision[4];
	uint8_t st_priv[1];
} ses2_ed_impl_t;

/*
 * SES-2 Type Descriptor Header (Table 9, 6.1.2.3)
 */
typedef struct ses2_td_hdr_impl {
	uint8_t sthi_element_type;
	uint8_t sthi_max_elements;
	uint8_t sthi_subenclosure_id;
	uint8_t sthi_text_len;
} ses2_td_hdr_impl_t;

/*
 * SES-2 Configuration diagnostic page (Table 7, 6.1.2.1)
 */
typedef struct ses2_config_page_impl {
	uint8_t scpi_page_code;
	uint8_t scpi_n_subenclosures;
	uint16_t scpi_page_length;
	uint32_t scpi_generation_code;
	uint8_t scpi_data[1];
} ses2_config_page_impl_t;

/*
 * Logically we should be able to use 4 or 8 bytes for a minimum allocation;
 * however, it seems at least some devices will fail the request in that case.
 */
#define	SES2_MIN_DIAGPAGE_ALLOC 512

/*
 * SES-2 Element Control and Overall Control fields (Table 59, 7.2.2)
 */
typedef struct ses2_cmn_elem_ctl_impl {
	DECL_BITFIELD5(
	    _reserved1		:4,
	    seci_rst_swap	:1,
	    seci_disable	:1,
	    seci_prdfail	:1,
	    seci_select		:1);
} ses2_cmn_elem_ctl_impl_t;

typedef struct ses2_elem_ctl_impl {
	ses2_cmn_elem_ctl_impl_t seci_common;
	uint8_t seci_data[3];
} ses2_elem_ctl_impl_t;

/*
 * SES-2 Element Status and Overall Status fields (Table 60, 7.2.3)
 */
typedef struct ses2_cmn_elem_status_impl {
	DECL_BITFIELD5(
	    sesi_status_code	:4,
	    sesi_swap		:1,
	    sesi_disabled	:1,
	    sesi_prdfail	:1,
	    _reserved1		:1);
} ses2_cmn_elem_status_impl_t;

typedef struct ses2_elem_status_impl {
	ses2_cmn_elem_status_impl_t sesi_common;
	uint8_t sesi_data[3];
} ses2_elem_status_impl_t;

/*
 * SES-2 Device element for the Enclosure Control diagnostic page.
 */
typedef struct ses2_device_ctl_impl {
	ses2_cmn_elem_ctl_impl_t sdci_common;
	uint8_t _reserved1;
	DECL_BITFIELD8(
	    _reserved2		:1,
	    sdci_rqst_ident	:1,
	    sdci_rqst_remove	:1,
	    sdci_rqst_insert	:1,
	    sdci_rqst_missing	:1,
	    _reserved3		:1,
	    sdci_do_not_remove	:1,
	    sdci_rqst_active	:1);
	DECL_BITFIELD6(
	    _reserved4		:2,
	    sdci_enable_byp_b	:1,
	    sdci_enable_byp_a	:1,
	    sdci_device_off	:1,
	    sdci_rqst_fault	:1,
	    _reserved5		:2);
} ses2_device_ctl_impl_t;

/*
 * SES-2 Device element for the Enclosure Status diagnostic page
 * (Table 64, 7.3.2).
 */
typedef struct ses2_device_status_impl {
	ses2_cmn_elem_status_impl_t sdsi_common;
	uint8_t sdsi_slot_addr;
	DECL_BITFIELD8(
	    sdsi_report			:1,
	    sdsi_ident			:1,
	    sdsi_rmv			:1,
	    sdsi_ready_to_insert	:1,
	    sdsi_enclosure_bypassed_b	:1,
	    sdsi_enclosure_bypassed_a	:1,
	    sdsi_do_not_remove		:1,
	    sdsi_app_client_bypassed_a	:1);
	DECL_BITFIELD8(
	    sdsi_device_bypassed_b	:1,
	    sdsi_device_bypassed_a	:1,
	    sdsi_bypassed_b		:1,
	    sdsi_bypassed_a		:1,
	    sdsi_device_off		:1,
	    sdsi_fault_reqstd		:1,
	    sdsi_fault_sensed		:1,
	    sdsi_app_client_bypassed_b	:1);
} ses2_device_status_impl_t;

typedef struct ses2_array_device_ctl_impl {
	ses2_cmn_elem_ctl_impl_t sadci_common;
	DECL_BITFIELD8(
	    sadci_rqst_rr_abort		:1,
	    sadci_rqst_rebuild		:1,
	    sadci_rqst_in_failed_array	:1,
	    sadci_rqst_in_crit_array	:1,
	    sadci_rqst_cons_check	:1,
	    sadci_rqst_hot_spare	:1,
	    sadci_rqst_rsvd_device	:1,
	    sadci_rqst_ok		:1);
	DECL_BITFIELD8(
	    _reserved1		:1,
	    sadci_rqst_ident	:1,
	    sadci_rqst_remove	:1,
	    sadci_rqst_insert	:1,
	    sadci_rqst_missing	:1,
	    _reserved2		:1,
	    sadci_do_not_remove	:1,
	    sadci_rqst_active	:1);
	DECL_BITFIELD6(
	    _reserved3		:2,
	    sadci_enable_byp_b	:1,
	    sadci_enable_byp_a	:1,
	    sadci_device_off	:1,
	    sadci_rqst_fault	:1,
	    _reserved4		:2);
} ses2_array_device_ctl_impl_t;

/*
 * SES-2 Array Device element for the Enclosure Status diagnostic page
 * (Table 66, 7.3.3)
 */
typedef struct ses2_array_device_status_impl {
	ses2_cmn_elem_status_impl_t sadsi_common;
	DECL_BITFIELD8(
	    sadsi_rr_abort		:1,
	    sadsi_rebuild		:1,
	    sadsi_in_failed_array	:1,
	    sadsi_in_crit_array		:1,
	    sadsi_cons_chk		:1,
	    sadsi_hot_spare		:1,
	    sadsi_rsvd_device		:1,
	    sadsi_ok			:1);
	DECL_BITFIELD8(
	    sadsi_report		:1,
	    sadsi_ident			:1,
	    sadsi_rmv			:1,
	    sadsi_ready_to_insert	:1,
	    sadsi_enclosure_bypassed_b	:1,
	    sadsi_enclosure_bypassed_a	:1,
	    sadsi_do_not_remove		:1,
	    sadsi_app_client_bypassed_a	:1);
	DECL_BITFIELD8(
	    sadsi_device_bypassed_b	:1,
	    sadsi_device_bypassed_a	:1,
	    sadsi_bypassed_b		:1,
	    sadsi_bypassed_a		:1,
	    sadsi_device_off		:1,
	    sadsi_fault_reqstd		:1,
	    sadsi_fault_sensed		:1,
	    sadsi_app_client_bypassed_b	:1);
} ses2_array_device_status_impl_t;

/*
 * SES-2 Power Supply element for control-type diagnostic pages (T68).
 */
typedef struct ses2_psu_ctl_impl {
	ses2_cmn_elem_ctl_impl_t spci_common;
	DECL_BITFIELD2(
	    _reserved1		:7,
	    spci_rqst_ident	:1);
	uint8_t _reserved2;
	DECL_BITFIELD4(
	    _reserved3		:5,
	    spci_rqst_on	:1,
	    spci_rqst_fail	:1,
	    _reserved4		:1);
} ses2_psu_ctl_impl_t;

/*
 * SES-2 Power Supply element for status-type diagnostic pages (Table 69, 7.3.4)
 */
typedef struct ses2_psu_status_impl {
	ses2_cmn_elem_status_impl_t spsi_common;
	DECL_BITFIELD2(
	    _reserved1	:7,
	    spsi_ident	:1);
	DECL_BITFIELD5(
	    _reserved2			:1,
	    spsi_dc_over_current	:1,
	    spsi_dc_under_voltage	:1,
	    spsi_dc_over_voltage	:1,
	    _reserved3			:4);
	DECL_BITFIELD8(
	    spsi_dc_fail		:1,
	    spsi_ac_fail		:1,
	    spsi_temp_warn		:1,
	    spsi_overtmp_fail		:1,
	    spsi_off			:1,
	    spsi_rqsted_on		:1,
	    spsi_fail			:1,
	    spsi_hot_swap		:1);
} ses2_psu_status_impl_t;

/*
 * SES-2 Cooling element for control-type diagnostic pages (Table 70).
 */
typedef struct ses2_cooling_ctl_impl {
	ses2_cmn_elem_ctl_impl_t scci_common;
	DECL_BITFIELD2(
	    _reserved1		:7,
	    scci_rqst_ident	:1);
	uint8_t _reserved2;
	DECL_BITFIELD5(
	    scci_requested_speed_code	:3,
	    _reserved3			:2,
	    scci_rqst_on		:1,
	    scci_rqst_fail		:1,
	    _reserved4			:1);
} ses2_cooling_ctl_impl_t;

/*
 * SES-2 Cooling element for status-type diagnostic pages (Table 71, 7.3.5)
 */
typedef struct ses2_cooling_status_impl {
	ses2_cmn_elem_status_impl_t scsi_common;
	DECL_BITFIELD3(
	    scsi_fan_speed_ms3	:3,
	    _reserved1		:4,
	    scsi_ident		:1);
	uint8_t scsi_fan_speed_lsb;
	DECL_BITFIELD6(
	    scsi_actual_speed_code	:3,
	    _reserved2			:1,
	    scsi_off			:1,
	    scsi_requested_on		:1,
	    scsi_fail			:1,
	    _reserved3			:1);
} ses2_cooling_status_impl_t;

/*
 * The fan_speed fields are multiplied by this factor to obtain the actual
 * number of RPMs.
 */
#define	SES2_ES_COOLING_SPEED_FACTOR	10

#define	SES2_ES_COOLING_ST_FAN_SPEED(csip)	\
	(((((uint16_t)(csip)->scsi_fan_speed_ms3) << 8) |	\
	    ((uint16_t)(csip)->scsi_fan_speed_lsb)) * \
	    (uint16_t)SES2_ES_COOLING_SPEED_FACTOR)

/*
 * SES-2 Temperature Sensor element for control-type diagnostic pages (T74).
 */
typedef struct ses2_temp_ctl_impl {
	ses2_cmn_elem_ctl_impl_t stci_common;
	DECL_BITFIELD3(
	    _reserved1		:6,
	    stci_rqst_fail	:1,
	    stci_rqst_ident	:1);
	uint8_t _reserved2[2];
} ses2_temp_ctl_impl_t;

/*
 * SES-2 Temperature Sensor element for status-type diagnostic pages
 * (Table 74, 7.3.6)
 */
typedef struct ses2_temp_status_impl {
	ses2_cmn_elem_status_impl_t stsi_common;
	DECL_BITFIELD3(
	    _reserved1	:6,
	    stsi_fail	:1,
	    stsi_ident	:1);
	uint8_t stsi_temperature;
	DECL_BITFIELD4(
	    stsi_ut_warn	:1,
	    stsi_ut_fail	:1,
	    stsi_ot_warn	:1,
	    stsi_ot_fail	:1);
} ses2_temp_status_impl_t;

#define	SES2_ES_TEMP_OFFSET	(-20)

#define	SES2_ES_TEMP_ST_TEMPERATURE(tsip)	\
	((tsip)->stsi_temperature + SES2_ES_TEMP_OFFSET)

/*
 * SES-2 Door Lock element for control-type diagnostic pages (T76).
 */
typedef struct ses2_lock_ctl_impl {
	ses2_cmn_elem_ctl_impl_t slci_common;
	DECL_BITFIELD3(
	    _reserved1		:6,
	    slci_rqst_fail	:1,
	    slci_rqst_ident	:1);
	uint8_t _reserved2;
	DECL_BITFIELD2(
	    slci_unlock	:1,
	    _reserved3	:7);
} ses2_lock_ctl_impl_t;

/*
 * SES-2 Door Lock element for status-type diagnostic pages (Table 77, 7.3.7)
 */
typedef struct ses2_lock_status_impl {
	ses2_cmn_elem_status_impl_t slsi_common;
	DECL_BITFIELD3(
	    _reserved1	:6,
	    slsi_fail	:1,
	    slsi_ident	:1);
	uint8_t _reserved2;
	DECL_BITFIELD2(
	    slsi_unlocked	:1,
	    _reserved3		:7);
} ses2_lock_status_impl_t;

/*
 * SES-2 Audible Alarm element for control-type diagnostic pages (T78).
 */
typedef struct ses2_alarm_ctl_impl {
	ses2_cmn_elem_ctl_impl_t saci_common;
	DECL_BITFIELD3(
	    _reserved1		:6,
	    saci_rqst_fail	:1,
	    saci_rqst_ident	:1);
	uint8_t _reserved2;
	DECL_BITFIELD8(
	    saci_unrecov	:1,
	    saci_crit		:1,
	    saci_noncrit	:1,
	    saci_info		:1,
	    saci_set_remind	:1,
	    _reserved3		:1,
	    saci_set_mute	:1,
	    _reserved4		:1);
} ses2_alarm_ctl_impl_t;

/*
 * SES-2 Audible Alarm element for status-type diagnostic pages
 * (Table 79, 7.3.8)
 */
typedef struct ses2_alarm_status_impl {
	ses2_cmn_elem_status_impl_t sasi_common;
	DECL_BITFIELD3(
	    _reserved1	:6,
	    sasi_fail	:1,
	    sasi_ident	:1);
	uint8_t _reserved2;
	DECL_BITFIELD8(
	    sasi_unrecov	:1,
	    sasi_crit		:1,
	    sasi_noncrit	:1,
	    sasi_info		:1,
	    sasi_remind		:1,
	    _reserved3		:1,
	    sasi_muted		:1,
	    sasi_rqst_mute	:1);
} ses2_alarm_status_impl_t;

/*
 * SES-2 Enclosure Services Controller Electronics element for control-type
 * diagnostic pages (Table 80, 7.3.9).
 */
typedef struct ses2_controller_ctl_impl {
	ses2_cmn_elem_ctl_impl_t scci_common;
	DECL_BITFIELD3(
	    _reserved1		:6,
	    scci_rqst_fail	:1,
	    scci_rqst_ident	:1);
	DECL_BITFIELD2(
	    scci_select_element	:1,
	    _reserved2		:7);
	uint8_t _reserved3;
} ses2_controller_ctl_impl_t;

/*
 * SES-2 Enclosure Services Controller Electronics element for status-type
 * diagnostic pages (Table 81, 7.3.9),
 */
typedef struct ses2_controller_status_impl {
	ses2_cmn_elem_status_impl_t scsi_common;
	DECL_BITFIELD3(
	    _reserved1	:6,
	    scsi_fail	:1,
	    scsi_ident	:1);
	DECL_BITFIELD2(
	    scsi_report	:1,
	    _reserved2	:7);
	DECL_BITFIELD2(
	    _reserved3		:7,
	    scsi_hot_swap	:1);
} ses2_controller_status_impl_t;

/*
 * SES-2 SCC Controller Electronics element for control-type diagnostic pages
 * (Table 82, 7.3.10).
 */
typedef struct ses2_scc_ctl_impl {
	ses2_cmn_elem_ctl_impl_t ssci_common;
	DECL_BITFIELD3(
	    _reserved1		:6,
	    ssci_rqst_fail	:1,
	    ssci_rqst_ident	:1);
	uint8_t _reserved2[2];
} ses2_scc_ctl_impl_t;

/*
 * SES-2 SCC Controller Electronics element for status-type diagnostic pages
 * (Table 83, 7.3.10)
 */
typedef struct ses2_scc_status_impl {
	ses2_cmn_elem_status_impl_t sss_common;
	DECL_BITFIELD3(
	    _reserved1	:6,
	    sss_fail	:1,
	    sss_ident	:1);
	DECL_BITFIELD2(
	    sss_report	:1,
	    _reserved2	:7);
	uint8_t _reserved3;
} ses2_scc_status_impl_t;

/*
 * SES-2 Nonvolatile Cache element for control-type diagnostic pages
 * (Table 84, 7.3.11).
 */
typedef struct ses2_nvcache_ctl_impl {
	ses2_cmn_elem_ctl_impl_t snci_common;
	DECL_BITFIELD3(
	    _reserved1		:6,
	    snci_rqst_fail	:1,
	    snci_rqst_ident	:1);
	uint8_t _reserved2[2];
} ses2_nvcache_ctl_impl_t;

/*
 * SES-2 Nonvolatile Cache element for status-type diagnostic pages (Table 85,
 * 7.3.11)
 */
typedef struct ses2_nvcache_status_impl {
	ses2_cmn_elem_status_impl_t snsi_common;
	DECL_BITFIELD4(
	    snsi_size_multiplier	:2,
	    _reserved1			:4,
	    snsi_fail			:1,
	    snsi_ident			:1);
	uint16_t snsi_nvcache_size;
} ses2_nvcache_status_impl_t;

/*
 * Ibid., Table 86 defines the size multipliers as follows:
 *
 * 00b	- bytes
 * 01b	- 1<<10 bytes
 * 10b	- 1<<20 bytes
 * 11b	- 1<<30 bytes
 *
 * We will calculate the actual size in bytes by doing
 *
 * nvcache_size << (SES2_NVCACHE_SHIFT * multiplier)
 */
#define	SES2_NVCACHE_SHIFT	10
#define	SES2_NVCACHE_SIZE(nsip)	\
	((uint64_t)SCSI_READ16(&(nsip)->snsi_nvcache_size) << \
	    (SES2_NVCACHE_SHIFT * (nsip)->snsi_size_multiplier))

/*
 * SES-2 Invalid Operation Reason element for status-type diagnostic pages
 * (Table 88, 7.3.12)
 */
typedef struct ses2_invop_reason_status_impl {
	ses2_cmn_elem_status_impl_t sirsi_common;
	DECL_BITFIELD2(
	    sirsi_priv_ms6	:6,
	    sirsi_invop_type	:2);
	uint8_t sirsi_priv[2];
} ses2_invop_reason_status_impl_t;

/*
 * Ibid., Invop Type values (Table 89)
 */
typedef enum ses2_invop_type {
	SES2_INVOP_SEND_PAGE_CODE = 0x0,
	SES2_INVOP_SEND_PAGE_FORMAT = 0x1,
	SES2_INVOP_VENDOR_SPECIFIC = 0x3
} ses2_invop_type_t;

/*
 * Ibid., Invalid Operation Reason element for status-type diagnostic pages
 * with Invop Type of 00b (Table 90)
 */
typedef struct ses2_invop_code_status_impl {
	ses2_cmn_elem_status_impl_t sicsi_common;
	DECL_BITFIELD3(
	    sicsi_page_not_supported	:1,
	    _reserved1			:5,
	    sicsi_invop_type		:2);
	uint8_t _reserved2[2];
} ses2_invop_code_status_impl_t;

/*
 * Ibid., Invalid Operation Reason element for status-type diagnostic pages
 * with Invop Type of 01b (Table 91)
 */
typedef struct ses2_invop_format_status_impl {
	ses2_cmn_elem_status_impl_t sifsi_common;
	DECL_BITFIELD3(
	    sifsi_bit_number	:3,
	    _reserved1		:3,
	    sifsi_invop_type	:2);
	uint16_t sifsi_byte_offset[2];
} ses2_invop_format_status_impl_t;

/*
 * SES-2 Uninterruptible Power Supply element for control-type diagnostic
 * pages (Table 93, 7.3.13)
 */
typedef struct ses2_ups_ctl_impl {
	ses2_cmn_elem_ctl_impl_t suci_common;
	uint8_t _reserved1[2];
	DECL_BITFIELD3(
	    _reserved2		:6,
	    suci_rqst_fail	:1,
	    suci_rqst_ident	:1);
} ses2_ups_ctl_impl_t;

/*
 * SES-2 Uninterruptible Power Supply element for status-type diagnostic pages
 * (Table 94, 7.3.13)
 */
typedef struct ses2_ups_status_impl {
	ses2_cmn_elem_status_impl_t susi_common;
	uint8_t susi_battery_status;	/* Time remaining in minutes */
	DECL_BITFIELD8(
	    susi_intf_fail	:1,
	    susi_warn		:1,
	    susi_ups_fail	:1,
	    susi_dc_fail	:1,
	    susi_ac_fail	:1,
	    susi_ac_qual	:1,
	    susi_ac_hi		:1,
	    susi_ac_lo		:1);
	DECL_BITFIELD5(
	    susi_bpf		:1,
	    susi_batt_fail	:1,
	    _reserved1		:4,
	    susi_fail		:1,
	    susi_ident		:1);
} ses2_ups_status_impl_t;

/*
 * SES-2 Display element for control-type diagnostic pages (Table 95, 7.3.14)
 */
typedef struct ses2_display_ctl_impl {
	ses2_cmn_elem_ctl_impl_t sdci_common;
	DECL_BITFIELD4(
	    sdci_display_mode	:2,
	    _reserved1		:4,
	    sdci_rqst_fail	:1,
	    sdci_rqst_ident	:1);
	uint16_t sdci_display_character;
} ses2_display_ctl_impl_t;

/*
 * SES-2 Display element for status-type diagnostic pages (Table 97, 7.3.14)
 */
typedef struct ses2_display_status_impl {
	ses2_cmn_elem_status_impl_t sdsi_common;
	DECL_BITFIELD4(
	    sdsi_display_mode_status	:2,
	    _reserved1			:3,
	    sdsi_fail			:1,
	    sdsi_ident			:1);
	uint16_t sdsi_display_character_status;
} ses2_display_status_impl_t;

/*
 * SES-2 Key Pad Entry element for control-type diagnostic pages (Table 99).
 */
typedef struct ses2_keypad_ctl_impl {
	ses2_cmn_elem_ctl_impl_t skci_common;
	DECL_BITFIELD3(
	    _reserved1		:6,
	    skci_rqst_fail	:1,
	    skci_rqst_ident	:1);
	uint8_t _reserved2[2];
} ses2_keypad_ctl_impl_t;

/*
 * SES-2 Key Pad Entry element for status-type diagnostic pages (Table 100,
 * 7.3.15)
 */
typedef struct ses2_keypad_status_impl {
	ses2_cmn_elem_status_impl_t sksi_common;
	DECL_BITFIELD3(
	    _reserved1	:6,
	    sksi_fail	:1,
	    sksi_ident	:1);
	uint8_t _reserved2[2];
} ses2_keypad_status_impl_t;

/*
 * SES-2 Enclosure element for control-type diagnostic pages (Table 101).
 */
typedef struct ses2_enclosure_ctl_impl {
	ses2_cmn_elem_ctl_impl_t seci_common;
	DECL_BITFIELD2(
	    _reserved1		:7,
	    seci_rqst_ident	:1);
	DECL_BITFIELD2(
	    seci_power_cycle_delay	:6,
	    seci_power_cycle_request	:2);
	DECL_BITFIELD3(
	    seci_request_warning	:1,
	    seci_request_failure	:1,
	    seci_power_off_duration	:6);
} ses2_enclosure_ctl_impl_t;

/*
 * SES-2 Enclosure element for status-type diagnostic pages (Table 101, 7.3.16)
 */
typedef struct ses2_enclosure_status_impl {
	ses2_cmn_elem_status_impl_t sesi_common;
	DECL_BITFIELD2(
	    _reserved1	:7,
	    sesi_ident	:1);
	DECL_BITFIELD3(
	    sesi_warning_indication	:1,
	    sesi_failure_indication	:1,
	    sesi_power_delay		:6);
	DECL_BITFIELD3(
	    sesi_warning_requested	:1,
	    sesi_failure_requested	:1,
	    sesi_power_duration		:6);
} ses2_enclosure_status_impl_t;

/*
 * SES-2 SCSI Port/Transceiver element for control-type diagnostic pages (T103)
 */
typedef struct ses2_port_ctl_impl {
	ses2_cmn_elem_ctl_impl_t spci_common;
	DECL_BITFIELD3(
	    _reserved1		:6,
	    spci_rqst_fail	:1,
	    spci_rqst_ident	:1);
	uint8_t _reserved2;
	DECL_BITFIELD3(
	    _reserved3		:4,
	    spci_disable	:1,
	    _reserved4		:3);
} ses2_port_ctl_impl_t;

/*
 * SES-2 SCSI Port/Transceiver element for status-type diagnostic pages
 * (Table 104, 7.3.17)
 */
typedef struct ses2_port_status_impl {
	ses2_cmn_elem_status_impl_t spsi_common;
	DECL_BITFIELD3(
	    _reserved1	:6,
	    spsi_fail	:1,
	    spsi_ident	:1);
	DECL_BITFIELD2(
	    spsi_report	:1,
	    _reserved2	:7);
	DECL_BITFIELD5(
	    spsi_xmit_fail	:1,
	    spsi_lol		:1,
	    _reserved3		:2,
	    spsi_disabled	:1,
	    _reserved4		:3);
} ses2_port_status_impl_t;

/*
 * SES-2 Language element for control-type diagnostic pages (T105)
 */
typedef struct ses2_lang_ctl_impl {
	ses2_cmn_elem_ctl_impl_t slci_common;
	DECL_BITFIELD2(
	    _reserved1		:7,
	    slci_rqst_ident	:1);
	uint16_t slci_language_code;
} ses2_lang_ctl_impl_t;

/*
 * SES-2 Language element for status-type diagnostic pages (Table 105, 7.3.18)
 */
typedef struct ses2_lang_status_impl {
	ses2_cmn_elem_status_impl_t slsi_common;
	DECL_BITFIELD2(
	    _reserved1	:7,
	    slsi_ident	:1);
	uint16_t slsi_language_code;
} ses2_lang_status_impl_t;

/*
 * SES-2 Communication Port element for control-type diagnostic pages
 * (Table 107, 7.3.19).
 */
typedef struct ses2_comm_ctl_impl {
	ses2_cmn_elem_ctl_impl_t scci_common;
	DECL_BITFIELD3(
	    _reserved1		:6,
	    scci_rqst_fail	:1,
	    scci_rqst_ident	:1);
	uint8_t _reserved2;
	DECL_BITFIELD2(
	    scci_disable	:1,
	    _reserved3		:7);
} ses2_comm_ctl_impl_t;

/*
 * SES-2 Communication Port element for status-type diagnostic pages
 * (Table 108, 7.3.19)
 */
typedef struct ses2_comm_status_impl {
	ses2_cmn_elem_status_impl_t scsi_common;
	DECL_BITFIELD3(
	    _reserved1	:6,
	    scsi_fail	:1,
	    scsi_ident	:1);
	uint8_t _reserved2;
	DECL_BITFIELD2(
	    scsi_disabled	:1,
	    _reserved3		:7);
} ses2_comm_status_impl_t;

/*
 * SES-2 Voltage Sensor element for control-type diagnostic pages
 * (Table 109, 7.3.20).
 */
typedef struct ses2_voltage_ctl_impl {
	ses2_cmn_elem_ctl_impl_t svci_common;
	DECL_BITFIELD3(
	    _reserved1		:6,
	    svci_rqst_fail	:1,
	    svci_rqst_ident	:1);
	uint8_t _reserved2[2];
} ses2_voltage_ctl_impl_t;

/*
 * SES-2 Voltage Sensor element for status-type diagnostic pages
 * (Table 110, 7.3.20).
 */
typedef struct ses2_voltage_status_impl {
	ses2_cmn_elem_status_impl_t svsi_common;
	DECL_BITFIELD7(
	    svsi_crit_under	:1,
	    svsi_crit_over	:1,
	    svsi_warn_under	:1,
	    svsi_warn_over	:1,
	    _reserved1		:2,
	    svsi_fail		:1,
	    svsi_ident		:1);
	uint16_t svsi_voltage;
} ses2_voltage_status_impl_t;

/*
 * Ibid. defines the svsi_voltage field as a 16-bit signed 2's complement
 * integer, represented in units of 10 mV.  AC voltages are RMS.
 */
#define	SES2_VOLTAGE_MULTIPLIER	(0.01)
#define	SES2_VOLTAGE(vsip)	\
	(SCSI_READ16(&(vsip)->svsi_voltage) * SES2_VOLTAGE_MULTIPLIER)

/*
 * SES-2 Current Sensor element for control-type diagnostic pages
 * (Table 111, 7.3.21).
 */
typedef struct ses2_current_ctl_impl {
	ses2_cmn_elem_ctl_impl_t scci_common;
	DECL_BITFIELD3(
	    _reserved1		:6,
	    scci_rqst_fail	:1,
	    scci_rqst_ident	:1);
	uint8_t _reserved2[2];
} ses2_current_ctl_impl_t;

/*
 * SES-2 Current Sensor element for status-type diagnostic pages
 * (Table 112, 7.3.21)
 */
typedef struct ses2_current_status_impl {
	ses2_cmn_elem_status_impl_t scsi_common;
	DECL_BITFIELD7(
	    _reserved1		:1,
	    scsi_crit_over	:1,
	    _reserved2		:1,
	    scsi_warn_over	:1,
	    _reserved3		:2,
	    scsi_fail		:1,
	    scsi_ident		:1);
	uint16_t scsi_current;
} ses2_current_status_impl_t;

/*
 * Ibid. defines the scsi_voltage field in the same way as for voltage above.
 * Units here are 10 mA.  AC amperages are RMS.
 */
#define	SES2_CURRENT_MULTIPLIER	(0.01)
#define	SES2_CURRENT(csip)	\
	(SCSI_READ16(&(csip)->scsi_current) * SES2_CURRENT_MULTIPLIER)

/*
 * SES-2 SCSI Target Port element for control-type diagnostic pages
 * (Table 113, 7.3.22), SCSI Initiator Port element for control-type
 * diagnostic pages (Table 115, 7.3.23).
 */
typedef struct ses2_itp_ctl_impl {
	ses2_cmn_elem_ctl_impl_t sici_common;
	DECL_BITFIELD3(
	    _reserved1		:6,
	    sici_rqst_fail	:1,
	    sici_rqst_ident	:1);
	uint8_t _reserved2;
	DECL_BITFIELD2(
	    sici_enable	:1,
	    _reserved3	:7);
} ses2_itp_ctl_impl_t;

/*
 * SES-2 SCSI Target Port element for status-type diagnostic pages (Table 114,
 * 7.3.22), SCSI Initiator Port element for status-type diagnostic pages
 * (Table 116, 7.3.23)
 */
typedef struct ses2_itp_status_impl {
	ses2_cmn_elem_status_impl_t sisi_common;
	DECL_BITFIELD3(
	    _reserved1	:6,
	    sisi_fail	:1,
	    sisi_ident	:1);
	DECL_BITFIELD2(
	    sisi_report	:1,
	    _reserved2	:7);
	DECL_BITFIELD2(
	    sisi_enabled	:1,
	    _reserved3		:7);
} ses2_itp_status_impl_t;

/*
 * SES-2 Simple Subenclosure element for control-type diagnostic pages
 * (Table 117, 7.3.24).
 */
typedef struct ses2_ss_ctl_impl {
	ses2_cmn_elem_ctl_impl_t ssci_common;
	DECL_BITFIELD3(
	    _reserved1		:6,
	    ssci_rqst_fail	:1,
	    ssci_rqst_ident	:1);
	uint8_t _reserved2[2];
} ses2_ss_ctl_impl_t;

/*
 * SES-2 Simple Subenclosure element for status-type diagnostic pages
 * (Table 117, 7.3.24)
 */
typedef struct ses2_ss_status_impl {
	ses2_cmn_elem_status_impl_t sss_common;
	DECL_BITFIELD3(
	    _reserved1	:6,
	    sss_fail	:1,
	    sss_ident	:1);
	uint8_t _reserved2;
	uint8_t sss_short_status;
} ses2_ss_status_impl_t;

/*
 * SES-2 SAS Expander element for control-type diagnostic pages
 * (Table 119, 7.3.25).
 */
typedef struct ses2_expander_ctl_impl {
	ses2_cmn_elem_ctl_impl_t seci_common;
	DECL_BITFIELD3(
	    _reserved1		:6,
	    seci_rqst_fail	:1,
	    seci_rqst_ident	:1);
	uint8_t _reserved2[2];
} ses2_expander_ctl_impl_t;

/*
 * SES-2 SAS Expander element for status-type diagnostic pages (Table 120,
 * 7.3.25)
 */
typedef struct ses2_expander_status_impl {
	ses2_cmn_elem_status_impl_t sesi_common;
	DECL_BITFIELD3(
	    _reserved1	:6,
	    sesi_fail	:1,
	    sesi_ident	:1);
	uint8_t _reserved2[2];
} ses2_expander_status_impl_t;

/*
 * SES-2 SAS Connector element for control-type diagnostic pages (Table 121,
 * 7.3.26).
 */
typedef struct ses2_sasconn_ctl_impl {
	ses2_cmn_elem_ctl_impl_t ssci_common;
	DECL_BITFIELD2(
	    _reserved1		:7,
	    ssci_rqst_ident	:1);
	uint8_t _reserved2;
	DECL_BITFIELD3(
	    _reserved3		:6,
	    ssci_rqst_fail	:1,
	    _reserved4		:1);
} ses2_sasconn_ctl_impl_t;

/*
 * SES-2 SAS Connector element for status-type diagnostic pages (Table 122,
 * 7.3.26)
 */
typedef struct ses2_sasconn_status_impl {
	ses2_cmn_elem_status_impl_t sss_common;
	DECL_BITFIELD2(
	    sss_connector_type	:7,
	    sss_ident		:1);
	uint8_t sss_connector_physical_link;
	DECL_BITFIELD3(
	    _reserved1	:6,
	    sss_fail	:1,
	    _reserved2	:1);
} ses2_sasconn_status_impl_t;

/*
 * SES-2 Enclosure Control diagnostic page (Table 10, 6.1.3)
 */
typedef struct ses2_control_page_impl {
	uint8_t scpi_page_code;
	DECL_BITFIELD5(
	    scpi_unrecov	:1,
	    scpi_crit		:1,
	    scpi_noncrit	:1,
	    scpi_info		:1,
	    _reserved1		:4);
	uint16_t scpi_page_length;
	uint32_t scpi_generation_code;
	ses2_elem_ctl_impl_t scpi_data[1];
} ses2_control_page_impl_t;

/*
 * SES-2 Enclosure Status (Table 11, 6.1.4)
 */
typedef struct ses2_status_page_impl {
	uint8_t sspi_page_code;
	DECL_BITFIELD6(
	    sspi_unrecov	:1,
	    sspi_crit		:1,
	    sspi_noncrit	:1,
	    sspi_info		:1,
	    sspi_invop		:1,
	    _reserved1		:3);
	uint16_t sspi_page_length;
	uint32_t sspi_generation_code;
	uint8_t sspi_data[1];
} ses2_status_page_impl_t;

/*
 * SES-2 Help Text diagnostic page (Table 13, 6.1.5).
 */
typedef struct ses2_help_page_impl {
	uint8_t shpi_page_code;
	uint8_t _reserved1;
	uint16_t shpi_page_length;
	char shpi_help_text[1];
} ses2_help_page_impl_t;

/*
 * SES-2 String Out diagnostic page (Table 14, 6.1.6).
 */
typedef struct ses2_string_out_page_impl {
	uint8_t ssopi_page_code;
	uint8_t _reserved1;
	uint16_t ssopi_page_length;
	uint8_t ssopi_data[1];
} ses2_string_out_page_impl_t;

/*
 * SES-2 String In diagnostic page (Table 15, 6.1.7).
 */
typedef struct ses2_string_in_page_impl {
	uint8_t ssipi_page_code;
	uint8_t _reserved1;
	uint16_t ssipi_page_length;
	uint8_t ssipi_data[1];
} ses2_string_in_page_impl_t;

/*
 * SES-2 Threshold fields - (Table 17, 6.1.8), (Table 19, 6.1.9).
 */
typedef struct ses2_threshold_impl {
	uint8_t sti_high_crit;
	uint8_t sti_high_warn;
	uint8_t sti_low_warn;
	uint8_t sti_low_crit;
} ses2_threshold_impl_t;

/*
 * SES-2 Threshold Out diagnostic page (Table 16, 6.1.8).
 */
typedef struct ses2_threshold_out_page_impl {
	uint8_t stopi_page_code;
	uint8_t _reserved1;
	uint16_t stopi_page_length;
	uint32_t stopi_generation_code;
	ses2_threshold_impl_t stopi_thresholds[1];
} ses2_threshold_out_page_impl_t;

/*
 * SES-2 Threshold In diagnostic page (Table 18, 6.1.9).
 */
typedef struct ses2_threshold_in_page_impl {
	uint8_t stipi_page_code;
	DECL_BITFIELD3(
	    _reserved1	:4,
	    stipi_invop	:1,
	    _reserved2	:3);
	uint16_t stipi_page_length;
	uint32_t stipi_generation_code;
	ses2_threshold_impl_t stipi_thresholds[1];
} ses2_threshold_in_page_impl_t;

/*
 * SES-2 Element Descriptor diagnostic page (Table 20, 6.1.10).
 */
typedef struct ses2_elem_desc_page_impl {
	uint8_t sedpi_page_code;
	uint8_t _reserved1;
	uint16_t sedpi_page_length;
	uint32_t sedpi_generation_code;
	uint8_t sedpi_data[1];
} ses2_elem_desc_page_impl_t;

/*
 * SES-2 Overall/element descriptor format (Table 22, 6.1.10).
 */
typedef struct ses2_elem_descriptor_impl {
	uint8_t _reserved1[2];
	uint16_t sedi_descriptor_length;
	char sedi_descriptor[1];
} ses2_elem_descriptor_impl_t;

/*
 * SES-2 Short Enclosure Status diagnostic page (Table 23, 6.1.11).
 */
typedef struct ses2_short_status_page_impl {
	uint8_t ssspi_page_code;
	uint8_t ssspi_short_status;
	uint16_t ssspi_page_length;
} ses2_short_status_page_impl_t;

/*
 * SES-2 Enclosure Busy diagnostic page (Table 24, 6.1.12).
 */
typedef struct ses2_enclosure_busy_page_impl {
	uint8_t sebpi_page_code;
	DECL_BITFIELD2(
	    sebpi_busy		:1,
	    sebpi_vs_1_1	:7);
	uint16_t sebpi_page_length;
} ses2_enclosure_busy_page_impl_t;

/*
 * SES-2 Additional Element Status diagnostic page (Table 25, 6.1.13).
 */
typedef struct ses2_aes_page_impl {
	uint8_t sapi_page_code;
	uint8_t _reserved1;
	uint16_t sapi_page_length;
	uint32_t sapi_generation_code;
	uint8_t sapi_data[1];
} ses2_aes_page_impl_t;

/*
 * SES-2 Additional Element Status descriptor (EIP == 1) (Table 26, 6.1.13).
 * Updated with EIIOE for Table 32 from SES-3, 6.1.13.
 * Note that we think later revs of SES-3 probably widen the EIIOE to 2 bits,
 * waiting for final document to be sure.
 */
typedef struct ses2_aes_descr_eip_impl {
	DECL_BITFIELD4(
	    sadei_protocol_identifier	:4,
	    sadei_eip			:1,
	    _reserved1			:2,
	    sadei_invalid		:1);
	uint8_t sadei_length;
	DECL_BITFIELD2(
	    sadei_eiioe			:2,
	    _reserved2			:6);
	uint8_t sadei_element_index;
	uint8_t sadei_protocol_specific[1];
} ses2_aes_descr_eip_impl_t;

/*
 * SES-2 Additional Element Status descriptor (EIP == 0) (Table 27, 6.1.13).
 */
typedef struct ses2_aes_descr_impl {
	DECL_BITFIELD4(
	    sadei_protocol_identifier	:4,
	    sadei_eip			:1,
	    _reserved1			:2,
	    sadei_invalid		:1);
	uint8_t sadei_length;
	uint8_t sadei_protocol_specific[1];
} ses2_aes_descr_impl_t;

/*
 * SES-2 Port descriptor (Table 30, 6.1.13.2).
 */
typedef struct ses2_aes_port_descr_impl {
	uint8_t sapdi_port_loop_position;
	uint8_t _reserved1[3];
	uint8_t sapdi_port_requested_hard_address;
	uint8_t sapdi_n_port_identifier[3];
	uint64_t sapdi_n_port_name;
} ses2_aes_port_descr_impl_t;

/*
 * SES-2 Additional Element Status descriptor for FC (Table 28, 6.1.13.2).
 */
typedef struct ses2_aes_descr_fc_eip_impl {
	uint8_t sadfi_n_ports;
	uint8_t _reserved1[2];
	uint8_t sadfi_bay_number;
	uint64_t sadfi_node_name;
	ses2_aes_port_descr_impl_t sadfi_ports[1];
} ses2_aes_descr_fc_eip_impl_t;

/*
 * SES-2 Additional Element Status descriptor for FC (EIP == 0)
 * (Table 29, 6.1.13.2).
 */
typedef struct ses2_aes_descr_fc_impl {
	uint8_t sadfi_n_ports;
	uint8_t _reserved1;
	uint64_t sadfi_node_name;
	ses2_aes_port_descr_impl_t sadfi_ports[1];
} ses2_aes_descr_fc_impl_t;

/*
 * SES-2 Additional Element Status descriptor for SAS (Table 31, 6.1.13.3).
 */
typedef struct ses2_aes_descr_sas_impl {
	uint8_t _specific1;
	DECL_BITFIELD2(
	    _specific2			:6,
	    sadsi_descriptor_type	:2);
	uint8_t _specific3[1];
} ses2_aes_descr_sas_impl_t;

typedef enum ses2_aes_descr_sas_type {
	SES2_AESD_SAS_DEVICE = 0,
	SES2_AESD_SAS_OTHER = 1
} ses2_aes_descr_sas_type_t;

typedef struct ses2_aes_phy0_descr_impl {
	DECL_BITFIELD3(
	    _reserved1		:4,
	    sapdi_device_type	:3,
	    _reserved2		:1);
	uint8_t _reserved3;
	DECL_BITFIELD5(
	    _reserved4			:1,
	    sapdi_smp_initiator_port	:1,
	    sapdi_stp_initiator_port	:1,
	    sapdi_ssp_initiator_port	:1,
	    _reserved5			:4);
	DECL_BITFIELD6(
	    sapdi_sata_device		:1,
	    sapdi_smp_target_port	:1,
	    sapdi_stp_target_port	:1,
	    sapdi_ssp_target_port	:1,
	    _reserved6			:3,
	    sapdi_sata_port_selector	:1);
	uint64_t sapdi_attached_sas_address;
	uint64_t sapdi_sas_address;
	uint8_t sapdi_phy_identifier;
	uint8_t _reserved7[7];
} ses2_aes_phy0_descr_impl_t;

typedef struct ses2_aes_descr_sas0_eip_impl {
	uint8_t sadsi_n_phy_descriptors;
	DECL_BITFIELD3(
	    sadsi_not_all_phys		:1,
	    _reserved1			:5,
	    sadsi_descriptor_type	:2);
	uint8_t _reserved2;
	uint8_t sadsi_bay_number;
	ses2_aes_phy0_descr_impl_t sadsi_phys[1];
} ses2_aes_descr_sas0_eip_impl_t;

typedef struct ses2_aes_descr_sas0_impl {
	uint8_t sadsi_n_phy_descriptors;
	DECL_BITFIELD3(
	    sadsi_not_all_phys		:1,
	    _reserved1			:5,
	    sadsi_descriptor_type	:2);
	ses2_aes_phy0_descr_impl_t sadsi_phys[1];
} ses2_aes_descr_sas0_impl_t;

/*
 * SES-2 Additional Element Status for SAS Expander elements
 * (Table 36, 6.1.13.3.3).
 */
typedef struct ses2_aes_exp_phy_descr_impl {
	uint8_t saepdi_connector_element_index;
	uint8_t saepdi_other_element_index;
} ses2_aes_exp_phy_descr_impl_t;

typedef struct ses2_aes_descr_exp_impl {
	uint8_t sadei_n_exp_phy_descriptors;
	DECL_BITFIELD2(
	    _reserved1			:6,
	    sadei_descriptor_type	:2);
	uint8_t _reserved2[2];
	uint64_t sadei_sas_address;
	ses2_aes_exp_phy_descr_impl_t sadei_phys[1];
} ses2_aes_descr_exp_impl_t;

/*
 * SES-2 Additional Element Status for SCSI Initiator/Target Port and
 * Enclosure Services Controller Electronics elements (Table 38, 6.1.13.3.4).
 */
typedef struct ses2_aes_phy1_descr_impl {
	uint8_t sapdi_phy_identifier;
	uint8_t _reserved1;
	uint8_t sapdi_connector_element_index;
	uint8_t sapdi_other_element_index;
	uint64_t sapdi_sas_address;
} ses2_aes_phy1_descr_impl_t;

typedef struct ses2_aes_descr_sas1_impl {
	uint8_t sadsi_n_phy_descriptors;
	DECL_BITFIELD2(
	    _reserved1			:6,
	    sadsi_descriptor_type	:2);
	uint8_t _reserved2[2];
	ses2_aes_phy1_descr_impl_t sadsi_phys[1];
} ses2_aes_descr_sas1_impl_t;

/*
 * SES-2 Subenclosure Help Text diagnostic page (Table 40, 6.1.14).
 */
typedef struct ses2_subhelp_page_impl {
	uint8_t sspi_page_code;
	uint8_t sspi_n_subenclosures;
	uint16_t sspi_page_length;
	uint32_t sspi_generation_code;
	uint8_t sspi_data[1];
} ses2_subhelp_page_impl_t;

/*
 * SES-2 Subenclosure help text format (Table 41, 6.1.14).
 */
typedef struct ses2_subhelp_text_impl {
	uint8_t _reserved1;
	uint8_t ssti_subenclosure_identifier;
	uint16_t ssti_subenclosure_help_text_length;
	char ssti_subenclosure_help_text[1];
} ses2_subhelp_text_impl_t;

#define	SES2_SUBHELP_LEN(stip)	\
	(SCSI_READ16(&(stip)->ssti_subenclosure_help_text_length) + \
	    offsetof(ses2_subhelp_text_impl_t, ssti_subenclosure_help_text[0]))
/*
 * SES-2 Subenclosure String Out diagnostic page (Table 42, 6.1.15).
 */
typedef struct ses2_substring_out_page_impl {
	uint8_t ssopi_page_code;
	uint8_t ssopi_subenclosure_identifier;
	uint16_t ssopi_page_length;
	uint32_t ssopi_generation_code;
	uint8_t ssopi_data[1];
} ses2_substring_out_page_impl_t;

/*
 * SES-2 Subenclosure String In diagnostic page (Table 43, 6.1.16).
 */
typedef struct ses2_substring_in_page_impl {
	uint8_t ssipi_page_code;
	uint8_t ssipi_n_subenclosures;
	uint16_t ssipi_page_length;
	uint32_t ssipi_generation_code;
	uint8_t ssipi_data[1];
} ses2_substring_in_page_impl_t;

/*
 * SES-2 Subenclosure string in data format (Table 44, 6.1.16).
 */
typedef struct ses2_substring_in_data_impl {
	uint8_t _reserved1;
	uint8_t ssidi_subenclosure_identifier;
	uint16_t ssidi_substring_data_length;
	uint8_t ssidi_data[1];
} ses2_substring_in_data_impl_t;

#define	SES2_SUBSTR_LEN(sdip)	\
	(SCSI_READ16(&(sdip)->ssidi_substring_data_length) + \
	    offsetof(ses2_substring_in_data_impl_t, ssidi_data[0]))

/*
 * SES-2 Supported SES Diagnostic Pages diagnostic page (Table 45, 6.1.17).
 */
typedef struct ses2_supported_ses_diag_page_impl {
	uint8_t sssdpi_page_code;
	uint8_t _reserved1;
	uint16_t sssdpi_page_length;
	uint8_t sssdpi_pages[1];
} ses2_supported_ses_diag_page_impl_t;

/*
 * SES-2 Download Microcode Control diagnostic page (Table 46, 6.1.18).
 */
typedef struct ses2_ucode_ctl_page_impl {
	uint8_t sucpi_page_code;
	uint8_t sucpi_subenclosure_identifier;
	uint16_t sucpi_page_length;
	uint32_t sucpi_generation_code;
	uint8_t sucpi_dl_ucode_mode;
	uint8_t _reserved1[2];
	uint8_t sucpi_buffer_id;
	uint32_t sucpi_buffer_offset;
	uint32_t sucpi_ucode_image_length;
	uint32_t sucpi_ucode_data_length;
	uint8_t sucpi_ucode_data[1];
} ses2_ucode_ctl_page_impl_t;

/*
 * SES-2 Download Microcode Status diagnostic page (Table 48-49, 6.1.19).
 */
typedef struct ses2_ucode_status_descr_impl {
	uint8_t _reserved1;
	uint8_t susdi_subenclosure_identifier;
	uint8_t susdi_subenclosure_dl_status;
	uint8_t susdi_subenclosure_dl_addl_status;
	uint32_t susdi_subenclosure_dl_max_size;
	uint8_t _reserved2[3];
	uint8_t susdi_subenclosure_dl_buffer_id;
	uint32_t susdi_subenclosure_dl_buffer_offset;
} ses2_ucode_status_descr_impl_t;

typedef struct ses2_ucode_status_page_impl {
	uint8_t suspi_page_code;
	uint8_t suspi_n_subenclosures;
	uint16_t suspi_page_length;
	uint32_t suspi_generation_code;
	ses2_ucode_status_descr_impl_t suspi_descriptors[1];
} ses2_ucode_status_page_impl_t;

/*
 * SES-2 Subenclosure Nickname Control diagnostic page (Table 51, 6.1.20).
 */
typedef struct ses2_subnick_ctl_page_impl {
	uint8_t sscpi_page_code;
	uint8_t sspci_subenclosure_identifier;
	uint16_t sspci_page_length;
	uint32_t sspci_generation_code;
	char sspci_subenclosure_nickname[32];
} ses2_subnick_ctl_page_impl_t;

/*
 * SES-2 Subenclosure Nickname Status diagnostic page (Table 52-53, 6.1.21).
 */
typedef struct ses2_subnick_descr_impl {
	uint8_t _reserved1;
	uint8_t ssdi_subenclosure_identifier;
	uint8_t ssdi_subenclosure_nick_status;
	uint8_t ssdi_subenclosure_nick_addl_status;
	uint8_t _reserved2[2];
	uint16_t ssdi_subenclosure_nick_lang_code;
	char ssdi_subenclosure_nickname[32];
} ses2_subnick_descr_impl_t;

typedef struct ses2_subnick_status_page_impl {
	uint8_t sspsi_page_code;
	uint8_t sspci_n_subenclosures;
	uint16_t sspci_page_length;
	uint32_t sspci_generation_code;
	ses2_subnick_descr_impl_t sspci_subnicks[1];
} ses2_subnick_status_page_impl_t;

/*
 * SES-2 Mode page code for enclosure services devices (Table 57, 6.3.2).
 */
typedef struct ses2_esm_mode_page_impl {
	DECL_BITFIELD3(
	    sempi_page_code	:6,
	    _reserved1		:1,
	    sempi_ps		:1);
	uint8_t sempi_page_length;
	uint8_t _reserved2[3];
	DECL_BITFIELD2(
	    sempi_enbltc	:1,
	    _reserved3		:7);
	uint16_t sempi_max_task_completion_time;
} ses2_esm_mode_page_impl_t;

#pragma pack()

extern ses_pagedesc_t ses2_pages[];

extern int ses2_fill_element_node(ses_plugin_t *, ses_node_t *);
extern int ses2_fill_enclosure_node(ses_plugin_t *, ses_node_t *);

typedef int (*ses2_setprop_f)(ses_plugin_t *, ses_node_t *, ses2_diag_page_t,
    nvpair_t *);

typedef struct ses2_ctl_prop {
	const char *scp_name;
	data_type_t scp_type;
	ses2_diag_page_t scp_num;
	ses2_setprop_f scp_setprop;
} ses2_ctl_prop_t;

typedef int (*ses2_setdef_f)(ses_node_t *, ses2_diag_page_t, void *);

extern int ses2_ctl_common_setprop(ses_plugin_t *sp, ses_node_t *,
    ses2_diag_page_t, nvpair_t *);

#define	SES_COMMON_CTL_PROPS	\
{	\
	.scp_name = SES_PROP_SWAP,	\
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,	\
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,	\
	.scp_setprop = ses2_ctl_common_setprop	\
},	\
{	\
	.scp_name = SES_PROP_DISABLED,	\
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,	\
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,	\
	.scp_setprop = ses2_ctl_common_setprop	\
},	\
{	\
	.scp_name = SES_PROP_PRDFAIL,	\
	.scp_type = DATA_TYPE_BOOLEAN_VALUE,	\
	.scp_num = SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS,	\
	.scp_setprop = ses2_ctl_common_setprop	\
}

typedef struct ses2_ctl_desc {
	ses2_element_type_t scd_et;
	const ses2_ctl_prop_t *scd_props;
	ses2_setdef_f scd_setdef;
} ses2_ctl_desc_t;

extern int ses2_setprop(ses_plugin_t *, ses_node_t *, const ses2_ctl_prop_t *,
    nvlist_t *);

extern int ses2_element_setdef(ses_node_t *, ses2_diag_page_t, void *);
extern int ses2_enclosure_setdef(ses_node_t *, ses2_diag_page_t, void *);

extern int ses2_element_ctl(ses_plugin_t *, ses_node_t *, const char *,
    nvlist_t *);
extern int ses2_enclosure_ctl(ses_plugin_t *, ses_node_t *, const char *,
    nvlist_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _PLUGIN_SES_IMPL_H */
