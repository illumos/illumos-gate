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

#ifndef _SYS_SGENV_IMPL_H
#define	_SYS_SGENV_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * sgenv_impl.h - Serengeti Environmental Driver
 *
 * This header file contains the private environmental definitions for
 * the Serengeti platform. (used only by sgenv driver)
 *
 */

/* get the public definitions */
#include <sys/sgenv.h>

/* named field of keyswitch kstat */
#define	POSITION_KSTAT_NAME	"position"

/* Mailbox message sub-types */
#define	SG_GET_ENV_HPU_KEYS	0x4000
#define	SG_GET_ENV_CONSTANTS	0x4004
#define	SG_GET_ENV_VOLATILES	0x4002
#define	SG_GET_ENV_THRESHOLDS	0x4003

/*
 * Max time sgenv waits for mailbox to respond before
 * it decides to timeout. (measured in seconds)
 */
#define	SGENV_DEFAULT_MAX_MBOX_WAIT_TIME	30

#define	SGENV_MAX_SENSORS_PER_KEY	27	/* from design doc (3.1.4) */
#define	SGENV_MAX_HPUS_PER_DOMAIN	24
#define	SGENV_MAX_HPU_KEYS		(SSM_MAX_INSTANCES * \
						SGENV_MAX_HPUS_PER_DOMAIN)
#define	SGENV_MAX_SENSORS		(SGENV_MAX_SENSORS_PER_KEY * \
						SGENV_MAX_HPU_KEYS)

#define	SGENV_NO_NODE_EXISTS		0x0
#define	SGENV_NODE_TYPE_DS		0x3FF

#define	SGENV_POLL_THREAD	0x1	/* cache update called from kstat */
#define	SGENV_INTERRUPT_THREAD	0x2	/* cache update called from softint */

#define	BOARD_CACHE		0x1
#define	ENV_CACHE		0x2

/*
 * Event Publisher definitions for sysevent.
 */
#define	EP_SGENV	SUNW_KERN_PUB SGENV_DRV_NAME

/*
 * Event definitions
 */
#define	MAX_TAG_ID_STR_LEN		100

#define	HPU_ENTRY(value_macro)	{	\
	value_macro,	\
	value_macro ## _STR,	\
	value_macro ## _ID	\
}

#define	PART_VALUE(value_macro)	{	\
	value_macro,	\
	value_macro ## _STR	\
}

#define	TYPE_VALUE(value_macro, scale) {	\
	value_macro,	\
	value_macro ## _STR,	\
	value_macro ## _UNITS,	\
	scale	\
}

typedef struct hpu_value {
	unsigned	value;
	const char	*name;
	const char	*IDstr;

} hpu_value_t;

typedef struct part_value {
	unsigned	value;
	const char	*name;
} part_value_t;

typedef struct type_value {
	unsigned	value;
	const char	*name;
	const char	*units;
	uint32_t	scale;

} type_value_t;


/*
 * SGENV soft state structure.
 */
typedef struct sgenv_soft_state {
	int			instance;	/* instance number */
	dev_info_t		*dip;		/* dev_info structure */
	kstat_t			*keyswitch_ksp;
	kstat_t			*env_info_ksp;
	kstat_t			*board_info_ksp;

} sgenv_soft_state_t;


/*
 * Environmental Info Structures.
 */
typedef int32_t envresp_key_t;

typedef struct envresp_constants {
	sensor_id_t	id; /* sd_id */
	sensor_data_t	lo; /* sd_lo */
	sensor_data_t	hi; /* sd_hi */
	/* no padding required, 3x4-bytes in total length */

} envresp_constants_t;

typedef struct envresp_volatiles {
	sensor_status_t	info;	/* sd_infostamp */
	sensor_data_t	value;	/* sd_value */
	int32_t		_pad;	/* pad to 2x8-bytes */

} envresp_volatiles_t;

typedef struct envresp_thresholds {
	sensor_data_t	lo_warn; /* sd_lo_warn */
	sensor_data_t	hi_warn; /* sd_hi_warn */
	/* no padding required, 2x4-bytes in total length */

} envresp_thresholds_t;


/*
 * functions local to this driver.
 */
static int	sgenv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int	sgenv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static int	sgenv_add_kstats(sgenv_soft_state_t *softsp);
static void	sgenv_remove_kstats(sgenv_soft_state_t *softsp);

static int	sgenv_create_cache_update_threads(void);
static int	sgenv_remove_cache_update_threads(void);
static void	sgenv_indicate_cache_update_needed(int cache);

static int	sgenv_keyswitch_kstat_update(kstat_t *ksp, int rw);

static void	sgenv_init_env_cache(void);
static void	sgenv_update_env_cache(void);
static int	sgenv_env_info_kstat_update(kstat_t *ksp, int rw);
static int	sgenv_env_info_kstat_snapshot(kstat_t *ksp, void *buf, int rw);
static int	sgenv_get_env_info_data(void);
static int	sgenv_get_hpu_keys(envresp_key_t *new, int *status);
static int	sgenv_get_env_data(envresp_key_t key, int key_posn,
					uint16_t flag, int *status);
static int	sgenv_handle_env_data_error(int err, int status, int key_posn,
					envresp_key_t key, char *str);
static void	sgenv_mbox_error_msg(char *str, int err, int status);
static void	sgenv_destroy_env_cache(void);
static void	sgenv_clear_env_cache_entry(int key_posn);
static int	sgenv_create_env_cache_entry(int key_posn);
static void	sgenv_set_sensor_status(env_sensor_t *sensor);
static void	sgenv_update_env_kstat_size(kstat_t *ksp);

static void	sgenv_init_board_cache(void);
static void	sgenv_update_board_cache(void);
static int	sgenv_board_info_kstat_update(kstat_t *ksp, int rw);
static int	sgenv_board_info_kstat_snapshot(kstat_t *ksp,
					void *buf, int rw);
static int	sgenv_get_board_info_data(void);
static void	sgenv_set_valid_node_positions(uint_t *node_present);

static int	sgenv_process_threshold_event(env_sensor_t sensor);
static void	sgenv_tagid_to_string(sensor_id_t id, char *str);
static int	sgenv_add_intr_handlers(void);
static int	sgenv_remove_intr_handlers(void);
static uint_t	sgenv_keyswitch_handler(char *);
static uint_t	sgenv_env_data_handler(char *);
static uint_t	sgenv_fan_status_handler(char *);
static uint_t	sgenv_dr_event_handler(char *);
static uint_t	sgenv_check_sensor_thresholds(void);
static const char	*sgenv_get_hpu_id_str(uint_t hpu_type);
static const char	*sgenv_get_part_str(uint_t sensor_part);
static const char	*sgenv_get_type_str(uint_t sensor_type);


/*
 * Debug stuff
 */
#ifdef DEBUG
extern uint_t	sgenv_debug;

#define	SGENV_DEBUG_NONE	0x00
#define	SGENV_DEBUG_POLL	0x01
#define	SGENV_DEBUG_EVENT	0x02
#define	SGENV_DEBUG_CACHE	0x04
#define	SGENV_DEBUG_MSG		0x08
#define	SGENV_DEBUG_THREAD	0x10
#define	SGENV_DEBUG_ALL		0xFF

#define	DCMN_ERR_S(v, s)	static fn_t (v) = (s)

#define	DCMN_ERR	cmn_err
#define	DCMN_ERR_EVENT	if (sgenv_debug & SGENV_DEBUG_EVENT)	DCMN_ERR
#define	DCMN_ERR_CACHE	if (sgenv_debug & SGENV_DEBUG_CACHE)	DCMN_ERR
#define	DCMN_ERR_THREAD	if (sgenv_debug & SGENV_DEBUG_THREAD)	DCMN_ERR

#define	SGENV_PRINT_MBOX_MSG(x, str)    \
	DCMN_ERR(CE_CONT, "Mbox msg info: %s", str);    \
	DCMN_ERR(CE_CONT, "\ttype = 0x%x,", x->msg_type.type);     \
	DCMN_ERR(CE_CONT, "\tsub_type = 0x%x\n", x->msg_type.sub_type);    \
	DCMN_ERR(CE_CONT, "\tstatus = 0x%x\n", x->msg_status);     \
	DCMN_ERR(CE_CONT, "\tlen = %d\n", x->msg_len);   \
	DCMN_ERR(CE_CONT, "\tbytes = %d\n", x->msg_bytes);       \
	DCMN_ERR(CE_CONT, "\tdata[0] = %d\n", x->msg_data[0]);       \
	DCMN_ERR(CE_CONT, "\tdata[1] = %d\n", x->msg_data[1]);

#define	SGENV_PRINT_ENV_INFO(x) \
	DCMN_ERR(CE_CONT, "Tag=%lx, Val=%d, Lo=%d, LoW=%d, HiW=%d, Hi=%d, " \
			"Inf=%llx St=%x PSt=%x",  \
		x.sd_id.tag_id, x.sd_value, \
		x.sd_lo, x.sd_lo_warn, x.sd_hi_warn, x.sd_hi, x.sd_infostamp, \
		SG_GET_SENSOR_STATUS(x.sd_status), \
		SG_GET_PREV_SENSOR_STATUS(x.sd_status));

#define	SGENV_PRINT_POLL_INFO(x) \
		if (sgenv_debug & SGENV_DEBUG_POLL)	SGENV_PRINT_ENV_INFO(x)

#else
#define	DCMN_ERR_S(v, s)	fn_t (v) = ""

#define	_DCMN_ERR		cmn_err
#define	DCMN_ERR		if (0) _DCMN_ERR
#define	DCMN_ERR_EVENT		if (0) _DCMN_ERR
#define	DCMN_ERR_CACHE		if (0) _DCMN_ERR
#define	DCMN_ERR_THREAD		if (0) _DCMN_ERR
#define	SGENV_PRINT_MBOX_MSG
#define	SGENV_PRINT_ENV_INFO
#define	SGENV_PRINT_POLL_INFO
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SGENV_IMPL_H */
