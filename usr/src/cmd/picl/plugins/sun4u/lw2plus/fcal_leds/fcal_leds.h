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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_FCAL_LEDS_H
#define	_FCAL_LEDS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <picl.h>
#include <picltree.h>
#include <picldefs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Header file for the FC-AL LEDs PICL plugin.
 * Contains message texts, constant definitions, typedefs for enums and
 * structs, global data and function templates.
 */

#define	SYSLOG	syslog

/*
 * log message tests
 */
#define	EM_CANT_OPEN	\
	gettext("SUNW_fcal_leds: open fail: %s\n")
#define	EM_NONALF_TOK	\
	gettext("SUNW_fcal_leds: line %d token begins non-alpha\n")
#define	EM_LONG_TOK	\
	gettext("SUNW_fcal_leds: line %d token too long\n")
#define	EM_UNKN_TOK	\
	gettext("SUNW_fcal_leds: line %d unknown token\n")
#define	EM_INVAL_TOK	\
	gettext("SUNW_fcal_leds: line %d invalid token at start of line\n")
#define	EM_NOCOLON	\
	gettext("SUNW_fcal_leds: line %d leading token not followed by ':'\n")
#define	EM_NOVERS	\
	gettext("SUNW_fcal_leds: first token not VERSION\n")
#define	EM_NUM_TERM	\
	gettext("SUNW_fcal_leds: invalid number terminator\n")
#define	EM_LOGIC_LVL	\
	gettext("SUNW_fcal_leds: logic level specified as neither 0 nor 1\n")
#define	EM_NOTPOS	\
	gettext("SUNW_fcal_leds: numeric field greater than 0 expected\n")
#define	EM_DISK_RANGE	\
	gettext("SUNW_fcal_leds: disk number out of range\n")
#define	EM_NDISKS_DBL	\
	gettext("SUNW_fcal_leds: number of disks defined twice\n")
#define	EM_NO_DISKS	\
	gettext("SUNW_fcal_leds: no disks defined\n")
#define	EM_VER_FRMT	\
	gettext("SUNW_fcal_leds: format error in VERSION string\n")
#define	EM_WRNGVER	\
	gettext("SUNW_fcal_leds: config version %d.%d not supported\n")
#define	EM_REL_PATH	\
	gettext("SUNW_fcal_leds: path names must be absolute\n")
#define	EM_ERRLINE	\
	gettext("SUNW_fcal_leds: error on line %d\n")
#define	EM_NO_LED_PROP	\
	gettext("SUNW_fcal_leds: LED property name missing\n")
#define	EM_PROP_TERM	\
	gettext("SUNW_fcal_leds: expected comma (',') after property name\n")
#define	EM_STR_NOT_SET	\
	gettext("SUNW_fcal_leds: %s not defined")
#define	EM_I2C_GET_PORT	\
	gettext("SUNW_fcal_leds: I2C_GET_PORT: %s\n")
#define	EM_DI_INIT_FAIL	\
	gettext("SUNW_fcal_leds: di_init failed: %s\n")
#define	EM_THREAD_CREATE_FAILED \
	gettext("SUNW_fcal_leds: pthread_create() call failed: %s\n")
#define	EM_MUTEX_FAIL	\
	gettext("SUNW_fcal_leds: pthread_mutex_lock returned: %s\n")
#define	EM_CONDWAITFAIL	\
	gettext("SUNW_fcal_leds: pthread_cond_wait returned: %s\n")
#define	EM_SPURIOUS_FP	\
	gettext("SUNW_fcal_leds: deleting spurious PICL fp node\n")
#define	EM_NO_FP_NODE \
	gettext(	\
	    "SUNW_fcal_leds: cannot get PICL disk node for hot plug disk %d\n")
#define	EM_POLL_FAIL	\
	gettext("SUNW_fcal_leds: poll() returned: %s, no more timed events\n")

/*
 * config file terminal name
 */
#define	FCAL_LEDS_CONF_FILE	"fcal_leds.conf"

/*
 * devinfo hardware properties
 */
#define	HW_PROP_TARGET		"target"
#define	HW_PROP_PORT		"port-wwn"

/*
 * PICL node names
 */
#define	FCAL_PICL_DISK_UNIT	"disk-unit"

/*
 * PICL property names
 */
#define	FCAL_PICL_REF		"_"
#define	FCAL_PICL_PROP_BUS_ADDR	"bus-addr"
#define	FCAL_PICL_PROP_TARGET	"target"
#define	FCAL_PICL_LED_REF	FCAL_PICL_REF PICL_CLASS_LED FCAL_PICL_REF
#define	FCAL_PICL_BLOCK_REF	FCAL_PICL_REF PICL_CLASS_BLOCK FCAL_PICL_REF

/*
 * String values for led State property
 */
#define	FCAL_PICL_LED_ON	"on"
#define	FCAL_PICL_LED_OFF	"off"
#define	FCAL_PICL_LED_TEST	"led test"
/*
 * MAX_LEN_LED_STATE is (strlen(FCAL_PICL_LED_TEST) + 1)
 */
#define	MAX_LEN_LED_STATE	9

/*
 * Space for 0123456789ABCDEF,0123456789ABCDEF<nul>
 */
#define	MAX_LEN_UNIT_ADDRESS	34

/*
 * properties per row in Device table
 */
#define	FCAL_DEVTABLE_NCOLS	2

/*
 * number of LEDs per disk
 */
#define	FCAL_LED_CNT	3

/*
 * special values for status when ioctl fails
 */
#define	I2C_IOCTL_FAIL	(-1)
#define	I2C_IOCTL_INIT	(-2)
#define	MINORS_UNKNOWN	(-1)

/*
 * other status values
 */
#define	NO_MINORS	0
#define	HAS_MINORS	1

/*
 * event flags
 */
#define	FCAL_EV_POLL	1
#define	FCAL_EV_CONFIG	2

/*
 * default timer values - overridden by .conf file
 */
#define	DFLT_SLOW_POLL	59
#define	DFLT_FAST_POLL	2
#define	DFLT_RELAX_TIME	300
#define	DFLT_TEST_TIME	10

typedef enum token {
	NO_TOKEN,
	TOKEN_ERROR,
	FCAL_VERSION,
	LED_PROPS_START,	/* next enums are for led properties */
	FCAL_REMOK_LED,
	FCAL_FAULT_LED,
	FCAL_READY_LED,
	LED_PROPS_END,		/* no more led properties */
	LINE_DEFS,		/* next enums define configuration lines */
	FCAL_LEDS_BOARD,
	FCAL_STATUS_BOARD,
	FCAL_DISK_DRIVER,
	FCAL_N_DISKS,
	FCAL_ASSERT_PRESENT,
	FCAL_ASSERT_FAULT,
	FCAL_LED_ON,
	FCAL_DISK_PRESENT,
	FCAL_DISK_FAULT,
	FCAL_LED_ID,
	FCAL_SLOW_POLL,
	FCAL_FAST_POLL,
	FCAL_RELAX_INTERVAL,
	FCAL_TEST_INTERVAL,
	FCAL_DISK_PARENT,
	FCAL_UNIT_PARENT,
	FCAL_LED_NODES
} token_t;

typedef enum led_state_enum {
	LED_STATE_OFF,
	LED_STATE_ON,
	LED_STATE_TEST
} led_state_t;

typedef char *str;
typedef const char *cstr;

/*
 * Note on disk_prev and disk_ready flags.
 * The following entries are dynamically created arrays:
 * presence, faults, disk_detected, disk_ready, disk_prev, led_test_end,
 * disk_port, led_addr.
 * The disk_prev and disk_ready flags (one per disk) are used as follows:
 * disk removed (disk_detected = 0), disk_ready[d] = 0, disk_prev[d] = 0
 * disk present (disk_detected = 1) use this table:
 * disk_ready[d] | disk_prev[d] | meaning
 *      0        |      0       | driver not (yet) attached (show green led)
 *      0        |      1       | driver has been detached (show blue led)
 *      1        |      0       | driver attached, PICL update needed (green)
 *      1        |      1       | driver attached, normal running (green)
 * OK to remove (blue) is only lit for the attached -> detached transition
 * state 1 0 (PICL update needed) is really transient and is cleared after
 * calling update_picl.
 */
typedef struct led_dtls {
	int		ver_maj;
	int		ver_min;
	cstr		fcal_leds;	/* path name of leds board */
	cstr		fcal_status;	/* path of back-plane status board */
	cstr		fcal_driver;	/* name of fcal disk driver */
	int		n_disks;	/* number of fcal disks */
	int		*presence;	/* presence detection masks */
	int		*faults;	/* fault status masks */
	int		*disk_detected;	/* working store for detected disks */
	int		*disk_ready;	/* working store for disk ready */
	int		*disk_prev;	/* previous ready state */
	volatile int	*led_test_end;	/* (per disk) ticks to end led test */
	boolean_t	*picl_retry;	/* (per disk) retry picl update flag */
	uchar_t		**disk_port;	/* for FC-AL this is WWN */
	int		assert_presence; /* status value for presence */
	int		assert_fault;	/* status value for fault */
	int		assert_led_on;	/* level required to light led */
	uint_t		*led_addr[FCAL_LED_CNT]; /* 2D array to leds */
	led_state_t	*led_state[FCAL_LED_CNT]; /* current states */
	boolean_t	led_retry;	/* flag set after led ioctl failure */
	volatile boolean_t polling;	/* set to B_FALSE after poll failure */
	volatile int	fast_poll_end;	/* fast_poll ticks left */
	int		fast_poll;	/* fast_poll interval in seconds */
	int		slow_poll_ticks; /* fast polls per slow poll */
	int		relax_time_ticks; /* time interval to do fast polling */
	int		led_test_time;	/* fast polls in led test interval */
	cstr		fcal_disk_parent; /* search string for /platform */
	cstr		disk_unit_parent; /* search template for disk-slots */
	cstr		disk_led_nodes;	/* search template for disk-leds */
} led_dtls_t;

typedef int (*actfun_t)(str *p_str, led_dtls_t *dtls);

typedef struct lookup {
	token_t		tok;
	cstr		tok_str;
	actfun_t	action;
} lookup_t;

/*
 * global data
 */
extern led_dtls_t	*g_led_dtls;
extern pthread_cond_t	g_cv;
extern pthread_cond_t	g_cv_ack;
extern pthread_mutex_t	g_mutex;
extern volatile int	g_event_flag;
extern volatile boolean_t g_finish_now;
extern volatile boolean_t g_leds_thread_ack;
extern volatile boolean_t g_poll_thread_ack;

/*
 * function templates
 */
char *mystrerror(int err);
void *fcal_leds_thread(void *args);
int fc_led_parse(FILE *fp, led_dtls_t **p_dtls);
void free_led_dtls(led_dtls_t *dtls);
int find_disk_slot(led_dtls_t *dtls, int disk, picl_nodehdl_t *nodeh);
void delete_disk_unit(led_dtls_t *dtls, int disk);
boolean_t is_led_test(led_dtls_t *dtls);
int create_Device_table(picl_prophdl_t *tbl_h, picl_prophdl_t *tableh);
void clr_led(int diskNo, token_t led_tok, led_dtls_t *dtls);

#ifdef	__cplusplus
}
#endif

#endif	/* _FCAL_LEDS_H */
