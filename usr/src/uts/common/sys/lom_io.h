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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_LOM_IO_H
#define	_SYS_LOM_IO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * I/O header file for LOMlite Driver.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ioccom.h>

/* ioctls for the TSalarm card */

/*
 * commands to access the alarm monitor node
 */

#define	TSIOCNBMON	_IOR('a', 1, int)
#define	TSIOCWTMON	_IOWR('a', 2, int)
#define	TSIOCGETMASK	_IOR('a', 3, int)

/*
 * commands to manipulate the control node
 */

#define	TSIOCALCTL	_IOW('a', 4, ts_aldata_t)
#define	TSIOCALSTATE	_IOWR('a', 5, ts_aldata_t)
#define	TSIOCDOGSTATE	_IOR('a', 6, ts_dogstate_t)
#define	TSIOCDOGCTL	_IOW('a', 7, ts_dogctl_t)
#define	TSIOCDOGTIME	_IOW('a', 8, uint_t)
#define	TSIOCDOGPAT	_IO('a', 9)
#define	TSIOCUNLOCK	_IO('a', 10)

/*
 * Defines for the number of the three alarms
 */

#define	ALARM_NUM_1	1
#define	ALARM_NUM_2	2
#define	ALARM_NUM_3	3

/*
 * command to tell the driver to output debug information. This information
 * includes :
 * - the hardware monitor port (R/O)
 * - in-core monitor status byte
 * - the in-core control port
 * - the watchdog timeout setting
 */
#define	TSIOCDUMP	_IO('a', 11)
#define	TSIOCDBCTL	_IOW('a', 12, ts_dbctl_t)

/*
 * typedefs used in alarm ioctl definitions
 */

typedef
struct {
	int alarm_no;
	int alarm_state;
} ts_aldata_t;

typedef
struct {
	int reset_enable;
	int dog_enable;
} ts_dogctl_t;

typedef
struct {
	int reset_enable;
	int dog_enable;
	uint_t dog_timeout;
} ts_dogstate_t;


typedef
struct {
	int db_timing;
	int db_debug;
} ts_dbctl_t;

#define	MAX_PSUS	3
#define	MAX_FANS	4
#define	NUM_EVENTS	10
#define	NUM_ALARMS	3

/*
 * Defines for the lom_ctl_t events/fault led flag.
 */

#define	OFF	1
#define	ON	2

/*
 * Defines for a3mode.
 */

#define	WATCHDOG	0x02
#define	USER		0x01

/*
 * Defines for PSUSTATE
 */
#define	LOM_PSU_NOACCESS	0x20

/* ioctls for the LOMlite card */

/*
 * old commands to access the monitor node
 */

#define	LOMIOCNBMON	TSIOCNBMON
#define	LOMIOCWTMON	TSIOCWTMON
#define	LOMIOCGETMASK	TSIOCGETMASK

/*
 * old commands to manipulate the control node
 */

#define	LOMIOCALCTL	TSIOCALCTL
#define	LOMIOCALSTATE	TSIOCALSTATE
#define	LOMIOCDOGSTATE	TSIOCDOGSTATE
#define	LOMIOCDOGCTL	TSIOCDOGCTL
#define	LOMIOCDOGTIME	TSIOCDOGTIME
#define	LOMIOCDOGPAT	TSIOCDOGPAT
#define	LOMIOCUNLOCK	TSIOCUNLOCK

/*
 * new commands to access the monitor node
 */

#define	LOMIOCPSUSTATE	_IOR('a', 21, lom_psudata_t)
#define	LOMIOCEVENTLOG	_IOR('a', 22, lom_eventlog_t)
#define	LOMIOCFANSTATE	_IOR('a', 23, lom_fandata_t)
#define	LOMIOCFLEDSTATE _IOR('a', 24, lom_fled_info_t)
#define	LOMIOCINFO	_IOR('a', 25, lom_info_t)

/*
 * new commands to manipulate the control node
 */

#define	LOMIOCCLEARLOG	_IO('a', 26)
#define	LOMIOCCTL	_IOW('a', 27, lom_ctl_t)
#define	LOMIOCPROG	_IOWR('a', 28, lom_prog_t)
#define	LOMIOCDAEMON	_IOWR('a', 29, int)
#define	LOMIOCDMON	_IOWR('a', 30, int)

/*
 * Command to read general purpose LOMlite inputs.
 * There are only 3 bits to general purpose inputs.
 */

#define	LOMIOCGPINPUTS	_IOWR('a', 31, int)

/*
 * Manufacture programming command.
 */

#define	LOMIOCMPROG	_IOW('a', 32, lom_mprog_t)
#define	LOMIOCMREAD	_IOR('a', 33, lom_mprog_t)

#define	LOMIOCLEDSTATE 	_IOR('a', 34, lom_led_state_t)

/*
 * command to tell the driver to output debug information. This information
 * includes :
 * - the hardware monitor port (R/O)
 * - in-core monitor status byte
 * - the in-core control port
 * - the watchdog timeout setting
 */
#define	LOMIOCDUMP	TSIOCDUMP
#define	LOMIOCDBCTL	TSIOCDBCTL

/*
 * typedefs used in LOMlite ioctl definitions
 */

typedef
struct {
	int alarm_no;
	int state;
} lom_aldata_t;

typedef
struct {
	int reset_enable;
	int dog_enable;
} lom_dogctl_t;

typedef
struct {
	int reset_enable;
	int dog_enable;
	uint_t dog_timeout;
} lom_dogstate_t;


typedef
struct {
	int db_timing;
	int db_debug;
} lom_dbctl_t;


typedef
struct {
	int fitted[MAX_PSUS];
	int output[MAX_PSUS];
	int supplya[MAX_PSUS];
	int supplyb[MAX_PSUS];
	int standby[MAX_PSUS];
} lom_psudata_t;

typedef
struct {
	int fitted[MAX_FANS];
	int speed[MAX_FANS];
	int minspeed[MAX_FANS];
} lom_fandata_t;

typedef
struct {
	int events[NUM_EVENTS];
	int fatalevent;
} lom_eventlog_t;

/*
 * The event codes as used in lom_eventlog_t are coded as described here:
 *
 * Event codes encode, in a single byte, the source and type
 * of event/failure in the system.
 *
 * There are two types of failure - fan and PSU.
 *
 * Other events need to be stored but do not constitue faults.
 */
#define	LOM_EVENT_NONE		0x00	/* No fault */
#define	LOM_EVENT_LOST		0x01	/* Event lost due to buffer overflow */
#define	LOM_EVENT_RESET		0x02	/* Reset is asserted by the LOM */
#define	LOM_EVENT_PWR_ON	0x03	/* Power is turned on by the LOM */
#define	LOM_EVENT_PWR_OFF	0x04	/* Power is turned off by the LOM */
#define	LOM_EVENT_WDOG_ON	0x05	/* Host watchdog enabled */
#define	LOM_EVENT_WDOG_OFF	0x06	/* Host watchdog disabled */
#define	LOM_EVENT_WDOG_TRIG	0x07	/* Host watchdog triggered */
#define	LOM_EVENT_LOM_RESET	0x08	/* LOMlite has been reset */
#define	LOM_EVENT_CHECKSUM	0x09	/* ROM checksum failure */
#define	LOM_EVENT_BUSY		0x0a	/* Event not ready yet (being read) */

/*
 * Fault LED events
 */
#define	LOM_EVENT_FAULT		0x20	/* Fault events - codes 0x20-0x2f */
#define	LOM_EVENT_FAULT_MASK	0xf0	/* Fault events - codes 0x20-0x2f */

/*
 * Fault LED events are encoded thus
 *
 *  7	 4 3		       0
 *  ----------------------------
 * | 0010 | Fault LED frequency |
 *  ----------------------------
 *
 * The "Fault LED frequency" is a 4 bit code allowing for LED
 * falshing rates of 0 to 14 Hz with a rate of 15 signifying off.
 *
 * For example the event code for the assertion of a fault LED rate of 2Hz is:
 *    LOM_EVENT_FAULT_ENCODE(2);
 */
#define	LOM_EVENT_FAULT_ENCODE(faultRate) \
	(LOM_EVENT_FAULT | ((faultRate)&0xf))

/*
 * Alarm events
 */
#define	LOM_EVENT_ALARM		0x30	/* Alarm events - codes 0x30-0x3f */
#define	LOM_EVENT_ALARM_MASK	0xf0	/* Alarm events - codes 0x30-0x3f */

/*
 * Alarm events are encoded thus
 *
 *  7	 4 3		1    0
 *  --------------------------
 * | 0011 | Alarm number | On |
 *  --------------------------
 *
 * The "Alarm number" is a 3 bit code allowing for up to 8 alarms
 *
 * For example the event code for the assertion of alarm 2 is:
 *    LOM_EVENT_ALARM_ENCODE(2, 1);
 */
#define	LOM_EVENT_ALARM_ENCODE(alarmNum, alarmOn) \
	(LOM_EVENT_ALARM | (alarmNum<<1) | ((alarmOn)&0x1))

/*
 * These alarms are considered fatal errors
 */

#define	LOM_EVENT_FAN		0x40	/* Fan failure - codes 0x40-0x7f */
#define	LOM_EVENT_FAN_MASK	0xc0	/* Fan failure - codes 0x40-0x7f */

/*
 * Fan events are encoded thus
 *
 *  7  6 5	    3 2	     0
 *  --------------------------
 * | 01 | Fan number | Status |
 *  --------------------------
 *
 * The "Fan number" is a 3 bit code allowing for up to 8 fans
 *
 * As yet there are no defined fan statuses.
 *
 * For example the event code for a failure on fan 3 is:
 *    LOM_EVENT_FAN_ENCODE(3, 0);
 */
#define	LOM_EVENT_FAN_ENCODE(fanNum, fanStatus) \
	(LOM_EVENT_FAN | (fanNum<<3) | ((fanStatus)&0x7))

#define	LOM_EVENT_PSU		0x80	/* PSU failure - codes 0x80-0xbf */
#define	LOM_EVENT_PSU_MASK	0xc0	/* PSU failure - codes 0x80-0xbf */

/*
 * These definitions will be picked up elsewhere in embedded code
 */
#ifndef LOM_PSU_PRESENT
/*
 * PSU status flags
 */
#define	LOM_PSU_PRESENT		0x08
#define	LOM_PSU_INPUT_A_OK	0x01
#define	LOM_PSU_INPUT_B_OK	0x02
#define	LOM_PSU_OUTPUT_OK	0x04
#define	LOM_PSU_STATUS_MASK	(LOM_PSU_INPUT_A_OK | LOM_PSU_INPUT_B_OK | \
				LOM_PSU_OUTPUT_OK)
#endif

/*
 * PSU events are encoded thus
 *
 *  7  6 5	    3		    2		     1		      0
 *  -------------------------------------------------------------------
 * | 10 | PSU number | Output Status | Input B Status | Input A Status |
 *  -------------------------------------------------------------------
 *
 * The PSU number is a 3 bit code allowing for up to 8 PSUs
 *
 * The PSU status is derived from the LOM_PSU... definitions.
 *
 * For example the event code for an "Input B" failure on PSU 2 is:
 *    LOM_EVENT_PSU_ENCODE(2, LOM_PSU_INPUT_A_OK | LOM_PSU_OUTPUT_OK);
 */
#define	LOM_EVENT_PSU_ENCODE(psuNum, psuStatus) \
	(LOM_EVENT_PSU | (psuNum<<3) | ((psuStatus)&0x7))

#define	MAX_LOM2_NAME_STR	16

#define	LOM_LED_STATE_OFF		0x00
#define	LOM_LED_STATE_ON_STEADY		0x01
#define	LOM_LED_STATE_ON_FLASHING	0x02
#define	LOM_LED_STATE_ON_SLOWFLASH	0x03
#define	LOM_LED_STATE_INACCESSIBLE	0xfd
#define	LOM_LED_STATE_STANDBY		0xfe
#define	LOM_LED_STATE_NOT_PRESENT	0xff

enum states {
	LOM_LED_OUTOFRANGE = -3,
	LOM_LED_NOT_IMPLEMENTED,
	LOM_LED_ACCESS_ERROR,
	LOM_LED_OFF,
	LOM_LED_ON,
	LOM_LED_BLINKING
};

enum colours {
	LOM_LED_COLOUR_NONE = -1,
	LOM_LED_COLOUR_ANY,
	LOM_LED_COLOUR_WHITE,
	LOM_LED_COLOUR_BLUE,
	LOM_LED_COLOUR_GREEN,
	LOM_LED_COLOUR_AMBER
};


typedef
struct {
	int on;
} lom_fled_info_t;

typedef
struct {
	int16_t index;
	int8_t state;
	int8_t colour;
	char label[MAX_LOM2_NAME_STR];
} lom_led_state_t;

typedef
struct {
	char ser_char;
	int a3mode;
	int fver;
	int fchksum;
	int prod_rev;
	char prod_id[12];
	int events;
} lom_info_t;

typedef
struct {
	char ser_char;
	int a3mode;
	int fault_led;
	int events;
	int check;
} lom_ctl_t;

/*
 * in mprog, config is:
 *  bits 5-7 no. fans
 *  bits 3-4 no.psus
 *  bit 2 tty_con
 *  bit 1 set to stop fault LED flashing
 *  bit 0 set if DC PSUs fitted
 *
 * fanhz is hz for 100% and fanmin is min speed as %.
 */

typedef
struct {
	char mod_id[12];
	int mod_rev;
	int config;
	int fanhz[4];
	int fanmin[4];
} lom_mprog_t;

typedef
struct {
	int index;	    /* top bit should be set if last buffer */
	uint8_t data[0x400];
	int size;
} lom_prog_t;

/*
 * LOMlite2 specific support.
 */

#define	LOMIOCCTL2	_IOW('a', 40, lom_ctl2_t)

typedef
struct {
	char  escape_chars[6];
	int   serial_events;
} lom_ctl2_t;

#define	LOM_EVENT_NOREP	0
#define	LOM_EVENT_FATAL	1
#define	LOM_EVENT_WARN	2
#define	LOM_EVENT_INFO	3
#define	LOM_EVENT_USER	4
#define	LOM_SER_EVENTS_ON	0x100
#define	LOM_SER_EVENTS_OFF	0x200
#define	LOM_SER_EVENTS_DEF	0x300
#define	DEFAULT_NUM_EVENTS	10

#define	LOMIOCVOLTS	_IOR('a', 41, lom_volts_t)
#define	MAX_VOLTS	16

typedef
struct {
	int   num;  /* No. of voltage lines being monitored on that system */
	char  name[MAX_VOLTS][MAX_LOM2_NAME_STR];
	int   status[MAX_VOLTS]; /* 0=ok 1=faulty */
	int   shutdown_enabled[MAX_VOLTS];
} lom_volts_t;

/* status flags (circuit breakers) */

#define	LOMIOCSTATS	_IOR('a', 42, lom_sflags_t)
#define	MAX_STATS	8

typedef
struct {
	int   num;  /* No. of status flags being monitored on that system */
	char  name[MAX_STATS][MAX_LOM2_NAME_STR];
	int   status[MAX_STATS]; /* 0=ok 1=faulty */
} lom_sflags_t;

#define	LOMIOCTEMP	_IOR('a', 43, lom_temp_t)
#define	MAX_TEMPS	8

typedef
struct {
	int   num;  /* No. of temps being monitored on that system */
	char  name[MAX_TEMPS][MAX_LOM2_NAME_STR];
	int   temp[MAX_TEMPS]; /* degrees C */
	int   warning[MAX_TEMPS]; /* degrees C - zero if not enabled */
	int   shutdown[MAX_TEMPS]; /* degrees C - zero if not enabled */
	int   num_ov;  /* No. of overtemp sensors being monitored */
	char  name_ov[MAX_TEMPS][MAX_LOM2_NAME_STR];
	int   status_ov[MAX_TEMPS]; /* 0=ok 1=faulty */
} lom_temp_t;

#define	LOMIOCCONS	_IOR('a', 44, lom_cbuf_t)
#define	CONS_BUF_SIZE	256

typedef
struct {
	char  lrbuf[CONS_BUF_SIZE];
} lom_cbuf_t;

#define	LOMIOCEVENTLOG2	_IOWR('a', 45, lom_eventlog2_t)
#define	MAX_EVENTS	128
#define	MAX_EVENT_STR	80

/*
 * NB no need for 1st fatal as the ioctl can ask for ONLY fatal events.
 * The driver will return the whole event string, but include the code
 * and time for mgmt applications.
 */

typedef
struct {
	int   num; /* no. events requested and no. returned */
	int   level; /* level of events requested */
	int   code[MAX_EVENTS];
	char  string[MAX_EVENTS][MAX_EVENT_STR];
	int   time[MAX_EVENTS];
} lom_eventlog2_t;

#define	LOMIOCINFO2	_IOWR('a', 46, lom2_info_t)

/*
 * We may not display all these properties by default, but add them all
 * into IOCTL structure to cover future enhancements.
 */

typedef
struct {
	char escape_chars[6];
	int  serial_events; /* as defined for LOMIOCCTL2 */
	int a3mode;
	int fver;
	int fchksum;
	int prod_rev;
	char prod_id[12];
	int serial_config; /* security, timeout, etc */
	int baud_rate;
	int serial_hw_config; /* stop bit, parity etc */
	int phone_home_config; /* TRUE is enabled */
	char phone_home_script[128];
	char fan_names[MAX_FANS][MAX_LOM2_NAME_STR];
} lom2_info_t;

/* serial_config defn - bottom 8bits are serial return timeout */
#define	LOM_SER_SECURITY 0x10000
#define	LOM_SER_RETURN	 0x20000
#define	LOM_DISABLE_WDOG_BREAK 0x40000

/*
 * For test ioctl low byte is test number and 2nd byte is the argument supplied
 * with the test.  Usually, it indicates the number of iterations to perform.
 * The result is returned in the low byte.
 */
#define	BSCV_LED_TEST			0x06
#define	BSCV_LED_TEST_FLASH_ALL		0x01
#define	BSCV_LED_TEST_SVC_REQD		0x02
#define	BSCV_LED_TEST_DONE		0x00
#define	LOMIOCTEST	_IOWR('a', 47, uint32_t)

#define	LOMIOCMPROG2	_IOW('a', 48, lom2_mprog_t)
#define	LOMIOCMREAD2	_IOR('a', 49, lom2_mprog_t)

typedef
struct {
	int   addr_space;
	uint8_t	data[255];
} lom2_mprog_t;

#define	LOMIOCEVNT	_IOWR('a', 50, int)

/*
 * Due to poll being broken in S8su2 add in ioctl to sleep for arg microsecs
 */

#define	LOMIOCSLEEP	_IOWR('a', 51, int)

/*
 * IOCTL defines for lomp - LOMlite field programming driver.
 */

#define	LOMPIOCRESON	_IO('p', 1)
#define	LOMPIOCRESOFF	_IO('p', 2)
#define	LOMPIOCFVPPON	_IO('p', 3)
#define	LOMPIOCFVPPOFF	_IO('p', 4)



#ifdef __cplusplus
}
#endif

#endif	/* _SYS_LOM_IO_H */
