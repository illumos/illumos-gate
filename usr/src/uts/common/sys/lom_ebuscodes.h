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

#ifndef _SYS_LOM_EBUSCODES_H
#define	_SYS_LOM_EBUSCODES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file enumerates the virtual registers exported by the microcontroller.
 * It cannot be changed without also revising the firwmare.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	EBUS_CMD_SPACE_GENERIC  0x00	/* generic space */
#define	EBUS_CMD_SPACE1		0x01	/* space 1 - console buffer or	*/
					/* boot script			*/
#define	EBUS_CMD_SPACE2		0x02	/* space 2 - supply rail data */
#define	EBUS_CMD_SPACE3		0x03	/* space 3 - circuit breaker data */
#define	EBUS_CMD_SPACE4		0x04	/* space 4 - fan data */
#define	EBUS_CMD_SPACE5		0x05	/* space 5 - temp/otemp sensor data */
#define	EBUS_CMD_SPACE6		0x06	/* space 6 - phone-home config */
#define	EBUS_CMD_SPACE_PROGRAM  0x07	/* space 7 - send a program */
#define	EBUS_CMD_SPACE_EEPROM   0x08	/* space 8 - eeprom/event-log access */
#define	EBUS_CMD_SPACE_SELFTEST 0x09	/* space 9 - selftest control */
#define	EBUS_CMD_SPACE_LEDS	0x0a	/* space 10 - LED name access */

/*
 * Read only values
 */
#define	EBUS_IDX_FW_REV		0x01	/* Firmware Revision */
#define	EBUS_IDX_CHECK_HI	0x02	/* Firmware checksum high */
#define	EBUS_IDX_CHECK_LO	0x03	/* Firmware checksum low */
#define	EBUS_IDX_FAN1_SPEED	0x04	/* Fan 1 current speed % of max */
#define	EBUS_IDX_FAN2_SPEED	0x05	/* Fan 2 current speed % of max */
#define	EBUS_IDX_FAN3_SPEED	0x06	/* Fan 3 current speed % of max */
#define	EBUS_IDX_FAN4_SPEED	0x07	/* Fan 4 current speed % of max */
#define	EBUS_IDX_PSU1_STAT	0x08	/* PSU 1 status */
#define	EBUS_IDX_PSU2_STAT	0x09	/* PSU 2 status */
#define	EBUS_IDX_PSU3_STAT	0x0a	/* PSU 3 status */
#define	EBUS_IDX_STATE_CHNG	0x0b	/* State change flags */
#define	EBUS_IDX_GPIP		0x0c	/* General purpose inputs */

/* RESERVED			0x0d	*/
/* RESERVED			0x0e	*/
/* RESERVED			0x0f	*/
#define	EBUS_IDX_LOG_START_HI	0x10	/* MSB of start of eventlog in eeprom */
#define	EBUS_IDX_LOG_START_LO	0x11	/* LSB of start of eventlog in eeprom */
#define	EBUS_IDX_LOG_PTR_HI	0x12	/* MSB of current position in log */
#define	EBUS_IDX_LOG_PTR_LO	0x13	/* LSB of current position in log */

/*
 * We currently don't have a virtual register to indicate the end of the log.
 * We cannot assume the log runs to the end of the EEPROM because the EEPROM
 * is logically partitioned into a Log portion (first 8K) and then a FRUID
 * portion (next 8K).  For the moment we therefore need to use a hardcoded
 * value to represent the end of the event log.
 */
#define	EBUS_LOG_END		0x2000

#define	EBUS_IDX_EEPROM_SIZE_KB	0x14	/* Size of eeprom in kilobytes */
#define	EBUS_IDX_UNREAD_EVENTS	0x15	/* Number of events (un)read by host */
/* RESERVED			0x16	*/
/* RESERVED			0x17	*/

#define	EBUS_IDX_TEMP1		0x18	/* Temperature sensors */
#define	EBUS_IDX_TEMP2		0x19
#define	EBUS_IDX_TEMP3		0x1A
#define	EBUS_IDX_TEMP4		0x1B
#define	EBUS_IDX_TEMP5		0x1C
#define	EBUS_IDX_TEMP6		0x1D
#define	EBUS_IDX_TEMP7		0x1E
#define	EBUS_IDX_TEMP8		0x1F

#define	EBUS_IDX_ALARMNEW	0x20
#define	EBUS_IDX_SUPPLY_LO	0x21	/* 1 bit per voltage line status */
#define	EBUS_IDX_SUPPLY_HI	0x22	/* whether faulty or not; 1=>faulty */
#define	EBUS_IDX_CBREAK_STATUS	0x23
#define	EBUS_IDX_OTEMP_STATUS	0x24

#define	EBUS_IDX_LED1_STATUS	0x25
#define	EBUS_IDX_LED2_STATUS	0x26
#define	EBUS_IDX_LED3_STATUS	0x27
#define	EBUS_IDX_LED4_STATUS	0x28
#define	EBUS_IDX_LED5_STATUS	0x29
#define	EBUS_IDX_LED6_STATUS	0x2a
#define	EBUS_IDX_LED7_STATUS	0x2b
#define	EBUS_IDX_LED8_STATUS	0x2c
/* RESERVED			0x2d	*/

#define	EBUS_IDX_CPU_IDENT	0x2e
#define	EBUS_IDX_EVENT_DETAIL   0x2f

/*
 * Read/write access registers
 */
#define	EBUS_IDX_ALARM		0x30	/* Alarm control/status */
#define	EBUS_IDX_WDOG_CTRL	0x31	/* Watchdog control */
#define	EBUS_IDX_WDOG_TIME	0x32	/* Watchdog timeout */

#define	EBUS_IDX_SER_BAUD	0x33
#define	EBUS_IDX_SER_CHARMODE	0x34
#define	EBUS_IDX_SER_FLOWCTL	0x35
#define	EBUS_IDX_SER_MODEMTYPE	0x36
#define	EBUS_IDX_EEPROM_PAGESEL	0x37

#define	EBUS_IDX_HNAME_LENGTH   0x38
#define	EBUS_IDX_HNAME_CHAR	0x39

#define	EBUS_IDX_CONFIG_MISC	0x3a	/* Host specific configuration */

#define	EBUS_IDX_TIME0		0x3b
#define	EBUS_IDX_TIME1		0x3c
#define	EBUS_IDX_TIME2		0x3d
#define	EBUS_IDX_TIME3		0x3e

#define	EBUS_IDX_ESCAPE		0x3f	/* Escape character, default '#' */
#define	EBUS_IDX_EVENT_CNT	0x40	/* Number of unread (via EBus) events */

#define	EBUS_IDX_SELFTEST0	0x41
#define	EBUS_IDX_SELFTEST1	0x42
#define	EBUS_IDX_SELFTEST2	0x43
#define	EBUS_IDX_SELFTEST3	0x44
#define	EBUS_IDX_SELFTEST4	0x45
#define	EBUS_IDX_SELFTEST5	0x46
#define	EBUS_IDX_SELFTEST6	0x47
#define	EBUS_IDX_SELFTEST7	0x48

#define	EBUS_IDX_ESCAPE_LEN	0x49
#define	EBUS_IDX_SER_TIMEOUT	0x4a
#define	EBUS_IDX_EVENT_FILTER   0x4b
#define	EBUS_IDX_POWERON_DELAY  0x4c

#define	EBUS_IDX_BOOTMODE	0x4d	/* boot-mode for PROM */

#define	EBUS_IDX_I2C_HOLDOFF	0x4e	/* hold off i2c bus while obp starts */
/* RESERVED			0x4f	*/

#define	EBUS_IDX_MODEL_ID1	0x50	/* Model identifier */
#define	EBUS_IDX_MODEL_ID2	0x51
#define	EBUS_IDX_MODEL_ID3	0x52
#define	EBUS_IDX_MODEL_ID4	0x53
#define	EBUS_IDX_MODEL_ID5	0x54
#define	EBUS_IDX_MODEL_ID6	0x55
#define	EBUS_IDX_MODEL_ID7	0x56
#define	EBUS_IDX_MODEL_ID8	0x57
#define	EBUS_IDX_MODEL_ID9	0x58
#define	EBUS_IDX_MODEL_ID10	0x59
#define	EBUS_IDX_MODEL_ID11	0x5a
#define	EBUS_IDX_MODEL_ID12	0x5b
#define	EBUS_IDX_MODEL_REV	0x5c	/* Model Revision */

#define	EBUS_IDX_CONFIG		0x5d	/* Model specific configuration */
#define	EBUS_IDX_FAN1_CAL	0x5e	/* Fan 1 calibration value */
#define	EBUS_IDX_FAN2_CAL	0x5f	/* Fan 2 calibration value */
#define	EBUS_IDX_FAN3_CAL	0x60	/* Fan 3 calibration value */
#define	EBUS_IDX_FAN4_CAL	0x61	/* Fan 4 calibration value */
#define	EBUS_IDX_FAN1_LOW	0x62	/* Fan 1 low limit */
#define	EBUS_IDX_FAN2_LOW	0x63	/* Fan 2 low limit */
#define	EBUS_IDX_FAN3_LOW	0x64	/* Fan 3 low limit */
#define	EBUS_IDX_FAN4_LOW	0x65	/* Fan 4 low limit */

#define	EBUS_IDX_CONFIG2	0x66	/* Model specific configuration */
#define	EBUS_IDX_CONFIG3	0x67	/* Model specific configuration */

#define	EBUS_IDX_HOSTID1	0X68	/* Host ID, MSB */
#define	EBUS_IDX_HOSTID2	0X69	/* Host ID */
#define	EBUS_IDX_HOSTID3	0X6a	/* Host ID */
#define	EBUS_IDX_HOSTID4	0X6b	/* Host ID */

/* RESERVED			0x6c	*/
/* RESERVED			0x6d	*/
/* RESERVED			0x6e	*/
/* RESERVED			0x6f	*/
/* RESERVED			0x70	*/
/* RESERVED			0x71	*/
/* RESERVED			0x72	*/
/* RESERVED			0x73	*/
/* RESERVED			0x74	*/
/* RESERVED			0x75	*/
/* RESERVED			0x76	*/
/* RESERVED			0x77	*/
/* RESERVED			0x78	*/
/* RESERVED			0x79	*/
/* RESERVED			0x7a	*/

/*
 * Capability bits:
 *
 * Register starting from 0x7e and downward are used to describe various
 * capabilities that the LOM firmware has.  A capability is present if the
 * corresponding bit returns '1'.
 */
#define	EBUS_IDX_CAP2		0x7b	/* Capabilities - Read only */
#define	EBUS_IDX_CAP1		0x7c	/* Capabilities - Read only */
#define	EBUS_IDX_CAP0		0x7d	/* Capabilities - Read only */

#define	EBUS_IDX_PROBE55	0x7e	/* Always returns 0x55 */
#define	EBUS_IDX_PROBEAA	0x7f	/* Always returns 0xaa */

#define	EBUS_FIRST_READONLY	EBUS_IDX_FW_REV
#define	EBUS_LAST_READONLY	EBUS_IDX_EVENT_DETAIL
#define	EBUS_FIRST_MODELLOCKED  EBUS_IDX_MODEL_ID1
#define	EBUS_LAST_MODELLOCKED   EBUS_IDX_CONFIG3

/*
 * Register for special address spaces
 */
#define	EBUS_IDX1_CONS_BUF_START	0x00
#define	EBUS_IDX1_CONS_BUF_END		0xff

#define	EBUS_IDX2_SUPPLY_ENABLE_MASK1	0x01
#define	EBUS_IDX2_SUPPLY_ENABLE_MASK2	0x02
#define	EBUS_IDX2_SUPPLY_FATAL_MASK1	0x03
#define	EBUS_IDX2_SUPPLY_FATAL_MASK2	0x04
#define	EBUS_IDX2_SUPPLY_FINE_TOL	0x05
#define	EBUS_IDX2_SUPPLY_GROSS_TOL	0x06
#define	EBUS_IDX2_SUPPLY_READING1	0x10
#define	EBUS_IDX2_SUPPLY_READING2	0x11
#define	EBUS_IDX2_SUPPLY_READING3	0x12
#define	EBUS_IDX2_SUPPLY_READING4	0x13
#define	EBUS_IDX2_SUPPLY_READING5	0x14
#define	EBUS_IDX2_SUPPLY_READING6	0x15
#define	EBUS_IDX2_SUPPLY_READING7	0x16
#define	EBUS_IDX2_SUPPLY_READING8	0x17
#define	EBUS_IDX2_SUPPLY_READING9	0x18
#define	EBUS_IDX2_SUPPLY_READING10	0x19
#define	EBUS_IDX2_SUPPLY_READING11	0x1a
#define	EBUS_IDX2_SUPPLY_READING12	0x1b
#define	EBUS_IDX2_SUPPLY_READING13	0x1c
#define	EBUS_IDX2_SUPPLY_READING14	0x1d
#define	EBUS_IDX2_SUPPLY_READING15	0x1e
#define	EBUS_IDX2_SUPPLY_READING16	0x1f
#define	EBUS_IDX2_SUPPLY_CAL1		0x20
#define	EBUS_IDX2_SUPPLY_CAL2		0x21
#define	EBUS_IDX2_SUPPLY_CAL3		0x22
#define	EBUS_IDX2_SUPPLY_CAL4		0x23
#define	EBUS_IDX2_SUPPLY_CAL5		0x24
#define	EBUS_IDX2_SUPPLY_CAL6		0x25
#define	EBUS_IDX2_SUPPLY_CAL7		0x26
#define	EBUS_IDX2_SUPPLY_CAL8		0x27
#define	EBUS_IDX2_SUPPLY_CAL9		0x28
#define	EBUS_IDX2_SUPPLY_CAL10		0x29
#define	EBUS_IDX2_SUPPLY_CAL11		0x2a
#define	EBUS_IDX2_SUPPLY_CAL12		0x2b
#define	EBUS_IDX2_SUPPLY_CAL13		0x2c
#define	EBUS_IDX2_SUPPLY_CAL14		0x2d
#define	EBUS_IDX2_SUPPLY_CAL15		0x2e
#define	EBUS_IDX2_SUPPLY_CAL16		0x2f
#define	EBUS_IDX2_SUPPLY_NAME_START	0x40
#define	EBUS_IDX2_SUPPLY_NAME_END	0xff

#define	EBUS_IDX3_BREAKER_ENABLE_MASK	0x01
#define	EBUS_IDX3_BREAKER_NAME_START	0x40
#define	EBUS_IDX3_BREAKER_NAME_END	0xff

#define	EBUS_IDX4_TEMP_ENABLE_MASK	0x01
#define	EBUS_IDX4_OTEMP_ENABLE_MASK	0x02
#define	EBUS_IDX4_TEMP_FATAL_MASK	0x03
#define	EBUS_IDX4_OTEMP_FATAL_MASK	0x04
#define	EBUS_IDX4_TEMP_HYSTERESIS	0x05
#define	EBUS_IDX4_TEMP_FAN_LINK_MASK	0x06
#define	EBUS_IDX4_TEMP_WARN1		0x10	/* Temp warning levels */
#define	EBUS_IDX4_TEMP_WARN2		0x11
#define	EBUS_IDX4_TEMP_WARN3		0x12
#define	EBUS_IDX4_TEMP_WARN4		0x13
#define	EBUS_IDX4_TEMP_WARN5		0x14
#define	EBUS_IDX4_TEMP_WARN6		0x15
#define	EBUS_IDX4_TEMP_WARN7		0x16
#define	EBUS_IDX4_TEMP_WARN8		0x17
#define	EBUS_IDX4_TEMP_SDOWN1		0x18	/* Temp shutdown levels */
#define	EBUS_IDX4_TEMP_SDOWN2		0x19
#define	EBUS_IDX4_TEMP_SDOWN3		0x1a
#define	EBUS_IDX4_TEMP_SDOWN4		0x1b
#define	EBUS_IDX4_TEMP_SDOWN5		0x1c
#define	EBUS_IDX4_TEMP_SDOWN6		0x1d
#define	EBUS_IDX4_TEMP_SDOWN7		0x1e
#define	EBUS_IDX4_TEMP_SDOWN8		0x1f
#define	EBUS_IDX4_TEMP_CORRECT1		0x20	/* Temp warning levels */
#define	EBUS_IDX4_TEMP_CORRECT2		0x21
#define	EBUS_IDX4_TEMP_CORRECT3		0x22
#define	EBUS_IDX4_TEMP_CORRECT4		0x23
#define	EBUS_IDX4_TEMP_CORRECT5		0x24
#define	EBUS_IDX4_TEMP_CORRECT6		0x25
#define	EBUS_IDX4_TEMP_CORRECT7		0x26
#define	EBUS_IDX4_TEMP_CORRECT8		0x27
#define	EBUS_IDX4_TEMP_NAME_START	0x40
#define	EBUS_IDX4_TEMP_NAME_END		0xff

#define	EBUS_IDX5_FAN_ENABLE_CONFIG	0x01
#define	EBUS_IDX5_FAN_NAME_START	0x40
#define	EBUS_IDX5_FAN_NAME_END		0xff

#define	EBUS_IDX10_LED_NAME_START	0x40
#define	EBUS_IDX10_LED_NAME_END		0xff

/*
 * This arrangement for CPU signatures allows only one CPU to generate a
 * CPU Signature at a time.  Since the signature won't fit into one byte
 * it is recommended to datafill the MSB, LSB, STATE, SUBSTATE first, and
 * then write the ID.  A one byte ID limits the number of CPUs to 255.
 * CPU 255 is handled specially; it denotes that the signature applies to
 * "all", or rather "any" CPU ID.
 */

#define	EBUS_ANY_CPU_ID		255

#define	EBUS_IDX11_CPU_ID	0x01	/* CPU with signature pending */
#define	EBUS_IDX11_CPU_SIG_MSB	0x02	/* MSB of sig */
#define	EBUS_IDX11_CPU_SIG_LSB	0x03	/* LSB of sig */
#define	EBUS_IDX11_CPU_STATE	0x04	/* state of sig */
#define	EBUS_IDX11_CPU_SUBSTATE	0x05	/* sub-state of sig */

/*
 * OBP-defined reset reasons.  Solaris never generates these.
 */
#define	EBUS_IDX11_HOST_RESET_REASON	0x07
#define	RESET_REASON_HOST	0x01	/* host reset itself */
#define	RESET_REASON_LOM	0x02	/* lom CLI or SSP request */
#define	RESET_REASON_ASR	0x04	/* watchdog or cpusig timeout */

/*
 * I2C Transfers can be done using the BSC as a proxy.  We transfer data at
 * the conceptual level of struct i2c_transfer defined by the i2c services
 * framework in Solaris.
 */

/*
 * TRANSFER_TYPE mirrors the i2c_transfer.i2c_flags used in Solaris i2c
 * services framework.
 */
#define	EBUS_I2C_WR		0x01 /* write */
#define	EBUS_I2C_RD		0x02 /* read */
#define	EBUS_I2C_WR_RD		0x04 /* write then read */

/*
 * RESULT mirrors the i2c_transfer.i2c_result used the Solaris i2c services
 * framework.
 */
#define	EBUS_I2C_SUCCESS		0x00
#define	EBUS_I2C_FAILURE		0xFF
#define	EBUS_I2C_INCOMPLETE		0xFE


#define	EBUS_IDX12_MAX_TRANSFER_SZ	0x01
#define	EBUS_IDX12_BUS_ADDRESS		0x02
#define	EBUS_IDX12_CLIENT_ADDRESS	0x03
#define	EBUS_IDX12_WR_RD_BOUNDARY	0x04
#define	EBUS_IDX12_TRANSFER_TYPE	0x05
#define	EBUS_IDX12_RESIDUAL_DATA	0x06
#define	EBUS_IDX12_DATA_INOUT		0x07
#define	EBUS_IDX12_RESULT		0x08

#define	EBUS_IDX12_TRANSACTION_LOCK	0x09	/* 1=> lock out i2c devices  */
						/* so multi i2c transactions */
						/* can complete atomically   */

#define	EBUS_PROGRAM_PCSR			0x01
#define	EBUS_PROGRAM_PCR_RSVD			0x00
#define	EBUS_PROGRAM_PCR_READ			0x02
#define	EBUS_PROGRAM_PCR_PRGMODE_ON		0x03
#define	EBUS_PROGRAM_PCR_ERASE			0x04
#define	EBUS_PROGRAM_PCR_PROGRAM		0x05
#define	EBUS_PROGRAM_PCR_PRSVD			0x06
#define	EBUS_PROGRAM_PCR_PRGMODE_OFF		0x07
#define	EBUS_PROGRAM_PCR_PROGOFF_JUMPTOADDR	0x08
#define	EBUS_PROGRAM_PSR_SUCCESS		0x00
#define	EBUS_PROGRAM_PSR_PROGRAM_FAIL		0x01
#define	EBUS_PROGRAM_PSR_ERASE_FAIL		0x02
#define	EBUS_PROGRAM_PSR_INVALID_AREA		0x03
#define	EBUS_PROGRAM_PSR_INCORRECT_CSUM		0x04
#define	EBUS_PROGRAM_PSR_INCORRECT_COUNT	0x05
#define	EBUS_PROGRAM_PSR_INVALID_OPERATION	0x06
#define	EBUS_PROGRAM_PSR_STATUS_MASK		0x7f
#define	EBUS_PROGRAM_PSR_PROG_MODE		0x80
#define	EBUS_PROGRAM_DATA			0x02
#define	EBUS_PROGRAM_PCSM0			0x03 /* MSB of checksum data */
#define	EBUS_PROGRAM_PCSM1			0x04
#define	EBUS_PROGRAM_PADR0			0x05 /* MSB of addr */
#define	EBUS_PROGRAM_PADR1			0x06
#define	EBUS_PROGRAM_PADR2			0x07
#define	EBUS_PROGRAM_PADR3			0x08
#define	EBUS_PROGRAM_PSIZ0			0x09 /* MSB of size */
#define	EBUS_PROGRAM_PSIZ1			0x0a
#define	EBUS_PROGRAM_PSIZ2			0x0b
#define	EBUS_PROGRAM_PSIZ3			0x0c
#define	EBUS_PROGRAM_PAGE0			0x0d /* MSB of ROM page size */
#define	EBUS_PROGRAM_PAGE1			0x0e
#define	EBUS_PROGRAM_PAGE2			0x0f
#define	EBUS_PROGRAM_PAGE3			0x10

/*
 * Command register and codes
 */

#define	EBUS_IDX_CMD_RES	0x00	/* Command/Result register */
#define	EBUS_CMD_CODE_CHK	'C'	/* Recheck alarm conditions */
#define	EBUS_CMD_CODE_CLR	'E'	/* Clear event log */
#define	EBUS_CMD_UNLOCK1	'M'	/* Model Unlock step 1 */
#define	EBUS_CMD_UNLOCK2	'u'	/* Model Unlock step 2 */
#define	EBUS_CMD_POWERINGOFF	'P'	/* host sends before powering off */
#define	EBUS_CMD_RESETTING	'R'	/* host sends before resetting self */
#define	EBUS_CMD_CONLOG_ON	'F'
#define	EBUS_CMD_CONLOG_OFF	'D'
#define	EBUS_CMD_INTERRUPTS_ON  'i'
#define	EBUS_CMD_INTERRUPTS_OFF 'I'
#define	EBUS_CMD_DOG_PAT	'W'	 /* Host pats it's watchdog */
#define	EBUS_CMD_PROG_START	'z'


/*
 * space 11 - CPU signatures and OBP reset information.
 */
#define	EBUS_CMD_SPACE_CPUSIG	0x0b
#define	EBUS_CMD_SPACE_I2C	0x0c	/* space 12 - I2C transfers */
#define	EBUS_CMD_SPACE13	0x0d
#define	EBUS_CMD_SPACE14	0x0e
#define	EBUS_CMD_SPACE15	0x0f

#define	EBUS_MAX_ADDRESS_SPACES 64  /* as defined by the protocol elsewhere */

/*
 * Number of unread events flag
 */
#define	EBUS_EVENT_CNT_CLEAR	0x80	/* Event log cleared since last read */

/*
 * Prom boot mode parameters
 */
#define	EBUS_BOOTMODE_FORCE_CONSOLE	0x01
#define	EBUS_BOOTMODE_FORCE_NOBOOT	0x02
#define	EBUS_BOOTMODE_RESET_DEFAULT	0x04
#define	EBUS_BOOTMODE_FULLDIAG		0x08
#define	EBUS_BOOTMODE_SKIPDIAG		0x10

/*
 * Configuration register
 */
#define	EBUS_CONFIG_NFAN_DEC(n)	(((n)>>5)&0x7)  /* Extract no. of fans */
#define	EBUS_CONFIG_NFAN_ENC(n)	(((n)&0x7)<<5)  /* Insert no. of fans */
#define	EBUS_CONFIG_NPSU_DEC(n)	(((n)>>3)&0x3)  /* Extract no. of PSUs */
#define	EBUS_CONFIG_NPSU_ENC(n)	(((n)&0x3)<<3)  /* Insert no. of PSUs */
#define	EBUS_CONFIG_TTY_CON	0x04	/* Set if TTY/LOM switchable */
#define	EBUS_CONFIG_STEADY_LED	0x02	/* Set to stop LED flashing */
#define	EBUS_CONFIG_USER_LOG	0x01	/* log user operations */

/*
 * Configuration register 2
 */
#define	EBUS_CONFIG2_NTEMP_DEC(n)	(((n)>>4)&0xf)
#define	EBUS_CONFIG2_NTEMP_ENC(n)	(((n)&0xf)<<4)
#define	EBUS_CONFIG2_NSUPPLY_DEC(n)	((n)&0xf)
#define	EBUS_CONFIG2_NSUPPLY_ENC(n)	((n)&0xf)

/*
 * Configuration register 3
 */
#define	EBUS_CONFIG3_NOTEMP_DEC(n)	(((n)>>4)&0xf)
#define	EBUS_CONFIG3_NOTEMP_ENC(n)	(((n)&0xf)<<4)
#define	EBUS_CONFIG3_NBREAKERS_DEC(n)   ((n)&0xf)
#define	EBUS_CONFIG3_NBREAKERS_ENC(n)   ((n)&0xf)

/*
 * Miscellaneous host configuration register
 */
#define	EBUS_CONFIG_MISC_PSUIPFAILEVENTS	0x80
#define	EBUS_CONFIG_MISC_DELAYED_STARTUP	0x40
#define	EBUS_CONFIG_MISC_RANDOM_DELAY		0x20
#define	EBUS_CONFIG_MISC_DECLINE_STARTUP	0x10
#define	EBUS_CONFIG_MISC_ALARM0_ENABLED		0x08
#define	EBUS_CONFIG_MISC_PHONEHOME_ENABLED	0x04
#define	EBUS_CONFIG_MISC_SECURITY_ENABLED	0x02
#define	EBUS_CONFIG_MISC_AUTO_CONSOLE		0x01

/*
 * Alarm control/status register
 */
#define	EBUS_ALARM_LED_DEC(n)	(((n)>>4)&0xf)  /* Extract LED Hz */
#define	EBUS_ALARM_LED_ENC(n)	(((n)&0xf)<<4)  /* Insert LED Hz */
#define	EBUS_ALARM_NOEVENTS	0x08	/* No serial event reports */
#define	EBUS_ALARM_ENABLE3	0x04	/* Alarm 3 enable */
#define	EBUS_ALARM_ENABLE2	0x02	/* Alarm 2 enable */
#define	EBUS_ALARM_ENABLE1	0x01	/* Alarm 1 enable */

/*
 * General Channel Watchdog control
 */
#define	EBUS_WDOG_BREAK_DISABLE	0x10	/* Set if wdog disabled if break seen */
#define	EBUS_WDOG_AL3_FANPSU	0x08	/* Set if fan/PSU errors set AL3 */
#define	EBUS_WDOG_AL3_WDOG	0x04	/* Set if wdog timeouts set AL3 */
#define	EBUS_WDOG_RST		0x02	/* Reset host on expiry */
#define	EBUS_WDOG_ENABLE	0x01	/* Enable host WDOG */

/*
 * Watchdog channel non-blocking byte
 * Top nibble command, bottom nibble data
 */
#define	EBUS_WDOG_NB_PAT		0x00
#define	EBUS_WDOG_NB_PAT_SEQ_MASK	0x0F	/* Sequence number */
#define	EBUS_WDOG_NB_CFG		0x10
#define	EBUS_WDOG_NB_CFG_ENB		0x01	/* enable/disable wdog */

/*
 * PSU status
 */
#define	EBUS_PSU_INPUTA		0x01	/* Input A OK */
#define	EBUS_PSU_INPUTB		0x02	/* Input B OK */
#define	EBUS_PSU_OUTPUT		0x04	/* Output OK */
#define	EBUS_PSU_PRESENT	0x08	/* PSU is present */
#define	EBUS_PSU_STANDBY	0x10	/* PSU is in standby */

/*
 * State change flags
 */
#define	EBUS_STATE_TEMPERATURE  0x80	/* a temperature was exceeded */
#define	EBUS_STATE_RAIL		0x40	/* a supply rail failed */
#define	EBUS_STATE_EVENT	0x20	/* An event has been logged */
#define	EBUS_STATE_CB		0x10	/* A circuit breaker failed */
#define	EBUS_STATE_GP		0x08	/* A GP input has changed */
#define	EBUS_STATE_PSU		0x04	/* A PSU state has changed */
#define	EBUS_STATE_FAN		0x02	/* A fan speed has changed */


/*
 * Bit-0 is overloaded.  It is used by the BSC to notify of a status change
 * The detail field will then be one of EBUS_DETAIL_XXXX.  Otherwise, it's used
 * to indicate that an Alarm state has changed.  The detail field would then
 * be the alarm number.
 */
#define	EBUS_STATE_ALARM	0x01	/* An alarm state has changed */
#define	EBUS_STATE_NOTIFY	0x01	/* BSC state changes */

/*
 * State Notify detail values
 */
#define	EBUS_DETAIL_FLASH	0xff	/* CSSP going to program BSC */
#define	EBUS_DETAIL_RESET	0xfe	/* BSC has been reset */

#define	EBUS_STATE_MASK		0xff	/* All state changes */

/*
 * Alarm config bytes for register $20
 */
#define	ALARM_0			0x01
#define	ALARM_0_ENABLE		0x02

/*
 * Phone home configuration information
 */
#define	PHONEHOME_CONFIG_REG		0x01
#define	PHONEHOME_SCRIPT_START_REG	0x02

#define	PHONEHOME_CONFIG_ON_UNXPOWEROFF	0x01
#define	PHONEHOME_CONFIG_ON_WATCHDOGTRG	0x02
#define	PHONEHOME_CONFIG_ON_DEMAND	0x04

/*
 * CPU type ident codes.  This determines the programming mode.
 */
#define	CPU_IDENT_UNKNOWN		0x80
#define	CPU_IDENT_H8_3434		0x81
#define	CPU_IDENT_H8_3436		0x82
#define	CPU_IDENT_H8_3437		0x83
#define	CPU_IDENT_H8_3437SF		0x84
#define	CPU_IDENT_H8S_2148		0x85
#define	CPU_IDENT_H8S_2148A		0x86
#define	CPU_IDENT_H8S_BSC 		0x87

/*
 * Capability codes
 */
#define	EBUS_CAP0_ASYNC_DOG		0x01 /* EBUS_CMD_DOGPAT implemented */
#define	EBUS_CAP0_SYNC_EVENTS		0x02 /* event report at command end */
#define	EBUS_CAP0_NEW_EVENTLOG_SPACE	0x04 /* new implementation of space8 */
#define	EBUS_CAP0_NEW_SELFTESTS 	0x08 /* new implementation of tests */
#define	EBUS_CAP0_NEW_PROGRAMMING	0x10 /* new flash programming scheme */
#define	EBUS_CAP0_LED_INFORMATION	0x20 /* new LED modelling scheme */
#define	EBUS_CAP0_CPU_SIG		0x40 /* understands CPU signatures */
#define	EBUS_CAP0_I2C_PROXY		0x80 /* implements i2c proxy service */
#define	EBUS_CAP1_H8_SETS_IDX_TIME	0x01 /* H8 writes IDX_TIME values */
#define	EBUS_CAP1_SPACE1_IS_BOOTSCRIPT	0x02 /* SPACE1 used for Boot Script */
#define	EBUS_CAP1_FRUID_OFFSET		0x04 /* i2c reads are already offset */

/*  Error codes as returned via the EBUS interface */

#define	EBUS_ERROR_NONE		0   /* no error occured */
#define	EBUS_ERROR_NOREAD	1   /* this register cannot be read */
#define	EBUS_ERROR_NOWRITE	2   /* this register cannot be written */
#define	EBUS_ERROR_PROTO_CMD	3   /* command sent unexpected */
#define	EBUS_ERROR_PROTO_DATA	4   /* data sent unexpected */
#define	EBUS_ERROR_INVALID_BIT	5   /* invalid bit was set in data passed */
#define	EBUS_ERROR_VALUE_BAD	6   /* data passed was plain bad */
#define	EBUS_ERROR_NOX_SPECCMD	7   /* no such special command exists */
#define	EBUS_ERROR_NOTUNLOCKED	8   /* need model-lock unlocked to do this */
#define	EBUS_ERROR_TIMEOUT	9   /* too long between cmd and data */
#define	EBUS_ERROR_DEVICEFAIL	10  /* Some device (e.g. eeprom) didn't work */
#define	EBUS_ERROR_STALEDATA	11  /* Data has changed - host must reread */
#define	EBUS_ERROR_NOX_DEVICE	12  /* Device doesn't exist */
#define	EBUS_ERROR_RESETNEEDED	13  /* host must reset the LOM */
#define	EBUS_ERROR_PROTO_PARAM	14  /* incorrect parameter count for command */
#define	EBUS_ERROR_PROTO_SEQ	15  /* Sequence number from host incorrect */
#define	EBUS_ERROR_IN_PROG_MODE	16  /* not supported in programming mode */
#define	EBUS_ERROR_NOT_PROG_MODE 17 /* must be in prog mode first */

/* Magic values for specific registers. */
#define	LOM_TEMP_MAX_VALUE		0x7c
#define	LOM_TEMP_STATE_INACCESSIBLE	0x7d /* can't tell - i2c faulted */
#define	LOM_TEMP_STATE_STANDBY		0x7e /* standby mode */
#define	LOM_TEMP_STATE_NOT_PRESENT	0x7f /* not fitted/present */

#define	LOM_FAN_MAX_SPEED	0xfb	/* protects folllowing special cases */
#define	LOM_FAN_RECOUNT		0xfc	/* last access failed */
#define	LOM_FAN_NOACCESS	0xfd	/* can't tell - i2c/lm80 faulted */
#define	LOM_FAN_STANDBY		0xfe	/* standby mode */
#define	LOM_FAN_NOT_PRESENT	0xff	/* no fan fitted */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_LOM_EBUSCODES_H */
