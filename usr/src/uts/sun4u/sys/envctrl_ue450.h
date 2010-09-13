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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_ENVCTRL_UE450_H
#define	_SYS_ENVCTRL_UE450_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * envctrl_ue450.h
 *
 * This header file contains environmental control definitions specific
 * to the UltraEnterprise-450 (aka. Ultra-4) platform.
 */

#define	OVERTEMP_TIMEOUT_USEC	60 * MICROSEC
#define	BLINK_TIMEOUT_USEC	500 * (MICROSEC / MILLISEC)

#define	MAX_TAZ_CONTROLLERS 0x02
#define	ENVCTRL_TAZCPU_STRING	"SUNW,UltraSPARC"
#define	ENVCTRL_TAZBLKBRDCPU_STRING	"SUNW,UltraSPARC-II"

/*
 * MACROS
 */

#define	S1	&unitp->bus_ctl_regs->s1
#define	S0	&unitp->bus_ctl_regs->s0

/*
 * I2c Sensor Types
 */

#define	PCD8584		0x00	/* Bus Controller Master */
#define	PCF8591		0x01	/* Temp Sensor 8bit A/D, D/A */
#define	PCF8574		0x02	/* PS, FAN, LED, Fail and Control */
#define	TDA8444T	0x03	/* Fan Speed Control, 8 bit D/A */
#define	PCF8574A	0x04	/* 8574A chip */
#define	PCF8583		0x05	/* PCF8583 clock chip */

/*
 * Max number of a particular
 * device on 1 bus.
 */
#define	MAX_DEVS	0x10
#define	I2C_NODEV	0xFF
#define	MIN_FAN_BANKS	0x02
#define	INSTANCE_0	0x00

/*
 * Defines for the PCF8583 Clock Calendar Chip
 * We use this chip as a watchdog timer for the fans
 * should the kernel thread controling the fans get
 * wedged. If it does, the alarm wil go off and
 * set the fans to max speed.
 * Valid addresses for this chip are A0, A2.
 * We use the address at A0.
 * To address this chip the format is as folows (write mode)
 * | SLaveaddress |MEMORY LOCATION| DATA|
 * Wgere memory location is the internal location from
 * 0x00 - 0x0F. 0x00 is the CSR and MUST be addressed
 * directly.
 */

#define	PCF8583_BASE_ADDR	0xA0
#define	PCF8583_READ_BIT	0x01

#define	CLOCK_CSR_REG		0x00

#define	ALARM_CTRL_REG		0x07
#define	EGG_TIMER_VAL		0x96
#define	DIAG_MAX_TIMER_VAL	0x00
#define	MAX_CL_VAL		59
#define	MIN_DIAG_TEMPR		0x00
#define	MAX_DIAG_TEMPR		70
#define	MAX_AMB_TEMP		50
#define	MAX_CPU_TEMP		80
#define	MAX_PS_TEMP		100
#define	MAX_PS_ADVAL		0xfd
#define	PS_DEFAULT_VAL		17 /* corresponds to 90 C in lookup table */
#define	PS_TEMP_WARN		95
#define	CPU_AMB_RISE		20 /* cpu runs avg of 20 above amb */
#define	PS_AMB_RISE		30 /* cpu runs avg of 30 above amb */

#define	CLOCK_ALARM_REG_A	0x08
#define	CLOCK_ENABLE_TIMER	0xCB
#define	CLOCK_ENABLE_TIMER_S	0xCA

#define	CLOCK_DISABLE		0xA0
#define	CLOCK_ENABLE		0x04

/* Keyswitch Definitions */
#define	ENVCTRL_FSP_KEYMASK	0xC0
#define	ENVCTRL_FSP_POMASK	0x20
#define	ENVCTRL_FSP_KEYLOCKED	0x00
#define	ENVCTRL_FSP_KEYOFF	0x40
#define	ENVCTRL_FSP_KEYDIAG	0x80
#define	ENVCTRL_FSP_KEYON	0xC0

/* Front Status Panel Definitions */
#define	ENVCTRL_FSP_DISK_ERR	0x01
#define	ENVCTRL_FSP_PS_ERR	0x02
#define	ENVCTRL_FSP_TEMP_ERR	0x04
#define	ENVCTRL_FSP_GEN_ERR	0x08
#define	ENVCTRL_FSP_ACTIVE	0x10
#define	ENVCTRL_FSP_POWER	0x20
#define	ENVCTRL_FSP_USRMASK	(ENVCTRL_FSP_DISK_ERR | ENVCTRL_FSP_GEN_ERR)

#define	ENVCTRL_ENCL_FSP	0x00
#define	ENVCTRL_ENCL_AMBTEMPR	0x01
#define	ENVCTRL_ENCL_CPUTEMPR	0x02
#define	ENVCTRL_ENCL_BACKPLANE4	0x03
#define	ENVCTRL_ENCL_BACKPLANE8	0x04

#define	ENVCTRL_FSP_OFF		0x4F

/*
 * configuration registers
 * Register S1 Looks like the following:
 * WRITE MODE ONLY
 *
 * MSB -------------------------------------> LSB
 * ----------------------------------------------
 * | X | ESO | ES1 | ES2 | ENI | STA | STO | ACK |
 * ----------------------------------------------
 * Low order bits
 */

#define	CSRS1_ENI	0x08	/* Enable interrupts */
#define	CSRS1_STA	0x04	/* Packet Start */
#define	CSRS1_STO	0x02	/* Packet Stop */
#define	CSRS1_ACK	0x01	/* Packet ACK */

/* Hight order bits */
#define	CSRS1_PIN	0x80	/* READ and WRITE mode Enable Serial Output */
#define	CSRS1_ESO	0x40	/* Enable Serial Output */
#define	CSRS1_ES1	0x20
#define	CSRS1_ES2	0x10

/*
 * configuration registers
 * Register S1 Looks like the following:
 * READ MODE ONLY
 *
 * MSB -------------------------------------> LSB
 * ----------------------------------------------
 * | PIN | 0 | STS | BER | AD0/LRB | AAS | LAB | BB|
 * ----------------------------------------------
 */

#define	CSRS1_STS	0x20	/* For Slave receiv mode stop */
#define	CSRS1_BER	0x10	/* Bus Error */

#define	CSRS1_LRB	0x08	/*  Last Received Bit */
#define	CSRS1_AAS	0x04	/*  Addressed as Slave */
#define	CSRS1_LAB	0x02	/*  Lost Arbitration Bit */
#define	CSRS1_BB	0x01	/* Bus Busy */

#define	START	CSRS1_PIN | CSRS1_ESO | CSRS1_STA | CSRS1_ACK
#define	STOP	CSRS1_PIN | CSRS1_ESO | CSRS1_STO | CSRS1_ACK
/*
 * A read wants to have an NACK on the bus to stop
 * transmitting data from the slave. If you don't
 * NACK the SDA line will get stuck low. After this you
 * can send the stop with the ack.
 */
#define	NACK	CSRS1_PIN | CSRS1_ESO

/*
 * ESO = Enable Serial output
 * ES1 and ES2 have different meanings based upon ES0.
 * The following table explains this association.
 *
 * ES0 = 0 = serial interface off.
 * ---------------------------------------------------------
 * | A0 | ES1 | ES1 | iACK | OPERATION
 * ---------------------------------------------------------
 * | H  |  X  |  X  |  X   | Read/write CSR1 (S1) Status n/a
 * |    |     |     |      |
 * | L  |  0  |  0  |  X   | R/W Own Address S0'
 * |    |     |     |      |
 * | L  |  0  |  1  |  X   | R/W Intr Vector S3
 * |    |     |     |      |
 * | L  |  1  |  0  |  X   | R/W Clock Register S2
 * ---------------------------------------------------------
 *
 * ES0 = 1 = serial interface ON.
 * ---------------------------------------------------------
 * | A0 | ES1 | ES1 | iACK | OPERATION
 * ---------------------------------------------------------
 * | H  |  X  |  X  |  H   | Write Control Register (S1)
 * |    |     |     |      |
 * | H  |  X  |  X  |  H   | Read Status Register (S1)
 * |    |     |     |      |
 * | L  |  X  |  0  |  H   | R/W Data Register (S0)
 * |    |     |     |      |
 * | L  |  X  |  1  |  H   | R/W Interrupt Vector (S3)
 * |    |     |     |      |
 * | X  |  0  |  X  |  L   | R Interrupt Vector (S3) ack cycle
 * |    |     |     |      |
 * | X  |  1  |  X  |  L   | long distance mode
 * ---------------------------------------------------------
 *
 */

#ifdef TESTBED
struct envctrl_pcd8584_regs {
	uchar_t s0;		/* Own Address S0' */
	uchar_t pad[3];		/* Padding XXX Will go away in FCS */
	uchar_t s1;		/* Control Status register */
	uchar_t pad1[3];
	uchar_t clock_s2;	/* Clock programming register */
};
#else
struct envctrl_pcd8584_regs {
	uchar_t s0;		/* Own Address S0' */
	uchar_t s1;		/* Control Status register */
	uchar_t clock_s2;	/* Clock programming register */
};
#endif
#define	ENVCTRL_BUS_INIT0	0x80
#define	ENVCTRL_BUS_INIT1	0x55
#define	ENVCTRL_BUS_CLOCK0	0xA0
#define	ENVCTRL_BUS_CLOCK1	0x1C
#define	ENVCTRL_BUS_ESI		0xC1


/*
 * PCF8591 Chip Used for temperature sensors
 *
 * Check with bob to see if singled ended inputs are true
 * for the pcf8591 temp sensors..
 *
 * Addressing Register definition.
 * A0-A2 valid range is 0-7
 *
 *  7    6  5   4    3     2     1      0
 * ------------------------------------------------
 * | 1 | 0 | 0 | 1 | A2 | A1 | A0 | R/W |
 * ------------------------------------------------
 */


#define	PCF8591_BASE_ADDR	0x90
#define	PCF8501_MAX_DEVS	0x08

#define	MAXPS 0x02	/* 0 based array */

#define	PSTEMP0		0x00	/* DUMMY PS */
#define	PSTEMP1		0x94
#define	PSTEMP2		0x92
#define	PSTEMP3		0x90
#define	ENVCTRL_CPU_PCF8591_ADDR (PCF8591_BASE_ADDR | PCF8591_DEV7)

#define	PCF8591_DEV0	0x00
#define	PCF8591_DEV1	0x02
#define	PCF8591_DEV2	0x04
#define	PCF8591_DEV3	0x06
#define	PCF8591_DEV4	0x08
#define	PCF8591_DEV5	0x0A
#define	PCF8591_DEV6    0x0C
#define	PCF8591_DEV7	0x0E


/*
 * For the LM75 thermal watchdog chip by TI
 */

#define	LM75_BASE_ADDR		0x9A
#define	LM75_READ_BIT		0x01
#define	LM75_CONFIG_ADDR2	0x02
#define	LM75_CONFIG_ADDR4	0x04
#define	LM75_CONFIG_ADDR6	0x06
#define	LM75_CONFIG_ADDR8	0x08
#define	LM75_CONFIG_ADDRA	0x0A
#define	LM75_CONFIG_ADDRC	0x0C
#define	LM75_CONFIG_ADDRE	0x0E
#define	LM75_COMP_MASK		0x100
#define	LM75_COMP_MASK_UPPER	0xFF

/*
 * 		CONTROL OF CHIP
 * PCF8591 Temp sensing control register definitions
 *
 *   7      6     5   4  3   2      1   0
 * ---------------------------------------------
 * | 0 | AOE | X | X | 0 | AIF | X | X |
 * ---------------------------------------------
 * AOE = Analog out enable.. not used on out implementation
 * 5 & 4 = Analog Input Programming.. see data sheet for bits..
 *
 * AIF = Auto increment flag
 * bits 1 & 0 are for the Chennel number.
 */

#define	PCF8591_ANALOG_OUTPUT_EN	0x40
#define	PCF8591_ANALOG_INPUT_EN		0x00
#define	PCF8591_READ_BIT		0x01


#define	PCF8591_AUTO_INCR 0x04
#define	PCF8591_OSCILATOR 0x40

#define	PCF8591_MAX_PORTS	0x04

#define	PCF8591_CH_0	0x00
#define	PCF8591_CH_1	0x01
#define	PCF8591_CH_2	0x02
#define	PCF8591_CH_3	0x03

struct envctrl_pcf8591_chip {
	uchar_t chip_num;		/* valid values are 0-7 */
	int type;			/* type is PCF8591 */
	uchar_t	sensor_num;		/* AIN0, AIN1, AIN2 AIN3 */
	uchar_t	temp_val;		/* value of temp probe */
};


/*
 * PCF8574 Fan Fail, Power Supply Fail Detector
 * This device is driven by interrupts. Each time it interrupts
 * you must look at the CSR to see which ports caused the interrupt
 * they are indicated by a 1.
 *
 * Address map of this chip
 *
 * -------------------------------------------
 * | 0 | 1 | 1 | 1 | A2 | A1 | A0 | 0 |
 * -------------------------------------------
 *
 */

#define	PCF8574A_BASE_ADDR	0x70
#define	PCF8574_BASE_ADDR	0x40

#define	PCF8574_READ_BIT	0x01

#define	ENVCTRL_PCF8574_DEV0		0x00
#define	ENVCTRL_PCF8574_DEV1		0x02
#define	ENVCTRL_PCF8574_DEV2		0x04
#define	ENVCTRL_PCF8574_DEV3		0x06
#define	ENVCTRL_PCF8574_DEV4		0x08
#define	ENVCTRL_PCF8574_DEV5		0x0A
#define	ENVCTRL_PCF8574_DEV6		0x0C
#define	ENVCTRL_PCF8574_DEV7		0x0E
#define	ENVCTRL_INTR_CHIP	PCF8574_DEV7

#define	PS1	PCF8574A_BASE_ADDR | ENVCTRL_PCF8574_DEV3
#define	PS2	PCF8574A_BASE_ADDR | ENVCTRL_PCF8574_DEV2
#define	PS3	PCF8574A_BASE_ADDR | ENVCTRL_PCF8574_DEV1

#define	ENVCTRL_PCF8574_PORT0	0x01
#define	ENVCTRL_PCF8574_PORT1	0x02
#define	ENVCTRL_PCF8574_PORT2	0x04
#define	ENVCTRL_PCF8574_PORT3	0x08
#define	ENVCTRL_PCF8574_PORT4	0x10
#define	ENVCTRL_PCF8574_PORT5	0x20
#define	ENVCTRL_PCF8574_PORT6	0x40
#define	ENVCTRL_PCF8574_PORT7	0x80

#define	ENVCTRL_DFLOP_INIT0	0x77
#define	ENVCTRL_DFLOP_INIT1	0x7F

#define	ENVCTRL_DEVINTR_INTI0	0xF7
#define	ENVCTRL_DEVINTR_INTI1	0xFF

#define	CPU_FAN_1		0x01
#define	CPU_FAN_2		0x02
#define	CPU_FAN_3		0x03

#define	PS_FAN_1		CPU_FAN_1
#define	PS_FAN_2		CPU_FAN_2
#define	PS_FAN_3		CPU_FAN_3

#define	AFB_FAN_1		0x00

struct envctrl_pcf8574_chip {
	uchar_t chip_num;		/* valid values are 0-7 */
	int type;			/* type is PCF8574 */
	uint_t	val;
};


/*
 * TDA8444T chip structure
 * FAN Speed Control
 */

/* ADDRESSING */

#define	TDA8444T_BASE_ADDR	0x40


#define	ENVCTRL_TDA8444T_DEV0	0x00
#define	ENVCTRL_TDA8444T_DEV1	0x02
#define	ENVCTRL_TDA8444T_DEV2	0x04
#define	ENVCTRL_TDA8444T_DEV3	0x06
#define	ENVCTRL_TDA8444T_DEV4	0x08
#define	ENVCTRL_TDA8444T_DEV5	0x0A
#define	ENVCTRL_TDA8444T_DEV6	0x0C
#define	ENVCTRL_TDA8444T_DEV7	0x0E

#define	ENVCTRL_FAN_ADDR_MIN	ENVCTRL_TDA8444T_DEV0
#define	ENVCTRL_FAN_ADDR_MAX	ENVCTRL_TDA8444T_DEV7

/* Control information and port addressing */

#define	NO_AUTO_PORT_INCR	0xF0
#define	AUTO_PORT_INCR		0x00
#define	TDA8444T_READ_BIT	0x01

#define	ENVCTRL_CPU_FANS	0x00
#define	ENVCTRL_PS_FANS		0x01
#define	ENVCTRL_AFB_FANS	0x02

#define	MAX_FAN_SPEED	0x3f
#define	MIN_FAN_VAL	0x00
#define	MAX_FAN_VAL	0x3f
#define	AFB_MAX		0x3f
#define	AFB_MIN		0x1d

struct envctrl_tda8444t_chip {
	uchar_t chip_num;		/* valid values are 0-7 */
	int type;			/* type is TDA8444T */
	uchar_t	fan_num;		/* Ao0-Ao7 */
	uchar_t	val;			/* for fan speed */
};

/*
 * This table converts an A/D value from the cpu thermistor to a
 * temperature in degrees C. Usable range is typically 35-135.
 */

static short cpu_temps[] = {
150,	150,	150,	150,	150,	150,	150,	150,	/* 0-7 */
150,	150,	150,	150,	150,	150,	150,	150,	/* 8-15 */
150,	150,	150,	150,	150,	150,	150,	150,	/* 16-23 */
150,	150,	150,	148,	146,	144,	143,	142,	/* 24-31 */
141,	140,	138,	136,	135,	134,	133,	132,	/* 32-39 */
131,	130,	129,	128,	127,	126,	125,	124,	/* 40-47 */
123,	122,	121,	121,	120,	120,	119,	118,	/* 48-55 */
117,	116,	115,	114,	113,	112,	112,	111,	/* 56-63 */
111,	110,	110,	110,	109,	109,	108,	107,	/* 64-71 */
106,	106,	105,	105,	104,	103,	102,	101,	/* 72-79 */
101,	100,	100,	100,	99,	99,	98,	98,	/* 80-87 */
97,	97,	96,	96,	95,	95,	94,	94,	/* 88-95 */
93,	93,	92,	92,	91,	91,	91,	90,	/* 96-103 */
90,	90,	89,	89,	88,	88,	87,	87,	/* 104-111 */
86,	86,	85,	85,	84,	84,	83,	83,	/* 112-119 */
82,	82,	82,	81,	81,	80,	80,	80,	/* 120-127 */
80,	79,	79,	79,	78,	78,	78,	77,	/* 128-135 */
77,	77,	76,	76,	76,	75,	75,	75,	/* 136-143 */
74,	74,	74,	73,	73,	73,	72,	72,	/* 144-151 */
72,	71,	71,	71,	70,	70,	70,	70,	/* 142-159 */
69,	69,	69,	68,	68,	68,	68,	67,	/* 160-167 */
67,	67,	67,	66,	66,	66,	66,	65,	/* 168-175 */
65,	65,	64,	64,	64,	63,	63,	63,	/* 176-183 */
62,	62,	62,	61,	61,	61,	61,	60,	/* 184-191 */
60,	60,	60,	59,	59,	59,	58,	58,	/* 192-199 */
58,	57,	57,	57,	56,	56,	56,	56,	/* 200-207 */
55,	55,	55,	55,	54,	54,	54,	53,	/* 208-215 */
53,	53,	52,	52,	52,	51,	51,	51,	/* 216-223 */
51,	50,	50,	50,	49,	49,	49,	48,	/* 224-231 */
48,	48,	47,	47,	47,	46,	46,	46,	/* 232-239 */
45,	45,	45,	44,	44,	44,	43,	43,	/* 240-247 */
43,	42,	42,	42,	41,	41,	41,	40,	/* 248-255 */
40,								/* 256 */
};

static short ps_temps[] = {
160,	155,	154,	150,	130,	125,	120,	115,	/* 0-7 */
110,	110,	106,	103,	101,	100,	97,	94,	/* 8-15 */
92,	90,	88,	86,	84,	83,	82,	81,	/* 16-23 */
80,	79,	78,	77,	76,	74,	72,	71,	/* 24-31 */
70,	69,	68,	67,	66,	65,	64,	63,	/* 32-39 */
62,	62,	61,	61,	60,	60,	60,	59,	/* 40-47 */
59,	58,	58,	57,	56,	56,	55,	55,	/* 48-55 */
54,	54,	53,	53,	52,	52,	51,	51,	/* 56-63 */
50,	50,	50,	49,	49,	49,	49,	48,	/* 64-71 */
48,	48,	48,	47,	47,	47,	47,	46,	/* 72-79 */
46,	46,	45,	44,	43,	42,	41,	41,	/* 80-87 */
40,	40,	40,	40,	39,	39,	39,	38,	/* 88-95 */
38,	38,	37,	37,	36,	36,	36,	35,	/* 96-103 */
35,	35,	35,	34,	34,	34,	33,	33,	/* 104-111 */
32,	32,	32,	32,	32,	32,	31,	31,	/* 112-119 */
31,	31,	31,	30,	30,	30,	29,	29,	/* 120-127 */
29,	29,	29,	29,	28,	28,	28,	28,	/* 128-135 */
28,	28,	27,	27,	27,	27,	27,	26,	/* 136-143 */
26,	26,	26,	26,	26,	26,	26,	26,	/* 144-151 */
25,	25,	25,	25,	24,	24,	23,	23,	/* 142-159 */
22,	22,	21,	21,	21,	21,	21,	21,	/* 160-167 */
20,	20,	20,	20,	19,	19,	19,	19,	/* 168-175 */
19,	18,	18,	18,	18,	18,	17,	17,	/* 176-183 */
17,	17,	17,	16,	16,	16,	16,	15,	/* 184-191 */
15,	15,	15,	15,	15,	14,	14,	14,	/* 192-199 */
14,	14,	13,	13,	13,	13,	12,	12,	/* 200-207 */
12,	12,	12,	11,	11,	11,	11,	11,	/* 208-215 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 216-223 */
9,	9,	9,	9,	9,	9,	8,	8,	/* 224-231 */
8,	8,	8,	7,	7,	7,	7,	7,	/* 232-239 */
7,	6,	6,	6,	6,	6,	6,	6,	/* 240-247 */
5,	5,	5,	5,	5,	5,	5,	4,	/* 248-255 */
4,								/* 256 */
};

/*
 * This is the lookup table used for P1 and FCS systems to convert a temperature
 * to a fanspeed for the CPU side of the machine.
 */

static short acme_cpu_fanspd[] = {
31,	31,	31,	31,	31,	31,	31,	31,	/* 0-7 */
31,	31,	31,	31,	31,	31,	31,	31,	/* 8-15 */
31,	31,	31,	31,	31,	31,	31,	31,	/* 16-23 */
31,	31,	31,	31,	32,	33,	34,	35,	/* 24-31 */
36,	37,	38,	39,	40,	42,	43,	45,	/* 32-39 */
48,	49,	50,	51,	52,	53,	54,	55,	/* 40-47 */
56,	57,	58,	59,	60,	61,	62,	63,	/* 48-55 */
63,	63,	63,	63,	63,	63,	63,	63,	/* 56-63 */
63,	63,	63,	63,	63,	63,	63,	63,	/* 64-71 */
63,	63,	63,	63,	63,	63,	63,	63,	/* 72-79 */
63,	63,	63,	63,	63,	63,	63,	63,	/* 80-87 */
63,	63,	63,	63,	63,	63,	63,	63,	/* 88-95 */
63,	63,	63,	63,	63,	63,	63,	63,	/* 96-103 */
63,	63,	63,	63,	63,	63,	63,	63,	/* 104-111 */
};

/*
 * This is the lookup table used for P1 and FCS systems to convert a temperature
 * to a fanspeed for the CPU side of the machine.
 */

static short acme_ps_fanspd[] = {
31,	31,	31,	31,	31,	31,	31,	31,	/* 0-7 */
31,	31,	31,	31,	31,	31,	31,	31,	/* 8-15 */
31,	31,	31,	31,	31,	31,	31,	31,	/* 16-23 */
31,	31,	31,	31,	31,	33,	34,	35,	/* 24-31 */
36,	37,	38,	38,	39,	40,	41,	42,	/* 32-39 */
43,	45,	46,	47,	48,	48,	48,	48,	/* 40-47 */
48,	48,	49,	50,	51,	52,	53,	54,	/* 48-55 */
55,	56,	57,	58,	59,	60,	61,	62,	/* 56-63 */
63,	63,	63,	63,	63,	63,	63,	63,	/* 64-71 */
63,	63,	63,	63,	63,	63,	63,	63,	/* 72-79 */
63,	63,	63,	63,	63,	63,	63,	63,	/* 80-87 */
63,	63,	63,	63,	63,	63,	63,	63,	/* 88-95 */
63,	63,	63,	63,	63,	63,	63,	63,	/* 96-103 */
63,	63,	63,	63,	63,	63,	63,	63,	/* 104-111 */
};

static short ps_fans[] = {
10,	10,	10,	10,	10,	10,	10,	10,	/* 0-7 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 8-15 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 16-23 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 24-31 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 32-39 */
11,	12,	13,	14,	15,	16,	17,	18,	/* 24-31 */
19,	20,	21,	22,	23,	24,	25,	26,	/* 32-39 */
27,	28,	29,	30,	31,	32,	33,	34,	/* 40-47 */
35,	36,	37,	38,	39,	40,	41,	42,	/* 48-55 */
43,	44,	45,	46,	47,	48,	49,	50,	/* 56-63 */
50,	50,	50,	50,	50,	50,	50,	50,	/* 56-63 */
13,	12,	11,	10,	10,	10,	10,	10,	/* 64-71 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,	10,	10,	10,	10,	10,	10,	10,	/* 72-79 */
10,
};

/*
 * Get a fan speed setting based upon a temperature value
 * from the above lookup tables.
 * Less than zero ia a special case and greater than 70 is a
 * the operating range of the powersupply. The system operating
 * range is 5 - 40 Degrees C.
 * This may need some tuning.
 * The MAX_CPU_TEMP is set to 80 now, this table is used to set their
 * fans.
 */
static short fan_speed[] = {
30,	29,	28,	27,	26,	25,	24,	23,	/* 0-7 */
23,	23,	23,	23,	22,	21,	20,	20,	/* 8-15 */
20,	20,	20,	20,	20,	20,	20,	20,	/* 16-23 */
19,	18,	17,	16,	15,	14,	13,	12,	/* 24-31 */
11,	11,	11,	11,	11,	11,	11,	11,	/* 32-39 */
11,	11,	11,	10,	10,	10,	9,	8,	/* 40-47 */
7,	6,	5,	4,	3,	2,	1,	1,	/* 48-55 */
1,	1,	1,	1,	1,	1,	1,	1,	/* 56-63 */
1,	1,	1,	1,	1,	1,	1,	1,	/* 64-71 */
1,	1,	1,	1,	1,	1,	1,	1,	/* 72-79 */
1,	1,	1,	1,	1,	1,	1,	1,	/* 80-87 */
};


#if defined(_KERNEL)

struct envctrlunit {
	struct envctrl_pcd8584_regs *bus_ctl_regs;
	ddi_acc_handle_t ctlr_handle;
	kmutex_t umutex;			/* lock for this structure */
	int instance;
	dev_info_t *dip;			/* device information */
	struct envctrl_ps ps_kstats[MAX_DEVS];	/* kstats for powersupplies */
	struct envctrl_fan fan_kstats[MAX_DEVS]; /* kstats for fans */
	struct envctrl_encl encl_kstats[MAX_DEVS]; /* kstats for enclosure */
	int cpu_pr_location[ENVCTRL_MAX_CPUS]; /* slot true if cpu present */
	uint_t num_fans_present;
	uint_t num_ps_present;
	uint_t num_encl_present;
	uint_t num_cpus_present;
	kstat_t *psksp;
	kstat_t *fanksp;
	kstat_t *enclksp;
	ddi_iblock_cookie_t ic_trap_cookie;	/* interrupt cookie */
	queue_t		*readq;		/* pointer to readq */
	queue_t		*writeq;	/* pointer to writeq */
	mblk_t	*msg;			/* current message block */
	/*  CPR support */
	boolean_t suspended;			/* TRUE if driver suspended */
	boolean_t oflag;			/*  already open */
	int current_mode;			/* NORMAL or DIAG_MODE */
	int AFB_present;			/* is the AFB present */
	timeout_id_t timeout_id;				/* timeout id */
	timeout_id_t pshotplug_id;			/* ps poll id */
	int ps_present[MAXPS+1];		/* PS present t/f 0 not used */
	int num_fans_failed;	/* don't change fan speed if > 0 */
	int activity_led_blink;
	int present_led_state; /* is it on or off?? */
	timeout_id_t blink_timeout_id;
	int initting; /* 1 is TRUE , 0 is FALSE , used to mask intrs */
	boolean_t shutdown; /* TRUE = power off in error event */

};

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ENVCTRL_UE450_H */
