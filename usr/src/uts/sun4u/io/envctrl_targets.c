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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Low level environmental control routines.
 * These routines implement the I2C bus protocol.
 */

#define	EHC_SUCCESS 0
#define	EHC_FAILURE (-1)
#define	EHC_NO_SLAVE_ACK 3

#define	EHC_MAX_WAIT 100 /* decimal */

#define	EHC_S1_PIN 0x80
#define	EHC_S1_ES1 0x20
#define	EHC_S1_ES0 0x40
#define	EHC_S1_NBB 0x01
#define	EHC_S1_ACK 0x01
#define	EHC_S1_STA 0x04
#define	EHC_S1_STO 0x02
#define	EHC_S1_LRB 0x08
#define	EHC_S1_BER 0x10
#define	EHC_S1_LAB 0x02
#define	EHC_S1_AAS 0x04
#define	EHC_S1_AD0 0x08
#define	EHC_S1_STS 0x20

#define	EHC_S0_OWN 0x55
#define	EHC_S0_CLK 0x1d

#define	EHC_BYTE_READ 0x01

#define	EHC_LONGEST_MSG 200000 /* 200 ms */

#define	DUMMY_WRITE_ADDR 0x20
#define	DUMMY_WRITE_DATA 0x00

/*
 * PCF8591 Chip Used for temperature sensors
 *
 * Addressing Register definition.
 * A0-A2 valid range is 0-7
 *
 * ------------------------------------------------
 * | 1 | 0 | 0 | 1 | A2 | A1 | A0 | R/W |
 * ------------------------------------------------
 */


#define	EHC_PCF8591_MAX_DEVS	0x08

#define	EHC_DEV0	0x00
#define	EHC_DEV1	0x02
#define	EHC_DEV2	0x04
#define	EHC_DEV3	0x06
#define	EHC_DEV4	0x08
#define	EHC_DEV5	0x0A
#define	EHC_DEV6    	0x0C
#define	EHC_DEV7	0x0E


/*
 * 		CONTROL OF CHIP
 * PCF8591 Temp sensing control register definitions
 *
 * ---------------------------------------------
 * | 0 | AOE | X | X | 0 | AIF | X | X |
 * ---------------------------------------------
 * AOE = Analog out enable.. not used on out implementation
 * 5 & 4 = Analog Input Programming.. see data sheet for bits..
 *
 * AIF = Auto increment flag
 * bits 1 & 0 are for the Chennel number.
 */

#define	EHC_PCF8591_ANALOG_OUTPUT_EN	0x40
#define	EHC_PCF8591_ANALOG_INPUT_EN	0x00
#define	EHC_PCF8591_READ_BIT		0x01


#define	EHC_PCF8591_AUTO_INCR 0x04
#define	EHC_PCF8591_OSCILATOR 0x40

#define	EHC_PCF8591_MAX_PORTS	0x04

#define	EHC_PCF8591_CH_0	0x00
#define	EHC_PCF8591_CH_1	0x01
#define	EHC_PCF8591_CH_2	0x02
#define	EHC_PCF8591_CH_3	0x03


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

#define	EHC_PCF8574_PORT0	0x01
#define	EHC_PCF8574_PORT1	0x02
#define	EHC_PCF8574_PORT2	0x04
#define	EHC_PCF8574_PORT3	0x08
#define	EHC_PCF8574_PORT4	0x10
#define	EHC_PCF8574_PORT5	0x20
#define	EHC_PCF8574_PORT6	0x40
#define	EHC_PCF8574_PORT7	0x80

/*
 * Defines for the PCF8583 Clock Calendar Chip.
 */
#define	EHC_PCF8583_READ_BIT	0x01

struct ehc_pcd8584_regs {
	uint8_t s0;		/* Own Address S0' */
	uint8_t s1;		/* Control Status register */
	uint8_t clock_s2;	/* Clock programming register */
};

struct ehc_envcunit {
	struct ehc_pcd8584_regs *bus_ctl_regs;
	ddi_acc_handle_t ctlr_handle;
	kmutex_t umutex;
};

int ehc_debug = 0;

#define	DCMN_ERR if (ehc_debug & 0x1) cmn_err
#define	DCMN2_ERR if (ehc_debug & 0x2) cmn_err

/*
 * Prototypes for routines used in other modules.
 */

void ehc_init_pcf8584(struct ehc_envcunit *);
int ehc_read_tda8444(struct ehc_envcunit *ehcp);
int ehc_write_tda8444(struct ehc_envcunit *, int, int, int, uint8_t *, int);
int ehc_write_pcf8591(struct ehc_envcunit *, int, int, int, int, int,
	uint8_t *, int);
int ehc_read_pcf8591(struct ehc_envcunit *, int, int, int, int, int,
	uint8_t *, int);
int ehc_read_pcf8574a(struct ehc_envcunit *, int, uint8_t *, int);
int ehc_write_pcf8574a(struct ehc_envcunit *, int, uint8_t *, int);
int ehc_read_pcf8574(struct ehc_envcunit *, int, uint8_t *, int);
int ehc_write_pcf8574(struct ehc_envcunit *, int, uint8_t *, int);
int ehc_read_lm75(struct ehc_envcunit *, int, uint8_t *, int);
int ehc_write_pcf8583(struct ehc_envcunit *, int, uint8_t *, int);

/*
 * Prototypes for routines used only in this source module.
 */

static int ehc_start_pcf8584(struct ehc_envcunit *, uint8_t);
static void ehc_stop_pcf8584(struct ehc_envcunit *);
static int ehc_read_pcf8584(struct ehc_envcunit *, uint8_t *);
static int ehc_write_pcf8584(struct ehc_envcunit *, uint8_t);
static int ehc_after_read_pcf8584(struct ehc_envcunit *, uint8_t *);

/*
 * put host interface into master mode
 */
static int
ehc_start_pcf8584(struct ehc_envcunit *ehcp, uint8_t byteaddress)
{
	uint8_t poll_status;
	uint8_t discard;
	int i;

	/* wait if bus is busy */

	i = 0;
	do {
		drv_usecwait(1000);
		poll_status =
			ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1);
		i++;
	} while (((poll_status & EHC_S1_NBB) == 0) && i < EHC_MAX_WAIT);

	if (i == EHC_MAX_WAIT) {
		DCMN_ERR(CE_WARN, "ehc_start_pcf8584(): busy bit clear failed");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_BER) {
		DCMN2_ERR(CE_WARN, "ehc_start_pcf8584()1: Bus error");
		ehc_init_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_LAB) {
		DCMN2_ERR(CE_WARN, "ehc_start_pcf8584()1: Lost Arbitration");
		ehc_init_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	/*
	 * This is a dummy arbitration using the lowest unused address
	 * possible. This step allows the PCF8584 to always win arbitration
	 * except in the case of "general call" being issued by the other
	 * master.
	 */
	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0, DUMMY_WRITE_ADDR);

	/* generate the "start condition" and clock out the slave address */
	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1,
		EHC_S1_PIN | EHC_S1_ES0 | EHC_S1_STA | EHC_S1_ACK);

	/* wait for completion of transmission */
	i = 0;
	do {
		drv_usecwait(1000);
		poll_status =
			ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1);
		i++;
	} while ((poll_status & EHC_S1_PIN) && i < EHC_MAX_WAIT);

	if (i == EHC_MAX_WAIT) {
		DCMN_ERR(CE_WARN, "ehc_start_pcf8584_5(): read of S1 failed");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_BER) {
		DCMN2_ERR(CE_WARN, "ehc_start_pcf8584()5: Bus error");
		ehc_init_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_LAB) {
		DCMN2_ERR(CE_WARN, "ehc_start_pcf8584()5: Lost Arbitration");
		ehc_init_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	/* dummy write */
	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0, DUMMY_WRITE_DATA);

	/* wait for completion of transmission */
	i = 0;
	do {
		drv_usecwait(1000);
		poll_status =
			ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1);
		i++;
	} while ((poll_status & EHC_S1_PIN) && i < EHC_MAX_WAIT);

	if (i == EHC_MAX_WAIT) {
		DCMN_ERR(CE_WARN, "ehc_start_pcf8584(): read of S1 failed");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_BER) {
		DCMN2_ERR(CE_WARN, "ehc_start_pcf8584()4: Bus error");
		ehc_init_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_LAB) {
		DCMN2_ERR(CE_WARN, "ehc_start_pcf8584()4: Lost Arbitration");
		ehc_init_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	/*
	 * generate the repeated "start condition" and
	 * clock out the slave address
	 */
	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1,
		EHC_S1_ES0 | EHC_S1_STA | EHC_S1_ACK);

	/* load the slave address */
	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0, byteaddress);

	/* wait for completion of transmission */
	i = 0;
	do {
		drv_usecwait(1000);
		poll_status =
			ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1);
		i++;
	} while ((poll_status & EHC_S1_PIN) && i < EHC_MAX_WAIT);

	if (i == EHC_MAX_WAIT) {
		DCMN_ERR(CE_WARN, "ehc_start_pcf8584(): read of S1 failed");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_BER) {
		DCMN2_ERR(CE_WARN, "ehc_start_pcf8584()2: Bus error");
		ehc_init_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_LAB) {
		DCMN2_ERR(CE_WARN, "ehc_start_pcf8584()2: Lost Arbitration");
		ehc_init_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_LRB) {
		DCMN_ERR(CE_WARN, "ehc_start_pcf8584(): No slave ACK");
		return (EHC_NO_SLAVE_ACK);
	}

	/*
	 * If this is a read we are setting up for (as indicated by
	 * the least significant byte being set), read
	 * and discard the first byte off the bus - this
	 * is the slave address.
	 */

	i = 0;
	if (byteaddress & EHC_BYTE_READ) {
		discard = ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0);
#ifdef lint
		discard = discard;
#endif

		/* wait for completion of transmission */
		do {
			drv_usecwait(1000);
			poll_status =
			ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1);
			i++;
		} while ((poll_status & EHC_S1_PIN) && i < EHC_MAX_WAIT);

		if (i == EHC_MAX_WAIT) {
			DCMN_ERR(CE_WARN,
				"ehc_start_pcf8584(): read of S1 failed");
			return (EHC_FAILURE);
		}

		if (poll_status & EHC_S1_BER) {
			DCMN2_ERR(CE_WARN, "ehc_start_pcf8584()3: Bus error");
			ehc_init_pcf8584(ehcp);
			return (EHC_FAILURE);
		}
		if (poll_status & EHC_S1_LAB) {
			DCMN2_ERR(CE_WARN,
				"ehc_start_pcf8584()3: Lost Arbitration");
			ehc_init_pcf8584(ehcp);
			return (EHC_FAILURE);
		}

	}

	return (EHC_SUCCESS);
}

/*
 * put host interface into slave/receiver mode
 */
static void
ehc_stop_pcf8584(struct ehc_envcunit *ehcp)
{
	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1,
		EHC_S1_PIN | EHC_S1_ES0 | EHC_S1_STO | EHC_S1_ACK);
}

static int
ehc_read_pcf8584(struct ehc_envcunit *ehcp, uint8_t *data)
{
	uint8_t poll_status;
	int i = 0;

	/* Read the byte of interest */
	*data = ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0);

	/* wait for completion of transmission */
	do {
		drv_usecwait(1000);
		poll_status =
			ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1);
		i++;
	} while ((poll_status & EHC_S1_PIN) && i < EHC_MAX_WAIT);

	if (i == EHC_MAX_WAIT) {
		DCMN_ERR(CE_WARN, "ehc_read_pcf8584(): read of S1 failed");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_BER) {
		DCMN2_ERR(CE_WARN, "ehc_read_pcf8584(): Bus error");
		ehc_init_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_LAB) {
		DCMN2_ERR(CE_WARN, "ehc_read_pcf8584(): Lost Arbitration");
		ehc_init_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	return (EHC_SUCCESS);
}

/*
 * host interface is in transmitter state, thus mode is master/transmitter
 * NOTE to Bill: this check the LRB bit (only done in transmit mode).
 */

static int
ehc_write_pcf8584(struct ehc_envcunit *ehcp, uint8_t data)
{
	uint8_t poll_status;
	int i = 0;

	/* send the data, EHC_S1_PIN should go to "1" immediately */
	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0, data);

	/* wait for completion of transmission */
	do {
		drv_usecwait(1000);
		poll_status =
			ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1);
		i++;
	} while ((poll_status & EHC_S1_PIN) && i < EHC_MAX_WAIT);

	if (i == EHC_MAX_WAIT) {
		DCMN_ERR(CE_WARN, "ehc_write_pcf8584(): read of S1 failed");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_BER) {
		DCMN2_ERR(CE_WARN, "ehc_write_pcf8584(): Bus error");
		ehc_init_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_LAB) {
		DCMN2_ERR(CE_WARN, "ehc_write_pcf8584(): Lost Arbitration");
		ehc_init_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_LRB) {
		DCMN_ERR(CE_WARN, "ehc_write_pcf8584(): No slave ACK");
		return (EHC_NO_SLAVE_ACK);
	}

	return (EHC_SUCCESS);
}

static int
ehc_after_read_pcf8584(struct ehc_envcunit *ehcp, uint8_t *data)
{
	uint8_t discard;
	uint8_t poll_status;
	int i = 0;

	/* set ACK in register S1 to 0 */
	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1, EHC_S1_ES0);

	/*
	 * Read the "byte-before-the-last-byte" - sets PIN bit to '1'
	 */

	*data = ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0);

	/* wait for completion of transmission */
	do {
		drv_usecwait(1000);
		poll_status =
			ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1);
		i++;
	} while ((poll_status & EHC_S1_PIN) && i < EHC_MAX_WAIT);

	if (i == EHC_MAX_WAIT) {
		DCMN_ERR(CE_WARN, "ehc_after_rd_pcf8584(): read of S1 failed");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_BER) {
		DCMN2_ERR(CE_WARN, "ehc_after_rd_pcf8584(): Bus error");
		ehc_init_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_LAB) {
		DCMN2_ERR(CE_WARN, "ehc_after_rd_pcf8584(): Lost Arbitration");
		ehc_init_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	/*
	 * Generate the "stop" condition.
	 */
	ehc_stop_pcf8584(ehcp);

	/*
	 * Read the "last" byte.
	 */
	discard = ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0);
#ifdef lint
	discard = discard;
#endif

	return (EHC_SUCCESS);
}

/*
 * Below this comment are the externally visible routines comprising the API
 */

/*
 * Initialize the 8584 chip
 */

void
ehc_init_pcf8584(struct ehc_envcunit *ehcp)
{
	/*
	 * Writing PIN bit of S1 causes software reset.
	 * The next write to S0 will be S0' "own address".
	 */

	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1, EHC_S1_PIN);

	/*
	 * Write the address which the controller chip will use
	 * (when addressed as a slave) on the I2C bus.
	 * DAF - should own address be passed as argument?
	 */

	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0, EHC_S0_OWN);

	/*
	 * Writing PIN bit and ES1 bit of S1 causes software
	 * reset and selects the S2 register for writing.
	 * Now, the next write to S0 will be the S2 clock
	 * control register.
	 */

	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1,
		EHC_S1_PIN | EHC_S1_ES1);

	/*
	 * Write the value into register that sets internal system clock
	 * to 12 Mhz, and the I2C bus rate (SCL) to 9 Khz.
	 * DAF - should these be parameters?
	 */

	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0, EHC_S0_CLK);

	/*
	 * Writing PIN bit causes software reset and the ES0 bit
	 * selects the (S0) register for reading/writing.  The ACK
	 * bit being set causes controller to send ACK after each
	 * byte.
	 */

	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1,
		EHC_S1_PIN | EHC_S1_ES0 | EHC_S1_ACK);

	/*
	 * Multi-Master: Wait for a period of time equal to the
	 * longest I2C message.  This accounts for the case
	 * where multiple controllers and, if this particular one
	 * is "lagging", misses the BB (bus busy) condition.
	 * DAF - What does this need?
	 * We wait 200 ms since the longest transaction at this time
	 * on the i2c bus is a 256 byte read from the seprom which takes
	 * about 75 ms. Some additional buffer does no harm to the driver.
	 */

	drv_usecwait(EHC_LONGEST_MSG);

}

int
ehc_read_tda8444(struct ehc_envcunit *ehcp)
{
#ifdef lint
	ehcp = ehcp;
#endif
	return (EHC_FAILURE);
}

/*
 * Write to the TDA8444 chip.
 * byteaddress = chip type base address | chip offset address.
 */
int
ehc_write_tda8444(struct ehc_envcunit *ehcp, int byteaddress, int instruction,
	int subaddress, uint8_t *buf, int size)
{
	uint8_t control;
	int i, status;

	ASSERT((byteaddress & 0x1) == 0);
	ASSERT(subaddress < 8);
	ASSERT(instruction == 0xf || instruction == 0x0);
	ASSERT(MUTEX_HELD(&ehcp->umutex));

	control = (instruction << 4) | subaddress;

	if ((status = ehc_start_pcf8584(ehcp, byteaddress)) != EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			/*
			 * Send the "stop" condition.
			 */
			ehc_stop_pcf8584(ehcp);
		}
		return (EHC_FAILURE);
	}

	if ((status = ehc_write_pcf8584(ehcp, control)) != EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			/*
			 * Send the "stop" condition.
			 */
			ehc_stop_pcf8584(ehcp);
		}
		return (EHC_FAILURE);
	}

	for (i = 0; i < size; i++) {
		if ((status = ehc_write_pcf8584(ehcp, (buf[i] & 0x3f))) !=
			EHC_SUCCESS) {
			if (status == EHC_NO_SLAVE_ACK)
				ehc_stop_pcf8584(ehcp);
			return (EHC_FAILURE);
		}
	}

	ehc_stop_pcf8584(ehcp);

	return (EHC_SUCCESS);
}

/*
 * Read from PCF8574A chip.
 * byteaddress = chip type base address | chip offset address.
 */
int
ehc_read_pcf8574a(struct ehc_envcunit *ehcp, int byteaddress, uint8_t *buf,
	int size)
{
	int i;
	int status;
	uint8_t discard;

	ASSERT((byteaddress & 0x1) == 0);
	ASSERT(MUTEX_HELD(&ehcp->umutex));

	/*
	 * Put the bus into the start condition
	 */
	if ((status = ehc_start_pcf8584(ehcp, EHC_BYTE_READ | byteaddress)) !=
			EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			/*
			 * Send the "stop" condition.
			 */
			ehc_stop_pcf8584(ehcp);
			/*
			 * Read the last byte - discard it.
			 */
			discard =
			ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0);
#ifdef lint
			discard = discard;
#endif
		}
		return (EHC_FAILURE);
	}

	for (i = 0; i < size - 1; i++) {
		if ((status = ehc_read_pcf8584(ehcp, &buf[i])) != EHC_SUCCESS) {
			return (EHC_FAILURE);
		}
	}

	/*
	 * Handle the part of the bus protocol which comes
	 * after a read, including reading the last byte.
	 */

	if (ehc_after_read_pcf8584(ehcp, &buf[i]) != EHC_SUCCESS) {
		return (EHC_FAILURE);
	}

	return (EHC_SUCCESS);
}

/*
 * Write to the PCF8574A chip.
 * byteaddress = chip type base address | chip offset address.
 */
int
ehc_write_pcf8574a(struct ehc_envcunit *ehcp, int byteaddress, uint8_t *buf,
	int size)
{
	int i;
	int status;

	ASSERT((byteaddress & 0x1) == 0);
	ASSERT(MUTEX_HELD(&ehcp->umutex));

	/*
	 * Put the bus into the start condition (write)
	 */
	if ((status = ehc_start_pcf8584(ehcp, byteaddress)) != EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			/*
			 * Send the "stop" condition.
			 */
			ehc_stop_pcf8584(ehcp);
		}
		return (EHC_FAILURE);
	}

	/*
	 * Send the data - poll as needed.
	 */
	for (i = 0; i < size; i++) {
		if ((status = ehc_write_pcf8584(ehcp, buf[i])) != EHC_SUCCESS) {
			if (status == EHC_NO_SLAVE_ACK)
				ehc_stop_pcf8584(ehcp);
			return (EHC_FAILURE);
		}
	}

	/*
	 * Transmission complete - generate stop condition and
	 * put device back into slave receiver mode.
	 */
	ehc_stop_pcf8584(ehcp);

	return (EHC_SUCCESS);
}

/*
 * Read from the PCF8574 chip.
 * byteaddress = chip type base address | chip offset address.
 */
int
ehc_read_pcf8574(struct ehc_envcunit *ehcp, int byteaddress, uint8_t *buf,
	int size)
{
	int i;
	int status;
	uint8_t discard;

	ASSERT((byteaddress & 0x1) == 0);
	ASSERT(MUTEX_HELD(&ehcp->umutex));

	/*
	 * Put the bus into the start condition
	 */
	if ((status = ehc_start_pcf8584(ehcp, EHC_BYTE_READ | byteaddress)) !=
			EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			/*
			 * Send the "stop" condition.
			 */
			ehc_stop_pcf8584(ehcp);
			/*
			 * Read the last byte - discard it.
			 */
			discard =
			ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0);
#ifdef lint
			discard = discard;
#endif
		}
		return (EHC_FAILURE);
	}

	for (i = 0; i < size - 1; i++) {
		if ((status = ehc_read_pcf8584(ehcp, &buf[i])) != EHC_SUCCESS) {
		return (EHC_FAILURE);
		}
	}

	/*
	 * Handle the part of the bus protocol which comes
	 * after a read.
	 */

	if (ehc_after_read_pcf8584(ehcp, &buf[i]) != EHC_SUCCESS) {
		return (EHC_FAILURE);
	}

	return (EHC_SUCCESS);
}

/*
 * Write to the PCF8574 chip.
 * byteaddress = chip type base address | chip offset address.
 */
int
ehc_write_pcf8574(struct ehc_envcunit *ehcp, int byteaddress, uint8_t *buf,
	int size)
{
	int i;
	int status;

	ASSERT((byteaddress & 0x1) == 0);
	ASSERT(MUTEX_HELD(&ehcp->umutex));

	/*
	 * Put the bus into the start condition (write)
	 */
	if ((status = ehc_start_pcf8584(ehcp, byteaddress)) != EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			/*
			 * Send the "stop" condition.
			 */
			ehc_stop_pcf8584(ehcp);
		}
		return (EHC_FAILURE);
	}

	/*
	 * Send the data - poll as needed.
	 */
	for (i = 0; i < size; i++) {
		if ((status = ehc_write_pcf8584(ehcp, buf[i])) != EHC_SUCCESS) {
			if (status == EHC_NO_SLAVE_ACK)
				ehc_stop_pcf8584(ehcp);
			return (EHC_FAILURE);
		}
	}
	/*
	 * Transmission complete - generate stop condition and
	 * put device back into slave receiver mode.
	 */
	ehc_stop_pcf8584(ehcp);

	return (EHC_SUCCESS);
}

/*
 * Read from the LM75
 * byteaddress = chip type base address | chip offset address.
 */
int
ehc_read_lm75(struct ehc_envcunit *ehcp, int byteaddress, uint8_t *buf,
	int size)
{
	int i;
	int status;
	uint8_t discard;

	ASSERT((byteaddress & 0x1) == 0);
	ASSERT(MUTEX_HELD(&ehcp->umutex));

	/*
	 * Put the bus into the start condition
	 */
	if ((status = ehc_start_pcf8584(ehcp, EHC_BYTE_READ | byteaddress)) !=
			EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			/*
			 * Send the stop condition.
			 */
			ehc_stop_pcf8584(ehcp);
			/*
			 * Read the last byte - discard it.
			 */
			discard =
			ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0);
#ifdef lint
			discard = discard;
#endif
		}
		return (EHC_FAILURE);
	}

	for (i = 0; i < size - 1; i++) {
		if ((status = ehc_read_pcf8584(ehcp, &buf[i])) != EHC_SUCCESS) {
			return (EHC_FAILURE);
		}
	}

	/*
	 * Handle the part of the bus protocol which comes
	 * after a read.
	 */
	if (ehc_after_read_pcf8584(ehcp, &buf[i]) != EHC_SUCCESS) {
		return (EHC_FAILURE);
	}

	return (EHC_SUCCESS);
}

/*
 * Write to the PCF8583 chip.
 * byteaddress = chip type base address | chip offset address.
 */
int
ehc_write_pcf8583(struct ehc_envcunit *ehcp, int byteaddress, uint8_t *buf,
	int size)
{
	int i;
	int status;

	ASSERT((byteaddress & 0x1) == 0);
	ASSERT(MUTEX_HELD(&ehcp->umutex));

	if ((status = ehc_start_pcf8584(ehcp, byteaddress)) != EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			/*
			 * Send the "stop" condition.
			 */
			ehc_stop_pcf8584(ehcp);
		}
		return (EHC_FAILURE);
	}

	/*
	 * Send the data - poll as needed.
	 */
	for (i = 0; i < size; i++) {
		if ((status = ehc_write_pcf8584(ehcp, buf[i])) != EHC_SUCCESS) {
			if (status == EHC_NO_SLAVE_ACK)
				ehc_stop_pcf8584(ehcp);
			return (EHC_FAILURE);
		}
	}

	/*
	 * Transmission complete - generate stop condition and
	 * put device back into slave receiver mode.
	 */
	ehc_stop_pcf8584(ehcp);

	return (EHC_SUCCESS);
}

/*
 * Read from the PCF8591 chip.
 */
int
ehc_read_pcf8591(struct ehc_envcunit *ehcp, int byteaddress, int channel,
	int autoinc, int amode, int aenable,  uint8_t *buf, int size)
{
	int i;
	int status;
	register uint8_t control;
	uint8_t discard;

	ASSERT((byteaddress & 0x1) == 0);
	ASSERT(channel < 4);
	ASSERT(amode < 4);
	ASSERT(MUTEX_HELD(&ehcp->umutex));

	/*
	 * Write the control word to the PCF8591.
	 * Follow the control word with a repeated START byte
	 * rather than a STOP so that reads can follow without giving
	 * up the bus.
	 */

	control = ((aenable << 6) | (amode << 4) | (autoinc << 2) | channel);

	if ((status = ehc_start_pcf8584(ehcp, byteaddress)) != EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			ehc_stop_pcf8584(ehcp);
		}
		return (EHC_FAILURE);
	}

	if ((status = ehc_write_pcf8584(ehcp, control)) != EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK)
			ehc_stop_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	/*
	 * The following two operations, 0x45 to S1, and the byteaddress
	 * to S0, will result in a repeated START being sent out on the bus.
	 * Refer to Fig.8 of Philips Semiconductors PCF8584 product spec.
	 */

	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1,
		EHC_S1_ES0 | EHC_S1_STA | EHC_S1_ACK);

	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0,
		EHC_BYTE_READ | byteaddress);

	i = 0;

	do {
		drv_usecwait(1000);
		status =
			ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1);
		i++;
	} while ((status & EHC_S1_PIN) && i < EHC_MAX_WAIT);

	if (i == EHC_MAX_WAIT) {
		DCMN_ERR(CE_WARN, "ehc_read_pcf8591(): read of S1 failed");
		return (EHC_FAILURE);
	}

	if (status & EHC_S1_BER) {
		DCMN2_ERR(CE_WARN, "ehc_read_pcf8591(): Bus error");
		ehc_init_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	if (status & EHC_S1_LAB) {
		DCMN2_ERR(CE_WARN, "ehc_read_pcf8591(): Lost Arbitration");
		ehc_init_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	if (status & EHC_S1_LRB) {
		DCMN_ERR(CE_WARN, "ehc_read_pcf8591(): No slave ACK");
		/*
		 * Send the stop condition.
		 */
		ehc_stop_pcf8584(ehcp);
		/*
		 * Read the last byte - discard it.
		 */
		discard = ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0);
#ifdef lint
		discard = discard;
#endif
		return (EHC_FAILURE);
	}

	/*
	 * Discard first read as per PCF8584 master receiver protocol.
	 * This is normally done in the ehc_start_pcf8584() routine.
	 */
	if ((status = ehc_read_pcf8584(ehcp, &discard)) != EHC_SUCCESS) {
		return (EHC_FAILURE);
	}

	/* Discard second read as per PCF8591 protocol */
	if ((status = ehc_read_pcf8584(ehcp, &discard)) != EHC_SUCCESS) {
		return (EHC_FAILURE);
	}

	for (i = 0; i < size - 1; i++) {
		if ((status = ehc_read_pcf8584(ehcp, &buf[i])) != EHC_SUCCESS) {
			return (EHC_FAILURE);
		}
	}

	if (ehc_after_read_pcf8584(ehcp, &buf[i]) != EHC_SUCCESS) {
		return (EHC_FAILURE);
	}

	return (EHC_SUCCESS);
}

/*
 * Write to the PCF8591 chip.
 * byteaddress = chip type base address | chip offset address.
 */
int
ehc_write_pcf8591(struct ehc_envcunit *ehcp, int byteaddress, int channel,
	int autoinc, int amode, int aenable, uint8_t *buf, int size)
{
	int i, status;
	register uint8_t control;

	ASSERT((byteaddress & 0x1) == 0);
	ASSERT(MUTEX_HELD(&ehcp->umutex));

	control = ((aenable << 6) | (amode << 4) | (autoinc << 2) | channel);

	status = ehc_start_pcf8584(ehcp, byteaddress);
	if (status != EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			/*
			 * Send the "stop" condition.
			 */
			ehc_stop_pcf8584(ehcp);
		}
		return (EHC_FAILURE);
	}

	if ((status = ehc_write_pcf8584(ehcp, control)) != EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK)
			ehc_stop_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	for (i = 0; i < size; i++) {
		status = ehc_write_pcf8584(ehcp, buf[i]);
		if (status != EHC_SUCCESS) {
			if (status == EHC_NO_SLAVE_ACK)
				ehc_stop_pcf8584(ehcp);
			return (EHC_FAILURE);
		}
	}

	ehc_stop_pcf8584(ehcp);

	return (EHC_SUCCESS);
}
