/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Interface to the 93C46 serial EEPROM that is used to store BIOS
 * settings for the aic7xxx based adaptec SCSI controllers.  It can
 * also be used for 93C26 and 93C06 serial EEPROMS.
 *
 * Copyright (c) 1994, 1995 Justin T. Gibbs.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * the GNU Public License ("GPL").
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/dev/aic7xxx/aic7xxx.c,v 1.40 2000/01/07 23:08:17gibbs Exp $
 */

#ifndef _SMC93CX6VAR_H_
#define	_SMC93CX6VAR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/param.h>
#include <sys/systm.h>

typedef enum {
	C46 = 6,
	C56_66 = 8
} seeprom_chip_t;

struct seeprom_descriptor {
	ddi_acc_handle_t	sd_handle;
	caddr_t			sd_base;
	size_t sd_regsize;
	size_t sd_control_offset;
	size_t sd_status_offset;
	size_t sd_dataout_offset;
	seeprom_chip_t sd_chip;
	uint32_t sd_MS;
	uint32_t sd_RDY;
	uint32_t sd_CS;
	uint32_t sd_CK;
	uint32_t sd_DO;
	uint32_t sd_DI;
};

/*
 * This function will read count 16-bit words from the serial EEPROM and
 * return their value in buf.  The port address of the aic7xxx serial EEPROM
 * control register is passed in as offset.  The following parameters are
 * also passed in:
 *
 *   CS  - Chip select
 *   CK  - Clock
 *   DO  - Data out
 *   DI  - Data in
 *   RDY - SEEPROM ready
 *   MS  - Memory port mode select
 *
 *  A failed read attempt returns 0, and a successful read returns 1.
 */

#define	SEEPROM_INB(sd) \
	(((sd)->sd_regsize == 4) \
	    ? ddi_get32((sd)->sd_handle, \
	    (uint32_t *)((uintptr_t)(sd)->sd_base+ \
	    (sd)->sd_control_offset)) \
	    : ddi_get8((sd)->sd_handle, (uint8_t *)((sd)->sd_base+ \
	    (sd)->sd_control_offset)))

#define	SEEPROM_OUTB(sd, value) { \
	if ((sd)->sd_regsize == 4) \
		ddi_put32((sd)->sd_handle, \
		    (uint32_t *)((uintptr_t)(sd)->sd_base+ \
		    (sd)->sd_control_offset), (value)); \
	else \
		ddi_put8((sd)->sd_handle, \
		    (uint8_t *)((sd)->sd_base+ \
		    (sd)->sd_control_offset), (uint8_t)(value)); \
}

#define	SEEPROM_STATUS_INB(sd) \
	(((sd)->sd_regsize == 4) \
	    ? ddi_get32((sd)->sd_handle, \
	    (uint32_t *)((uintptr_t)(sd)->sd_base+ \
	    (sd)->sd_status_offset)) \
	    : ddi_get8((sd)->sd_handle, (uint8_t *)((sd)->sd_base+ \
	    (sd)->sd_status_offset)))

#define	SEEPROM_DATA_INB(sd) \
	(((sd)->sd_regsize == 4) \
	    ? ddi_get32((sd)->sd_handle, \
	    (uint32_t *)((uintptr_t)(sd)->sd_base+ \
	    (sd)->sd_dataout_offset)) \
	    : ddi_get8((sd)->sd_handle, (uint8_t *)((sd)->sd_base+ \
	    (sd)->sd_dataout_offset)))

int read_seeprom(struct seeprom_descriptor *sd, uint16_t *buf,
    size_t start_addr, size_t count);
#ifdef __cplusplus
}
#endif

#endif	/* _SMC93CX6VAR_H_ */
