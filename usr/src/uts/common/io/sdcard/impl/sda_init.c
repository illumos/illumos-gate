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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * SD card initialization support.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sdcard/sda.h>
#include <sys/sdcard/sda_impl.h>


/*
 * Local Prototypes.
 */

static sda_err_t sda_init_mmc(sda_slot_t *);
static sda_err_t sda_init_sdio(sda_slot_t *);
static sda_err_t sda_init_sdmem(sda_slot_t *);
static sda_err_t sda_init_cmd(sda_slot_t *, sda_index_t, uint32_t,
    sda_rtype_t, uint32_t *);
static sda_err_t sda_init_acmd(sda_slot_t *, sda_index_t, uint32_t,
    sda_rtype_t, uint32_t *);
static sda_err_t sda_init_blocklen(sda_slot_t *);
static sda_err_t sda_init_width(sda_slot_t *);
static sda_err_t sda_init_rca(sda_slot_t *);
static sda_err_t sda_init_ifcond(sda_slot_t *);
static sda_err_t sda_init_highspeed(sda_slot_t *);
static sda_err_t sda_init_switch(sda_slot_t *, uint8_t, uint8_t, uint8_t,
    uint8_t *);
static void sda_init_clock(sda_slot_t *, uint32_t);

/*
 * Implementation.
 */
sda_err_t
sda_init_cmd(sda_slot_t *slot, sda_index_t cmd, uint32_t arg,
    sda_rtype_t rtype, uint32_t *resp)
{
	sda_cmd_t	*cmdp;
	sda_err_t	errno;

	cmdp = sda_cmd_alloc(slot, cmd, arg, rtype, NULL, KM_SLEEP);

	cmdp->sc_flags |= SDA_CMDF_INIT;

	errno = sda_cmd_exec(slot, cmdp, resp);

	sda_cmd_free(cmdp);

	return (errno);
}

sda_err_t
sda_init_acmd(sda_slot_t *slot, sda_index_t cmd, uint32_t arg,
    sda_rtype_t rtype, uint32_t *resp)
{
	sda_cmd_t	*cmdp;
	sda_err_t	errno;

	cmdp = sda_cmd_alloc_acmd(slot, cmd, arg, rtype, NULL, KM_SLEEP);

	cmdp->sc_flags |= SDA_CMDF_INIT;

	errno = sda_cmd_exec(slot, cmdp, resp);

	sda_cmd_free(cmdp);

	return (errno);
}

sda_err_t
sda_init_sdio(sda_slot_t *slot)
{
	slot->s_num_io = 0;

	/*
	 * TODO: SDIO: We need to initialize the SDIO OCR register using
	 * the special CMD_IO_SEND_OCR (CMD5) command.
	 */
	return (SDA_EOK);
}

sda_err_t
sda_init_sdmem(sda_slot_t *slot)
{
	uint32_t	ocr;
	int		count;

	slot->s_flags &= ~SLOTF_SDMEM;

	/*
	 * Try sending the ACMD41 to query the OCR (Op Cond Register).
	 */
	if (sda_init_acmd(slot, ACMD_SD_SEND_OCR, 0, R3, &ocr) != SDA_EOK) {
		/*
		 * Card failed to respond to query, not an SD card?
		 * We send GO_IDLE to clear any error status on the
		 * card.
		 */
		(void) sda_init_cmd(slot, CMD_GO_IDLE, 0, R0, NULL);
		return (SDA_EOK);
	}

	/*
	 * Now we have to send our OCR value, along with the HCS (High
	 * Capacity Support) bit.  The HCS bit is required, to
	 * activate high capacity cards.  We only set the HCS bit if
	 * the card responded to CMD8 (SEND_IFCOND), indicating that
	 * it supports the new protocol.
	 *
	 * Note that the HCS bit occupies the same location as the CCS bit
	 * in the response.
	 */
	if ((ocr & slot->s_cur_ocr) == 0) {
		sda_slot_err(slot, "SD card not compatible with host");
		return (SDA_ENOTSUP);
	}
	/* set the HCS bit if its a ver 2.00 card */
	if (slot->s_flags & SLOTF_IFCOND) {
		ocr |= OCR_CCS;
	}

	/* make sure card is powered up */
	for (count = 1000000; count != 0; count -= 10000) {
		uint32_t	r3;

		if (sda_init_acmd(slot, ACMD_SD_SEND_OCR, ocr, R3, &r3) != 0) {
			sda_slot_err(slot, "SD card failed to power up");
			return (SDA_ENOTSUP);
		}

		/* Now check the busy bit */
		if (r3 & OCR_POWER_UP) {
			slot->s_flags |= SLOTF_SDMEM;
			if ((slot->s_flags & SLOTF_IFCOND) &&
			    (r3 & OCR_CCS)) {
				slot->s_flags |= SLOTF_SDHC;
			} else {
				slot->s_flags &= ~SLOTF_SDHC;
			}
			return (0);
		}

		drv_usecwait(10000);
	}

	sda_slot_err(slot, "SD card timed out during power up");
	return (SDA_ETIME);
}

sda_err_t
sda_init_mmc(sda_slot_t *slot)
{
	uint32_t	ocr;
	int		count;

	slot->s_flags &= ~SLOTF_MMC;

	/*
	 * If the card has already been identified as an SD card, then
	 * cannot also be an MMC card, so don't probe it as such.
	 */
	if (slot->s_flags & SLOTF_SD) {
		return (SDA_EOK);
	}

	/*
	 * Try sending the CMD1 to query the OCR.
	 */
	if (sda_init_cmd(slot, CMD_SEND_OCR, 0, R3, &ocr) != 0) {
		/*
		 * Card failed to respond to query, not an MMC card?
		 * We send GO_IDLE to clear any error status on the
		 * card.
		 */
		(void) sda_init_cmd(slot, CMD_GO_IDLE, 0, R0, NULL);
		return (SDA_EOK);
	}

	if ((ocr & slot->s_cur_ocr) == 0) {
		sda_slot_err(slot, "MMC card not compatible with host");
		return (SDA_ENOTSUP);
	}

	/* make sure card is powered up */
	for (count = 1000000; count != 0; count -= 10000) {
		uint32_t	r3;

		if (sda_init_cmd(slot, CMD_SEND_OCR, ocr, R3, &r3) != 0) {
			sda_slot_err(slot, "MMC card failed to power up");
			return (SDA_ENOTSUP);
		}

		/* Now check the busy bit */
		if (r3 & OCR_POWER_UP) {
			slot->s_flags |= SLOTF_MMC;
			return (SDA_EOK);
		}

		drv_usecwait(10000);
	}

	sda_slot_err(slot, "MMC card timed out during power up");
	return (SDA_ETIME);
}

sda_err_t
sda_init_card(sda_slot_t *slot)
{
	int		rv;
	uint32_t	resp;
	uint32_t	val;

	/*
	 * Power off slot/card initially.
	 */
	sda_slot_power_off(slot);

	/*
	 * Apply initial power to the slot.
	 */
	if ((rv = sda_slot_power_on(slot)) != 0) {
		return (rv);
	}

	/*
	 * First enable the clock, but only at 400 kHz.  All cards are
	 * supposed to be able to operate between this speed and 100
	 * kHz, and all hosts must be able to pick a speed between 100
	 * kHz and 400 kHz.
	 *
	 * Once we know what the device can support, then we speed up.
	 */
	sda_init_clock(slot, 400000);

	if ((rv = sda_init_ifcond(slot)) != SDA_EOK) {
		goto done;
	}

	if (((rv = sda_init_sdio(slot)) != SDA_EOK) ||
	    ((rv = sda_init_sdmem(slot)) != SDA_EOK) ||
	    ((rv = sda_init_mmc(slot)) != SDA_EOK)) {

		/* message will already have been logged */
		goto done;
	}

	if ((slot->s_flags & (SLOTF_MEMORY | SLOTF_SDIO)) == 0) {
		sda_slot_err(slot, "Unidentified card type");
		rv = SDA_ENOTSUP;
		goto done;
	}

	/*
	 * Memory cards need to obtain their CID before getting their RCA.
	 * This is a requirement for the state transitions... they go thru
	 * the ident state, unlike SDIO cards.
	 */
	if (slot->s_flags & SLOTF_MEMORY) {
		rv = sda_init_cmd(slot, CMD_BCAST_CID, 0, R2, slot->s_rcid);
		if (rv != SDA_EOK) {
			sda_slot_err(slot, "Failed getting card CID (%d)", rv);
			goto done;
		}
	}

	if ((rv = sda_init_rca(slot)) != SDA_EOK) {
		goto done;
	}

	slot->s_maxclk = 0xffffffffU;	/* special sentinel */

	/*
	 * Figure out card supported bus width and speed.
	 *
	 * TODO: SDIO: For IO cards, we have to check what speed the card
	 * supports by looking in the CCCR_CAPAB register.  (SDIO cards
	 * can go low-speed only, full-speed, or high-speed.)
	 */
	if (slot->s_flags & SLOTF_MEMORY) {

		/*
		 * We need to obtain the CSD.
		 */
		rv = sda_init_cmd(slot, CMD_SEND_CSD, slot->s_rca << 16, R2,
		    slot->s_rcsd);
		if (rv != 0) {
			sda_slot_err(slot, "Failed getting card CSD (%d)", rv);
			goto done;
		}

		/*
		 * Calculate the maxclock.
		 */
		slot->s_maxclk = sda_mem_maxclk(slot);
	}
	if (((slot->s_flags & SLOTF_SDMEM) != 0) &&
	    ((slot->s_caps & SLOT_CAP_4BITS) != 0)) {
		slot->s_flags |= SLOTF_4BITS;
	}
	if (slot->s_flags & SLOTF_SDIO) {
		sda_slot_debug(slot, "Wide SDIO bus not yet supported");
		slot->s_flags &= ~SLOTF_4BITS;
	}

	/*
	 * Now select the card.
	 */
	if ((rv = sda_init_cmd(slot, CMD_SELECT_CARD, slot->s_rca << 16,
	    R1b, &resp)) != SDA_EOK) {
		sda_slot_err(slot, "Failed selecting card (%d, %x)", rv, resp);
		goto done;
	}

	if ((rv = sda_init_highspeed(slot)) != SDA_EOK) {
		goto done;
	}

	sda_init_clock(slot, slot->s_maxclk);

	/*
	 * Lets go to 4-bit bus mode, if possible.
	 */
	if ((rv = sda_init_width(slot)) != SDA_EOK) {
		goto done;
	}

	if ((rv = sda_init_blocklen(slot)) != SDA_EOK) {
		goto done;
	}

	/* note if a card is writable */
	if ((sda_getprop(slot, SDA_PROP_WPROTECT, &val) == SDA_EOK) &&
	    (val == 0)) {
		slot->s_flags |= SLOTF_WRITABLE;
	}

	rv = SDA_EOK;

done:

	sda_slot_enter(slot);
	slot->s_init = B_FALSE;
	sda_slot_exit(slot);

	sda_slot_wakeup(slot);

	return (rv);
}

sda_err_t
sda_init_blocklen(sda_slot_t *slot)
{
	int		rv;
	uint32_t	resp;

	if ((slot->s_flags & SLOTF_MEMORY) == 0)  {
		return (SDA_EOK);
	}

	/*
	 * All memory cards support block sizes of 512.  Full stop.
	 */
	rv = sda_init_cmd(slot, CMD_SET_BLOCKLEN, 512, R1, &resp);
	if (rv != SDA_EOK) {
		sda_slot_err(slot, "Unable to set block length (%d, %x)",
		    rv, resp);
	}
	return (rv);
}

void
sda_init_clock(sda_slot_t *slot, uint32_t hz)
{
	int		rv;
	uint32_t	act;

	/*
	 * Note that at no time is a failure programming the clock
	 * itself necessarily a fatal error.  Although if the clock
	 * wasn't programmed, other things will probably not work during
	 * initialization.
	 */

	if ((rv = sda_setprop(slot, SDA_PROP_CLOCK, hz)) != SDA_EOK) {
		sda_slot_err(slot, "Failed setting clock to %u Hz (%d)",
		    hz, rv);
		/* XXX: FMA fail the slot */
		return;
	}

	if ((rv = sda_getprop(slot, SDA_PROP_CLOCK, &act)) == SDA_EOK) {
		sda_slot_debug(slot, "Clock set to %u Hz (requested %u Hz)",
		    act, hz);
	} else {
		sda_slot_debug(slot, "Clock frequency unknown (good luck).");
	}

	/*
	 * For now, just wait 10msec for clocks to stabilize to the
	 * card.  (Is this really necessary?)
	 */
	delay(drv_usectohz(10000));
}

sda_err_t
sda_init_width(sda_slot_t *slot)
{
	int		rv;
	uint32_t	resp;

	/*
	 * Spec says we should command the card first.
	 */

	rv = sda_setprop(slot, SDA_PROP_BUSWIDTH, 1);
	if (rv != SDA_EOK) {
		sda_slot_err(slot, "Unable to set slot 1-bit mode (%d)", rv);
		return (rv);
	}

	if ((slot->s_flags & SLOTF_4BITS) == 0) {
		return (SDA_EOK);
	}

	/*
	 * TODO: SDIO: SDIO cards set the CCCR_BUS_WIDTH
	 * and CCCR_CD_DISABLE bits here.
	 */

	/*
	 * If we're going to use all 4 pins, we really need to disconnect
	 * the card pullup resistor.   A consquence of this, is that hosts
	 * which use that resistor for detection must not claim to support
	 * 4-bit bus mode.  This is a limitation of our implementation.
	 */
	rv = sda_init_acmd(slot, ACMD_SET_CLR_CARD_DETECT, 1, R1, &resp);
	if (rv != SDA_EOK) {
		sda_slot_err(slot,
		    "Unable disconnect DAT3 resistor on card (%d, %x)",
		    rv, resp);
		/* non-fatal error, muddle on */
		return (SDA_EOK);
	}

	rv = sda_init_acmd(slot, ACMD_SET_BUS_WIDTH, 2, R1, &resp);
	if (rv != SDA_EOK) {
		sda_slot_err(slot, "Unable to set card 4-bit mode (%d, %x)",
		    rv, resp);
		/* non-fatal error, muddle on */
		return (SDA_EOK);
	}

	rv = sda_setprop(slot, SDA_PROP_BUSWIDTH, 4);
	if (rv != SDA_EOK) {
		/*
		 * This is bad news.  We've already asked for the card to
		 * to use 4-bit mode, but the host is not complying.  It
		 * shouldn't ever happen, so we just error out.
		 */
		sda_slot_err(slot, "Unable to set slot 4-bit mode (%d)", rv);
	}

	return (rv);
}

sda_err_t
sda_init_ifcond(sda_slot_t *slot)
{
	int		rv;
	int		tries;
	uint32_t	vchk;
	uint32_t	resp;

	/*
	 * Try SEND_IF_COND.  Note that this assumes that the host is
	 * supplying 2.7 - 3.6 voltage range.  The standard is not
	 * defined for any other ranges.
	 */
	vchk = R7_VHS_27_36V | R7_PATTERN;

	/* we try this a few times, just to be sure */
	for (tries = 0; tries < 5; tries++) {
		rv = sda_init_cmd(slot, CMD_GO_IDLE, 0, R0, NULL);
		if (rv != SDA_EOK) {
			sda_slot_err(slot, "Failed to IDLE card");
			return (rv);
		}

		rv = sda_init_cmd(slot, CMD_SEND_IF_COND, vchk, R7, &resp);
		if (rv == SDA_EOK) {
			break;
		}
		delay(drv_usectohz(10000));
	}

	if (rv != SDA_EOK) {
		(void) sda_init_cmd(slot, CMD_GO_IDLE, 0, R0, NULL);
		slot->s_flags &= ~SLOTF_IFCOND;

	} else if (resp != vchk) {
		sda_slot_err(slot, "Card voltages incompatible! (%x)", resp);
		return (SDA_ENOTSUP);

	} else {
		/* SDHC compliant */
		slot->s_flags |= SLOTF_IFCOND;
	}

	return (SDA_EOK);
}

sda_err_t
sda_init_rca(sda_slot_t *slot)
{
	int		rv;
	int		tries;
	uint32_t	resp;

	/*
	 * Program the RCA.  Note that MMC has a different mechanism
	 * for this.
	 */
	for (tries = 0; tries < 10; tries++) {

		if (slot->s_flags & SLOTF_MMC) {
			/*
			 * For MMC, we push the RCA to the MMC.  We
			 * arbitrarily start at 0x100, and add from
			 * there.
			 */
			rv = sda_init_cmd(slot, CMD_SEND_RCA,
			    (0x100 + tries) << 16, R1, NULL);
			if (rv == SDA_EOK)
				slot->s_rca = 0x100 + tries;
		} else {
			/*
			 * For SDcard, we are basically asking the
			 * card to propose a value.  It *may* propose
			 * a value of zero, in which case we will have
			 * to ask again.
			 */
			rv = sda_init_cmd(slot, CMD_SEND_RCA, 0, R6, &resp);
			if (rv == SDA_EOK)
				slot->s_rca = resp >> 16;
		}
		if ((rv == SDA_EOK) && (slot->s_rca != 0)) {
			sda_slot_debug(slot, "Relative address (RCA) = %d",
			    slot->s_rca);
			return (SDA_EOK);
		}
	}

	sda_slot_err(slot, "Unable to negotiate a suitable RCA (%d)", rv);
	return ((rv != SDA_EOK) ? rv : SDA_EINVAL);
}

sda_err_t
sda_init_switch(sda_slot_t *slot, uint8_t mode, uint8_t grp, uint8_t val,
    uint8_t *data)
{
	sda_cmd_t	*cmdp;
	sda_err_t	errno;
	uint32_t	arg;

	/*
	 * The spec says we should leave unselected groups set to 0xf,
	 * to prevent inadvertent changes.
	 */
	arg = (mode << 31) | 0xffffff;
	arg &= ~(0xf << (grp << 2));
	arg |= (val << (grp << 2));

	cmdp = sda_cmd_alloc(slot, CMD_SWITCH_FUNC, arg, R1, NULL, KM_SLEEP);

	cmdp->sc_flags |= SDA_CMDF_INIT | SDA_CMDF_DAT | SDA_CMDF_READ;
	cmdp->sc_blksz = 64;
	cmdp->sc_nblks = 1;
	cmdp->sc_kvaddr = (void *)data;

	errno = sda_cmd_exec(slot, cmdp, NULL);

	sda_cmd_free(cmdp);

	return (errno);

}

sda_err_t
sda_init_highspeed(sda_slot_t *slot)
{
	uint32_t	ccc;
	uint8_t		data[64];
	sda_err_t	rv;

	if ((slot->s_caps & SLOT_CAP_HISPEED) == 0) {
		return (SDA_EOK);
	}
	if ((slot->s_flags & SLOTF_SDMEM) == 0) {
		return (SDA_EOK);
	}
	ccc = sda_mem_getbits(slot->s_rcsd, 95, 12);
	if ((ccc & (1 << 10)) == 0) {
		return (SDA_EOK);
	}

	rv = sda_init_switch(slot, 0, 0, 1, data);

	/* these are big-endian bits, bit 401 */
	if ((rv != SDA_EOK) || ((data[13] & (1 << 1)) == 0)) {
		return (SDA_EOK);
	}

	rv = sda_init_switch(slot, 1, 0, 1, data);
	if (rv != SDA_EOK) {
		return (SDA_EOK);
	}

	/* now program the card */
	rv = sda_setprop(slot, SDA_PROP_HISPEED, 1);
	if (rv != SDA_EOK) {
		sda_slot_err(slot, "Failed setting slot to high speed mode");
	} else {
		/* the card should now support 50 MHz */
		slot->s_maxclk = 50000000;
	}

	return (rv);
}
