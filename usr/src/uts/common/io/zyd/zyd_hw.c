/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2008 by  Ben Taylor <bentaylor.solx86@gmail.com>
 * Copyright (c) 2007 by  Lukas Turek <turek@ksvi.mff.cuni.cz>
 * Copyright (c) 2007 by  Jiri Svoboda <jirik.svoboda@seznam.cz>
 * Copyright (c) 2007 by  Martin Krulis <martin.krulis@matfyz.cz>
 * Copyright (c) 2006 by Damien Bergamini <damien.bergamini@free.fr>
 * Copyright (c) 2006 by Florian Stoehr <ich@florian-stoehr.de>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

/*
 * ZD1211 wLAN driver
 * Device hardware control
 *
 * Control the ZD1211 chip and the RF chip.
 */

#include <sys/byteorder.h>
#include <sys/strsun.h>

#include "zyd.h"
#include "zyd_reg.h"

static zyd_res zyd_hw_configure(struct zyd_softc *sc);
static zyd_res	zyd_al2230_rf_init(struct zyd_softc *);
static zyd_res	zyd_al2230_rf_init_b(struct zyd_softc *);
static zyd_res	zyd_al2230_switch_radio(struct zyd_softc *, boolean_t);
static zyd_res	zyd_al2230_set_channel(struct zyd_softc *, uint8_t);
static zyd_res	zyd_rfmd_rf_init(struct zyd_softc *);
static zyd_res	zyd_rfmd_switch_radio(struct zyd_softc *, boolean_t);
static zyd_res	zyd_rfmd_set_channel(struct zyd_softc *, uint8_t);

/* io write sequences to initialize RF-independent PHY registers */
static const struct zyd_iowrite16 zyd_def_phy[] = ZYD_DEF_PHY;
static const struct zyd_iowrite16 zyd_def_phyB[] = ZYD_DEF_PHYB;
static const char *zyd_rf_name(uint8_t type)
{
	static const char *const zyd_rfs[] = {
		"unknown", "unknown", "UW2451", "UCHIP", "AL2230",
		"AL7230B", "THETA", "AL2210", "MAXIM_NEW", "GCT",
		"PV2000", "RALINK", "INTERSIL", "RFMD", "MAXIM_NEW2",
		"PHILIPS"
	};
	return (zyd_rfs[(type > 15) ? 0 : type]);
}

/*
 * Read a 32-bit I/O register.
 *
 *	sc	soft state
 *	reg	register number
 *	*val	place to store the value
 */
zyd_res
zyd_read32(struct zyd_softc *sc, uint16_t reg, uint32_t *val)
{
	zyd_res result;
	uint16_t tmp[4];
	uint16_t regs[2];

	regs[0] = LE_16(ZYD_REG32_HI(reg));
	regs[1] = LE_16(ZYD_REG32_LO(reg));

	result = zyd_usb_ioread_req(&sc->usb, regs, sizeof (regs),
	    tmp, sizeof (tmp));

	if (result != USB_SUCCESS)
		return (ZYD_FAILURE);

	if (tmp[0] != regs[0] || tmp[2] != regs[1]) {
		ZYD_WARN("ioread response doesn't match request\n");
		ZYD_WARN("requested regs %04x, %04x; got %04x, %04x\n",
		    LE_16(regs[0]), LE_16(regs[1]),
		    LE_16(tmp[0]), LE_16(tmp[2]));
		return (ZYD_FAILURE);
	}

	*val = ((uint32_t)LE_16(tmp[1]) << 16) | (uint32_t)LE_16(tmp[3]);

	return (ZYD_SUCCESS);
}

/*
 * Write a 32-bit I/O register.
 *
 *	sc	soft state
 *	reg	register number
 *	val	value to write
 */
zyd_res
zyd_write32(struct zyd_softc *sc, uint16_t reg, uint32_t val)
{
	zyd_res result;
	uint16_t tmp[4];

	tmp[0] = LE_16(ZYD_REG32_HI(reg));
	tmp[1] = LE_16(val >> 16);
	tmp[2] = LE_16(ZYD_REG32_LO(reg));
	tmp[3] = LE_16(val & 0xffff);

	result = zyd_usb_cmd_send(&sc->usb, ZYD_CMD_IOWR, tmp, sizeof (tmp));

	return (result);
}

/*
 * Read a 16-bit I/O register.
 *
 *	sc	soft state
 *	reg	register number
 *	*val	place to store the value
 */
zyd_res
zyd_read16(struct zyd_softc *sc, uint16_t reg, uint16_t *val)
{
	zyd_res result;
	uint16_t tmp[2];
	uint16_t regbuf;

	regbuf = LE_16(reg);

	result = zyd_usb_ioread_req(&sc->usb, &regbuf, sizeof (regbuf),
	    tmp, sizeof (tmp));

	if (result != USB_SUCCESS)
		return (ZYD_FAILURE);

	if (tmp[0] != regbuf) {
		ZYD_WARN("ioread response doesn't match request\n");
		ZYD_WARN("requested reg %04x; got %04x\n",
		    LE_16(regbuf), LE_16(tmp[0]));
		return (ZYD_FAILURE);
	}

	if (result != USB_SUCCESS)
		return (ZYD_FAILURE);

	*val = LE_16(tmp[1]);

	return (ZYD_SUCCESS);
}

/*
 * Write a 16-bit I/O register.
 *
 *	sc	soft state
 *	reg	register number
 *	val	value to write
 */
zyd_res
zyd_write16(struct zyd_softc *sc, uint16_t reg, uint16_t val)
{
	zyd_res result;
	uint16_t tmp[2];

	tmp[0] = LE_16(ZYD_REG32_LO(reg));
	tmp[1] = LE_16(val & 0xffff);

	result = zyd_usb_cmd_send(&sc->usb, ZYD_CMD_IOWR, tmp, sizeof (tmp));

	return (result);
}

/*
 * Write an array of 16-bit registers.
 *
 *	sc	soft state
 *	*reqa	array of register-value pairs
 *	n	number of registers
 */
zyd_res
zyd_write16a(struct zyd_softc *sc, const struct zyd_iowrite16 *reqa, int n)
{
	zyd_res res;
	int i;

	for (i = 0; i < n; i++) {
		res = zyd_write16(sc, reqa[i].reg, reqa[i].value);
		if (res != ZYD_SUCCESS)
			return (ZYD_FAILURE);
	}

	return (ZYD_SUCCESS);
}

/*
 * Lock PHY registers.
 */
static void
zyd_lock_phy(struct zyd_softc *sc)
{
	uint32_t tmp;

	(void) zyd_read32(sc, ZYD_MAC_MISC, &tmp);
	tmp &= ~ZYD_UNLOCK_PHY_REGS;
	(void) zyd_write32(sc, ZYD_MAC_MISC, tmp);
}

/*
 * Unlock PHY registers.
 */
static void
zyd_unlock_phy(struct zyd_softc *sc)
{
	uint32_t tmp;

	(void) zyd_read32(sc, ZYD_MAC_MISC, &tmp);
	tmp |= ZYD_UNLOCK_PHY_REGS;
	(void) zyd_write32(sc, ZYD_MAC_MISC, tmp);
}

/*
 * Read MAC address from EEPROM.
 */
static zyd_res
zyd_read_mac(struct zyd_softc *sc)
{
	uint32_t tmp;

	if (zyd_read32(sc, ZYD_EEPROM_MAC_ADDR_P1, &tmp) != ZYD_SUCCESS)
		return (ZYD_FAILURE);

	sc->macaddr[0] = tmp & 0xff;
	sc->macaddr[1] = tmp >> 8;
	sc->macaddr[2] = tmp >> 16;
	sc->macaddr[3] = tmp >> 24;

	if (zyd_read32(sc, ZYD_EEPROM_MAC_ADDR_P2, &tmp) != ZYD_SUCCESS)
		return (ZYD_FAILURE);

	sc->macaddr[4] = tmp & 0xff;
	sc->macaddr[5] = tmp >> 8;

	return (ZYD_SUCCESS);
}

/*
 * Write bits to RF configuration register.
 */
static zyd_res
zyd_rfwrite(struct zyd_softc *sc, uint32_t val, int bits)
{
	uint16_t cr203;
	struct zyd_rfwrite req;
	uint16_t tmp;
	int bit;
	zyd_res res;
	int i;

	if (zyd_read16(sc, ZYD_CR203, &cr203) != ZYD_SUCCESS)
		return (ZYD_FAILURE);

	cr203 &= ~(ZYD_RF_IF_LE | ZYD_RF_CLK | ZYD_RF_DATA);

	req.code = LE_16(ZYD_RFCFG_VALUE);
	req.width = LE_16((uint16_t)bits);

	for (i = 0; i < bits; i++) {
		bit = (val & (1 << (bits - i - 1))) != 0;
		tmp = LE_16(cr203) | (bit ? LE_16(ZYD_RF_DATA) : 0);
		req.bit[i] = tmp;
	}
	res = zyd_usb_cmd_send(&sc->usb, ZYD_CMD_RFCFG, &req,
	    sizeof (uint16_t) * (2 + bits));

	if (res != ZYD_SUCCESS) {
		ZYD_WARN("failed configuring rf register\n");
		return (ZYD_FAILURE);
	}

	return (ZYD_SUCCESS);
}

/*
 * Control the LEDs.
 */
static void
zyd_set_led(struct zyd_softc *sc, int which, boolean_t on)
{
	uint32_t tmp;

	(void) zyd_read32(sc, ZYD_MAC_TX_PE_CONTROL, &tmp);
	tmp &= ~which;
	if (on == B_TRUE)
		tmp |= which;
	(void) zyd_write32(sc, ZYD_MAC_TX_PE_CONTROL, tmp);
}

/*
 * Set MAC address.
 */
static void
zyd_set_macaddr(struct zyd_softc *sc, const uint8_t *addr)
{
	uint32_t tmp;

	tmp = addr[3] << 24 | addr[2] << 16 | addr[1] << 8 | addr[0];
	(void) zyd_write32(sc, ZYD_MAC_MACADRL, tmp);

	tmp = addr[5] << 8 | addr[4];
	(void) zyd_write32(sc, ZYD_MAC_MACADRH, tmp);
}

/*
 * Read data from EEPROM.
 */
static void
zyd_read_eeprom(struct zyd_softc *sc)
{
	uint32_t tmp;
	uint16_t val;
	int i;

	/* read RF chip type */
	(void) zyd_read32(sc, ZYD_EEPROM_POD, &tmp);
	sc->rf_rev = tmp & 0x0f;
	sc->pa_rev = (tmp >> 16) & 0x0f;
	sc->fix_cr47 = (tmp >> 8) & 0x01;
	sc->fix_cr157 = (tmp >> 13) & 0x01;

	ZYD_DEBUG((ZYD_DBG_HW, "fix cr47: 0x%x\n", sc->fix_cr47));
	ZYD_DEBUG((ZYD_DBG_HW, "fix cr157: 0x%x\n", sc->fix_cr157));
	ZYD_DEBUG((ZYD_DBG_HW, "found RF chip %s, rev 0x%x\n",
	    zyd_rf_name(sc->rf_rev), sc->rf_rev));

	/* read regulatory domain (currently unused) */
	(void) zyd_read32(sc, ZYD_EEPROM_SUBID, &tmp);
	sc->regdomain = tmp >> 16;

	ZYD_DEBUG((ZYD_DBG_HW, "regulatory domain: %x\n", sc->regdomain));

	/* read Tx power calibration tables */
	for (i = 0; i < 7; i++) {
		(void) zyd_read16(sc, ZYD_EEPROM_PWR_CAL + i, &val);
		sc->pwr_cal[i * 2] = val >> 8;
		sc->pwr_cal[i * 2 + 1] = val & 0xff;

		(void) zyd_read16(sc, ZYD_EEPROM_PWR_INT + i, &val);
		sc->pwr_int[i * 2] = val >> 8;
		sc->pwr_int[i * 2 + 1] = val & 0xff;

		(void) zyd_read16(sc, ZYD_EEPROM_36M_CAL + i, &val);
		sc->ofdm36_cal[i * 2] = val >> 8;
		sc->ofdm36_cal[i * 2 + 1] = val & 0xff;

		(void) zyd_read16(sc, ZYD_EEPROM_48M_CAL + i, &val);
		sc->ofdm48_cal[i * 2] = val >> 8;
		sc->ofdm48_cal[i * 2 + 1] = val & 0xff;

		(void) zyd_read16(sc, ZYD_EEPROM_54M_CAL + i, &val);
		sc->ofdm54_cal[i * 2] = val >> 8;
		sc->ofdm54_cal[i * 2 + 1] = val & 0xff;
	}
}

zyd_res
zyd_hw_init(struct zyd_softc *sc)
{
	struct zyd_usb *uc = &sc->usb;
	int ures;
	zyd_res res;

	sc->mac_rev = zyd_usb_mac_rev(uc->cdata->dev_descr->idVendor,
	    uc->cdata->dev_descr->idProduct);
	if (sc->mac_rev == ZYD_ZD1211) {
		res = zyd_usb_loadfirmware(uc, zd1211_firmware,
		    zd1211_firmware_size);
	} else {
		res = zyd_usb_loadfirmware(uc, zd1211b_firmware,
		    zd1211b_firmware_size);
	}
	if (res != ZYD_SUCCESS) {
		ZYD_WARN("failed to load firmware\n");
		goto fail1;
	}

	/* set configuration 1 - required for later communication */
	ures = usb_set_cfg(uc->dip, 0, USB_FLAGS_SLEEP, NULL, NULL);
	if (ures != USB_SUCCESS) {
		ZYD_WARN("failed to set configuration 1 (%d)\n", ures);
		goto fail1;
	}

	if (zyd_usb_open_pipes(uc) != ZYD_SUCCESS) {
		ZYD_WARN("failed to open pipes\n");
		goto fail1;
	}

	if (zyd_usb_cmd_in_start_polling(uc) != ZYD_SUCCESS) {
		ZYD_WARN("failed to start command IN polling\n");
		goto fail2;
	}

	if (zyd_read_mac(sc) != ZYD_SUCCESS) {
		ZYD_WARN("failed to read MAC address\n");
		goto fail3;
	}

	zyd_read_eeprom(sc);
	switch (sc->rf_rev) {
	case ZYD_RF_AL2230:
	case ZYD_RF_RFMD:
		break;
	default:
		ZYD_WARN("unsupported RF %s, chip type 0x%x\n",
		    zyd_rf_name(sc->rf_rev), sc->rf_rev);
		goto fail3;
	}

	if (zyd_hw_configure(sc) != ZYD_SUCCESS) {
		ZYD_WARN("failed to configure hardware\n");
		goto fail3;
	}

	/* RF chip init */
	zyd_lock_phy(sc);
	switch (sc->rf_rev) {
	case ZYD_RF_AL2230:
		if (sc->mac_rev == ZYD_ZD1211) {
			res = zyd_al2230_rf_init(sc);
		} else {
			res = zyd_al2230_rf_init_b(sc);
		}
		break;
	case ZYD_RF_RFMD:
		res = zyd_rfmd_rf_init(sc);
		break;
	default:
		ZYD_WARN("unsupported Radio %s, code = 0x%x\n",
		    zyd_rf_name(sc->rf_rev), sc->rf_rev);
		res = ZYD_FAILURE;
		break;
	}
	zyd_unlock_phy(sc);

	if (res != ZYD_SUCCESS) {
		ZYD_WARN("failed to configure RF chip\n");
		goto fail3;
	}

	ZYD_DEBUG((ZYD_DBG_HW, "MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
	    sc->macaddr[0], sc->macaddr[1], sc->macaddr[2],
	    sc->macaddr[3], sc->macaddr[4], sc->macaddr[5]));

	return (ZYD_SUCCESS);

fail3:
	zyd_usb_cmd_in_stop_polling(uc);
fail2:
	zyd_usb_close_pipes(uc);
fail1:
	return (ZYD_FAILURE);
}

void
zyd_hw_deinit(struct zyd_softc *sc)
{
	struct zyd_usb *uc = &sc->usb;

	zyd_usb_cmd_in_stop_polling(uc);
	zyd_usb_close_pipes(uc);
}

/*
 * Finish ZD chip initialization.
 */
static zyd_res
zyd_hw_configure(struct zyd_softc *sc)
{
	zyd_res res;
	uint32_t tmp;

	/* specify that the plug and play is finished */
	(void) zyd_write32(sc, ZYD_MAC_AFTER_PNP, 1);
	(void) zyd_read16(sc, ZYD_FIRMWARE_BASE_ADDR, &sc->fwbase);
	ZYD_DEBUG((ZYD_DBG_FW, "firmware base address: 0x%04x\n", sc->fwbase));

	/* retrieve firmware revision number */
	(void) zyd_read16(sc, sc->fwbase + ZYD_FW_FIRMWARE_REV, &sc->fw_rev);
	ZYD_DEBUG((ZYD_DBG_FW, "firmware revision: x0x%4x\n", sc->fw_rev));

	(void) zyd_write32(sc, ZYD_CR_GPI_EN, 0);
	(void) zyd_write32(sc, ZYD_MAC_CONT_WIN_LIMIT, 0x7f043f);

	/* disable interrupts */
	(void) zyd_write32(sc, ZYD_CR_INTERRUPT, 0);

	/* Init RF chip-independent PHY registers */
	zyd_lock_phy(sc);
	if (sc->mac_rev == ZYD_ZD1211) {
		res = zyd_write16a(sc, zyd_def_phy,
		    ZYD_ARRAY_LENGTH(zyd_def_phy));
	} else {
		res = zyd_write16a(sc, zyd_def_phyB,
		    ZYD_ARRAY_LENGTH(zyd_def_phyB));
	}
	if (sc->fix_cr157) {
		if (zyd_read32(sc, ZYD_EEPROM_PHY_REG, &tmp) == 0)
			(void) zyd_write32(sc, ZYD_CR157, tmp >> 8);
	}
	zyd_unlock_phy(sc);

	if (res != ZYD_SUCCESS)
		return (ZYD_FAILURE);

	/* HMAC initialization magic */
	if (sc->mac_rev == ZYD_ZD1211) {
		(void) zyd_write32(sc, ZYD_MAC_RETRY, 0x00000002);
	} else {
		(void) zyd_write32(sc, ZYD_MACB_MAX_RETRY, 0x02020202);
		(void) zyd_write32(sc, ZYD_MACB_TXPWR_CTL4, 0x007f003f);
		(void) zyd_write32(sc, ZYD_MACB_TXPWR_CTL3, 0x007f003f);
		(void) zyd_write32(sc, ZYD_MACB_TXPWR_CTL2, 0x003f001f);
		(void) zyd_write32(sc, ZYD_MACB_TXPWR_CTL1, 0x001f000f);
		(void) zyd_write32(sc, ZYD_MACB_AIFS_CTL1, 0x00280028);
		(void) zyd_write32(sc, ZYD_MACB_AIFS_CTL2, 0x008C003c);
		(void) zyd_write32(sc, ZYD_MACB_TXOP, 0x01800824);
	}
	(void) zyd_write32(sc, ZYD_MAC_ACK_EXT, 0x00000020);
	(void) zyd_write32(sc, ZYD_CR_ADDA_MBIAS_WT, 0x30000808);
	(void) zyd_write32(sc, ZYD_MAC_SNIFFER, 0x00000000);
	(void) zyd_write32(sc, ZYD_MAC_RXFILTER, 0x00000000);
	(void) zyd_write32(sc, ZYD_MAC_GHTBL, 0x00000000);
	(void) zyd_write32(sc, ZYD_MAC_GHTBH, 0x80000000);
	(void) zyd_write32(sc, ZYD_MAC_MISC, 0x000000a4);
	(void) zyd_write32(sc, ZYD_CR_ADDA_PWR_DWN, 0x0000007f);
	(void) zyd_write32(sc, ZYD_MAC_BCNCFG, 0x00f00401);
	(void) zyd_write32(sc, ZYD_MAC_PHY_DELAY2, 0x00000000);
	(void) zyd_write32(sc, ZYD_MAC_ACK_EXT, 0x00000080);
	(void) zyd_write32(sc, ZYD_CR_ADDA_PWR_DWN, 0x00000000);
	(void) zyd_write32(sc, ZYD_MAC_SIFS_ACK_TIME, 0x00000100);
	(void) zyd_write32(sc, ZYD_MAC_DIFS_EIFS_SIFS, 0x0547c032);
	(void) zyd_write32(sc, ZYD_CR_RX_PE_DELAY, 0x00000070);
	(void) zyd_write32(sc, ZYD_CR_PS_CTRL, 0x10000000);
	(void) zyd_write32(sc, ZYD_MAC_RTSCTSRATE, 0x02030203);
	(void) zyd_write32(sc, ZYD_MAC_RX_THRESHOLD, 0x000c0640);
	(void) zyd_write32(sc, ZYD_MAC_BACKOFF_PROTECT, 0x00000114);

	return (ZYD_SUCCESS);
}

/*
 * Set active channel number.
 */
void
zyd_hw_set_channel(struct zyd_softc *sc, uint8_t chan)
{
	uint32_t tmp;

	zyd_lock_phy(sc);

	ZYD_DEBUG((ZYD_DBG_HW, "setting channel %d\n", chan));

	switch (sc->rf_rev) {
	case ZYD_RF_AL2230:
		(void) zyd_al2230_set_channel(sc, chan);
		break;
	case ZYD_RF_RFMD:
		(void) zyd_rfmd_set_channel(sc, chan);
		break;
	}

	/* update Tx power */
	ZYD_DEBUG((ZYD_DBG_HW, "updating tx power table\n"));

	(void) zyd_write16(sc, ZYD_CR31, sc->pwr_int[chan - 1]);
	if (sc->mac_rev == ZYD_ZD1211B) {
		(void) zyd_write16(sc, ZYD_CR67, sc->ofdm36_cal[chan - 1]);
		(void) zyd_write16(sc, ZYD_CR66, sc->ofdm48_cal[chan - 1]);
		(void) zyd_write16(sc, ZYD_CR65, sc->ofdm54_cal[chan - 1]);
		(void) zyd_write16(sc, ZYD_CR68, sc->pwr_cal[chan - 1]);
		(void) zyd_write16(sc, ZYD_CR69, 0x28);
		(void) zyd_write16(sc, ZYD_CR69, 0x2a);
	}

	if (sc->fix_cr47) {
		/* set CCK baseband gain from EEPROM */
		if (zyd_read32(sc, ZYD_EEPROM_PHY_REG, &tmp) == 0)
			(void) zyd_write16(sc, ZYD_CR47, tmp & 0xff);
	}

	(void) zyd_write32(sc, ZYD_CR_CONFIG_PHILIPS, 0);

	zyd_unlock_phy(sc);
}

/*
 * Activate the device.
 */
zyd_res
zyd_hw_start(struct zyd_softc *sc)
{
	struct zyd_usb *uc = &sc->usb;
	struct ieee80211com *ic = &sc->ic;
	zyd_res res;

	if (zyd_usb_data_in_enable(&sc->usb) != ZYD_SUCCESS) {
		ZYD_WARN("error starting rx transfer\n");
		goto fail1;
	}

	ZYD_DEBUG((ZYD_DBG_HW, "setting MAC address\n"));
	zyd_set_macaddr(sc, sc->macaddr);

	/* we'll do software WEP decryption for now */
	ZYD_DEBUG((ZYD_DBG_HW, "setting encryption mode\n"));
	res = zyd_write32(sc, ZYD_MAC_ENCRYPTION_TYPE, ZYD_ENC_SNIFFER);
	if (res != ZYD_SUCCESS)
		goto fail2;

	/* promiscuous mode */
	(void) zyd_write32(sc, ZYD_MAC_SNIFFER, 0);

	/* try to catch all packets */
	(void) zyd_write32(sc, ZYD_MAC_RXFILTER, ZYD_FILTER_BSS);

	/* switch radio transmitter ON */
	switch (sc->rf_rev) {
	case ZYD_RF_AL2230:
		(void) zyd_al2230_switch_radio(sc, B_TRUE);
		break;
	case ZYD_RF_RFMD:
		(void) zyd_rfmd_switch_radio(sc, B_TRUE);
		break;
	}

	/* set basic rates */
	ZYD_DEBUG((ZYD_DBG_HW, "setting basic rates\n"));
	if (ic->ic_curmode == IEEE80211_MODE_11B)
		(void) zyd_write32(sc, ZYD_MAC_BAS_RATE, 0x0003);
	else if (ic->ic_curmode == IEEE80211_MODE_11A)
		(void) zyd_write32(sc, ZYD_MAC_BAS_RATE, 0x1500);
	else			/* assumes 802.11b/g */
		(void) zyd_write32(sc, ZYD_MAC_BAS_RATE, 0x000f);

	/* set mandatory rates */
	ZYD_DEBUG((ZYD_DBG_HW, "setting mandatory rates\n"));
	if (ic->ic_curmode == IEEE80211_MODE_11B)
		(void) zyd_write32(sc, ZYD_MAC_MAN_RATE, 0x000f);
	else if (ic->ic_curmode == IEEE80211_MODE_11A)
		(void) zyd_write32(sc, ZYD_MAC_MAN_RATE, 0x1500);
	else			/* assumes 802.11b/g */
		(void) zyd_write32(sc, ZYD_MAC_MAN_RATE, 0x150f);

	/* enable interrupts */
	(void) zyd_write32(sc, ZYD_CR_INTERRUPT, ZYD_HWINT_MASK);

	zyd_set_led(sc, ZYD_LED2, B_TRUE);

	return (ZYD_SUCCESS);

fail2:
	zyd_usb_data_in_disable(uc);
fail1:
	return (ZYD_FAILURE);
}

/*
 * Deactivate the device.
 */
void
zyd_hw_stop(struct zyd_softc *sc)
{
	struct zyd_usb *uc = &sc->usb;

	if (uc->connected) {
		/* switch radio transmitter OFF */
		switch (sc->rf_rev) {
		case ZYD_RF_AL2230:
			(void) zyd_al2230_switch_radio(sc, B_FALSE);
			break;
		case ZYD_RF_RFMD:
			(void) zyd_rfmd_switch_radio(sc, B_FALSE);
			break;
		}

		/* disable reception */
		(void) zyd_write32(sc, ZYD_MAC_RXFILTER, 0);

		/* disable interrupts */
		(void) zyd_write32(sc, ZYD_CR_INTERRUPT, 0);

		zyd_set_led(sc, ZYD_LED2, B_FALSE);
	} else {
		ZYD_DEBUG((ZYD_DBG_HW, "stop: device absent\n"));

	}

	zyd_usb_data_in_disable(uc);
	sc->tx_queued = 0;
}

/*
 * ZD1211 AL2230 Radio control
 * Init the AL2230 RF chip.
 */
static zyd_res
zyd_al2230_rf_init(struct zyd_softc *sc)
{
	const struct zyd_iowrite16 phyini[] = ZYD_AL2230_PHY;
	const uint32_t rfini[] = ZYD_AL2230_RF;

	zyd_res res;
	int i;

	zyd_lock_phy(sc);

	/* init RF-dependent PHY registers */
	res = zyd_write16a(sc, phyini, ZYD_ARRAY_LENGTH(phyini));
	if (res != ZYD_SUCCESS) {
		zyd_unlock_phy(sc);
		return (ZYD_FAILURE);
	}

	/* init AL2230 radio */
	for (i = 0; i < ZYD_ARRAY_LENGTH(rfini); i++) {
		res = zyd_rfwrite(sc, rfini[i], ZYD_AL2230_RF_BITS);
		if (res != ZYD_SUCCESS) {
			zyd_unlock_phy(sc);
			return (ZYD_FAILURE);
		}
	}

	zyd_unlock_phy(sc);

	ZYD_DEBUG((ZYD_DBG_HW, "RF chip AL2230 initialized\n"));

	return (ZYD_SUCCESS);
}

/*
 * Init the AL2230B RF chip (11b).
 */
static zyd_res
zyd_al2230_rf_init_b(struct zyd_softc *sc)
{
	const struct zyd_iowrite16 phyini[] = ZYD_AL2230_PHY_B;
	const uint32_t rfini[] = ZYD_AL2230_RF_B;
	zyd_res res;
	int i;

	zyd_lock_phy(sc);
	/* init RF-dependent PHY registers */
	res = zyd_write16a(sc, phyini, ZYD_ARRAY_LENGTH(phyini));
	if (res != ZYD_SUCCESS) {
		zyd_unlock_phy(sc);
		return (ZYD_FAILURE);
	}

	/* init AL2230 radio */
	for (i = 0; i < ZYD_ARRAY_LENGTH(rfini); i++) {
		res = zyd_rfwrite(sc, rfini[i], ZYD_AL2230_RF_BITS);
		if (res != ZYD_SUCCESS) {
			zyd_unlock_phy(sc);
			return (ZYD_FAILURE);
		}
	}
	zyd_unlock_phy(sc);
	ZYD_DEBUG((ZYD_DBG_HW, "RF chip AL2230 (11b) initialized\n"));

	return (ZYD_SUCCESS);
}

/*
 * Tune RF chip to a specified channel.
 */
static zyd_res
zyd_al2230_set_channel(struct zyd_softc *sc, uint8_t chan)
{
	static const struct {
		uint32_t r1, r2, r3;
	} rfprog[] = ZYD_AL2230_CHANTABLE;

	(void) zyd_rfwrite(sc, rfprog[chan - 1].r1, ZYD_AL2230_RF_BITS);
	(void) zyd_rfwrite(sc, rfprog[chan - 1].r2, ZYD_AL2230_RF_BITS);
	(void) zyd_rfwrite(sc, rfprog[chan - 1].r3, ZYD_AL2230_RF_BITS);

	(void) zyd_write16(sc, ZYD_CR138, 0x28);
	(void) zyd_write16(sc, ZYD_CR203, 0x06);

	return (ZYD_SUCCESS);
}

/*
 * Turn the radio transciever on/off.
 */
static zyd_res
zyd_al2230_switch_radio(struct zyd_softc *sc, boolean_t on)
{
	int on251 = (sc->mac_rev == ZYD_ZD1211) ? 0x3f : 0x7f;

	zyd_lock_phy(sc);

	(void) zyd_write16(sc, ZYD_CR11, (on == B_TRUE) ? 0x00 : 0x04);
	(void) zyd_write16(sc, ZYD_CR251, (on == B_TRUE) ? on251 : 0x2f);

	zyd_unlock_phy(sc);

	return (ZYD_SUCCESS);
}


/*
 * RFMD RF methods.
 */
static zyd_res
zyd_rfmd_rf_init(struct zyd_softc *sc)
{
	static const struct zyd_iowrite16 phyini[] = ZYD_RFMD_PHY;
	static const uint32_t rfini[] = ZYD_RFMD_RF;
	zyd_res res;
	int i;

	/* init RF-dependent PHY registers */
	zyd_lock_phy(sc);
	res = zyd_write16a(sc, phyini, ZYD_ARRAY_LENGTH(phyini));
	if (res != ZYD_SUCCESS) {
		zyd_unlock_phy(sc);
		return (ZYD_FAILURE);
	}
	/* init RFMD radio */
	for (i = 0; i < ZYD_ARRAY_LENGTH(rfini); i++) {
		res = zyd_rfwrite(sc, rfini[i], ZYD_RFMD_RF_BITS);
		if (res != ZYD_SUCCESS) {
			zyd_unlock_phy(sc);
			return (ZYD_FAILURE);
		}
	}
	zyd_unlock_phy(sc);
	ZYD_DEBUG((ZYD_DBG_HW, "RF chip RFMD initialized\n"));

	return (ZYD_SUCCESS);
}

static zyd_res
zyd_rfmd_switch_radio(struct zyd_softc *sc, boolean_t on)
{

	(void) zyd_write16(sc, ZYD_CR10, on ? 0x89 : 0x15);
	(void) zyd_write16(sc, ZYD_CR11, on ? 0x00 : 0x81);

	return (ZYD_SUCCESS);
}

static zyd_res
zyd_rfmd_set_channel(struct zyd_softc *sc, uint8_t chan)
{
	static const struct {
		uint32_t r1, r2;
	} rfprog[] = ZYD_RFMD_CHANTABLE;

	(void) zyd_rfwrite(sc, rfprog[chan - 1].r1, ZYD_RFMD_RF_BITS);
	(void) zyd_rfwrite(sc, rfprog[chan - 1].r2, ZYD_RFMD_RF_BITS);

	return (ZYD_SUCCESS);
}
