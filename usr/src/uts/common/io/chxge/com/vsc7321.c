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
 * Copyright (C) 2003-2005 Chelsio Communications.  All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* vsc7321.c */

/* Driver for Vitesse VSC7321 (Meigs II) MAC */


#if 0
#ifndef INVARIANTS
#define INVARIANTS
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <pci/pcivar.h>
#include <pci/pcireg.h>
#endif

#include "gmac.h"
#include "elmer0.h"
#include "vsc7321_reg.h"

#define DEBUG 1

struct init_table {
    u32 addr;
    u32 data;
};

static struct cmac_ops vsc7321_ops;

struct _cmac_instance {
	u32 mac_base;
	u32 index;
	u32 version;
};

#define INITBLOCK_SLEEP	0xffffffff

static void vsc_read(adapter_t *adapter, u32 addr, u32 *val)
{
    u32 status, vlo, vhi;

    (void) t1_tpi_read(adapter, (addr << 2) + 4, &vlo);

    do {
	(void) t1_tpi_read(adapter, (REG_LOCAL_STATUS << 2) + 4, &vlo);
	(void) t1_tpi_read(adapter, REG_LOCAL_STATUS << 2, &vhi);
	status = (vhi << 16) | vlo;
    } while ((status & 1) == 0);

    (void) t1_tpi_read(adapter, (REG_LOCAL_DATA << 2) + 4, &vlo);
    (void) t1_tpi_read(adapter, REG_LOCAL_DATA << 2, &vhi);

    *val = (vhi << 16) | vlo;
}

static void vsc_write(adapter_t *adapter, u32 addr, u32 data)
{
    (void) t1_tpi_write(adapter, (addr << 2) + 4, data & 0xFFFF);
    (void) t1_tpi_write(adapter, addr << 2, (data >> 16) & 0xFFFF);
}

/* Hard reset the MAC.  This wipes out *all* configuration. */
static void vsc7321_full_reset(adapter_t* adapter)
{
    u32 val;

    (void) t1_tpi_read(adapter, A_ELMER0_GPO, &val);
    val &= ~1;
    (void) t1_tpi_write(adapter, A_ELMER0_GPO, val);
    DELAY_US(2);
    val |= 0x80001;	/* Turn on SPI4_EN, and the MAC itself */
    if (is_10G(adapter)) {
	val |= 0x40000;	/* Enable 10G section */
    } else {
	val |= 0x20000;	/* Enable 1G section */
    }
    val &= ~0x800;	/* Turn off the red LED */
    (void) t1_tpi_write(adapter, A_ELMER0_GPO, val);
    DELAY_US(1000);
}

static struct init_table vsc7321_reset[] = {
    {        REG_SW_RESET, 0x80000001 },
    { INITBLOCK_SLEEP, 0x64 },
    {        REG_SW_RESET, 0x00000000 },
    {      REG_IFACE_MODE, 0x00000000 },
    {         REG_CRC_CFG, 0x00000020 },
    {   REG_PLL_CLK_SPEED, 0x00000000 },
    { INITBLOCK_SLEEP, 0x0a },
    {   REG_PLL_CLK_SPEED, 0x000000d4 },
    {       REG_SPI4_MISC, 0x00040009 },
    { REG_SPI4_ING_SETUP2, 0x04040004 },
    { REG_SPI4_ING_SETUP0, 0x0011100f },	/* FIXME: Multiport */
    { REG_SPI4_EGR_SETUP0, 0x0004100f },	/* FIXME: Multiport */
    { REG_SPI4_ING_SETUP1, 0x00100000 },
    {      REG_AGE_INC(0), 0x00000000 },
    {      REG_AGE_INC(1), 0x00000000 },
    {     REG_ING_CONTROL, 0x0a000014 },	/* FIXME: 1G vs 10G */
    {     REG_EGR_CONTROL, 0xa0010091 },	/* FIXME: 1G vs 10G */
};

static struct init_table vsc7321_portinit[4][20] = {
    {	/* Port 0 */
    		/* FIFO setup */
	{        REG_TEST(0,0), 0x00000002 },
	{        REG_TEST(1,0), 0x00000002 },
	{  REG_TOP_BOTTOM(0,0), 0x00100000 },
	{  REG_TOP_BOTTOM(1,0), 0x00100000 },
	{ REG_HIGH_LOW_WM(0,0), 0x0fff0fff },
	{ REG_HIGH_LOW_WM(1,0), 0x0fff0fff },
	{   REG_CT_THRHLD(0,0), 0x00000000 },
	{   REG_CT_THRHLD(1,0), 0x00000000 },
	{        REG_TEST(0,0), 0x00000000 },
	{        REG_TEST(1,0), 0x00000000 },
		/* Port config */
	{      REG_MODE_CFG(0), 0x0000054c },
	{       REG_MAX_LEN(0), 0x000005ee },
	{     REG_DEV_SETUP(0), 0x00000001 },
	{    REG_TBI_CONFIG(0), 0x00000000 },
	{     REG_DEV_SETUP(0), 0x00000046 },
	{     REG_PAUSE_CFG(0), 0x00000000 },
	{    REG_NORMALIZER(0), 0x00000064 },
	{        REG_DENORM(0), 0x00000010 },
    },
    {	/* Port 1 */
    		/* FIFO setup */
	{        REG_TEST(0,1), 0x00000002 },
	{        REG_TEST(1,1), 0x00000002 },
	{  REG_TOP_BOTTOM(0,1), 0x00100000 },
	{  REG_TOP_BOTTOM(1,1), 0x00100000 },
	{ REG_HIGH_LOW_WM(0,1), 0x0fff0fff },
	{ REG_HIGH_LOW_WM(1,1), 0x0fff0fff },
	{   REG_CT_THRHLD(0,1), 0x00000000 },
	{   REG_CT_THRHLD(1,1), 0x00000000 },
	{        REG_TEST(0,1), 0x00000000 },
	{        REG_TEST(1,1), 0x00000000 },
		/* Port config */
	{      REG_MODE_CFG(1), 0x0000054c },
	{       REG_MAX_LEN(1), 0x000005ee },
	{     REG_DEV_SETUP(1), 0x00000001 },
	{    REG_TBI_CONFIG(1), 0x00000000 },
	{     REG_DEV_SETUP(1), 0x00000046 },
	{     REG_PAUSE_CFG(1), 0x00000000 },
	{    REG_NORMALIZER(1), 0x00000064 },
	{        REG_DENORM(1), 0x00000010 },
    },
    {	/* Port 2 */
    		/* FIFO setup */
	{        REG_TEST(0,2), 0x00000002 },
	{        REG_TEST(1,2), 0x00000002 },
	{  REG_TOP_BOTTOM(0,2), 0x00100000 },
	{  REG_TOP_BOTTOM(1,2), 0x00100000 },
	{ REG_HIGH_LOW_WM(0,2), 0x0fff0fff },
	{ REG_HIGH_LOW_WM(1,2), 0x0fff0fff },
	{   REG_CT_THRHLD(0,2), 0x00000000 },
	{   REG_CT_THRHLD(1,2), 0x00000000 },
	{        REG_TEST(0,2), 0x00000000 },
	{        REG_TEST(1,2), 0x00000000 },
		/* Port config */
	{      REG_MODE_CFG(2), 0x0000054c },
	{       REG_MAX_LEN(2), 0x000005ee },
	{     REG_DEV_SETUP(2), 0x00000001 },
	{    REG_TBI_CONFIG(2), 0x00000000 },
	{     REG_DEV_SETUP(2), 0x00000046 },
	{     REG_PAUSE_CFG(2), 0x00000000 },
	{    REG_NORMALIZER(2), 0x00000064 },
	{        REG_DENORM(2), 0x00000010 },
    },
    {	/* Port 3 */
    		/* FIFO setup */
	{        REG_TEST(0,3), 0x00000002 },
	{        REG_TEST(1,3), 0x00000002 },
	{  REG_TOP_BOTTOM(0,3), 0x00100000 },
	{  REG_TOP_BOTTOM(1,3), 0x00100000 },
	{ REG_HIGH_LOW_WM(0,3), 0x0fff0fff },
	{ REG_HIGH_LOW_WM(1,3), 0x0fff0fff },
	{   REG_CT_THRHLD(0,3), 0x00000000 },
	{   REG_CT_THRHLD(1,3), 0x00000000 },
	{        REG_TEST(0,3), 0x00000000 },
	{        REG_TEST(1,3), 0x00000000 },
		/* Port config */
	{      REG_MODE_CFG(3), 0x0000054c },
	{       REG_MAX_LEN(3), 0x000005ee },
	{     REG_DEV_SETUP(3), 0x00000001 },
	{    REG_TBI_CONFIG(3), 0x00000000 },
	{     REG_DEV_SETUP(3), 0x00000046 },
	{     REG_PAUSE_CFG(3), 0x00000000 },
	{    REG_NORMALIZER(3), 0x00000064 },
	{        REG_DENORM(3), 0x00000010 },
    },
};

static void run_table(adapter_t *adapter, struct init_table *ib, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (ib[i].addr == INITBLOCK_SLEEP) {
			DELAY_US( ib[i].data );
		} else {
			vsc_write( adapter, ib[i].addr, ib[i].data );
		}
	}
}

/* ARGSUSED */
static int vsc7321_mac_reset(adapter_t *adapter)
{
	return 0;
}

static struct cmac *vsc7321_mac_create(adapter_t *adapter, int index)
{
	struct cmac *mac;
	u32 val;
	int i;

	mac = t1_os_malloc_wait_zero(sizeof(*mac) + sizeof(cmac_instance));
	if (!mac) return NULL;

	mac->ops = &vsc7321_ops;
	mac->instance = (cmac_instance *)(mac + 1);

	mac->adapter   = adapter;
	mac->instance->index = index;


	vsc7321_full_reset(adapter);

	i = 0;
	do {
		u32 vhi, vlo;

		vhi = vlo = 0;
		(void) t1_tpi_read(adapter, (REG_LOCAL_STATUS << 2) + 4, &vlo);
		DELAY_US(1);
		(void) t1_tpi_read(adapter, REG_LOCAL_STATUS << 2, &vhi);
		DELAY_US(5);
		val = (vhi << 16) | vlo;
	} while ((++i < 10000) && (val == 0xffffffff));


	vsc_read(adapter, REG_CHIP_ID, &val);

	if ((val & 0xfff0ffff) != 0x0F407321) {
		CH_ERR("%s: Didn't find a VSC 7321.\n", adapter_name(adapter));
		t1_os_free((void *)mac, sizeof(*mac) + sizeof(cmac_instance));
		return NULL;
	}

	mac->instance->version = (val >> 16) & 0xf;

	run_table(adapter, vsc7321_reset, DIMOF(vsc7321_reset));
	return mac;
}

/* ARGSUSED */
static int mac_intr_handler(struct cmac *mac)
{
	return 0;
}

/* ARGSUSED */
static int mac_intr_enable(struct cmac *mac)
{
	return 0;
}

/* ARGSUSED */
static int mac_intr_disable(struct cmac *mac)
{
	return 0;
}

/* ARGSUSED */
static int mac_intr_clear(struct cmac *mac)
{
    /* Nothing extra needed */
    return 0;
}

/* Expect MAC address to be in network byte order. */
static int mac_set_address(struct cmac* mac, u8 addr[6])
{
	u32 addr_lo, addr_hi;
	int port = mac->instance->index;

	addr_lo = addr[3];
	addr_lo = (addr_lo << 8) | addr[4];
	addr_lo = (addr_lo << 8) | addr[5];

	addr_hi = addr[0];
	addr_hi = (addr_hi << 8) | addr[1];
	addr_hi = (addr_hi << 8) | addr[2];

	vsc_write(mac->adapter, REG_MAC_LOW_ADDR(port), addr_lo);
	vsc_write(mac->adapter, REG_MAC_HIGH_ADDR(port), addr_hi);
	return 0;
}

static int mac_get_address(struct cmac *mac, u8 addr[6])
{
	u32 addr_lo, addr_hi;
	int port = mac->instance->index;

	vsc_read(mac->adapter, REG_MAC_LOW_ADDR(port), &addr_lo);
	vsc_read(mac->adapter, REG_MAC_HIGH_ADDR(port), &addr_hi);

	addr[0] = (u8) (addr_hi >> 16);
	addr[1] = (u8) (addr_hi >> 8);
	addr[2] = (u8) addr_hi;
	addr[3] = (u8) (addr_lo >> 16);
	addr[4] = (u8) (addr_lo >> 8);
	addr[5] = (u8) addr_lo;
	return 0;
}

/* This is intended to reset a port, not the whole MAC */
static int mac_reset(struct cmac *mac)
{
	int index = mac->instance->index;

	run_table(mac->adapter, vsc7321_portinit[index],
		  DIMOF(vsc7321_portinit[index]));
	return 0;
}

/* ARGSUSED */
static int mac_set_rx_mode(struct cmac *mac, struct t1_rx_mode *rm)
{
	/* Meigs II is always promiscuous. */
	return 0;
}

/* ARGSUSED */
static int mac_set_mtu(struct cmac *mac, int mtu)
{
	return 0;
}

/* ARGSUSED */
static int mac_set_speed_duplex_fc(struct cmac *mac, int speed, int duplex,
				   int fc)
{
        /* XXX Fixme */
	return 0;
}

static int mac_enable(struct cmac *mac, int which)
{
	u32 val;
	int port = mac->instance->index;

	vsc_read(mac->adapter, REG_MODE_CFG(port), &val);
	if (which & MAC_DIRECTION_RX)
		val |= 0x2;
	if (which & MAC_DIRECTION_TX)
		val |= 1;
	vsc_write(mac->adapter, REG_MODE_CFG(port), val);
	return 0;
}

static int mac_disable(struct cmac *mac, int which)
{
	u32 val;
	int port = mac->instance->index;

	vsc_read(mac->adapter, REG_MODE_CFG(port), &val);
	if (which & MAC_DIRECTION_RX)
		val &= ~0x2;
	if (which & MAC_DIRECTION_TX)
		val &= ~0x1;
	vsc_write(mac->adapter, REG_MODE_CFG(port), val);
	return 0;
}

#if 0
/* TBD XXX cmac interface stats will need to assigned to Chelsio's
 *         mac stats.  cmac stats is now just usings Chelsio's
 *         so we don't need the conversion.
 */
int mac_get_statistics(struct cmac* mac, struct cmac_statistics* ps)
{
    port_stats_update(mac);
    return 0;
}
#endif

/* ARGSUSED */
static const struct cmac_statistics *mac_update_statistics(struct cmac *mac,
							   int flag)
{
	return &mac->stats;
}

static void mac_destroy(struct cmac *mac)
{
	t1_os_free((void *)mac, sizeof(*mac) + sizeof(cmac_instance));
}

#ifdef C99_NOT_SUPPORTED
static struct cmac_ops vsc7321_ops = {
	mac_destroy,
	mac_reset,
	mac_intr_enable,
	mac_intr_disable,
	mac_intr_clear,
	mac_intr_handler,
	mac_enable,
	mac_disable,
	NULL,
	NULL,
	mac_set_mtu,
	mac_set_rx_mode,
	mac_set_speed_duplex_fc,
	NULL,
	mac_update_statistics,
	mac_get_address,
	mac_set_address
};
#else
static struct cmac_ops vsc7321_ops = {
	.destroy                  = mac_destroy,
	.reset                    = mac_reset,
	.interrupt_handler        = mac_intr_handler,
	.interrupt_enable         = mac_intr_enable,
	.interrupt_disable        = mac_intr_disable,
	.interrupt_clear          = mac_intr_clear,
	.enable                   = mac_enable,
	.disable                  = mac_disable,
	.set_mtu                  = mac_set_mtu,
	.set_rx_mode              = mac_set_rx_mode,
	.set_speed_duplex_fc      = mac_set_speed_duplex_fc,
	.statistics_update        = mac_update_statistics,
	.macaddress_get           = mac_get_address,
	.macaddress_set           = mac_set_address,
};
#endif

struct gmac t1_vsc7321_ops = {
	0,
	vsc7321_mac_create,
	vsc7321_mac_reset
};
