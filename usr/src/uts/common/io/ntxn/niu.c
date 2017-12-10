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
 * Copyright 2008 NetXen, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/vtrace.h>
#include <sys/dlpi.h>
#include <sys/strsun.h>
#include <sys/ethernet.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>

#include <sys/pci.h>

#include "unm_inc.h"
#include "unm_nic.h"

static long phy_lock_timeout = 100000000;

static int phy_lock(struct unm_adapter_s *adapter)
{
	u32	done = 0;
	int	timeout = 0;

	while (!done) {
		/* acquire semaphore3 from PCI HW block */
		adapter->unm_nic_pci_read_immediate(adapter,
		    UNM_PCIE_REG(PCIE_SEM3_LOCK), &done);
		if (done == 1)
			break;
		if (timeout >= phy_lock_timeout)
			return (-1);
		timeout++;
	}

	adapter->unm_crb_writelit_adapter(adapter, UNM_PHY_LOCK_ID,
	    PHY_LOCK_DRIVER);
	return (0);
}

static void
phy_unlock(struct unm_adapter_s *adapter)
{
	u32	val;

	/* release semaphore3 */
	adapter->unm_nic_pci_read_immediate(adapter,
	    UNM_PCIE_REG(PCIE_SEM3_UNLOCK), &val);
}

/*
 * unm_niu_gbe_phy_read - read a register from the GbE PHY via
 * mii management interface.
 *
 * Note: The MII management interface goes through port 0.
 *	   Individual phys are addressed as follows:
 *	   [15:8]  phy id
 *	   [7:0]   register number
 *
 * Returns:  0 success
 *	  -1 error
 *
 */
long
unm_niu_gbe_phy_read(struct unm_adapter_s *adapter, long reg,
    unm_crbword_t *readval)
{
	long phy = adapter->physical_port;
	unm_niu_gb_mii_mgmt_address_t address;
	unm_niu_gb_mii_mgmt_command_t command;
	unm_niu_gb_mii_mgmt_indicators_t status;

	long timeout = 0;
	long result = 0;
	long restore = 0;
	unm_niu_gb_mac_config_0_t mac_cfg0;

	if (phy_lock(adapter) != 0)
		return (-1);

	/*
	 * MII mgmt all goes through port 0 MAC interface, so it cannot be
	 * in reset
	 */
	adapter->unm_nic_hw_read_wx(adapter, UNM_NIU_GB_MAC_CONFIG_0(0),
	    &mac_cfg0, 4);
	if (mac_cfg0.soft_reset) {
		unm_niu_gb_mac_config_0_t temp;
		*(unm_crbword_t *)&temp = 0;
		temp.tx_reset_pb = 1;
		temp.rx_reset_pb = 1;
		temp.tx_reset_mac = 1;
		temp.rx_reset_mac = 1;
		adapter->unm_nic_hw_write_wx(adapter,
		    UNM_NIU_GB_MAC_CONFIG_0(0), &temp, 4);
		restore = 1;
	}

	*(unm_crbword_t *)&address = 0;
	address.reg_addr = (unm_crbword_t)reg;
	address.phy_addr = (unm_crbword_t)phy;
	adapter->unm_nic_hw_write_wx(adapter, UNM_NIU_GB_MII_MGMT_ADDR(0),
	    &address, 4);

	*(unm_crbword_t *)&command = 0;	/* turn off any prior activity */
	adapter->unm_nic_hw_write_wx(adapter, UNM_NIU_GB_MII_MGMT_COMMAND(0),
	    &command, 4);

	/* send read command */
	command.read_cycle = 1;
	adapter->unm_nic_hw_write_wx(adapter, UNM_NIU_GB_MII_MGMT_COMMAND(0),
	    &command, 4);

	*(unm_crbword_t *)&status = 0;
	do {
		adapter->unm_nic_hw_read_wx(adapter,
		    UNM_NIU_GB_MII_MGMT_INDICATE(0), &status, 4);
		timeout++;
	} while ((status.busy || status.notvalid) &&
	    (timeout++ < UNM_NIU_PHY_WAITMAX));

	if (timeout < UNM_NIU_PHY_WAITMAX) {
		adapter->unm_nic_hw_read_wx(adapter,
		    UNM_NIU_GB_MII_MGMT_STATUS(0), readval, 4);
		result = 0;
	} else
		result = -1;

	if (restore)
		adapter->unm_nic_hw_write_wx(adapter,
		    UNM_NIU_GB_MAC_CONFIG_0(0), &mac_cfg0, 4);

	phy_unlock(adapter);

	return (result);
}

/*
 * Return the current station MAC address.
 * Note that the passed-in value must already be in network byte order.
 */
int
unm_niu_macaddr_get(struct unm_adapter_s *adapter, unsigned char *addr)
{
	__uint64_t result;
	int phy = adapter->physical_port;

	if (addr == NULL)
		return (-1);
	if ((phy < 0) || (phy > 3))
		return (-1);

	UNM_WRITE_LOCK_IRQS(&adapter->adapter_lock, flags);
	if (adapter->curr_window != 0) {
		adapter->unm_nic_pci_change_crbwindow(adapter, 0);
	}

	result = UNM_NIC_PCI_READ_32((void *)pci_base_offset(adapter,
	    UNM_NIU_GB_STATION_ADDR_1(phy))) >> 16;
	result |= ((uint64_t)UNM_NIC_PCI_READ_32((void *)pci_base_offset(
	    adapter, UNM_NIU_GB_STATION_ADDR_0(phy)))) << 16;

	(void) memcpy(addr, &result, sizeof (unm_ethernet_macaddr_t));

	adapter->unm_nic_pci_change_crbwindow(adapter, 1);

	UNM_WRITE_UNLOCK_IRQR(&adapter->adapter_lock, flags);

	return (0);
}

/*
 * Set the station MAC address.
 * Note that the passed-in value must already be in network byte order.
 */
int
unm_niu_macaddr_set(struct unm_adapter_s *adapter, unm_ethernet_macaddr_t addr)
{
	unm_crbword_t temp = 0;
	int phy = adapter->physical_port;

	if ((phy < 0) || (phy > 3))
		return (-1);

	(void) memcpy(&temp, addr, 2);
	temp <<= 16;
	adapter->unm_nic_hw_write_wx(adapter, UNM_NIU_GB_STATION_ADDR_1(phy),
	    &temp, 4);
	temp = 0;
	(void) memcpy(&temp, ((__uint8_t *)addr)+2, sizeof (unm_crbword_t));
	adapter->unm_nic_hw_write_wx(adapter, UNM_NIU_GB_STATION_ADDR_0(phy),
	    &temp, 4);
	return (0);
}

/* Enable a GbE interface */
native_t
unm_niu_enable_gbe_port(struct unm_adapter_s *adapter)
{
	unm_niu_gb_mac_config_0_t mac_cfg0;
	unm_niu_gb_mac_config_1_t mac_cfg1;
	unm_niu_gb_mii_mgmt_config_t mii_cfg;
	native_t port = adapter->physical_port;
	int zero = 0;
	int one = 1;
	u32 port_mode = 0;

	if ((port < 0) || (port > UNM_NIU_MAX_GBE_PORTS)) {
		return (-1);
	}

	if (adapter->link_speed != MBPS_10 &&
	    adapter->link_speed != MBPS_100 &&
	    adapter->link_speed != MBPS_1000) {

		if (NX_IS_REVISION_P3(adapter->ahw.revision_id)) {
			/*
			 * Do NOT fail this call because the cable is unplugged.
			 * Updated when the link comes up...
			 */
			adapter->link_speed = MBPS_1000;
		} else {
			return (-1);
		}
	}

	port_mode = adapter->unm_nic_pci_read_normalize(adapter,
	    UNM_PORT_MODE_ADDR);
	if (port_mode == UNM_PORT_MODE_802_3_AP) {
		*(unm_crbword_t *)&mac_cfg0 = 0x0000003f;
		*(unm_crbword_t *)&mac_cfg1 = 0x0000f2df;
		unm_crb_write_adapter(UNM_NIU_AP_MAC_CONFIG_0(port), &mac_cfg0,
		    adapter);
		unm_crb_write_adapter(UNM_NIU_AP_MAC_CONFIG_1(port), &mac_cfg1,
		    adapter);
	} else {
		*(unm_crbword_t *)&mac_cfg0 = 0;
		mac_cfg0.soft_reset = 1;
		unm_crb_write_adapter(UNM_NIU_GB_MAC_CONFIG_0(port), &mac_cfg0,
		    adapter);

		*(unm_crbword_t *)&mac_cfg0 = 0;
		mac_cfg0.tx_enable = 1;
		mac_cfg0.rx_enable = 1;
		mac_cfg0.rx_flowctl = 0;
		mac_cfg0.tx_reset_pb = 1;
		mac_cfg0.rx_reset_pb = 1;
		mac_cfg0.tx_reset_mac = 1;
		mac_cfg0.rx_reset_mac = 1;

		unm_crb_write_adapter(UNM_NIU_GB_MAC_CONFIG_0(port), &mac_cfg0,
		    adapter);

		*(unm_crbword_t *)&mac_cfg1 = 0;
		mac_cfg1.preamblelen = 0xf;
		mac_cfg1.duplex = 1;
		mac_cfg1.crc_enable = 1;
		mac_cfg1.padshort = 1;
		mac_cfg1.checklength = 1;
		mac_cfg1.hugeframes = 1;

		switch (adapter->link_speed) {
			case MBPS_10:
			case MBPS_100: /* Fall Through */
				mac_cfg1.intfmode = 1;
				unm_crb_write_adapter(UNM_NIU_GB_MAC_CONFIG_1
				    (port), &mac_cfg1, adapter);

				/* set mii mode */
				unm_crb_write_adapter(
				    UNM_NIU_GB0_GMII_MODE+(port<<3),
				    &zero, adapter);
				unm_crb_write_adapter(
				    UNM_NIU_GB0_MII_MODE+(port<< 3),
				    &one, adapter);
				break;

			case MBPS_1000:
				mac_cfg1.intfmode = 2;
				unm_crb_write_adapter(
				    UNM_NIU_GB_MAC_CONFIG_1(port),
				    &mac_cfg1, adapter);

				/* set gmii mode */
				unm_crb_write_adapter(
				    UNM_NIU_GB0_MII_MODE+(port << 3),
				    &zero, adapter);
				unm_crb_write_adapter(
				    UNM_NIU_GB0_GMII_MODE+(port << 3),
				    &one, adapter);
				break;

			default:
				/* Will not happen */
				break;
		}

		*(unm_crbword_t *)&mii_cfg = 0;
		mii_cfg.clockselect = 7;
		unm_crb_write_adapter(UNM_NIU_GB_MII_MGMT_CONFIG(port),
		    &mii_cfg, adapter);

		*(unm_crbword_t *)&mac_cfg0 = 0;
		mac_cfg0.tx_enable = 1;
		mac_cfg0.rx_enable = 1;
		mac_cfg0.tx_flowctl = 0;
		mac_cfg0.rx_flowctl = 0;
		unm_crb_write_adapter(UNM_NIU_GB_MAC_CONFIG_0(port),
		    &mac_cfg0, adapter);
	}

	return (0);
}

/* Disable a GbE interface */
native_t
unm_niu_disable_gbe_port(struct unm_adapter_s *adapter)
{
	native_t			port = adapter->physical_port;
	unm_niu_gb_mac_config_0_t	mac_cfg0;

	if ((port < 0) || (port > UNM_NIU_MAX_GBE_PORTS))
		return (-1);

	*(unm_crbword_t *)&mac_cfg0 = 0;
	mac_cfg0.soft_reset = 1;

	if (NX_IS_REVISION_P3(adapter->ahw.revision_id))
		adapter->unm_nic_hw_write_wx(adapter,
		    UNM_NIU_GB_MAC_CONFIG_0(port), &mac_cfg0, 0);
	else
		adapter->unm_nic_hw_write_wx(adapter,
		    UNM_NIU_GB_MAC_CONFIG_0(port), &mac_cfg0, 4);
	return (0);
}

/* Disable an XG interface */
native_t
unm_niu_disable_xg_port(struct unm_adapter_s *adapter)
{
	native_t			port = adapter->physical_port;
	unm_niu_xg_mac_config_0_t	mac_cfg;

	*(unm_crbword_t *)&mac_cfg = 0;
	mac_cfg.soft_reset = 1;

	if (NX_IS_REVISION_P3(adapter->ahw.revision_id)) {
		if (port != 0)
			return (-1);
		adapter->unm_nic_hw_write_wx(adapter, UNM_NIU_XGE_CONFIG_0,
		    &mac_cfg, 4);
	} else {
		if ((port < 0) || (port >= UNM_NIU_MAX_XG_PORTS))
			return (-1);
		adapter->unm_nic_hw_write_wx(adapter, UNM_NIU_XGE_CONFIG_0 +
		    (port * 0x10000), &mac_cfg, 4);
	}
	return (0);
}


/* Set promiscuous mode for a GbE interface */
native_t
unm_niu_set_promiscuous_mode(struct unm_adapter_s *adapter,
    unm_niu_prom_mode_t mode)
{
	native_t port = adapter->physical_port;
	unm_niu_gb_drop_crc_t reg;
	unm_niu_gb_mac_config_0_t mac_cfg;
	unm_crbword_t data;
	int cnt = 0, ret = 0;
	ulong_t val;

	if ((port < 0) || (port > UNM_NIU_MAX_GBE_PORTS))
		return (-1);

	/* Turn off mac */
	adapter->unm_nic_hw_read_wx(adapter, UNM_NIU_GB_MAC_CONFIG_0(port),
	    &mac_cfg, 4);
	mac_cfg.rx_enable = 0;
	adapter->unm_nic_hw_write_wx(adapter, UNM_NIU_GB_MAC_CONFIG_0(port),
	    &mac_cfg, 4);

	/* wait until mac is drained by sre */
	/* Port 0 rx fifo bit 5 */
	val = (0x20 << port);
	adapter->unm_crb_writelit_adapter(adapter, UNM_NIU_FRAME_COUNT_SELECT,
	    val);

	do {
		adapter->unm_nic_hw_read_wx(adapter, UNM_NIU_FRAME_COUNT,
		    &val, 4);
		cnt++;
		if (cnt > 2000) {
			ret = -1;
			break;
		}
		drv_usecwait(10);
	} while (val);

	/* now set promiscuous mode */
	if (ret != -1) {
		if (mode == UNM_NIU_PROMISCOUS_MODE)
			data = 0;
		else
			data = 1;

		adapter->unm_nic_hw_read_wx(adapter, UNM_NIU_GB_DROP_WRONGADDR,
		    &reg, 4);
		switch (port) {
		case 0:
			reg.drop_gb0 = data;
			break;
		case 1:
			reg.drop_gb1 = data;
			break;
		case 2:
			reg.drop_gb2 = data;
			break;
		case 3:
			reg.drop_gb3 = data;
			break;
		default:
			ret  = -1;
			break;
		}
		adapter->unm_nic_hw_write_wx(adapter, UNM_NIU_GB_DROP_WRONGADDR,
		    &reg, 4);
	}

	/* turn the mac on back */
	mac_cfg.rx_enable = 1;
	adapter->unm_nic_hw_write_wx(adapter, UNM_NIU_GB_MAC_CONFIG_0(port),
	    &mac_cfg, 4);

	return (ret);
}

/*
 * Set the MAC address for an XG port
 * Note that the passed-in value must already be in network byte order.
 */
int
unm_niu_xg_macaddr_set(struct unm_adapter_s *adapter,
    unm_ethernet_macaddr_t addr)
{
	int		phy = adapter->physical_port;
	unm_crbword_t	temp = 0;
	u32		port_mode = 0;

	if ((phy < 0) || (phy > 3))
		return (-1);

	switch (phy) {
	case 0:
		(void) memcpy(&temp, addr, 2);
		temp <<= 16;
		port_mode = adapter->unm_nic_pci_read_normalize(adapter,
		    UNM_PORT_MODE_ADDR);
		if (port_mode == UNM_PORT_MODE_802_3_AP) {
			adapter->unm_nic_hw_write_wx(adapter,
			    UNM_NIU_AP_STATION_ADDR_1(phy), &temp, 4);
			temp = 0;
			(void) memcpy(&temp, ((__uint8_t *)addr) + 2,
			    sizeof (unm_crbword_t));
			adapter->unm_nic_hw_write_wx(adapter,
			    UNM_NIU_AP_STATION_ADDR_0(phy), &temp, 4);
		} else {
			adapter->unm_nic_hw_write_wx(adapter,
			    UNM_NIU_XGE_STATION_ADDR_0_1, &temp, 4);
			temp = 0;
			(void) memcpy(&temp, ((__uint8_t *)addr) + 2,
			    sizeof (unm_crbword_t));
			adapter->unm_nic_hw_write_wx(adapter,
			    UNM_NIU_XGE_STATION_ADDR_0_HI, &temp, 4);
		}
		break;

	case 1:
		(void) memcpy(&temp, addr, 2);
		temp <<= 16;
		port_mode = adapter->unm_nic_pci_read_normalize(adapter,
		    UNM_PORT_MODE_ADDR);
		if (port_mode == UNM_PORT_MODE_802_3_AP) {
			adapter->unm_nic_hw_write_wx(adapter,
			    UNM_NIU_AP_STATION_ADDR_1(phy), &temp, 4);
			temp = 0;
			(void) memcpy(&temp, ((__uint8_t *)addr) + 2,
			    sizeof (unm_crbword_t));
			adapter->unm_nic_hw_write_wx(adapter,
			    UNM_NIU_AP_STATION_ADDR_0(phy), &temp, 4);
		} else {
			adapter->unm_nic_hw_write_wx(adapter,
			    UNM_NIU_XGE_STATION_ADDR_0_1, &temp, 4);
			temp = 0;
			(void) memcpy(&temp, ((__uint8_t *)addr) + 2,
			    sizeof (unm_crbword_t));
			adapter->unm_nic_hw_write_wx(adapter,
			    UNM_NIU_XGE_STATION_ADDR_0_HI, &temp, 4);
		}
		break;

	default:
		cmn_err(CE_WARN, "Unknown port %d\n", phy);
		return (DDI_FAILURE);
	}

	return (0);
}

native_t
unm_niu_xg_set_promiscuous_mode(struct unm_adapter_s *adapter,
    unm_niu_prom_mode_t mode)
{
	long  reg;
	unm_niu_xg_mac_config_0_t mac_cfg;
	native_t port = adapter->physical_port;
	int cnt = 0;
	int result = 0;
	u32 port_mode = 0;

	if ((port < 0) || (port > UNM_NIU_MAX_XG_PORTS))
		return (-1);

	port_mode = adapter->unm_nic_pci_read_normalize(adapter,
	    UNM_PORT_MODE_ADDR);

	if (port_mode == UNM_PORT_MODE_802_3_AP) {
		reg = 0;
		adapter->unm_nic_hw_write_wx(adapter,
		    UNM_NIU_GB_DROP_WRONGADDR, (void*)&reg, 4);
	} else {
		/* Turn off mac */
		adapter->unm_nic_hw_read_wx(adapter, UNM_NIU_XGE_CONFIG_0 +
		    (0x10000 * port), &mac_cfg, 4);
		mac_cfg.rx_enable = 0;
		adapter->unm_nic_hw_write_wx(adapter, UNM_NIU_XGE_CONFIG_0 +
		    (0x10000 * port), &mac_cfg, 4);

		/* wait until mac is drained by sre */
		if ((adapter->ahw.boardcfg.board_type !=
		    UNM_BRDTYPE_P2_SB31_10G_IMEZ) &&
		    (adapter->ahw.boardcfg.board_type !=
		    UNM_BRDTYPE_P2_SB31_10G_HMEZ)) {
			/* single port case bit 9 */
			reg = 0x0200;
			adapter->unm_crb_writelit_adapter(adapter,
			    UNM_NIU_FRAME_COUNT_SELECT, reg);
		} else {
			/* Port 0 rx fifo bit 5 */
			reg = (0x20 << port);
			adapter->unm_crb_writelit_adapter(adapter,
			    UNM_NIU_FRAME_COUNT_SELECT, reg);
		}
		do {
			adapter->unm_nic_hw_read_wx(adapter,
			    UNM_NIU_FRAME_COUNT, &reg, 4);
			cnt++;
			if (cnt > 2000) {
				result = -1;
				break;
			}
			drv_usecwait(10);
		} while (reg);

		/* now set promiscuous mode */
		if (result != -1) {
			adapter->unm_nic_hw_read_wx(adapter,
			    UNM_NIU_XGE_CONFIG_1 + (0x10000 * port), &reg, 4);
			if (mode == UNM_NIU_PROMISCOUS_MODE) {
				reg = (reg | 0x2000UL);
			} else { /* FIXME  use the correct mode value here */
				reg = (reg & ~0x2000UL);
			}
			adapter->unm_crb_writelit_adapter(adapter,
			    UNM_NIU_XGE_CONFIG_1 + (0x10000 * port), reg);
		}

		/* turn the mac back on */
		mac_cfg.rx_enable = 1;
		adapter->unm_nic_hw_write_wx(adapter, UNM_NIU_XGE_CONFIG_0 +
		    (0x10000 * port), &mac_cfg, 4);
	}

	return (result);
}

int
unm_niu_xg_set_tx_flow_ctl(struct unm_adapter_s *adapter, int enable)
{
	int port = adapter->physical_port;
	unm_niu_xg_pause_ctl_t reg;

	if ((port < 0) || (port > UNM_NIU_MAX_XG_PORTS))
		return (-1);

	adapter->unm_nic_hw_read_wx(adapter, UNM_NIU_XG_PAUSE_CTL, &reg, 4);
	if (port == 0)
		reg.xg0_mask = !enable;
	else
		reg.xg1_mask = !enable;

	adapter->unm_nic_hw_write_wx(adapter, UNM_NIU_XG_PAUSE_CTL, &reg, 4);

	return (0);
}

int
unm_niu_gbe_set_tx_flow_ctl(struct unm_adapter_s *adapter, int enable)
{
	int port = adapter->physical_port;
	unm_niu_gb_pause_ctl_t reg;

	if ((port < 0) || (port > UNM_NIU_MAX_GBE_PORTS))
		return (-1);

	adapter->unm_nic_hw_read_wx(adapter, UNM_NIU_GB_PAUSE_CTL, &reg, 4);
	switch (port) {
	case (0):
		reg.gb0_mask = !enable;
		break;
	case (1):
		reg.gb1_mask = !enable;
		break;
	case (2):
		reg.gb2_mask = !enable;
		break;
	case (3):
	default:
		reg.gb3_mask = !enable;
		break;
	}
	adapter->unm_nic_hw_write_wx(adapter, UNM_NIU_GB_PAUSE_CTL, &reg, 4);

	return (0);
}

int
unm_niu_gbe_set_rx_flow_ctl(struct unm_adapter_s *adapter, int enable)
{
	int port = adapter->physical_port;
	unm_niu_gb_mac_config_0_t reg;

	if ((port < 0) || (port > UNM_NIU_MAX_GBE_PORTS))
		return (-1);

	adapter->unm_nic_hw_read_wx(adapter, UNM_NIU_GB_MAC_CONFIG_0(port),
	    &reg, 4);
	reg.rx_flowctl = enable;
	adapter->unm_nic_hw_write_wx(adapter, UNM_NIU_GB_MAC_CONFIG_0(port),
	    &reg, 4);

	return (0);
}
