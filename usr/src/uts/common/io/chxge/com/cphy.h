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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* cphy.h */

#ifndef CHELSIO_CPHY_H
#define CHELSIO_CPHY_H

#include "common.h"

struct mdio_ops {
	void (*init)(adapter_t *adapter, const struct board_info *bi);
	int  (*read)(adapter_t *adapter, int phy_addr, int mmd_addr,
		     int reg_addr, unsigned int *val);
        int  (*write)(adapter_t *adapter, int phy_addr, int mmd_addr,
		      int reg_addr, unsigned int val);
};

/* PHY interrupt types */
enum {
	cphy_cause_link_change = 0x1,
	cphy_cause_error = 0x2
};

enum {
	PHY_LINK_UP = 0x1,
	PHY_AUTONEG_RDY = 0x2,
	PHY_AUTONEG_EN = 0x4
};

struct cphy;

/* PHY operations */
struct cphy_ops {
	void (*destroy)(struct cphy *);
	int (*reset)(struct cphy *, int wait);

	int (*interrupt_enable)(struct cphy *);
	int (*interrupt_disable)(struct cphy *);
	int (*interrupt_clear)(struct cphy *);
	int (*interrupt_handler)(struct cphy *);

	int (*autoneg_enable)(struct cphy *);
	int (*autoneg_disable)(struct cphy *);
	int (*autoneg_restart)(struct cphy *);

	int (*advertise)(struct cphy *phy, unsigned int advertise_map);
	int (*set_loopback)(struct cphy *, int on);
	int (*set_speed_duplex)(struct cphy *phy, int speed, int duplex);
	int (*get_link_status)(struct cphy *phy, int *link_ok, int *speed,
			       int *duplex, int *fc);
};

/* A PHY instance */
struct cphy {
	int addr;                            /* PHY address */
	int state;	/* Link status state machine */
	adapter_t *adapter;                  /* associated adapter */

	ch_cyclic_t phy_update_cyclic;

	u16 bmsr;
	int count;
	int act_count;
	int act_on;

	u32 elmer_gpo;

	struct cphy_ops *ops;                /* PHY operations */
	int (*mdio_read)(adapter_t *adapter, int phy_addr, int mmd_addr,
			 int reg_addr, unsigned int *val);
        int (*mdio_write)(adapter_t *adapter, int phy_addr, int mmd_addr,
			  int reg_addr, unsigned int val);
	struct cphy_instance *instance;
};

/* Convenience MDIO read/write wrappers */
static inline int mdio_read(struct cphy *cphy, int mmd, int reg,
			    unsigned int *valp)
{
        return cphy->mdio_read(cphy->adapter, cphy->addr, mmd, reg, valp);
}

static inline int mdio_write(struct cphy *cphy, int mmd, int reg,
			     unsigned int val)
{
        return cphy->mdio_write(cphy->adapter, cphy->addr, mmd, reg, val);
}

static inline int simple_mdio_read(struct cphy *cphy, int reg,
				   unsigned int *valp)
{
	return mdio_read(cphy, 0, reg, valp);
}

static inline int simple_mdio_write(struct cphy *cphy, int reg,
				    unsigned int val)
{
	return mdio_write(cphy, 0, reg, val);
}

/* Convenience initializer */
static inline void cphy_init(struct cphy *phy, adapter_t *adapter,
			     int phy_addr, struct cphy_ops *phy_ops,
			     struct mdio_ops *mdio_ops)
{
	phy->adapter = adapter;
	phy->addr    = phy_addr;
	phy->ops     = phy_ops;
	if (mdio_ops) {
		phy->mdio_read  = mdio_ops->read;
		phy->mdio_write = mdio_ops->write;
	}
}

/* Operations of the PHY-instance factory */
struct gphy {
	/* Construct a PHY instance with the given PHY address */
	struct cphy *(*create)(adapter_t *adapter, int phy_addr,
			       struct mdio_ops *mdio_ops);

	/*
	 * Reset the PHY chip.  This resets the whole PHY chip, not individual
	 * ports.
	 */
	int (*reset)(adapter_t *adapter);
};

extern struct gphy t1_my3126_ops;
extern struct gphy t1_mv88e1xxx_ops;
extern struct gphy t1_xpak_ops;
extern struct gphy t1_mv88x201x_ops;
extern struct gphy t1_dummy_phy_ops;
#endif
