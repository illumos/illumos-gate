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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * mii.h
 * Generic MII/PHY Support for MAC drivers.
 *
 * Copyrighted as an unpublished work. (c) Copyright 1997 Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _DNET_MII_H
#define	_DNET_MII_H

/*
 * NOTES
 * All calls to MII functions are assumed to be serialized by the user.
 * In the case of the port monitor, which causes asynchronous callbacks,
 * you must pass the address of a mutex. MII aquires this before calling
 * the user callback, and releases it after the callback returns.
 *
 * All calls requiring a PHY address must be done AFTER calling
 * mii_init_phy() for that PHY, with the exception of mii_phyexists()
 *
 * mii_rsan() will not accept mii_wait_interrupt as a wait type. Its futile to
 * expect autonegotiation to happen fast enough. (You're better off using the
 * port monitor to tell you, asynchronously that the link has been
 * re-established than waiting at all.)
 */

/*
 * MII programming Interface types
 */

enum mii_phy_state {phy_state_unknown, phy_state_linkup, phy_state_linkdown};
enum mii_wait_type {mii_wait_none, mii_wait_user, mii_wait_interrupt};
typedef ushort_t (*mii_readfunc_t)(dev_info_t *, int phy, int reg);
typedef void (*mii_writefunc_t)(dev_info_t *, int phy, int reg, int value);
typedef void (*mii_linkfunc_t)(dev_info_t *, int phy, enum mii_phy_state state);

struct mii_info;	/* Private to MII! */
typedef struct mii_info *mii_handle_t;

/*
 * Entrypoints
 */

int mii_create(dev_info_t *, mii_writefunc_t, mii_readfunc_t, mii_handle_t *);
			/* Initialise the PHY interface */

int mii_init_phy(mii_handle_t, int phy);
			/* Initialise a PHY */

int mii_getspeed(mii_handle_t, int phy, int *speed, int *full_duplex);
			/* Check operating speed of PHY */

int mii_probe_phy(mii_handle_t, int phy);
			/* Check if PHY exists at an address */

int mii_rsan(mii_handle_t mac, int phy, enum mii_wait_type wait_type);
					/* Restart autonegotiation */

int mii_fixspeed(mii_handle_t, int phy, int speed, int fullduplex);
			/* Fix speed and duplex mode of PHY (disable autoneg) */

int mii_autoneg_enab(mii_handle_t mac, int phy);
			/* (re-)enable autonegotiation */

int mii_reset_phy(mii_handle_t, int phy, enum mii_wait_type wait_type);
			/* Force PHY to reset itself */

int mii_disable_fullduplex(mii_handle_t, int phy);
			/* Stop the PHY advertising full duplex capability */

int mii_linkup(mii_handle_t, int phy);
			/* Check link status on a phy */

int mii_sync(mii_handle_t, int phy);
			/* Sync API if something may have affected the PHY */

int mii_isolate(mii_handle_t, int phy);
			/* Electrically isolate a PHY */

int mii_unisolate(mii_handle_t, int phy);
			/* Unisolate */

int mii_dump_phy(mii_handle_t, int phy);
			/* Dump register contents */

int mii_start_portmon(mii_handle_t mac, mii_linkfunc_t func, kmutex_t *lock);
			/* Monitor initialised PHYs for link state changes */

int mii_stop_portmon(mii_handle_t mac);
			/* Stop port monitor */

void mii_destroy(mii_handle_t mac);
			/* Cleanup MII interface */

/*
 * Errorcodes
 */
#define	MII_SUCCESS 0
#define	MII_PHYPRESENT 1	/* PHY already exists at specified address */
#define	MII_NOMEM 2		/* Not enough memory */
#define	MII_PARAM 3		/* parameters passed are incorrect */
#define	MII_NOTSUPPORTED 4	/* operation not supported by hardware. */
#define	MII_STATE 5		/* The request is not valid at this time. */
#define	MII_HARDFAIL 6		/* The hardware is not functioning correctly */
#define	MII_TIMEOUT 7		/* Timeout waiting for operation to complete */
#define	MII_PHYNOTPRESENT 8	/* There is no PHY at the specified address */

/* Vendor Specific functions */
typedef void (*phy_genfunc)(mii_handle_t, int phy);
typedef int (*phy_getspeedfunc)(mii_handle_t, int phy, int *speed, int *fd);

/* per-PHY information. */
struct phydata
{
	ulong_t id;			/* ID from MII registers 2,3 */
	char *description;		/* Text description from ID */
	phy_genfunc phy_dump;		/* how to dump registers this make */
	phy_genfunc phy_postreset;	/* What to do after a reset (or init) */
	phy_getspeedfunc phy_getspeed;	/* how to find current speed */
	unsigned short control;		/* Bits that need to be written ...  */
					/* ...to control register */
	enum mii_phy_state state;	/* Current state of link at this PHY */
	int fix_speed;			/* Speed fixed in conf file */
	int fix_duplex;
	/*
	 * ^^NEEDSWORK: We can only fix speed for the driver, never mind a
	 * particular PHY on a particular instance, but this is where this
	 * belongs.
	 */
};

typedef struct mii_info
{
	mii_readfunc_t mii_read;	/* How to read an MII register */
	mii_writefunc_t mii_write;	/* How to write an MII register */
	mii_linkfunc_t mii_linknotify;	/* What to do when link state changes */
	dev_info_t *mii_dip;		/* MAC's devinfo */
	timeout_id_t portmon_timer;	/* ID of timer for the port monitor */
	kmutex_t *lock;			/* Lock to serialise mii calls */
	struct phydata *phys[32];	/* PHY Information indexed by address */
} mii_info_t;

#define	OUI_NATIONAL_SEMICONDUCTOR 0x80017
#define	NS_DP83840		0x00
#define	MII_83840_ADDR		25
#define	NS83840_ADDR_SPEED10	(1<<6)
#define	NS83840_ADDR_CONSTAT	(1<<5)
#define	NS83840_ADDR_ADDR	(0x1f<<0)

#define	OUI_INTEL		0x0aa00
#define	INTEL_82553_CSTEP	0x35	/* A and B steps are non-standard */
#define	MII_82553_EX0		16
#define	I82553_EX0_FDUPLEX	(1<<0)
#define	I82553_EX0_100MB	(1<<1)
#define	I82553_EX0_WAKE		(1<<2)
#define	I82553_EX0_SQUELCH	(3<<3) /* 3:4 */
#define	I82553_EX0_REVCNTR	(7<<5) /* 5:7 */
#define	I82553_EX0_FRCFAIL	(1<<8)
#define	I82553_EX0_TEST		(0x1f<<9) /* 13:9 */
#define	I82553_EX0_LINKDIS	(1<<14)
#define	I82553_EX0_JABDIS	(1<<15)

#define	MII_82553_EX1
#define	I82553_EX1_RESERVE	(0x1ff<<0) /* 0:8 */
#define	I82553_EX1_CH2EOF	(1<<9)
#define	I82553_EX1_MNCHSTR	(1<<10)
#define	I82553_EX1_EOP		(1<<11)
#define	I82553_EX1_BADCODE	(1<<12)
#define	I82553_EX1_INVALCODE	(1<<13)
#define	I82553_EX1_DCBALANCE	(1<<14)
#define	I82553_EX1_PAIRSKEW	(1<<15)

#define	INTEL_82555		0x15
#define	INTEL_82562_EH		0x33
#define	INTEL_82562_ET		0x32
#define	INTEL_82562_EM		0x31

#define	OUI_ICS			0x57d
#define	ICS_1890		2
#define	ICS_1889		1
#define	ICS_EXCTRL		16
#define	ICS_EXCTRL_CMDOVRD	(1<<15)
#define	ICS_EXCTRL_PHYADDR	(0x1f<<6)
#define	ICS_EXCTRL_SCSTEST	(1<<5)
#define	ICS_EXCTRL_INVECTEST	(1<<2)
#define	ICS_EXCTRL_SCDISABLE	(1<<0)

#define	ICS_QUICKPOLL		17
#define	ICS_QUICKPOLL_100MB	(1<<15)
#define	ICS_QUICKPOLL_FDUPLEX	(1<<14)
#define	ICS_QUICKPOLL_ANPROG	(7<<11)
#define	ICS_QUICKPOLL_RSE	(1<<10)
#define	ICS_QUICKPOLL_PLLLOCK	(1<<9)
#define	ICS_QUICKPOLL_FALSECD	(1<<8)
#define	ICS_QUICKPOLL_SYMINVAL	(1<<7)
#define	ICS_QUICKPOLL_SYMHALT	(1<<6)
#define	ICS_QUICKPOLL_PREMEND	(1<<5)
#define	ICS_QUICKPOLL_ANDONE	(1<<4)
#define	ICS_QUICKPOLL_RESERVED	(1<<3)
#define	ICS_QUICKPOLL_JABBER	(1<<2)
#define	ICS_QUICKPOLL_REMFAULT	(1<<1)
#define	ICS_QUICKPOLL_LINKSTAT	(1<<0)

#define	ICS_10BASET		18
#define	ICS_10BASET_REMJABBER	(1<<15)
#define	ICS_10BASET_REVPOLARITY (1<<14)
#define	ICS_10BASET_RESERVED	(0xff<<6)
#define	ICS_10BASET_NOJABBER	(1<<5)
#define	ICS_10BASET_NORMLOOP	(1<<4)
#define	ICS_10BASET_NOAUTOPOLL	(1<<3)
#define	ICS_10BASET_NOSQE	(1<<2)
#define	ICS_10BASET_NOLINKLOSS	(1<<1)
#define	ICS_10BASET_NOSQUELCH	(1<<0)

#define	ICS_EXCTRL2		19
#define	ICS_EXCTRL2_ISREPEATER	(1<<15)
#define	ICS_EXCTRL2_SOFTPRI	(1<<14)
#define	ICS_EXCTRL2_LPCANREMF	(1<<13)
#define	ICS_EXCTRL2_RMFSXMITED	(1<<10)
#define	ICS_EXCTRL2_ANPWRREMF	(1<<4)
#define	ICS_EXCTRL2_10BASETQUAL (1<<2)
#define	ICS_EXCTRL2_AUTOPWRDN	(1<<0)

#endif /* _DNET_MII_H */
