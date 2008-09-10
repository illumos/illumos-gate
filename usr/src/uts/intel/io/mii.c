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
 * mii - MII/PHY support for MAC drivers
 *
 * Utility module to provide a consistent interface to a MAC driver accross
 * different implementations of PHY devices
 */

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/devops.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/mii.h>
#include <sys/miipriv.h>
#include <sys/miiregs.h>

#ifdef DEBUG
#define	MIIDEBUG
int miidebug = 0;
#define	MIITRACE 1
#define	MIIDUMP 2
#define	MIIPROBE 4
#define	MIICOMPAT 8
#endif

/* Local functions */
static struct phydata *mii_get_valid_phydata(mii_handle_t mac, int phy);
static void mii_portmon(mii_handle_t mac);

/* Vendor specific callback function prototypes */
static void dump_NS83840(mii_handle_t, int);
static void dump_ICS1890(struct mii_info *, int);
static int getspeed_NS83840(mii_handle_t, int, int *, int *);
static int getspeed_82553(mii_handle_t, int, int *, int *);
static int getspeed_ICS1890(mii_handle_t, int, int *, int *);
static int getspeed_generic(mii_handle_t, int, int *, int *);
static void postreset_ICS1890(mii_handle_t mac, int phy);
static void postreset_NS83840(mii_handle_t mac, int phy);

#ifdef MII_IS_MODULE
/*
 * Loadable module structures/entrypoints
 */

extern struct mod_ops mod_misc_ops;

static struct modlmisc modlmisc = {
	&mod_miscops,
	"802.3u MII support",
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlmisc, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
#endif

/*
 * MII Interface functions
 */

/*
 * Register an instance of an MII interface user
 */

int
mii_create(dev_info_t *dip,		/* Passed to read/write functions */
	    mii_writefunc_t writefunc, 	/* How to write to a MII register */
	    mii_readfunc_t readfunc,	/* How to read from a MII regster */
	    mii_handle_t *macp)
{
	mii_handle_t mac;

	/*  Allocate space for the mii structure */
	if ((mac = (mii_handle_t)
	    kmem_zalloc(sizeof (struct mii_info), KM_NOSLEEP)) == NULL)
		return (MII_NOMEM);

	mac->mii_write = writefunc;
	mac->mii_read = readfunc;
	mac->mii_dip = dip;
	*macp = mac;
	return (MII_SUCCESS);
}

/*
 * Returns true if PHY at address phy is accessible. This should be
 * considered the only function that takes a PHY address that can be called
 * before mii_init_phy. There should be at least one bit set in the status
 * register, and at least one clear
 */
int
mii_probe_phy(mii_handle_t mac, int phy)
{
	ushort_t status;
	dev_info_t *dip;

	if (!mac || phy < 0 || phy > 31)
		return (MII_PARAM);

	dip = mac->mii_dip;

	/* Clear any latched bits by reading twice */
	mac->mii_read(dip, phy, MII_STATUS);
	status = mac->mii_read(dip, phy, MII_STATUS);

#ifdef MIIDEBUG
	mac->mii_read(dip, phy, MII_CONTROL);
	if (miidebug & MIIPROBE)
		cmn_err(CE_NOTE, "PHY Probe: Control=%x, Status=%x",
			mac->mii_read(dip, phy, MII_CONTROL), status);
#endif
	/*
	 * At least one bit in status should be clear (one of the error
	 * bits), and there must be at least one bit set for the device
	 * capabilities. Unconnected devices tend to show 0xffff, but 0x0000
	 * has been seen.
	 */

	if (status == 0xffff || status == 0x0000)
		return (MII_PHYNOTPRESENT);
	return (MII_SUCCESS);
}

/*
 * Initialise PHY, and store info about it in the handle for future
 * reference when the MAC calls us. PHY Vendor-specific code here isolates
 * the LAN driver from worrying about different PHY implementations
 */

int
mii_init_phy(mii_handle_t mac, int phy)
{
	ushort_t status;
	void *dip;
	struct phydata *phydata;

	if ((mac == (mii_handle_t)NULL) || phy < 0 || phy > 31)
		return (MII_PARAM);

	dip = mac->mii_dip;

	/* Create a phydata structure for this new phy */
	if (mac->phys[phy])
		return (MII_PHYPRESENT);

	mac->phys[phy] = phydata = (struct phydata *)
			    kmem_zalloc(sizeof (struct phydata), KM_NOSLEEP);

	if (!phydata)
		return (MII_NOMEM);

	phydata->id = (ulong_t)mac->mii_read(dip, phy, MII_PHYIDH) << 16;
	phydata->id |= (ulong_t)mac->mii_read(dip, phy, MII_PHYIDL);
	phydata->state = phy_state_unknown;

	/* Override speed and duplex mode from conf-file if present */
	phydata->fix_duplex =
	    ddi_getprop(DDI_DEV_T_NONE,
	    mac->mii_dip, DDI_PROP_DONTPASS, "full-duplex", 0);

	phydata->fix_speed =
	    ddi_getprop(DDI_DEV_T_NONE,
	    mac->mii_dip, DDI_PROP_DONTPASS, "speed", 0);

	status = mac->mii_read(dip, phy, MII_STATUS);

	/*
	 * when explicitly setting speed or duplex, we must
	 * disable autonegotiation
	 */
	if (!(status & MII_STATUS_CANAUTONEG) ||
	    phydata->fix_speed || phydata->fix_duplex) {
		/*
		 * If local side cannot autonegotiate, we can't try to enable
		 * full duplex without the user's consent, because we cannot
		 * tell without AN if the partner can support it
		 */
		if ((status & (MII_STATUS_100_BASEX | MII_STATUS_100_BASEX_FD |
		    MII_STATUS_100_BASE_T4)) && phydata->fix_speed == 0) {
			phydata->fix_speed = 100;
		} else if ((status & (MII_STATUS_10 | MII_STATUS_10_FD)) &&
		    phydata->fix_speed == 0) {
			phydata->fix_speed = 10;
		} else if (phydata->fix_speed == 0) {
			/* A very stupid PHY would not be supported */
			kmem_free(mac->phys[phy], sizeof (struct phydata));
			mac->phys[phy] = NULL;
			return (MII_NOTSUPPORTED);
		}
		/* mii_sync will sort out the speed selection on the PHY */
	} else
		phydata->control = MII_CONTROL_ANE;

	switch (PHY_MANUFACTURER(phydata->id)) {
	case OUI_NATIONAL_SEMICONDUCTOR:
		switch (PHY_MODEL(phydata->id)) {
		case NS_DP83840:
			phydata->phy_postreset = postreset_NS83840;
			phydata->phy_dump = dump_NS83840;
			phydata->description =
				"National Semiconductor DP-83840";
			phydata->phy_getspeed = getspeed_NS83840;
			break;
		default:
			phydata->description = "Unknown NS";
			break;
		}
		break;

	case OUI_INTEL:
		switch (PHY_MODEL(phydata->id)) {
		case INTEL_82553_CSTEP:
			phydata->description = "Intel 82553 C-step";
			phydata->phy_getspeed = getspeed_82553;
			break;
		case INTEL_82555:
			phydata->description = "Intel 82555";
			phydata->phy_getspeed = getspeed_82553;
			break;
		case INTEL_82562_EH:
			phydata->description = "Intel 82562 EH";
			phydata->phy_getspeed = getspeed_82553;
			break;
		case INTEL_82562_ET:
			phydata->description = "Intel 82562 ET";
			phydata->phy_getspeed = getspeed_82553;
			break;
		case INTEL_82562_EM:
			phydata->description = "Intel 82562 EM";
			phydata->phy_getspeed = getspeed_82553;
			break;
		default:
			phydata->description = "Unknown INTEL";
			break;
		}
		break;

	case OUI_ICS:
		switch (PHY_MODEL(phydata->id)) {
		case ICS_1890:
		case ICS_1889:
			phydata->phy_postreset = postreset_ICS1890;
			phydata->description = "ICS 1890/1889 PHY";
			phydata->phy_getspeed = getspeed_ICS1890;
			phydata->phy_dump = dump_ICS1890;
			break;
		default:
			phydata->description = "ICS Unknown PHY";
			break;
		}
		break;

	default: /* Non-standard PHYs, that encode weird IDs */
		phydata->description = "Unknown PHY";
		phydata->phy_dump = NULL;
		phydata->phy_getspeed = getspeed_generic;
		break;
	}

	/* Do all post-reset hacks and user settings */
	(void) mii_sync(mac, phy);

	if (ddi_getprop(DDI_DEV_T_NONE, mac->mii_dip, DDI_PROP_DONTPASS,
	    "dump-phy", 0))
		(void) mii_dump_phy(mac, phy);

	return (MII_SUCCESS);
}

/*
 * Cause a reset on a PHY
 */

int
mii_reset_phy(mii_handle_t mac, int phy, enum mii_wait_type wait)
{
	int i;
	struct phydata *phyd;
	ushort_t control;
	if (!(phyd = mii_get_valid_phydata(mac, phy)))
		return (MII_PARAM);

	/* Strobe the reset bit in the control register */
	mac->mii_write(mac->mii_dip, phy, MII_CONTROL,
			phyd->control | MII_CONTROL_RESET);

	phyd->state = phy_state_unknown;

	/*
	 * This is likely to be very fast (ie, by the time we read the
	 * control register once, the devices we have seen can have already
	 * reset), but according to 802.3u 22.2.4.1.1, it could be up to .5 sec.
	 */
	if (wait == mii_wait_interrupt || wait == mii_wait_user) {
		for (i = 100; i--; ) {
			control = mac->mii_read(mac->mii_dip, phy, MII_CONTROL);
			if (!(control & MII_CONTROL_RESET))
				break;
			drv_usecwait(10);
		}
		if (i)
			goto reset_completed;
	}

	if (wait == mii_wait_user) {
		for (i = 50; i--; ) {
			control = mac->mii_read(mac->mii_dip, phy, MII_CONTROL);
			if (!(control & MII_CONTROL_RESET))
				break;
			delay(drv_usectohz(10000));
		}
		if (i)
			goto reset_completed;
		return (MII_HARDFAIL);	/* It MUST reset within this time */

	}
	return (MII_TIMEOUT);

reset_completed:
	(void) mii_sync(mac, phy);
	return (MII_SUCCESS);
}

/*
 * This routine is called to synchronise the software and the PHY. It should
 * be called after the PHY is reset, and after initialising the PHY. This
 * routine is external because devices (DNET) can reset the PHY in ways beyond
 * the control of the mii interface. Should this happen, the driver is
 * required to call mii_sync().
 * If the PHY is resetting still when this is called, it will do nothing,
 * but, it will be retriggered when the portmon timer expires.
 */

int
mii_sync(mii_handle_t mac, int phy)
{
	struct phydata *phyd = mac->phys[phy];
	int len, i, numprop;
	struct regprop {
		int reg;
		int value;
	} *regprop;

#ifdef MIIDEBUG
	if (miidebug & MIITRACE)
		cmn_err(CE_NOTE, "mii_sync (phy addr %d)", phy);
#endif

	len = 0;
	/*
	 * Conf file can specify a sequence of values to write to
	 * the PHY registers if required
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, mac->mii_dip,
	    DDI_PROP_DONTPASS, "phy-registers", (caddr_t)&regprop,
	    &len) == DDI_PROP_SUCCESS) {
		numprop = len / sizeof (struct regprop);
		for (i = 0; i < numprop; i++) {
			mac->mii_write(mac->mii_dip, phy,
			    regprop[i].reg, regprop[i].value);
#ifdef MIIDEBUG
			if (miidebug & MIITRACE)
				cmn_err(CE_NOTE, "PHY Write reg %d=%x",
				    regprop[i].reg, regprop[i].value);
#endif
		}
		kmem_free(regprop, len);
	} else {
		mac->mii_write(mac->mii_dip, phy, MII_CONTROL, phyd->control);
		if (phyd->phy_postreset)
			phyd->phy_postreset(mac, phy);
		if (phyd->fix_speed || phyd->fix_duplex) {
			/* XXX function return value ignored */
			(void) mii_fixspeed(mac, phy, phyd->fix_speed,
			    phyd->fix_duplex);
		}
	}
	return (MII_SUCCESS);
}

/*
 * Disable full-duplex negotiation on the PHY. This is useful if the
 * driver or link-partner is advertising full duplex, but does not support
 * it properly (as some previous solaris drivers didn't)
 */

int
mii_disable_fullduplex(mii_handle_t mac, int phy)
{
	void *dip = mac->mii_dip;
	ushort_t expansion,  miiadvert;
	/* dont advertise full duplex capabilites */
	const int fullduplex = MII_ABILITY_10BASE_T_FD
				| MII_ABILITY_100BASE_TX_FD;

	if (!(mac->mii_read(dip, phy, MII_STATUS) & MII_STATUS_CANAUTONEG)) {
		/*
		 * Local side cannot autonegotiate, so full duplex should
		 * never be negotiated. Consider it as a success
		 */
		return (MII_SUCCESS);
	}

	/* Change what we advertise if it includes full duplex */

	miiadvert = mac->mii_read(dip, phy, MII_AN_ADVERT);
	if (miiadvert & fullduplex)
		mac->mii_write(dip, phy, MII_AN_ADVERT,
				miiadvert & ~fullduplex);

	/* See what other end is able to do.  */

	expansion = mac->mii_read(dip, phy, MII_AN_EXPANSION);

	/*
	 * Renegotiate if the link partner supports autonegotiation
	 * If it doesn't, we will never have auto-negotiated full duplex
	 * anyway
	 */

	if (expansion & MII_AN_EXP_LPCANAN)
		return (mii_rsan(mac, phy, mii_wait_none));
	else
		return (MII_SUCCESS);
}

/*
 * (re)enable autonegotiation on a PHY.
 */

int
mii_autoneg_enab(mii_handle_t mac, int phy)
{
	struct phydata *phyd;
	if (!(phyd = mii_get_valid_phydata(mac, phy)))
		return (MII_PARAM);
	phyd->control |= MII_CONTROL_ANE;
	mac->mii_write(mac->mii_dip, phy, MII_CONTROL, phyd->control);
	return (MII_SUCCESS);
}

/*
 * Check the link status of a PHY connection
 */
int
mii_linkup(mii_handle_t mac, int phy)
{
	ushort_t status;

	/*
	 * Link status latches, so we need to read it twice, to make sure we
	 * get its current status
	 */
	mac->mii_read(mac->mii_dip, phy, MII_STATUS);
	status = mac->mii_read(mac->mii_dip, phy, MII_STATUS);

	if (status != 0xffff && (status & MII_STATUS_LINKUP))
		return (1);
	else
		return (0);
}

/*
 * Discover what speed the PHY is running at, irrespective of wheather it
 * autonegotiated this, or was fixed at that rate.
 */

int
mii_getspeed(mii_handle_t mac, int phy, int *speed, int *fulld)
{
	struct phydata *phyd;

	if (!(phyd = mii_get_valid_phydata(mac, phy)))
		return (MII_PARAM);
	if (!(phyd->control & MII_CONTROL_ANE)) {
		/*
		 * user has requested fixed speed operation, return what we
		 * wrote to the control registerfrom control register
		 */

		*speed = phyd->control & MII_CONTROL_100MB ? 100:10;
		*fulld = phyd->control & MII_CONTROL_FDUPLEX ? 1:0;
		return (MII_SUCCESS);
	}

	if (!phyd->phy_getspeed) /* No standard way to do this(!) */
		return (MII_NOTSUPPORTED);

	return (phyd->phy_getspeed(mac, phy, speed, fulld));
}

/*
 * Fix the speed and duplex mode of a PHY
 */

int
mii_fixspeed(mii_handle_t mac, int phy, int speed, int fullduplex)
{
	struct phydata *phyd;

#ifdef MIIDEBUG
	cmn_err(CE_CONT, "!%s: setting speed to %d, %s duplex",
			ddi_get_name(mac->mii_dip), speed,
			fullduplex ? "full" : "half");
#endif

	if (!(phyd = mii_get_valid_phydata(mac, phy)))
		return (MII_PARAM);
	phyd->control &= ~MII_CONTROL_ANE;

	if (speed == 100)
		phyd->control |= MII_CONTROL_100MB;
	else if (speed == 10)
		phyd->control &= ~MII_CONTROL_100MB;
	else
		cmn_err(CE_NOTE, "%s: mii does not support %d Mb/s speed",
			ddi_get_name(mac->mii_dip), speed);

	if (fullduplex)
		phyd->control |= MII_CONTROL_FDUPLEX;
	else
		phyd->control &= ~MII_CONTROL_FDUPLEX;

	mac->mii_write(mac->mii_dip, phy, MII_CONTROL, phyd->control);
	phyd->fix_speed = speed;
	phyd->fix_duplex = fullduplex;
	return (MII_SUCCESS);
}
/*
 * Electrically isolate/unisolate the PHY
 */

int
mii_isolate(mii_handle_t mac, int phy)
{
	struct phydata *phyd;

	if (!(phyd = mii_get_valid_phydata(mac, phy)))
		return (MII_PARAM);

	phyd->control |= MII_CONTROL_ISOLATE;
	mac->mii_write(mac->mii_dip, phy, MII_CONTROL, phyd->control);

	/* Wait for device to settle */
	drv_usecwait(50);
	return (MII_SUCCESS);
}

int
mii_unisolate(mii_handle_t mac, int phy)
{
	struct phydata *phyd;

	if (!(phyd = mii_get_valid_phydata(mac, phy)))
		return (MII_PARAM);

	phyd->control &= ~MII_CONTROL_ISOLATE;
	mac->mii_write(mac->mii_dip, phy, MII_CONTROL, phyd->control);
	return (MII_SUCCESS);
}

/*
 * Restart autonegotiation on a PHY
 */

int
mii_rsan(mii_handle_t mac, int phy, enum mii_wait_type wait)
{
	int i;
	void *dip;
	struct phydata *phyd;

	if (wait == mii_wait_interrupt ||
	    !(phyd = mii_get_valid_phydata(mac, phy)))
		return (MII_PARAM);

	if (phyd->fix_speed)
		return (MII_STATE);

	dip = mac->mii_dip;

	phyd->control |= MII_CONTROL_ANE;
	mac->mii_write(dip, phy, MII_CONTROL, phyd->control|MII_CONTROL_RSAN);

	/*
	 * This can take ages (a second or so). It makes more sense to use
	 * the port monitor rather than waiting for completion of this on the
	 * PHY. It is pointless doing a busy wait here
	 */

	if (wait == mii_wait_user) {
		for (i = 200; i--; ) {
			delay(drv_usectohz(10000));
			if (mac->mii_read(dip, phy, MII_STATUS) &
			    MII_STATUS_ANDONE)
				return (MII_SUCCESS);
		}
		cmn_err(CE_NOTE,
		    "!%s:Timed out waiting for autonegotiation",
		    ddi_get_name(mac->mii_dip));
		return (MII_TIMEOUT);
	}
	return (MII_TIMEOUT);
}

/*
 * Debuging function to dump contents of PHY registers
 */
int
mii_dump_phy(mii_handle_t mac, int phy)
{
	struct phydata *phydat;

	char *miiregs[] = {
		"Control             ",
		"Status              ",
		"PHY Id(H)           ",
		"PHY Id(L)           ",
		"Advertisement       ",
		"Link Partner Ability",
		"Expansion           ",
		"Next Page Transmit  ",
		0
	};
	int i;

	if (!(phydat = mii_get_valid_phydata(mac, phy)))
		return (MII_PARAM);

	cmn_err(CE_NOTE, "%s: PHY %d, type %s", ddi_get_name(mac->mii_dip), phy,
	    phydat->description ? phydat->description: "Unknown");

	for (i = 0; miiregs[i]; i++)
		cmn_err(CE_NOTE, "%s:\t%x",
		    miiregs[i], mac->mii_read(mac->mii_dip, phy, i));

	if (phydat->phy_dump)
		phydat->phy_dump((struct mii_info *)mac, phy);

	return (MII_SUCCESS);
}

/*
 * Start a periodic check to monitor the MII devices attached, and callback
 * to the MAC driver when the state on a device changes
 */

int
mii_start_portmon(mii_handle_t mac, mii_linkfunc_t notify, kmutex_t *lock)
{
	if (mac->mii_linknotify || mac->portmon_timer)
		return (MII_STATE);
	mac->mii_linknotify = notify;
	/*
	 * NOTE: Portmon is normally called through a timeout. In the case
	 * of starting off, we assume that the lock is already held
	 */
	mac->lock = NULL; /* portmon wont try to aquire any lock this time */
	mii_portmon(mac);
	mac->lock = lock;
	return (MII_SUCCESS);
}

int
mii_stop_portmon(mii_handle_t mac)
{
	if (!mac->mii_linknotify || !mac->portmon_timer)
		return (MII_STATE);

	mac->mii_linknotify = NULL;
	mac->lock = NULL;
	(void) untimeout(mac->portmon_timer);
	mac->portmon_timer = 0;
	return (MII_SUCCESS);
}

static void
mii_portmon(mii_handle_t mac)
{
	int i;
	enum mii_phy_state state;
	struct phydata *phydata;

	/*
	 * There is a potential deadlock between this test and the
	 * mutex_enter
	 */
	if (!mac->mii_linknotify) /* Exiting */
		return;

	if (mac->lock)
		mutex_enter(mac->lock);

	/*
	 * For each initialised phy, see if the link state has changed, and
	 * callback to the mac driver if it has
	 */
	for (i = 0; i < 32; i++) {
		if ((phydata = mac->phys[i]) != 0) {
			state = mii_linkup(mac, i) ?
				phy_state_linkup : phy_state_linkdown;
			if (state != phydata->state) {
#ifdef MIIDEBUG
				if (miidebug)
					cmn_err(CE_NOTE, "%s: PHY %d link %s",
					    ddi_get_name(mac->mii_dip), i,
					    state == phy_state_linkup ?
						"up" : "down");
#endif
				phydata->state = state;
				mac->mii_linknotify(mac->mii_dip, i, state);
			}
		}
	}
	/* Check the ports every 5 seconds */
	mac->portmon_timer = timeout((void (*)(void*))mii_portmon, (void *)mac,
				    (clock_t)(5 * drv_usectohz(1000000)));
	if (mac->lock)
		mutex_exit(mac->lock);
}

/*
 * Close a handle to the MII interface from a registered user
 */

void
mii_destroy(mii_handle_t mac)
{
	/* Free per-PHY information */
	int i;

	(void) mii_stop_portmon(mac);

	for (i = 0; i < 32; i++)
		if (mac->phys[i])
			kmem_free(mac->phys[i], sizeof (struct phydata));

	kmem_free(mac, sizeof (*mac));
}

/*
 * Get a PHY data structure from an MII handle, and validate the common
 * parameters to the MII functions. Used to verify parameters in most MII
 * functions
 */
static struct phydata *
mii_get_valid_phydata(mii_handle_t mac, int phy)
{
	if (!mac || phy > 31 || phy < 0 || !mac->phys[phy]) {
		ASSERT(!"MII: Bad invocation");
		return (NULL);
	}
	return (mac->phys[phy]);
}
/*
 * Device-specific routines - National Semiconductor
 */

#define	BIT(bit, value) ((value) & (1<<(bit)))
static void
dump_NS83840(mii_handle_t mac, int phy)
{
	ushort_t reg;
	void *dip;

	dip = mac->mii_dip;
	cmn_err(CE_NOTE, "Disconnect count: %x",
				mac->mii_read(dip, phy, 0x12));
	cmn_err(CE_NOTE, "False Carrier detect count: %x",
				mac->mii_read(dip, phy, 0x13));
	cmn_err(CE_NOTE, "Receive error count: %x",
				mac->mii_read(dip, phy, 0x15));
	cmn_err(CE_NOTE, "Silicon revision: %x",
				mac->mii_read(dip, phy, 0x16));
	cmn_err(CE_NOTE, "PCS Configuration : %x",
				mac->mii_read(dip, phy, 0x17));

	cmn_err(CE_NOTE, "Loopback, Bypass and Receiver error mask: %x",
				mac->mii_read(dip, phy, 0x18));
	cmn_err(CE_NOTE, "Wired phy address: %x",
				mac->mii_read(dip, phy, 0x19)&0xf);

	reg = mac->mii_read(dip, phy, 0x1b);
	cmn_err(CE_NOTE, "10 Base T in %s mode",
				BIT(9, reg) ? "serial":"nibble");

	cmn_err(CE_NOTE, "%slink pulses, %sheartbeat, %s,%s squelch,jabber %s",
				BIT(reg, 5) ? "" : "no ",
				BIT(reg, 4) ? "" : "no ",
				BIT(reg, 3) ? "UTP" : "STP",
				BIT(reg, 2) ? "low" : "normal",
				BIT(reg, 0) ? "enabled" : "disabled");
}

static int
getspeed_NS83840(mii_handle_t mac, int phy, int *speed, int *fulld)
{
	int exten =  mac->mii_read(mac->mii_dip, phy, MII_AN_EXPANSION);
	if (exten & MII_AN_EXP_LPCANAN) {
		/*
		 * Link partner can auto-neg, take speed from LP Ability
		 * register
		 */
		int lpable, anadv, mask;

		lpable = mac->mii_read(mac->mii_dip, phy, MII_AN_LPABLE);
		anadv = mac->mii_read(mac->mii_dip, phy, MII_AN_ADVERT);
		mask = anadv & lpable;

		if (mask & MII_ABILITY_100BASE_TX_FD) {
			*speed = 100;
			*fulld = 1;
		} else if (mask & MII_ABILITY_100BASE_T4) {
			*speed = 100;
			*fulld = 0;
		} else if (mask & MII_ABILITY_100BASE_TX) {
			*speed = 100;
			*fulld = 0;
		} else if (mask & MII_ABILITY_10BASE_T_FD) {
			*speed = 10;
			*fulld = 1;
		} else if (mask & MII_ABILITY_10BASE_T) {
			*speed = 10;
			*fulld = 0;
		}
	} else {
		int addr = mac->mii_read(mac->mii_dip, phy, MII_83840_ADDR);
		*speed = (addr & NS83840_ADDR_SPEED10) ? 10:100;
		/* No fullduplex without autonegotiation on link partner */
		*fulld = 0;
	}
	return (0);
}

/*
 * Device-specific routines - INTEL
 */

static int
getspeed_82553(mii_handle_t mac, int phy, int *speed, int *fulld)
{
	int ex0 = mac->mii_read(mac->mii_dip, phy, MII_82553_EX0);
	*fulld = (ex0 & I82553_EX0_FDUPLEX) ? 1:0;
	*speed = (ex0 & I82553_EX0_100MB) ? 100:10;
	return (0);
}

/*
 * Device-specific routines - ICS
 */

static int
getspeed_ICS1890(mii_handle_t mac, int phy, int *speed, int *fulld)
{
	ushort_t quickpoll = mac->mii_read(mac->mii_dip, phy, ICS_QUICKPOLL);
	*speed = (quickpoll & ICS_QUICKPOLL_100MB) ? 100 : 10;
	*fulld = (quickpoll & ICS_QUICKPOLL_FDUPLEX) ? 1 : 0;
	return (0);
}

static void
dump_ICS1890(mii_handle_t mac, int phy)
{
	ushort_t quickpoll = mac->mii_read(mac->mii_dip, phy, ICS_QUICKPOLL);
	cmn_err(CE_NOTE, "QuickPoll:%x (Speed:%d FullDuplex:%c) ",
				quickpoll,
				quickpoll & ICS_QUICKPOLL_100MB ? 100:10,
				quickpoll & ICS_QUICKPOLL_FDUPLEX ? 'Y' : 'N');
}

static void
postreset_NS83840(mii_handle_t mac, int phy)
{
	ushort_t reg;
	struct phydata *phyd = mac->phys[phy];
	/*
	 * As per INTEL "PRO/100B Adapter Software Technical
	 * Reference Manual", set bit 10 of MII register 23.
	 * National Semiconductor documentation shows this as
	 * "reserved, write to as zero". We also set the
	 * "f_connect" bit, also as requested by the PRO/100B
	 * doc
	 */

	reg = mac->mii_read(mac->mii_dip, phy, 23) | (1<<10) | (1<<5);
	mac->mii_write(mac->mii_dip, phy, 23, reg);

	/*
	 * Some of thses PHYs seem to reset with the wrong value in the
	 * AN advertisment register. It should containt 1e1, indicating that
	 * the device can do 802.3 10BASE-T, 10BASE-T Full duplex, 100BASE-TX,
	 * and 100 BASE-TX full duplex. Instead it seems to advertise only
	 * 100BASE-TX Full duplex. The result of this is that the device will
	 * NOT autonegotiate at all against a 10MB only or 100MB/Half duplex
	 * autonegotiating hub
	 * NEEDSWORK:
	 * There is possibly a time-dependancy here.
	 * If the autonegotiation has completed BEFORE we get to here
	 * (after the reset) then this could possibly have not effect
	 */
	if (!phyd->fix_speed) {
#ifdef MIIDEBUG
		if (miidebug & MIICOMPAT)
			cmn_err(CE_NOTE, "Reset value of AN_ADV reg:%x",
			    mac->mii_read(mac->mii_dip, phy, MII_AN_ADVERT));
#endif
		mac->mii_write(mac->mii_dip, phy, MII_AN_ADVERT, 0x1e1);
	}
}

void
postreset_ICS1890(mii_handle_t mac, int phy)
{
	/* This device comes up isolated if no link is found */
	(void) mii_unisolate(mac, phy);
}

/*
 * generic getspeed routine
 */
static int
getspeed_generic(mii_handle_t mac, int phy, int *speed, int *fulld)
{
	int exten =  mac->mii_read(mac->mii_dip, phy, MII_AN_EXPANSION);
	if (exten & MII_AN_EXP_LPCANAN) {
		/*
		 * Link partner can auto-neg, take speed from LP Ability
		 * register
		 */
		int lpable, anadv, mask;

		lpable = mac->mii_read(mac->mii_dip, phy, MII_AN_LPABLE);
		anadv = mac->mii_read(mac->mii_dip, phy, MII_AN_ADVERT);
		mask = anadv & lpable;

		if (mask & MII_ABILITY_100BASE_TX_FD) {
			*speed = 100;
			*fulld = 1;
		} else if (mask & MII_ABILITY_100BASE_T4) {
			*speed = 100;
			*fulld = 0;
		} else if (mask & MII_ABILITY_100BASE_TX) {
			*speed = 100;
			*fulld = 0;
		} else if (mask & MII_ABILITY_10BASE_T_FD) {
			*speed = 10;
			*fulld = 1;
		} else if (mask & MII_ABILITY_10BASE_T) {
			*speed = 10;
			*fulld = 0;
		}
	} else {
		/*
		 * Link partner cannot auto-neg, it would be nice if we
		 * could figure out what the device selected.  (NWay?)
		 */
		*speed = 0;
		*fulld = 0;
	}
	return (MII_SUCCESS);
}
