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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/policy.h>
#include <sys/note.h>
#include <sys/strsun.h>
#include <sys/miiregs.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/mii.h>
#include "miipriv.h"

#define	MII_SECOND	1000000

/* indices into error array */
enum {
	MII_EOK = 0,
	MII_ERESET,
	MII_ESTART,
	MII_ENOPHY,
	MII_ECHECK,
	MII_ELOOP,
};

static const char *mii_errors[] = {
	"",
	"Failure resetting PHY.",
	"Failure starting PHY.",
	"No Ethernet PHY found.",
	"Failure reading PHY (removed?)",
	"Failure setting loopback."
};

/* Indexed by XCVR_ type */
static const const char *mii_xcvr_types[] = {
	"Undefined",
	"Unknown",
	"10 Mbps",
	"100BASE-T4",
	"100BASE-X",
	"100BASE-T2",
	"1000BASE-X",
	"1000BASE-T"
};

/* state machine */
typedef enum {
	MII_STATE_PROBE = 0,
	MII_STATE_RESET,
	MII_STATE_START,
	MII_STATE_RUN,
	MII_STATE_LOOPBACK,
} mii_tstate_t;

struct mii_handle {
	dev_info_t	*m_dip;
	void		*m_private;
	mii_ops_t	m_ops;

	kt_did_t	m_tq_id;
	kmutex_t	m_lock;
	kcondvar_t	m_cv;
	ddi_taskq_t	*m_tq;
	int		m_flags;

	boolean_t	m_started;
	boolean_t	m_suspending;
	boolean_t	m_suspended;
	int		m_error;
	mii_tstate_t	m_tstate;

#define	MII_FLAG_EXIT		0x1	/* exit the thread */
#define	MII_FLAG_STOP		0x2	/* shutdown MII monitoring */
#define	MII_FLAG_RESET		0x4	/* reset the MII */
#define	MII_FLAG_PROBE		0x8	/* probe for PHYs */
#define	MII_FLAG_NOTIFY		0x10	/* notify about a change */
#define	MII_FLAG_SUSPEND	0x20	/* monitoring suspended */
#define	MII_FLAG_MACRESET	0x40	/* send reset to MAC */
#define	MII_FLAG_PHYSTART	0x80	/* start up the PHY */

	/* device name for printing, e.g. "hme0" */
	char		m_name[MODMAXNAMELEN + 16];

	int		m_addr;
	phy_handle_t	m_phys[32];
	phy_handle_t	m_bogus_phy;
	phy_handle_t	*m_phy;

	link_state_t	m_link;

	/* these start out undefined, but get values due to mac_prop_set */
	int		m_en_aneg;
	int		m_en_10_hdx;
	int		m_en_10_fdx;
	int		m_en_100_t4;
	int		m_en_100_hdx;
	int		m_en_100_fdx;
	int		m_en_1000_hdx;
	int		m_en_1000_fdx;
	int		m_en_flowctrl;

	boolean_t	m_cap_pause;
	boolean_t	m_cap_asmpause;
};


static void _mii_task(void *);
static void _mii_probe_phy(phy_handle_t *);
static void _mii_probe(mii_handle_t);
static int _mii_reset(mii_handle_t);
static int _mii_loopback(mii_handle_t);
static void _mii_notify(mii_handle_t);
static int _mii_check(mii_handle_t);
static int _mii_start(mii_handle_t);

/*
 * Loadable module structures/entrypoints
 */

extern struct mod_ops mod_misc_ops;

static struct modlmisc modlmisc = {
	&mod_miscops,
	"802.3 MII support",
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

void
_mii_error(mii_handle_t mh, int errno)
{
	/*
	 * This dumps an error message, but it avoids filling the log with
	 * repeated error messages.
	 */
	if (mh->m_error != errno) {
		cmn_err(CE_WARN, "%s: %s", mh->m_name, mii_errors[errno]);
		mh->m_error = errno;
	}
}

/*
 * Known list of specific PHY probes.
 */
typedef boolean_t (*phy_probe_t)(phy_handle_t *);
phy_probe_t _phy_probes[] = {
	phy_natsemi_probe,
	phy_intel_probe,
	phy_qualsemi_probe,
	phy_cicada_probe,
	phy_marvell_probe,
	phy_realtek_probe,
	phy_other_probe,
	NULL
};

/*
 * MII Interface functions
 */

mii_handle_t
mii_alloc_instance(void *private, dev_info_t *dip, int inst, mii_ops_t *ops)
{
	mii_handle_t	mh;
	char		tqname[16];

	if (ops->mii_version != MII_OPS_VERSION) {
		cmn_err(CE_WARN, "%s: incompatible MII version (%d)",
		    ddi_driver_name(dip), ops->mii_version);
		return (NULL);
	}
	mh = kmem_zalloc(sizeof (*mh), KM_SLEEP);

	(void) snprintf(mh->m_name, sizeof (mh->m_name), "%s%d",
	    ddi_driver_name(dip), inst);

	/* DDI will prepend the driver name */
	(void) snprintf(tqname, sizeof (tqname), "mii%d", inst);

	mh->m_dip = dip;
	mh->m_ops = *ops;
	mh->m_private = private;
	mh->m_suspended = B_FALSE;
	mh->m_started = B_FALSE;
	mh->m_tstate = MII_STATE_PROBE;
	mh->m_link = LINK_STATE_UNKNOWN;
	mh->m_error = MII_EOK;
	mh->m_addr = -1;
	mutex_init(&mh->m_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&mh->m_cv, NULL, CV_DRIVER, NULL);

	mh->m_tq = ddi_taskq_create(dip, tqname, 1, TASKQ_DEFAULTPRI, 0);
	if (mh->m_tq == NULL) {
		cmn_err(CE_WARN, "%s: unable to create MII monitoring task",
		    ddi_driver_name(dip));
		cv_destroy(&mh->m_cv);
		mutex_destroy(&mh->m_lock);
		kmem_free(mh, sizeof (*mh));
		return (NULL);
	}

	/*
	 * Initialize user prefs by loading properties.  Ultimately,
	 * Brussels interfaces would be superior here.
	 */
#define	GETPROP(name)	ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, name, -1)
	mh->m_en_aneg = GETPROP("adv_autoneg_cap");
	mh->m_en_10_hdx = GETPROP("adv_10hdx_cap");
	mh->m_en_10_fdx = GETPROP("adv_10fdx_cap");
	mh->m_en_100_hdx = GETPROP("adv_100hdx_cap");
	mh->m_en_100_fdx = GETPROP("adv_100fdx_cap");
	mh->m_en_100_t4 = GETPROP("adv_100T4_cap");
	mh->m_en_1000_hdx = GETPROP("adv_1000hdx_cap");
	mh->m_en_1000_fdx = GETPROP("adv_1000fdx_cap");

	mh->m_cap_pause = B_FALSE;
	mh->m_cap_asmpause = B_FALSE;

	bzero(&mh->m_bogus_phy, sizeof (mh->m_bogus_phy));
	mh->m_bogus_phy.phy_link = LINK_STATE_UNKNOWN;
	mh->m_bogus_phy.phy_duplex = LINK_DUPLEX_UNKNOWN;
	mh->m_bogus_phy.phy_addr = 0xff;
	mh->m_bogus_phy.phy_type = XCVR_NONE;
	mh->m_bogus_phy.phy_id = (uint32_t)-1;
	mh->m_bogus_phy.phy_loopback = PHY_LB_NONE;
	mh->m_bogus_phy.phy_flowctrl = LINK_FLOWCTRL_NONE;
	mh->m_phy = &mh->m_bogus_phy;

	for (int i = 0; i < 32; i++) {
		mh->m_phys[i].phy_mii = mh;
	}
	mh->m_bogus_phy.phy_mii = mh;

	return (mh);
}

mii_handle_t
mii_alloc(void *private, dev_info_t *dip, mii_ops_t *ops)
{
	return (mii_alloc_instance(private, dip, ddi_get_instance(dip), ops));
}

void
mii_set_pauseable(mii_handle_t mh, boolean_t pauseable, boolean_t asymetric)
{
	phy_handle_t	*ph;

	mutex_enter(&mh->m_lock);
	ph = mh->m_phy;
	ph->phy_cap_pause = mh->m_cap_pause = pauseable;
	ph->phy_cap_asmpause = mh->m_cap_asmpause = asymetric;
	if (pauseable) {
		mh->m_en_flowctrl = LINK_FLOWCTRL_BI;
	} else {
		mh->m_en_flowctrl = LINK_FLOWCTRL_NONE;
	}
	mutex_exit(&mh->m_lock);
}

void
mii_free(mii_handle_t mh)
{
	mutex_enter(&mh->m_lock);
	mh->m_started = B_FALSE;
	cv_broadcast(&mh->m_cv);
	mutex_exit(&mh->m_lock);

	ddi_taskq_destroy(mh->m_tq);
	mutex_destroy(&mh->m_lock);
	cv_destroy(&mh->m_cv);
	kmem_free(mh, sizeof (*mh));
}

void
mii_reset(mii_handle_t mh)
{
	mutex_enter(&mh->m_lock);
	if (mh->m_tstate > MII_STATE_RESET)
		mh->m_tstate = MII_STATE_RESET;
	cv_broadcast(&mh->m_cv);
	mutex_exit(&mh->m_lock);
}

void
mii_suspend(mii_handle_t mh)
{
	mutex_enter(&mh->m_lock);
	while ((!mh->m_suspended) && (mh->m_started)) {
		mh->m_suspending = B_TRUE;
		cv_broadcast(&mh->m_cv);
		cv_wait(&mh->m_cv, &mh->m_lock);
	}
	mutex_exit(&mh->m_lock);
}

void
mii_resume(mii_handle_t mh)
{
	mutex_enter(&mh->m_lock);

	switch (mh->m_tstate) {
	case MII_STATE_PROBE:
		break;
	case MII_STATE_RESET:
	case MII_STATE_START:
	case MII_STATE_RUN:
		/* let monitor thread deal with this */
		mh->m_tstate = MII_STATE_RESET;
		break;

	case MII_STATE_LOOPBACK:
		/* loopback is handled synchronously */
		(void) _mii_loopback(mh);
		break;
	}

	mh->m_suspended = B_FALSE;
	cv_broadcast(&mh->m_cv);
	mutex_exit(&mh->m_lock);
}

void
mii_start(mii_handle_t mh)
{
	mutex_enter(&mh->m_lock);
	if (!mh->m_started) {
		mh->m_tstate = MII_STATE_PROBE;
		mh->m_started = B_TRUE;
		if (ddi_taskq_dispatch(mh->m_tq, _mii_task, mh, DDI_NOSLEEP) !=
		    DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "%s: unable to start MII monitoring task",
			    mh->m_name);
			mh->m_started = B_FALSE;
		}
	}
	cv_broadcast(&mh->m_cv);
	mutex_exit(&mh->m_lock);
}

void
mii_stop(mii_handle_t mh)
{
	mutex_enter(&mh->m_lock);
	mh->m_started = B_FALSE;
	/*
	 * Reset link state to unknown defaults, since we're not
	 * monitoring it anymore.  We'll reprobe all link state later.
	 */
	mh->m_link = LINK_STATE_UNKNOWN;
	mh->m_phy = &mh->m_bogus_phy;
	cv_broadcast(&mh->m_cv);
	mutex_exit(&mh->m_lock);
	/*
	 * Notify the MAC driver.  This will allow it to call back
	 * into the MAC framework to clear any previous link state.
	 */
	_mii_notify(mh);
}

void
mii_probe(mii_handle_t mh)
{
	mutex_enter(&mh->m_lock);
	_mii_probe(mh);
	mutex_exit(&mh->m_lock);
}

void
mii_check(mii_handle_t mh)
{
	mutex_enter(&mh->m_lock);
	cv_broadcast(&mh->m_cv);
	mutex_exit(&mh->m_lock);
}

int
mii_get_speed(mii_handle_t mh)
{
	phy_handle_t	*ph = mh->m_phy;

	return (ph->phy_speed);
}

link_duplex_t
mii_get_duplex(mii_handle_t mh)
{
	phy_handle_t	*ph = mh->m_phy;

	return (ph->phy_duplex);
}

link_state_t
mii_get_state(mii_handle_t mh)
{
	phy_handle_t	*ph = mh->m_phy;

	return (ph->phy_link);
}

link_flowctrl_t
mii_get_flowctrl(mii_handle_t mh)
{
	phy_handle_t	*ph = mh->m_phy;

	return (ph->phy_flowctrl);
}

int
mii_get_loopmodes(mii_handle_t mh, lb_property_t *modes)
{
	phy_handle_t	*ph = mh->m_phy;
	int		cnt = 0;
	lb_property_t	lmodes[MII_LOOPBACK_MAX];

	lmodes[cnt].lb_type = normal;
	(void) strlcpy(lmodes[cnt].key, "normal", sizeof (lmodes[cnt].key));
	lmodes[cnt].value = PHY_LB_NONE;
	cnt++;

	if (ph->phy_cap_1000_fdx ||
	    ph->phy_cap_100_fdx ||
	    ph->phy_cap_10_fdx) {
		/* we only support full duplex internal phy testing */
		lmodes[cnt].lb_type = internal;
		(void) strlcpy(lmodes[cnt].key, "PHY",
		    sizeof (lmodes[cnt].key));
		lmodes[cnt].value = PHY_LB_INT_PHY;
		cnt++;
	}

	if (ph->phy_cap_1000_fdx) {
		lmodes[cnt].lb_type = external;
		(void) strlcpy(lmodes[cnt].key, "1000Mbps",
		    sizeof (lmodes[cnt].key));
		lmodes[cnt].value = PHY_LB_EXT_1000;
		cnt++;
	}

	if (ph->phy_cap_100_fdx) {
		lmodes[cnt].lb_type = external;
		(void) strlcpy(lmodes[cnt].key, "100Mbps",
		    sizeof (lmodes[cnt].key));
		lmodes[cnt].value = PHY_LB_EXT_100;
		cnt++;
	}

	if (ph->phy_cap_10_fdx) {
		lmodes[cnt].lb_type = external;
		(void) strlcpy(lmodes[cnt].key, "10Mbps",
		    sizeof (lmodes[cnt].key));
		lmodes[cnt].value = PHY_LB_EXT_10;
		cnt++;
	}

	if (modes) {
		bcopy(lmodes, modes, sizeof (lb_property_t) * cnt);
	}

	return (cnt);
}

uint32_t
mii_get_loopback(mii_handle_t mh)
{
	phy_handle_t	*ph = mh->m_phy;

	return (ph->phy_loopback);
}

int
mii_set_loopback(mii_handle_t mh, uint32_t loop)
{
	phy_handle_t	*ph;
	int		rv;

	mutex_enter(&mh->m_lock);
	ph = mh->m_phy;

	if ((!mh->m_started) || (!ph->phy_present) ||
	    (loop >= mii_get_loopmodes(mh, NULL))) {
		return (EINVAL);
	}

	ph->phy_loopback = loop;
	rv = _mii_loopback(mh);
	if (rv == DDI_SUCCESS) {
		mh->m_tstate = MII_STATE_LOOPBACK;
	}
	cv_broadcast(&mh->m_cv);
	mutex_exit(&mh->m_lock);

	return (rv == DDI_SUCCESS ? 0 : EIO);
}

uint32_t
mii_get_id(mii_handle_t mh)
{
	phy_handle_t	*ph = mh->m_phy;

	return (ph->phy_id);
}

int
mii_get_addr(mii_handle_t mh)
{
	return (mh->m_addr);
}

/* GLDv3 helpers */

boolean_t
mii_m_loop_ioctl(mii_handle_t mh, queue_t *wq, mblk_t *mp)
{
	struct iocblk	*iocp;
	int		rv = 0;
	int		cnt;
	lb_property_t	modes[MII_LOOPBACK_MAX];
	lb_info_sz_t	sz;
	int		cmd;
	uint32_t	mode;

	iocp = (void *)mp->b_rptr;
	cmd = iocp->ioc_cmd;

	switch (cmd) {
	case LB_SET_MODE:
	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
	case LB_GET_MODE:
		break;

	default:
		return (B_FALSE);
	}

	if (mp->b_cont == NULL) {
		miocnak(wq, mp, 0, EINVAL);
		return (B_TRUE);
	}

	switch (cmd) {
	case LB_GET_INFO_SIZE:
		cnt = mii_get_loopmodes(mh, modes);
		if (iocp->ioc_count != sizeof (sz)) {
			rv = EINVAL;
		} else {
			sz = cnt * sizeof (lb_property_t);
			bcopy(&sz, mp->b_cont->b_rptr, sizeof (sz));
		}
		break;

	case LB_GET_INFO:
		cnt = mii_get_loopmodes(mh, modes);
		if (iocp->ioc_count != (cnt * sizeof (lb_property_t))) {
			rv = EINVAL;
		} else {
			bcopy(modes, mp->b_cont->b_rptr, iocp->ioc_count);
		}
		break;

	case LB_GET_MODE:
		if (iocp->ioc_count != sizeof (mode)) {
			rv = EINVAL;
		} else {
			mode = mii_get_loopback(mh);
			bcopy(&mode, mp->b_cont->b_rptr, sizeof (mode));
		}
		break;

	case LB_SET_MODE:
		rv = secpolicy_net_config(iocp->ioc_cr, B_FALSE);
		if (rv != 0)
			break;
		if (iocp->ioc_count != sizeof (mode)) {
			rv = EINVAL;
			break;
		}
		bcopy(mp->b_cont->b_rptr, &mode, sizeof (mode));
		rv = mii_set_loopback(mh, mode);
		break;
	}

	if (rv == 0) {
		miocack(wq, mp, iocp->ioc_count, 0);
	} else {
		miocnak(wq, mp, 0, rv);
	}
	return (B_TRUE);
}

int
mii_m_getprop(mii_handle_t mh, const char *name, mac_prop_id_t num,
    uint_t sz, void *val)
{
	phy_handle_t	*ph;
	int		err = 0;

	_NOTE(ARGUNUSED(name));

	if (sz < 1)
		return (EINVAL);

	mutex_enter(&mh->m_lock);

	ph = mh->m_phy;

#define	CASE_PROP_ABILITY(PROP, VAR)					\
	case MAC_PROP_ADV_##PROP:					\
		*(uint8_t *)val = ph->phy_adv_##VAR;			\
		break;							\
									\
	case MAC_PROP_EN_##PROP:					\
		*(uint8_t *)val = ph->phy_en_##VAR;			\
		break;

	switch (num) {
	case MAC_PROP_DUPLEX:
		ASSERT(sz >= sizeof (link_duplex_t));
		bcopy(&ph->phy_duplex, val, sizeof (link_duplex_t));
		break;

	case MAC_PROP_SPEED: {
		uint64_t speed = ph->phy_speed * 1000000ull;
		ASSERT(sz >= sizeof (uint64_t));
		bcopy(&speed, val, sizeof (speed));
		break;
	}

	case MAC_PROP_AUTONEG:
		*(uint8_t *)val = ph->phy_adv_aneg;
		break;

	case MAC_PROP_FLOWCTRL:
		ASSERT(sz >= sizeof (link_flowctrl_t));
		bcopy(&ph->phy_flowctrl, val, sizeof (link_flowctrl_t));
		break;

	CASE_PROP_ABILITY(1000FDX_CAP, 1000_fdx)
	CASE_PROP_ABILITY(1000HDX_CAP, 1000_hdx)
	CASE_PROP_ABILITY(100T4_CAP, 100_t4)
	CASE_PROP_ABILITY(100FDX_CAP, 100_fdx)
	CASE_PROP_ABILITY(100HDX_CAP, 100_hdx)
	CASE_PROP_ABILITY(10FDX_CAP, 10_fdx)
	CASE_PROP_ABILITY(10HDX_CAP, 10_hdx)

	default:
		err = ENOTSUP;
		break;
	}

	mutex_exit(&mh->m_lock);

	return (err);
}

void
mii_m_propinfo(mii_handle_t mh, const char *name, mac_prop_id_t num,
    mac_prop_info_handle_t prh)
{
	phy_handle_t	*ph;

	_NOTE(ARGUNUSED(name));

	mutex_enter(&mh->m_lock);

	ph = mh->m_phy;

	switch (num) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_AUTONEG:
		mac_prop_info_set_default_uint8(prh, ph->phy_cap_aneg);
		break;

#define	CASE_PROP_PERM(PROP, VAR)					\
	case MAC_PROP_ADV_##PROP:					\
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);	\
		mac_prop_info_set_default_uint8(prh, ph->phy_cap_##VAR); \
		break;							\
									\
	case MAC_PROP_EN_##PROP:					\
		if (!ph->phy_cap_##VAR)					\
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ); \
		mac_prop_info_set_default_uint8(prh, ph->phy_cap_##VAR); \
		break;

	CASE_PROP_PERM(1000FDX_CAP, 1000_fdx)
	CASE_PROP_PERM(1000HDX_CAP, 1000_hdx)
	CASE_PROP_PERM(100T4_CAP, 100_t4)
	CASE_PROP_PERM(100FDX_CAP, 100_fdx)
	CASE_PROP_PERM(100HDX_CAP, 100_hdx)
	CASE_PROP_PERM(10FDX_CAP, 10_fdx)
	CASE_PROP_PERM(10HDX_CAP, 10_hdx)
	}

	mutex_exit(&mh->m_lock);
}

int
mii_m_setprop(mii_handle_t mh, const char *name, mac_prop_id_t num,
    uint_t sz, const void *valp)
{
	phy_handle_t	*ph;
	boolean_t	*advp = NULL;
	boolean_t	*capp = NULL;
	int		*macpp = NULL;
	int		rv = ENOTSUP;

	_NOTE(ARGUNUSED(name));

	if (sz < 1)
		return (EINVAL);

	mutex_enter(&mh->m_lock);

	ph = mh->m_phy;

	/* we don't support changing parameters while in loopback mode */
	if (ph->phy_loopback != PHY_LB_NONE) {
		switch (num) {
		case MAC_PROP_EN_1000FDX_CAP:
		case MAC_PROP_EN_1000HDX_CAP:
		case MAC_PROP_EN_100FDX_CAP:
		case MAC_PROP_EN_100HDX_CAP:
		case MAC_PROP_EN_100T4_CAP:
		case MAC_PROP_EN_10FDX_CAP:
		case MAC_PROP_EN_10HDX_CAP:
		case MAC_PROP_AUTONEG:
		case MAC_PROP_FLOWCTRL:
			return (EBUSY);
		}
	}

	switch (num) {
	case MAC_PROP_EN_1000FDX_CAP:
		capp = &ph->phy_cap_1000_fdx;
		advp = &ph->phy_en_1000_fdx;
		macpp = &mh->m_en_1000_fdx;
		break;
	case MAC_PROP_EN_1000HDX_CAP:
		capp = &ph->phy_cap_1000_hdx;
		advp = &ph->phy_en_1000_hdx;
		macpp = &mh->m_en_1000_hdx;
		break;
	case MAC_PROP_EN_100FDX_CAP:
		capp = &ph->phy_cap_100_fdx;
		advp = &ph->phy_en_100_fdx;
		macpp = &mh->m_en_100_fdx;
		break;
	case MAC_PROP_EN_100HDX_CAP:
		capp = &ph->phy_cap_100_hdx;
		advp = &ph->phy_en_100_hdx;
		macpp = &mh->m_en_100_hdx;
		break;
	case MAC_PROP_EN_100T4_CAP:
		capp = &ph->phy_cap_100_t4;
		advp = &ph->phy_en_100_t4;
		macpp = &mh->m_en_100_t4;
		break;
	case MAC_PROP_EN_10FDX_CAP:
		capp = &ph->phy_cap_10_fdx;
		advp = &ph->phy_en_10_fdx;
		macpp = &mh->m_en_10_fdx;
		break;
	case MAC_PROP_EN_10HDX_CAP:
		capp = &ph->phy_cap_10_hdx;
		advp = &ph->phy_en_10_hdx;
		macpp = &mh->m_en_10_hdx;
		break;
	case MAC_PROP_AUTONEG:
		capp = &ph->phy_cap_aneg;
		advp = &ph->phy_en_aneg;
		macpp = &mh->m_en_aneg;
		break;
	case MAC_PROP_FLOWCTRL: {
		link_flowctrl_t	fc;
		boolean_t chg;

		ASSERT(sz >= sizeof (link_flowctrl_t));
		bcopy(valp, &fc, sizeof (fc));

		chg = fc == ph->phy_en_flowctrl ? B_FALSE : B_TRUE;
		switch (fc) {
		case LINK_FLOWCTRL_NONE:
			ph->phy_en_pause = B_FALSE;
			ph->phy_en_asmpause = B_FALSE;
			ph->phy_en_flowctrl = fc;
			break;
		/*
		 * Note that while we don't have a way to advertise
		 * that we can RX pause (we just won't send pause
		 * frames), we advertise full support.  The MAC driver
		 * will learn of the configuration via the saved value
		 * of the tunable.
		 */
		case LINK_FLOWCTRL_BI:
		case LINK_FLOWCTRL_RX:
			if (ph->phy_cap_pause) {
				ph->phy_en_pause = B_TRUE;
				ph->phy_en_asmpause = B_TRUE;
				ph->phy_en_flowctrl = fc;
			} else {
				rv = EINVAL;
			}
			break;

		/*
		 * Tell the other side that we can assert pause, but
		 * we cannot resend.
		 */
		case LINK_FLOWCTRL_TX:
			if (ph->phy_cap_asmpause) {
				ph->phy_en_pause = B_FALSE;
				ph->phy_en_flowctrl = fc;
				ph->phy_en_asmpause = B_TRUE;
			} else {
				rv = EINVAL;
			}
			break;
		default:
			rv = EINVAL;
			break;
		}
		if ((rv == 0) && chg) {
			mh->m_en_flowctrl = fc;
			mh->m_tstate = MII_STATE_RESET;
			cv_broadcast(&mh->m_cv);
		}
		break;
	}

	default:
		rv = ENOTSUP;
		break;
	}

	if (capp && advp && macpp) {
		if (sz < sizeof (uint8_t)) {
			rv = EINVAL;

		} else if (*capp) {
			if (*advp != *(uint8_t *)valp) {
				*advp = *(uint8_t *)valp;
				*macpp = *(uint8_t *)valp;
				mh->m_tstate = MII_STATE_RESET;
				cv_broadcast(&mh->m_cv);
			}
			rv = 0;
		}
	}

	mutex_exit(&mh->m_lock);
	return (rv);
}

int
mii_m_getstat(mii_handle_t mh, uint_t stat, uint64_t *val)
{
	phy_handle_t	*ph;
	int		rv = 0;

	mutex_enter(&mh->m_lock);

	ph = mh->m_phy;

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = ph->phy_speed * 1000000ull;
		break;
	case ETHER_STAT_LINK_DUPLEX:
		*val = ph->phy_duplex;
		break;
	case ETHER_STAT_LINK_AUTONEG:
		*val = !!(ph->phy_adv_aneg && ph->phy_lp_aneg);
		break;
	case ETHER_STAT_XCVR_ID:
		*val = ph->phy_id;
		break;
	case ETHER_STAT_XCVR_INUSE:
		*val = ph->phy_type;
		break;
	case ETHER_STAT_XCVR_ADDR:
		*val = ph->phy_addr;
		break;
	case ETHER_STAT_LINK_ASMPAUSE:
		*val = ph->phy_adv_asmpause && ph->phy_lp_asmpause &&
		    ph->phy_adv_pause != ph->phy_lp_pause;
		break;
	case ETHER_STAT_LINK_PAUSE:
		*val = (ph->phy_flowctrl == LINK_FLOWCTRL_BI) ||
		    (ph->phy_flowctrl == LINK_FLOWCTRL_RX);
		break;
	case ETHER_STAT_CAP_1000FDX:
		*val = ph->phy_cap_1000_fdx;
		break;
	case ETHER_STAT_CAP_1000HDX:
		*val = ph->phy_cap_1000_hdx;
		break;
	case ETHER_STAT_CAP_100FDX:
		*val = ph->phy_cap_100_fdx;
		break;
	case ETHER_STAT_CAP_100HDX:
		*val = ph->phy_cap_100_hdx;
		break;
	case ETHER_STAT_CAP_10FDX:
		*val = ph->phy_cap_10_fdx;
		break;
	case ETHER_STAT_CAP_10HDX:
		*val = ph->phy_cap_10_hdx;
		break;
	case ETHER_STAT_CAP_100T4:
		*val = ph->phy_cap_100_t4;
		break;
	case ETHER_STAT_CAP_AUTONEG:
		*val = ph->phy_cap_aneg;
		break;
	case ETHER_STAT_CAP_PAUSE:
		*val = ph->phy_cap_pause;
		break;
	case ETHER_STAT_CAP_ASMPAUSE:
		*val = ph->phy_cap_asmpause;
		break;

	case ETHER_STAT_LP_CAP_1000FDX:
		*val = ph->phy_lp_1000_fdx;
		break;
	case ETHER_STAT_LP_CAP_1000HDX:
		*val = ph->phy_lp_1000_hdx;
		break;
	case ETHER_STAT_LP_CAP_100FDX:
		*val = ph->phy_lp_100_fdx;
		break;
	case ETHER_STAT_LP_CAP_100HDX:
		*val = ph->phy_lp_100_hdx;
		break;
	case ETHER_STAT_LP_CAP_10FDX:
		*val = ph->phy_lp_10_fdx;
		break;
	case ETHER_STAT_LP_CAP_10HDX:
		*val = ph->phy_lp_10_hdx;
		break;
	case ETHER_STAT_LP_CAP_100T4:
		*val = ph->phy_lp_100_t4;
		break;
	case ETHER_STAT_LP_CAP_AUTONEG:
		*val = ph->phy_lp_aneg;
		break;
	case ETHER_STAT_LP_CAP_PAUSE:
		*val = ph->phy_lp_pause;
		break;
	case ETHER_STAT_LP_CAP_ASMPAUSE:
		*val = ph->phy_lp_asmpause;
		break;

	case ETHER_STAT_ADV_CAP_1000FDX:
		*val = ph->phy_adv_1000_fdx;
		break;
	case ETHER_STAT_ADV_CAP_1000HDX:
		*val = ph->phy_adv_1000_hdx;
		break;
	case ETHER_STAT_ADV_CAP_100FDX:
		*val = ph->phy_adv_100_fdx;
		break;
	case ETHER_STAT_ADV_CAP_100HDX:
		*val = ph->phy_adv_100_hdx;
		break;
	case ETHER_STAT_ADV_CAP_10FDX:
		*val = ph->phy_adv_10_fdx;
		break;
	case ETHER_STAT_ADV_CAP_10HDX:
		*val = ph->phy_adv_10_hdx;
		break;
	case ETHER_STAT_ADV_CAP_100T4:
		*val = ph->phy_adv_100_t4;
		break;
	case ETHER_STAT_ADV_CAP_AUTONEG:
		*val = ph->phy_adv_aneg;
		break;
	case ETHER_STAT_ADV_CAP_PAUSE:
		*val = ph->phy_adv_pause;
		break;
	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		*val = ph->phy_adv_asmpause;
		break;

	default:
		rv = ENOTSUP;
		break;
	}
	mutex_exit(&mh->m_lock);

	return (rv);
}

/*
 * PHY support routines.  Private to the MII module and the vendor
 * specific PHY implementation code.
 */
uint16_t
phy_read(phy_handle_t *ph, uint8_t reg)
{
	mii_handle_t	mh = ph->phy_mii;

	return ((*mh->m_ops.mii_read)(mh->m_private, ph->phy_addr, reg));
}

void
phy_write(phy_handle_t *ph, uint8_t reg, uint16_t val)
{
	mii_handle_t	mh = ph->phy_mii;

	(*mh->m_ops.mii_write)(mh->m_private, ph->phy_addr, reg, val);
}

int
phy_reset(phy_handle_t *ph)
{
	ASSERT(mutex_owned(&ph->phy_mii->m_lock));

	/*
	 * For our device, make sure its powered up and unisolated.
	 */
	PHY_CLR(ph, MII_CONTROL,
	    MII_CONTROL_PWRDN | MII_CONTROL_ISOLATE);

	/*
	 * Finally reset it.
	 */
	PHY_SET(ph, MII_CONTROL, MII_CONTROL_RESET);

	/*
	 * Apparently some devices (DP83840A) like to have a little
	 * bit of a wait before we start accessing anything else on
	 * the PHY.
	 */
	drv_usecwait(500);

	/*
	 * Wait for reset to complete - probably very fast, but no
	 * more than 0.5 sec according to spec.  It would be nice if
	 * we could use delay() here, but MAC drivers may call
	 * functions which hold this lock in interrupt context, so
	 * sleeping would be a definite no-no.  The good news here is
	 * that it seems to be the case that most devices come back
	 * within only a few hundred usec.
	 */
	for (int i = 500000; i; i -= 100) {
		if ((phy_read(ph, MII_CONTROL) & MII_CONTROL_RESET) == 0) {
			/* reset completed */
			return (DDI_SUCCESS);
		}
		drv_usecwait(100);
	}

	return (DDI_FAILURE);
}

int
phy_stop(phy_handle_t *ph)
{
	phy_write(ph, MII_CONTROL, MII_CONTROL_ISOLATE);

	return (DDI_SUCCESS);
}

int
phy_loop(phy_handle_t *ph)
{
	uint16_t	bmcr, gtcr;

	ASSERT(mutex_owned(&ph->phy_mii->m_lock));

	/*
	 * Disable everything to start... we'll add in modes as we go.
	 */
	ph->phy_adv_aneg = B_FALSE;
	ph->phy_adv_1000_fdx = B_FALSE;
	ph->phy_adv_1000_hdx = B_FALSE;
	ph->phy_adv_100_fdx = B_FALSE;
	ph->phy_adv_100_t4 = B_FALSE;
	ph->phy_adv_100_hdx = B_FALSE;
	ph->phy_adv_10_fdx = B_FALSE;
	ph->phy_adv_10_hdx = B_FALSE;
	ph->phy_adv_pause = B_FALSE;
	ph->phy_adv_asmpause = B_FALSE;

	bmcr = 0;
	gtcr = MII_MSCONTROL_MANUAL | MII_MSCONTROL_MASTER;

	switch (ph->phy_loopback) {
	case PHY_LB_NONE:
		/* We shouldn't be here */
		ASSERT(0);
		break;

	case PHY_LB_INT_PHY:
		bmcr |= MII_CONTROL_LOOPBACK;
		ph->phy_duplex = LINK_DUPLEX_FULL;
		if (ph->phy_cap_1000_fdx) {
			bmcr |= MII_CONTROL_1GB | MII_CONTROL_FDUPLEX;
			ph->phy_speed = 1000;
		} else if (ph->phy_cap_100_fdx) {
			bmcr |= MII_CONTROL_100MB | MII_CONTROL_FDUPLEX;
			ph->phy_speed = 100;
		} else if (ph->phy_cap_10_fdx) {
			bmcr |= MII_CONTROL_FDUPLEX;
			ph->phy_speed = 10;
		}
		break;

	case PHY_LB_EXT_10:
		bmcr = MII_CONTROL_FDUPLEX;
		ph->phy_speed = 10;
		ph->phy_duplex = LINK_DUPLEX_FULL;
		break;

	case PHY_LB_EXT_100:
		bmcr = MII_CONTROL_100MB | MII_CONTROL_FDUPLEX;
		ph->phy_speed = 100;
		ph->phy_duplex = LINK_DUPLEX_FULL;
		break;

	case PHY_LB_EXT_1000:
		bmcr = MII_CONTROL_1GB | MII_CONTROL_FDUPLEX;
		ph->phy_speed = 1000;
		ph->phy_duplex = LINK_DUPLEX_FULL;
		break;
	}

	ph->phy_link = LINK_STATE_UP;	/* force up for loopback */
	ph->phy_flowctrl = LINK_FLOWCTRL_NONE;

	switch (ph->phy_type) {
	case XCVR_1000T:
	case XCVR_1000X:
	case XCVR_100T2:
		phy_write(ph, MII_MSCONTROL, gtcr);
		break;
	}

	phy_write(ph, MII_CONTROL, bmcr);

	return (DDI_SUCCESS);
}

int
phy_start(phy_handle_t *ph)
{
	uint16_t	bmcr, anar, gtcr;
	ASSERT(mutex_owned(&ph->phy_mii->m_lock));

	ASSERT(ph->phy_loopback == PHY_LB_NONE);

	/*
	 * No loopback overrides, so try to advertise everything
	 * that is administratively enabled.
	 */
	ph->phy_adv_aneg = ph->phy_en_aneg;
	ph->phy_adv_1000_fdx = ph->phy_en_1000_fdx;
	ph->phy_adv_1000_hdx = ph->phy_en_1000_hdx;
	ph->phy_adv_100_fdx = ph->phy_en_100_fdx;
	ph->phy_adv_100_t4 = ph->phy_en_100_t4;
	ph->phy_adv_100_hdx = ph->phy_en_100_hdx;
	ph->phy_adv_10_fdx = ph->phy_en_10_fdx;
	ph->phy_adv_10_hdx = ph->phy_en_10_hdx;
	ph->phy_adv_pause = ph->phy_en_pause;
	ph->phy_adv_asmpause = ph->phy_en_asmpause;

	/*
	 * Limit properties to what the hardware can actually support.
	 */
#define	FILTER_ADV(CAP)		\
	if (!ph->phy_cap_##CAP)	\
	    ph->phy_adv_##CAP = 0

	FILTER_ADV(aneg);
	FILTER_ADV(1000_fdx);
	FILTER_ADV(1000_hdx);
	FILTER_ADV(100_fdx);
	FILTER_ADV(100_t4);
	FILTER_ADV(100_hdx);
	FILTER_ADV(10_fdx);
	FILTER_ADV(10_hdx);
	FILTER_ADV(pause);
	FILTER_ADV(asmpause);

#undef	FILTER_ADV

	/*
	 * We need at least one valid mode.
	 */
	if ((!ph->phy_adv_1000_fdx) &&
	    (!ph->phy_adv_1000_hdx) &&
	    (!ph->phy_adv_100_t4) &&
	    (!ph->phy_adv_100_fdx) &&
	    (!ph->phy_adv_100_hdx) &&
	    (!ph->phy_adv_10_fdx) &&
	    (!ph->phy_adv_10_hdx)) {

		phy_warn(ph,
		    "No valid link mode selected.  Powering down PHY.");

		PHY_SET(ph, MII_CONTROL, MII_CONTROL_PWRDN);

		ph->phy_link = LINK_STATE_DOWN;
		return (DDI_SUCCESS);
	}

	bmcr = 0;
	gtcr = 0;

	if (ph->phy_adv_aneg) {
		bmcr |= MII_CONTROL_ANE | MII_CONTROL_RSAN;
	}

	if ((ph->phy_adv_1000_fdx) || (ph->phy_adv_1000_hdx)) {
		bmcr |= MII_CONTROL_1GB;

	} else if (ph->phy_adv_100_fdx || ph->phy_adv_100_hdx ||
	    ph->phy_adv_100_t4) {
		bmcr |= MII_CONTROL_100MB;
	}

	if (ph->phy_adv_1000_fdx || ph->phy_adv_100_fdx || ph->phy_adv_10_fdx) {
		bmcr |= MII_CONTROL_FDUPLEX;
	}

	if (ph->phy_type == XCVR_1000X) {
		/* 1000BASE-X (usually fiber) */
		anar = 0;
		if (ph->phy_adv_1000_fdx) {
			anar |= MII_ABILITY_X_FD;
		}
		if (ph->phy_adv_1000_hdx) {
			anar |= MII_ABILITY_X_HD;
		}
		if (ph->phy_adv_pause) {
			anar |= MII_ABILITY_X_PAUSE;
		}
		if (ph->phy_adv_asmpause) {
			anar |= MII_ABILITY_X_ASMPAUSE;
		}

	} else if (ph->phy_type == XCVR_100T2) {
		/* 100BASE-T2 */
		anar = 0;
		if (ph->phy_adv_100_fdx) {
			anar |= MII_ABILITY_T2_FD;
		}
		if (ph->phy_adv_100_hdx) {
			anar |= MII_ABILITY_T2_HD;
		}

	} else {
		anar = MII_AN_SELECTOR_8023;

		/* 1000BASE-T or 100BASE-X probably  */
		if (ph->phy_adv_1000_fdx) {
			gtcr |= MII_MSCONTROL_1000T_FD;
		}
		if (ph->phy_adv_1000_hdx) {
			gtcr |= MII_MSCONTROL_1000T;
		}
		if (ph->phy_adv_100_fdx) {
			anar |= MII_ABILITY_100BASE_TX_FD;
		}
		if (ph->phy_adv_100_hdx) {
			anar |= MII_ABILITY_100BASE_TX;
		}
		if (ph->phy_adv_100_t4) {
			anar |= MII_ABILITY_100BASE_T4;
		}
		if (ph->phy_adv_10_fdx) {
			anar |= MII_ABILITY_10BASE_T_FD;
		}
		if (ph->phy_adv_10_hdx) {
			anar |= MII_ABILITY_10BASE_T;
		}
		if (ph->phy_adv_pause) {
			anar |= MII_ABILITY_PAUSE;
		}
		if (ph->phy_adv_asmpause) {
			anar |= MII_ABILITY_ASMPAUSE;
		}
	}

	ph->phy_link = LINK_STATE_DOWN;
	ph->phy_duplex = LINK_DUPLEX_UNKNOWN;
	ph->phy_speed = 0;

	phy_write(ph, MII_AN_ADVERT, anar);
	phy_write(ph, MII_CONTROL, bmcr & ~(MII_CONTROL_RSAN));

	switch (ph->phy_type) {
	case XCVR_1000T:
	case XCVR_1000X:
	case XCVR_100T2:
		phy_write(ph, MII_MSCONTROL, gtcr);
	}

	/*
	 * Finally, this will start up autoneg if it is enabled, or
	 * force link settings otherwise.
	 */
	phy_write(ph, MII_CONTROL, bmcr);

	return (DDI_SUCCESS);
}


int
phy_check(phy_handle_t *ph)
{
	uint16_t control, status, lpar, msstat, anexp;
	int debounces = 100;

	ASSERT(mutex_owned(&ph->phy_mii->m_lock));

debounce:
	status = phy_read(ph, MII_STATUS);
	control = phy_read(ph, MII_CONTROL);

	if (status & MII_STATUS_EXTENDED) {
		lpar = phy_read(ph, MII_AN_LPABLE);
		anexp = phy_read(ph, MII_AN_EXPANSION);
	} else {
		lpar = 0;
		anexp = 0;
	}

	/*
	 * We reread to clear any latched bits.  This also debounces
	 * any state that might be in transition.
	 */
	drv_usecwait(10);
	if ((status != phy_read(ph, MII_STATUS)) && debounces) {
		debounces--;
		goto debounce;
	}

	/*
	 * Detect the situation where the PHY is removed or has died.
	 * According to spec, at least one bit of status must be set,
	 * and at least one bit must be clear.
	 */
	if ((status == 0xffff) || (status == 0)) {
		ph->phy_speed = 0;
		ph->phy_duplex = LINK_DUPLEX_UNKNOWN;
		ph->phy_link = LINK_STATE_UNKNOWN;
		ph->phy_present = B_FALSE;
		return (DDI_FAILURE);
	}

	/* We only respect the link flag if we are not in loopback. */
	if ((ph->phy_loopback != PHY_LB_INT_PHY) &&
	    ((status & MII_STATUS_LINKUP) == 0)) {
		ph->phy_speed = 0;
		ph->phy_duplex = LINK_DUPLEX_UNKNOWN;
		ph->phy_link = LINK_STATE_DOWN;
		return (DDI_SUCCESS);
	}

	ph->phy_link = LINK_STATE_UP;

	if ((control & MII_CONTROL_ANE) == 0) {

		ph->phy_lp_aneg = B_FALSE;
		ph->phy_lp_10_hdx = B_FALSE;
		ph->phy_lp_10_fdx = B_FALSE;
		ph->phy_lp_100_t4 = B_FALSE;
		ph->phy_lp_100_hdx = B_FALSE;
		ph->phy_lp_100_fdx = B_FALSE;
		ph->phy_lp_1000_hdx = B_FALSE;
		ph->phy_lp_1000_fdx = B_FALSE;

		/*
		 * We have no idea what our link partner might or might
		 * not be able to support, except that it appears to
		 * support the same mode that we have forced.
		 */
		if (control & MII_CONTROL_1GB) {
			ph->phy_speed = 1000;
		} else if (control & MII_CONTROL_100MB) {
			ph->phy_speed = 100;
		} else {
			ph->phy_speed = 10;
		}
		ph->phy_duplex = control & MII_CONTROL_FDUPLEX ?
		    LINK_DUPLEX_FULL : LINK_DUPLEX_HALF;

		return (DDI_SUCCESS);
	}

	if (ph->phy_type == XCVR_1000X) {

		ph->phy_lp_10_hdx = B_FALSE;
		ph->phy_lp_10_fdx = B_FALSE;
		ph->phy_lp_100_t4 = B_FALSE;
		ph->phy_lp_100_hdx = B_FALSE;
		ph->phy_lp_100_fdx = B_FALSE;

		/* 1000BASE-X requires autonegotiation */
		ph->phy_lp_aneg = B_TRUE;
		ph->phy_lp_1000_fdx = !!(lpar & MII_ABILITY_X_FD);
		ph->phy_lp_1000_hdx = !!(lpar & MII_ABILITY_X_HD);
		ph->phy_lp_pause = !!(lpar & MII_ABILITY_X_PAUSE);
		ph->phy_lp_asmpause = !!(lpar & MII_ABILITY_X_ASMPAUSE);

	} else if (ph->phy_type == XCVR_100T2) {
		ph->phy_lp_10_hdx = B_FALSE;
		ph->phy_lp_10_fdx = B_FALSE;
		ph->phy_lp_100_t4 = B_FALSE;
		ph->phy_lp_1000_hdx = B_FALSE;
		ph->phy_lp_1000_fdx = B_FALSE;
		ph->phy_lp_pause = B_FALSE;
		ph->phy_lp_asmpause = B_FALSE;

		/* 100BASE-T2 requires autonegotiation */
		ph->phy_lp_aneg = B_TRUE;
		ph->phy_lp_100_fdx = !!(lpar & MII_ABILITY_T2_FD);
		ph->phy_lp_100_hdx = !!(lpar & MII_ABILITY_T2_HD);

	} else if (anexp & MII_AN_EXP_PARFAULT) {
		/*
		 * Parallel detection fault!  This happens when the
		 * peer does not use autonegotiation, and the
		 * detection logic reports more than one type of legal
		 * link is available.  Note that parallel detection
		 * can only happen with half duplex 10, 100, and
		 * 100TX4.  We also should not have got here, because
		 * the link state bit should have failed.
		 */
#ifdef	DEBUG
		phy_warn(ph, "Parallel detection fault!");
#endif
		ph->phy_lp_10_hdx = B_FALSE;
		ph->phy_lp_10_fdx = B_FALSE;
		ph->phy_lp_100_t4 = B_FALSE;
		ph->phy_lp_100_hdx = B_FALSE;
		ph->phy_lp_100_fdx = B_FALSE;
		ph->phy_lp_1000_hdx = B_FALSE;
		ph->phy_lp_1000_fdx = B_FALSE;
		ph->phy_lp_pause = B_FALSE;
		ph->phy_lp_asmpause = B_FALSE;
		ph->phy_speed = 0;
		ph->phy_duplex = LINK_DUPLEX_UNKNOWN;
		return (DDI_SUCCESS);

	} else {
		ph->phy_lp_aneg = !!(anexp & MII_AN_EXP_LPCANAN);

		/*
		 * Note: If the peer doesn't support autonegotiation, then
		 * according to clause 28.5.4.5, the link partner ability
		 * register will still have the right bits set.  However,
		 * gigabit modes cannot use legacy parallel detection.
		 */

		if ((ph->phy_type == XCVR_1000T) &
		    (anexp & MII_AN_EXP_LPCANAN)) {

			/* check for gige */
			msstat = phy_read(ph, MII_MSSTATUS);

			ph->phy_lp_1000_hdx =
			    !!(msstat & MII_MSSTATUS_LP1000T);

			ph->phy_lp_1000_fdx =
			    !!(msstat & MII_MSSTATUS_LP1000T_FD);
		}

		ph->phy_lp_100_fdx = !!(lpar & MII_ABILITY_100BASE_TX_FD);
		ph->phy_lp_100_hdx = !!(lpar & MII_ABILITY_100BASE_TX);
		ph->phy_lp_100_t4 = !!(lpar & MII_ABILITY_100BASE_T4);
		ph->phy_lp_10_fdx = !!(lpar & MII_ABILITY_10BASE_T_FD);
		ph->phy_lp_10_hdx = !!(lpar & MII_ABILITY_10BASE_T);
		ph->phy_lp_pause = !!(lpar & MII_ABILITY_PAUSE);
		ph->phy_lp_asmpause = !!(lpar & MII_ABILITY_ASMPAUSE);
	}

	/* resolve link pause */
	if ((ph->phy_en_flowctrl == LINK_FLOWCTRL_BI) &&
	    (ph->phy_lp_pause)) {
		ph->phy_flowctrl = LINK_FLOWCTRL_BI;
	} else if ((ph->phy_en_flowctrl == LINK_FLOWCTRL_RX) &&
	    (ph->phy_lp_pause || ph->phy_lp_asmpause)) {
		ph->phy_flowctrl = LINK_FLOWCTRL_RX;
	} else if ((ph->phy_en_flowctrl == LINK_FLOWCTRL_TX) &&
	    (ph->phy_lp_pause)) {
		ph->phy_flowctrl = LINK_FLOWCTRL_TX;
	} else {
		ph->phy_flowctrl = LINK_FLOWCTRL_NONE;
	}

	if (ph->phy_adv_1000_fdx && ph->phy_lp_1000_fdx) {
		ph->phy_speed = 1000;
		ph->phy_duplex = LINK_DUPLEX_FULL;

	} else if (ph->phy_adv_1000_hdx && ph->phy_lp_1000_hdx) {
		ph->phy_speed = 1000;
		ph->phy_duplex = LINK_DUPLEX_HALF;

	} else if (ph->phy_adv_100_fdx && ph->phy_lp_100_fdx) {
		ph->phy_speed = 100;
		ph->phy_duplex = LINK_DUPLEX_FULL;

	} else if (ph->phy_adv_100_t4 && ph->phy_lp_100_t4) {
		ph->phy_speed = 100;
		ph->phy_duplex = LINK_DUPLEX_HALF;

	} else if (ph->phy_adv_100_hdx && ph->phy_lp_100_hdx) {
		ph->phy_speed = 100;
		ph->phy_duplex = LINK_DUPLEX_HALF;

	} else if (ph->phy_adv_10_fdx && ph->phy_lp_10_fdx) {
		ph->phy_speed = 10;
		ph->phy_duplex = LINK_DUPLEX_FULL;

	} else if (ph->phy_adv_10_hdx && ph->phy_lp_10_hdx) {
		ph->phy_speed = 10;
		ph->phy_duplex = LINK_DUPLEX_HALF;

	} else {
#ifdef	DEBUG
		phy_warn(ph, "No common abilities.");
#endif
		ph->phy_speed = 0;
		ph->phy_duplex = LINK_DUPLEX_UNKNOWN;
	}

	return (DDI_SUCCESS);
}

int
phy_get_prop(phy_handle_t *ph, char *prop, int dflt)
{
	mii_handle_t	mh = ph->phy_mii;

	return (ddi_prop_get_int(DDI_DEV_T_ANY, mh->m_dip, 0, prop, dflt));
}

const char *
phy_get_name(phy_handle_t *ph)
{
	mii_handle_t	mh = ph->phy_mii;

	return (mh->m_name);
}

const char *
phy_get_driver(phy_handle_t *ph)
{
	mii_handle_t	mh = ph->phy_mii;

	return (ddi_driver_name(mh->m_dip));
}

void
phy_warn(phy_handle_t *ph, const char *fmt, ...)
{
	va_list	va;
	char buf[256];

	(void) snprintf(buf, sizeof (buf), "%s: %s", phy_get_name(ph), fmt);

	va_start(va, fmt);
	vcmn_err(CE_WARN, buf, va);
	va_end(va);
}

/*
 * Internal support routines.
 */

void
_mii_notify(mii_handle_t mh)
{
	if (mh->m_ops.mii_notify != NULL) {
		mh->m_ops.mii_notify(mh->m_private, mh->m_link);
	}
}

void
_mii_probe_phy(phy_handle_t *ph)
{
	uint16_t	bmsr;
	uint16_t	extsr;
	mii_handle_t	mh = ph->phy_mii;


	/*
	 * Apparently, PHY 0 is less likely to be physically
	 * connected, and should always be the last one tried.  Most
	 * single solution NICs use PHY1 for their built-in
	 * transceiver.  NICs with an external MII will often place
	 * the external PHY at address 1, and use address 0 for the
	 * internal PHY.
	 */

	ph->phy_id = 0;
	ph->phy_model = "PHY";
	ph->phy_vendor = "Unknown Vendor";

	/* done twice to clear any latched bits */
	bmsr = phy_read(ph, MII_STATUS);
	bmsr = phy_read(ph, MII_STATUS);
	if ((bmsr == 0) || (bmsr == 0xffff)) {
		ph->phy_present = B_FALSE;
		return;
	}

	if (bmsr & MII_STATUS_EXTSTAT) {
		extsr = phy_read(ph, MII_EXTSTATUS);
	} else {
		extsr = 0;
	}

	ph->phy_present = B_TRUE;
	ph->phy_id = ((uint32_t)phy_read(ph, MII_PHYIDH) << 16) |
	    phy_read(ph, MII_PHYIDL);

	/* setup default handlers */
	ph->phy_reset = phy_reset;
	ph->phy_start = phy_start;
	ph->phy_stop = phy_stop;
	ph->phy_check = phy_check;
	ph->phy_loop = phy_loop;

	/*
	 * We ignore the non-existent 100baseT2 stuff -- no
	 * known products for it exist.
	 */
	ph->phy_cap_aneg =	!!(bmsr & MII_STATUS_CANAUTONEG);
	ph->phy_cap_100_t4 =	!!(bmsr & MII_STATUS_100_BASE_T4);
	ph->phy_cap_100_fdx =	!!(bmsr & MII_STATUS_100_BASEX_FD);
	ph->phy_cap_100_hdx =	!!(bmsr & MII_STATUS_100_BASEX);
	ph->phy_cap_10_fdx =	!!(bmsr & MII_STATUS_10_FD);
	ph->phy_cap_10_hdx =	!!(bmsr & MII_STATUS_10);
	ph->phy_cap_1000_fdx =
	    !!(extsr & (MII_EXTSTATUS_1000X_FD|MII_EXTSTATUS_1000T_FD));
	ph->phy_cap_1000_hdx =
	    !!(extsr & (MII_EXTSTATUS_1000X | MII_EXTSTATUS_1000T));
	ph->phy_cap_pause =	mh->m_cap_pause;
	ph->phy_cap_asmpause =	mh->m_cap_asmpause;

	if (bmsr & MII_STATUS_10) {
		ph->phy_cap_10_hdx = B_TRUE;
		ph->phy_type = XCVR_10;
	}
	if (bmsr & MII_STATUS_10_FD) {
		ph->phy_cap_10_fdx = B_TRUE;
		ph->phy_type = XCVR_10;
	}
	if (bmsr & MII_STATUS_100T2) {
		ph->phy_cap_100_hdx = B_TRUE;
		ph->phy_type = XCVR_100T2;
	}
	if (bmsr & MII_STATUS_100T2_FD) {
		ph->phy_cap_100_fdx = B_TRUE;
		ph->phy_type = XCVR_100T2;
	}
	if (bmsr & MII_STATUS_100_BASE_T4) {
		ph->phy_cap_100_hdx = B_TRUE;
		ph->phy_type = XCVR_100T4;
	}
	if (bmsr & MII_STATUS_100_BASEX) {
		ph->phy_cap_100_hdx = B_TRUE;
		ph->phy_type = XCVR_100X;
	}
	if (bmsr & MII_STATUS_100_BASEX_FD) {
		ph->phy_cap_100_fdx = B_TRUE;
		ph->phy_type = XCVR_100X;
	}
	if (extsr & MII_EXTSTATUS_1000X) {
		ph->phy_cap_1000_hdx = B_TRUE;
		ph->phy_type = XCVR_1000X;
	}
	if (extsr & MII_EXTSTATUS_1000X_FD) {
		ph->phy_cap_1000_fdx = B_TRUE;
		ph->phy_type = XCVR_1000X;
	}
	if (extsr & MII_EXTSTATUS_1000T) {
		ph->phy_cap_1000_hdx = B_TRUE;
		ph->phy_type = XCVR_1000T;
	}
	if (extsr & MII_EXTSTATUS_1000T_FD) {
		ph->phy_cap_1000_fdx = B_TRUE;
		ph->phy_type = XCVR_1000T;
	}

	for (int j = 0; _phy_probes[j] != NULL; j++) {
		if ((*_phy_probes[j])(ph)) {
			break;
		}
	}

#define	INIT_ENABLE(CAP)	\
	ph->phy_en_##CAP = (mh->m_en_##CAP > 0) ? \
	    mh->m_en_##CAP : ph->phy_cap_##CAP

	INIT_ENABLE(aneg);
	INIT_ENABLE(1000_fdx);
	INIT_ENABLE(1000_hdx);
	INIT_ENABLE(100_fdx);
	INIT_ENABLE(100_t4);
	INIT_ENABLE(100_hdx);
	INIT_ENABLE(10_fdx);
	INIT_ENABLE(10_hdx);

#undef	INIT_ENABLE
	ph->phy_en_flowctrl = mh->m_en_flowctrl;
	switch (ph->phy_en_flowctrl) {
	case LINK_FLOWCTRL_BI:
	case LINK_FLOWCTRL_RX:
		ph->phy_en_pause = B_TRUE;
		ph->phy_en_asmpause = B_TRUE;
		break;
	case LINK_FLOWCTRL_TX:
		ph->phy_en_pause = B_FALSE;
		ph->phy_en_asmpause = B_TRUE;
		break;
	default:
		ph->phy_en_pause = B_FALSE;
		ph->phy_en_asmpause = B_FALSE;
		break;
	}
}

void
_mii_probe(mii_handle_t mh)
{
	uint8_t		new_addr;
	uint8_t		old_addr;
	uint8_t		user_addr;
	uint8_t		curr_addr;
	phy_handle_t	*ph;
	int		pri = 0;
	int		first;

	user_addr = ddi_prop_get_int(DDI_DEV_T_ANY, mh->m_dip, 0,
	    "phy-addr", -1);
	old_addr = mh->m_addr;
	new_addr = 0xff;

	/*
	 * Apparently, PHY 0 is less likely to be physically
	 * connected, and should always be the last one tried.  Most
	 * single solution NICs use PHY1 for their built-in
	 * transceiver.  NICs with an external MII will often place
	 * the external PHY at address 1, and use address 0 for the
	 * internal PHY.
	 *
	 * Some devices have a different preference however.  They can
	 * override the default starting point of the search by
	 * exporting a "first-phy" property.
	 */

	first = ddi_prop_get_int(DDI_DEV_T_ANY, mh->m_dip, 0, "first-phy", 1);
	if ((first < 0) || (first > 31)) {
		first = 1;
	}
	for (int i = first; i < (first + 32); i++) {

		/*
		 * This is tricky: it lets us start searching at an
		 * arbitrary address instead of 0, dealing with the
		 * wrap-around at address 31 properly.
		 */
		curr_addr = i % 32;

		ph = &mh->m_phys[curr_addr];

		bzero(ph, sizeof (*ph));
		ph->phy_addr = curr_addr;
		ph->phy_mii = mh;

		_mii_probe_phy(ph);

		if (!ph->phy_present)
			continue;

		if (curr_addr == user_addr) {
			/*
			 * We always try to honor the user configured phy.
			 */
			new_addr = curr_addr;
			pri = 4;

		}

		/* two reads to clear latched bits */
		if ((phy_read(ph, MII_STATUS) & MII_STATUS_LINKUP) &&
		    (phy_read(ph, MII_STATUS) & MII_STATUS_LINKUP) &&
		    (pri < 3)) {
			/*
			 * Link present is good.  We prefer this over
			 * a possibly disconnected link.
			 */
			new_addr = curr_addr;
			pri = 3;
		}
		if ((curr_addr == old_addr) && (pri < 2)) {
			/*
			 * All else being equal, minimize change.
			 */
			new_addr = curr_addr;
			pri = 2;

		}
		if (pri < 1) {
			/*
			 * But make sure we at least select a present PHY.
			 */
			new_addr = curr_addr;
			pri = 1;
		}
	}

	if (new_addr == 0xff) {
		mh->m_addr = -1;
		mh->m_phy = &mh->m_bogus_phy;
		_mii_error(mh, MII_ENOPHY);
	} else {
		mh->m_addr = new_addr;
		mh->m_phy = &mh->m_phys[new_addr];
		mh->m_tstate = MII_STATE_RESET;
		if (new_addr != old_addr) {
			cmn_err(CE_CONT,
			    "?%s: Using %s Ethernet PHY at %d: %s %s\n",
			    mh->m_name, mii_xcvr_types[mh->m_phy->phy_type],
			    mh->m_addr, mh->m_phy->phy_vendor,
			    mh->m_phy->phy_model);
			mh->m_link = LINK_STATE_UNKNOWN;
		}
	}
}

int
_mii_reset(mii_handle_t mh)
{
	phy_handle_t	*ph;
	boolean_t	notify;

	ASSERT(mutex_owned(&mh->m_lock));

	/*
	 * Reset logic.  We want to isolate all the other
	 * phys that are not in use.
	 */
	for (int i = 0; i < 32; i++) {
		ph = &mh->m_phys[i];

		if (!ph->phy_present)
			continue;

		/* Don't touch our own phy, yet. */
		if (ph == mh->m_phy)
			continue;

		ph->phy_stop(ph);
	}

	ph = mh->m_phy;

	ASSERT(ph->phy_present);

	/* If we're resetting the PHY, then we want to notify loss of link */
	notify = (mh->m_link != LINK_STATE_DOWN);
	mh->m_link = LINK_STATE_DOWN;
	ph->phy_link = LINK_STATE_DOWN;
	ph->phy_speed = 0;
	ph->phy_duplex = LINK_DUPLEX_UNKNOWN;

	if (ph->phy_reset(ph) != DDI_SUCCESS) {
		_mii_error(mh, MII_ERESET);
		return (DDI_FAILURE);
	}

	/* Perform optional mac layer reset. */
	if (mh->m_ops.mii_reset != NULL) {
		mh->m_ops.mii_reset(mh->m_private);
	}

	/* Perform optional mac layer notification. */
	if (notify) {
		_mii_notify(mh);
	}
	return (DDI_SUCCESS);
}

int
_mii_loopback(mii_handle_t mh)
{
	phy_handle_t	*ph;

	ASSERT(mutex_owned(&mh->m_lock));

	ph = mh->m_phy;

	if (_mii_reset(mh) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	if (ph->phy_loopback == PHY_LB_NONE) {
		mh->m_tstate = MII_STATE_START;
		return (DDI_SUCCESS);
	}
	if (ph->phy_loop(ph) != DDI_SUCCESS) {
		_mii_error(mh, MII_ELOOP);
		return (DDI_FAILURE);
	}

	/* Just force loopback to link up. */
	mh->m_link = ph->phy_link = LINK_STATE_UP;
	_mii_notify(mh);

	return (DDI_SUCCESS);
}

int
_mii_start(mii_handle_t mh)
{
	phy_handle_t		*ph;

	ph = mh->m_phy;

	ASSERT(mutex_owned(&mh->m_lock));
	ASSERT(ph->phy_present);
	ASSERT(ph->phy_loopback == PHY_LB_NONE);

	if (ph->phy_start(ph) != DDI_SUCCESS) {
		_mii_error(mh, MII_ESTART);
		return (DDI_FAILURE);
	}
	/* clear the error state since we got a good startup! */
	mh->m_error = MII_EOK;
	return (DDI_SUCCESS);
}

int
_mii_check(mii_handle_t mh)
{
	link_state_t	olink;
	int		ospeed;
	link_duplex_t	oduplex;
	link_flowctrl_t	ofctrl;
	phy_handle_t	*ph;

	ph = mh->m_phy;

	olink = mh->m_link;
	ospeed = ph->phy_speed;
	oduplex = ph->phy_duplex;
	ofctrl = ph->phy_flowctrl;

	ASSERT(ph->phy_present);

	if (ph->phy_check(ph) == DDI_FAILURE) {
		_mii_error(mh, MII_ECHECK);
		mh->m_link = LINK_STATE_UNKNOWN;
		_mii_notify(mh);
		return (DDI_FAILURE);
	}

	mh->m_link = ph->phy_link;

	/* if anything changed, notify! */
	if ((mh->m_link != olink) ||
	    (ph->phy_speed != ospeed) ||
	    (ph->phy_duplex != oduplex) ||
	    (ph->phy_flowctrl != ofctrl)) {
		_mii_notify(mh);
	}

	return (DDI_SUCCESS);
}

void
_mii_task(void *_mh)
{
	mii_handle_t	mh = _mh;
	phy_handle_t	*ph;
	clock_t		wait;
	clock_t		downtime;

	mutex_enter(&mh->m_lock);

	for (;;) {

		/* If detaching, exit the thread. */
		if (!mh->m_started) {
			break;
		}

		ph = mh->m_phy;

		/*
		 * If we're suspended or otherwise not supposed to be
		 * monitoring the link, just go back to sleep.
		 *
		 * Theoretically we could power down the PHY, but we
		 * don't bother.  (The link might be used for
		 * wake-on-lan!)  Another option would be to reduce
		 * power on the PHY if both it and the link partner
		 * support 10 Mbps mode.
		 */
		if (mh->m_suspending) {
			mh->m_suspended = B_TRUE;
			cv_broadcast(&mh->m_cv);
		}
		if (mh->m_suspended) {
			mh->m_suspending = B_FALSE;
			cv_wait(&mh->m_cv, &mh->m_lock);
			continue;
		}

		switch (mh->m_tstate) {
		case MII_STATE_PROBE:
			_mii_probe(mh);
			ph = mh->m_phy;
			if (!ph->phy_present) {
				/*
				 * If no PHY is found, wait a bit before
				 * trying the probe again.  10 seconds ought
				 * to be enough.
				 */
				wait = 10 * MII_SECOND;
			} else {
				wait = 0;
			}
			break;

		case MII_STATE_RESET:
			if (_mii_reset(mh) == DDI_SUCCESS) {
				mh->m_tstate = MII_STATE_START;
				wait = 0;
			} else {
				/*
				 * If an error occurred, wait a bit and
				 * try again later.
				 */
				wait = 10 * MII_SECOND;
			}
			break;

		case MII_STATE_START:
			/*
			 * If an error occurs, we're going to go back to
			 * probe or reset state.  Otherwise we go to run
			 * state.  In all cases we want to wait 1 second
			 * before doing anything else - either for link to
			 * settle, or to give other code a chance to run
			 * while we reset.
			 */
			if (_mii_start(mh) == DDI_SUCCESS) {
				/* reset watchdog to latest */
				downtime = ddi_get_lbolt();
				mh->m_tstate = MII_STATE_RUN;
			} else {
				mh->m_tstate = MII_STATE_PROBE;
			}
			wait = 0;
			break;

		case MII_STATE_LOOPBACK:
			/*
			 * In loopback mode we don't check anything,
			 * and just wait for some condition to change.
			 */
			wait = (clock_t)-1;
			break;

		case MII_STATE_RUN:
		default:
			if (_mii_check(mh) == DDI_FAILURE) {
				/*
				 * On error (PHY removed?), wait a
				 * short bit before reprobing or
				 * resetting.
				 */
				wait = MII_SECOND;
				mh->m_tstate = MII_STATE_PROBE;

			} else if (mh->m_link == LINK_STATE_UP) {
				/* got goood link, so reset the watchdog */
				downtime = ddi_get_lbolt();
				/* rescan again in a second */
				wait = MII_SECOND;

			} else if ((ddi_get_lbolt() - downtime) >
			    (drv_usectohz(MII_SECOND * 10))) {

				/*
				 * If we were down for 10 seconds,
				 * hard reset the PHY.
				 */
				mh->m_tstate = MII_STATE_RESET;
				wait = 0;

			} else {
				/*
				 * Otherwise, if we are still down,
				 * rescan the link much more
				 * frequently.  We might be trying to
				 * autonegotiate.
				 */
				wait = MII_SECOND / 4;
			}
			break;
		}

		switch (wait) {
		case 0:
			break;

		case (clock_t)-1:
			cv_wait(&mh->m_cv, &mh->m_lock);
			break;

		default:
			(void) cv_reltimedwait(&mh->m_cv, &mh->m_lock,
			    drv_usectohz(wait), TR_CLOCK_TICK);
		}
	}

	mutex_exit(&mh->m_lock);
}
