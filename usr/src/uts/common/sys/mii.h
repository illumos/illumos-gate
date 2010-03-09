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
 * mii.h
 * Generic MII/PHY Support for MAC drivers.
 */

#ifndef _SYS_MII_H
#define	_SYS_MII_H

#include <sys/mac_provider.h>
#include <sys/netlb.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * NOTES
 *
 * The device driver is required to protect its own registers.  The
 * MII common code will call MII entry points asynchronously, from a
 * taskq, and holds an internal lock across such calls (except the
 * notify entry point).  Therefore, device drivers MUST NOT hold any
 * locks across calls into the MII framework.
 *
 * If a device must be suspended (e.g. due to DDI_SUSPEND) the MII
 * layer can be suspended by calling mii_stop().  After this point,
 * the monitoring task will be suspended and the driver can be assured
 * that MII will not interfere until restarted with mii_start().
 *
 * Note that monitoring is not started until mii_start() is called.
 * The mii_start() function may be called multiple times.  It performs
 * an implicit reset of the MII bus and PHY.
 *
 * Once started, if not already done, a probe of the MII bus is done to
 * find a suitable PHY.  If no PHY is found, then you won't have any
 * link!  Once a suitable PHY is selected, any other PHYs are isolated and
 * powered down.  The device driver can cause MII to re-probe the bus for
 * changes to the available PHYs by calling mii_probe().  Note that this
 * will also cause a full reset of all PHYs.
 *
 * The mii_reset entry point, which is optional, is used to notify the
 * driver when the MII layer has reset the device.  This can allow
 * certain drivers the opportunity to "fix up" things after reset.
 * Note however, that when possible, it is better if the logic is
 * encoded into a vendor specific PHY module.
 */

#ifdef	_KERNEL

typedef struct mii_handle *mii_handle_t;
typedef struct mii_ops mii_ops_t;

struct mii_ops {
	int		mii_version;
	uint16_t	(*mii_read)(void *, uint8_t, uint8_t);
	void		(*mii_write)(void *, uint8_t, uint8_t, uint16_t);
	void		(*mii_notify)(void *, link_state_t);
	void		(*mii_reset)(void *);
};
#define	MII_OPS_VERSION	0

/*
 * Support routines.
 */

/*
 * mii_alloc
 *
 * 	Allocate an MII handle.  Called during driver's attach(9e)
 *	handling, this routine is valid in kernel context only.
 *
 * Arguments
 *
 * 	private		A private state structure, provided back to
 *			entry points.
 *	dip		The dev_info node for the MAC driver.
 *	ops		Entry points into the MAC driver.
 *
 * Returns
 *	Handle to MII bus on success, NULL on failure.
 */
mii_handle_t mii_alloc(void *private, dev_info_t *dip, mii_ops_t *ops);

/*
 * mii_alloc
 *
 * 	Allocate an MII handle.  Called during driver's attach(9e)
 *	handling, this routine is valid in kernel context only.  This
 *	routine is an alternative to mii_alloc() for use when the
 *	instance number (PPA) is not the same as the devinfo instance
 *	number, and hence needs to be overridden.
 *
 * Arguments
 *
 * 	private		A private state structure, provided back to
 *			entry points.
 *	dip		The dev_info node for the MAC driver.
 *	instance	The instance (PPA) of the interface.
 *	ops		Entry points into the MAC driver.
 *
 * Returns
 *	Handle to MII bus on success, NULL on failure.
 */
mii_handle_t mii_alloc_instance(void *private, dev_info_t *dip, int instance,
    mii_ops_t *ops);

/*
 * mii_free
 *
 *	Free an MII handle and associated resources.  Call from
 *	detach(9e) handling, this routine is valid in kernel context
 *	only.
 */
void mii_free(mii_handle_t mii);

/*
 * mii_set_pauseable
 *
 *	Lets the MII know if the MAC layer can support pause or
 *	asymetric pause capabilities.  The MII layer will use this to
 *	determine what capabilities should be negotiated for (along
 *	with user preferences, of course.)  If not called, the MII
 *	will assume the device has no support for flow control.
 *
 * Arguments
 *
 * 	mii		MII handle.
 *	cap		B_TRUE if the device supports symmetric of pause.
 *	asym		B_TRUE if the device supports asymmetric pause.
 */
void mii_set_pauseable(mii_handle_t mii, boolean_t cap, boolean_t asym);

/*
 * mii_reset
 *
 *	Schedules a reset of the MII bus.  Normally not needed, but
 *	can be used to perform a full master reset, including
 *	rescanning for PHYs.  This function may be called in any
 *	context except high level interrupt context, but must be
 *	called without any locks held.  The reset will probably not
 *	be complete until sometime after the call returns.
 *
 *	Note that if mii_start has not been called, then the reset
 *	will not be performed until _after_ the MII is started.
 */
void mii_reset(mii_handle_t mii);


/*
 * mii_start
 *
 *	Starts monitoring of the MII bus.  Normally this is called as
 *	a result of a driver's mac_start() entry point, but it may also
 *	be called when a PHY needs to be reset or during handling of
 *	DDI_RESUME.   This function may be called in any context except
 *	high level interrupt context, but
 *	must be called without any locks held.
 */
void mii_start(mii_handle_t mii);

/*
 * mii_stop
 *
 *	Stops monitoring of the MII bus.  Normally this is called as a
 *	result of a driver's mac_stop() entry point.  As a side
 *	effect, also isolates and powers down any active PHY.  On
 *	return, the MII layer is guaranteed not to be executing any
 *	code in the MII entry points.  This function may be called in
 *	any context except high level interrupt context, but must be
 *	called without any locks held.
 */
void mii_stop(mii_handle_t mii);

/*
 * mii_resume
 *
 *	Starts monitoring of the MII bus.  Normally this is called as
 *	a part of a driver's DDI_RESUME handling.  This function may
 *	be called in any context except high level interrupt context,
 *	but must be called without any locks held.
 */
void mii_resume(mii_handle_t mii);

/*
 * mii_suspend
 *
 *	Suspends monitoring of the MII bus.  Normally this is called
 *	as a part of a driver's DDI_SUSPEND handling.  On return, the
 *	MII layer is guaranteed not to be executing any code in the
 *	MII entry points.  This function may be called in any context
 *	except high level interrupt context, but must be called
 *	without any locks held.
 */
void mii_suspend(mii_handle_t mii);

/*
 * mii_probe
 *
 *	Used to reset the entire MII bus and probe for PHYs.  This
 *	routine should be called if the driver has reason to believe that
 *	PHYs have changed.  This is implicitly executed the first time
 *	monitoring is started on the MII bus, and normally need not be
 *	explicitly called. This function may be called in any context
 *	except high level interrupt context, but must be called
 *	without any locks held.
 */
void mii_probe(mii_handle_t mii);

/*
 * mii_check
 *
 *	Used to alert the MII layer that it should check for changes.
 *	This can be called by drivers in response to link status
 *	interrupts, for example, giving a quicker response to link
 *	status changes without waiting for the MII timer to expire.
 *	This function may be called in any context except high level
 *	interrupt context, but must be called without any locks held.
 */
void mii_check(mii_handle_t mii);

/*
 * mii_get_addr
 *
 *	Used to get the PHY address that is currently active for the MII
 *	bus.  This function may be called in any context.
 *
 * Returns
 *
 *	The PHY address (0-31) if a PHY is active on the MII bus.  If
 *	no PHY is active, -1 is returned.
 */
int mii_get_addr(mii_handle_t mii);

/*
 * mii_get_id
 *
 *	Used to get the identifier of the active PHY.  This function
 *	may be called in any context.
 *
 * Returns
 *
 *	The PHY identifier register contents, encoded with the high
 * 	order (PHYIDH) bits in the upper word and the low order bits
 * 	in the lower word.  If no PHY is active, the value -1 will be
 * 	returned.
 */
uint32_t mii_get_id(mii_handle_t mii);

/*
 * mii_get_speed
 *
 *	Used to get the speed of the active PHY.  This function may be
 *	called in any context.
 *
 * Returns
 *
 *	The speed, in Mbps, if the active PHY has link (10, 100, or 1000),
 *	otherwise 0.
 */
int mii_get_speed(mii_handle_t mii);

/*
 * mii_get_duplex
 *
 *	Used to get the duplex of the active PHY.  This function may
 *	be called in any context.
 *
 * Returns
 *
 *	The duplex, if the active PHY has link (LINK_DUPLEX_FULL or
 *	LINK_DUPLEX_HALF), otherwise LINK_DUPLEX_UNKNOWN.
 */
link_duplex_t mii_get_duplex(mii_handle_t mii);

/*
 * mii_get_state
 *
 *	Used to get the state of the link on the active PHY.  This
 *	function may be called in any context.
 *
 * Returns
 *
 *	The link state (LINK_STATE_UP or LINK_STATE_DOWN), if known,
 *	otherwise LINK_STATE_UNKNOWN.
 */
link_state_t mii_get_state(mii_handle_t mii);

/*
 * mii_get_flowctrl
 *
 *	Used to get the state of the negotiated flow control on the
 *	active PHY.  This function may be called in any context.
 *
 * Returns
 *
 *	The flowctrl state (LINK_FLOWCTRL_NONE, LINK_FLOWCTRL_RX,
 *	LINK_FLOWCTRL_TX, or LINK_FLOWCTRL_BI.
 */
link_flowctrl_t mii_get_flowctrl(mii_handle_t mii);

/*
 * mii_get_loopmodes
 *
 *	This function is used to support the LB_GET_INFO_SIZE and
 *	LB_GET_INFO ioctls.  It probably should not be used outside of
 *	that context.  The modes supplied are supported by the MII/PHY.
 *	Drivers may wish to add modes for MAC internal loopbacks as well.
 *	See <sys/netlb.h> for more information.
 *
 *	Note that the first item in the modes array will always be the
 *	mode to disable the MII/PHY loopback, and will have the value
 *	MII_LOOPBACK_NONE.
 *
 * Arguments
 *
 * 	mii		MII handle.
 *	modes		Location to receive an array of loopback modes.
 *			Drivers should ensure that enough room is available.
 *			There will never be more than MII_LOOPBACK_MAX modes
 *			returned.  May be NULL, in which case no data will
 *			be returned to the caller.
 *
 * Returns
 *
 *	Count of number of modes available, in no case larger than
 *	MII_LOOPBACK_MAX.
 */
int mii_get_loopmodes(mii_handle_t mii, lb_property_t *modes);

#define	MII_LOOPBACK_MAX	16
#define	MII_LOOPBACK_NONE	0

/*
 * mii_set_loopback
 *
 *	Sets the loopback mode, intended for use in support of the
 *	LB_SET_MODE ioctl.  The mode value will be one of the values
 *	returned in the modes array (see mii_get_loopmodes), or the
 *	special value MII_LOOPBACK_NONE to return to normal operation.
 *
 * Arguments
 *
 * 	mii		MII handle.
 *	mode		New loopback mode number; MII_LOOPBACK_NONE indicates
 *			a return to normal operation.
 *
 * Returns
 *
 *	Zero on success, or EINVAL if the mode is invalid or unsupported.
 */
int mii_set_loopback(mii_handle_t mii, uint32_t mode);

/*
 * mii_get_loopback
 *
 *	Queries the loopback mode, intended for use in support of the
 *	LB_GET_MODE ioctl, but may be useful in programming device
 *	settings that are sensitive to loopback setting.
 *
 * Returns
 *
 *	The current mode number (one of the reported by
 *	mii_get_loopmodes), or the special value MII_LOOPBACK_NONE
 *	indicating that loopback is not in use.
 */
uint32_t mii_get_loopback(mii_handle_t mii);

/*
 * mii_m_loop_ioctl
 *
 *	Used to support the driver's mc_ioctl() for loopback ioctls.
 *	If the driver is going to use the loopback optons from the
 *	PHY, and isn't adding any MAC level loopback, then this function
 *	can handle the entire set of ioctls, removing yet more code from
 *	the driver.  Ultimately, this is a very reasonable thing to do,
 *	since the PHY level loopback should exercise all of the same
 *	MAC level circuitry that a MAC internal loopback would do.
 *
 * Arguments
 *
 * 	mii		MII handle.
 *	wq		The write queue supplied to mc_ioctl().
 *	msg		The mblk from the mc_ioctl (contains an iocblk).
 *
 * Returns
 *
 *	B_TRUE if the ioctl was handled by the driver.
 *	B_FALSE if the ioctl was not handled, and may need to be
 *	handled by the driver.
 */
boolean_t mii_m_loop_ioctl(mii_handle_t mii, queue_t *wq, mblk_t *msg);

/*
 * mii_m_getprop
 *
 *	Used to support the driver's mc_getprop() mac callback,
 *	and only to be called from that function (and without any
 *	locks held).  This routine will process all of the properties
 *	that are relevant to MII on behalf of the driver.
 *
 * Arguments
 *
 * 	mii		MII handle.
 *	name		Property name.
 *	id		Property ID.
 *	sz		Size of property in bytes.
 *	val		Location to receive property value.
 *
 * Returns
 *
 *	0 on successful handling of property.
 *	EINVAL if invalid arguments (e.g. a bad size) are supplied.
 *	ENOTSUP	if the prooperty is not supported by MII or the PHY.
 */
int mii_m_getprop(mii_handle_t mii, const char *name, mac_prop_id_t id,
    uint_t sz, void *val);

/*
 * mii_m_setprop
 *
 *	Used to support the driver's mc_setprop() mac callback,
 *	and only to be called from that function (and without any
 *	locks held).  This routine will process all of the properties
 *	that are relevant to MII on behalf of the driver.  This will
 *	often result in the PHY being reset.
 *
 * Arguments
 *
 * 	mii		MII handle.
 *	name		Property name.
 *	id		Property ID.
 *	sz		Size of property in bytes.
 *	val		Location of property value.
 *
 * Returns
 *
 *	0 on successful handling of property.
 *	EINVAL if invalid arguments (e.g. a bad size) are supplied.
 *	ENOTSUP	if the prooperty is not supported by MII or the PHY,
 *	or if the property is read-only.
 */
int mii_m_setprop(mii_handle_t mii, const char *name, mac_prop_id_t id,
    uint_t sz, const void *val);

/*
 * mii_m_propinfo
 *
 *	Used to support the driver's mc_setprop() mac callback,
 *	and only to be called from that function (and without any
 *	locks held).
 *
 * Arguments
 *
 * 	mii		MII handle.
 *	name		Property name.
 *	id		Property ID.
 *	prh		Property info handle.
 *
 */
void mii_m_propinfo(mii_handle_t mii, const char *name, mac_prop_id_t id,
    mac_prop_info_handle_t prh);


/*
 * mii_m_getstat
 *
 *	Used to support the driver's mc_getstat() mac callback for
 *	statistic collection, and only to be called from that function
 *	(without any locks held).  This routine will process all of
 *	the statistics that are relevant to MII on behalf of the
 *	driver.
 *
 * Arguments
 *
 * 	mii		MII handle.
 *	stat		Statistic number.
 *	val		Location to receive statistic value.
 *
 * Returns
 *
 *	0 on successful handling of statistic.
 *	ENOTSUP	if the statistic is not supported by MII.
 */
int mii_m_getstat(mii_handle_t mii, uint_t stat, uint64_t *val);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_MII_H */
