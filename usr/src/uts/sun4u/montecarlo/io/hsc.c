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
 * MonteCarlo HotSwap Controller functionality
 */

#include	<sys/types.h>
#include	<sys/stropts.h>
#include	<sys/stream.h>
#include	<sys/strsun.h>
#include	<sys/kmem.h>
#include	<sys/cmn_err.h>
#include	<sys/errno.h>
#include	<sys/cpuvar.h>
#include	<sys/open.h>
#include	<sys/stat.h>
#include	<sys/conf.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/modctl.h>
#include	<sys/promif.h>
#include	<sys/hotplug/hpcsvc.h>

#include	<sys/hscimpl.h>
#include	<sys/hsc.h>

#include	<sys/mct_topology.h>
#include	<sys/scsbioctl.h>
#include	<sys/scsb.h>

#define	HOTSWAP_MODE_PROP	"hotswap-mode"
#define	ALARM_CARD_ON_SLOT	1
#define	SCSB_HSC_FORCE_REMOVE	1	/* force remove enum intr handler */

/* TUNABLE PARAMETERS. Some are Debug Only. Please take care when using. */

/*
 * Set this flag to 1, to enable full hotswap mode at boot time.
 * Since HPS is threaded, it is not recommended that we set this flag
 * to 1 because enabling full hotswap interrupt can invoke the ENUM
 * event handler accessing the slot data structure which may have not
 * been initialized in the hotplug framework since the HPS may not yet
 * have called the slot registration function with the bus nexus.
 */
static int	scsb_hsc_enable_fhs = 0;

/*
 * Every time  a slot is registered with the hotswap framework, the
 * framework calls back. This variable keeps a count on how many
 * callbacks are done.
 */
static int scsb_hsc_numReg = 0;
/*
 * When this flag is set, the board is taken offline (put in reset) after
 * a unconfigure operation, in Basic Hotswap mode.
 */
static int	scsb_hsc_bhs_slot_reset = 1;
/*
 * When this flag is set, we take the board to reset after unconfigure
 * operation when operating in full hotswap mode.
 */
static int	scsb_hsc_fhs_slot_reset = 1;
/*
 * Implementation of this counter will work only on Montecarlo since
 * the ENUM# Interrupt line is not shared with other interrupts.
 * When the hardware routing changes, then there may be need to remove
 * or change this functionality.
 * This functionality is provided so that a bad or non friendly full hotswap
 * board does not hang the system in full hotswap mode. Atleast the
 * intent is that! Eventually Solaris kernel will provide similar support
 * for recovering from a stuck interrupt line. Till then, lets do this.
 */
static int	scsb_hsc_max_intr_count = 8;
/*
 * Since the hardware does not support enabling/disabling ENUM#, the
 * following flag can be used for imitating that behaviour.
 * Currently we can set this flag and use the remove op to remove the
 * interrupt handler from the system. Care must be taken when using this
 * function since trying to remove the interrupt handler when the interrupts
 * are pending may hang the system permanently.
 * Since the hardware does not support this functionality, we adopt this
 * approach for debugs.
 */
static int	scsb_hsc_enum_switch = 0;

/*
 * When the board loses Healthy# at runtime (with the board being configured),
 * cPCI specs states that a Reset has to be asserted immediately.
 * We dont do this currently, until satellite processor support is given
 * and the implications of such a act is fully understood.
 * To adopt the cPCI specs recommendation, set this flag to 1.
 */
static	int	scsb_hsc_healthy_reset = 0;

/*
 * According to PCI 2.2 specification, once a board comes out of PCI_RST#,
 * it may take upto 2^25 clock cycles to respond to config cycles. For
 * montecarlo using a 33MHz cPCI bus, it's around 1.024 s. The variable
 * will specify the time in ms to wait before attempting config access.
 */
static	int scsb_connect_delay = 1025;

/*
 * slot map property for MC should be
 *
 *	hsc-slot-map="/pci@1f,0/pci@1/pci@1","15","2",
 *               "/pci@1f,0/pci@1/pci@1","14","3",
 *               "/pci@1f,0/pci@1/pci@1","13","4",
 *               "/pci@1f,0/pci@1/pci@1","12","5"
 *               "/pci@1f,0/pci@1/pci@1","11","6"
 *               "/pci@1f,0/pci@1/pci@1","10","7"
 *               "/pci@1f,0/pci@1/pci@1","8","8";
 *
 * slot map property for Tonga should be
 *	hsc-slot-map="/pci@1f,0/pci@1/pci@1","8","1"
 *		"/pci@1f,0/pci@1/pci@1", "15", "2"
 *		"/pci@1f,0/pci@1/pci@1", "14", "4"
 *		"/pci@1f,0/pci@1/pci@1", "13", "5"
 *
 * Please note that the CPU slot number is 3 for Tonga.
 */

/*
 * Services we require from the SCSB
 */
extern int	scsb_get_slot_state(void *, int, int *);
extern int	scsb_read_bhealthy(scsb_state_t *scsb);
extern int	scsb_read_slot_health(scsb_state_t *scsb, int pslotnum);
extern int	scsb_connect_slot(void *, int, int);
extern int	scsb_disconnect_slot(void *, int, int);

static void	*hsc_state;

static uint_t	hsc_enum_intr(char *);
static hsc_slot_t *hsc_get_slot_info(hsc_state_t *, int);
static int	scsb_enable_enum(hsc_state_t *);
static int	scsb_disable_enum(hsc_state_t *, int);
static int	atoi(const char *);
static int	isdigit(int);
static hsc_slot_t *hsc_find_slot(int);
static void	hsc_led_op(hsc_slot_t *, int, hpc_led_t, hpc_led_state_t);
static int	hsc_led_state(hsc_slot_t *, int, hpc_led_info_t *);
static int	scsb_hsc_disable_slot(hsc_slot_t *);
static int	scsb_hsc_enable_slot(hsc_slot_t *);
#ifndef	lint
static int hsc_clear_all_enum(hsc_state_t *);
#endif
static int	hsc_slot_register(hsc_state_t *, char *, uint16_t, uint_t,
					boolean_t);
static int	hsc_slot_unregister(int);
static int	scsb_hsc_init_slot_state(hsc_state_t *, hsc_slot_t *);
static int	hsc_slot_autoconnect(hsc_slot_t *);

static hpc_slot_ops_t	*hsc_slotops;
static hsc_slot_t	*hsc_slot_list;		/* linked list of slots */

/*
 * This mutex protects the following variables:
 *	hsc_slot_list
 */
static kmutex_t		hsc_mutex;


/* ARGSUSED */
static int
hsc_connect(caddr_t ops_arg, hpc_slot_t slot_hdl, void *data, uint_t flags)
{
	hsc_slot_t *hsp = (hsc_slot_t *)ops_arg;
	int rc, rstate;
	hsc_state_t	*hsc;

	DEBUG2("hsc_connect: slot %d, healthy %d", hsp->hs_slot_number,
						hsp->hs_board_healthy);

	if (!(hsp->hs_flags & (HSC_ENABLED|HSC_SLOT_ENABLED)))
		return (HPC_ERR_FAILED);
	/* if SCB hotswapped, do not allow connect operations */
	if (hsp->hs_flags & HSC_SCB_HOTSWAPPED)
		return (HPC_ERR_FAILED);
	/*
	 * if previous occupant stayed configured, do not allow another
	 * occupant to be connected.
	 * This behaviour is an indication that the slot state
	 * is not clean.
	 */
	if (hsp->hs_flags & HSC_SLOT_BAD_STATE) {
		/*
		 * In the current implementation, we turn both fault
		 * and active LEDs to ON state in this situation.
		 */
		hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_ACTIVE_LED,
							HPC_LED_ON);
		return (HPC_ERR_FAILED);
	}
	/*
	 * Get the actual status from the i2c bus
	 */
	rc = scsb_get_slot_state(hsp->hs_hpchandle, hsp->hs_slot_number,
								&rstate);
	if (rc != DDI_SUCCESS)
		return (HPC_ERR_FAILED);

	hsp->hs_slot_state = rstate;
	if (hsp->hs_slot_state == HPC_SLOT_EMPTY) {
#ifdef DEBUG
		cmn_err(CE_CONT,
			"?hsc_connect: slot %d is empty\n",
			hsp->hs_slot_number);
#endif
		return (HPC_ERR_FAILED);
	}

	if (hsp->hs_slot_state == HPC_SLOT_CONNECTED)
		return (HPC_SUCCESS);

	rc = HPC_SUCCESS;
	/*
	 * call scsb to connect the slot. This also makes sure board is healthy
	 */
	if (scsb_connect_slot(hsp->hs_hpchandle, hsp->hs_slot_number,
				hsp->hs_board_healthy) != DDI_SUCCESS) {
		DEBUG1("hsc_connect: slot %d connection failed",
				hsp->hs_slot_number);
		rc = HPC_ERR_FAILED;
	} else {
		if (hsp->hs_slot_state != HPC_SLOT_CONNECTED) {
			if (hsp->hs_board_healthy == B_FALSE) {
				cmn_err(CE_NOTE, "HEALTHY# not asserted on "
					" slot %d", hsp->hs_slot_number);
				return (HPC_ERR_FAILED);
			}
			hsc = hsp->hsc;
			hsc->hsp_last = hsp;
			if (scsb_reset_slot(hsp->hs_hpchandle,
				hsp->hs_slot_number, SCSB_UNRESET_SLOT) != 0) {

				return (HPC_ERR_FAILED);
			}
			/*
			 * Unresetting a board may have caused an interrupt
			 * burst in case of non friendly boards. So it is
			 * important to make sure that the ISR has not
			 * put this board back to disconnect state.
			 */
			delay(1);
			if (hsp->hs_flags & HSC_ENUM_FAILED) {
				hsp->hs_flags &= ~HSC_ENUM_FAILED;
				return (HPC_ERR_FAILED);
			}
			DEBUG1("hsc_connect: slot %d connected",
						hsp->hs_slot_number);
			rc = HPC_SUCCESS;
			hsp->hs_slot_state = HPC_SLOT_CONNECTED;
			(void) hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE,
				HPC_FAULT_LED, HPC_LED_OFF);
		}
	}

	/*
	 * PCI 2.2 specs recommend that the probe software wait
	 * for upto 2^25 PCI clock cycles after deassertion of
	 * PCI_RST# before the board is able to respond to config
	 * cycles. So, before we return, we wait for ~1 sec.
	 */
	delay(drv_usectohz(scsb_connect_delay * 1000));
	return (rc);
}


/* ARGSUSED */
static int
hsc_disconnect(caddr_t ops_arg, hpc_slot_t slot_hdl, void *data, uint_t flags)
{
	hsc_slot_t		*hsp = (hsc_slot_t *)ops_arg;
	hsc_state_t		*hsc;
#ifdef	DEBUG
	static const char	func[] = "hsc_disconnect";
#endif

	DEBUG1("hsc_disconnect: slot %d", hsp->hs_slot_number);

	if (hsp->hs_board_configured) {
#ifdef	DEBUG
		cmn_err(CE_NOTE,
			"%s: cannot disconnect configured board in slot %d",
			func, hsp->hs_slot_number);
#endif
		return (HPC_ERR_FAILED);
	}

	if (hsp->hs_slot_state == HPC_SLOT_EMPTY) {
#ifdef	DEBUG
		cmn_err(CE_NOTE, "%s: slot %d is empty",
			func, hsp->hs_slot_number);
#endif
		return (HPC_SUCCESS);
	}

	if (hsp->hs_slot_state == HPC_SLOT_DISCONNECTED) {
		/*
		 * if already disconnected, just return success
		 * Duplicate disconnect messages should not be failed!
		 */
		return (HPC_SUCCESS);
	}
	/* if SCB hotswapped, do not allow disconnect operations */
	if (hsp->hs_flags & HSC_SCB_HOTSWAPPED)
		return (HPC_ERR_FAILED);

	/* call scsb to disconnect the slot */
	if (scsb_disconnect_slot(hsp->hs_hpchandle, B_TRUE, hsp->hs_slot_number)
			!= DDI_SUCCESS)
		return (HPC_ERR_FAILED);
	hsc = hsp->hsc;
	if (hsc->hsp_last == hsp)
		hsc->hsp_last = NULL;

	return (HPC_SUCCESS);
}


/*
 * In the cPCI world, this operation is not applicable.
 * However, we use this function to enable full hotswap mode in debug mode.
 */
/* ARGSUSED */
static int
hsc_insert(caddr_t ops_arg, hpc_slot_t slot_hdl, void *data, uint_t flags)
{
	hsc_slot_t		*hsp = (hsc_slot_t *)ops_arg;

	if (scsb_hsc_enum_switch &&
			(scsb_enable_enum(hsp->hsc) == DDI_SUCCESS)) {
		return (HPC_SUCCESS);
	}
	return (HPC_ERR_NOTSUPPORTED);
}


/*
 * In the cPCI world, this operation is not applicable.
 * However, we use this function to disable full hotswap mode in debug mode.
 */
/* ARGSUSED */
static int
hsc_remove(caddr_t ops_arg, hpc_slot_t slot_hdl, void *data, uint_t flags)
{
	hsc_slot_t		*hsp = (hsc_slot_t *)ops_arg;

	if (scsb_hsc_enum_switch &&
			(scsb_disable_enum(hsp->hsc, SCSB_HSC_FORCE_REMOVE)
					== DDI_SUCCESS)) {
		hsp->hs_flags &= ~HSC_ENUM_FAILED;
		return (HPC_SUCCESS);
	}
	return (HPC_ERR_NOTSUPPORTED);
}

static void
hsc_led_op(hsc_slot_t *hsp, int cmd, hpc_led_t led, hpc_led_state_t led_state)
{
	hpc_led_info_t	ledinfo;

	ledinfo.led = led;
	ledinfo.state = led_state;
	(void) hsc_led_state(hsp, cmd, &ledinfo);
}

static int
hsc_led_state(hsc_slot_t *hsp, int cmd, hpc_led_info_t *hlip)
{
	hpc_led_state_t	*hlsp;
	scsb_uinfo_t	sunit;
	int		res;

	DEBUG3("hsc_led_state: slot %d, led %x, state %x",
		hsp->hs_slot_number, hlip->led, hlip->state);

	sunit.unit_type = SLOT;
	sunit.unit_number = hsp->hs_slot_number;
	/*
	 * We ignore operations on LEDs that we don't support
	 */
	switch (hlip->led) {
		case HPC_FAULT_LED:
			sunit.led_type = NOK;
			hlsp = &hsp->hs_fault_led_state;
			break;
		case HPC_ACTIVE_LED:
			sunit.led_type = OK;
			hlsp = &hsp->hs_active_led_state;
			break;
		default:
			return (HPC_ERR_NOTSUPPORTED);
	}

	switch (hlip->state) {
		case HPC_LED_BLINK:
			sunit.unit_state = BLINK;
			if (hlip->led != HPC_ACTIVE_LED)
				return (HPC_ERR_NOTSUPPORTED);
			break;
		case HPC_LED_ON:
			sunit.unit_state = ON;
			break;
		case HPC_LED_OFF:
			sunit.unit_state = OFF;
			break;
		default:
			break;
	}

	switch (cmd) {
	case HPC_CTRL_SET_LED_STATE:
		res = scsb_led_set(hsp->hs_hpchandle, &sunit, sunit.led_type);
		if (res != 0)
			return (HPC_ERR_FAILED);
		*hlsp = (hpc_led_state_t)sunit.unit_state;
		break;

	case HPC_CTRL_GET_LED_STATE:
		res = scsb_led_get(hsp->hs_hpchandle, &sunit, sunit.led_type);
		if (res)
			return (HPC_ERR_FAILED);
		/* hlip->state = sunit.unit_state; */
		break;

	default:
		return (HPC_ERR_INVALID);
	}

	return (HPC_SUCCESS);

}


static int
hsc_get_slot_state(hsc_slot_t *hsp, hpc_slot_state_t *hssp)
{
	int rstate = 0;
	int rc;
#ifdef	DEBUG
	int orstate;	/* original rstate */
#endif

	DEBUG1("hsc_get_slot_state: slot %d", hsp->hs_slot_number);
	rc = scsb_get_slot_state(hsp->hs_hpchandle, hsp->hs_slot_number,
								&rstate);
	if (rc != DDI_SUCCESS)
		return (HPC_ERR_FAILED);
#ifdef	DEBUG
	orstate = hsp->hs_slot_state;
#endif
	hsp->hs_slot_state = rstate;
	switch (hsp->hs_slot_state) {
	case HPC_SLOT_EMPTY:
		DEBUG0("empty");
		break;
	case HPC_SLOT_CONNECTED:
		DEBUG0("connected");
		break;
	case HPC_SLOT_DISCONNECTED:
		DEBUG0("disconnected");
		break;
	}

	*hssp = hsp->hs_slot_state;

	/* doing get-state above may have caused a freeze operation */
	if ((hsp->hs_flags & HSC_SCB_HOTSWAPPED) &&
			(rstate == HPC_SLOT_DISCONNECTED)) {
		/* freeze puts disconnected boards to connected state */
		*hssp = HPC_SLOT_CONNECTED;
#if 0
		/* in FHS, deassertion of reset may have configured the board */
		if (hsp->hs_board_configured == B_TRUE) {
			hsp->hs_slot_state = *hssp;
		}
#endif
	}
#ifdef	DEBUG
	/* a SCB hotswap may have forced a state change on the receptacle */
	if (orstate != *hssp) {
		cmn_err(CE_NOTE, "hsc_get_state: slot%d state change due"
			" to SCB hotswap!", hsp->hs_slot_number);
	}
#endif
	return (HPC_SUCCESS);
}


static int
hsc_set_config_state(hsc_slot_t *hsp, int cmd)
{
	hsc_state_t	*hsc = hsp->hsc;

	DEBUG1("hsc_set_config_state: slot %d", hsp->hs_slot_number);

	switch (cmd) {
	case HPC_CTRL_DEV_CONFIGURED:
		/*
		 * Closing of the Ejector switch in configured/busy state can
		 * cause duplicate CONFIGURED messages to come down.
		 * Make sure our LED states are fine.
		 */
		if (hsp->hs_board_configured == B_TRUE) {
			hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_ACTIVE_LED,
								HPC_LED_ON);
			break;
		}
		hsp->hs_board_configured = B_TRUE;
		hsp->hs_board_configuring = B_FALSE;
		if ((hsc->state & HSC_ATTACHED) == HSC_ATTACHED &&
			hsp->hs_flags & HSC_ALARM_CARD_PRES)
			(void) scsb_hsc_ac_op(hsp->hs_hpchandle,
				hsp->hs_slot_number, SCSB_HSC_AC_CONFIGURED);
		/* LED must be OFF on the occupant. */
		(void) hpc_slot_event_notify(hsp->hs_slot_handle,
					HPC_EVENT_SLOT_BLUE_LED_OFF, 0);
		if (hsp->hs_flags & HSC_AUTOCFG)
			(void) hpc_slot_event_notify(hsp->hs_slot_handle,
					HPC_EVENT_ENABLE_ENUM, 0);
		else
			(void) hpc_slot_event_notify(hsp->hs_slot_handle,
					HPC_EVENT_DISABLE_ENUM, 0);
		hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_ACTIVE_LED,
								HPC_LED_ON);
		if (hsc->hsp_last == hsp)
			hsc->hsp_last = NULL;
		break;
	case HPC_CTRL_DEV_UNCONFIGURED:
		hsp->hs_board_configured = B_FALSE;
		hsp->hs_board_unconfiguring = B_FALSE;
		hsp->hs_flags &= ~HSC_SLOT_BAD_STATE;
		if (hsp->hs_flags & HSC_ALARM_CARD_PRES)
			(void) scsb_hsc_ac_op(hsp->hs_hpchandle,
				hsp->hs_slot_number, SCSB_HSC_AC_UNCONFIGURED);
		hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_ACTIVE_LED,
							HPC_LED_BLINK);
		if (((hsc->state & HSC_ENUM_ENABLED) &&
			scsb_hsc_fhs_slot_reset) ||
		(((hsc->state & HSC_ENUM_ENABLED) != HSC_ENUM_ENABLED) &&
				scsb_hsc_bhs_slot_reset) ||
				((hsp->hs_flags & HSC_AUTOCFG) !=
					HSC_AUTOCFG)) {
			if (scsb_reset_slot(hsp->hs_hpchandle,
				hsp->hs_slot_number, SCSB_RESET_SLOT) == 0) {

				hsp->hs_slot_state = HPC_SLOT_DISCONNECTED;
				hsp->hs_board_healthy = B_FALSE;
				hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE,
					HPC_FAULT_LED, HPC_LED_ON);
			}
		}
		break;
	case HPC_CTRL_DEV_CONFIG_FAILURE:
		hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_ACTIVE_LED,
							HPC_LED_BLINK);
		hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE,
				HPC_FAULT_LED, HPC_LED_ON);
		break;
	case HPC_CTRL_DEV_UNCONFIG_FAILURE:
		hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_ACTIVE_LED,
							HPC_LED_ON);
		break;
	case HPC_CTRL_DEV_CONFIG_START:
	case HPC_CTRL_DEV_UNCONFIG_START:
			hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_FAULT_LED,
					HPC_LED_OFF);
			hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_ACTIVE_LED,
					HPC_LED_BLINK);
		break;
	default:
		return (HPC_ERR_INVALID);
	}

	if (cmd != HPC_CTRL_DEV_CONFIG_START &&
		cmd != HPC_CTRL_DEV_UNCONFIG_START &&
		hsc->regDone == B_FALSE &&
			scsb_hsc_numReg < hsc->n_registered_occupants) {
		scsb_hsc_numReg++;

		/*
		 * If the callback is invoked for all registered slots,
		 * enable ENUM.
		 */
		if (((hsc->state & HSC_ATTACHED) == HSC_ATTACHED) &&
			(scsb_hsc_numReg == hsc->n_registered_occupants)) {
			hsc->regDone = B_TRUE;
			if (hsc->hotswap_mode == HSC_HOTSWAP_MODE_FULL) {
#ifdef DEBUG
				cmn_err(CE_CONT, "%s%d: Enabling full hotswap"
					":%d non-empty slots\n",
					ddi_driver_name(hsc->dip),
					ddi_get_instance(hsc->dip),
					hsc->n_registered_occupants);
#endif
				if (scsb_enable_enum(hsc) != DDI_SUCCESS) {
					cmn_err(CE_WARN, "%s#%d: Cannot enable "
						"Full Hotswap",
						ddi_driver_name(hsc->dip),
						ddi_get_instance(hsc->dip));

					return (HPC_ERR_FAILED);
				}
			}
		}
	}

	return (HPC_SUCCESS);
}


/*ARGSUSED*/
static int
hsc_get_board_type(hsc_slot_t *hsp, hpc_board_type_t *hbtp)
{
	*hbtp = hsp->hs_board_type;
	return (HPC_SUCCESS);
}


/* ARGSUSED */
static int
hsc_autoconfig(hsc_slot_t *hsp, int cmd)
{
	int res = HPC_SUCCESS, enum_disable = B_TRUE, i;
	char slotautocfg_prop[18];
	hsc_state_t *hsc;

	DEBUG1("hsc_autoconfig: slot %d", hsp->hs_slot_number);
	(void) sprintf(slotautocfg_prop, "slot%d-autoconfig",
	    hsp->hs_slot_number);

	if (cmd == HPC_CTRL_ENABLE_AUTOCFG) {
		hsp->hs_flags |= HSC_AUTOCFG;
		(void) ddi_prop_update_string(DDI_DEV_T_NONE, hsp->hsc->dip,
				slotautocfg_prop, "enabled");
		if ((res = scsb_enable_enum(hsp->hsc)) == DDI_SUCCESS) {
			(void) hpc_slot_event_notify(hsp->hs_slot_handle,
					HPC_EVENT_ENABLE_ENUM, 0);
		}
	} else {
		(void) ddi_prop_update_string(DDI_DEV_T_NONE, hsp->hsc->dip,
		    slotautocfg_prop, "disabled");
		hsp->hs_flags &= ~HSC_AUTOCFG;
		hsc = hsp->hsc;
		if (hsc->state & HSC_ATTACHED) {
			(void) hpc_slot_event_notify(hsp->hs_slot_handle,
						HPC_EVENT_DISABLE_ENUM, 0);
			for (i = 0; i < hsc->slot_table_size; i++) {
				hsc_slot_t	*thsp;
				int slotnum;

				slotnum = hsc->slot_table_prop[i].pslotnum;
				thsp = hsc_find_slot(slotnum);
				if (thsp == NULL) {
					cmn_err(CE_WARN, "%s#%d: hsc_autocfg:"
						"No Slot Info for slot %d",
						ddi_driver_name(hsc->dip),
						ddi_get_instance(hsc->dip),
						slotnum);
					continue;
				}
				if (thsp->hs_flags & HSC_AUTOCFG) {
					enum_disable = B_FALSE;
					break;
				}
			}
			if (enum_disable == B_TRUE)
				(void) scsb_disable_enum(hsc,
				    SCSB_HSC_FORCE_REMOVE);
		}
	}
	return (res);
}


/*
 * This function is invoked to enable/disable a slot
 */
/* ARGSUSED */
#ifndef	lint
static int
hsc_slot_enable(hsc_slot_t *hsp, boolean_t enabled)
{
	scsb_uinfo_t	sunit;
	int		res;

	DEBUG1("hsc_slot_enable: slot %d", hsp->hs_slot_number);

	sunit.unit_type = SLOT;
	sunit.unit_number = hsp->hs_slot_number;
	if (enabled)
		sunit.unit_state = ON;
	else
		sunit.unit_state = OFF;

	res = scsb_reset_unit(hsp->hs_hpchandle, &sunit);
	if (res == 0)
		return (HPC_SUCCESS);
	else if (res == EINVAL)
		return (HPC_ERR_INVALID);
	else
		return (HPC_ERR_FAILED);
}
#endif


/*ARGSUSED*/
static int
hsc_control(caddr_t ops_arg, hpc_slot_t slot_hdl, int request, caddr_t arg)
{
	hsc_slot_t *hsp = (hsc_slot_t *)ops_arg;
	int rc = HPC_SUCCESS;

	DEBUG2("hsc_control: slot %d, op=%x\n", hsp->hs_slot_number, request);

	switch (request) {
	case HPC_CTRL_GET_LED_STATE:
		return (hsc_led_state(hsp,
			HPC_CTRL_GET_LED_STATE, (hpc_led_info_t *)arg));

	case HPC_CTRL_SET_LED_STATE:
		return (hsc_led_state(hsp,
			HPC_CTRL_SET_LED_STATE, (hpc_led_info_t *)arg));

	case HPC_CTRL_GET_SLOT_STATE:
		return (hsc_get_slot_state(hsp, (hpc_slot_state_t *)arg));

	case HPC_CTRL_DEV_CONFIGURED:
		return (hsc_set_config_state(hsp, HPC_CTRL_DEV_CONFIGURED));

	case HPC_CTRL_DEV_UNCONFIGURED:
		return (hsc_set_config_state(hsp, HPC_CTRL_DEV_UNCONFIGURED));

	case HPC_CTRL_DEV_CONFIG_FAILURE:
		return (hsc_set_config_state(hsp, HPC_CTRL_DEV_CONFIG_FAILURE));

	case HPC_CTRL_DEV_UNCONFIG_FAILURE:
		return (hsc_set_config_state(hsp,
				HPC_CTRL_DEV_UNCONFIG_FAILURE));

	case HPC_CTRL_DEV_CONFIG_START:
	case HPC_CTRL_DEV_UNCONFIG_START:
		return (hsc_set_config_state(hsp, request));

	case HPC_CTRL_GET_BOARD_TYPE:
		return (hsc_get_board_type(hsp, (hpc_board_type_t *)arg));

	case HPC_CTRL_DISABLE_AUTOCFG:
		return (hsc_autoconfig(hsp, HPC_CTRL_DISABLE_AUTOCFG));

	case HPC_CTRL_ENABLE_AUTOCFG:
		return (hsc_autoconfig(hsp, HPC_CTRL_ENABLE_AUTOCFG));

	case HPC_CTRL_DISABLE_SLOT:
		/*
		 * No hardware support for disabling the slot.
		 * Just imitate a disable_autoconfig operation for now
		 */
		if (hsp->hs_board_configured == B_TRUE)
			return (HPC_ERR_FAILED);
		if (scsb_hsc_disable_slot(hsp) != DDI_SUCCESS)
			rc = HPC_ERR_FAILED;
		return (rc);

	case HPC_CTRL_ENABLE_SLOT:
		if (scsb_hsc_enable_slot(hsp) != DDI_SUCCESS)
			rc = HPC_ERR_FAILED;
		return (rc);

	case HPC_CTRL_ENABLE_ENUM:
		return (scsb_enable_enum(hsp->hsc));

	case HPC_CTRL_DISABLE_ENUM:
		return (scsb_disable_enum(hsp->hsc, 0));

	default:
		return (HPC_ERR_INVALID);
	}
}

static int
scsb_hsc_disable_slot(hsc_slot_t *hsp)
{
	int rc;
	char slot_disable_prop[18];

	DEBUG1("hsc_disable_slot: slot %d", hsp->hs_slot_number);
	(void) sprintf(slot_disable_prop, "slot%d-status", hsp->hs_slot_number);

	rc = scsb_reset_slot(hsp->hs_hpchandle, hsp->hs_slot_number,
					SCSB_RESET_SLOT);
	if (rc == DDI_SUCCESS) {
		(void) hsc_autoconfig(hsp, HPC_CTRL_DISABLE_AUTOCFG);
		hsp->hs_flags &= ~HSC_SLOT_ENABLED;
		(void) ddi_prop_update_string(DDI_DEV_T_NONE, hsp->hsc->dip,
		    slot_disable_prop, "disabled");
	} else
		rc = DDI_FAILURE;
	return (rc);
}

static int
scsb_hsc_enable_slot(hsc_slot_t *hsp)
{
	int rc;
	char slot_disable_prop[18];

	DEBUG1("hsc_disable_slot: slot %d", hsp->hs_slot_number);
	(void) sprintf(slot_disable_prop, "slot%d-status", hsp->hs_slot_number);

	rc = scsb_reset_slot(hsp->hs_hpchandle, hsp->hs_slot_number,
					SCSB_UNRESET_SLOT);
	if (rc == DDI_SUCCESS) {
		(void) hsc_autoconfig(hsp, HPC_CTRL_ENABLE_AUTOCFG);
		hsp->hs_flags |= HSC_SLOT_ENABLED;
		(void) ddi_prop_remove(DDI_DEV_T_NONE, hsp->hsc->dip,
		    slot_disable_prop);
	} else
		rc = HPC_ERR_FAILED;
	return (rc);
}

#define	NEW(type)	(type *) kmem_zalloc(sizeof (type), KM_SLEEP)

static hsc_slot_t *
hsc_alloc_slot(
		uint16_t	device_number,
		int		slot_number,
		boolean_t	board_in_slot)
{
	hpc_slot_info_t	*hsip;
	hsc_slot_t	*hsp = NEW(hsc_slot_t);

	DEBUG2("hsc_alloc_slot: slot %d %s", slot_number,
		board_in_slot ? "occupied" : "empty");

	if (hsp == NULL) {
		cmn_err(CE_NOTE,
			"hsc_alloc_slot: allocation failed for slot %d",
			slot_number);
		return (NULL);
	}

	hsip = &hsp->hs_info;

	hsip->version			= HPC_SLOT_INFO_VERSION;
	hsip->slot_type			= HPC_SLOT_TYPE_CPCI;
	hsip->pci_dev_num		= device_number;
	hsip->pci_slot_capabilities	= 0;
	hsip->slot_flags		= HPC_SLOT_CREATE_DEVLINK;
	/*
	 * Note: the name *must* be 'pci' so that the correct cfgadm plug-in
	 *	 library is selected
	 */
	(void) sprintf(hsip->pci_slot_name, "cpci_slot%d", slot_number);

	/*
	 * We assume that the following LED settings reflect
	 * the hardware state.
	 * After we register the slot, we will be invoked by the nexus
	 * if the slot is occupied, and we will turn on the LED then.
	 */
	hsp->hs_active_led_state	= HPC_LED_OFF;
	hsp->hs_fault_led_state		= HPC_LED_OFF;

	hsp->hs_board_configured	= B_FALSE;
	hsp->hs_board_healthy		= B_FALSE;
	hsp->hs_board_type		= HPC_BOARD_UNKNOWN;

	hsp->hs_flags			= HSC_ENABLED | HSC_SLOT_ENABLED;
	hsp->hs_slot_number		= slot_number;

	/*
	 * we should just set this to connected,
	 * as MC slots are always connected.
	 */
	if (board_in_slot)
		hsp->hs_slot_state = HPC_SLOT_CONNECTED;
	else
		hsp->hs_slot_state = HPC_SLOT_EMPTY;

	return (hsp);
}


static void
hsc_free_slot(hsc_slot_t *hsp)
{
	DEBUG0("hsc_free_slot");

	kmem_free(hsp, sizeof (*hsp));
}


/*
 * This function is invoked to register a slot
 */
static int
hsc_slot_register(
	hsc_state_t	*hsc,
	char		*bus_path,	/* PCI nexus pathname */
	uint16_t	device_number,	/* PCI device number */
	uint_t		slot_number,	/* physical slot number */
	boolean_t	board_in_slot)	/* receptacle status */
{
	int		rc = HPC_SUCCESS;
	hsc_slot_t	*hsp;

	DEBUG2("hsc_slot_register: slot number %d, device number %d",
		slot_number, device_number);

	hsp = hsc_alloc_slot(device_number, slot_number,
			board_in_slot);

	if (hsp == NULL) {
#ifdef	DEBUG
		cmn_err(CE_NOTE, "hsc_slot_register: hsc_alloc_slot failed");
#endif
		return (HPC_ERR_FAILED);
	}

	hsp->hs_hpchandle = hsc->scsb_handle; /* handle for call backs */
	hsp->hsc = hsc;

	rc = scsb_hsc_init_slot_state(hsc, hsp);
	if (rc != DDI_SUCCESS)
		return (HPC_ERR_FAILED);

	/* slot autoconfiguration by default. */
	if (hsc->hotswap_mode == HSC_HOTSWAP_MODE_FULL)
		(void) hsc_autoconfig(hsp, HPC_CTRL_ENABLE_AUTOCFG);
	else
		(void) hsc_autoconfig(hsp, HPC_CTRL_DISABLE_AUTOCFG);

	/*
	 * Append to our list
	 */
	mutex_enter(&hsc_mutex);
	hsp->hs_next = hsc_slot_list;
	hsc_slot_list = hsp;
	mutex_exit(&hsc_mutex);

	rc = hpc_slot_register(hsc->dip,
			bus_path,
			&hsp->hs_info,
			&hsp->hs_slot_handle,	/* return value */
			hsc_slotops,
			(caddr_t)hsp,
			0);

	if (rc != HPC_SUCCESS) {
		cmn_err(CE_WARN, "%s#%d: failed to register slot %s:%d",
			ddi_driver_name(hsc->dip), ddi_get_instance(hsc->dip),
			bus_path, device_number);
		hsc_free_slot(hsp);
		return (rc);
	}

	DEBUG0("hsc_slot_register: hpc_slot_register successful");

	return (rc);
}


static int
hsc_slot_unregister(int slot_number)
{
	hsc_slot_t	*hsp, *prev;

	DEBUG1("hsc_slot_unregister: slot number %d", slot_number);

	mutex_enter(&hsc_mutex);
	hsp = prev = NULL;
	for (hsp = hsc_slot_list; hsp != NULL; hsp = hsp->hs_next) {
		if (hsp->hs_slot_number == slot_number) {
			if (prev == NULL) /* first entry */
				hsc_slot_list = hsc_slot_list->hs_next;
			else
				prev->hs_next = hsp->hs_next;
			hsp->hs_next = NULL;
			break;
		}
		prev = hsp;
	}
	mutex_exit(&hsc_mutex);

	if (hsp != NULL) {
		(void) hpc_slot_unregister(&hsp->hs_slot_handle);
		if ((hsp->hsc->state & HSC_ATTACHED) != HSC_ATTACHED &&
				hsp->hs_slot_state != HPC_SLOT_EMPTY) {
			hsp->hsc->n_registered_occupants--;
		}
		hsc_free_slot(hsp);
		return (0);
	}
	return (1);
}

static int
scsb_hsc_init_slot_state(hsc_state_t *hsc, hsc_slot_t *hsp)
{
	int rc, rstate;
	int slot_number = hsp->hs_slot_number;
	scsb_state_t	*scsb = (scsb_state_t *)hsc->scsb_handle;

	rc = scsb_get_slot_state(hsc->scsb_handle, slot_number, &rstate);
	if (rc != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Set the healthy status for this slot
	 */
	hsp->hs_board_healthy = scsb_read_slot_health(scsb, slot_number);
	hsp->hs_slot_state = rstate;
	switch (rstate) {
		case HPC_SLOT_EMPTY:
			/*
			 * this will clear any state differences between
			 * SCB Freeze operations.
			 */
			hsp->hs_slot_state = HPC_SLOT_EMPTY;
			/* slot empty. */
			(void) scsb_reset_slot(hsc->scsb_handle, slot_number,
			    SCSB_RESET_SLOT);
			hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_ACTIVE_LED,
			    HPC_LED_OFF);
			hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_FAULT_LED,
			    HPC_LED_OFF);
			break;
		case HPC_SLOT_DISCONNECTED:
			/*
			 * this will clear any state differences between
			 * SCB Freeze operations.
			 */
			hsp->hs_slot_state = HPC_SLOT_DISCONNECTED;
			/* check recovery from SCB freeze */
			if (hsp->hs_board_configured != B_TRUE) {
				/*
				 * Force a disconnect just in case there are
				 * differences between healthy and reset states.
				 */
				(void) scsb_reset_slot(hsc->scsb_handle,
				    slot_number, SCSB_RESET_SLOT);
				/*
				 * Slot in reset. OBP has not probed this
				 * device. Hence it is ok to remove this board.
				 */
				hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE,
						HPC_ACTIVE_LED, HPC_LED_BLINK);
				hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE,
						HPC_FAULT_LED, HPC_LED_ON);
				break;
			}
			/*FALLTHROUGH*/
		case HPC_SLOT_CONNECTED:
			/*
			 * this will clear any state differences between
			 * SCB Freeze operations.
			 */
			hsp->hs_slot_state = HPC_SLOT_CONNECTED;
			/*
			 * OBP should have probed this device, unless
			 * it was plugged in during the boot operation
			 * before the driver was loaded. In any case,
			 * no assumption is made and hence we take
			 * the conservative approach by keeping fault
			 * led off so board removal is not allowed.
			 */
			if (hsp->hs_board_configured == B_TRUE)
				hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE,
					HPC_ACTIVE_LED, HPC_LED_ON);
			else
				hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE,
					HPC_ACTIVE_LED, HPC_LED_BLINK);
			hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_FAULT_LED,
							HPC_LED_OFF);
			/*
			 * Netra ct alarm card hotswap support
			 */
			if (slot_number == scsb->ac_slotnum &&
				scsb->scsb_hsc_state & SCSB_ALARM_CARD_PRES) {
				hsp->hs_flags |= HSC_ALARM_CARD_PRES;
				DEBUG0("Xscsb_hsc_init_slot_state: "
						"set HSC_ALARM_CARD_PRES");
			}
			break;
		default:
			break;
	}
	return (rc);
}

static hsc_slot_t *
hsc_get_slot_info(hsc_state_t *hsc, int pci_devno)
{
	int i;

	for (i = 0; i < hsc->slot_table_size; i++) {

		if (hsc->slot_table_prop[i].pci_devno == pci_devno)
			return ((hsc_slot_t *)hsc_find_slot(
				hsc->slot_table_prop[i].pslotnum));
	}
	return (NULL);
}

static hsc_slot_t *
hsc_find_slot(int slot_number)
{
	hsc_slot_t	*hsp;

	mutex_enter(&hsc_mutex);
	for (hsp = hsc_slot_list; hsp != NULL; hsp = hsp->hs_next) {
		if (hsp->hs_slot_number == slot_number)
			break;
	}
	mutex_exit(&hsc_mutex);
	return (hsp);
}


/*
 * This function is invoked by the SCSB when an interrupt
 * happens to indicate that a board has been inserted-in/removed-from
 * the specified slot.
 */
int
hsc_slot_occupancy(int slot_number, boolean_t occupied, int flags, int healthy)
{
	static const char	func[]	= "hsc_slot_occupancy";
	hsc_slot_t		*hsp;
	int			rc = DDI_SUCCESS;

	DEBUG4("hsc_slot_occupancy: slot %d %s, ac=%d, healthy=%d",
			slot_number, occupied ? "occupied" : "not occupied",
			(flags == ALARM_CARD_ON_SLOT) ? 1:0, healthy);

	hsp = hsc_find_slot(slot_number);

	if (hsp == NULL) {
		cmn_err(CE_NOTE,
			"%s: cannot map slot number %d to a hsc_slot_t",
			func, slot_number);
		return (DDI_FAILURE);
	}

	hsp->hs_board_healthy = healthy;
	if (occupied) {
		/*
		 * A board was just inserted. We are disconnected at this point.
		 */
		if (hsp->hs_slot_state == HPC_SLOT_EMPTY)
			hsp->hs_board_type = HPC_BOARD_CPCI_HS;
		hsp->hs_slot_state = HPC_SLOT_DISCONNECTED;
		if (flags == ALARM_CARD_ON_SLOT) {
			hsp->hs_flags |= HSC_ALARM_CARD_PRES;
			DEBUG0("Xhsc_slot_occupancy: set HSC_ALARM_CARD_PRES");
		}
		hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_FAULT_LED,
						HPC_LED_ON);
		/*
		 * if previous occupant stayed configured, do not allow another
		 * occupant to be connected.
		 * So as soon as the board is plugged in, we turn both LEDs On.
		 * This behaviour is an indication that the slot state
		 * is not clean.
		 */
		if (hsp->hs_flags & HSC_SLOT_BAD_STATE) {
			hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_ACTIVE_LED,
								HPC_LED_ON);
			return (DDI_SUCCESS);
		}

		/* Do not allow connect if slot is disabled */
		if ((hsp->hs_flags & HSC_SLOT_ENABLED) != HSC_SLOT_ENABLED)
			return (DDI_SUCCESS);
		/* if no healthy, we stay disconnected. */
		if (healthy == B_FALSE) {
			return (DDI_SUCCESS);
		}
		rc = hsc_slot_autoconnect(hsp);
		hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_ACTIVE_LED,
								HPC_LED_BLINK);
	} else {
		/*
		 * A board was just removed
		 */
		hsp->hs_slot_state = HPC_SLOT_EMPTY;
		hsp->hs_board_type = HPC_BOARD_UNKNOWN;
		hsp->hs_flags &= ~HSC_ENUM_FAILED;
		if (hsp->hs_flags & HSC_ALARM_CARD_PRES) {
			hsp->hs_flags &= ~HSC_ALARM_CARD_PRES;
			DEBUG0("Xhsc_slot_occupancy:clear HSC_ALARM_CARD_PRES");
		}
		if (hsp->hs_board_configured == B_TRUE) {
			(void) hpc_slot_event_notify(hsp->hs_slot_handle,
					HPC_EVENT_SLOT_NOT_HEALTHY, 0);
			cmn_err(CE_WARN, "%s#%d: ALERT! Surprise Removal "
				" on Slot %d, Occupant Online!!",
					ddi_driver_name(hsp->hsc->dip),
					ddi_get_instance(hsp->hsc->dip),
					slot_number);
			cmn_err(CE_WARN, "%s#%d: ALERT! System now in "
				" Inconsistent State! Slot disabled. Halt!",
					ddi_driver_name(hsp->hsc->dip),
					ddi_get_instance(hsp->hsc->dip));
			/* Slot in reset and disabled */
			(void) scsb_hsc_disable_slot(hsp);
			hsp->hs_flags |= HSC_SLOT_BAD_STATE;
			/* the following works for P1.0 only. */
			hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_FAULT_LED,
						HPC_LED_ON);
			hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_ACTIVE_LED,
								HPC_LED_ON);
		} else {
			hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_FAULT_LED,
						HPC_LED_OFF);
			hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_ACTIVE_LED,
								HPC_LED_OFF);
		}
	}
	return (rc);
}


/*
 * This function is invoked by the SCSB when the health status of
 * a board changes.
 */
/*ARGSUSED*/
int
scsb_hsc_board_healthy(int slot_number, boolean_t healthy)
{
	hsc_slot_t		*hsp;
	hsc_state_t		*hsc;

	DEBUG2("hsc_board_healthy: slot %d = %d\n", slot_number, healthy);

	hsp = hsc_find_slot(slot_number);
	if (hsp == NULL) {
		cmn_err(CE_NOTE, "hsc_board_healthy: No Slot Info.");
		return (DDI_FAILURE);
	}

	hsc = hsp->hsc;
	if (hsp->hs_slot_state == HPC_SLOT_EMPTY) {
#ifdef	DEBUG
		cmn_err(CE_NOTE, "%s#%d: Healthy# %s on "
			"empty slot %d", ddi_driver_name(hsc->dip),
			ddi_get_instance(hsc->dip),
			healthy == B_TRUE ? "On" : "Off", slot_number);
#endif
		return (DDI_FAILURE);
	}
	if (hsp->hs_slot_state == HPC_SLOT_DISCONNECTED) {
		DEBUG2("healthy %s on disconnected slot %d\n",
			healthy == B_TRUE ? "On":"Off", slot_number);
		/*
		 * Connect the slot if board healthy and in autoconfig mode.
		 */
		hsp->hs_board_healthy = healthy;
		if (healthy == B_TRUE)
			return (hsc_slot_autoconnect(hsp));
	}

	/*
	 * the board is connected. The result could be seviour depending
	 * on the occupant state.
	 */
	if (healthy == B_TRUE) {
		if (hsp->hs_board_healthy != B_TRUE) {
			hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE, HPC_FAULT_LED,
					HPC_LED_OFF);
			/* Regained HEALTHY# at Run Time...!!! */
			cmn_err(CE_NOTE, "%s#%d: slot %d Occupant "
				"%s, Regained HEALTHY#!",
				ddi_driver_name(hsc->dip),
				ddi_get_instance(hsc->dip), slot_number,
				hsp->hs_board_configured == B_TRUE ?
						"configured" : "Unconfigured");
			(void) hpc_slot_event_notify(hsp->hs_slot_handle,
				HPC_EVENT_SLOT_HEALTHY_OK, 0);
		}
	} else {
		if (hsp->hs_board_configured == B_TRUE) {
			/* Lost HEALTHY# at Run Time...Serious Condition. */
			cmn_err(CE_WARN, "%s#%d: ALERT! Lost HEALTHY#"
				" on Slot %d, Occupant %s",
				ddi_driver_name(hsc->dip),
				ddi_get_instance(hsc->dip), slot_number,
					hsp->hs_board_configured == B_TRUE ?
						"Online!!!" : "Offline");
			(void) hpc_slot_event_notify(hsp->hs_slot_handle,
					HPC_EVENT_SLOT_NOT_HEALTHY, 0);
		}
		if ((hsp->hs_board_configured != B_TRUE) ||
						scsb_hsc_healthy_reset) {
			if (scsb_reset_slot(hsp->hs_hpchandle,
					slot_number, SCSB_RESET_SLOT) == 0) {
				/* signal Ok to remove board. */
				hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE,
					HPC_FAULT_LED, HPC_LED_ON);
				cmn_err(CE_WARN, "%s#%d: Slot %d "
					"successfully taken offline",
					ddi_driver_name(hsc->dip),
					ddi_get_instance(hsc->dip),
					slot_number);
			}
		}
	}
	hsp->hs_board_healthy = healthy;
	return (DDI_SUCCESS);
}

static int
hsc_slot_autoconnect(hsc_slot_t *hsp)
{
	hsc_state_t *hsc = hsp->hsc;
	int rc = DDI_SUCCESS;
	/*
	 * Keep slot in reset unless autoconfiguration is enabled
	 * Ie. for Basic Hotswap mode, we stay disconnected at
	 * insertion. For full hotswap mode, we automatically
	 * go into connected state at insertion, so that occupant
	 * autoconfiguration is possible.
	 */
	if (((hsc->state & HSC_ENUM_ENABLED) == HSC_ENUM_ENABLED) &&
			(hsp->hs_flags & HSC_AUTOCFG)) {
		/* this statement must be here before unreset. */
		hsc->hsp_last = hsp;
		if ((rc = scsb_reset_slot(hsp->hs_hpchandle,
			hsp->hs_slot_number, SCSB_UNRESET_SLOT)) == 0) {

			hsp->hs_slot_state = HPC_SLOT_CONNECTED;
			hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE,
					HPC_FAULT_LED, HPC_LED_OFF);
		} else {
			hsc->hsp_last = NULL;
			rc = DDI_FAILURE;
		}
	}
	return (rc);
}

/*
 * The SCSB code should invoke this function from its _init() function.
 */
int
hsc_init()
{
	int rc;

	rc = ddi_soft_state_init(&hsc_state, sizeof (hsc_state_t), 1);
	if (rc != 0)
		return (rc);

	hsc_slotops = hpc_alloc_slot_ops(KM_SLEEP);

	hsc_slotops->hpc_version	= HPC_SLOT_OPS_VERSION;
	hsc_slotops->hpc_op_connect	= hsc_connect;
	hsc_slotops->hpc_op_disconnect	= hsc_disconnect;
	hsc_slotops->hpc_op_insert	= hsc_insert;
	hsc_slotops->hpc_op_remove	= hsc_remove;
	hsc_slotops->hpc_op_control	= hsc_control;

	return (DDI_SUCCESS);
}


/*
 * The SCSB code should invoke this function from its _fini() function.
 */
int
hsc_fini()
{
	if (hsc_slotops != NULL) {
		hpc_free_slot_ops(hsc_slotops);
		hsc_slotops = NULL;
	}
	ddi_soft_state_fini(&hsc_state);
	return (DDI_SUCCESS);
}

static int
scsb_enable_enum(hsc_state_t *hsc)
{
	DEBUG0("hsc: Enable ENUM#\n");

	if ((hsc->state & HSC_ENUM_ENABLED) == HSC_ENUM_ENABLED)
		return (DDI_SUCCESS);
	if ((hsc->state & HSC_ATTACHED) != HSC_ATTACHED)
		return (DDI_FAILURE);

	if (ddi_add_intr(hsc->dip, 1, NULL, NULL,
			hsc_enum_intr, (caddr_t)hsc) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s#%d: failed ENUM# interrupt registration",
			ddi_driver_name(hsc->dip), ddi_get_instance(hsc->dip));
		return (DDI_FAILURE);
	}
	cmn_err(CE_CONT, "?%s%d: Successfully Upgraded to "
			"Full Hotswap Mode\n", ddi_driver_name(hsc->dip),
			ddi_get_instance(hsc->dip));
	hsc->state |= HSC_ENUM_ENABLED;
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, hsc->dip,
	    HOTSWAP_MODE_PROP, "full");
	return (DDI_SUCCESS);

}

/*ARGSUSED*/
static int
scsb_disable_enum(hsc_state_t *hsc, int op)
{

	DEBUG0("hsc: Disable ENUM#\n");
	if (op == SCSB_HSC_FORCE_REMOVE) {
		/*
		 * Clear all pending interrupts before unregistering
		 * the interrupt. Otherwise the system will hang.
		 *
		 * Due to the hang problem, we'll not turn off or disable
		 * interrupts because if there's a non-friendly full hotswap
		 * device out there, the ENUM# will be kept asserted and
		 * hence hsc_clear_all_enum() can never deassert ENUM#.
		 * So the system will hang.
		 */
		if ((hsc->state & HSC_ENUM_ENABLED) == HSC_ENUM_ENABLED) {
			/* hsc_clear_all_enum(hsc); */
			ddi_remove_intr(hsc->dip, 1, NULL);
			hsc->state &= ~HSC_ENUM_ENABLED;
			cmn_err(CE_CONT, "?%s%d: Successfully Downgraded to "
				"Basic Hotswap Mode\n",
				ddi_driver_name(hsc->dip),
				ddi_get_instance(hsc->dip));
		}
		(void) ddi_prop_update_string(DDI_DEV_T_NONE, hsc->dip,
		    HOTSWAP_MODE_PROP, "basic");
		return (DDI_SUCCESS);
	} else
		/* No programming interface for disabling ENUM# on MC/Tonga */
		return (HPC_ERR_NOTSUPPORTED);
}

#ifndef	lint
static int
hsc_clear_all_enum(hsc_state_t *hsc)
{
	int i, rc;
	hsc_slot_t *hsp;

	for (i = 0; i < hsc->slot_table_size; i++) {

		hsp = hsc_find_slot(hsc->slot_table_prop[i].pslotnum);
		if (hsp == NULL)
			continue;
		rc = hpc_slot_event_notify(hsp->hs_slot_handle,
					HPC_EVENT_CLEAR_ENUM,
						HPC_EVENT_SYNCHRONOUS);
		if (rc == HPC_EVENT_UNCLAIMED)
			break;	/* no pending interrupts across the bus */
		DEBUG1("Pending Intr on slot %d\n",
			hsc->slot_table_prop[i].pslotnum);
	}
	return (0);
}
#endif

int
scsb_hsc_attach(dev_info_t *dip, void *scsb_handle, int instance)
{
	int i, n, prop_len;
	int prom_prop = 0;	/* default: OS property gives slot-table */
	int rc;
	char *hotswap_model;
	hsc_state_t	*hsc;
	scsb_state_t	*scsb = (scsb_state_t *)scsb_handle;
	caddr_t hpc_slot_table_data, s;
	int hpc_slot_table_size;
	hsc_prom_slot_table_t	*hpstp;
	int rstate;

	DEBUG0("hsc_attach: enter\n");
	/*
	 * To get the slot information,
	 * The OBP defines the 'slot-table' property. But the OS
	 * can override it with 'hsc-slot-map' property
	 * through the .conf file.
	 * Since the formats are different, 2 different property names
	 * are chosen.
	 * The OBP property format is
	 * <phandle>,<pci-devno>,<phys-slotno>,<ga-bits>
	 * The OS property format is (ga-bits is not used however)
	 * <busnexus-path>,<pci-devno>,<phys-slotno>,<ga-bits>
	 */
	rc = ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		"hsc-slot-map", (caddr_t)&hpc_slot_table_data,
		&hpc_slot_table_size);
	if (rc != DDI_PROP_SUCCESS)  {
		prom_prop = 1;
		rc = ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
			"slot-table", (caddr_t)&hpc_slot_table_data,
			&hpc_slot_table_size);
		if (rc != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "%s#%d: 'slot-table' property "
				"missing!", ddi_driver_name(dip),
						ddi_get_instance(dip));
			return (DDI_FAILURE);
		}
	}
	rc = ddi_soft_state_zalloc(hsc_state, instance);
	if (rc != DDI_SUCCESS)
		return (DDI_FAILURE);

	hsc = (hsc_state_t *)ddi_get_soft_state(hsc_state, instance);
	hsc->scsb_handle = scsb_handle;
	hsc->dip = dip;
	hsc->instance = instance;
	hsc->n_registered_occupants = 0;
	hsc->regDone = B_FALSE;
	/* hsc->slot_info = hsc_slot_list; */

	/*
	 * Check whether the system should be in basic or full
	 * hotswap mode. The PROM property always says full, so
	 * look at the .conf file property whether this is "full"
	 */
	if (scsb_hsc_enable_fhs) {
		hsc->hotswap_mode = HSC_HOTSWAP_MODE_FULL;
	} else {
		hsc->hotswap_mode = HSC_HOTSWAP_MODE_BASIC;
	}

	rc = ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		"default-hotswap-mode", (caddr_t)&hotswap_model, &prop_len);

	if (rc == DDI_PROP_SUCCESS) {
		if (strcmp(hotswap_model, "full") == 0) {
			hsc->hotswap_mode = HSC_HOTSWAP_MODE_FULL;
		} else if (strcmp(hotswap_model, "basic") == 0) {
			hsc->hotswap_mode = HSC_HOTSWAP_MODE_BASIC;
		}

		kmem_free(hotswap_model, prop_len);
	}

	/*
	 * Determine the size of the slot table from the property and
	 * allocate the slot table arrary..Decoding is different for
	 * OS and PROM property.
	 */
	if (!prom_prop) {	/* OS .conf property */
		for (i = 0, n = 0; i < hpc_slot_table_size; i++) {
			if (hpc_slot_table_data[i] == 0) {
				n++;
			}
		}

		/* There should be four elements per entry */
		if (n % 4) {
			cmn_err(CE_WARN, "%s#%d: bad format for "
				"slot-table(%d)", ddi_driver_name(dip),
						ddi_get_instance(dip), n);
			kmem_free(hpc_slot_table_data, hpc_slot_table_size);
			ddi_soft_state_free(hsc_state, instance);
			return (DDI_FAILURE);
		}

		hsc->slot_table_size = n / 4;
	} else {
		hsc->slot_table_size = hpc_slot_table_size /
						sizeof (hsc_prom_slot_table_t);
		n = hpc_slot_table_size % sizeof (hsc_prom_slot_table_t);
		if (n) {
			cmn_err(CE_WARN, "%s#%d: bad format for "
				"slot-table(%d)", ddi_driver_name(dip),
				ddi_get_instance(dip), hpc_slot_table_size);
			kmem_free(hpc_slot_table_data, hpc_slot_table_size);
			ddi_soft_state_free(hsc_state, instance);
			return (DDI_FAILURE);
		}
	}

	/*
	 * Netract800 FTC (formerly known as CFTM) workaround.
	 * Leave Slot 2 out of the HS table if FTC is present in Slot 2
	 */
	if (scsb->scsb_hsc_state & SCSB_HSC_CTC_PRES) {
		hsc->slot_table_size -= 1;
	}
	DEBUG1("hsc_attach: %d hotplug slots on bus\n", hsc->slot_table_size);
	/*
	 * Create enough space for each slot table entry
	 * based on how many entries in the property
	 */
	hsc->slot_table_prop = (hsc_slot_table_t *)
		kmem_zalloc(hsc->slot_table_size *
			sizeof (hsc_slot_table_t), KM_SLEEP);

	if (!prom_prop) {
		s = hpc_slot_table_data;
		for (i = 0; i < hsc->slot_table_size; i++) {

			char *nexus, *pcidev, *phys_slotname, *ga;

			/* Pick off pointer to nexus path or PROM handle */
			nexus = s;
			while (*s != NULL)
				s++;
			s++;

			/* Pick off pointer to the pci device number */
			pcidev = s;
			while (*s != NULL)
				s++;
			s++;

			/* Pick off physical slot no */
			phys_slotname = s;
			while (*s != NULL)
				s++;
			s++;

			/* Pick off GA bits which we dont use for now. */
			ga = s;
			while (*s != NULL)
				s++;
			s++;

			if (scsb->scsb_hsc_state & SCSB_HSC_CTC_PRES &&
					atoi(phys_slotname) == SC_MC_CTC_SLOT) {
				--i;
				continue;
			}
			hsc->slot_table_prop[i].pslotnum = atoi(phys_slotname);
			hsc->slot_table_prop[i].ga = atoi(ga);
			hsc->slot_table_prop[i].pci_devno = atoi(pcidev);
			(void) strcpy(hsc->slot_table_prop[i].nexus, nexus);
		}
	} else {
		hpstp = (hsc_prom_slot_table_t *)hpc_slot_table_data;
		for (i = 0; i < hsc->slot_table_size; i++, hpstp++) {
			if (scsb->scsb_hsc_state & SCSB_HSC_CTC_PRES &&
					hpstp->pslotnum == SC_MC_CTC_SLOT) {
				--i;
				continue;
			}
			hsc->slot_table_prop[i].pslotnum = hpstp->pslotnum;
			hsc->slot_table_prop[i].ga = hpstp->ga;
			hsc->slot_table_prop[i].pci_devno = hpstp->pci_devno;

			if (prom_phandle_to_path((uint_t)hpstp->phandle,
				hsc->slot_table_prop[i].nexus,
				sizeof (hsc->slot_table_prop[i].nexus))
						== -1) {
				cmn_err(CE_WARN, "%s#%d: Cannot get phandle "
					"to nexus path", ddi_driver_name(dip),
					ddi_get_instance(dip));
				kmem_free(hsc->slot_table_prop,
					(hsc->slot_table_size *
						sizeof (hsc_slot_table_t)));
				kmem_free(hpc_slot_table_data,
						hpc_slot_table_size);
				ddi_soft_state_free(hsc_state, instance);
				return (DDI_FAILURE);
			}
		}
	}

	/* keep healthy register cache uptodate before reading slot state */
	if (scsb_read_bhealthy(scsb_handle) != 0) {
		cmn_err(CE_WARN, "%s#%d: hsc_attach: Cannot read "
			"Healthy Registers", ddi_driver_name(dip),
				ddi_get_instance(dip));
		kmem_free(hsc->slot_table_prop,
			(hsc->slot_table_size *
				sizeof (hsc_slot_table_t)));
		kmem_free(hpc_slot_table_data,
				hpc_slot_table_size);
		ddi_soft_state_free(hsc_state, instance);
		return (DDI_FAILURE);
	}

	/*
	 * Before we start registering the slots, calculate how many
	 * slots are occupied.
	 */

	for (i = 0; i < hsc->slot_table_size; i++) {
		if (scsb_get_slot_state(scsb_handle,
				hsc->slot_table_prop[i].pslotnum, &rstate) !=
				DDI_SUCCESS)
				return (rc);
		if (rstate != HPC_SLOT_EMPTY)
			hsc->n_registered_occupants++;
	}

	mutex_init(&hsc->hsc_mutex, NULL, MUTEX_DRIVER, NULL);
	for (i = 0; i < hsc->slot_table_size; i++) {

		DEBUG2("Registering on nexus [%s] cPCI device [%d]\n",
			hsc->slot_table_prop[i].nexus,
			hsc->slot_table_prop[i].pci_devno);

		if (hsc_slot_register(hsc, hsc->slot_table_prop[i].nexus,
			hsc->slot_table_prop[i].pci_devno,
			hsc->slot_table_prop[i].pslotnum, B_FALSE) !=
								HPC_SUCCESS) {

			cmn_err(CE_WARN, "%s#%d: Slot Registration Failure",
				ddi_driver_name(dip), ddi_get_instance(dip));
			while (i) {
				i--;
				n = hsc->slot_table_prop[i].pslotnum;
				if (hsc_slot_unregister(n) != 0) {
					cmn_err(CE_WARN,
						"%s#%d: failed to unregister"
						" slot %d",
						ddi_driver_name(dip),
						ddi_get_instance(dip), n);

				}
			}
			mutex_destroy(&hsc->hsc_mutex);
			kmem_free(hsc->slot_table_prop, (hsc->slot_table_size *
					sizeof (hsc_slot_table_t)));
			kmem_free(hpc_slot_table_data, hpc_slot_table_size);
			ddi_soft_state_free(hsc_state, instance);
			return (DDI_FAILURE);
		}
	}

	hsc->hsp_last = NULL;
	hsc->hsc_intr_counter = 0;
	kmem_free(hpc_slot_table_data, hpc_slot_table_size);
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, hsc->dip,
	    HOTSWAP_MODE_PROP, "basic");
	hsc->state |= (HSC_ATTACHED|HSC_SCB_CONNECTED);

	/*
	 * We enable full hotswap right here if all the slots are empty.
	 */
	if ((hsc->regDone == B_FALSE && hsc->n_registered_occupants == 0) ||
			scsb_hsc_numReg == hsc->n_registered_occupants) {
		hsc->regDone = B_TRUE;
		if (hsc->hotswap_mode == HSC_HOTSWAP_MODE_FULL) {
			if (scsb_enable_enum(hsc) != DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s#%d: Cannot enable "
					"Full Hotswap", ddi_driver_name(dip),
					ddi_get_instance(dip));
			}
		}
	}
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
scsb_hsc_detach(dev_info_t *dip, void *scsb_handle, int instance)
{
	int i = 0;
	hsc_state_t	*hsc;
	char slotautocfg_prop[18];

	DEBUG0("hsc_detach: enter\n");
	hsc = (hsc_state_t *)ddi_get_soft_state(hsc_state, instance);
	if (hsc == NULL) {
		DEBUG2("%s#%d: hsc_detach: Soft state NULL",
				ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	if ((hsc->state & HSC_ATTACHED) != HSC_ATTACHED)
		return (DDI_FAILURE);
	/*
	 * let's unregister the hotpluggable slots with hotplug service.
	 */
	for (i = 0; i < hsc->slot_table_size; i++) {

		hsc_slot_t	*hsp;

		hsp = hsc_find_slot(hsc->slot_table_prop[i].pslotnum);
		if (hsp == NULL) {
			cmn_err(CE_WARN, "%s#%d: hsc_detach: No Slot Info",
				ddi_driver_name(dip), ddi_get_instance(dip));
		} else {
			hpc_led_info_t	aledinfo;	/* active led info. */
			hpc_led_info_t	fledinfo;	/* fault led info. */

			aledinfo.led = HPC_ACTIVE_LED;
			aledinfo.state = HPC_LED_BLINK;
			fledinfo.led = HPC_FAULT_LED;
			fledinfo.state = HPC_LED_OFF;
			(void) hsc_led_state(hsp, HPC_CTRL_SET_LED_STATE,
							&aledinfo);
			(void) hsc_led_state(hsp, HPC_CTRL_SET_LED_STATE,
							&fledinfo);
		}
		(void) sprintf(slotautocfg_prop, "slot%d-autoconfig",
		    hsp->hs_slot_number);
		(void) ddi_prop_remove(DDI_DEV_T_NONE, hsc->dip,
		    slotautocfg_prop);
		if (hsc_slot_unregister(hsc->slot_table_prop[i].pslotnum)
						!= 0) {
			cmn_err(CE_NOTE, "%s#%d: failed to unregister"
				" slot %d\n", ddi_driver_name(dip),
				ddi_get_instance(dip),
				hsc->slot_table_prop[i].pslotnum);
			return (DDI_FAILURE);
		}
	}
	kmem_free(hsc->slot_table_prop, (hsc->slot_table_size *
					sizeof (hsc_slot_table_t)));
	if ((hsc->state & HSC_ENUM_ENABLED) == HSC_ENUM_ENABLED) {
		ddi_remove_intr(hsc->dip, 1, hsc->enum_iblock);
		hsc->state &= ~HSC_ENUM_ENABLED;
	}
	mutex_destroy(&hsc->hsc_mutex);
	(void) ddi_prop_remove(DDI_DEV_T_NONE, hsc->dip, HOTSWAP_MODE_PROP);
	hsc->state &= ~(HSC_ATTACHED|HSC_SCB_CONNECTED);
	ddi_soft_state_free(hsc_state, instance);
	return (DDI_SUCCESS);
}

/*
 * The following function is called when the SCSB is hot extracted from
 * the system.
 */
int
scsb_hsc_freeze(dev_info_t *dip)
{
	hsc_state_t	*hsc;
	int instance = ddi_get_instance(dip);
	int i;
	hsc_slot_t	*hsp;

	hsc = (hsc_state_t *)ddi_get_soft_state(hsc_state, instance);
	if (hsc == NULL) {
		DEBUG2("%s#%d: Soft state NULL",
				ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_SUCCESS);
	}
	if ((hsc->state & HSC_ATTACHED) != HSC_ATTACHED)
		return (DDI_SUCCESS);
	hsc->state &= ~HSC_SCB_CONNECTED;

	for (i = 0; i < hsc->slot_table_size; i++) {
		hsp = hsc_find_slot(hsc->slot_table_prop[i].pslotnum);

		if (hsp == NULL) {
			cmn_err(CE_NOTE, "hsc_freeze: "
				" Cannot map slot number %d to a hsc_slot_t",
					hsc->slot_table_prop[i].pslotnum);
			continue;
		}
		/*
		 * Since reset lines are pulled low, lets mark these
		 * slots and not allow a connect operation.
		 * Note that we still keep the slot as slot disconnected,
		 * although it is connected from the hardware standpoint.
		 * As soon as the SCB is plugged back in, we check these
		 * states and put the hardware state back to its original
		 * state.
		 */
		if (hsp->hs_slot_state == HPC_SLOT_DISCONNECTED) {
			cmn_err(CE_WARN, "%s#%d: Slot %d Now out of Reset!",
				ddi_driver_name(hsc->dip),
				ddi_get_instance(hsc->dip),
				hsp->hs_slot_number);
		}
		hsp->hs_flags |= HSC_SCB_HOTSWAPPED;
	}

	return (DDI_SUCCESS);
}

/*
 * The following function is called when the SCSB is hot inserted from
 * the system. We must update the LED status and set the RST# registers
 * again.
 */
int
scsb_hsc_restore(dev_info_t *dip)
{
	int i;
	hsc_state_t	*hsc;
	hsc_slot_t	*hsp;
	int instance = ddi_get_instance(dip);

	hsc = (hsc_state_t *)ddi_get_soft_state(hsc_state, instance);
	if (hsc == NULL) {
		DEBUG2("%s#%d: Soft state NULL",
				ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_SUCCESS);
	}

	if ((hsc->state & HSC_ATTACHED) != HSC_ATTACHED)
		return (DDI_SUCCESS);
	hsc->state |= HSC_SCB_CONNECTED;
	for (i = 0; i < hsc->slot_table_size; i++) {
		hsp = hsc_find_slot(hsc->slot_table_prop[i].pslotnum);

		if (hsp == NULL) {
			cmn_err(CE_NOTE, "%s#%d: hsc_restore: "
				" Cannot map slot number %d to a hsc_slot_t",
					ddi_driver_name(hsc->dip),
					ddi_get_instance(hsc->dip),
					hsc->slot_table_prop[i].pslotnum);
			continue;
		}
		if ((hsp->hs_slot_state == HPC_SLOT_DISCONNECTED) &&
				(hsp->hs_board_configured == B_FALSE)) {
			if (scsb_reset_slot(hsp->hs_hpchandle,
					hsp->hs_slot_number,
					SCSB_RESET_SLOT) != 0) {
				cmn_err(CE_WARN, "%s#%d: hsc_restore: "
					" Cannot reset disconnected slot %d",
						ddi_driver_name(hsc->dip),
						ddi_get_instance(hsc->dip),
						hsp->hs_slot_number);
			}
		}

		if (scsb_hsc_init_slot_state(hsc, hsp) != DDI_SUCCESS) {

			cmn_err(CE_WARN, "%s#%d: hsc_freeze: Cannot init"
				" slot%d state",
				ddi_driver_name(hsc->dip),
				ddi_get_instance(hsc->dip),
				hsp->hs_slot_number);
		}
		hsp->hs_flags &= ~HSC_SCB_HOTSWAPPED;
	}
	return (DDI_SUCCESS);
}

#ifndef	lint
int
scsb_hsc_freeze_check(dev_info_t *dip)
{
	hsc_state_t	*hsc;
	int instance = ddi_get_instance(dip);

	hsc = (hsc_state_t *)ddi_get_soft_state(hsc_state, instance);
	if (hsc == NULL) {
		DEBUG2("%s#%d: Soft state NULL",
				ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_SUCCESS);
	}
	if ((hsc->state & HSC_ATTACHED) != HSC_ATTACHED)
		return (DDI_SUCCESS);
	return (DDI_SUCCESS);
}
#endif

/*
 * update info about Alarm Card insert/remove mechanism.
 */
void
hsc_ac_op(int instance, int pslotnum, int op, void *arg)
{
	hsc_slot_t *hsp;
	hsc_state_t	*hsc;

	hsc = (hsc_state_t *)ddi_get_soft_state(hsc_state, instance);
	if (hsc == NULL) {
		cmn_err(CE_WARN, "%s#%d: hsc_ac_op: No Soft State Info",
			ddi_driver_name(hsc->dip), ddi_get_instance(hsc->dip));
		return;
	}

	hsp = hsc_find_slot(pslotnum);
	if (hsp == NULL) {
		cmn_err(CE_WARN, "%s#%d: hsc_ac_op: No Slot Info",
			ddi_driver_name(hsc->dip), ddi_get_instance(hsc->dip));
		return;
	}

	switch (op) {
		case SCSB_HSC_AC_UNCONFIGURE :
			/*
			 * If ENUM# is enabled, then action is pending on
			 * this slot, just send a event.
			 */
			if (hsc->state & HSC_ENUM_ENABLED)
				(void) hpc_slot_event_notify(
				    hsp->hs_slot_handle,
				    HPC_EVENT_PROCESS_ENUM, 0);
			break;
		case SCSB_HSC_AC_GET_SLOT_INFO :
			*(hsc_slot_t **)arg = hsp;
			break;
		default :
			break;
	}
}

static uint_t
hsc_enum_intr(caddr_t iarg)
{
	int rc;
	hsc_state_t *hsc = (hsc_state_t *)iarg;
	hsc_slot_t *hsp;

	DEBUG0("!E!");
	if ((hsc->state & HSC_ATTACHED) == 0)
		return (DDI_INTR_UNCLAIMED);

	hsp = hsc_find_slot(hsc->slot_table_prop[0].pslotnum);
	if (hsp == NULL)	/* No slots registered */
		return (DDI_INTR_UNCLAIMED);

	/*
	 * The following must be done to clear interrupt (synchronous event).
	 * To process the interrupt, we send an asynchronous event.
	 */
	rc = hpc_slot_event_notify(hsp->hs_slot_handle,
					HPC_EVENT_CLEAR_ENUM,
						HPC_EVENT_SYNCHRONOUS);
	if (rc == HPC_EVENT_UNCLAIMED) {
		/*
		 * possible support for handling insertion of non friendly
		 * full hotswap boards, otherwise the system hangs due
		 * to uncleared interrupt bursts.
		 */
		DEBUG2("!E>counter %d, last op@slot %lx\n",
				hsc->hsc_intr_counter, hsc->hsp_last);
		hsc->hsc_intr_counter ++;
		if (hsc->hsc_intr_counter == scsb_hsc_max_intr_count) {
			if (!hsc->hsp_last) {
				cmn_err(CE_WARN, "%s#%d: hsc_enum_intr: "
					" No Last Board Insertion Info.",
					ddi_driver_name(hsc->dip),
					ddi_get_instance(hsc->dip));
				hsc->hsc_intr_counter = 0;
				return (DDI_INTR_UNCLAIMED);
			}
			hsp = hsc->hsp_last;
			cmn_err(CE_WARN, "%s#%d: Bad (non friendly ?) Board "
				"in Slot %d ? Taking it Offline.",
				ddi_driver_name(hsc->dip),
				ddi_get_instance(hsc->dip),
				hsp->hs_slot_number);
			/*
			 * this should put just inserted board back in
			 * reset, thus deasserting the ENUM# and the
			 * system hang.
			 */
			if (scsb_reset_slot(hsp->hs_hpchandle,
					hsp->hs_slot_number,
					SCSB_RESET_SLOT) == 0) {
				/* Enumeration failed on this board */
				hsp->hs_flags |= HSC_ENUM_FAILED;
				if (hsp->hs_board_configured == B_TRUE)
					cmn_err(CE_WARN, "%s#%d: ALERT! System"
						" now in Inconsistent State."
						" Halt!",
					    ddi_driver_name(hsc->dip),
					    ddi_get_instance(hsc->dip));
				hsc_led_op(hsp, HPC_CTRL_SET_LED_STATE,
						HPC_FAULT_LED, HPC_LED_ON);
			}
			hsc->hsc_intr_counter = 0;
		}
		return (DDI_INTR_UNCLAIMED);
	}
	hsc->hsc_intr_counter = 0;
	/*
	 * if interrupt success, rc denotes the PCI device number which
	 * generated the ENUM# interrupt.
	 */
	hsp = hsc_get_slot_info(hsc, rc);
	if (hsp == NULL) {
		cmn_err(CE_WARN, "%s#%d: hsc_enum_intr: no slot info for "
			"dev %x", ddi_driver_name(hsc->dip),
			ddi_get_instance(hsc->dip), rc);
		return (DDI_INTR_CLAIMED);	/* interrupt already cleared */
	}
	/* if this is Alarm Card and if it is busy, dont process event */
	if (hsp->hs_flags & HSC_ALARM_CARD_PRES) {
		if (scsb_hsc_ac_op(hsp->hs_hpchandle, hsp->hs_slot_number,
						SCSB_HSC_AC_BUSY) == B_TRUE) {
			/*
			 * Busy means we need to inform (envmond)alarmcard.so
			 * that it should save the AC configuration, stop the
			 * heartbeat, and shutdown the RSC link.
			 */
			(void) scsb_hsc_ac_op(hsp->hs_hpchandle,
					hsp->hs_slot_number,
					SCSB_HSC_AC_REMOVAL_ALERT);
			return (DDI_INTR_CLAIMED);
		}
	}
	/*
	 * If SCB was swapped out, dont process ENUM#. We put this slot
	 * back in reset after SCB is inserted.
	 */
	if ((hsp->hs_flags & HSC_SCB_HOTSWAPPED) &&
			(hsp->hs_slot_state == HPC_SLOT_DISCONNECTED))
		return (DDI_INTR_CLAIMED);

	(void) hpc_slot_event_notify(hsp->hs_slot_handle,
	    HPC_EVENT_PROCESS_ENUM, 0);
	return (DDI_INTR_CLAIMED);
}
/*
 * A routine to convert a number (represented as a string) to
 * the integer value it represents.
 */

static int
isdigit(int ch)
{
	return (ch >= '0' && ch <= '9');
}

#define	isspace(c)	((c) == ' ' || (c) == '\t' || (c) == '\n')
#define	bad(val)	(val == NULL || !isdigit(*val))

static int
atoi(const char *p)
{
	int n;
	int c, neg = 0;

	if (!isdigit(c = *p)) {
		while (isspace(c))
			c = *++p;
		switch (c) {
			case '-':
				neg++;
				/* FALLTHROUGH */
			case '+':
			c = *++p;
		}
		if (!isdigit(c))
			return (0);
	}
	for (n = '0' - c; isdigit(c = *++p); ) {
		n *= 10; /* two steps to avoid unnecessary overflow */
		n += '0' - c; /* accum neg to avoid surprises at MAX */
	}
	return (neg ? n : -n);
}
