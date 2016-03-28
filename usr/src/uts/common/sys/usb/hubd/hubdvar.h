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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2016 Joyent, Inc.
 */

#ifndef	_SYS_USB_HUBDVAR_H
#define	_SYS_USB_HUBDVAR_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/usb/usba/usba_types.h>
#include <sys/callb.h>

/*
 * HUB USB device state management :
 *
 *                          CHILD PWRLVL---1>--------+
 *                               ^                   |
 *                               8                   |
 *                               |                   |
 *                               9                   |
 *                               v                   |
 *	PWRED_DWN---<3----4>--ONLINE---<2-----1>-DISCONNECTED
 *          |                  |  ^                |  |
 *          |                  |  10               |  |
 *          |                  |  |                |  |
 *          |                  |  RECOVER-<2-------+  |
 *          |                  |  ^                   |
 *          |                  5  6                   |
 *          |                  |  |                   |
 *          |                  v  |                   |
 *          +----5>----------SUSPENDED----<5----7>----+
 *
 *	1 = Device Unplug
 *	2 = Original Device reconnected and after hub driver restores its own
 *	    device state.
 *	3 = Device idles for time T & transitions to low power state
 *	4 = Remote wakeup by device OR Application kicking off IO to device
 *	5 = Notification to save state prior to DDI_SUSPEND
 *	6 = Notification to restore state after DDI_RESUME with correct device
 *          and after hub driver restores its own device state.
 *	7 = Notification to restore state after DDI_RESUME with device
 *	    disconnected or a wrong device
 *	8 = Hub detect child doing remote wakeup and request the PM
 *	    framework to bring it to full power
 *      9 = PM framework has compeleted call power entry point of the child
 *	    and bus ctls of hub
 *     10 = Restoring states of its children i.e. set addrs & config.
 *
 */

#define	HUBD_INITIAL_SOFT_SPACE	4

typedef struct hub_power_struct {
	void		*hubp_hubd;	/* points back to hubd_t */

	uint8_t		hubp_wakeup_enabled;	/* remote wakeup enabled? */

	/* this is the bit mask of the power states that device has */
	uint8_t		hubp_pwr_states;

	int		hubp_busy_pm;	/* device busy accounting */

	/* wakeup and power transition capabilities of an interface */
	uint8_t		hubp_pm_capabilities;

	uint8_t		hubp_current_power;	/* current power level */

	hrtime_t	hubp_time_at_full_power;	/* timestamp 0->3 */

	hrtime_t	hubp_min_pm_threshold;		/* in nanoseconds */

	/* power state of all children are tracked here */
	uint8_t		*hubp_child_pwrstate;

	/* pm-components properties are stored here */
	char		*hubp_pmcomp[5];

	usba_cfg_pwr_descr_t	hubp_confpwr_descr; /* config pwr descr */
} hub_power_t;

/* warlock directives, stable data */
_NOTE(DATA_READABLE_WITHOUT_LOCK(hub_power_t::hubp_hubd))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hub_power_t::hubp_wakeup_enabled))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hub_power_t::hubp_pwr_states))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hub_power_t::hubp_time_at_full_power))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hub_power_t::hubp_min_pm_threshold))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hub_power_t::hubp_pm_capabilities))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hub_power_t::hubp_pmcomp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hub_power_t::hubp_confpwr_descr))


#define	HUBD_APID_NAMELEN	32		/* max len in cfgadm display */

/*
 * hubd cpr data structure used for callback before kernel threads are
 * suspended
 */
typedef struct hubd_cpr {
	callb_cpr_t		cpr;		/* for cpr related info */
	struct hubd		*statep;	/* ohci soft state struct */
	kmutex_t		lockp;
} hubd_cpr_t;

_NOTE(DATA_READABLE_WITHOUT_LOCK(hubd_cpr_t::cpr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hubd_cpr_t::statep))


/*
 * soft	state information for this hubd
 */
typedef struct hubd {
	int			h_instance;
	uint_t			h_init_state;
	uint_t			h_dev_state;
	int8_t			h_bus_ctls;
	int8_t			h_bus_pwr;
	hub_power_t		*h_hubpm; /* pointer to power struct */
	dev_info_t		*h_dip;

	/*
	 * mutex to protect softstate and hw regs
	 */
	kmutex_t		h_mutex;

	/*
	 * save the usba_device pointer
	 */
	usba_device_t		*h_usba_device;

	int			h_softstate;

	/*
	 * default pipe handle
	 */
	usb_pipe_handle_t	h_default_pipe;

	/*
	 * pipe handle for ep1
	 */
	usb_pipe_handle_t	h_ep1_ph;
	usb_ep_xdescr_t		h_ep1_xdescr;
	usb_pipe_policy_t	h_pipe_policy;
	uint_t			h_intr_pipe_state;

	/*
	 * hub characteristics (normalized across various USB versions) from the
	 * Hub class description.
	 */
	uint8_t			h_nports;	/* from bNbrPorts */
	uint16_t		h_hub_chars;	/* from wHubCharacteristics */
	uint_t			h_power_good;	/* from bPwrOn2PwrGood */
	uint_t			h_current;	/* from bHubContrCurrent */

	/*
	 * hotplug handling
	 */
	uint_t			h_hotplug_thread;

	/*
	 * h_children_dips is a  array for holding
	 * each child dip indexed by port
	 * h_usba_devices is the corresponding usba_device
	 */
	dev_info_t		**h_children_dips;
	size_t			h_cd_list_length;
	usba_device_t		**h_usba_devices;

	/* change reported by hub, limited to 31 ports */
	usb_port_mask_t		h_port_change;

	/* waiting for reset completion callback */
	usb_port_mask_t		h_port_reset_wait;

	/* track transitions of child on each port */
	uint16_t		h_port_state[MAX_PORTS + 1];

	/* track reset state of each port */
	boolean_t		h_reset_port[MAX_PORTS + 1];

	/* track event registration of children */
	uint8_t			h_child_events[MAX_PORTS + 1];

	/* track the raw port state for debugging purposes */
	uint16_t		h_port_raw[MAX_PORTS + 1];

	kcondvar_t		h_cv_reset_port;
	kcondvar_t		h_cv_hotplug_dev;
	uint_t			h_intr_completion_reason;
	usb_log_handle_t	h_log_handle;	/* for logging msgs */

	ndi_event_hdl_t		h_ndi_event_hdl;
	hubd_cpr_t		*h_cpr_cb;

	/*
	 * Hotplug event statistics since hub was attached
	 */
	ulong_t			h_total_hotplug_success;
	ulong_t			h_total_hotplug_failure;

	/* for minor node */
	char			*h_ancestry_str;

	/* registration data */
	usb_client_dev_data_t	*h_dev_data;

	/* for deathrow implementation */
	boolean_t		h_cleanup_enabled;
	boolean_t		h_cleanup_needed;
	boolean_t		h_cleanup_active;

	/*
	 * for power budget support
	 * h_pwr_limit and h_pwr_left are expressed
	 * in 2mA units
	 */
	boolean_t		h_local_pwr_capable;
	boolean_t		h_local_pwr_on;
	uint16_t		h_pwr_limit; /* per port pwr limit */
	int16_t			h_pwr_left; /* limit on the whole hub */

	/*
	 * conf file override to power budget property
	 * if 1, power budget is disabled
	 */
	boolean_t		h_ignore_pwr_budget;

	/* for HWA to cleanup child, NULL for normal hubs */
	int			(*h_cleanup_child)(dev_info_t *);
} hubd_t;

_NOTE(MUTEX_PROTECTS_DATA(hubd::h_mutex, hubd))
_NOTE(MUTEX_PROTECTS_DATA(hubd::h_mutex, hub_power_t))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hubd::h_default_pipe
		hubd::h_usba_device
		hubd::h_dev_data
		hubd::h_ndi_event_hdl
		hubd::h_cpr_cb
		hubd::h_log_handle
		hubd::h_ep1_ph
		hubd::h_instance
		hubd::h_hubpm
		hubd::h_dip
		hubd::h_ignore_pwr_budget
		hubd::h_hub_descr
		hubd::h_cleanup_child
))

_NOTE(SCHEME_PROTECTS_DATA("stable data", usb_ep_descr))

/*
 * hubd hotplug thread argument data structure
 */
typedef struct hubd_hotplug_arg {
	hubd_t		*hubd;

	/*
	 * flag to indicate if a hotplug thread is started
	 * during hubd attach time, if true, it means the
	 * connected devices need to be enumerated regardless
	 * of the connect status change bit
	 */
	boolean_t	hotplug_during_attach;
} hubd_hotplug_arg_t;

/*
 * hubd reset thread argument data structure
 */
typedef struct hubd_reset_arg {
	hubd_t		*hubd;
	/* The port needs to be reset */
	uint16_t	reset_port;
} hubd_reset_arg_t;

_NOTE(SCHEME_PROTECTS_DATA("unshared", hubd_hotplug_arg))
_NOTE(SCHEME_PROTECTS_DATA("unshared", hubd_reset_arg))

#define	HUBD_UNIT(dev)		(getminor((dev)))
#define	HUBD_MUTEX(hubd)	(&((hubd)->h_mutex))
#define	HUBD_SS_ISOPEN		0x0001
#define	HUBD_ACK_ALL_CHANGES	PORT_CHANGE_MASK

/* init state */
#define	HUBD_LOCKS_DONE		0x0001
#define	HUBD_HUBDI_REGISTERED	0x0002
#define	HUBD_MINOR_NODE_CREATED 0x0004
#define	HUBD_CHILDREN_CREATED	0x0008
#define	HUBD_EVENTS_REGISTERED	0x0020

/*
 * port flags : These are essentially extensions of  Port Status Field Bits
 * as in USB 2.0 spec Table 11-21 and #defined in hubd.h file. We make use
 * of the unused bits (5-7,13-15) here to track states of the hub's child.
 */
#define	HUBD_CHILD_ATTACHING		0x0020
#define	HUBD_CHILD_DETACHING		0x0040
#define	HUBD_CHILD_PWRLVL_CHNG		0x0080
#define	HUBD_CHILD_RAISE_POWER		0x2000
#define	HUBD_CHILD_ZAP			0x4000

/* Tracking events registered by children */
#define	HUBD_CHILD_EVENT_DISCONNECT	0x01
#define	HUBD_CHILD_EVENT_PRESUSPEND	0x02

/* This dev state is used exclusively by hub to change port suspend/resume */
#define	USB_DEV_HUB_CHILD_PWRLVL	0x80
#define	USB_DEV_HUB_STATE_RECOVER	0x81

/*
 * hubd interrupt pipe management :
 *
 * Following are the states of the interrupt pipe
 *
 * IDLE:
 *	initial state and after closing of the interrupt pipe
 *
 * OPENING:
 *	Set when the pipe is being opened
 *
 * ACTIVE:
 *	Set when the pipe has been opened in hubd_open_intr_pipe. This is
 *	typically after a hub has got enumerated and initialized.
 *
 * CLOSING :
 *	Set when the pipe is closed by calling hubd_close_intr_pipe(). This is
 *	typically called on hub disconnect via hubd_cleanup.
 */
#define	HUBD_INTR_PIPE_IDLE		0
#define	HUBD_INTR_PIPE_OPENING		1
#define	HUBD_INTR_PIPE_ACTIVE		2
#define	HUBD_INTR_PIPE_STOPPED		3
#define	HUBD_INTR_PIPE_CLOSING		4


/* request structure for putting dips on deathrow list */
typedef struct hubd_offline_req {
	usba_list_entry_t	or_queue; /* DO NOT MOVE! */
	hubd_t			*or_hubd;
	usb_port_t		or_port;
	dev_info_t		*or_dip;
	uint_t			or_flag;
} hubd_offline_req_t;

_NOTE(SCHEME_PROTECTS_DATA("unshared", hubd_offline_req))


/*
 * cfgadm state values
 */
#define	HUBD_CFGADM_NORMAL		0	/* normal state */
#define	HUBD_CFGADM_DISCONNECTED	1	/* logically disconnected */
#define	HUBD_CFGADM_UNCONFIGURED	2	/* port is unconfigured */
#define	HUBD_CFGADM_EMPTY		3	/* port is empty */
#define	HUBD_CFGADM_STILL_REFERENCED	4	/* ndi_devi_offline failed */
#define	HUBD_CFGADM_CONFIGURED		5	/* port is configured */

/*
 * Debug printing
 * Masks
 */
#define	DPRINT_MASK_ATTA	0x00000001
#define	DPRINT_MASK_CBOPS	0x00000002
#define	DPRINT_MASK_CALLBACK	0x00000004
#define	DPRINT_MASK_PORT	0x00000008
#define	DPRINT_MASK_HUB 	0x00000010
#define	DPRINT_MASK_HOTPLUG	0x00000020
#define	DPRINT_MASK_EVENTS	0x00000040
#define	DPRINT_MASK_PM		0x00000080
#define	DPRINT_MASK_ALL 	0xFFFFFFFF


/* status length used in getting hub status */
#define	GET_STATUS_LENGTH	0x04		/* length of get status req */

/* flag for hubd_start_polling */
#define	HUBD_ALWAYS_START_POLLING	1

/* enumeration timeout */
#define	HUBDI_ENUM_TIMEOUT	1	/* 1 second */

/* power budget unit in mA */
#define	USB_PWR_UNIT_LOAD	100

/* power values in 100mA units */
#define	USB_HIGH_PWR_VALUE	5
#define	USB_LOW_PWR_VALUE	1

/*
 * According to section 9.6.3 of USB 2.0 spec,
 * bMaxPower in the device configuration descriptor
 * is expressed in 2mA units
 */
#define	USB_CFG_DESCR_PWR_UNIT	2

/*
 * USB 3.x devices have the notion of a 'route' which describes the series of
 * hubs which must be passed through to reach a given device. The route string
 * has support for a fixed number of nested hubs. Each USB 3.x hub has to be
 * told what its depth in the route string is, effectively it's 4-bit index into
 * the route string. The maximum number of nested hubs, in other words a hub's
 * depth, is defined in USB 3.1 / 10.16.2.9.
 */
#define	HUBD_SS_MAX_DEPTH	5

/* variables shared with wire adapter class drivers */
extern uint_t hubd_errlevel;
extern uint_t hubd_errmask;
extern uint_t hubd_instance_debug;

/* common interfaces for hub and wire adapter class devices */
hubd_t	*hubd_get_soft_state(dev_info_t *);
void	hubd_get_ancestry_str(hubd_t *);
int	hubd_get_all_device_config_cloud(hubd_t *, dev_info_t *,
	usba_device_t *);
int	hubd_select_device_configuration(hubd_t *, usb_port_t,
	dev_info_t *, usba_device_t *);
dev_info_t *hubd_ready_device(hubd_t *, dev_info_t *, usba_device_t *,
	uint_t);
void	hubd_schedule_cleanup(dev_info_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_HUBDVAR_H */
