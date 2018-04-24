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
 * PCMCIA NEXUS
 *	The PCMCIA module is a generalized interface for
 *	implementing PCMCIA nexus drivers.  It preserves
 *	the logical socket name space while allowing multiple
 *	instances of the hardware to be properly represented
 *	in the device tree.
 *
 *	The nexus also exports events to an event manager
 *	driver if it has registered.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/autoconf.h>
#include <sys/vtoc.h>
#include <sys/dkio.h>
#include <sys/ddi.h>
#include <sys/debug.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/cred.h>
#include <sys/kstat.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/callb.h>
#include <sys/param.h>
#include <sys/thread.h>
#include <sys/proc.h>

#include <sys/pctypes.h>
#include <sys/pcmcia.h>
#include <sys/sservice.h>
#include <pcmcia/sys/cs_types.h>
#include <pcmcia/sys/cis.h>
#include <pcmcia/sys/cis_handlers.h>
#include <pcmcia/sys/cs.h>
#include <pcmcia/sys/cs_priv.h>

#ifdef sparc
#include <sys/ddi_subrdefs.h>

#elif defined(__x86) || defined(__amd64)
#include <sys/mach_intr.h>
#endif

#undef SocketServices

/* some bus specific stuff */

/* need PCI regspec size for worst case at present */
#include <sys/pci.h>

typedef struct pcmcia_logical_socket {
	int			ls_socket; /* adapter's socket number */
	uint32_t		ls_flags;
	struct pcmcia_adapter	*ls_adapter;
	pcmcia_if_t		*ls_if;
	dev_info_t		*ls_sockdrv;
	dev_info_t		*ls_dip[PCMCIA_MAX_FUNCTIONS];
	dev_info_t		*ls_mfintr_dip;
	int			ls_functions;
	uint32_t		ls_cs_events;
	uint32_t		ls_intr_pri;
	uint32_t		ls_intr_vec;
	int			ls_intrrefs;
	struct intrspec		ls_intrspec; /* MFC intrspec */
	inthandler_t		*ls_inthandlers; /* for multifunction cards */
	ddi_iblock_cookie_t	ls_iblk;
	ddi_idevice_cookie_t	ls_idev;
	kmutex_t		ls_ilock;
	int			ls_error; /* error for CS return */
} pcmcia_logical_socket_t;

/*
 * entry points used by the true nexus
 */
int pcmcia_detach(dev_info_t *, ddi_detach_cmd_t);
int pcmcia_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *, void *);
int pcmcia_prop_op(dev_t, dev_info_t *, dev_info_t *, ddi_prop_op_t,
			int, char *, caddr_t, int *);
void pcmcia_set_assigned(dev_info_t *, int, ra_return_t *);
int pcmcia_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result);

/*
 * prototypes used internally by the nexus and sometimes Card Services
 */
int SocketServices(int function, ...);


void *CISParser(int function, ...);
extern void *(*cis_parser)(int, ...);

struct regspec *pcmcia_cons_regspec(dev_info_t *, int, uchar_t *,
					ra_return_t *);

static int (*pcmcia_card_services)(int, ...) = NULL;

/*
 * variables used in the logical/physical mappings
 * that the nexus common code maintains.
 */
struct pcmcia_adapter *pcmcia_adapters[PCMCIA_MAX_ADAPTERS];
int    pcmcia_num_adapters;
pcmcia_logical_socket_t *pcmcia_sockets[PCMCIA_MAX_SOCKETS];
int    pcmcia_num_sockets;
pcmcia_logical_window_t *pcmcia_windows[PCMCIA_MAX_WINDOWS];
int    pcmcia_num_windows;
struct power_entry pcmcia_power_table[PCMCIA_MAX_POWER];
int	pcmcia_num_power;

struct pcmcia_mif *pcmcia_mif_handlers = NULL;
pcm_dev_node_t *pcmcia_devnodes = NULL;

kmutex_t pcmcia_global_lock;
kcondvar_t pcmcia_condvar;
kmutex_t pcmcia_enum_lock;

/*
 * Mapping of the device "type" to names acceptable to
 * the DDI
 */
static char *pcmcia_dev_type[] = {
	"multifunction",
	"byte",
	"serial",
	"parallel",
	"block",
	"display",
	"network",
	"block",
	"byte"
};

char *pcmcia_default_pm_mode = "parental-suspend-resume";

/*
 * generic names from the approved list:
 *	disk tape pci sbus scsi token-ring isa keyboard display mouse
 *	audio ethernet timer memory parallel serial rtc nvram scanner
 *	floppy(controller) fddi isdn atm ide pccard video-in video-out
 * in some cases there will need to be device class dependent names.
 * network -> ethernet, token-ring, etc.
 * this list is a first guess and is used when all else fails.
 */

char *pcmcia_generic_names[] = {
	"multifunction",
	"memory",
	"serial",
	"parallel",
	"disk",
	"video",		/* no spec for video-out yet */
	"network",
	"aims",
	"scsi",
	"security"
};

#define	PCM_GENNAME_SIZE	(sizeof (pcmcia_generic_names) / \
					sizeof (char *))
#define	PCMCIA_MAP_IO	0x0
#define	PCMCIA_MAP_MEM	0x1
#define	PPB_SUBTRACTIVE	((PCI_CLASS_BRIDGE << 16) | (PCI_BRIDGE_PCI << 8) | \
		(PCI_BRIDGE_PCI_IF_SUBDECODE))

/*
 * The following should be 2^^n - 1
 */
#define	PCMCIA_SOCKET_BITS	0x7f

#ifdef PCMCIA_DEBUG
int pcmcia_debug = 0x0;
static void pcmcia_dump_minors(dev_info_t *);
#endif

static f_tt *pcmcia_cs_event = NULL;
int pcmcia_timer_id;
dev_info_t	*pcmcia_dip;
/*
 * XXX - See comments in cs.c
 */
static f_tt *pcmcia_cis_parser = NULL;

extern struct pc_socket_services pc_socket_services;

/* some function declarations */
static int pcm_adapter_callback(dev_info_t *, int, int, int);
extern void pcmcia_init_adapter(anp_t *, dev_info_t *);
extern void pcmcia_find_cards(anp_t *);
extern void pcmcia_merge_power(struct power_entry *);
extern void pcmcia_do_resume(int, pcmcia_logical_socket_t *);
extern void pcmcia_resume(int, pcmcia_logical_socket_t *);
extern void pcmcia_do_suspend(int, pcmcia_logical_socket_t *);
extern void pcm_event_manager(int, int, void *);
static void pcmcia_create_dev_info(int);
static int pcmcia_create_device(ss_make_device_node_t *);
static void pcmcia_init_devinfo(dev_info_t *, struct pcm_device_info *);
void pcmcia_fix_string(char *str);
dev_info_t *pcmcia_number_socket(dev_info_t *, int);
static int pcmcia_merge_conf(dev_info_t *);
static uint32_t pcmcia_mfc_intr(caddr_t, caddr_t);
void pcmcia_free_resources(dev_info_t *);
static void pcmcia_ppd_free(struct pcmcia_parent_private *ppd);
int pcmcia_get_intr(dev_info_t *, int);
int pcmcia_return_intr(dev_info_t *, int);
int pcmcia_ra_alloc(dev_info_t *, ndi_ra_request_t *, ra_return_t *, char *,
		dev_info_t **);
int pcmcia_ra_free(dev_info_t *, ra_return_t *, char *);

extern int cs_init(void);
extern int cs_deinit(void);
extern void cisp_init(void);
extern void cis_deinit(void);

/*
 * non-DDI compliant functions are listed here
 * some will be declared while others that have
 * entries in .h files. All will be commented on.
 *
 * with declarations:
 *	ddi_add_child
 *	ddi_binding_name
 *	ddi_bus_prop_op
 *	ddi_ctlops
 *	ddi_find_devinfo
 *	ddi_get_name_addr
 *	ddi_get_parent_data
 *	ddi_hold_installed_driver
 *	ddi_name_to_major
 *	ddi_node_name
 *	ddi_pathname
 *	ddi_rele_driver
 *	ddi_set_name_addr
 *	ddi_set_parent_data
 *	ddi_unorphan_devs
 *	i_ddi_bind_node_to_driver
 *	i_ddi_bind_node_to_driver
 *	i_ddi_bus_map
 *	i_ddi_map_fault
 *	i_ddi_mem_alloc
 *	i_ddi_mem_alloc
 *	i_ddi_mem_free
 *	i_ddi_mem_free
 *	modload
 *	modunload
 */

extern void ddi_unorphan_devs(major_t);

/* Card&Socket Services entry points */
static int GetCookiesAndDip(sservice_t *);
static int SSGetAdapter(get_adapter_t *);
static int SSGetPage(get_page_t *);
static int SSGetSocket(get_socket_t *);
static int SSGetStatus(get_ss_status_t *);
static int SSGetWindow(get_window_t *);
static int SSInquireAdapter(inquire_adapter_t *);
static int SSInquireSocket(inquire_socket_t *);
static int SSInquireWindow(inquire_window_t *);
static int SSResetSocket(int, int);
static int SSSetPage(set_page_t *);
static int SSSetSocket(set_socket_t *);
static int SSSetWindow(set_window_t *);
static int SSSetIRQHandler(set_irq_handler_t *);
static int SSClearIRQHandler(clear_irq_handler_t *);

static struct modldrv modlmisc = {
	&mod_miscops,		/* Type of module. This one is a driver */
	"PCMCIA Nexus Support", /* Name of the module. */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init()
{
	int	ret;

	cisp_init();

	if (cs_init() != CS_SUCCESS) {
		if (cs_deinit() != CS_SUCCESS)
			cmn_err(CE_CONT, "pcmcia: _init cs_deinit error\n");
		return (-1);
	}

	mutex_init(&pcmcia_global_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&pcmcia_condvar, NULL, CV_DRIVER, NULL);
	mutex_init(&pcmcia_enum_lock, NULL, MUTEX_DEFAULT, NULL);

	if ((ret = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&pcmcia_global_lock);
		cv_destroy(&pcmcia_condvar);
		mutex_destroy(&pcmcia_enum_lock);
	}
	return (ret);
}

int
_fini()
{
	int	ret;

	if ((ret = mod_remove(&modlinkage)) == 0) {
		mutex_destroy(&pcmcia_global_lock);
		cv_destroy(&pcmcia_condvar);
		mutex_destroy(&pcmcia_enum_lock);
		cis_deinit();
		if (cs_deinit() != CS_SUCCESS) {
			cmn_err(CE_CONT, "pcmcia: _fini cs_deinit error\n");
		}
	}
	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

extern pri_t minclsyspri;

/*
 * pcmcia_attach()
 *	the attach routine must make sure that everything needed is present
 *	including real hardware.  The sequence of events is:
 *		attempt to load all adapter drivers
 *		attempt to load Card Services
 *		initialize logical sockets
 *		report the nexus exists
 */

int
pcmcia_attach(dev_info_t *dip, anp_t *adapter)
{
	int count, done, i;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {
		cmn_err(CE_CONT, "pcmcia_attach: dip=0x%p adapter=0x%p\n",
		    (void *)dip, (void *)adapter);
	}
#endif

	pcmcia_dip = dip;

	mutex_enter(&pcmcia_enum_lock);
	mutex_enter(&pcmcia_global_lock);
	if (pcmcia_num_adapters == 0) {
		pcmcia_cis_parser = (f_tt *)CISParser;
		cis_parser = (void *(*)(int, ...)) CISParser;
		pcmcia_cs_event = (f_tt *)cs_event;
		cs_socket_services = SocketServices;
		/* tell CS we are up with basic init level */
		(void) cs_event(PCE_SS_INIT_STATE, PCE_SS_STATE_INIT, 0);
	}

	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    PCM_DEVICETYPE, "pccard");

	ddi_report_dev(dip);	/* directory/device naming */

	/*
	 * now setup any power management stuff necessary.
	 * we do it here in order to ensure that all PC Card nexi
	 * implement it.
	 */

	if (pm_create_components(dip, 1) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: not power managed\n",
		    ddi_get_name_addr(dip));
	} else {
		pm_set_normal_power(dip, 0, 1);
	}

	/*
	 * setup the info necessary for Card Services/SocketServices
	 * and notify CS when ready.
	 */

	pcmcia_free_resources(dip);
	pcmcia_init_adapter(adapter, dip);
	/* exit mutex so CS can run for any cards found */
	mutex_exit(&pcmcia_global_lock);

	/*
	 * make sure the devices are identified before
	 * returning.  We do this by checking each socket to see if
	 * a card is present.  If there is one, and there isn't a dip,
	 * we can't be done.  We scan the list of sockets doing the
	 * check. if we aren't done, wait for a condition variable to
	 * wakeup.
	 * Because we can miss a wakeup and because things can
	 * take time, we do eventually give up and have a timeout.
	 */

	for (count = 0, done = 0;
	    done == 0 && count < max(pcmcia_num_sockets, 16);
	    count++) {
		done = 1;
		/* block CS while checking so we don't miss anything */
		mutex_enter(&pcmcia_global_lock);
		for (i = 0; i < pcmcia_num_sockets; i++) {
			get_ss_status_t status;
			if (pcmcia_sockets[i] == NULL)
				continue;
			bzero(&status, sizeof (status));
			status.socket = i;
			if (SSGetStatus(&status) == SUCCESS) {
				if (status.CardState & SBM_CD &&
				    pcmcia_sockets[i]->ls_dip[0] == NULL) {
					done = 0;
				}
			}
		}
		/* only wait if we aren't done with this set */
		if (!done) {
			mutex_exit(&pcmcia_global_lock);
			delay(10); /* give up CPU for a time */
			mutex_enter(&pcmcia_global_lock);
		}
		mutex_exit(&pcmcia_global_lock);
	}

	mutex_exit(&pcmcia_enum_lock);
	return (DDI_SUCCESS);
}

/*
 * pcmcia_detach
 *	unload everything and then detach the nexus
 */
/* ARGSUSED */
int
pcmcia_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		pm_destroy_components(dip);
		return (DDI_SUCCESS);

	/*
	 * resume from a checkpoint
	 * We don't do anything special here since the adapter
	 * driver will generate resume events that we intercept
	 * and convert to insert events.
	 */
	case DDI_SUSPEND:
	case DDI_PM_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*
 * card_services_error()
 *	used to make 2.4/2.5 drivers get an error when
 *	they try to initialize.
 */
static int
card_services_error()
{
	return (CS_BAD_VERSION);
}
static int (*cs_error_ptr)() = card_services_error;

/*
 * pcmcia_ctlops
 *	handle the nexus control operations for the cases where
 *	a PC Card driver gets called and we need to modify the
 *	devinfo structure or otherwise do bus specific operations
 */
int
pcmcia_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	int e;
	char name[64];
	struct pcmcia_parent_private *ppd;
	power_req_t *pm;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {
		cmn_err(CE_CONT, "pcmcia_ctlops(%p, %p, %d, %p, %p)\n",
		    (void *)dip, (void *)rdip, ctlop, (void *)arg,
		    (void *)result);
		if (rdip != NULL && ddi_get_name(rdip) != NULL)
			cmn_err(CE_CONT, "\t[%s]\n", ddi_get_name(rdip));
	}
#endif

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);

		if (strcmp("pcs", ddi_node_name(rdip)) == 0)
			cmn_err(CE_CONT, "?PCCard socket %d at %s@%s\n",
			    ddi_get_instance(rdip),
			    ddi_driver_name(dip), ddi_get_name_addr(dip));
		else
			cmn_err(CE_CONT, "?%s%d at %s@%s in socket %d\n",
			    ddi_driver_name(rdip),
			    ddi_get_instance(rdip),
			    ddi_driver_name(dip),
			    ddi_get_name_addr(dip),
			    CS_GET_SOCKET_NUMBER(
			    ddi_getprop(DDI_DEV_T_NONE, rdip,
			    DDI_PROP_DONTPASS,
			    PCM_DEV_SOCKET, -1)));

		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
		/*
		 * we get control here before the child is called.
		 * we can change things if necessary.  This is where
		 * the CardServices hook gets planted.
		 */
#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug) {
			cmn_err(CE_CONT, "pcmcia: init child: %s(%d) @%p\n",
			    ddi_node_name(arg), ddi_get_instance(arg),
			    (void *)arg);
			if (DEVI(arg)->devi_binding_name != NULL)
				cmn_err(CE_CONT, "\tbinding_name=%s\n",
				    DEVI(arg)->devi_binding_name);
			if (DEVI(arg)->devi_node_name != NULL)
				cmn_err(CE_CONT, "\tnode_name=%s\n",
				    DEVI(arg)->devi_node_name);
		}
#endif

		ppd = (struct pcmcia_parent_private *)
		    ddi_get_parent_data((dev_info_t *)arg);
		if (ppd == NULL)
			return (DDI_FAILURE);

		if (strcmp("pcs", ddi_node_name((dev_info_t *)arg)) == 0) {
			if (ppd == NULL)
				return (DDI_FAILURE);
			(void) sprintf(name, "%x",
			    (int)ppd->ppd_reg[0].phys_hi);
			ddi_set_name_addr((dev_info_t *)arg, name);
			return (DDI_SUCCESS);
		}

		/*
		 * We don't want driver.conf files that stay in
		 * pseudo device form.	It is acceptable to have
		 * .conf files add properties only.
		 */
		if (ndi_dev_is_persistent_node((dev_info_t *)arg) == 0) {
			(void) pcmcia_merge_conf((dev_info_t *)arg);
			cmn_err(CE_WARN, "%s%d: %s.conf invalid",
			    ddi_get_name((dev_info_t *)arg),
			    ddi_get_instance((dev_info_t *)arg),
			    ddi_get_name((dev_info_t *)arg));
			return (DDI_FAILURE);
		}


#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug && ppd != NULL) {
			cmn_err(CE_CONT, "\tnreg=%x, intr=%x, socket=%x,"
			    " function=%x, active=%x, flags=%x\n",
			    ppd->ppd_nreg, ppd->ppd_intr,
			    ppd->ppd_socket, ppd->ppd_function,
			    ppd->ppd_active, ppd->ppd_flags);
		}
#endif

		/*
		 * make sure names are relative to socket number
		 */
		if (ppd->ppd_function > 0) {
			int sock;
			int func;
			sock = ppd->ppd_socket;
			func = ppd->ppd_function;
			(void) sprintf(name, "%x,%x", sock, func);
		} else {
			(void) sprintf(name, "%x", ppd->ppd_socket);
		}
		ddi_set_name_addr((dev_info_t *)arg, name);

#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug)
			cmn_err(CE_CONT, "pcmcia: system init done for %s [%s] "
			    "nodeid: %x @%s\n",
			    ddi_get_name(arg), ddi_get_name_addr(arg),
			    DEVI(arg)->devi_nodeid, name);
		if (pcmcia_debug > 1)
			pcmcia_dump_minors((dev_info_t *)arg);
#endif

		return (DDI_SUCCESS);

	case DDI_CTLOPS_UNINITCHILD:

#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug) {
			cmn_err(CE_CONT, "pcmcia: uninit child: %s(%d) @%p\n",
			    ddi_node_name(arg), ddi_get_instance(arg),
			    (void *)arg);
			if (DEVI(arg)->devi_binding_name != NULL)
				cmn_err(CE_CONT, "\tbinding_name=%s\n",
				    DEVI(arg)->devi_binding_name);
			if (DEVI(arg)->devi_node_name != NULL)
				cmn_err(CE_CONT, "\tnode_name=%s\n",
				    DEVI(arg)->devi_node_name);
		}
#endif

		ddi_set_name_addr((dev_info_t *)arg, NULL);
		ddi_remove_minor_node((dev_info_t *)arg, NULL);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_SLAVEONLY:
		/* PCMCIA devices can't ever be busmaster until CardBus */
		ppd = (struct pcmcia_parent_private *)
		    ddi_get_parent_data(rdip);
		if (ppd != NULL && ppd->ppd_flags & PPD_CB_BUSMASTER)
			return (DDI_FAILURE); /* at most */
		return (DDI_SUCCESS);

	case DDI_CTLOPS_SIDDEV:
		/* in general this is true. */
		return (DDI_SUCCESS);

	case DDI_CTLOPS_NREGS:
		ppd = (struct pcmcia_parent_private *)
		    ddi_get_parent_data(rdip);
		if (ppd != NULL)
			*((uint32_t *)result) = (ppd->ppd_nreg);
		else
			*((uint32_t *)result) = 0;
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
		ppd = (struct pcmcia_parent_private *)
		    ddi_get_parent_data(rdip);
		if (ppd != NULL && ppd->ppd_nreg > 0)
			*((off_t *)result) =  sizeof (struct pcm_regs);
		else
			*((off_t *)result) = 0;
		return (DDI_SUCCESS);

	case DDI_CTLOPS_POWER:
		ppd = (struct pcmcia_parent_private *)
		    ddi_get_parent_data(rdip);

		if (ppd == NULL)
			return (DDI_FAILURE);
		/*
		 * if this is not present, don't bother (claim success)
		 * since it is already in the right state.  Don't
		 * do any resume either since the card insertion will
		 * happen independently.
		 */
		if (!ppd->ppd_active)
			return (DDI_SUCCESS);
		for (e = 0; e < pcmcia_num_adapters; e++)
			if (pcmcia_adapters[e] ==
			    pcmcia_sockets[ppd->ppd_socket]->ls_adapter)
				break;
		if (e == pcmcia_num_adapters)
			return (DDI_FAILURE);
		pm = (power_req_t *)arg;
#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug) {
			cmn_err(CE_WARN, "power: %d: %p, %d, %d [%s]\n",
			    pm->request_type,
			    (void *)pm->req.set_power_req.who,
			    pm->req.set_power_req.cmpt,
			    pm->req.set_power_req.level,
			    ddi_get_name_addr(rdip));
		}
#endif
		e = ppd->ppd_socket;
		switch (pm->request_type) {
		case PMR_SUSPEND:
			if (!(pcmcia_sockets[e]->ls_flags &
			    PCS_SUSPENDED)) {
				pcmcia_do_suspend(ppd->ppd_socket,
				    pcmcia_sockets[e]);
			}
			ppd->ppd_flags |= PPD_SUSPENDED;
			return (DDI_SUCCESS);
		case PMR_RESUME:
			/* for now, we just succeed since the rest is done */
			return (DDI_SUCCESS);
		case PMR_SET_POWER:
			/*
			 * not sure how to handle power control
			 * for now, we let the child handle it itself
			 */
			(void) pcmcia_power(pm->req.set_power_req.who,
			    pm->req.set_power_req.cmpt,
			    pm->req.set_power_req.level);
			break;
		default:
			break;
		}
		return (DDI_FAILURE);
		/* These CTLOPS will need to be implemented for new form */
		/* let CardServices know about this */
	case DDI_CTLOPS_DETACH:
		return (DDI_SUCCESS);
	case DDI_CTLOPS_ATTACH:
		return (DDI_SUCCESS);

	default:
		/* if we don't understand, pass up the tree */
		/* most things default to general ops */
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}
}

struct pcmcia_props {
	char *name;
	int   len;
	int   prop;
} pcmcia_internal_props[] = {
	{ PCM_DEV_ACTIVE, 0, PCMCIA_PROP_ACTIVE },
	{ PCM_DEV_R2TYPE, 0, PCMCIA_PROP_R2TYPE },
	{ PCM_DEV_CARDBUS, 0, PCMCIA_PROP_CARDBUS },
	{ CS_PROP, sizeof (void *), PCMCIA_PROP_OLDCS },
	{ "reg", 0, PCMCIA_PROP_REG },
	{ "interrupts", sizeof (int), PCMCIA_PROP_INTR },
	{ "pm-hardware-state", 0, PCMCIA_PROP_DEFAULT_PM },
};

/*
 * pcmcia_prop_decode(name)
 *	decode the name and determine if this is a property
 *	we construct on the fly, one we have on the prop list
 *	or one that requires calling the CIS code.
 */
static int
pcmcia_prop_decode(char *name)
{
	int i;
	if (strncmp(name, "cistpl_", 7) == 0)
		return (PCMCIA_PROP_CIS);

	for (i = 0; i < (sizeof (pcmcia_internal_props) /
	    sizeof (struct pcmcia_props)); i++) {
		if (strcmp(name, pcmcia_internal_props[i].name) == 0)
			return (i);
	}

	return (PCMCIA_PROP_UNKNOWN);
}

/*
 * pcmcia_prop_op()
 *	we don't have properties in PROM per se so look for them
 *	only in the devinfo node.  Future may allow us to find
 *	certain CIS tuples via this interface if a user asks for
 *	a property of the form "cistpl-<tuplename>" but not yet.
 *
 *	The addition of 1275 properties adds to the necessity.
 */
int
pcmcia_prop_op(dev_t dev, dev_info_t *dip, dev_info_t *ch_dip,
    ddi_prop_op_t prop_op, int mod_flags,
    char *name, caddr_t valuep, int *lengthp)
{
	int len, proplen, which, flags;
	caddr_t buff, propptr;
	struct pcmcia_parent_private *ppd;

	len = *lengthp;
	ppd = (struct pcmcia_parent_private *)ddi_get_parent_data(ch_dip);

	switch (which = pcmcia_prop_decode(name)) {
	default:
		if (ppd == NULL)
			return (DDI_PROP_NOT_FOUND);

		/* note that proplen may get modified */
		proplen = pcmcia_internal_props[which].len;
		switch (pcmcia_internal_props[which].prop) {
		case PCMCIA_PROP_DEFAULT_PM:
			propptr = pcmcia_default_pm_mode;
			proplen = strlen(propptr) + 1;
			break;
		case PCMCIA_PROP_OLDCS:
			propptr = (caddr_t)&cs_error_ptr;
			break;
		case PCMCIA_PROP_REG:
			propptr = (caddr_t)ppd->ppd_reg;
			proplen = ppd->ppd_nreg * sizeof (struct pcm_regs);
			break;
		case PCMCIA_PROP_INTR:
			propptr = (caddr_t)&ppd->ppd_intr;
			break;

		/* the next set are boolean values */
		case PCMCIA_PROP_ACTIVE:
			propptr = NULL;
			if (!ppd->ppd_active) {
				return (DDI_PROP_NOT_FOUND);
			}
			break;
		case PCMCIA_PROP_R2TYPE:
			propptr = NULL;
			if (ppd->ppd_flags & PPD_CARD_CARDBUS)
				return (DDI_PROP_NOT_FOUND);
			break;
		case PCMCIA_PROP_CARDBUS:
			propptr = NULL;
			if ((ppd->ppd_flags & PPD_CARD_CARDBUS) == 0)
				return (DDI_PROP_NOT_FOUND);
			break;
		}

		break;

	case PCMCIA_PROP_CIS:
		/*
		 * once we have the lookup code in place
		 * it is sufficient to break out of the switch
		 * once proplen and propptr are set.
		 * The common prop_op code deals with the rest.
		 */
	case PCMCIA_PROP_UNKNOWN:
		return (ddi_bus_prop_op(dev, dip, ch_dip, prop_op,
		    mod_flags | DDI_PROP_NOTPROM,
		    name, valuep, lengthp));
	}

	if (prop_op == PROP_LEN) {
		/* just the length */
		*lengthp = proplen;
		return (DDI_PROP_SUCCESS);
	}
	switch (prop_op) {
	case PROP_LEN_AND_VAL_ALLOC:
		if (mod_flags & DDI_PROP_CANSLEEP)
			flags = KM_SLEEP;
		else
			flags = KM_NOSLEEP;
		buff = kmem_alloc((size_t)proplen, flags);
		if (buff == NULL)
			return (DDI_PROP_NO_MEMORY);
		*(caddr_t *)valuep = (caddr_t)buff;
		break;
	case PROP_LEN_AND_VAL_BUF:
		buff = (caddr_t)valuep;
		if (len < proplen)
			return (DDI_PROP_BUF_TOO_SMALL);
		break;
	default:
		break;
	}

	if (proplen > 0)
		bcopy(propptr, buff, proplen);
	*lengthp = proplen;
	return (DDI_PROP_SUCCESS);
}


struct regspec *
pcmcia_rnum_to_regspec(dev_info_t *dip, int rnumber)
{
	struct pcmcia_parent_private *ppd;
	ppd = (struct pcmcia_parent_private *)ddi_get_parent_data(dip);
	if (ppd->ppd_nreg < rnumber)
		return (NULL);
	return ((struct regspec *)&ppd->ppd_reg[rnumber]);
}

struct regspec *
pcmcia_rnum_to_mapped(dev_info_t *dip, int rnumber)
{
	struct pcmcia_parent_private *ppd;
	ppd = (struct pcmcia_parent_private *)ddi_get_parent_data(dip);
	if (ppd->ppd_nreg < rnumber)
		return (NULL);
	if (ppd->ppd_assigned == NULL)
		return (NULL);
	if (ppd->ppd_assigned[rnumber].phys_len == 0)
		return (NULL);
	else
		return ((struct regspec *)&ppd->ppd_assigned[rnumber]);
}

int
pcmcia_find_rnum(dev_info_t *dip, struct regspec *reg)
{
	struct pcmcia_parent_private *ppd;
	struct regspec *regp;
	int i;

	ppd = (struct pcmcia_parent_private *)ddi_get_parent_data(dip);
	if (ppd == NULL)
		return (-1);
	for (regp = (struct regspec *)ppd->ppd_reg, i = 0;
	    i < ppd->ppd_nreg; i++, regp++) {
		if (bcmp(reg, regp, sizeof (struct regspec)) == 0)
			return (i);
	}
	for (regp = (struct regspec *)ppd->ppd_assigned, i = 0;
	    i < ppd->ppd_nreg; i++, regp++) {
		if (bcmp(reg, regp, sizeof (struct regspec)) == 0)
			return (i);
	}

	return (-1);
}

int
pcmcia_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp)
{
	struct pcm_regs *regs, *mregs = NULL, tmp_reg;
	ddi_map_req_t mr = *mp;
	ra_return_t ret;
	int check, rnum = -1;
	uint32_t base;
	uchar_t regbuf[sizeof (pci_regspec_t)];

	mp = &mr;		/* a copy of original request */

	/* check for register number */
	switch (mp->map_type) {
	case DDI_MT_REGSPEC:
		regs = (struct pcm_regs *)mp->map_obj.rp;
		mregs = (struct pcm_regs *)mp->map_obj.rp;
		/*
		 * when using regspec, must not be relocatable
		 * and should be from assigned space.
		 */
		if (!PC_REG_RELOC(regs->phys_hi))
			return (DDI_FAILURE);
		rnum = pcmcia_find_rnum(rdip, (struct regspec *)mregs);
		break;
	case DDI_MT_RNUMBER:
		regs = (struct pcm_regs *)
		    pcmcia_rnum_to_regspec(rdip, mp->map_obj.rnumber);
		mregs = (struct pcm_regs *)
		    pcmcia_rnum_to_mapped(rdip, mp->map_obj.rnumber);
		rnum = mp->map_obj.rnumber;
		if (regs == NULL)
			return (DDI_FAILURE);
		mp->map_type = DDI_MT_REGSPEC;
		mp->map_obj.rp = (struct regspec *)mregs;
		break;
	default:
		return (DDI_ME_INVAL);
	}

	/* basic sanity checks */
	switch (mp->map_op) {
	default:
		return (DDI_ME_UNIMPLEMENTED);
	case DDI_MO_UNMAP:
		if (mregs == NULL)
			return (DDI_FAILURE);
		regs = mregs;
		break;
	case DDI_MO_MAP_LOCKED:
	case DDI_MO_MAP_HANDLE:
		panic("unsupported bus operation");
		/*NOTREACHED*/
	}

	/*
	 * we need a private copy for manipulation and
	 * calculation of the correct ranges
	 */
	tmp_reg = *regs;
	mp->map_obj.rp = (struct regspec *)(regs = &tmp_reg);
	base = regs->phys_lo;
	if (base == 0 && offset != 0) {
		/*
		 * for now this is an error.  What does it really mean
		 * to ask for an offset from an address that hasn't
		 * been allocated yet.
		 */
		return (DDI_ME_INVAL);
	}
	regs->phys_lo += (uint32_t)offset;
	if (len != 0) {
		if (len > regs->phys_len) {
			return (DDI_ME_INVAL);
		}
		regs->phys_len = len;
	}

	/*
	 * basic sanity is checked so now make sure
	 * we can actually allocate something for this
	 * request and then convert to a "standard"
	 * regspec for the next layer up (pci/isa/rootnex/etc.)
	 */

	switch (PC_GET_REG_TYPE(regs->phys_hi)) {
	case PC_REG_SPACE_IO:
		check = PCA_RES_NEED_IO;
		break;
	case PC_REG_SPACE_MEMORY:
		check = PCA_RES_NEED_MEM;
		break;
	default:
		/* not a valid register type */
		return (DDI_FAILURE);
	}

	mr.map_type = DDI_MT_REGSPEC;
	ret.ra_addr_hi = 0;
	ret.ra_addr_lo = regs->phys_lo;
	ret.ra_len = regs->phys_len;
	mr.map_obj.rp = pcmcia_cons_regspec(dip,
	    (check == PCA_RES_NEED_IO) ?
	    PCMCIA_MAP_IO : PCMCIA_MAP_MEM,
	    regbuf, &ret);
	switch (mp->map_op) {
	case DDI_MO_UNMAP:
		pcmcia_set_assigned(rdip, rnum, NULL);
		break;
	default:
		break;
	}
	return (ddi_map(dip, &mr, (off_t)0, (off_t)0, vaddrp));
}

/*
 * pcmcia_cons_regspec()
 * based on parent's bus type, construct a regspec that is usable
 * by that parent to map the resource into the system.
 */
#define	PTYPE_PCI	1
#define	PTYPE_ISA	0
struct regspec *
pcmcia_cons_regspec(dev_info_t *dip, int type, uchar_t *buff, ra_return_t *ret)
{
	int ptype = -1, len, bus;
	char device_type[MODMAXNAMELEN + 1];
	dev_info_t *pdip;
	struct regspec *defreg;
	pci_regspec_t *pcireg;

	pdip = ddi_get_parent(dip);
	if (pdip != ddi_root_node()) {
		/* we're not a child of root so find out what */
		len = sizeof (device_type);
		if (ddi_prop_op(DDI_DEV_T_ANY, pdip, PROP_LEN_AND_VAL_BUF, 0,
		    "device_type", (caddr_t)device_type, &len) ==
		    DDI_PROP_SUCCESS) {
			/* check things out */
			if (strcmp(device_type, "pci") == 0)
				ptype = PTYPE_PCI;
			else if (strcmp(device_type, "isa") == 0)
				ptype = PTYPE_ISA;
		}
	}
	switch (ptype) {
	case PTYPE_PCI:
		/* XXX need to look at carefully */
		if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)&pcireg, &len) == DDI_SUCCESS) {
			bus = PCI_REG_BUS_G(pcireg->pci_phys_hi);
			kmem_free(pcireg, len);
		} else {
			bus = 0;
		}
		pcireg = (pci_regspec_t *)buff;
		pcireg->pci_phys_hi = (type == PCMCIA_MAP_IO ? PCI_ADDR_IO :
		    PCI_ADDR_MEM32) | PCI_RELOCAT_B | (bus << 16);
		pcireg->pci_phys_mid = ret->ra_addr_hi;
		pcireg->pci_phys_low = ret->ra_addr_lo;
		if (type == PCMCIA_MAP_IO)
			pcireg->pci_phys_low &= 0xFFFF;
		pcireg->pci_size_hi = 0;
		pcireg->pci_size_low = ret->ra_len;
		break;
	default:
		/* default case is to use struct regspec */
		defreg = (struct regspec *)buff;
		defreg->regspec_bustype = type == PCMCIA_MAP_IO ? 1 : 0;
		defreg->regspec_addr = ret->ra_addr_lo;
		defreg->regspec_size = ret->ra_len;
		break;
	}
	return ((struct regspec *)buff);
}

/*
 * pcmcia_init_adapter
 *	Initialize the per-adapter structures and check to see if
 *	there are possible other instances coming.
 */
void
pcmcia_init_adapter(anp_t *adapter, dev_info_t *dip)
{
	int i, n;
	pcmcia_if_t *ls_if;

	i = pcmcia_num_adapters++;
	pcmcia_adapters[i] = kmem_zalloc(sizeof (struct pcmcia_adapter),
	    KM_SLEEP);
	pcmcia_adapters[i]->pca_dip = dip;
	/* should this be pca_winshift??? */
	pcmcia_adapters[i]->pca_module = ddi_driver_major(dip);
	pcmcia_adapters[i]->pca_unit = ddi_get_instance(dip);
	pcmcia_adapters[i]->pca_iblock = adapter->an_iblock;
	pcmcia_adapters[i]->pca_idev = adapter->an_idev;
	pcmcia_adapters[i]->pca_if = ls_if = adapter->an_if;
	pcmcia_adapters[i]->pca_number = i;
	(void) strcpy(pcmcia_adapters[i]->pca_name, ddi_get_name(dip));
	pcmcia_adapters[i]->
	    pca_name[sizeof (pcmcia_adapters[i]->pca_name) - 1] = NULL;

	if (ls_if != NULL) {
		inquire_adapter_t conf;
		int sock, win;

		if (ls_if->pcif_inquire_adapter != NULL)
			GET_CONFIG(ls_if, dip, &conf);

		/* resources - assume worst case and fix from there */
		pcmcia_adapters[i]->pca_flags = PCA_RES_NEED_IRQ |
		    PCA_RES_NEED_IO | PCA_RES_NEED_MEM;
		/* indicate first socket not initialized */
		pcmcia_adapters[i]->pca_first_socket = -1;

		if (conf.ResourceFlags & RES_OWN_IRQ)
			pcmcia_adapters[i]->pca_flags &= ~PCA_RES_NEED_IRQ;
		if (conf.ResourceFlags & RES_OWN_IO)
			pcmcia_adapters[i]->pca_flags &= ~PCA_RES_NEED_IO;
		if (conf.ResourceFlags & RES_OWN_MEM)
			pcmcia_adapters[i]->pca_flags &= ~PCA_RES_NEED_MEM;
		if (conf.ResourceFlags & RES_IRQ_SHAREABLE)
			pcmcia_adapters[i]->pca_flags |= PCA_IRQ_SHAREABLE;
		if (conf.ResourceFlags & RES_IRQ_NEXUS)
			pcmcia_adapters[i]->pca_flags |= PCA_IRQ_SMI_SHARE;

		/* need to know interrupt limitations */
		if (conf.ActiveLow) {
			pcmcia_adapters[i]->pca_avail_intr = conf.ActiveLow;
			pcmcia_adapters[i]->pca_flags |= PCA_IRQ_ISA;
		} else
			pcmcia_adapters[i]->pca_avail_intr = conf.ActiveHigh;

		/* power entries for adapter */
		pcmcia_adapters[i]->pca_power = conf.power_entry;
		pcmcia_adapters[i]->pca_numpower = conf.NumPower;

		for (n = 0; n < conf.NumPower; n++)
			pcmcia_merge_power(&conf.power_entry[n]);

		/* now setup the per socket info */
		for (sock = 0; sock < conf.NumSockets;
		    sock++) {
			dev_info_t *sockdrv = NULL;
			sockdrv = pcmcia_number_socket(dip, sock);
			if (sockdrv == NULL)
				n = sock + pcmcia_num_sockets;
			else {
				n = ddi_get_instance(sockdrv);
			}
			/* make sure we know first socket on adapter */
			if (pcmcia_adapters[i]->pca_first_socket == -1)
				pcmcia_adapters[i]->pca_first_socket = n;

			/*
			 * the number of sockets is weird.
			 * we might have only two sockets but
			 * due to persistence of instances we
			 * will need to call them something other
			 * than 0 and 1.  So, we use the largest
			 * instance number as the number and
			 * have some that just don't get used.
			 */
			if (n >= pcmcia_num_sockets)
				pcmcia_num_sockets = n + 1;
#if defined(PCMCIA_DEBUG)
			if (pcmcia_debug) {
				cmn_err(CE_CONT,
				    "pcmcia_init: new socket added %d "
				    "(%d)\n",
				    n, pcmcia_num_sockets);
			}
#endif

			pcmcia_sockets[n] =
			    kmem_zalloc(sizeof (pcmcia_logical_socket_t),
			    KM_SLEEP);
			pcmcia_sockets[n]->ls_socket = sock;
			pcmcia_sockets[n]->ls_if = ls_if;
			pcmcia_sockets[n]->ls_adapter =
			    pcmcia_adapters[i];
			pcmcia_sockets[n]->ls_cs_events = 0L;
			pcmcia_sockets[n]->ls_sockdrv = sockdrv;
			/* Prototype of intrspec */
			pcmcia_sockets[n]->ls_intr_pri = adapter->an_ipl;
#if defined(PCMCIA_DEBUG)
			if (pcmcia_debug)
				cmn_err(CE_CONT,
				    "phys sock %d, log sock %d\n",
				    sock, n);
#endif
			mutex_init(&pcmcia_sockets[n]->ls_ilock, NULL,
			    MUTEX_DRIVER, *adapter->an_iblock);
		}

		pcmcia_adapters[i]->pca_numsockets = conf.NumSockets;
		/* now setup the per window information */
		for (win = 0; win < conf.NumWindows; win++) {
			n = win + pcmcia_num_windows;
			pcmcia_windows[n] =
			    kmem_zalloc(sizeof (pcmcia_logical_window_t),
			    KM_SLEEP);
			pcmcia_windows[n]->lw_window = win;
			pcmcia_windows[n]->lw_if = ls_if;
			pcmcia_windows[n]->lw_adapter =
			    pcmcia_adapters[i];
		}
		pcmcia_num_windows += conf.NumWindows;
		SET_CALLBACK(ls_if, dip,
		    pcm_adapter_callback, i);

		/* now tell CS about each socket */
		for (sock = 0; sock < pcmcia_num_sockets; sock++) {
#if defined(PCMCIA_DEBUG)
			if (pcmcia_debug) {
				cmn_err(CE_CONT,
				    "pcmcia_init: notify CS socket %d "
				    "sockp=%p\n",
				    sock, (void *)pcmcia_sockets[sock]);
			}
#endif
			if (pcmcia_sockets[sock] == NULL ||
			    (pcmcia_sockets[sock]->ls_flags &
			    PCS_SOCKET_ADDED)) {
				/* skip the ones that are done already */
				continue;
			}
			pcmcia_sockets[sock]->ls_flags |= PCS_SOCKET_ADDED;
			if (cs_event(PCE_ADD_SOCKET, sock, 0) !=
			    CS_SUCCESS) {
				/* flag socket as broken */
				pcmcia_sockets[sock]->ls_flags = 0;
			} else {
				pcm_event_manager(PCE_ADD_SOCKET,
				    sock, NULL);
			}
		}

	}
#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {
		cmn_err(CE_CONT, "logical sockets:\n");
		for (i = 0; i < pcmcia_num_sockets; i++) {
			if (pcmcia_sockets[i] == NULL)
				continue;
			cmn_err(CE_CONT,
			    "\t%d: phys sock=%d, if=%p, adapt=%p\n",
			    i, pcmcia_sockets[i]->ls_socket,
			    (void *)pcmcia_sockets[i]->ls_if,
			    (void *)pcmcia_sockets[i]->ls_adapter);
		}
		cmn_err(CE_CONT, "logical windows:\n");
		for (i = 0; i < pcmcia_num_windows; i++) {
			cmn_err(CE_CONT,
			    "\t%d: phys_window=%d, if=%p, adapt=%p\n",
			    i, pcmcia_windows[i]->lw_window,
			    (void *)pcmcia_windows[i]->lw_if,
			    (void *)pcmcia_windows[i]->lw_adapter);
		}
		cmn_err(CE_CONT, "\tpcmcia_num_power=%d\n", pcmcia_num_power);
		for (n = 0; n < pcmcia_num_power; n++)
			cmn_err(CE_CONT,
			    "\t\tPowerLevel: %d\tValidSignals: %x\n",
			    pcmcia_power_table[n].PowerLevel,
			    pcmcia_power_table[n].ValidSignals);
	}
#endif
}

/*
 * pcmcia_find_cards()
 *	check the adapter to see if there are cards present at
 *	driver attach time.  If there are, generate an artificial
 *	card insertion event to get CS running and the PC Card ultimately
 *	identified.
 */
void
pcmcia_find_cards(anp_t *adapt)
{
	int i;
	get_ss_status_t status;
	for (i = 0; i < pcmcia_num_sockets; i++) {
		if (pcmcia_sockets[i] &&
		    pcmcia_sockets[i]->ls_if == adapt->an_if) {
			/* check the status */
			status.socket = i;
			if (SSGetStatus(&status) == SUCCESS &&
			    status.IFType != IF_CARDBUS &&
			    status.CardState & SBM_CD &&
			    pcmcia_sockets[i]->ls_dip[0] == NULL) {
				(void) cs_event(PCE_CARD_INSERT, i, 0);
				delay(1);
			}
		}
	}
}

/*
 * pcmcia_number_socket(dip, adapt)
 *	we determine socket number by creating a driver for each
 *	socket on the adapter and then forcing it to attach.  This
 *	results in an instance being assigned which becomes the
 *	logical socket number.	If it fails, then we are the first
 *	set of sockets and renumbering occurs later.  We do this
 *	one socket at a time and return the dev_info_t so the
 *	instance number can be used.
 */
dev_info_t *
pcmcia_number_socket(dev_info_t *dip, int localsocket)
{
	dev_info_t *child = NULL;
	struct pcmcia_parent_private *ppd;

	if (ndi_devi_alloc(dip, "pcs", (pnode_t)DEVI_SID_NODEID,
	    &child) == NDI_SUCCESS) {
		ppd = kmem_zalloc(sizeof (struct pcmcia_parent_private),
		    KM_SLEEP);
		ppd->ppd_reg = kmem_zalloc(sizeof (struct pcm_regs), KM_SLEEP);
		ppd->ppd_nreg = 1;
		ppd->ppd_reg[0].phys_hi = localsocket;
		ddi_set_parent_data(child, (caddr_t)ppd);
		if (ndi_devi_online(child, 0) != NDI_SUCCESS) {
			kmem_free(ppd->ppd_reg, sizeof (struct pcm_regs));
			kmem_free(ppd, sizeof (struct pcmcia_parent_private));
			(void) ndi_devi_free(child);
			child = NULL;
		}
	}
	return (child);
}

/*
 * pcm_phys_to_log_socket()
 *	from an adapter and socket number return the logical socket
 */
int
pcm_phys_to_log_socket(struct pcmcia_adapter *adapt, int socket)
{
	register pcmcia_logical_socket_t *sockp;
	int i;

	for (i = 0, sockp = pcmcia_sockets[0];
	    i < pcmcia_num_sockets; i++, sockp = pcmcia_sockets[i]) {
		if (sockp == NULL)
			continue;
		if (sockp->ls_socket == socket && sockp->ls_adapter == adapt)
			break;
	}
	if (i >= pcmcia_num_sockets) {
#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug)
			cmn_err(CE_CONT,
			    "\tbad socket/adapter: %x/%p != %x/%x\n",
			    socket, (void *)adapt, pcmcia_num_sockets,
			    pcmcia_num_adapters);
#endif
		return (-1);
	}

	return (i);		/* want logical socket */
}

/*
 * pcm_adapter_callback()
 *	this function is called back by the adapter driver at interrupt time.
 *	It is here that events should get generated for the event manager if it
 *	is present.  It would also be the time where a device information
 *	tree could be constructed for a card that was added in if we
 *	choose to create them dynamically.
 */

#if defined(PCMCIA_DEBUG)
char *cblist[] = {
	"removal",
	"insert",
	"ready",
	"battery-warn",
	"battery-dead",
	"status-change",
	"write-protect", "reset", "unlock", "client-info", "eject-complete",
	"eject-request", "erase-complete", "exclusive-complete",
	"exclusive-request", "insert-complete", "insert-request",
	"reset-complete", "reset-request", "timer-expired",
	"resume", "suspend"
};
#endif

/*ARGSUSED*/
static int
pcm_adapter_callback(dev_info_t *dip, int adapter, int event, int socket)
{
	pcmcia_logical_socket_t *sockp;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {
		cmn_err(CE_CONT, "pcm_adapter_callback: %p %x %x %x: ",
		    (void *)dip, adapter, event, socket);
		cmn_err(CE_CONT, "[%s]\n", cblist[event]);
	}
#endif

	if (adapter >= pcmcia_num_adapters || adapter < 0) {
#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug)
			cmn_err(CE_CONT, "\tbad adapter number: %d : %d\n",
			    adapter, pcmcia_num_adapters);
#endif
		return (1);
	}

	/* get the logical socket since that is what CS knows */
	socket = pcm_phys_to_log_socket(pcmcia_adapters[adapter], socket);
	if (socket == -1) {
		cmn_err(CE_WARN, "pcmcia callback - bad logical socket\n");
		return (0);
	}
	sockp = pcmcia_sockets[socket];
	switch (event) {
	case -1:		/* special case of adapter going away */
	case PCE_CARD_INSERT:
		sockp->ls_cs_events |= PCE_E2M(PCE_CARD_INSERT) |
		    PCE_E2M(PCE_CARD_REMOVAL);
		break;
	case PCE_CARD_REMOVAL:
				/* disable interrupts at this point */
		sockp->ls_cs_events |= PCE_E2M(PCE_CARD_INSERT) |
		    PCE_E2M(PCE_CARD_REMOVAL);
		/* remove children that never attached */

		break;
	case PCE_PM_RESUME:
		pcmcia_do_resume(socket, sockp);
		/* event = PCE_CARD_INSERT; */
		break;
	case PCE_PM_SUSPEND:
		pcmcia_do_suspend(socket, sockp);
		/* event = PCE_CARD_REMOVAL; */
		break;
	default:
		/* nothing to do */
		break;
	}

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {
		cmn_err(CE_CONT,
		    "\tevent %d, event mask=%x, match=%x (log socket=%d)\n",
		    event,
		    (int)sockp->ls_cs_events,
		    (int)(sockp->ls_cs_events & PCE_E2M(event)), socket);
	}
#endif

	if (pcmcia_cs_event && sockp->ls_cs_events & (1 << event)) {
#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug)
			cmn_err(CE_CONT, "\tcalling CS event handler (%p) "
			    "with event=%d\n",
			    (void *)pcmcia_cs_event, event);
#endif
		CS_EVENT(event, socket, 0);
	}

	/* let the event manager(s) know about the event */
	pcm_event_manager(event, socket, NULL);

	return (0);
}

/*
 * pcm_event_manager()
 *	checks for registered management driver callback handlers
 *	if there are any, call them if the event warrants it
 */
void
pcm_event_manager(int event, int socket, void *arg)
{
	struct pcmcia_mif *mif;

	for (mif = pcmcia_mif_handlers; mif != NULL; mif = mif->mif_next) {
#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug)
			cmn_err(CE_CONT,
			    "pcm_event_manager: event=%d, mif_events=%x"
			    " (tst:%d)\n",
			    event, (int)*(uint32_t *)mif->mif_events,
			    PR_GET(mif->mif_events, event));
#endif
		if (PR_GET(mif->mif_events, event)) {
			mif->mif_function(mif->mif_id, event, socket, arg);
		}
	}

}

/*
 * pcm_search_devinfo(dev_info_t *, pcm_device_info *, int)
 * search for an immediate child node to the nexus and not siblings of nexus
 * and not grandchildren.  We follow the same sequence that name binding
 * follows so we match same class of device (modem == modem) and don't
 * have to depend on features that might not exist.
 */
dev_info_t *
pcm_search_devinfo(dev_info_t *self, struct pcm_device_info *info, int socket)
{
	char bf[256];
	struct pcmcia_parent_private *ppd;
	dev_info_t *dip;
	int circ;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug)
		cmn_err(CE_CONT,
		    "pcm_search_devinfo: socket=%x [%s|%s|%s] pd_flags=%x\n",
		    socket, info->pd_bind_name, info->pd_generic_name,
		    info->pd_vers1_name, info->pd_flags);
#endif

	ndi_devi_enter(self, &circ);
	/* do searches in compatible property order */
	for (dip = (dev_info_t *)DEVI(self)->devi_child;
	    dip != NULL;
	    dip = (dev_info_t *)DEVI(dip)->devi_sibling) {
		int ppd_socket;
		ppd = (struct pcmcia_parent_private *)
		    ddi_get_parent_data(dip);
		if (ppd == NULL) {
#if defined(PCMCIA_DEBUG)
			cmn_err(CE_WARN, "No parent private data\n");
#endif
			continue;
		}
		ppd_socket = CS_MAKE_SOCKET_NUMBER(ppd->ppd_socket,
		    ppd->ppd_function);
#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug) {
			cmn_err(CE_CONT, "\tbind=[%s], node=[%s]\n",
			    DEVI(dip)->devi_binding_name,
			    DEVI(dip)->devi_node_name);
		}
#endif
		if (info->pd_flags & PCM_NAME_VERS1) {
			(void) strcpy(bf, info->pd_vers1_name);
			pcmcia_fix_string(bf);
			if (DEVI(dip)->devi_binding_name &&
			    strcmp(DEVI(dip)->devi_binding_name, bf) == 0 &&
			    socket == ppd_socket)
				break;
		}
		if ((info->pd_flags & (PCM_NAME_1275 | PCM_MULTI_FUNCTION)) ==
		    (PCM_NAME_1275 | PCM_MULTI_FUNCTION)) {
			(void) sprintf(bf, "%s,%x", info->pd_bind_name,
			    info->pd_function);
			if (strcmp(bf, DEVI(dip)->devi_binding_name) == 0 &&
			    socket == ppd->ppd_socket)
				break;
		}
		if (info->pd_flags & PCM_NAME_1275) {
			if (DEVI(dip)->devi_binding_name &&
			    strcmp(DEVI(dip)->devi_binding_name,
			    info->pd_bind_name) == 0 &&
			    socket == ppd_socket)
				break;
		}
		if (info->pd_flags & PCM_NAME_GENERIC) {
			(void) sprintf(bf, "%s,%s", PCMDEV_NAMEPREF,
			    info->pd_generic_name);
			if (DEVI(dip)->devi_binding_name &&
			    strcmp(DEVI(dip)->devi_binding_name, bf) == 0 &&
			    socket == ppd_socket)
				break;
		}
		if (info->pd_flags & PCM_NAME_GENERIC) {
			if (DEVI(dip)->devi_binding_name &&
			    strcmp(DEVI(dip)->devi_binding_name,
			    info->pd_generic_name) == 0 &&
			    socket == ppd_socket)
				break;
		}
		if (info->pd_flags & PCM_NO_CONFIG) {
			if (DEVI(dip)->devi_binding_name &&
			    strcmp(DEVI(dip)->devi_binding_name,
			    "pccard,memory") == 0 &&
			    socket == ppd_socket)
				break;
		}
	}
	ndi_devi_exit(self, circ);
	return (dip);
}

/*
 * pcm_find_devinfo()
 *	this is a wrapper around DDI calls to "find" any
 *	devinfo node and then from there find the one associated
 *	with the socket
 */
dev_info_t *
pcm_find_devinfo(dev_info_t *pdip, struct pcm_device_info *info, int socket)
{
	dev_info_t *dip;

	dip = pcm_search_devinfo(pdip, info, socket);
	if (dip == NULL)
		return (NULL);
	/*
	 * we have at least a base level dip
	 * see if there is one (this or a sibling)
	 * that has the correct socket number
	 * if there is, return that one else
	 * NULL so a new one is created
	 */
#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug)
		cmn_err(CE_CONT, "find: initial dip = %p, socket=%d, name=%s "
		    "(instance=%d, socket=%d, name=%s)\n",
		    (void *)dip, socket, info->pd_bind_name,
		    ddi_get_instance(dip),
		    ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    PCM_DEV_SOCKET, -1),
		    ddi_get_name(dip));
#endif

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug && dip != NULL)
		cmn_err(CE_CONT, "\treturning non-NULL dip (%s)\n",
		    ddi_get_name(dip));
#endif
	return (dip);
}

/*
 * pcm_find_parent_dip(socket)
 *	find the correct parent dip for this logical socket
 */
dev_info_t *
pcm_find_parent_dip(int socket)
{
	if ((socket < 0 || socket >= pcmcia_num_sockets) ||
	    pcmcia_sockets[socket] == NULL)
		return (NULL);
	return (pcmcia_sockets[socket]->ls_adapter->pca_dip);
}

/*
 * pcmcia_set_em_handler()
 *	This is called by the management and event driver to tell
 *	the nexus what to call.	 Multiple drivers are allowed
 *	but normally only one will exist.
 */
int
pcmcia_set_em_handler(int (*handler)(), caddr_t events, int elen,
    uint32_t id, void **cs, void **ss)
{
	struct pcmcia_mif *mif, *tmp;

	if (handler == NULL) {
		/* NULL means remove the handler based on the ID */
		if (pcmcia_mif_handlers == NULL)
			return (0);
		mutex_enter(&pcmcia_global_lock);
		if (pcmcia_mif_handlers->mif_id == id) {
			mif = pcmcia_mif_handlers;
			pcmcia_mif_handlers = mif->mif_next;
			kmem_free(mif, sizeof (struct pcmcia_mif));
		} else {
			for (mif = pcmcia_mif_handlers;
			    mif->mif_next != NULL &&
			    mif->mif_next->mif_id != id;
			    mif = mif->mif_next)
				;
			if (mif->mif_next != NULL &&
			    mif->mif_next->mif_id == id) {
				tmp = mif->mif_next;
				mif->mif_next = tmp->mif_next;
				kmem_free(tmp, sizeof (struct pcmcia_mif));
			}
		}
		mutex_exit(&pcmcia_global_lock);
	} else {

		if (pcmcia_num_adapters == 0) {
			return (ENXIO);
		}
		if (elen > EM_EVENTSIZE)
			return (EINVAL);

		mif = (struct pcmcia_mif *)
		    kmem_zalloc(sizeof (struct pcmcia_mif), KM_NOSLEEP);
		if (mif == NULL)
			return (ENOSPC);

		mif->mif_function = (void (*)())handler;
		bcopy(events, mif->mif_events, elen);
		mif->mif_id = id;
		mutex_enter(&pcmcia_global_lock);
		mif->mif_next = pcmcia_mif_handlers;
		pcmcia_mif_handlers = mif;
		if (cs != NULL)
			*cs = (void *)pcmcia_card_services;
		if (ss != NULL) {
			*ss = (void *)SocketServices;
		}

		mutex_exit(&pcmcia_global_lock);
	}
	return (0);
}

/*
 * pcm_fix_bits(uchar_t *data, int num, int dir)
 *	shift socket bits left(0) or right(0)
 *	This is used when mapping logical and physical
 */
void
pcm_fix_bits(socket_enum_t src, socket_enum_t dst, int num, int dir)
{
	int i;

	PR_ZERO(dst);

	if (dir == 0) {
				/* LEFT */
		for (i = 0; i <= PCMCIA_MAX_SOCKETS - num; i++) {
			if (PR_GET(src, i))
				PR_SET(dst, i + num);
		}
	} else {
				/* RIGHT */
		for (i = num; i < PCMCIA_MAX_SOCKETS; i++) {
			if (PR_GET(src, i))
				PR_SET(dst, i - num);
		}
	}
}

uint32_t
genmask(int len)
{
	uint32_t mask;
	for (mask = 0; len > 0; len--) {
		mask |= 1 << (len - 1);
	}
	return (mask);
}

int
genp2(int val)
{
	int i;
	if (val == 0)
		return (0);
	for (i = 0; i < 32; i++)
		if (val > (1 << i))
			return (i);
	return (0);
}

#if defined(PCMCIA_DEBUG)
char *ssfuncs[128] = {
	"GetAdapter", "GetPage", "GetSocket", "GetStatus", "GetWindow",
	"InquireAdapter", "InquireSocket", "InquireWindow", "ResetSocket",
	"SetPage", "SetAdapter", "SetSocket", "SetWindow", "SetIRQHandler",
	"ClearIRQHandler",
	/* 15 */ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	/* 25 */ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	/* 35 */ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	/* 45 */ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	/* 55 */ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	/* 65 */ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	/* 75 */ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	/* 85 */ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	/* 95 */ NULL, NULL, NULL,
	"CSIsActiveDip",
	"CSInitDev", "CSRegister", "CSCISInit", "CSUnregister",
	"CISGetAddress", "CISSetAddress", "CSCardRemoved", "CSGetCookiesAndDip"
};
#endif

/*
 * SocketServices
 *	general entrypoint for Card Services to find
 *	Socket Services.  Finding the entry requires
 *	a _depends_on[] relationship.
 *
 *	In some cases, the work is done locally but usually
 *	the parameters are adjusted and the adapter driver
 *	code asked to do the work.
 */
int
SocketServices(int function, ...)
{
	va_list arglist;
	uint32_t args[16];
	csregister_t *reg;
	sservice_t *serv;
	dev_info_t *dip;
	int socket, func;
	int error = SUCCESS;
	pcmcia_logical_socket_t *sockp;

	va_start(arglist, function);

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug > 1)
		cmn_err(CE_CONT, "SocketServices called for function %d [%s]\n",
		    function,
		    ((function < 128) && ssfuncs[function] != NULL) ?
		    ssfuncs[function] : "UNKNOWN");
#endif
	switch (function) {
	case CSRegister:
	case CISGetAddress:
	case CISSetAddress:

		reg = va_arg(arglist, csregister_t *);

		if (reg->cs_magic != PCCS_MAGIC ||
		    reg->cs_version != PCCS_VERSION) {
			cmn_err(CE_WARN,
			    "pcmcia: CSRegister (%x, %x, %p, %p) *ERROR*",
			    reg->cs_magic, reg->cs_version,
			    (void *)reg->cs_card_services,
			    (void *)reg->cs_event);
			error = BAD_FUNCTION;
			break;
		}

		switch (function) {
		case CISGetAddress:
			reg->cs_event = pcmcia_cis_parser;
			break;
		case CISSetAddress:
			pcmcia_cis_parser = reg->cs_event;
			break;
		case CSRegister:
			break;
		}
		break;

	case CSUnregister:
		break;

	case CSCISInit:
		args[0] = va_arg(arglist, int);
#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug)
			cmn_err(CE_CONT,
			    "CSCISInit: CIS is initialized on socket %d\n",
			    (int)args[0]);
#endif
		/*
		 * now that the CIS has been parsed (there may not
		 * be one but the work is done) we can create the
		 * device information structures.
		 *
		 * we serialize the node creation to avoid problems
		 * with initial probe/attach of nexi.
		 */

		mutex_enter(&pcmcia_global_lock);
		pcmcia_create_dev_info(args[0]);
		cv_broadcast(&pcmcia_condvar); /* wakeup the nexus attach */
		mutex_exit(&pcmcia_global_lock);
		break;

	case CSInitDev:
#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug)
			cmn_err(CE_CONT, "CSInitDev: initialize device\n");
#endif
		/*
		 * this is where we create the /devices entries
		 * that let us out into the world
		 */

		(void) pcmcia_create_device(va_arg(arglist,
		    ss_make_device_node_t *));
		break;

	case CSCardRemoved:
		args[0] = va_arg(arglist, uint32_t);
		socket = CS_GET_SOCKET_NUMBER(args[0]);
		func = CS_GET_FUNCTION_NUMBER(args[0]);
#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug)
			cmn_err(CE_CONT,
			    "CSCardRemoved! (socket=%d)\n", (int)args[0]);
#endif
		if (socket >= pcmcia_num_sockets)
			break;

		sockp = pcmcia_sockets[socket];
		if (sockp == NULL) {
			cmn_err(CE_WARN,
			    "pcmcia: bad socket = %x", socket);
			break;
		}

		if (!(sockp->ls_flags & PCS_SUSPENDED)) {
			for (func = 0; func < sockp->ls_functions; func++) {
				/*
				 * break the association of dip and socket
				 * for all functions on that socket
				 */
				dip = sockp->ls_dip[func];
				sockp->ls_dip[func] = NULL;
				if (dip != NULL) {
					struct pcmcia_parent_private *ppd;
					ppd = (struct pcmcia_parent_private *)
					    ddi_get_parent_data(dip);
					ppd->ppd_active = 0;
					(void) ndi_devi_offline(dip,
					    NDI_DEVI_REMOVE);

					pcmcia_ppd_free(ppd);
				}
#if defined(PCMCIA_DEBUG)
				else {
					if (pcmcia_debug)
						cmn_err(CE_CONT,
						    "CardRemoved: no "
						    "dip present "
						    "on socket %d!\n",
						    (int)args[0]);
				}
#endif
			}
		} else {
			mutex_enter(&pcmcia_global_lock);
			sockp->ls_flags &= ~PCS_SUSPENDED;
			cv_broadcast(&pcmcia_condvar);
			mutex_exit(&pcmcia_global_lock);
		}
		break;

	case CSGetCookiesAndDip:
		serv = va_arg(arglist, sservice_t *);
		if (serv != NULL)
			error = GetCookiesAndDip(serv);
		else
			error = BAD_SOCKET;
		break;

	case CSGetActiveDip:
		/*
		 * get the dip associated with the card currently
		 * in the specified socket
		 */
		args[0] = va_arg(arglist, uint32_t);
		socket = CS_GET_SOCKET_NUMBER(args[0]);
		func = CS_GET_FUNCTION_NUMBER(args[0]);
		error = (long)pcmcia_sockets[socket]->ls_dip[func];
		break;

		/*
		 * the remaining entries are SocketServices calls
		 */
	case SS_GetAdapter:
		error = SSGetAdapter(va_arg(arglist, get_adapter_t *));
		break;
	case SS_GetPage:
		error = SSGetPage(va_arg(arglist, get_page_t *));
		break;
	case SS_GetSocket:
		error = SSGetSocket(va_arg(arglist, get_socket_t *));
		break;
	case SS_GetStatus:
		error = SSGetStatus(va_arg(arglist, get_ss_status_t *));
		break;
	case SS_GetWindow:
		error = SSGetWindow(va_arg(arglist, get_window_t *));
		break;
	case SS_InquireAdapter:
		error = SSInquireAdapter(va_arg(arglist, inquire_adapter_t *));
		break;
	case SS_InquireSocket:
		error = SSInquireSocket(va_arg(arglist, inquire_socket_t *));
		break;
	case SS_InquireWindow:
		error = SSInquireWindow(va_arg(arglist, inquire_window_t *));
		break;
	case SS_ResetSocket:
		args[0] = va_arg(arglist, uint32_t);
		args[1] = va_arg(arglist, int);
		error = SSResetSocket(args[0], args[1]);
		break;
	case SS_SetPage:
		error = SSSetPage(va_arg(arglist, set_page_t *));
		break;
	case SS_SetSocket:
		error = SSSetSocket(va_arg(arglist, set_socket_t *));
		break;
	case SS_SetWindow:
		error = SSSetWindow(va_arg(arglist, set_window_t *));
		break;
	case SS_SetIRQHandler:
		error = SSSetIRQHandler(va_arg(arglist, set_irq_handler_t *));
		break;
	case SS_ClearIRQHandler:
		error = SSClearIRQHandler(va_arg(arglist,
		    clear_irq_handler_t *));
		break;
	default:
		error = BAD_FUNCTION;
		break;
	}
	va_end(arglist);
	return (error);
}

/*
 * pcmcia_merge_power()
 *	The adapters may have different power tables so it
 *	is necessary to construct a single power table that
 *	can be used throughout the system.  The result is
 *	a merger of all capabilities.  The nexus adds
 *	power table entries one at a time.
 */
void
pcmcia_merge_power(struct power_entry *power)
{
	int i;
	struct power_entry pwr;

	pwr = *power;

	for (i = 0; i < pcmcia_num_power; i++) {
		if (pwr.PowerLevel == pcmcia_power_table[i].PowerLevel) {
			if (pwr.ValidSignals ==
			    pcmcia_power_table[i].ValidSignals) {
				return;
			} else {
				/* partial match */
				pwr.ValidSignals &=
				    ~pcmcia_power_table[i].ValidSignals;
			}
		}
	}
	/* what's left becomes a new entry */
	if (pcmcia_num_power == PCMCIA_MAX_POWER)
		return;
	pcmcia_power_table[pcmcia_num_power++] = pwr;
}

/*
 * pcmcia_do_suspend()
 *	tell CS that a suspend has happened by passing a
 *	card removal event.  Then cleanup the socket state
 *	to fake the cards being removed so resume works
 */
void
pcmcia_do_suspend(int socket, pcmcia_logical_socket_t *sockp)
{
	get_ss_status_t stat;
	struct pcmcia_adapter *adapt;
	pcmcia_if_t *ls_if;
	dev_info_t *dip;
	int i;

#ifdef	XXX
	if (pcmcia_cs_event == NULL) {
		return;
	}
#endif

	ls_if = sockp->ls_if;
	adapt = sockp->ls_adapter;

	if (ls_if == NULL || ls_if->pcif_get_status == NULL) {
		return;
	}

	stat.socket = socket;
#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {
		cmn_err(CE_CONT,
		    "pcmcia_do_suspend(%d, %p)\n", socket, (void *)sockp);
	}
#endif

	if (GET_STATUS(ls_if, adapt->pca_dip, &stat) != SUCCESS)
		return;

	/*
	 * If there is a card in the socket, then we need to send
	 *	everyone a PCE_CARD_REMOVAL event, and remove the
	 *	card active property.
	 */

	for (i = 0; i < sockp->ls_functions; i++) {
		struct pcmcia_parent_private *ppd;
		dip = sockp->ls_dip[i];
		if (dip != NULL) {
			ppd = (struct pcmcia_parent_private *)
			    ddi_get_parent_data(dip);
			ppd->ppd_flags |= PPD_SUSPENDED;
		}
#if 0
		sockp->ls_dip[i] = NULL;
#endif
	}
	sockp->ls_flags |= PCS_SUSPENDED;

	if (pcmcia_cs_event &&
	    (sockp->ls_cs_events & (1 << PCE_PM_SUSPEND))) {
		CS_EVENT(PCE_PM_SUSPEND, socket, 0);
	}
	pcm_event_manager(PCE_PM_SUSPEND, socket, NULL);
}

/*
 * pcmcia_do_resume()
 *	tell CS that a suspend has happened by passing a
 *	card removal event.  Then cleanup the socket state
 *	to fake the cards being removed so resume works
 */
void
pcmcia_do_resume(int socket, pcmcia_logical_socket_t *sockp)
{
	get_ss_status_t stat;
	struct pcmcia_adapter *adapt;
	pcmcia_if_t *ls_if;

#ifdef	XXX
	if (pcmcia_cs_event == NULL) {
		return;
	}
#endif

	ls_if = sockp->ls_if;
	adapt = sockp->ls_adapter;

	if (ls_if == NULL || ls_if->pcif_get_status == NULL) {
		return;
	}

	stat.socket = socket;
#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {
		cmn_err(CE_CONT,
		    "pcmcia_do_resume(%d, %p)\n", socket, (void *)sockp);
	}
#endif
	if (GET_STATUS(ls_if, adapt->pca_dip, &stat) ==
	    SUCCESS) {

#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug)
			cmn_err(CE_CONT, "\tsocket=%x, CardState=%x\n",
			    socket, stat.CardState);
#endif
#if 0
		/* now have socket info -- do we have events? */
		if ((stat.CardState & SBM_CD) == SBM_CD) {
			if (pcmcia_cs_event &&
			    (sockp->ls_cs_events & (1 << PCE_CARD_INSERT))) {
				CS_EVENT(PCE_CARD_INSERT, socket, 0);
			}

			/* we should have card removed from CS soon */
			pcm_event_manager(PCE_CARD_INSERT, socket, NULL);
		}
#else
		if (pcmcia_cs_event &&
		    (sockp->ls_cs_events & (1 << PCE_PM_SUSPEND))) {
			CS_EVENT(PCE_PM_RESUME, socket, 0);
			CS_EVENT(PCE_CARD_REMOVAL, socket, 0);
			if ((stat.CardState & SBM_CD) == SBM_CD)
				CS_EVENT(PCE_CARD_INSERT, socket, 0);
		}
#endif
	}
}

/*
 * pcmcia_map_power_set()
 *	Given a power table entry and level, find it in the
 *	master table and return the index in the adapter table.
 */
static int
pcmcia_map_power_set(struct pcmcia_adapter *adapt, int level, int which)
{
	int plevel, i;
	struct power_entry *pwr = (struct power_entry *)adapt->pca_power;
	plevel = pcmcia_power_table[level].PowerLevel;
	/* mask = pcmcia_power_table[level].ValidSignals; */
	for (i = 0; i < adapt->pca_numpower; i++)
		if (plevel == pwr[i].PowerLevel &&
		    pwr[i].ValidSignals & which)
			return (i);
	return (0);
}

/*
 * pcmcia_map_power_get()
 *	Given an adapter power entry, find the appropriate index
 *	in the master table.
 */
static int
pcmcia_map_power_get(struct pcmcia_adapter *adapt, int level, int which)
{
	int plevel, i;
	struct power_entry *pwr = (struct power_entry *)adapt->pca_power;
	plevel = pwr[level].PowerLevel;
	/* mask = pwr[level].ValidSignals; */
	for (i = 0; i < pcmcia_num_power; i++)
		if (plevel == pcmcia_power_table[i].PowerLevel &&
		    pcmcia_power_table[i].ValidSignals & which)
			return (i);
	return (0);
}

/*
 * XXX - SS really needs a way to allow the caller to express
 *	interest in PCE_CARD_STATUS_CHANGE events.
 */
static uint32_t
pcm_event_map[32] = {
	PCE_E2M(PCE_CARD_WRITE_PROTECT)|PCE_E2M(PCE_CARD_STATUS_CHANGE),
	PCE_E2M(PCE_CARD_UNLOCK)|PCE_E2M(PCE_CARD_STATUS_CHANGE),
	PCE_E2M(PCE_EJECTION_REQUEST)|PCE_E2M(PCE_CARD_STATUS_CHANGE),
	PCE_E2M(PCE_INSERTION_REQUEST)|PCE_E2M(PCE_CARD_STATUS_CHANGE),
	PCE_E2M(PCE_CARD_BATTERY_WARN)|PCE_E2M(PCE_CARD_STATUS_CHANGE),
	PCE_E2M(PCE_CARD_BATTERY_DEAD)|PCE_E2M(PCE_CARD_STATUS_CHANGE),
	PCE_E2M(PCE_CARD_READY)|PCE_E2M(PCE_CARD_STATUS_CHANGE),
	PCE_E2M(PCE_CARD_REMOVAL)|PCE_E2M(PCE_CARD_INSERT)|
					PCE_E2M(PCE_CARD_STATUS_CHANGE),
	PCE_E2M(PCE_PM_SUSPEND)|PCE_E2M(PCE_PM_RESUME),
};

static int
pcm_mapevents(uint32_t eventmask)
{
	uint32_t mask;
	int i;

	for (i = 0, mask = 0; eventmask && i < 32; i++) {
		if (eventmask & (1 << i)) {
			mask |= pcm_event_map[i];
			eventmask &= ~(1 << i);
		}
	}
	return (mask);
}


/*
 * PCMCIA Generic Naming Support
 *
 * With 2.6, PCMCIA naming moves to the 1275 and generic naming model.
 * Consequently, the whole naming mechanism is to be changed.  This is
 * not backward compatible with the current names but that isn't a problem
 * due to so few drivers existing.
 *
 * For cards with a device_id tuple, a generic name will be used.
 * if there is no device_id, then the 1275 name will be used if possible.
 * The 1275 name is of the form pccardNNNN,MMMM from the manfid tuple.
 * if there is not manfid tuple, an attempt will be made to bind the
 * node to the version_1 strings.
 *
 * In all cases, a "compatible" property is created with a number
 * of names.  The most generic name will be last in the list.
 */

/*
 * pcmcia_fix_string()
 * want to avoid special characters in alias strings so convert
 * to something innocuous
 */

void
pcmcia_fix_string(char *str)
{
	for (; str && *str; str++) {
		switch (*str) {
			case ' ':
			case '\t':
				*str = '_';
				break;
		}
	}
}

void
pcmcia_1275_name(int socket, struct pcm_device_info *info,
    client_handle_t handle)
{
	cistpl_manfid_t manfid;
	cistpl_jedec_t jedec;
	tuple_t tuple;
	int i;

	tuple.Socket = socket;

	/* get MANFID if it exists -- this is most important form */
	tuple.DesiredTuple = CISTPL_MANFID;
	tuple.Attributes = 0;
	if ((i = csx_GetFirstTuple(handle, &tuple)) ==
	    SUCCESS) {
		i = csx_Parse_CISTPL_MANFID(handle, &tuple,
		    &manfid);
		if (i == SUCCESS) {
			(void) sprintf(info->pd_bind_name, "%s%x,%x",
			    PCMDEV_NAMEPREF,
			    manfid.manf, manfid.card);
			info->pd_flags |= PCM_NAME_1275;
		}
	} else {
		tuple.Attributes = 0;
		tuple.DesiredTuple = CISTPL_JEDEC_A;
		if ((i = csx_GetFirstTuple(handle, &tuple)) ==
		    SUCCESS) {
			i = csx_Parse_CISTPL_JEDEC_A(handle, &tuple,
			    &jedec);
			if (i == SUCCESS) {
				(void) sprintf(info->pd_bind_name, "%s%x,%x",
				    PCMDEV_NAMEPREF,
				    jedec.jid[0].id, jedec.jid[0].info);
				info->pd_flags |= PCM_NAME_1275;
			}
		}
	}
}

void
pcmcia_vers1_name(int socket, struct pcm_device_info *info,
    client_handle_t handle)
{
	cistpl_vers_1_t vers1;
	tuple_t tuple;
	int which = 0;
	int i, len, space;

	tuple.Socket = socket;
	info->pd_vers1_name[0] = '\0';

	/* Version 1 strings */
	tuple.DesiredTuple = CISTPL_VERS_1;
	tuple.Attributes = 0;
	if (!which &&
	    (i = csx_GetFirstTuple(handle, &tuple)) == SUCCESS) {
		i = csx_Parse_CISTPL_VERS_1(handle, &tuple, &vers1);
		if (i == SUCCESS) {
			/* BEGIN CSTYLED */
			for (i = 0, len = 0, space = 0; i < vers1.ns; i++) {
			    if ((space + len + strlen(info->pd_vers1_name)) >=
				sizeof (info->pd_vers1_name))
				    break;
			    if (space) {
				    info->pd_vers1_name[len++] = ',';
			    }
			    (void) strcpy(info->pd_vers1_name + len,
				(char *)vers1.pi[i]);
			    len += strlen((char *)vers1.pi[i]);
			    /* strip trailing spaces off of string */
			    while (info->pd_vers1_name[len - 1] == ' ' &&
				    len > 0)
				    len--;
			    space = 1;
			}
			/* END CSTYLED */
			info->pd_vers1_name[len] = '\0';
			info->pd_flags |= PCM_NAME_VERS1;
		}
	}
}


int
pcmcia_get_funce(client_handle_t handle, tuple_t *tuple)
{
	int ret = 0;

	tuple->Attributes = 0;
	while (csx_GetNextTuple(handle, tuple) == SUCCESS) {
		if (tuple->TupleCode == CISTPL_FUNCID) {
			break;
		}
		if (tuple->TupleCode == CISTPL_FUNCE) {
			ret = 1;
			break;
		}
		tuple->Attributes = 0;
	}
	return (ret);
}

char *pcmcia_lan_types[] = {
	"arcnet",
	"ethernet",
	"token-ring",
	"localtalk",
	"fddi",
	"atm",
	"wireless",
	"reserved"
};

void
pcmcia_generic_name(int socket, struct pcm_device_info *info,
    client_handle_t handle)
{
	cistpl_funcid_t funcid;
	cistpl_funce_t funce;
	tuple_t tuple;
	int which = 0;
	int i;

	tuple.Socket = socket;

	tuple.DesiredTuple = CISTPL_FUNCID;
	tuple.Attributes = 0;
	if ((i = csx_GetFirstTuple(handle, &tuple)) ==
	    SUCCESS) {
		/*
		 * need to make sure that CISTPL_FUNCID is not
		 * present in both a global and local CIS for MF
		 * cards.  3COM seems to do this erroneously
		 */

		if (info->pd_flags & PCM_MULTI_FUNCTION &&
		    tuple.Flags & CISTPLF_GLOBAL_CIS) {
			tuple_t ltuple;
			ltuple = tuple;
			ltuple.DesiredTuple = CISTPL_FUNCID;
			ltuple.Attributes = 0;
			if ((i = csx_GetNextTuple(handle, &ltuple)) ==
			    SUCCESS) {
				/* this is the per-function funcid */
				tuple = ltuple;
			}
		}

		i = csx_Parse_CISTPL_FUNCID(handle, &tuple, &funcid);
		if (i == SUCCESS) {
			/* in case no function extension */
			if (funcid.function < PCM_GENNAME_SIZE)
				(void) strcpy(info->pd_generic_name,
				    pcmcia_generic_names[funcid.function]);
			else
				(void) sprintf(info->pd_generic_name,
				    "class,%x",
				    funcid.function);
		}
		info->pd_type = funcid.function;
		switch (funcid.function) {
		case TPLFUNC_LAN:
			which = pcmcia_get_funce(handle, &tuple);
			if (which) {
				i = csx_Parse_CISTPL_FUNCE(handle,
				    &tuple,
				    &funce, TPLFUNC_LAN);
				if (i == SUCCESS) {
					i = funce.data.lan.tech;
					if (i >= sizeof (pcmcia_lan_types) /
					    sizeof (char *)) {
						break;
					}
					(void) strcpy(info->pd_generic_name,
					    pcmcia_lan_types[i]);
				}
			}
			break;
		case TPLFUNC_VIDEO:
#ifdef future_pcmcia_spec
			which = pcmcia_get_funce(handle, &tuple);
			if (which) {
				i = csx_Parse_CISTPL_FUNCE(handle,
				    &tuple,
				    &funce, TPLFUNC_VIDEO);
				if (i == SUCCESS) {
					i = funce.video.tech;
					if (i > sizeof (pcmcia_lan_types) /
					    sizeof (char *)) {
						break;
					}
					(void) strcpy(info->pd_generic_names,
					    pcmcia_lan_types[i]);
				}
			}
#endif
			break;
		}
		info->pd_flags |= PCM_NAME_GENERIC;
	} else {
		/* if no FUNCID, do we have CONFIG */
		tuple.DesiredTuple = CISTPL_CONFIG;
		tuple.Attributes = 0;
		if (csx_GetFirstTuple(handle, &tuple) != SUCCESS) {
			info->pd_flags |= PCM_NO_CONFIG | PCM_NAME_GENERIC;
			(void) strcpy(info->pd_generic_name,
			    pcmcia_generic_names[PCM_TYPE_MEMORY]);
			info->pd_type = PCM_TYPE_MEMORY;
		}
	}
}


/*
 * pcmcia_add_compatible()
 * add the cached compatible property list.
 */
void
pcmcia_add_compatible(dev_info_t *dip, struct pcm_device_info *info)
{
	int length = 0, i;
	char buff[MAXNAMELEN];
	char *compat_name[8];
	int ci = 0;

	bzero(compat_name, sizeof (compat_name));

	if (info->pd_flags & PCM_NAME_VERS1) {
		(void) sprintf(buff, "%s,%s", PCMDEV_NAMEPREF,
		    info->pd_vers1_name);
		pcmcia_fix_string(buff); /* don't want spaces */
		length = strlen(buff) + 1;
		compat_name[ci] = kmem_alloc(length, KM_SLEEP);
		(void) strcpy(compat_name[ci++], buff);
	}

	if ((info->pd_flags & (PCM_NAME_1275 | PCM_MULTI_FUNCTION)) ==
	    (PCM_NAME_1275 | PCM_MULTI_FUNCTION)) {
		(void) sprintf(buff, "%s,%x", info->pd_bind_name,
		    info->pd_function);
		length = strlen(buff) + 1;
		compat_name[ci] = kmem_alloc(length, KM_SLEEP);
		(void) strcpy(compat_name[ci++], buff);
	}

	if (info->pd_flags & PCM_NAME_1275) {
		length = strlen(info->pd_bind_name) + 1;
		compat_name[ci] = kmem_alloc(length, KM_SLEEP);
		(void) strcpy(compat_name[ci++], info->pd_bind_name);
	}

	if (info->pd_flags & PCM_NAME_GENERIC) {
		if (strncmp(info->pd_generic_name, "class,", 6) == 0) {
			/* no generic without "pccard" */
			(void) sprintf(buff, "%s%s", PCMDEV_NAMEPREF,
			    info->pd_generic_name);
		} else {
			/* first pccard,generic-name */
			(void) sprintf(buff, "%s,%s", PCMDEV_NAMEPREF,
			    info->pd_generic_name);
		}
		length = strlen(buff) + 1;
		compat_name[ci] = kmem_alloc(length, KM_SLEEP);
		(void) strcpy(compat_name[ci++], buff);

		/* now the simple generic name */
		length = strlen(info->pd_generic_name) + 1;
		compat_name[ci] = kmem_alloc(length, KM_SLEEP);
		(void) strcpy(compat_name[ci++], info->pd_generic_name);
	}

	if (info->pd_flags & PCM_NO_CONFIG) {
		char *mem = "pccard,memory";
		/*
		 * I/O cards are required to have a config tuple.
		 * there are some that violate the spec and don't
		 * but it is most likely that this is a memory card
		 * so tag it as such.  "memory" is more general
		 * than other things so needs to come last.
		 */
		length = strlen(mem) + 1;
		compat_name[ci] = kmem_alloc(length, KM_SLEEP);
		(void) strcpy(compat_name[ci++], mem);
	}

	if (ci == 0)
		return;

	if (ndi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    "compatible", (char **)compat_name, ci) != DDI_PROP_SUCCESS)
		cmn_err(CE_WARN, "pcmcia: unable to create compatible prop");

	for (i = 0; i < ci; i++)
		kmem_free(compat_name[i], strlen(compat_name[i]) + 1);
}
/*
 * CIS parsing and other PC Card specific code
 */

/*
 * pcmcia_get_mem_regs()
 */
static int
pcmcia_get_mem_regs(struct pcm_regs *regs, struct pcm_device_info *info,
    int type, int pctype)
{
	int num_regs = 0;
	tuple_t tuple;
	cistpl_device_t device;
	uint32_t curr_base;
	int ret, len;
	int space;

	/*
	 * current plan for reg spec:
	 * device_a will be accumulated to determine max size of
	 * attribute memory.  device for common.  Then config
	 * tuples to get a worst case I/O size.
	 */
	bzero(&tuple, sizeof (tuple));
	tuple.Socket = info->pd_socket;

	tuple.DesiredTuple = (cisdata_t)type;

	space = (type == CISTPL_DEVICE_A) ? PC_REG_SPACE_ATTRIBUTE :
	    PC_REG_SPACE_MEMORY;
	if ((ret = csx_GetFirstTuple(info->pd_handle, &tuple)) == CS_SUCCESS) {
		bzero(&device, sizeof (device));

		if (type == CISTPL_DEVICE)
			ret = csx_Parse_CISTPL_DEVICE(info->pd_handle, &tuple,
			    &device);
		else
			ret = csx_Parse_CISTPL_DEVICE_A(info->pd_handle, &tuple,
			    &device);

		if (ret == CS_SUCCESS) {
			curr_base = 0;
			for (ret = 0; ret < device.num_devices; ret++) {
				/* need to order these for real mem first */
				if (device.devnode[ret].type !=
				    CISTPL_DEVICE_DTYPE_NULL) {
					/* how to represent types??? */
					regs[num_regs].phys_hi =
					    PC_REG_PHYS_HI(0, 0,
					    pctype,
					    space,
					    info->pd_socket,
					    info->pd_function,
					    0);
					regs[num_regs].phys_lo = curr_base;
					len = device.devnode[ret].size_in_bytes;
					curr_base += len;
					regs[num_regs].phys_len = len;
					num_regs++;
				} else {
					/*
					 * NULL device is a "hole"
					 */
					curr_base +=
					    device.devnode[ret].size_in_bytes;
				}
			}
		}
	}
	return (num_regs);
}

/*
 *
 */
static int
pcmcia_get_io_regs(struct pcm_regs *regs, struct pcm_device_info *info,
    int pctype)
{
	int num_regs = 0;
	tuple_t tuple;
	uint32_t curr_base;
	int len, curr, i, curr_len;
	cistpl_config_t config;
	cistpl_cftable_entry_t cftable;
	struct pcm_regs tmp[16];
	int found = 0;

	bzero(&tuple, sizeof (tuple));
	tuple.DesiredTuple = CISTPL_CONFIG;
	tuple.Socket = info->pd_socket;
	tuple.Attributes = 0;
	curr_base = 0;
	len = 0;

	if (csx_GetFirstTuple(info->pd_handle, &tuple) == CS_SUCCESS) {
		if (csx_Parse_CISTPL_CONFIG(info->pd_handle,
		    &tuple, &config) != CS_SUCCESS) {
			info->pd_flags |= PCM_NO_CONFIG; /* must be memory */
			return (0);
		}
		curr = 0;

		tuple.DesiredTuple = CISTPL_CFTABLE_ENTRY;
		tuple.Socket = info->pd_socket;
		tuple.Attributes = 0;
		bzero(tmp, sizeof (tmp));

	while (csx_GetNextTuple(info->pd_handle, &tuple) == CS_SUCCESS) {
		bzero(&cftable, sizeof (cftable));

		if (csx_Parse_CISTPL_CFTABLE_ENTRY(info->pd_handle,
		    &tuple, &cftable) == CS_SUCCESS) {

		/* BEGIN CSTYLED */
		if (cftable.flags & CISTPL_CFTABLE_TPCE_FS_IO) {
		    /* we have an I/O entry */
		    if (cftable.io.flags &
			CISTPL_CFTABLE_TPCE_FS_IO_RANGE) {
			len = cftable.io.addr_lines;
			if (len != 0)
				len = 1 << len;
			for (i = 0; i < cftable.io.ranges && curr < 16; i++) {
			    curr_base = cftable.io.range[i].addr;
			    curr_len = cftable.io.range[i].length;
			    if (curr_len == 0)
				    curr_len = len;
			    if (len != 0 || cftable.io.addr_lines == 0) {
				/* we have potential relocation */
				int mask;
				mask = cftable.io.addr_lines ?
				    cftable.io.addr_lines : genp2(len);
				mask = genmask(mask);
				if ((mask & curr_base) == 0) {
					/* more accurate length */
					regs->phys_len = curr_len;
					regs->phys_lo = 0;
					regs->phys_hi =
					    PC_REG_PHYS_HI(0,
					    0,
					    pctype,
					    PC_REG_SPACE_IO,
					    info->pd_socket,
					    info->pd_function,
					    0);
					num_regs++;
					found = 2;
					break;
				}
			    }
			    tmp[curr].phys_len = curr_len;
			    tmp[curr].phys_lo = curr_base;
			    curr++;
			    found = 1;
			}
			if (found == 2)
				break;
		    } else {
			/* no I/O range so just a mask */
			regs->phys_len = 1 << cftable.io.addr_lines;
			regs->phys_hi =
			    PC_REG_PHYS_HI(0,
			    0,
			    pctype,
			    PC_REG_SPACE_IO,
			    info->pd_socket,
			    info->pd_function,
			    0);
			regs->phys_lo = 0;
			num_regs++;
			regs++;
			/* quit on "good" entry */
			break;
		    }
		    /* was this the last CFTABLE Entry? */
		    if (config.last == cftable.index)
			    break;
		}
		/* END CSTYLE */
		}
	}
	if (found == 1) {
		/*
		 * have some non-relocatable values
		 * so we include them all for now
		 */
		for (i = 0; i < curr && num_regs < 8; i++) {
		    regs->phys_len = tmp[i].phys_len;
		    regs->phys_lo = tmp[i].phys_lo;
		    regs->phys_hi = PC_REG_PHYS_HI(1, 0, pctype,
			    PC_REG_SPACE_IO, info->pd_socket,
			    info->pd_function, 0);
		    regs++;
		    num_regs++;
		}
	    }
	}
	return (num_regs);
}

/*
 * pcmcia_create_regs()
 *	create a valid set of regspecs for the card
 *	The first one is always for CIS access and naming
 */
/*ARGSUSED*/
static void
pcmcia_find_regs(dev_info_t *dip, struct pcm_device_info *info,
			struct pcmcia_parent_private *ppd)
{
	struct pcm_regs regs[32]; /* assume worst case */
	int num_regs = 0;
	int len;
	int bustype;

	if (ppd->ppd_flags & PPD_CARD_CARDBUS) {
		/* always have a CIS map */
		regs[0].phys_hi = PC_REG_PHYS_HI(0, 0, PC_REG_TYPE_CARDBUS,
		    PC_REG_SPACE_CONFIG,
		    info->pd_socket,
		    info->pd_function, 0);
		bustype = PC_REG_TYPE_CARDBUS;
	} else {
		/* always have a CIS map */
		regs[0].phys_hi = PC_REG_PHYS_HI(0, 0, PC_REG_TYPE_16BIT,
		    PC_REG_SPACE_ATTRIBUTE,
		    info->pd_socket,
		    info->pd_function, 0);
		bustype = PC_REG_TYPE_16BIT;
	}
	regs[0].phys_lo = 0;	/* always starts at zero */
	regs[0].phys_len = 0;
	num_regs++;
	/*
	 * need to search CIS for other memory instances
	 */

	if (info->pd_flags & PCM_OTHER_NOCIS) {
		/* special case of memory only card without CIS */
		regs[1].phys_hi = PC_REG_PHYS_HI(0, 0, PC_REG_TYPE_16BIT,
		    PC_REG_SPACE_MEMORY,
		    info->pd_socket,
		    info->pd_function, 0);
		regs[1].phys_lo = 0;
		regs[1].phys_len = PCM_MAX_R2_MEM;
		num_regs++;
	} else {
		/*
		 * want to get any other memory and/or I/O regions
		 * on the card and represent them here.
		 */
		num_regs += pcmcia_get_mem_regs(&regs[num_regs], info,
		    CISTPL_DEVICE_A, bustype);
		num_regs += pcmcia_get_mem_regs(&regs[num_regs], info,
		    CISTPL_DEVICE, bustype);

		/* now look for an I/O space to configure */
		num_regs += pcmcia_get_io_regs(&regs[num_regs], info,
		    bustype);

	}

	len = num_regs * sizeof (uint32_t) * 3;
	ppd->ppd_nreg = num_regs;
	ppd->ppd_reg = kmem_alloc(len, KM_SLEEP);
	bcopy(regs, ppd->ppd_reg, len);
	len = sizeof (struct pcm_regs) * ppd->ppd_nreg;
	ppd->ppd_assigned = kmem_zalloc(len, KM_SLEEP);
}


/*
 * pcmcia_need_intr()
 *	check to see if an interrupt tuple exists.
 *	existence means we need one in the intrspec.
 */
static int
pcmcia_need_intr(int socket, struct pcm_device_info *info)
{
	cistpl_config_t config;
	cistpl_cftable_entry_t cftable;
	tuple_t tuple;
	int i;

	bzero(&tuple, sizeof (tuple));
	tuple.DesiredTuple = CISTPL_CONFIG;
	tuple.Socket = socket;
	tuple.Attributes = 0;
	if (csx_GetFirstTuple(info->pd_handle, &tuple) != CS_SUCCESS) {
		return (0);
	}
#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {
		cmn_err(CE_CONT, "pcmcia_need_intr: have config tuple\n");
	}
#endif
	bzero(&config, sizeof (config));
	if (csx_Parse_CISTPL_CONFIG(info->pd_handle,
	    &tuple, &config) != CS_SUCCESS) {
		cmn_err(CE_WARN, "pcmcia: config failed to parse\n");
		return (0);
	}

	for (cftable.index = (int)-1, i = -1;
	    i != config.last; i = cftable.index) {
		tuple.DesiredTuple = CISTPL_CFTABLE_ENTRY;
		tuple.Attributes = 0;
		if (csx_GetNextTuple(info->pd_handle,
		    &tuple) != CS_SUCCESS) {
			cmn_err(CE_WARN, "pcmcia: get cftable failed\n");
			break;
		}
		bzero(&cftable, sizeof (cftable));
		if (csx_Parse_CISTPL_CFTABLE_ENTRY(info->pd_handle,
		    &tuple, &cftable) !=
		    CS_SUCCESS) {
			cmn_err(CE_WARN, "pcmcia: parse cftable failed\n");
			break;
		}
#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug)
			cmn_err(CE_CONT, "\t%x: flags=%x (%x)\n",
			    i, cftable.flags,
			    cftable.flags & CISTPL_CFTABLE_TPCE_FS_IRQ);
#endif
		if (cftable.flags & CISTPL_CFTABLE_TPCE_FS_IRQ)
			return (1);
	}
	return (0);

}

/*
 * pcmcia_num_funcs()
 *	look for a CISTPL_LONGLINK_MFC
 *	if there is one, return the number of functions
 *	if there isn't one, then there is one function
 */
static int
pcmcia_num_funcs(int socket, client_handle_t handle)
{
	int count = 1;
	cistpl_longlink_mfc_t mfc;
	tuple_t tuple;

	bzero(&tuple, sizeof (tuple_t));
	tuple.DesiredTuple = CISTPL_LONGLINK_MFC;
	tuple.Socket = socket;
	tuple.Attributes = 0;
	if (csx_GetFirstTuple(handle, &tuple) == CS_SUCCESS) {
		/* this is a multifunction card */
		if (csx_ParseTuple(handle, &tuple, (cisparse_t *)&mfc,
		    CISTPL_LONGLINK_MFC) == CS_SUCCESS) {
			count = mfc.nfuncs;
		}
	}
	return (count);
}

client_handle_t pcmcia_cs_handle;

/*
 * pcmcia_create_dev_info(socket)
 *	either find or create the device information structure
 *	for the card(s) just inserted.	We don't care about removal yet.
 *	In any case, we will only do this at CS request
 */
static void
pcmcia_create_dev_info(int socket)
{
	struct pcm_device_info card_info;
	client_reg_t reg;
	cisinfo_t cisinfo;
	int i;
	dev_info_t *pdip;
	static int handle_def = 0;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug)
		cmn_err(CE_CONT, "create dev_info_t for device in socket %d\n",
		    socket);
#endif

	/*
	 * before we can do anything else, we need the parent
	 * devinfo of the socket.  This gets things in the right
	 * place in the device tree.
	 */

	pdip = pcm_find_parent_dip(socket);
	if (pdip == NULL)
		return;

	/* Card Services calls needed to get CIS info */
	reg.dip = NULL;
	reg.Attributes = INFO_SOCKET_SERVICES;
	reg.EventMask = 0;
	reg.event_handler = NULL;
	reg.Version = CS_VERSION;

	bzero(&card_info, sizeof (card_info));

	if (handle_def == 0) {
		if (csx_RegisterClient(&pcmcia_cs_handle,
		    &reg) != CS_SUCCESS) {
#if defined(PCMCIA_DEBUG)
			if (pcmcia_debug)
				cmn_err(CE_CONT,
				    "pcmcia: RegisterClient failed\n");
#endif
			return;
		}
		handle_def++;
	}
	card_info.pd_handle = pcmcia_cs_handle;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug)
		cmn_err(CE_CONT,
		    "pcmcia_create_dev_info: handle = %x\n",
		    (int)card_info.pd_handle);
#endif
	card_info.pd_type = -1; /* no type to start */
	card_info.pd_socket = socket;
	card_info.pd_function = 0;
	pcmcia_sockets[socket]->ls_functions = 1; /* default */

	cisinfo.Socket = socket;

	if ((i = csx_ValidateCIS(card_info.pd_handle,
	    &cisinfo)) != SUCCESS ||
	    cisinfo.Tuples == 0) {
		/* no CIS means memory */
		(void) strcpy(card_info.pd_generic_name, "memory");
		card_info.pd_flags |= PCM_NAME_GENERIC |
		    PCM_OTHER_NOCIS | PCM_NAME_1275;
		(void) strcpy(card_info.pd_bind_name, "pccard,memory");
		(void) strcpy(card_info.pd_generic_name, "memory");
		card_info.pd_type = PCM_TYPE_MEMORY;
	} else {
		int functions, lsocket;
		card_info.pd_tuples = cisinfo.Tuples;

		/*
		 * how many functions on the card?
		 * we need to know and then we do one
		 * child node for each function using
		 * the function specific tuples.
		 */
		lsocket = CS_MAKE_SOCKET_NUMBER(socket, CS_GLOBAL_CIS);
		functions = pcmcia_num_funcs(lsocket,
		    card_info.pd_handle);
		pcmcia_sockets[socket]->ls_functions = functions;
		if (functions > 1) {
			card_info.pd_flags |= PCM_MULTI_FUNCTION;
		}
		for (i = 0; i < functions; i++) {
			register int flags;
			lsocket = CS_MAKE_SOCKET_NUMBER(socket, i);
			card_info.pd_socket = socket;
			card_info.pd_function = i;
			/*
			 * new name construction
			 */
			if (functions != 1) {
				/* need per function handle */
				card_info.pd_function = i;
				/* get new handle */
			}
			pcmcia_1275_name(lsocket, &card_info,
			card_info.pd_handle);
			pcmcia_vers1_name(lsocket, &card_info,
			card_info.pd_handle);
			pcmcia_generic_name(lsocket, &card_info,
			card_info.pd_handle);
			flags = card_info.pd_flags;
			if (!(flags & PCM_NAME_1275)) {
				if (flags & PCM_NAME_VERS1) {
				    (void) strcpy(card_info.pd_bind_name,
					PCMDEV_NAMEPREF);
				    card_info.pd_bind_name[
				        sizeof (PCMDEV_NAMEPREF)] = ',';
				    (void) strncpy(card_info.pd_bind_name +
					sizeof (PCMDEV_NAMEPREF),
					card_info.pd_vers1_name,
					MODMAXNAMELEN -
					sizeof (PCMDEV_NAMEPREF));
				    pcmcia_fix_string(card_info.pd_bind_name);
				} else {
					/*
					 * have a CIS but not the right info
					 * so treat as generic "pccard"
					 */
					(void) strcpy(card_info.pd_generic_name,
					    "pccard,memory");
					card_info.pd_flags |= PCM_NAME_GENERIC;
					(void) strcpy(card_info.pd_bind_name,
					    "pccard,memory");
				}
			}
			pcmcia_init_devinfo(pdip, &card_info);
		}
		return;
	}

	pcmcia_init_devinfo(pdip, &card_info);
}

/*
 * pcmcia_init_devinfo()
 *	if there isn't a device info structure, create one
 *	if there is, we don't do much.
 *
 *	Note: this will need updating as 1275 finalizes their spec.
 */
static void
pcmcia_init_devinfo(dev_info_t *pdip, struct pcm_device_info *info)
{
	int unit;
	dev_info_t *dip;
	char *name;
	struct pcmcia_parent_private *ppd;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug)
		cmn_err(CE_CONT, "init_devinfo(%s, %d)\n", info->pd_bind_name,
		    info->pd_socket);
#endif

	/*
	 * find out if there is already an instance of this
	 * device.  We don't want to create a new one unnecessarily
	 */
	unit = CS_MAKE_SOCKET_NUMBER(info->pd_socket, info->pd_function);

	dip = pcm_find_devinfo(pdip, info, unit);
	if ((dip != NULL) && (ddi_getprop(DDI_DEV_T_NONE, dip,
	    DDI_PROP_DONTPASS, PCM_DEV_SOCKET, -1) != -1)) {
		/* it already exist but isn't a .conf file */

#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug)
			cmn_err(CE_CONT, "\tfound existing device node (%s)\n",
			    ddi_get_name(dip));
#endif
		if (strlen(info->pd_vers1_name) > 0)
			(void) ndi_prop_update_string(DDI_DEV_T_NONE,
			    dip, PCM_DEV_MODEL, info->pd_vers1_name);

		ppd = (struct pcmcia_parent_private *)
		    ddi_get_parent_data(dip);

		pcmcia_sockets[info->pd_socket]->ls_dip[info->pd_function] =
		    dip;

		ppd->ppd_active = 1;

		if (ndi_devi_online(dip, 0) == NDI_FAILURE) {
			pcmcia_sockets[info->pd_socket]-> \
			    ls_dip[info->pd_function] = NULL;
			ppd->ppd_active = 0;
		}
	} else {

		char *dtype;

#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug)
			cmn_err(CE_CONT, "pcmcia: create child [%s](%d): %s\n",
			    info->pd_bind_name, info->pd_socket,
			    info->pd_generic_name);
#endif

		if (info->pd_flags & PCM_NAME_GENERIC)
			name = info->pd_generic_name;
		else
			name = info->pd_bind_name;

		if (ndi_devi_alloc(pdip, name, (pnode_t)DEVI_SID_NODEID,
		    &dip) !=
		    NDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "pcmcia: unable to create device [%s](%d)\n",
			    name, info->pd_socket);
			return;
		}
		/*
		 * construct the "compatible" property if the device
		 * has a generic name
		 */
		pcmcia_add_compatible(dip, info);

		ppd = kmem_zalloc(sizeof (struct pcmcia_parent_private),
		    KM_SLEEP);

		ppd->ppd_socket = info->pd_socket;
		ppd->ppd_function = info->pd_function;

		/*
		 * add the "socket" property
		 * the value of this property contains the logical PCMCIA
		 * socket number the device has been inserted in, along
		 * with the function # if the device is part of a
		 * multi-function device.
		 */
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    PCM_DEV_SOCKET, unit);

		if (info->pd_flags & PCM_MULTI_FUNCTION)
			ppd->ppd_flags |= PPD_CARD_MULTI;

		/*
		 * determine all the properties we need for PPD
		 * then create the properties
		 */
		/* socket is unique */
		pcmcia_find_regs(dip, info, ppd);

		ppd->ppd_intr = pcmcia_need_intr(unit, info);

		if (ppd->ppd_nreg > 0)
			(void) ddi_prop_update_int_array(DDI_DEV_T_NONE, dip,
			    "reg", (int *)ppd->ppd_reg, ppd->ppd_nreg *
			    sizeof (struct pcm_regs) / sizeof (int));
		if (ppd->ppd_intr) {
			(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip,
			    "interrupts", ppd->ppd_intr);
			ppd->ppd_intrspec =
			    kmem_zalloc(sizeof (struct intrspec), KM_SLEEP);
		}

		/* set parent private - our own format */
		ddi_set_parent_data(dip, (caddr_t)ppd);

		/* init the device type */
		if (info->pd_type >= 0 &&
		    info->pd_type < (sizeof (pcmcia_dev_type) /
		    (sizeof (char *))))
			dtype = pcmcia_dev_type[info->pd_type];
		else
			dtype = "unknown";

		if (strlen(info->pd_vers1_name) > 0)
			(void) ndi_prop_update_string(DDI_DEV_T_NONE,
			    dip, PCM_DEV_MODEL, info->pd_vers1_name);

		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    PCM_DEVICETYPE, dtype);

		/* set PC Card as active and present in socket */
		pcmcia_sockets[info->pd_socket]->ls_dip[info->pd_function] =
		    dip;

		ppd->ppd_active = 1;

		/*
		 * We should not call ndi_devi_online here if
		 * pcmcia attach is in progress. This causes a deadlock.
		 */
		if (pcmcia_dip != dip) {
			if (ndi_devi_online_async(dip, 0)
			    != NDI_SUCCESS) {
				pcmcia_sockets[info->pd_socket]->\
				    ls_dip[info->pd_function] = NULL;
				pcmcia_ppd_free(ppd);
				(void) ndi_devi_free(dip);
				return;
			}
		}

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug)
		cmn_err(CE_CONT, "\tjust added \"active\" to %s in %d\n",
		    ddi_get_name(dip), info->pd_socket);
#endif
	}

	/*
	 * inform the event manager that a child was added
	 * to the device tree.
	 */
	pcm_event_manager(PCE_DEV_IDENT, unit, ddi_get_name(dip));

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug > 1) {
		pcmcia_dump_minors(dip);
	}
#endif
}

/*
 * free any allocated parent-private data
 */
static void
pcmcia_ppd_free(struct pcmcia_parent_private *ppd)
{
	size_t len;

	if (ppd->ppd_nreg != 0) {
		len = ppd->ppd_nreg * sizeof (uint32_t) * 3;
		kmem_free(ppd->ppd_reg, len);
		len = sizeof (struct pcm_regs) * ppd->ppd_nreg;
		kmem_free(ppd->ppd_assigned, len);
	}

	/*
	 * pcmcia only allocates 1 intrspec today
	 */
	if (ppd->ppd_intr != 0) {
		len = sizeof (struct intrspec) * ppd->ppd_intr;
		kmem_free(ppd->ppd_intrspec, len);
	}

	kmem_free(ppd, sizeof (*ppd));
}


/*
 * pcmcia_get_devinfo(socket)
 *	entry point to allow finding the device info structure
 *	for a given logical socket.  Used by event manager
 */
dev_info_t *
pcmcia_get_devinfo(int socket)
{
	int func = CS_GET_FUNCTION_NUMBER(socket);
	socket = CS_GET_SOCKET_NUMBER(socket);
	if (pcmcia_sockets[socket])
		return (pcmcia_sockets[socket]->ls_dip[func]);
	return ((dev_info_t *)NULL);
}

/*
 * CSGetCookiesAndDip()
 *	get info needed by CS to setup soft interrupt handler and provide
 *		socket-specific adapter information
 */
static int
GetCookiesAndDip(sservice_t *serv)
{
	pcmcia_logical_socket_t *socket;
	csss_adapter_info_t *ai;
	int sock;

	sock = CS_GET_SOCKET_NUMBER(serv->get_cookies.socket);

	if (sock >= pcmcia_num_sockets ||
	    (int)serv->get_cookies.socket < 0)
		return (BAD_SOCKET);

	socket = pcmcia_sockets[sock];
	ai = &serv->get_cookies.adapter_info;
	serv->get_cookies.dip = socket->ls_adapter->pca_dip;
	serv->get_cookies.iblock = socket->ls_adapter->pca_iblock;
	serv->get_cookies.idevice = socket->ls_adapter->pca_idev;

	/*
	 * Setup the adapter info for Card Services
	 */
	(void) strcpy(ai->name, socket->ls_adapter->pca_name);
	ai->major = socket->ls_adapter->pca_module;
	ai->minor = socket->ls_adapter->pca_unit;
	ai->number = socket->ls_adapter->pca_number;
	ai->num_sockets = socket->ls_adapter->pca_numsockets;
	ai->first_socket = socket->ls_adapter->pca_first_socket;

	return (SUCCESS);
}

/*
 * Note:
 *	The following functions that start with 'SS'
 *	implement SocketServices interfaces.  They
 *	simply map the socket and/or window number to
 *	the adapter specific number based on the general
 *	value that CardServices uses.
 *
 *	See the descriptions in SocketServices for
 *	details.  Also refer to specific adapter drivers
 *	for implementation reference.
 */

static int
SSGetAdapter(get_adapter_t *adapter)
{
	int n;
	get_adapter_t info;

	adapter->state = (unsigned)0xFFFFFFFF;
	adapter->SCRouting = 0xFFFFFFFF;

	for (n = 0; n < pcmcia_num_adapters; n++) {
		GET_ADAPTER(pcmcia_adapters[n]->pca_if,
		    pcmcia_adapters[n]->pca_dip, &info);
		adapter->state &= info.state;
		adapter->SCRouting &= info.SCRouting;
	}

	return (SUCCESS);
}

static int
SSGetPage(get_page_t *page)
{
	pcmcia_logical_window_t *window;
	get_page_t newpage;
	int retval, win;

	if (page->window > pcmcia_num_windows) {
		return (BAD_WINDOW);
	}

	window = pcmcia_windows[page->window];
	newpage = *page;
	win = newpage.window = window->lw_window; /* real window */

	retval = GET_PAGE(window->lw_if, window->lw_adapter->pca_dip,
	    &newpage);
	if (retval == SUCCESS) {
		*page = newpage;
		page->window = win;
	}
	return (retval);
}

static int
SSGetSocket(get_socket_t *socket)
{
	int retval, sock;
	get_socket_t newsocket;
	pcmcia_logical_socket_t *sockp;

	sock = socket->socket;
	if (sock > pcmcia_num_sockets ||
	    (sockp = pcmcia_sockets[sock]) == NULL) {
		return (BAD_SOCKET);
	}

	newsocket = *socket;
	newsocket.socket = sockp->ls_socket;
	retval = GET_SOCKET(sockp->ls_if, sockp->ls_adapter->pca_dip,
	    &newsocket);
	if (retval == SUCCESS) {
		newsocket.VccLevel = pcmcia_map_power_get(sockp->ls_adapter,
		    newsocket.VccLevel,
		    VCC);
		newsocket.Vpp1Level = pcmcia_map_power_get(sockp->ls_adapter,
		    newsocket.Vpp1Level,
		    VPP1);
		newsocket.Vpp2Level = pcmcia_map_power_get(sockp->ls_adapter,
		    newsocket.Vpp2Level,
		    VPP2);
		*socket = newsocket;
		socket->socket = sock;
	}

	return (retval);
}

static int
SSGetStatus(get_ss_status_t *status)
{
	get_ss_status_t newstat;
	int sock, retval;
	pcmcia_logical_socket_t *sockp;

	sock = status->socket;
	if (sock > pcmcia_num_sockets ||
	    (sockp = pcmcia_sockets[sock]) == NULL) {
		return (BAD_SOCKET);
	}

	newstat = *status;
	newstat.socket = sockp->ls_socket;
	retval = GET_STATUS(sockp->ls_if, sockp->ls_adapter->pca_dip,
	    &newstat);
	if (retval == SUCCESS) {
		*status = newstat;
		status->socket = sock;
	}

	return (retval);
}

static int
SSGetWindow(get_window_t *window)
{
	int win, retval;
	get_window_t newwin;
	pcmcia_logical_window_t *winp;

	win = window->window;
	winp = pcmcia_windows[win];
	newwin = *window;
	newwin.window = winp->lw_window;

	retval = GET_WINDOW(winp->lw_if, winp->lw_adapter->pca_dip,
	    &newwin);
	if (retval == SUCCESS) {
		newwin.socket = winp->lw_socket;
		newwin.window = win;
		*window = newwin;
	}
	return (retval);
}

/*
 * SSInquireAdapter()
 *	Get the capabilities of the "generic" adapter
 *	we are exporting to CS.
 */
static int
SSInquireAdapter(inquire_adapter_t *adapter)
{
	adapter->NumSockets = pcmcia_num_sockets;
	adapter->NumWindows = pcmcia_num_windows;
	adapter->NumEDCs = 0;
	/*
	 * notes: Adapter Capabilities are going to be difficult to
	 * determine with reliability.	Fortunately, most of them
	 * don't matter under Solaris or can be handled transparently
	 */
	adapter->AdpCaps = 0;	/* need to fix these */
	/*
	 * interrupts need a little work.  For x86, the valid IRQs will
	 * be restricted to those that the system has exported to the nexus.
	 * for SPARC, it will be the DoRight values.
	 */
	adapter->ActiveHigh = 0;
	adapter->ActiveLow = 0;
	adapter->power_entry = pcmcia_power_table; /* until we resolve this */
	adapter->NumPower = pcmcia_num_power;
	return (SUCCESS);
}

static int
SSInquireSocket(inquire_socket_t *socket)
{
	int retval, sock;
	inquire_socket_t newsocket;
	pcmcia_logical_socket_t *sockp;

	sock = socket->socket;
	if (sock > pcmcia_num_sockets ||
	    (sockp = pcmcia_sockets[sock]) == NULL)
		return (BAD_SOCKET);
	newsocket = *socket;
	newsocket.socket = sockp->ls_socket;
	retval = INQUIRE_SOCKET(sockp->ls_if, sockp->ls_adapter->pca_dip,
	    &newsocket);
	if (retval == SUCCESS) {
		*socket = newsocket;
		socket->socket = sock;
	}
	return (retval);
}

static int
SSInquireWindow(inquire_window_t *window)
{
	int retval, win;
	pcmcia_logical_window_t *winp;
	inquire_window_t newwin;
	int slide;

	win = window->window;
	if (win > pcmcia_num_windows)
		return (BAD_WINDOW);

	winp = pcmcia_windows[win];
	newwin = *window;
	newwin.window = winp->lw_window;
	retval = INQUIRE_WINDOW(winp->lw_if, winp->lw_adapter->pca_dip,
	    &newwin);
#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug > 1)
			cmn_err(CE_CONT, "SSInquireWindow: win=%d, pwin=%d\n",
			    win, newwin.window);
#endif
	if (retval == SUCCESS) {
		*window = newwin;
		/* just in case */
		window->iowin_char.IOWndCaps &= ~WC_BASE;
		slide = winp->lw_adapter->pca_first_socket;
		/*
		 * note that sockets are relative to the adapter.
		 * we have to adjust the bits to show a logical
		 * version.
		 */

		pcm_fix_bits(newwin.Sockets, window->Sockets, slide, 0);

#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug > 1) {
			cmn_err(CE_CONT, "iw: orig bits=%x, new bits=%x\n",
			    (int)*(uint32_t *)newwin.Sockets,
			    (int)*(uint32_t *)window->Sockets);
			cmn_err(CE_CONT, "\t%x.%x.%x\n", window->WndCaps,
			    window->mem_win_char.MemWndCaps,
			    window->mem_win_char.MinSize);
		}
#endif
		window->window = win;
	}
	return (retval);
}

static int
SSResetSocket(int socket, int mode)
{
	pcmcia_logical_socket_t *sockp;

	if (socket >= pcmcia_num_sockets ||
	    (sockp = pcmcia_sockets[socket]) == NULL)
		return (BAD_SOCKET);

	return (RESET_SOCKET(sockp->ls_if, sockp->ls_adapter->pca_dip,
	    sockp->ls_socket, mode));
}

static int
SSSetPage(set_page_t *page)
{
	int window, retval;
	set_page_t newpage;
	pcmcia_logical_window_t *winp;

	window = page->window;
	if (window > pcmcia_num_windows) {
#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug > 1)
			cmn_err(CE_CONT, "SSSetPage: window=%d (of %d)\n",
			    window, pcmcia_num_windows);
#endif
		return (BAD_WINDOW);
	}

	winp = pcmcia_windows[window];
	newpage = *page;
	newpage.window = winp->lw_window;
	retval = SET_PAGE(winp->lw_if, winp->lw_adapter->pca_dip, &newpage);
	if (retval == SUCCESS) {
		newpage.window = window;
		*page = newpage;
	}
#if defined(PCMCIA_DEBUG)
	if ((pcmcia_debug > 1) && retval != SUCCESS)
		cmn_err(CE_CONT, "\tSetPage: returning error %x\n", retval);
#endif
	return (retval);
}

static int
SSSetWindow(set_window_t *win)
{
	int socket, window, retval, func;
	set_window_t newwin;
	pcmcia_logical_window_t *winp;
	pcmcia_logical_socket_t *sockp;

	window = win->window;
	if (window > pcmcia_num_windows)
		return (BAD_WINDOW);

	socket = CS_GET_SOCKET_NUMBER(win->socket);
	func = CS_GET_FUNCTION_NUMBER(win->socket);

	if (socket > pcmcia_num_sockets ||
	    (sockp = pcmcia_sockets[socket]) == NULL) {
		return (BAD_SOCKET);
	}

	winp = pcmcia_windows[window];
	winp->lw_socket = win->socket; /* reverse map */
	newwin = *win;
	newwin.window = winp->lw_window;
	newwin.socket = sockp->ls_socket;
	newwin.child = sockp->ls_dip[func]; /* so we carry the dip around */

	retval = SET_WINDOW(winp->lw_if, winp->lw_adapter->pca_dip, &newwin);
	if (retval == SUCCESS) {
		newwin.window = window;
		newwin.socket = winp->lw_socket;
		*win = newwin;
	}
	return (retval);
}

static int
SSSetSocket(set_socket_t *socket)
{
	int sock, retval;
	pcmcia_logical_socket_t *sockp;
	set_socket_t newsock;

	sock = socket->socket;
	if (sock > pcmcia_num_sockets ||
	    (sockp = pcmcia_sockets[sock]) == NULL) {
		return (BAD_SOCKET);
	}

	newsock = *socket;
	/* note: we force CS to always get insert/removal events */
	sockp->ls_cs_events = pcm_mapevents(newsock.SCIntMask) |
	    PCE_E2M(PCE_CARD_INSERT) | PCE_E2M(PCE_CARD_REMOVAL) |
	    PCE_E2M(PCE_PM_SUSPEND);
#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug > 1)
		cmn_err(CE_CONT,
		    "SetSocket: SCIntMask = %x\n", newsock.SCIntMask);
#endif
	newsock.socket = sockp->ls_socket;
	newsock.VccLevel = pcmcia_map_power_set(sockp->ls_adapter,
	    newsock.VccLevel, VCC);
	newsock.Vpp1Level = pcmcia_map_power_set(sockp->ls_adapter,
	    newsock.Vpp1Level, VPP1);
	newsock.Vpp2Level = pcmcia_map_power_set(sockp->ls_adapter,
	    newsock.Vpp2Level, VPP2);
	retval = SET_SOCKET(sockp->ls_if, sockp->ls_adapter->pca_dip,
	    &newsock);
	if (retval == SUCCESS) {
		newsock.socket = sock;
		newsock.VccLevel = pcmcia_map_power_get(sockp->ls_adapter,
		    newsock.VccLevel,
		    VCC);
		newsock.Vpp1Level = pcmcia_map_power_get(sockp->ls_adapter,
		    newsock.Vpp1Level,
		    VPP1);
		newsock.Vpp2Level = pcmcia_map_power_get(sockp->ls_adapter,
		    newsock.Vpp2Level,
		    VPP2);
		*socket = newsock;
		if (socket->IREQRouting & IRQ_ENABLE) {
			sockp->ls_flags |= PCS_IRQ_ENABLED;
		} else {
			sockp->ls_flags &= ~PCS_IRQ_ENABLED;
		}
	}
	return (retval);
}

/*
 * SSSetIRQHandler()
 *	arrange for IRQ to be allocated if appropriate and always
 *	arrange that PC Card interrupt handlers get called.
 */
static int
SSSetIRQHandler(set_irq_handler_t *handler)
{
	int sock, retval, func;
	pcmcia_logical_socket_t *sockp;
	struct pcmcia_parent_private *ppd;
	dev_info_t *dip;
	ddi_iblock_cookie_t iblk;
	ddi_idevice_cookie_t idev;

	sock = CS_GET_SOCKET_NUMBER(handler->socket);
	func = CS_GET_FUNCTION_NUMBER(handler->socket);
	if (sock > pcmcia_num_sockets ||
	    (sockp = pcmcia_sockets[sock]) == NULL) {
		return (BAD_SOCKET);
	}
#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {

		cmn_err(CE_CONT, "SSSetIRQHandler: socket=%x, function=%x\n",
		    sock, func);
		cmn_err(CE_CONT, "\thandler(%p): socket=%x, irq=%x, id=%x\n",
		    (void *)handler->handler, handler->socket, handler->irq,
		    handler->handler_id);
	}
#endif
	dip = sockp->ls_dip[func];

	ppd = (struct pcmcia_parent_private *)ddi_get_parent_data(dip);

	handler->iblk_cookie = &iblk;
	handler->idev_cookie = &idev;

	retval = ddi_add_intr(dip, 0, handler->iblk_cookie,
	    handler->idev_cookie,
	    (uint32_t(*)(caddr_t)) handler->handler,
	    handler->arg1);

	if (retval == DDI_SUCCESS) {
		handler->iblk_cookie = &sockp->ls_iblk;
		handler->idev_cookie = &sockp->ls_idev;
		handler->irq = ppd->ppd_intrspec->intrspec_vec;
		retval = SUCCESS;
	} else {
		retval = sockp->ls_error;
	}
	return (retval);
}

/*
 * SSClearIRQHandler()
 *	Arrange to have the interrupt handler specified removed
 *	from the interrupt list.
 */
static int
SSClearIRQHandler(clear_irq_handler_t *handler)
{
	int sock, func;
	pcmcia_logical_socket_t *sockp;
	dev_info_t *dip;

	sock = CS_GET_SOCKET_NUMBER(handler->socket);
	func = CS_GET_FUNCTION_NUMBER(handler->socket);

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {

		cmn_err(CE_CONT,
		    "SSClearIRQHandler: socket=%x, function=%x\n",
		    sock, func);
		cmn_err(CE_CONT,
		    "\thandler(%p): socket=%x, id=%x\n",
		    (void *)handler, handler->socket,
		    handler->handler_id);
	}
#endif

	if (sock > pcmcia_num_sockets ||
	    (sockp = pcmcia_sockets[sock]) == NULL) {
		return (BAD_SOCKET);
	}
	dip = sockp->ls_dip[func];
	if (dip) {
		ddi_remove_intr(dip, 0, NULL);
		return (SUCCESS);
	}
	return (BAD_SOCKET);
}


/*
 * pcm_pathname()
 *	make a partial path from dip.
 *	used to mknods relative to /devices/pcmcia/
 *
 * XXX - we now use ddi_get_name_addr to get the "address" portion
 *	of the name; that way, we only have to modify the name creation
 *	algorithm in one place
 */
static void
pcm_pathname(dev_info_t *dip, char *name, char *path)
{
	(void) sprintf(path, "%s@%s:%s", ddi_node_name(dip),
	    ddi_get_name_addr(dip), name);
}

/*
 * pcmcia_create_device()
 *	create the /devices entries for the driver
 *	it is assumed that the PC Card driver will do a
 *	RegisterClient for each subdevice.
 *	The device type string is encoded here to match
 *	the standardized names when possible.
 * XXX - note that we may need to provide a way for the
 *	caller to specify the complete name string that
 *	we pass to ddi_set_name_addr
 */
static int
pcmcia_create_device(ss_make_device_node_t *init)
{
	int err = SUCCESS;
	struct pcm_make_dev device;
	struct dev_ops *ops;
	major_t major;

	/*
	 * Now that we have the name, create it.
	 */

	bzero(&device, sizeof (device));
	if (init->flags & SS_CSINITDEV_CREATE_DEVICE) {
		if ((err = ddi_create_minor_node(init->dip,
		    init->name,
		    init->spec_type,
		    init->minor_num,
		    init->node_type,
		    0)) != DDI_SUCCESS) {
#if defined(PCMCIA_DEBUG)
			if (pcmcia_debug)
				cmn_err(CE_CONT,
				    "pcmcia_create_device: failed "
				    "create\n");
#endif
			return (BAD_ATTRIBUTE);
		}

		major = ddi_driver_major(init->dip);
		ops = ddi_get_driver(init->dip);
		LOCK_DEV_OPS(&devnamesp[major].dn_lock);
		INCR_DEV_OPS_REF(ops);
		(void) ddi_pathname(init->dip, device.path);
		DECR_DEV_OPS_REF(ops);
		UNLOCK_DEV_OPS(&devnamesp[major].dn_lock);
		(void) sprintf(device.path + strlen(device.path), ":%s",
		    init->name);

		(void) strcpy(device.driver, ddi_binding_name(init->dip));
#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug)
			cmn_err(CE_CONT,
			    "pcmcia_create_device: created %s "
			    "from %s [%s]\n",
			    device.path, init->name, device.driver);
#endif
		device.dev =
		    makedevice(ddi_driver_major(init->dip), init->minor_num);
		device.flags |= (init->flags & SS_CSINITDEV_MORE_DEVICES) ?
		    PCM_EVENT_MORE : 0;
		device.type = init->spec_type;
		device.op = SS_CSINITDEV_CREATE_DEVICE;
		device.socket = ddi_getprop(DDI_DEV_T_ANY, init->dip,
		    DDI_PROP_CANSLEEP, PCM_DEV_SOCKET,
		    -1);
	} else if (init->flags & SS_CSINITDEV_REMOVE_DEVICE) {
		device.op = SS_CSINITDEV_REMOVE_DEVICE;
		device.socket = ddi_getprop(DDI_DEV_T_ANY, init->dip,
		    DDI_PROP_CANSLEEP, PCM_DEV_SOCKET,
		    -1);
		if (init->name != NULL)
			(void) strcpy(device.path, init->name);
		device.dev = makedevice(ddi_driver_major(init->dip), 0);
		ddi_remove_minor_node(init->dip, init->name);
	}

	/*
	 *	we send an event for ALL devices created.
	 *	To do otherwise ties us to using drvconfig
	 *	forever.  There are relatively few devices
	 *	ever created so no need to do otherwise.
	 *	The existence of the event manager must never
	 *	be visible to a PCMCIA device driver.
	 */
	pcm_event_manager(PCE_INIT_DEV, device.socket, &device);

	return (err);
}

/*
 * pcmcia_get_minors()
 *	We need to traverse the minor node list of the
 *	dip if there are any.  This takes two passes;
 *	one to get the count and buffer size and the
 *	other to actually copy the data into the buffer.
 *	The framework requires that the dip be locked
 *	during this time to avoid breakage as well as the
 *	driver being locked.
 */
int
pcmcia_get_minors(dev_info_t *dip, struct pcm_make_dev **minors)
{
	int circ;
	int count = 0;
	struct ddi_minor_data *dp;
	struct pcm_make_dev *md;
	int socket;
	major_t major;
	struct dev_ops *ops;

	socket = ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    PCM_DEV_SOCKET, -1);
	ndi_devi_enter(dip, &circ);
	if (DEVI(dip)->devi_minor != (struct ddi_minor_data *)NULL) {
		for (dp = DEVI(dip)->devi_minor;
		    dp != (struct ddi_minor_data *)NULL;
		    dp = dp->next) {
			count++; /* have one more */
		}
		/* we now know how many nodes to allocate */
		md = kmem_zalloc(count * sizeof (struct pcm_make_dev),
		    KM_NOSLEEP);
		if (md != NULL) {
			*minors = md;
			for (dp = DEVI(dip)->devi_minor;
			    dp != (struct ddi_minor_data *)NULL;
			    dp = dp->next, md++) {
#if defined(PCMCIA_DEBUG)
				if (pcmcia_debug > 1) {
					cmn_err(CE_CONT,
					    "pcmcia_get_minors: name=%s,"
					    "socket=%d, stype=%x, "
					    "ntype=%s, dev_t=%x",
					    dp->ddm_name,
					    socket,
					    dp->ddm_spec_type,
					    dp->ddm_node_type,
					    (int)dp->ddm_dev);
					cmn_err(CE_CONT,
					    "\tbind name = %s\n",
					    ddi_binding_name(dip));
				}
#endif
				md->socket = socket;
				md->op = SS_CSINITDEV_CREATE_DEVICE;
				md->dev = dp->ddm_dev;
				md->type = dp->ddm_spec_type;
				(void) strcpy(md->driver,
				    ddi_binding_name(dip));
				major = ddi_driver_major(dip);
				ops = ddi_get_driver(dip);
				LOCK_DEV_OPS(&devnamesp[major].dn_lock);
				pcm_pathname(dip, dp->ddm_name, md->path);
				INCR_DEV_OPS_REF(ops);
				(void) ddi_pathname(dip, md->path);
				DECR_DEV_OPS_REF(ops);
				UNLOCK_DEV_OPS(&devnamesp[major].dn_lock);
				(void) sprintf(md->path + strlen(md->path),
				    ":%s", dp->ddm_name);
				if (dp->next == NULL)
					/* no more */
					md->flags |= PCM_EVENT_MORE;
			}
		} else {
			count = 0;
		}
	}
	ndi_devi_exit(dip, circ);
	return (count);
}

#if defined(PCMCIA_DEBUG)
static char *ddmtypes[] = { "minor", "alias", "default", "internal" };

static void
pcmcia_dump_minors(dev_info_t *dip)
{
	int circ;
	int count = 0;
	struct ddi_minor_data *dp;
	int unit, major;
	dev_info_t *np;

	unit = ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    PCM_DEV_SOCKET, -1);
	cmn_err(CE_CONT,
	    "pcmcia_dump_minors: dip=%p, socket=%d\n", (void *)dip, unit);

	major = ddi_driver_major(dip);
	if (major != -1) {
		for (np = devnamesp[major].dn_head; np != NULL;
		    np = (dev_info_t *)DEVI(np)->devi_next) {
			char *cf2 = "";
			char *cur = "";
			if (i_ddi_node_state(np) == DS_READY)
				cf2 = "DS_READY";
			if (np == dip)
				cur = "CUR";
			cmn_err(CE_CONT, "\tsibs: %s %s %s\n",
			    ddi_binding_name(np), cf2, cur);

			ndi_devi_enter(np, &circ);
			if (DEVI(np)->devi_minor !=
			    (struct ddi_minor_data *)NULL) {
				for (dp = DEVI(np)->devi_minor;
				    dp != (struct ddi_minor_data *)NULL;
				    dp = dp->next) {
					count++; /* have one more */
				}
				for (dp = DEVI(dip)->devi_minor;
				    dp != (struct ddi_minor_data *)NULL;
				    dp = dp->next) {
					cmn_err(CE_CONT, "\ttype=%s, name=%s,"
					    "socket=%d, stype=%x, "
					    "ntype=%s, dev_t=%x",
					    ddmtypes[dp->type],
					    dp->ddm_name,
					    unit,
					    dp->ddm_spec_type,
					    dp->ddm_node_type,
					    (int)dp->ddm_dev);
					cmn_err(CE_CONT, "\tbind name = %s\n",
					    ddi_binding_name(np));
				}
			}
			ndi_devi_exit(np, circ);
		}
	}
}
#endif

/*
 * experimental merging code
 * what are the things that we should merge on?
 *	match something by name in the "compatible" property
 *	restrict to a specific "socket"
 *	restrict to a specific "instance"
 */
/*ARGSUSED*/
static int
pcmcia_merge_conf(dev_info_t *dip)
{
	return (0);		/* merge failed */
}

/*
 * pcmcia_mfc_intr()
 *	Multifunction Card interrupt handler
 *	While some adapters share interrupts at the lowest
 *	level, some can't.  In order to be consistent, we
 *	split multifunction cards out with this intercept and
 *	allow the low level to do what is best for it.
 *	the arg is a pcmcia_socket structure and all interrupts
 *	are per-socket in this case.  We also have the option
 *	to optimize if the cards support it.  It also means
 *	that we can use the INTRACK mode if it proves desirable
 */
/*ARGSUSED*/
static uint32_t
pcmcia_mfc_intr(caddr_t arg1, caddr_t arg2)
{
	pcmcia_logical_socket_t *sockp;
	inthandler_t *intr, *first;
	int done, result;

	sockp = (pcmcia_logical_socket_t *)arg1;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug > 1) {
		cmn_err(CE_CONT, "pcmcia_mfc_intr sockp=%p"
		    " ls_inthandlers=%p\n"
		    "\t ls_flags=0x%x PCS_IRQ_ENABLED=0x%x \n",
		    (void *) sockp, (void *) sockp->ls_inthandlers,
		    sockp->ls_flags, PCS_IRQ_ENABLED);
	}
#endif

	if (sockp == NULL || sockp->ls_inthandlers == NULL ||
	    !(sockp->ls_flags & PCS_IRQ_ENABLED))
		return (DDI_INTR_UNCLAIMED);

	mutex_enter(&sockp->ls_ilock);
	for (done = 0, result = 0, first = intr = sockp->ls_inthandlers;
	    intr != NULL && !done; intr = intr->next) {
		result |= intr->intr(intr->arg1, intr->arg2);
		if (intr->next == first)
			done++;
	}
	if (intr == NULL) {
		cmn_err(CE_WARN, "pcmcia_mfc_intr: bad MFC handler list");
	}
	if (sockp->ls_inthandlers)
		sockp->ls_inthandlers = sockp->ls_inthandlers->next;

	mutex_exit(&sockp->ls_ilock);
	return (result ? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
}

/*
 * pcmcia_power(dip)
 *	control power for nexus and children
 */
int
pcmcia_power(dev_info_t *dip, int component, int level)
{
#if 0
	anp_t *anp = (anp_t *)ddi_get_driver_private(dip);
	int i;
	/*
	 * for now, we only have one component.  Should there be one per-socket?
	 * the level is only one (power on or off)
	 */
	if (component != 0 || level > 1)
		return (DDI_FAILURE);

	for (i = 0; i < pcic->pc_numsockets; i++) {
		if (pcic->pc_callback)
			PC_CALLBACK(dip, pcic->pc_cb_arg,
			    (level == 0) ? PCE_PM_SUSPEND :
			    PCE_PM_RESUME,
			    i);
	}
#else
	cmn_err(CE_WARN, "pcmcia_power: component=%d, level=%d for %s",
	    component, level, ddi_get_name_addr(dip));
	return (DDI_FAILURE);
#endif
}

void
pcmcia_begin_resume(dev_info_t *dip)
{
	int i;
	struct pcmcia_adapter *adapt = NULL;
	for (i = 0; i < pcmcia_num_adapters; i++) {
		if (pcmcia_adapters[i]->pca_dip == dip) {
			adapt = pcmcia_adapters[i];
			break;
		}
	}
	if (adapt == NULL)
		return;

	for (i = 0; i < adapt->pca_numsockets; i++) {
		int s;
		s = adapt->pca_first_socket + i;
		if (pcmcia_sockets[s]->ls_flags & PCS_SUSPENDED) {
			if (pcmcia_sockets[s]->ls_flags &
			    (1 << PCE_PM_RESUME)) {
				(void) cs_event(PCE_PM_RESUME, s, 0);
				pcm_event_manager(PCE_PM_RESUME, s, NULL);
			}
			(void) cs_event(PCE_CARD_REMOVAL, s, 0);
			pcm_event_manager(PCE_CARD_REMOVAL, s, NULL);
		}
	}
}

/*
 * mark a cardbus card as "suspended" in the pcmcia module
 */
void
pcmcia_cb_suspended(int socket)
{
	mutex_enter(&pcmcia_global_lock);
	pcmcia_sockets[socket]->ls_flags |= PCS_SUSPENDED;
	mutex_exit(&pcmcia_global_lock);

}

/*
 * mark a cardbus card as "resumed" in the pcmcia module
 */
void
pcmcia_cb_resumed(int socket)
{
	if (pcmcia_sockets[socket]->ls_flags & PCS_SUSPENDED) {
		mutex_enter(&pcmcia_global_lock);
		pcmcia_sockets[socket]->ls_flags &= ~PCS_SUSPENDED;
		cv_broadcast(&pcmcia_condvar);
		mutex_exit(&pcmcia_global_lock);
#ifdef PCMCIA_DEBUG
		if (pcmcia_debug) {
			cmn_err(CE_NOTE, "pcmcia_cb_resume RESUMED");
		}
#endif
	}

}

void
pcmcia_wait_insert(dev_info_t *dip)
{
	int i, f, tries, done;
	struct pcmcia_adapter *adapt = NULL;
	anp_t *nexus;

	for (i = 0; i < pcmcia_num_adapters; i++) {
		if (pcmcia_adapters[i]->pca_dip == dip) {
			adapt = pcmcia_adapters[i];
			break;
		}
	}
	if (adapt == NULL)
		return;

	for (tries = adapt->pca_numsockets * 10; tries > 0; tries--) {
		done = 1;
		mutex_enter(&pcmcia_global_lock);
		for (i = 0; i < adapt->pca_numsockets; i++) {
			int s;
			s = adapt->pca_first_socket + i;
			for (f = 0; f < PCMCIA_MAX_FUNCTIONS; f++)
				if (pcmcia_sockets[s] &&
				    pcmcia_sockets[s]->ls_flags &
				    PCS_SUSPENDED) {

#ifdef PCMCIA_DEBUG
					if (pcmcia_debug) {
						cmn_err(CE_NOTE,
						    "pcmcia_wait_insert: "
						    "socket in SUSPENDED "
						    "state");
					}
#endif
					done = 0;
					break;
				}
		}
		if (!done) {
			(void) cv_reltimedwait(&pcmcia_condvar,
			    &pcmcia_global_lock, drv_usectohz(100000),
			    TR_CLOCK_TICK);
		} else {
			tries = 0;
		}
		mutex_exit(&pcmcia_global_lock);
	}

	if (tries == 0) {
		cmn_err(CE_NOTE, "pcmcia_wait_insert timed out");
	}

	nexus = (anp_t *)ddi_get_driver_private(dip);
	pcmcia_find_cards(nexus);
}

int
pcmcia_map_reg(dev_info_t *pdip, dev_info_t *dip, ra_return_t *ra,
		uint32_t state, caddr_t *base,
		ddi_acc_handle_t *handle, ddi_device_acc_attr_t *attrib,
		uint32_t req_base)
{
	struct pcmcia_parent_private *ppd;
	int rnum = 0, type = PCMCIA_MAP_MEM;
	ddi_map_req_t mr;
	ddi_acc_hdl_t *hp;
	int result;
	struct regspec *reg;
	ddi_device_acc_attr_t attr;

	if (dip != NULL) {
		ppd = (struct pcmcia_parent_private *)ddi_get_parent_data(dip);
		if (ppd == NULL)
			return (DDI_FAILURE);
		for (rnum = 1; rnum < ppd->ppd_nreg; rnum++) {
			struct pcm_regs *p;
			p = &ppd->ppd_reg[rnum];
			if (state & WS_IO) {
				/* need I/O */
				type = PCMCIA_MAP_IO;
				/*
				 * We want to find an IO regspec. When we
				 *	find one, it either has to match
				 *	the caller's requested base address
				 *	or it has to be relocatable.
				 * We match on the requested base address
				 *	rather than the allocated base
				 *	address so that we handle the case
				 *	of adapters that have IO window base
				 *	relocation registers.
				 */
				if ((p->phys_hi &
				    PC_REG_SPACE(PC_REG_SPACE_IO)) &&
				    ((req_base == p->phys_lo) ||
				    !(p->phys_hi & PC_REG_RELOC(1))))
					break;
			} else {
				/* need memory */
				type = PCMCIA_MAP_MEM;
				if (p->phys_hi &
				    PC_REG_SPACE(PC_REG_SPACE_MEMORY|
				    PC_REG_SPACE_ATTRIBUTE))
					break;
			}
		}
		if (rnum >= ppd->ppd_nreg)
			return (DDI_FAILURE);
	} else if (state & WS_IO) {
		return (DDI_FAILURE);
	}

	reg = kmem_zalloc(sizeof (pci_regspec_t), KM_SLEEP);
	reg = pcmcia_cons_regspec(pdip, type, (uchar_t *)reg, ra);

	if (attrib == NULL ||
	    attrib->devacc_attr_version != DDI_DEVICE_ATTR_V0) {
		attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
		attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
		attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	} else {
		attr = *attrib;
	}
	/*
	 * Allocate and initialize the common elements of data access handle.
	 */
	*handle = impl_acc_hdl_alloc(KM_SLEEP, NULL);
	hp = impl_acc_hdl_get(*handle);
	hp->ah_vers = VERS_ACCHDL;
	hp->ah_dip = dip != NULL ? dip : pdip;
	hp->ah_rnumber = rnum;
	hp->ah_offset = 0;
	hp->ah_len = ra->ra_len;
	hp->ah_acc = attr;

	/*
	 * Set up the mapping request and call to parent.
	 */
	mr.map_op = DDI_MO_MAP_LOCKED;
	mr.map_type = DDI_MT_REGSPEC;
	mr.map_obj.rp = reg;
	mr.map_prot = PROT_READ | PROT_WRITE;
	mr.map_flags = DDI_MF_KERNEL_MAPPING;
	mr.map_handlep = hp;
	mr.map_vers = DDI_MAP_VERSION;

	result = ddi_map(pdip, &mr, 0, ra->ra_len, base);
	if (result != DDI_SUCCESS) {
		impl_acc_hdl_free(*handle);
		*handle = (ddi_acc_handle_t)NULL;
	} else {
		hp->ah_addr = *base;
		if (mr.map_op == DDI_MO_UNMAP)
			ra = NULL;
		if (dip != NULL)
			pcmcia_set_assigned(dip, rnum, ra);
	}

	kmem_free(reg, sizeof (pci_regspec_t));

	return (result);
}

struct pcmcia_adapter *
pcmcia_get_adapter(dev_info_t *dip)
{
	int i;

	for (i = 0; i < pcmcia_num_adapters; i++) {
		if (pcmcia_adapters[i] &&
		    pcmcia_adapters[i]->pca_dip == dip) {
			return (pcmcia_adapters[i]);
		}
	}
	return (NULL);
}


void
pcmcia_set_assigned(dev_info_t *dip, int rnum, ra_return_t *ret)
{
	struct pcmcia_parent_private *ppd;
	struct pcm_regs *reg, *assign;

	ppd = (struct pcmcia_parent_private *)ddi_get_parent_data(dip);
	if (ppd) {
		reg = &ppd->ppd_reg[rnum];
		assign = &ppd->ppd_assigned[rnum];
		if (ret) {
			if (assign->phys_hi == 0) {
				assign->phys_hi = reg->phys_hi;
				assign->phys_lo = ret->ra_addr_lo;
				assign->phys_len = ret->ra_len;
			} else if (assign->phys_lo != ret->ra_addr_lo) {
#ifdef PCMCIA_DEBUG
				cmn_err(CE_WARN, "pcmcia: bad address:"
				    "%s=<%x,%x>",
				    ddi_get_name_addr(dip),
				    ret->ra_addr_lo, assign->phys_lo);
#else
				cmn_err(CE_WARN, "!pcmcia: bad address:"
				    "%s=<%x,%x>",
				    ddi_get_name_addr(dip),
				    ret->ra_addr_lo, (int)assign->phys_lo);
#endif
			}
			assign->phys_hi = PC_INCR_REFCNT(assign->phys_hi);
		} else {
			int i;
			assign->phys_hi = PC_DECR_REFCNT(assign->phys_hi);
			i = PC_GET_REG_REFCNT(assign->phys_hi);
			if (i == 0) {
				assign->phys_hi = 0;
				assign->phys_lo = 0;
				assign->phys_len = 0;
			}
		}
	}
}

int
pcmcia_alloc_mem(dev_info_t *dip, ndi_ra_request_t *req, ra_return_t *ret,
		dev_info_t **res_dip)
{
	return (pcmcia_ra_alloc(dip, req, ret, NDI_RA_TYPE_MEM, res_dip));
}

int
pcmcia_alloc_io(dev_info_t *dip, ndi_ra_request_t *req, ra_return_t *ret,
		dev_info_t **res_dip)
{
	return (pcmcia_ra_alloc(dip, req, ret, NDI_RA_TYPE_IO, res_dip));
}

static boolean_t
is_subtractv(dev_info_t *dip)
{
	uint_t  class;

	if (dip == NULL)
		return (B_FALSE);
	class = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_CANSLEEP|DDI_PROP_DONTPASS,
	    "class-code", 0xff);
	if (class == PPB_SUBTRACTIVE) {
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * pcmcia_pci_alloc()
 * 	allocate mem or I/O resource from the ancestor of the cardbus bridge.
 * 	First start from the parent node. If the parent is a subtractive
 * 	decode bridge and it does not have the requested resource, go up the
 * 	device tree to find the resource.
 *
 * 	dip		the parent node of the cardbus bridge
 *
 * 	res_dip		returns a pointer to the node from which the
 * 			resource is obtained. *res_dip could point to
 * 			the parent or a higher level ancestor. *res_dip
 * 			should be saved by the caller and later passed
 * 			to pcmcia_ra_free();
 */
int
pcmcia_pci_alloc(dev_info_t *dip, ndi_ra_request_t *req, ra_return_t *ret,
		char *type, dev_info_t **res_dip)
{
	uint64_t base = 0;
	uint64_t len = 0;

	if ((ndi_ra_alloc(dip, req, &base, &len, type, NDI_RA_PASS)
	    == NDI_FAILURE) ||
	    ((base >> 32) != 0)) {
		if (is_subtractv(dip)) {
			return (pcmcia_pci_alloc(ddi_get_parent(dip),
			    req, ret, type, res_dip));

		} else {
			ret->ra_addr_hi = 0;
			ret->ra_addr_lo = 0;
			ret->ra_len = 0;
			return (DDI_FAILURE);
		}
	}
	ret->ra_addr_lo =  base & 0xffffffff;
	ret->ra_addr_hi = 0;
	ret->ra_len = len;
	*res_dip = dip;
	return (DDI_SUCCESS);
}

int
pcmcia_ra_alloc(dev_info_t *dip, ndi_ra_request_t *req, ra_return_t *ret,
		char *type, dev_info_t **res_dip)
{
	uint64_t base = 0;
	uint64_t len = 0;

	/*
	 * Allocate space from busra resource list
	 * should not return an address > 32 bits
	 */

	if ((ndi_ra_alloc(dip, req, &base, &len, type, NDI_RA_PASS)
	    == NDI_FAILURE) ||
	    ((base >> 32) != 0)) {
		return (pcmcia_pci_alloc(ddi_get_parent(dip), req, ret,
		    type, res_dip));
	} else {
		ret->ra_addr_lo =  base & 0xffffffff;
		ret->ra_addr_hi = 0;
		ret->ra_len = len;
		*res_dip = dip;
		return (DDI_SUCCESS);
	}
}

int
pcmcia_free_mem(dev_info_t *dip, ra_return_t *ret)
{
	return (pcmcia_ra_free(dip, ret, NDI_RA_TYPE_MEM));
}

int
pcmcia_free_io(dev_info_t *dip, ra_return_t *ret)
{
	return (pcmcia_ra_free(dip, ret, NDI_RA_TYPE_IO));
}

int
pcmcia_ra_free(dev_info_t *dip, ra_return_t *ret, char *type)
{
	if (dip == (dev_info_t *)-1)
		return (DDI_FAILURE);
	if (ndi_ra_free(dip, (uint64_t)ret->ra_addr_lo, (uint64_t)ret->ra_len,
	    type, NDI_RA_PASS) == NDI_SUCCESS) {
		return (DDI_SUCCESS);
	} else {
		return (DDI_FAILURE);
	}
}


/*
 * when the low level device configuration does resource assignment
 * (devconf) then free the allocated resources so we can reassign them
 * later.  Walk the child list to get them.
 */
void
pcmcia_free_resources(dev_info_t *self)
{
	struct regspec *assigned;
	int len;
	dev_info_t *dip;
	int circ;

	ndi_devi_enter(self, &circ);
	/* do searches in compatible property order */
	for (dip = (dev_info_t *)DEVI(self)->devi_child;
	    dip != NULL;
	    dip = (dev_info_t *)DEVI(dip)->devi_sibling) {
		len = 0;
		if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS|DDI_PROP_CANSLEEP,
		    "assigned-addresses",
		    (caddr_t)&assigned,
		    &len) == DDI_PROP_SUCCESS) {
			/*
			 * if there are assigned resources at this point,
			 * then the OBP or devconf have assigned them and
			 * they need to be freed.
			 */
			kmem_free(assigned, len);
		}
	}
	ndi_devi_exit(self, circ);
}

/*
 * this is the equivalent of pcm_get_intr using ra_allocs.
 * returns -1 if failed, otherwise returns the allocated irq.
 * The input request, if less than zero it means not a specific
 * irq requested. If larger then 0 then we are requesting that specific
 * irq
 */
int
pcmcia_get_intr(dev_info_t *dip, int request)
{
	ndi_ra_request_t req;
	uint64_t base;
	uint64_t len;
	int err;

	bzero(&req, sizeof (req));
	base = 0;
	len = 1;
	if (request >= 0) {
		req.ra_flags = NDI_RA_ALLOC_SPECIFIED;
		req.ra_len = 1;
		req.ra_addr = (uint64_t)request;
	}

	req.ra_boundbase = 0;
	req.ra_boundlen = 0xffffffffUL;
	req.ra_flags |= NDI_RA_ALLOC_BOUNDED;

	err = ndi_ra_alloc(dip, &req, &base, &len, NDI_RA_TYPE_INTR,
	    NDI_RA_PASS);

	if (err == NDI_FAILURE) {
		return (-1);
	} else {
		return ((int)base);
	}
}


int
pcmcia_return_intr(dev_info_t *dip, int request)
{
	if ((ndi_ra_free(dip, (uint64_t)request, 1, NDI_RA_TYPE_INTR,
	    NDI_RA_PASS)) == NDI_SUCCESS) {
		return (0);
	} else
		return (-1);

}

#ifdef sparc

int
pcmcia_add_intr_impl(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{

	struct pcmcia_parent_private *ppd;
	pcmcia_logical_socket_t *sockp;
	int socket, ret;
	struct pcmcia_adapter *adapt;
	set_irq_handler_t handler;
	struct intrspec *pispec;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {
		cmn_err(CE_CONT,
		    "pcmcia_add_intr_impl() entered "
		    "dip=%p rdip=%p hdlp=%p \n",
		    (void *)dip, (void *)rdip, (void *)hdlp);
	}
#endif

	ppd = (struct pcmcia_parent_private *)ddi_get_parent_data(rdip);
	socket = ppd->ppd_socket;
	sockp = pcmcia_sockets[socket];
	adapt = sockp->ls_adapter;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {
		cmn_err(CE_CONT, "pcmcia_add_intr_impl()"
		    " ppd_flags=0X%x PPD_CARD_MULTI=0X%x\n"
		    " ppd_intrspec=%p ls_inthandlers=%p\n",
		    ppd->ppd_flags, PPD_CARD_MULTI,
		    (void *) ppd->ppd_intrspec,
		    (void *)sockp->ls_inthandlers);
	}
#endif

	/*
	 * calculate IPL level when we support multiple levels
	 */
	pispec = ppd->ppd_intrspec;
	if (pispec == NULL) {
		sockp->ls_error = BAD_IRQ;
		return (DDI_FAILURE);
	}

	handler.socket = sockp->ls_socket;
	handler.irq = 0;	/* default case */
	handler.handler = (f_tt *)hdlp->ih_cb_func;
	handler.arg1 = hdlp->ih_cb_arg1;
	handler.arg2 = hdlp->ih_cb_arg2;
	handler.handler_id = (uint32_t)(uintptr_t)rdip;

	/*
	 * check if multifunction and do the right thing
	 * we put an intercept in between the mfc handler and
	 * us so we can catch and process.  We might be able
	 * to optimize this depending on the card features
	 * (a future option).
	 */
	if (ppd->ppd_flags & PPD_CARD_MULTI) {
		inthandler_t *intr;
		/*
		 * note that the first function is a special
		 * case since it sets things up.  We fall through
		 * to the lower code and get the hardware set up.
		 * subsequent times we just lock the list and insert
		 * the handler and all is well.
		 */
		intr = kmem_zalloc(sizeof (inthandler_t), KM_NOSLEEP);
		if (intr == NULL) {
			sockp->ls_error = BAD_IRQ;
			return (DDI_FAILURE);
		}
		intr->intr = hdlp->ih_cb_func;
		intr->handler_id = (uint_t)(uintptr_t)rdip;
		intr->arg1 = hdlp->ih_cb_arg1;
		intr->arg2 = hdlp->ih_cb_arg2;
		intr->socket = socket;

		mutex_enter(&sockp->ls_ilock);
		if (sockp->ls_inthandlers == NULL) {
			intr->next = intr->prev = intr;
			sockp->ls_inthandlers = intr;
			sockp->ls_mfintr_dip = rdip;
			mutex_exit(&sockp->ls_ilock);

			/*
			 * replace first function handler with
			 * the mfc handler
			 */
			handler.handler =  (f_tt *)pcmcia_mfc_intr;
			handler.arg1 = (caddr_t)sockp;
			handler.arg2 = NULL;
		} else {
			insque(intr, sockp->ls_inthandlers);
			mutex_exit(&sockp->ls_ilock);

			pispec->intrspec_vec = sockp->ls_intr_vec;
			pispec->intrspec_pri = sockp->ls_intr_pri;
			hdlp->ih_pri = sockp->ls_intr_pri;

			return (DDI_SUCCESS);
		}
	}

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {
		cmn_err(CE_CONT, "pcmcia_add_intr_impl() let adapter do it\n");
	}
#endif
	pispec->intrspec_func = (uint32_t (*)())handler.handler;

	/* set default IPL then check for override */

	pispec->intrspec_pri = sockp->ls_intr_pri;
	hdlp->ih_pri = pispec->intrspec_pri;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {
		cmn_err(CE_CONT, "pcmcia_add_intr_impl() socket=%d irq=%d"
		    " handler_id=0X%x handler=%p arg1=%p arg2=%p\n",
		    handler.socket, handler.irq,
		    handler.handler_id, (void *)handler.handler, handler.arg1,
		    handler.arg2);
	}
#endif

	if ((ret = SET_IRQ(sockp->ls_if, adapt->pca_dip, &handler)) !=
	    SUCCESS) {
		sockp->ls_error = ret;
		return (DDI_FAILURE);
	}

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {
		cmn_err(CE_CONT, "pcmcia_add_intr_impl()"
		    " iblk_cookie=%p idev_cookie=%p\n"
		    " ls_flags=0X%x PCS_COOKIES_VALID=0X%x\n",
		    (void *)handler.iblk_cookie,
		    (void *)handler.idev_cookie,
		    sockp->ls_flags, PCS_COOKIES_VALID);
	}
#endif

	if (!(sockp->ls_flags & PCS_COOKIES_VALID)) {
		hdlp->ih_pri = (uint_t)(uintptr_t)*handler.iblk_cookie;
		sockp->ls_iblk = *handler.iblk_cookie;
		sockp->ls_idev = *handler.idev_cookie;
		sockp->ls_flags |= PCS_COOKIES_VALID;
	}

	return (DDI_SUCCESS);
}

void
pcmcia_remove_intr_impl(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{

	struct pcmcia_parent_private *ppd;
	pcmcia_logical_socket_t *sockp;
	clear_irq_handler_t handler;
	struct intrspec *pispec;
	int socket;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {
		cmn_err(CE_CONT, "pcmcia_remove_intr_impl() entered"
		    " dip=%p rdip=%p hdlp=%p\n",
		    (void *)dip, (void *)rdip, (void *)hdlp);
	}
#endif

	ppd = (struct pcmcia_parent_private *)ddi_get_parent_data(rdip);
	socket = ppd->ppd_socket;
	sockp = pcmcia_sockets[socket];
	pispec = ppd->ppd_intrspec;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {
		cmn_err(CE_CONT, "pcmcia_remove_intr_impl()"
		    " ls_inthandlers=%p ls_intrspec=%p\n",
		    (void *)sockp->ls_inthandlers,
		    (void *)&sockp->ls_intrspec);
	}
#endif

	/* first handle the multifunction case since it is simple */
	mutex_enter(&sockp->ls_ilock);
	if (sockp->ls_inthandlers != NULL) {
		/* we must be MFC */
		inthandler_t *intr;
		int remhandler = 0;
		intr = sockp->ls_inthandlers;

		/* Check if there is only one handler left */
		if ((intr->next == intr) && (intr->prev == intr)) {
			if (intr->handler_id == (unsigned)(uintptr_t)rdip) {
				sockp->ls_inthandlers = NULL;
				remhandler++;
				kmem_free(intr, sizeof (inthandler_t));
			}
		} else {
			inthandler_t *first;
			int done;

			for (done = 0, first = intr; !done; intr = intr->next) {
				if (intr->next == first)
					done++;
				if (intr->handler_id ==
				    (unsigned)(uintptr_t)rdip) {
					done++;

					/*
					 * If we're about to remove the
					 *	handler at the head of
					 *	the list, make the next
					 *	handler in line the head.
					 */
					if (sockp->ls_inthandlers == intr)
						sockp->ls_inthandlers =
						    intr->next;

					remque(intr);
					kmem_free(intr, sizeof (inthandler_t));
					break;
				} /* handler_id */
			} /* for */
		} /* intr->next */

		if (!remhandler) {
			mutex_exit(&sockp->ls_ilock);
			return;
		}

		/* need to get the dip that was used to add the handler */
		rdip = sockp->ls_mfintr_dip;
	}

	mutex_exit(&sockp->ls_ilock);

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {
		cmn_err(CE_CONT, "pcmcia_remove_intr_impl()"
		    " pispec=%p rdip=%p\n",
		    (void *)pispec, (void *)rdip);
	}
#endif

	handler.socket = sockp->ls_socket;
	handler.handler_id = (uint32_t)(uintptr_t)rdip;
	handler.handler = (f_tt *)pispec->intrspec_func;
	CLEAR_IRQ(sockp->ls_if, dip, &handler);
}


/* Consolidated interrupt processing interface */
/*ARGSUSED*/
int
pcmcia_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int	ret = DDI_SUCCESS;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug) {
		cmn_err(CE_CONT, "pcmcia_intr_ops() intr_op=%d\n",
		    (int)intr_op);
	}
#endif

	switch (intr_op) {
	case DDI_INTROP_GETCAP:
		*(int *)result = DDI_INTR_FLAG_LEVEL;
		break;
	case DDI_INTROP_SETCAP:
		ret = DDI_ENOTSUP;
		break;
	case DDI_INTROP_ALLOC:
		*(int *)result = hdlp->ih_scratch1;
		break;
	case DDI_INTROP_FREE:
		break;
	case DDI_INTROP_GETPRI:
		if (pcmcia_add_intr_impl(dip, rdip, hdlp) != DDI_SUCCESS)
			return (DDI_FAILURE);
		*(int *)result = hdlp->ih_pri;
		pcmcia_remove_intr_impl(dip, rdip, hdlp);
		break;
	case DDI_INTROP_SETPRI:
		break;
	case DDI_INTROP_ADDISR:
		ret = pcmcia_add_intr_impl(dip, rdip, hdlp);
		break;
	case DDI_INTROP_REMISR:
		pcmcia_remove_intr_impl(dip, rdip, hdlp);
		break;
	case DDI_INTROP_ENABLE:
	case DDI_INTROP_DISABLE:
		break;
	case DDI_INTROP_NINTRS:
	case DDI_INTROP_NAVAIL:
		*(int *)result = i_ddi_get_intx_nintrs(rdip);
		break;
	case DDI_INTROP_SUPPORTED_TYPES:
		/* PCI nexus driver supports only fixed interrupts */
		*(int *)result = i_ddi_get_intx_nintrs(rdip) ?
		    DDI_INTR_TYPE_FIXED : 0;
		break;
	default:
		ret = DDI_ENOTSUP;
		break;
	}

	return (ret);
}

#elif defined(__x86) || defined(__amd64)

static struct intrspec	*pcmcia_intr_get_ispec(dev_info_t *, int,
			    pcmcia_logical_socket_t **);
static struct intrspec	*pcmcia_intr_add_isr(dev_info_t *, dev_info_t *,
			    ddi_intr_handle_impl_t *);
static int		pcmcia_intr_enable_isr(dev_info_t *, dev_info_t *,
			    ddi_intr_handle_impl_t *);
static void		pcmcia_intr_remove_isr(dev_info_t *, dev_info_t *,
			    ddi_intr_handle_impl_t *);
static void		pcmcia_intr_disable_isr(dev_info_t *, dev_info_t *,
			    ddi_intr_handle_impl_t *);

/*
 * pcmcia_intr_get_ispec:
 *	This is mostly copied from older 'pcmcia_get_intrspec' function
 */
static struct intrspec *
pcmcia_intr_get_ispec(dev_info_t *rdip, int inum,
    pcmcia_logical_socket_t **sockp)
{
	int				socket;
	struct intrspec			*intrspec;
	struct pcmcia_parent_private	*ppd;

	if ((int)inum > 0 || (ddi_getprop(DDI_DEV_T_ANY, rdip,
	    DDI_PROP_DONTPASS, "interrupts", -1) < 0))
		return (NULL);

	ppd = (struct pcmcia_parent_private *)ddi_get_parent_data(rdip);
	if (ppd == NULL || ppd->ppd_intrspec == NULL)
		return (NULL);

	if ((socket = ppd->ppd_socket) < 0)
		return (NULL);

	if ((*sockp = pcmcia_sockets[socket]) == NULL)
		return (NULL);

	intrspec = ppd->ppd_intrspec;
	if (intrspec->intrspec_vec == 0 && (*sockp)->ls_intr_vec != 0)
		intrspec->intrspec_vec = (*sockp)->ls_intr_vec;

	return (intrspec);
}

static struct intrspec *
pcmcia_intr_add_isr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	int				socket;
	struct intrspec			*ispecp;
	struct pcmcia_adapter		*adapt;
	pcmcia_logical_socket_t		*sockp;
	struct pcmcia_parent_private	*ppd;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug)
		cmn_err(CE_CONT, "pcmcia_intr_add_isr: "
		    "dip=0x%p rdip=0x%p hdlp=0x%p\n",
		    (void *)dip, (void *)rdip, (void *)hdlp);
#endif	/* PCMCIA_DEBUG */

	ppd = (struct pcmcia_parent_private *)ddi_get_parent_data(rdip);
	socket = ppd->ppd_socket;
	sockp = pcmcia_sockets[socket];
	adapt = sockp->ls_adapter;

	ispecp = ppd->ppd_intrspec;
	if (ispecp == NULL) {
		sockp->ls_error = BAD_IRQ;
		return (ispecp);
	}

	/*
	 * check if multifunction and do the right thing
	 * we put an intercept in between the mfc handler and us so we can
	 * catch and process. We might be able to optimize this depending
	 * on the card features (a future option).
	 */
	if (ppd->ppd_flags & PPD_CARD_MULTI &&
	    hdlp->ih_cb_func != pcmcia_mfc_intr) {
		inthandler_t *intr;

		/*
		 * note that the first function is a special case since it
		 * sets things up.  We fall through to the lower code and
		 * get the hardware set up. Subsequent times we just lock
		 * the list and insert the handler and all is well.
		 */
		intr = kmem_zalloc(sizeof (inthandler_t), KM_NOSLEEP);
		if (intr == NULL) {
			sockp->ls_error = BAD_IRQ;
			return (NULL);
		}

		intr->intr = (uint32_t (*)())hdlp->ih_cb_func;
		intr->handler_id = (uint32_t)(uintptr_t)rdip;
		intr->arg1 = hdlp->ih_cb_arg1;
		intr->arg2 = hdlp->ih_cb_arg2;
		intr->socket = socket;
		mutex_enter(&sockp->ls_ilock);
		if (sockp->ls_inthandlers == NULL) {
			intr->next = intr->prev = intr;
			sockp->ls_inthandlers = intr;
			sockp->ls_mfintr_dip = rdip;
		} else {
			insque(intr, sockp->ls_inthandlers);
		}
		mutex_exit(&sockp->ls_ilock);
		return (ispecp);
	}

	/*
	 * Do we need to allocate an IRQ at this point or not?
	 */
	if (adapt->pca_flags & PCA_RES_NEED_IRQ) {
		int i, irq;

		/*
		 * this adapter needs IRQ allocations
		 * this is only necessary if it is the first function on the
		 * card being setup. The socket will keep the allocation info
		 */
		/* all functions use same intrspec except mfc handler */
		if (hdlp->ih_cb_func == pcmcia_mfc_intr) {
			/*
			 * We treat this special in order to allow things to
			 * work properly for MFC cards. The intrspec for the
			 * mfc dispatcher is intercepted and taken from the
			 * logical socket in order to not be trying to
			 * multiplex the meaning when ENABLE is called.
			 */
			ispecp = &sockp->ls_intrspec;
			((ihdl_plat_t *)hdlp->ih_private)->ip_ispecp = ispecp;
		}

		if (adapt->pca_flags & PCA_IRQ_ISA) {
			for (irq = -1, i = 1; irq == -1 && i < 16; i++) {
				/* find available and usable IRQ level */
				if (adapt->pca_avail_intr & (1 << i))
					irq = pcmcia_get_intr(dip, i);
			}
		}
		if (irq < 0) {
			sockp->ls_error = NO_RESOURCE;
			return (NULL);
		}
		hdlp->ih_vector = sockp->ls_intr_vec = irq;


#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug)
			cmn_err(CE_CONT, "allocated irq=%x\n", irq);
#endif	/* PCMCIA_DEBUG */

		ispecp->intrspec_vec = sockp->ls_intr_vec;
		ispecp->intrspec_pri = sockp->ls_intr_pri;
		return (ispecp);
	}

	if (ispecp->intrspec_func != NULL)
		ispecp->intrspec_func = hdlp->ih_cb_func;

	/* set default IPL then check for override */
	ispecp->intrspec_pri = sockp->ls_intr_pri;
	return (ispecp);
}


static int
pcmcia_intr_enable_isr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	int				socket, ret;
	int				irq = 0;	/* default case */
	dev_info_t			*parent = ddi_root_node();
	struct intrspec			*ispecp;
	set_irq_handler_t		handler;
	struct pcmcia_adapter		*adapt;
	pcmcia_logical_socket_t		*sockp;
	struct pcmcia_parent_private	*ppd;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug)
		cmn_err(CE_CONT, "pcmcia_intr_enable_isr: "
		    "dip=0x%p rdip=0x%p hdlp=0x%p\n",
		    (void *)dip, (void *)rdip, (void *)hdlp);
#endif	/* PCMCIA_DEBUG */

	ppd = (struct pcmcia_parent_private *)ddi_get_parent_data(rdip);
	socket = ppd->ppd_socket;
	sockp = pcmcia_sockets[socket];
	adapt = sockp->ls_adapter;

	ispecp = ppd->ppd_intrspec;
	ASSERT(ispecp);

	mutex_enter(&sockp->ls_ilock);
	if ((sockp->ls_inthandlers != NULL) &&
	    ((ihdl_plat_t *)hdlp->ih_private)->ip_ispecp !=
	    &sockp->ls_intrspec) {
		inthandler_t *intr = sockp->ls_inthandlers;

		ASSERT(ppd->ppd_flags & PPD_CARD_MULTI);

		/* Only one handler. So, call ddi_add_intr on it */
		if ((intr->next == intr) && (intr->prev == intr)) {
			hdlp->ih_cb_func = pcmcia_mfc_intr;
			hdlp->ih_cb_arg1 = (caddr_t)sockp;
			hdlp->ih_cb_arg2 = NULL;

			ret = (*(DEVI(parent)->devi_ops->devo_bus_ops->
			    bus_intr_op))(parent, rdip, DDI_INTROP_ENABLE,
			    hdlp, NULL);

			if (ret == DDI_FAILURE) {
				sockp->ls_inthandlers = NULL;
				kmem_free(intr, sizeof (inthandler_t));
				sockp->ls_error = BAD_IRQ;
				mutex_exit(&sockp->ls_ilock);
				return (ret);
			}
		}
		mutex_exit(&sockp->ls_ilock);
		hdlp->ih_vector = ispecp->intrspec_vec = sockp->ls_intr_vec;
		hdlp->ih_pri = sockp->ls_intr_pri;
		sockp->ls_iblk = (ddi_iblock_cookie_t)(uintptr_t)
		    sockp->ls_intr_pri;
		sockp->ls_idev.idev_vector = (ushort_t)hdlp->ih_vector;
		sockp->ls_idev.idev_priority = (ushort_t)sockp->ls_intr_pri;
		return (DDI_SUCCESS);
	}
	mutex_exit(&sockp->ls_ilock);

	if (adapt->pca_flags & PCA_RES_NEED_IRQ) {
		if (hdlp->ih_cb_func == pcmcia_mfc_intr)
			ispecp = (struct intrspec *)&sockp->ls_intrspec;

		/* XXX: remove it later as this is done in _add_isr as well */
		ispecp->intrspec_vec = sockp->ls_intr_vec;
		ispecp->intrspec_pri = sockp->ls_intr_pri;

		/* Enable interrupts */
		ret = (*(DEVI(parent)->devi_ops->devo_bus_ops->bus_intr_op))(
		    parent, rdip, DDI_INTROP_ENABLE, hdlp, NULL);

		sockp->ls_iblk = (ddi_iblock_cookie_t)(uintptr_t)
		    sockp->ls_intr_pri;
		sockp->ls_idev.idev_vector = (ushort_t)sockp->ls_intr_vec;
		sockp->ls_idev.idev_priority = (ushort_t)sockp->ls_intr_pri;

		if (ret != DDI_SUCCESS)
			sockp->ls_error = BAD_IRQ;
		return (ret);
	}

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug)
		cmn_err(CE_CONT, "pcmcia_intr_enable_isr; let adapter do it\n");
#endif	/* PCMCIA_DEBUG */

	handler.socket = sockp->ls_socket;
	handler.irq = irq;
	handler.handler = (f_tt *)hdlp->ih_cb_func;
	handler.arg1 = hdlp->ih_cb_arg1;
	handler.arg2 = hdlp->ih_cb_arg2;
	handler.handler_id = (uint32_t)(uintptr_t)rdip;
	if (ispecp->intrspec_func != NULL)
		ispecp->intrspec_func = hdlp->ih_cb_func;

	/* set default IPL then check for override */
	ispecp->intrspec_pri = sockp->ls_intr_pri;

	if ((ret = SET_IRQ(sockp->ls_if, adapt->pca_dip, &handler)) !=
	    SUCCESS) {
		sockp->ls_error = ret;
		return (DDI_FAILURE);
	}
	ispecp->intrspec_func = hdlp->ih_cb_func;
	if (!(sockp->ls_flags & PCS_COOKIES_VALID)) {
		sockp->ls_iblk = *handler.iblk_cookie;
		sockp->ls_idev = *handler.idev_cookie;
		sockp->ls_flags |= PCS_COOKIES_VALID;
	}
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static void
pcmcia_intr_remove_isr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	int				done, remhandler = 0;
	inthandler_t			*intr, *first;
	struct intrspec			*ispecp;
	pcmcia_logical_socket_t		*sockp;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug)
		cmn_err(CE_CONT, "pcmcia_intr_remove_isr: "
		    "dip=0x%p rdip=0x%p hdlp=0x%p\n",
		    (void *)dip, (void *)rdip, (void *)hdlp);
#endif	/* PCMCIA_DEBUG */

	ispecp = pcmcia_intr_get_ispec(rdip, hdlp->ih_inum, &sockp);
	ASSERT(ispecp);

	/* first handle the multifunction case since it is simple */
	mutex_enter(&sockp->ls_ilock);
	if (sockp->ls_inthandlers != NULL &&
	    ((ihdl_plat_t *)hdlp->ih_private)->ip_ispecp !=
	    &sockp->ls_intrspec) {

		intr = sockp->ls_inthandlers;

		/* Check if there is only one handler left */
		if ((intr->next == intr) && (intr->prev == intr)) {
			if (intr->handler_id == (uint32_t)(uintptr_t)rdip) {
				sockp->ls_inthandlers = NULL;
				remhandler++;
				kmem_free(intr, sizeof (inthandler_t));
			}

		} else {
			for (done = 0, first = intr; !done; intr = intr->next) {
				if (intr->next == first)
					done++;
				if (intr->handler_id ==
				    (uint32_t)(uintptr_t)rdip) {
					done++;

					/*
					 * If we're about to remove the handler
					 * at the head of the list, make the
					 * next handler in line the head.
					 */
					if (sockp->ls_inthandlers == intr)
						sockp->ls_inthandlers =
						    intr->next;

					remque(intr);
					kmem_free(intr, sizeof (inthandler_t));
					break;
				} /* handler_id */
			} /* end of for */
		} /* end of if intr->next */

		if (!remhandler) {
			mutex_exit(&sockp->ls_ilock);
			return;
		}
	}
	mutex_exit(&sockp->ls_ilock);

	if (sockp->ls_adapter->pca_flags & PCA_RES_NEED_IRQ) {
		sockp->ls_intr_vec = 0;
		ispecp->intrspec_vec = 0;
	}
}


static void
pcmcia_intr_disable_isr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	int				socket, ret;
	dev_info_t			*parent;
	struct intrspec			*ispecp;
	clear_irq_handler_t		handler;
	struct pcmcia_adapter		*adapt;
	pcmcia_logical_socket_t		*sockp;
	struct pcmcia_parent_private	*ppd;
	ihdl_plat_t			*ihdl_plat_datap =
	    (ihdl_plat_t *)hdlp->ih_private;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug)
		cmn_err(CE_CONT, "pcmcia_intr_disable_isr: "
		    "dip=0x%p rdip=0x%p hdlp=0x%p\n",
		    (void *)dip, (void *)rdip, (void *)hdlp);
#endif	/* PCMCIA_DEBUG */

	ppd = (struct pcmcia_parent_private *)ddi_get_parent_data(rdip);
	socket = ppd->ppd_socket;
	sockp = pcmcia_sockets[socket];
	adapt = sockp->ls_adapter;
	ispecp = ppd->ppd_intrspec;
	ASSERT(ispecp);

	mutex_enter(&sockp->ls_ilock);
	if (sockp->ls_inthandlers != NULL &&
	    ihdl_plat_datap->ip_ispecp != &sockp->ls_intrspec) {
		inthandler_t	*intr = sockp->ls_inthandlers;

		/* Check if there is only one handler left */
		if ((intr->next == intr) && (intr->prev == intr)) {
			if (intr->handler_id != (uint32_t)(uintptr_t)rdip) {
				/*
				 * need to get the dip that was
				 * used to add the handler
				 */
				rdip = sockp->ls_mfintr_dip;
			}
			ispecp = (struct intrspec *)&sockp->ls_intrspec;
		} else {
			/* Don't call cleanup if list still has members */
			mutex_exit(&sockp->ls_ilock);
			return;
		}
	}
	mutex_exit(&sockp->ls_ilock);

	if (ihdl_plat_datap->ip_ispecp ==
	    (struct intrspec *)&sockp->ls_intrspec)
		ispecp = ihdl_plat_datap->ip_ispecp;

	if (adapt->pca_flags & PCA_RES_NEED_IRQ) {
		ret = ispecp->intrspec_vec;
		parent = ddi_root_node();
		ret = (*(DEVI(parent)->devi_ops->devo_bus_ops->bus_intr_op))(
		    parent, rdip, DDI_INTROP_DISABLE, hdlp, NULL);
		(void) pcmcia_return_intr(dip, hdlp->ih_vector);
#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug)
			cmn_err(CE_CONT, "pcmcia_intr_disable_isr: "
			    "INTROP_DISABLE returned %x\n", ret);
#endif	/* PCMCIA_DEBUG */
	} else {
		handler.socket = sockp->ls_socket;
		handler.handler_id = (uint32_t)(uintptr_t)rdip;
		handler.handler = (f_tt *)ispecp->intrspec_func;
		ret = CLEAR_IRQ(sockp->ls_if, dip, &handler);
#if defined(PCMCIA_DEBUG)
		if (pcmcia_debug)
			cmn_err(CE_CONT, "pcmcia_intr_disable_isr: "
			    "CLEAR_IRQ returned %x\n", ret);
#endif	/* PCMCIA_DEBUG */
	}
}

/* Consolidated interrupt processing interface */
int
pcmcia_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	struct intrspec		*ispecp;
	pcmcia_logical_socket_t	*sockp;

#if defined(PCMCIA_DEBUG)
	if (pcmcia_debug)
		cmn_err(CE_CONT, "pcmcia_intr_ops: "
		    "dip=0x%p rdip=0x%p op=0x%x hdlp=0x%p\n",
		    (void *)dip, (void *)rdip, intr_op, (void *)hdlp);
#endif	/* PCMCIA_DEBUG */

	switch (intr_op) {
	case DDI_INTROP_SUPPORTED_TYPES:
		if (ddi_get_parent_data(rdip) == NULL) {
			*(int *)result = 0;
			return (DDI_FAILURE);
		}
		*(int *)result = DDI_INTR_TYPE_FIXED;
		break;
	case DDI_INTROP_GETCAP:
		*(int *)result = DDI_INTR_FLAG_LEVEL;
		break;
	case DDI_INTROP_NINTRS:
	case DDI_INTROP_NAVAIL:
		if (i_ddi_get_intx_nintrs(rdip) == 0) {
			*(int *)result = 0;
			return (DDI_FAILURE);
		}
		*(int *)result = 1;	/* for PCMCIA there is only one intr */
		break;
	case DDI_INTROP_ALLOC:
		if ((ispecp = pcmcia_intr_get_ispec(rdip, hdlp->ih_inum,
		    &sockp)) == NULL)
			return (DDI_FAILURE);
		*(int *)result = hdlp->ih_scratch1;
		break;
	case DDI_INTROP_FREE:
		break;
	case DDI_INTROP_GETPRI:
		ispecp = pcmcia_intr_get_ispec(rdip, hdlp->ih_inum, &sockp);
		if (ispecp == NULL) {
			*(int *)result = 0;
			return (DDI_FAILURE);
		}

		*(int *)result = ispecp->intrspec_pri = sockp->ls_intr_pri;
		break;
	case DDI_INTROP_SETPRI:
		if (*(int *)result > LOCK_LEVEL)
			return (DDI_FAILURE);
		ispecp = pcmcia_intr_get_ispec(rdip, hdlp->ih_inum, &sockp);
		ASSERT(ispecp);
		ispecp->intrspec_pri = sockp->ls_intr_pri = *(int *)result;
		break;
	case DDI_INTROP_ADDISR:
		if ((ispecp = pcmcia_intr_add_isr(dip, rdip, hdlp)) == NULL)
			return (DDI_FAILURE);
		((ihdl_plat_t *)hdlp->ih_private)->ip_ispecp = ispecp;
		break;
	case DDI_INTROP_REMISR:
		pcmcia_intr_remove_isr(dip, rdip, hdlp);
		break;
	case DDI_INTROP_ENABLE:
		if (pcmcia_intr_enable_isr(dip, rdip, hdlp) != DDI_SUCCESS)
			return (DDI_FAILURE);
		break;
	case DDI_INTROP_DISABLE:
		pcmcia_intr_disable_isr(dip, rdip, hdlp);
		break;
	default:
		return (DDI_ENOTSUP);
	}

	return (DDI_SUCCESS);
}
#endif
