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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * PCIC device/interrupt handler
 *	The "pcic" driver handles the Intel 82365SL, Cirrus Logic
 *	and Toshiba (and possibly other clones) PCMCIA adapter chip
 *	sets.  It implements a subset of Socket Services as defined
 *	in the Solaris PCMCIA design documents
 */

/*
 * currently defined "properties"
 *
 * clock-frequency		bus clock frequency
 * smi				system management interrupt override
 * need-mult-irq		need status IRQ for each pair of sockets
 * disable-audio		don't route audio signal to speaker
 */


#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/param.h>
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
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/var.h>
#include <sys/callb.h>
#include <sys/open.h>
#include <sys/ddidmareq.h>
#include <sys/dma_engine.h>
#include <sys/kstat.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>

#include <sys/pctypes.h>
#include <sys/pcmcia.h>
#include <sys/sservice.h>

#include <sys/note.h>

#include <sys/pcic_reg.h>
#include <sys/pcic_var.h>

#if defined(__i386) || defined(__amd64)
#include <sys/pci_cfgspace.h>
#endif

#if defined(__sparc)
#include <sys/pci/pci_nexus.h>
#endif

#include <sys/hotplug/hpcsvc.h>
#include "cardbus/cardbus.h"

#define	SOFTC_SIZE	(sizeof (anp_t))

static int pcic_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int pcic_attach(dev_info_t *, ddi_attach_cmd_t);
static int pcic_detach(dev_info_t *, ddi_detach_cmd_t);
static int32_t pcic_quiesce(dev_info_t *);
static uint_t pcic_intr(caddr_t, caddr_t);
static int pcic_do_io_intr(pcicdev_t *, uint32_t);
static int pcic_probe(dev_info_t *);

static int pcic_open(dev_t *, int, int, cred_t *);
static int pcic_close(dev_t, int, int, cred_t *);
static int pcic_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

typedef struct pcm_regs pcm_regs_t;

static void pcic_init_assigned(dev_info_t *);
static int pcic_apply_avail_ranges(dev_info_t *, pcm_regs_t *,
	pci_regspec_t *, int);
int pci_resource_setup_avail(dev_info_t *, pci_regspec_t *, int);

/*
 * On x86 platforms the ddi_iobp_alloc(9F) and ddi_mem_alloc(9F) calls
 * are xlated into DMA ctlops. To make this nexus work on x86, we
 * need to have the default ddi_dma_mctl ctlops in the bus_ops
 * structure, just to pass the request to the parent. The correct
 * ctlops should be ddi_no_dma_mctl because so far we don't do DMA.
 */
static
struct bus_ops pcmciabus_ops = {
	BUSO_REV,
	pcmcia_bus_map,
	NULL,
	NULL,
	NULL,
	i_ddi_map_fault,
	ddi_no_dma_map,
	ddi_no_dma_allochdl,
	ddi_no_dma_freehdl,
	ddi_no_dma_bindhdl,
	ddi_no_dma_unbindhdl,
	ddi_no_dma_flush,
	ddi_no_dma_win,
	ddi_dma_mctl,
	pcmcia_ctlops,
	pcmcia_prop_op,
	NULL,				/* (*bus_get_eventcookie)();	*/
	NULL,				/* (*bus_add_eventcall)();	*/
	NULL,				/* (*bus_remove_eventcall)();	*/
	NULL,				/* (*bus_post_event)();		*/
	NULL,				/* (*bus_intr_ctl)();		*/
	NULL,				/* (*bus_config)(); 		*/
	NULL,				/* (*bus_unconfig)(); 		*/
	NULL,				/* (*bus_fm_init)(); 		*/
	NULL,				/* (*bus_fm_fini)(); 		*/
	NULL,				/* (*bus_enter)()		*/
	NULL,				/* (*bus_exit)()		*/
	NULL,				/* (*bus_power)()		*/
	pcmcia_intr_ops			/* (*bus_intr_op)(); 		*/
};

static struct cb_ops pcic_cbops = {
	pcic_open,
	pcic_close,
	nodev,
	nodev,
	nodev,
	nodev,
	nodev,
	pcic_ioctl,
	nodev,
	nodev,
	nodev,
	nochpoll,
	ddi_prop_op,
	NULL,
#ifdef CARDBUS
	D_NEW | D_MP | D_HOTPLUG
#else
	D_NEW | D_MP
#endif
};

static struct dev_ops pcic_devops = {
	DEVO_REV,
	0,
	pcic_getinfo,
	nulldev,
	pcic_probe,
	pcic_attach,
	pcic_detach,
	nulldev,
	&pcic_cbops,
	&pcmciabus_ops,
	NULL,
	pcic_quiesce,	/* devo_quiesce */
};

void *pcic_soft_state_p = NULL;
static int pcic_maxinst = -1;

int pcic_do_insertion = 1;
int pcic_do_removal = 1;

struct irqmap {
	int irq;
	int count;
} pcic_irq_map[16];


int pcic_debug = 0x0;
static  void    pcic_err(dev_info_t *dip, int level, const char *fmt, ...);
extern void cardbus_dump_pci_config(dev_info_t *dip);
extern void cardbus_dump_socket(dev_info_t *dip);
extern int cardbus_validate_iline(dev_info_t *dip, ddi_acc_handle_t handle);
static void pcic_dump_debqueue(char *msg);

#if defined(PCIC_DEBUG)
static void xxdmp_all_regs(pcicdev_t *, int, uint32_t);

#define	pcic_mutex_enter(a)	\
	{ \
		pcic_err(NULL, 10, "Set lock at %d\n", __LINE__); \
		mutex_enter(a); \
	};

#define	pcic_mutex_exit(a)	\
	{ \
		pcic_err(NULL, 10, "Clear lock at %d\n", __LINE__); \
		mutex_exit(a); \
	};

#else
#define	pcic_mutex_enter(a)	mutex_enter(a)
#define	pcic_mutex_exit(a)	mutex_exit(a)
#endif

#define	PCIC_VCC_3VLEVEL	1
#define	PCIC_VCC_5VLEVEL	2
#define	PCIC_VCC_12LEVEL	3

/* bit patterns to select voltage levels */
int pcic_vpp_levels[13] = {
	0, 0, 0,
	1,	/* 3.3V */
	0,
	1,	/* 5V */
	0, 0, 0, 0, 0, 0,
	2	/* 12V */
};

uint8_t pcic_cbv_levels[13] = {
	0, 0, 0,
	3,			/* 3.3V */
	0,
	2,			/* 5V */
	0, 0, 0, 0, 0, 0,
	1			/* 12V */
};

struct power_entry pcic_power[4] = {
	{
		0, VCC|VPP1|VPP2
	},
	{
		33,		/* 3.3Volt */
		VCC|VPP1|VPP2
	},
	{
		5*10,		/* 5Volt */
		VCC|VPP1|VPP2	/* currently only know about this */
	},
	{
		12*10,		/* 12Volt */
		VPP1|VPP2
	}
};

/*
 * Base used to allocate ranges of PCI memory on x86 systems
 * Each instance gets a chunk above the base that is used to map
 * in the memory and I/O windows for that device.
 * Pages below the base are also allocated for the EXCA registers,
 * one per instance.
 */
#define	PCIC_PCI_MEMCHUNK	0x1000000

static int pcic_wait_insert_time = 5000000;	/* In micro-seconds */
static int pcic_debounce_time = 200000; /* In micro-seconds */

struct debounce {
	pcic_socket_t *pcs;
	clock_t expire;
	struct debounce *next;
};

static struct debounce *pcic_deb_queue = NULL;
static kmutex_t pcic_deb_mtx;
static kcondvar_t pcic_deb_cv;
static kthread_t *pcic_deb_threadid;

static inthandler_t *pcic_handlers;

static void pcic_setup_adapter(pcicdev_t *);
static int pcic_change(pcicdev_t *, int);
static int pcic_ll_reset(pcicdev_t *, int);
static void pcic_mswait(pcicdev_t *, int, int);
static boolean_t pcic_check_ready(pcicdev_t *, int);
static void pcic_set_cdtimers(pcicdev_t *, int, uint32_t, int);
static void pcic_ready_wait(pcicdev_t *, int);
extern int pcmcia_get_intr(dev_info_t *, int);
extern int pcmcia_return_intr(dev_info_t *, int);
extern void pcmcia_cb_suspended(int);
extern void pcmcia_cb_resumed(int);

static int pcic_callback(dev_info_t *, int (*)(), int);
static int pcic_inquire_adapter(dev_info_t *, inquire_adapter_t *);
static int pcic_get_adapter(dev_info_t *, get_adapter_t *);
static int pcic_get_page(dev_info_t *, get_page_t *);
static int pcic_get_socket(dev_info_t *, get_socket_t *);
static int pcic_get_status(dev_info_t *, get_ss_status_t *);
static int pcic_get_window(dev_info_t *, get_window_t *);
static int pcic_inquire_socket(dev_info_t *, inquire_socket_t *);
static int pcic_inquire_window(dev_info_t *, inquire_window_t *);
static int pcic_reset_socket(dev_info_t *, int, int);
static int pcic_set_page(dev_info_t *, set_page_t *);
static int pcic_set_window(dev_info_t *, set_window_t *);
static int pcic_set_socket(dev_info_t *, set_socket_t *);
static int pcic_set_interrupt(dev_info_t *, set_irq_handler_t *);
static int pcic_clear_interrupt(dev_info_t *, clear_irq_handler_t *);
static void pcic_pm_detection(void *);
static void pcic_iomem_pci_ctl(ddi_acc_handle_t, uchar_t *, unsigned);
static int clext_reg_read(pcicdev_t *, int, uchar_t);
static void clext_reg_write(pcicdev_t *, int, uchar_t, uchar_t);
static int pcic_calc_speed(pcicdev_t *, uint32_t);
static int pcic_card_state(pcicdev_t *, pcic_socket_t *);
static int pcic_find_pci_type(pcicdev_t *);
static void pcic_82092_smiirq_ctl(pcicdev_t *, int, int, int);
static void pcic_handle_cd_change(pcicdev_t *, pcic_socket_t *, uint8_t);
static uint_t pcic_cd_softint(caddr_t, caddr_t);
static uint8_t pcic_getb(pcicdev_t *, int, int);
static void pcic_putb(pcicdev_t *, int, int, int8_t);
static int pcic_set_vcc_level(pcicdev_t *, set_socket_t *);
static uint_t pcic_softintr(caddr_t, caddr_t);

static void pcic_debounce(pcic_socket_t *);
static void pcic_do_resume(pcicdev_t *);
static void *pcic_add_debqueue(pcic_socket_t *, int);
static void pcic_rm_debqueue(void *);
static void pcic_deb_thread();

static boolean_t pcic_load_cardbus(pcicdev_t *pcic, const pcic_socket_t *sockp);
static void pcic_unload_cardbus(pcicdev_t *pcic, const pcic_socket_t *sockp);
static uint32_t pcic_getcb(pcicdev_t *pcic, int reg);
static void pcic_putcb(pcicdev_t *pcic, int reg, uint32_t value);
static void pcic_cb_enable_intr(dev_info_t *);
static void pcic_cb_disable_intr(dev_info_t *);
static void pcic_enable_io_intr(pcicdev_t *pcic, int socket, int irq);
static void pcic_disable_io_intr(pcicdev_t *pcic, int socket);

static cb_nexus_cb_t pcic_cbnexus_ops = {
	pcic_cb_enable_intr,
	pcic_cb_disable_intr
};

static int pcic_exca_powerctl(pcicdev_t *pcic, int socket, int powerlevel);
static int pcic_cbus_powerctl(pcicdev_t *pcic, int socket);

#if defined(__sparc)
static int pcic_fault(enum pci_fault_ops op, void *arg);
#endif


/*
 * pcmcia interface operations structure
 * this is the private interface that is exported to the nexus
 */
pcmcia_if_t pcic_if_ops = {
	PCIF_MAGIC,
	PCIF_VERSION,
	pcic_callback,
	pcic_get_adapter,
	pcic_get_page,
	pcic_get_socket,
	pcic_get_status,
	pcic_get_window,
	pcic_inquire_adapter,
	pcic_inquire_socket,
	pcic_inquire_window,
	pcic_reset_socket,
	pcic_set_page,
	pcic_set_window,
	pcic_set_socket,
	pcic_set_interrupt,
	pcic_clear_interrupt,
	NULL,
};

/*
 * chip type identification routines
 * this list of functions is searched until one of them succeeds
 * or all fail.  i82365SL is assumed if failed.
 */
static int pcic_ci_cirrus(pcicdev_t *);
static int pcic_ci_vadem(pcicdev_t *);
static int pcic_ci_ricoh(pcicdev_t *);

int (*pcic_ci_funcs[])(pcicdev_t *) = {
	pcic_ci_cirrus,
	pcic_ci_vadem,
	pcic_ci_ricoh,
	NULL
};

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module. This one is a driver */
	"PCIC PCMCIA adapter driver",	/* Name of the module. */
	&pcic_devops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init()
{
	int stat;

	/* Allocate soft state */
	if ((stat = ddi_soft_state_init(&pcic_soft_state_p,
	    SOFTC_SIZE, 2)) != DDI_SUCCESS)
		return (stat);

	if ((stat = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&pcic_soft_state_p);

	return (stat);
}

int
_fini()
{
	int stat = 0;

	if ((stat = mod_remove(&modlinkage)) != 0)
		return (stat);

	if (pcic_deb_threadid) {
		mutex_enter(&pcic_deb_mtx);
		pcic_deb_threadid = 0;
		while (!pcic_deb_threadid)
			cv_wait(&pcic_deb_cv, &pcic_deb_mtx);
		pcic_deb_threadid = 0;
		mutex_exit(&pcic_deb_mtx);

		mutex_destroy(&pcic_deb_mtx);
		cv_destroy(&pcic_deb_cv);
	}

	ddi_soft_state_fini(&pcic_soft_state_p);

	return (stat);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * pcic_getinfo()
 *	provide instance/device information about driver
 */
/*ARGSUSED*/
static int
pcic_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	anp_t *anp;
	int error = DDI_SUCCESS;
	minor_t minor;

	switch (cmd) {
		case DDI_INFO_DEVT2DEVINFO:
		minor = getminor((dev_t)arg);
		minor &= 0x7f;
		if (!(anp = ddi_get_soft_state(pcic_soft_state_p, minor)))
			*result = NULL;
		else
			*result = anp->an_dip;
		break;
		case DDI_INFO_DEVT2INSTANCE:
		minor = getminor((dev_t)arg);
		minor &= 0x7f;
		*result = (void *)((long)minor);
		break;
		default:
		error = DDI_FAILURE;
		break;
	}
	return (error);
}

static int
pcic_probe(dev_info_t *dip)
{
	int value;
	ddi_device_acc_attr_t attr;
	ddi_acc_handle_t handle;
	uchar_t *index, *data;

	if (ddi_dev_is_sid(dip) == DDI_SUCCESS)
		return (DDI_PROBE_DONTCARE);

	/*
	 * find a PCIC device (any vendor)
	 * while there can be up to 4 such devices in
	 * a system, we currently only look for 1
	 * per probe.  There will be up to 2 chips per
	 * instance since they share I/O space
	 */
	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (ddi_regs_map_setup(dip, PCIC_ISA_CONTROL_REG_NUM,
	    (caddr_t *)&index,
	    PCIC_ISA_CONTROL_REG_OFFSET,
	    PCIC_ISA_CONTROL_REG_LENGTH,
	    &attr, &handle) != DDI_SUCCESS)
		return (DDI_PROBE_FAILURE);

	data = index + 1;

#if defined(PCIC_DEBUG)
	if (pcic_debug)
		cmn_err(CE_CONT, "pcic_probe: entered\n");
	if (pcic_debug)
		cmn_err(CE_CONT, "\tindex=%p\n", (void *)index);
#endif
	ddi_put8(handle, index, PCIC_CHIP_REVISION);
	ddi_put8(handle, data, 0);
	value = ddi_get8(handle, data);
#if defined(PCIC_DEBUG)
	if (pcic_debug)
		cmn_err(CE_CONT, "\tchip revision register = %x\n", value);
#endif
	if ((value & PCIC_REV_MASK) >= PCIC_REV_LEVEL_LOW &&
	    (value & 0x30) == 0) {
		/*
		 * we probably have a PCIC chip in the system
		 * do a little more checking.  If we find one,
		 * reset everything in case of softboot
		 */
		ddi_put8(handle, index, PCIC_MAPPING_ENABLE);
		ddi_put8(handle, data, 0);
		value = ddi_get8(handle, data);
#if defined(PCIC_DEBUG)
		if (pcic_debug)
			cmn_err(CE_CONT, "\tzero test = %x\n", value);
#endif
		/* should read back as zero */
		if (value == 0) {
			/*
			 * we do have one and it is off the bus
			 */
#if defined(PCIC_DEBUG)
			if (pcic_debug)
				cmn_err(CE_CONT, "pcic_probe: success\n");
#endif
			ddi_regs_map_free(&handle);
			return (DDI_PROBE_SUCCESS);
		}
	}
#if defined(PCIC_DEBUG)
	if (pcic_debug)
		cmn_err(CE_CONT, "pcic_probe: failed\n");
#endif
	ddi_regs_map_free(&handle);
	return (DDI_PROBE_FAILURE);
}

/*
 * These are just defaults they can also be changed via a property in the
 * conf file.
 */
static int pci_config_reg_num = PCIC_PCI_CONFIG_REG_NUM;
static int pci_control_reg_num = PCIC_PCI_CONTROL_REG_NUM;
static int pcic_do_pcmcia_sr = 1;
static int pcic_use_cbpwrctl = PCF_CBPWRCTL;

/*
 * enable insertion/removal interrupt for 32bit cards
 */
static int
cardbus_enable_cd_intr(dev_info_t *dip)
{
	ddi_acc_handle_t	iohandle;
	caddr_t	ioaddr;
	ddi_device_acc_attr_t attr;
	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	(void) ddi_regs_map_setup(dip, 1,
	    (caddr_t *)&ioaddr,
	    0,
	    4096,
	    &attr, &iohandle);

	/* CSC Interrupt: Card detect interrupt on */
	ddi_put32(iohandle, (uint32_t *)(ioaddr+CB_STATUS_MASK),
	    ddi_get32(iohandle,
	    (uint32_t *)(ioaddr+CB_STATUS_MASK)) | CB_SE_CCDMASK);

	ddi_put32(iohandle, (uint32_t *)(ioaddr+CB_STATUS_EVENT),
	    ddi_get32(iohandle, (uint32_t *)(ioaddr+CB_STATUS_EVENT)));

	ddi_regs_map_free(&iohandle);
	return (1);
}

/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
static int32_t
pcic_quiesce(dev_info_t *dip)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;
	int i;

	for (i = 0; i < pcic->pc_numsockets; i++) {
		pcic_putb(pcic, i, PCIC_MANAGEMENT_INT, 0);
		pcic_putb(pcic, i, PCIC_CARD_DETECT, 0);
		pcic_putb(pcic, i, PCIC_MAPPING_ENABLE, 0);
		/* disable interrupts and put card into RESET */
		pcic_putb(pcic, i, PCIC_INTERRUPT, 0);
		/* poweroff socket */
		pcic_putb(pcic, i, PCIC_POWER_CONTROL, 0);
		pcic_putcb(pcic, CB_CONTROL, 0);
	}

	return (DDI_SUCCESS);
}

/*
 * pcic_attach()
 *	attach the PCIC (Intel 82365SL/CirrusLogic/Toshiba) driver
 *	to the system.  This is a child of "sysbus" since that is where
 *	the hardware lives, but it provides services to the "pcmcia"
 *	nexus driver.  It gives a pointer back via its private data
 *	structure which contains both the dip and socket services entry
 *	points
 */
static int
pcic_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	anp_t *pcic_nexus;
	pcicdev_t *pcic;
	int irqlevel, value;
	int pci_cfrn, pci_ctrn;
	int i, j, smi, actual;
	char *typename;
	char bus_type[16] = "(unknown)";
	int len = sizeof (bus_type);
	ddi_device_acc_attr_t attr;
	anp_t *anp = ddi_get_driver_private(dip);
	uint_t	pri;

#if defined(PCIC_DEBUG)
	if (pcic_debug) {
		cmn_err(CE_CONT, "pcic_attach: entered\n");
	}
#endif
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		pcic = anp->an_private;
		/*
		 * for now, this is a simulated resume.
		 * a real one may need different things.
		 */
		if (pcic != NULL && pcic->pc_flags & PCF_SUSPENDED) {
			mutex_enter(&pcic->pc_lock);
			/* should probe for new sockets showing up */
			pcic_setup_adapter(pcic);
			pcic->pc_flags &= ~PCF_SUSPENDED;
			mutex_exit(&pcic->pc_lock);
			(void) pcmcia_begin_resume(dip);

			pcic_do_resume(pcic);
#ifdef CARDBUS
			cardbus_restore_children(ddi_get_child(dip));
#endif

			/*
			 * for complete implementation need END_RESUME (later)
			 */
			return (DDI_SUCCESS);

		}
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	/*
	 * Allocate soft state associated with this instance.
	 */
	if (ddi_soft_state_zalloc(pcic_soft_state_p,
	    ddi_get_instance(dip)) != DDI_SUCCESS) {
		cmn_err(CE_CONT, "pcic%d: Unable to alloc state\n",
		    ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	pcic_nexus = ddi_get_soft_state(pcic_soft_state_p,
	    ddi_get_instance(dip));

	pcic = kmem_zalloc(sizeof (pcicdev_t), KM_SLEEP);

	pcic->dip = dip;
	pcic_nexus->an_dip = dip;
	pcic_nexus->an_if = &pcic_if_ops;
	pcic_nexus->an_private = pcic;
	pcic->pc_numpower = sizeof (pcic_power)/sizeof (pcic_power[0]);
	pcic->pc_power = pcic_power;

	pci_ctrn = ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_CANSLEEP,
	    "pci-control-reg-number", pci_control_reg_num);
	pci_cfrn = ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_CANSLEEP,
	    "pci-config-reg-number", pci_config_reg_num);

	ddi_set_driver_private(dip, pcic_nexus);

	/*
	 * pcic->pc_irq is really the IPL level we want to run at
	 * set the default values here and override from intr spec
	 */
	pcic->pc_irq = ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_CANSLEEP,
	    "interrupt-priorities", -1);

	if (pcic->pc_irq == -1) {
		int			actual;
		uint_t			pri;
		ddi_intr_handle_t	hdl;

		/* see if intrspec tells us different */
		if (ddi_intr_alloc(dip, &hdl, DDI_INTR_TYPE_FIXED,
		    0, 1, &actual, DDI_INTR_ALLOC_NORMAL) == DDI_SUCCESS) {
			if (ddi_intr_get_pri(hdl, &pri) == DDI_SUCCESS)
				pcic->pc_irq = pri;
			else
				pcic->pc_irq = LOCK_LEVEL + 1;
			(void) ddi_intr_free(hdl);
		}
	}
	pcic_nexus->an_ipl = pcic->pc_irq;

	/*
	 * Check our parent bus type. We do different things based on which
	 * bus we're on.
	 */
	if (ddi_prop_op(DDI_DEV_T_ANY, ddi_get_parent(dip),
	    PROP_LEN_AND_VAL_BUF, DDI_PROP_CANSLEEP,
	    "device_type", (caddr_t)&bus_type[0], &len) !=
	    DDI_PROP_SUCCESS) {
		if (ddi_prop_op(DDI_DEV_T_ANY, ddi_get_parent(dip),
		    PROP_LEN_AND_VAL_BUF, DDI_PROP_CANSLEEP,
		    "bus-type", (caddr_t)&bus_type[0], &len) !=
		    DDI_PROP_SUCCESS) {

			cmn_err(CE_CONT,
			    "pcic%d: can't find parent bus type\n",
			    ddi_get_instance(dip));

			kmem_free(pcic, sizeof (pcicdev_t));
			ddi_soft_state_free(pcic_soft_state_p,
			    ddi_get_instance(dip));
			return (DDI_FAILURE);
		}
	} /* ddi_prop_op("device_type") */

	if (strcmp(bus_type, DEVI_PCI_NEXNAME) == 0 ||
	    strcmp(bus_type, DEVI_PCIEX_NEXNAME) == 0) {
		pcic->pc_flags = PCF_PCIBUS;
	} else {
		cmn_err(CE_WARN, "!pcic%d: non-pci mode (%s) not supported, "
		    "set BIOS to yenta mode if applicable\n",
		    ddi_get_instance(dip), bus_type);
		kmem_free(pcic, sizeof (pcicdev_t));
		ddi_soft_state_free(pcic_soft_state_p,
		    ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	if ((pcic->bus_speed = ddi_getprop(DDI_DEV_T_ANY, ddi_get_parent(dip),
	    DDI_PROP_CANSLEEP,
	    "clock-frequency", 0)) == 0) {
		if (pcic->pc_flags & PCF_PCIBUS)
			pcic->bus_speed = PCIC_PCI_DEF_SYSCLK;
		else
			pcic->bus_speed = PCIC_ISA_DEF_SYSCLK;
	} else {
		/*
		 * OBP can declare the speed in Hz...
		 */
		if (pcic->bus_speed > 1000000)
			pcic->bus_speed /= 1000000;
	} /* ddi_prop_op("clock-frequency") */

	pcic->pc_io_type = PCIC_IO_TYPE_82365SL; /* default mode */

#ifdef	PCIC_DEBUG
	if (pcic_debug) {
		cmn_err(CE_CONT,
		    "pcic%d: parent bus type = [%s], speed = %d MHz\n",
		    ddi_get_instance(dip),
		    bus_type, pcic->bus_speed);
	}
#endif

	/*
	 * The reg properties on a PCI node are different than those
	 *	on a non-PCI node. Handle that difference here.
	 *	If it turns out to be a CardBus chip, we have even more
	 *	differences.
	 */
	if (pcic->pc_flags & PCF_PCIBUS) {
		int class_code;
#if defined(__i386) || defined(__amd64)
		pcic->pc_base = 0x1000000;
		pcic->pc_bound = (uint32_t)~0;
		pcic->pc_iobase = 0x1000;
		pcic->pc_iobound = 0xefff;
#elif defined(__sparc)
		pcic->pc_base = 0x0;
		pcic->pc_bound = (uint32_t)~0;
		pcic->pc_iobase = 0x00000;
		pcic->pc_iobound = 0xffff;
#endif

		/* usually need to get at config space so map first */
		attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
		attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
		attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

		if (ddi_regs_map_setup(dip, pci_cfrn,
		    (caddr_t *)&pcic->cfgaddr,
		    PCIC_PCI_CONFIG_REG_OFFSET,
		    PCIC_PCI_CONFIG_REG_LENGTH,
		    &attr,
		    &pcic->cfg_handle) !=
		    DDI_SUCCESS) {
			cmn_err(CE_CONT,
			    "pcic%d: unable to map config space"
			    "regs\n",
			    ddi_get_instance(dip));

			kmem_free(pcic, sizeof (pcicdev_t));
			return (DDI_FAILURE);
		} /* ddi_regs_map_setup */

		class_code = ddi_getprop(DDI_DEV_T_ANY, dip,
		    DDI_PROP_CANSLEEP|DDI_PROP_DONTPASS,
		    "class-code", -1);
#ifdef  PCIC_DEBUG
		if (pcic_debug) {
			cmn_err(CE_CONT, "pcic_attach class_code=%x\n",
			    class_code);
		}
#endif

		switch (class_code) {
		case PCIC_PCI_CARDBUS:
			pcic->pc_flags |= PCF_CARDBUS;
			pcic->pc_io_type = PCIC_IO_TYPE_YENTA;
			/*
			 * Get access to the adapter registers on the
			 * PCI bus.  A 4K memory page
			 */
#if defined(PCIC_DEBUG)
			pcic_err(dip, 8, "Is Cardbus device\n");
			if (pcic_debug) {
				int nr;
				long rs;
				(void) ddi_dev_nregs(dip, &nr);
				pcic_err(dip, 9, "\tdev, cfgaddr 0x%p,"
				    "cfghndl 0x%p nregs %d",
				    (void *)pcic->cfgaddr,
				    (void *)pcic->cfg_handle, nr);

				(void) ddi_dev_regsize(dip,
				    PCIC_PCI_CONTROL_REG_NUM, &rs);

				pcic_err(dip, 9, "\tsize of reg %d is 0x%x\n",
				    PCIC_PCI_CONTROL_REG_NUM, (int)rs);
			}
#endif
			attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
			attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
			attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

			if (ddi_regs_map_setup(dip, pci_ctrn,
			    (caddr_t *)&pcic->ioaddr,
			    PCIC_PCI_CONTROL_REG_OFFSET,
			    PCIC_CB_CONTROL_REG_LENGTH,
			    &attr, &pcic->handle) !=
			    DDI_SUCCESS) {
				cmn_err(CE_CONT,
				    "pcic%d: unable to map PCI regs\n",
				    ddi_get_instance(dip));
				ddi_regs_map_free(&pcic->cfg_handle);
				kmem_free(pcic, sizeof (pcicdev_t));
				return (DDI_FAILURE);
			} /* ddi_regs_map_setup */

			/*
			 * Find out the chip type - If we're on a PCI bus,
			 *	the adapter has that information in the PCI
			 *	config space.
			 * Note that we call pcic_find_pci_type here since
			 *	it needs a valid mapped pcic->handle to
			 *	access some of the adapter registers in
			 *	some cases.
			 */
			if (pcic_find_pci_type(pcic) != DDI_SUCCESS) {
				ddi_regs_map_free(&pcic->handle);
				ddi_regs_map_free(&pcic->cfg_handle);
				kmem_free(pcic, sizeof (pcicdev_t));
				cmn_err(CE_WARN, "pcic: %s: unsupported "
				    "bridge\n", ddi_get_name_addr(dip));
				return (DDI_FAILURE);
			}
			break;

		default:
		case PCIC_PCI_PCMCIA:
			/*
			 * Get access to the adapter IO registers on the
			 * PCI bus config space.
			 */
			attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
			attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
			attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

			/*
			 * We need a default mapping to the adapter's IO
			 *	control register space. For most adapters
			 *	that are of class PCIC_PCI_PCMCIA (or of
			 *	a default class) the control registers
			 *	will be using the 82365-type control/data
			 *	format.
			 */
			if (ddi_regs_map_setup(dip, pci_ctrn,
			    (caddr_t *)&pcic->ioaddr,
			    PCIC_PCI_CONTROL_REG_OFFSET,
			    PCIC_PCI_CONTROL_REG_LENGTH,
			    &attr,
			    &pcic->handle) != DDI_SUCCESS) {
				cmn_err(CE_CONT,
				    "pcic%d: unable to map PCI regs\n",
				    ddi_get_instance(dip));
				ddi_regs_map_free(&pcic->cfg_handle);
				kmem_free(pcic, sizeof (pcicdev_t));
				return (DDI_FAILURE);
			} /* ddi_regs_map_setup */

			/*
			 * Find out the chip type - If we're on a PCI bus,
			 *	the adapter has that information in the PCI
			 *	config space.
			 * Note that we call pcic_find_pci_type here since
			 *	it needs a valid mapped pcic->handle to
			 *	access some of the adapter registers in
			 *	some cases.
			 */
			if (pcic_find_pci_type(pcic) != DDI_SUCCESS) {
				ddi_regs_map_free(&pcic->handle);
				ddi_regs_map_free(&pcic->cfg_handle);
				kmem_free(pcic, sizeof (pcicdev_t));
				cmn_err(CE_WARN, "pcic: %s: unsupported "
				    "bridge\n",
				    ddi_get_name_addr(dip));
				return (DDI_FAILURE);
			}

			/*
			 * Some PCI-PCMCIA(R2) adapters are Yenta-compliant
			 *	for extended registers even though they are
			 *	not CardBus adapters. For those adapters,
			 *	re-map pcic->handle to be large enough to
			 *	encompass the Yenta registers.
			 */
			switch (pcic->pc_type) {
				case PCIC_TI_PCI1031:
				ddi_regs_map_free(&pcic->handle);

				if (ddi_regs_map_setup(dip,
				    PCIC_PCI_CONTROL_REG_NUM,
				    (caddr_t *)&pcic->ioaddr,
				    PCIC_PCI_CONTROL_REG_OFFSET,
				    PCIC_CB_CONTROL_REG_LENGTH,
				    &attr,
				    &pcic->handle) != DDI_SUCCESS) {
					cmn_err(CE_CONT,
					    "pcic%d: unable to map "
					"PCI regs\n",
					    ddi_get_instance(dip));
					ddi_regs_map_free(&pcic->cfg_handle);
					kmem_free(pcic, sizeof (pcicdev_t));
					return (DDI_FAILURE);
				} /* ddi_regs_map_setup */
				break;
				default:
				break;
			} /* switch (pcic->pc_type) */
			break;
		} /* switch (class_code) */
	} else {
		/*
		 * We're not on a PCI bus, so assume an ISA bus type
		 * register property. Get access to the adapter IO
		 * registers on a non-PCI bus.
		 */
		attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
		attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
		attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
		pcic->mem_reg_num = PCIC_ISA_MEM_REG_NUM;
		pcic->io_reg_num = PCIC_ISA_IO_REG_NUM;

		if (ddi_regs_map_setup(dip, PCIC_ISA_CONTROL_REG_NUM,
		    (caddr_t *)&pcic->ioaddr,
		    PCIC_ISA_CONTROL_REG_OFFSET,
		    PCIC_ISA_CONTROL_REG_LENGTH,
		    &attr,
		    &pcic->handle) != DDI_SUCCESS) {
			cmn_err(CE_CONT,
			    "pcic%d: unable to map ISA registers\n",
			    ddi_get_instance(dip));

			kmem_free(pcic, sizeof (pcicdev_t));
			return (DDI_FAILURE);
		} /* ddi_regs_map_setup */

		/* ISA bus is limited to 24-bits, but not first 640K */
		pcic->pc_base = 0xd0000;
		pcic->pc_bound = (uint32_t)~0;
		pcic->pc_iobase = 0x1000;
		pcic->pc_iobound = 0xefff;
	} /* !PCF_PCIBUS */

#ifdef  PCIC_DEBUG
	if (pcic_debug) {
		cmn_err(CE_CONT, "pcic_attach pc_flags=%x pc_type=%x\n",
		    pcic->pc_flags, pcic->pc_type);
	}
#endif

	/*
	 * Setup various adapter registers for the PCI case. For the
	 * non-PCI case, find out the chip type.
	 */
	if (pcic->pc_flags & PCF_PCIBUS) {
		int iline;
#if defined(__sparc)
		iline = 0;
#else
		iline = cardbus_validate_iline(dip, pcic->cfg_handle);
#endif

		/* set flags and socket counts based on chip type */
		switch (pcic->pc_type) {
			uint32_t cfg;
		case PCIC_INTEL_i82092:
			cfg = ddi_get8(pcic->cfg_handle,
			    pcic->cfgaddr + PCIC_82092_PCICON);
			/* we can only support 4 Socket version */
			if (cfg & PCIC_82092_4_SOCKETS) {
				pcic->pc_numsockets = 4;
				pcic->pc_type = PCIC_INTEL_i82092;
				if (iline != 0xFF)
					pcic->pc_intr_mode =
					    PCIC_INTR_MODE_PCI_1;
				else
					pcic->pc_intr_mode = PCIC_INTR_MODE_ISA;
			} else {
				cmn_err(CE_CONT,
				    "pcic%d: Intel 82092 adapter "
				    "in unsupported configuration: 0x%x",
				    ddi_get_instance(pcic->dip), cfg);
				pcic->pc_numsockets = 0;
			} /* PCIC_82092_4_SOCKETS */
			break;
		case PCIC_CL_PD6730:
		case PCIC_CL_PD6729:
			pcic->pc_intr_mode = PCIC_INTR_MODE_PCI_1;
			cfg = ddi_getprop(DDI_DEV_T_ANY, dip,
			    DDI_PROP_CANSLEEP,
			    "interrupts", 0);
			/* if not interrupt pin then must use ISA style IRQs */
			if (cfg == 0 || iline == 0xFF)
				pcic->pc_intr_mode = PCIC_INTR_MODE_ISA;
			else {
				/*
				 * we have the option to use PCI interrupts.
				 * this might not be optimal but in some cases
				 * is the only thing possible (sparc case).
				 * we now deterine what is possible.
				 */
				pcic->pc_intr_mode = PCIC_INTR_MODE_PCI_1;
			}
			pcic->pc_numsockets = 2;
			pcic->pc_flags |= PCF_IO_REMAP;
			break;
		case PCIC_TI_PCI1031:
			/* this chip doesn't do CardBus but looks like one */
			pcic->pc_flags &= ~PCF_CARDBUS;
			/* FALLTHROUGH */
		default:
			pcic->pc_flags |= PCF_IO_REMAP;
			/* FALLTHROUGH */
			/* indicate feature even if not supported */
			pcic->pc_flags |= PCF_DMA | PCF_ZV;
			/* Not sure if these apply to all these chips */
			pcic->pc_flags |= (PCF_VPPX|PCF_33VCAP);
			pcic->pc_flags |= pcic_use_cbpwrctl;

			pcic->pc_numsockets = 1; /* one per function */
			if (iline != 0xFF) {
				uint8_t cfg;
				pcic->pc_intr_mode = PCIC_INTR_MODE_PCI_1;

				cfg = ddi_get8(pcic->cfg_handle,
				    (pcic->cfgaddr + PCIC_BRIDGE_CTL_REG));
				cfg &= (~PCIC_FUN_INT_MOD_ISA);
				ddi_put8(pcic->cfg_handle, (pcic->cfgaddr +
				    PCIC_BRIDGE_CTL_REG), cfg);
			}
			else
				pcic->pc_intr_mode = PCIC_INTR_MODE_ISA;
			pcic->pc_io_type = PCIC_IOTYPE_YENTA;
			break;
		}
	} else {
		/*
		 * We're not on a PCI bus so do some more
		 *	checking for adapter type here.
		 * For the non-PCI bus case:
		 * It could be any one of a number of different chips
		 * If we can't determine anything else, it is assumed
		 * to be an Intel 82365SL.  The Cirrus Logic PD6710
		 * has an extension register that provides unique
		 * identification. Toshiba chip isn't detailed as yet.
		 */

		/* Init the CL id mode */
		pcic_putb(pcic, 0, PCIC_CHIP_INFO, 0);
		value = pcic_getb(pcic, 0, PCIC_CHIP_INFO);

		/* default to Intel i82365SL and then refine */
		pcic->pc_type = PCIC_I82365SL;
		pcic->pc_chipname = PCIC_TYPE_I82365SL;
		for (value = 0; pcic_ci_funcs[value] != NULL; value++) {
			/* go until one succeeds or none left */
			if (pcic_ci_funcs[value](pcic))
				break;
		}

		/* any chip specific flags get set here */
		switch (pcic->pc_type) {
		case PCIC_CL_PD6722:
			pcic->pc_flags |= PCF_DMA;
		}

		for (i = 0; i < PCIC_MAX_SOCKETS; i++) {
			/*
			 * look for total number of sockets.
			 * basically check each possible socket for
			 * presence like in probe
			 */

			/* turn all windows off */
			pcic_putb(pcic, i, PCIC_MAPPING_ENABLE, 0);
			value = pcic_getb(pcic, i, PCIC_MAPPING_ENABLE);

			/*
			 * if a zero is read back, then this socket
			 * might be present. It would be except for
			 * some systems that map the secondary PCIC
			 * chip space back to the first.
			 */
			if (value != 0) {
				/* definitely not so skip */
				/* note: this is for Compaq support */
				continue;
			}

			/* further tests */
			value = pcic_getb(pcic, i, PCIC_CHIP_REVISION) &
			    PCIC_REV_MASK;
			if (!(value >= PCIC_REV_LEVEL_LOW &&
			    value <= PCIC_REV_LEVEL_HI))
				break;

			pcic_putb(pcic, i, PCIC_SYSMEM_0_STARTLOW, 0xaa);
			pcic_putb(pcic, i, PCIC_SYSMEM_1_STARTLOW, 0x55);
			value = pcic_getb(pcic, i, PCIC_SYSMEM_0_STARTLOW);

			j = pcic_getb(pcic, i, PCIC_SYSMEM_1_STARTLOW);
			if (value != 0xaa || j != 0x55)
				break;

			/*
			 * at this point we know if we have hardware
			 * of some type and not just the bus holding
			 * a pattern for us. We still have to determine
			 * the case where more than 2 sockets are
			 * really the same due to peculiar mappings of
			 * hardware.
			 */
			j = pcic->pc_numsockets++;
			pcic->pc_sockets[j].pcs_flags = 0;
			pcic->pc_sockets[j].pcs_io = pcic->ioaddr;
			pcic->pc_sockets[j].pcs_socket = i;

			/* put PC Card into RESET, just in case */
			value = pcic_getb(pcic, i, PCIC_INTERRUPT);
			pcic_putb(pcic, i, PCIC_INTERRUPT,
			    value & ~PCIC_RESET);
		}

#if defined(PCIC_DEBUG)
		if (pcic_debug)
			cmn_err(CE_CONT, "num sockets = %d\n",
			    pcic->pc_numsockets);
#endif
		if (pcic->pc_numsockets == 0) {
			ddi_regs_map_free(&pcic->handle);
			kmem_free(pcic, sizeof (pcicdev_t));
			return (DDI_FAILURE);
		}

		/*
		 * need to think this through again in light of
		 * Compaq not following the model that all the
		 * chip vendors recommend.  IBM 755 seems to be
		 * afflicted as well.  Basically, if the vendor
		 * wired things wrong, socket 0 responds for socket 2
		 * accesses, etc.
		 */
		if (pcic->pc_numsockets > 2) {
			int count = pcic->pc_numsockets / 4;
			for (i = 0; i < count; i++) {
				/* put pattern into socket 0 */
				pcic_putb(pcic, i,
				    PCIC_SYSMEM_0_STARTLOW, 0x11);

				/* put pattern into socket 2 */
				pcic_putb(pcic, i + 2,
				    PCIC_SYSMEM_0_STARTLOW, 0x33);

				/* read back socket 0 */
				value = pcic_getb(pcic, i,
				    PCIC_SYSMEM_0_STARTLOW);

				/* read back chip 1 socket 0 */
				j = pcic_getb(pcic, i + 2,
				    PCIC_SYSMEM_0_STARTLOW);
				if (j == value) {
					pcic->pc_numsockets -= 2;
				}
			}
		}

		smi = 0xff;	/* no more override */

		if (ddi_getprop(DDI_DEV_T_NONE, dip,
		    DDI_PROP_DONTPASS, "need-mult-irq",
		    0xffff) != 0xffff)
			pcic->pc_flags |= PCF_MULT_IRQ;

	} /* !PCF_PCIBUS */

	/*
	 * some platforms/busses need to have resources setup
	 * this is temporary until a real resource allocator is
	 * implemented.
	 */

	pcic_init_assigned(dip);

	typename = pcic->pc_chipname;

#ifdef	PCIC_DEBUG
	if (pcic_debug) {
		int nregs, nintrs;

		if (ddi_dev_nregs(dip, &nregs) != DDI_SUCCESS)
			nregs = 0;

		if (ddi_dev_nintrs(dip, &nintrs) != DDI_SUCCESS)
			nintrs = 0;

		cmn_err(CE_CONT,
		    "pcic%d: %d register sets, %d interrupts\n",
		    ddi_get_instance(dip), nregs, nintrs);

		nintrs = 0;
		while (nregs--) {
			off_t size;

			if (ddi_dev_regsize(dip, nintrs, &size) ==
			    DDI_SUCCESS) {
				cmn_err(CE_CONT,
				    "\tregnum %d size %ld (0x%lx)"
				    "bytes",
				    nintrs, size, size);
				if (nintrs ==
				    (pcic->pc_io_type == PCIC_IO_TYPE_82365SL ?
				    PCIC_ISA_CONTROL_REG_NUM :
				    PCIC_PCI_CONTROL_REG_NUM))
					cmn_err(CE_CONT,
					    " mapped at: 0x%p\n",
					    (void *)pcic->ioaddr);
				else
					cmn_err(CE_CONT, "\n");
			} else {
				cmn_err(CE_CONT,
				    "\tddi_dev_regsize(rnumber"
				    "= %d) returns DDI_FAILURE\n",
				    nintrs);
			}
			nintrs++;
		} /* while */
	} /* if (pcic_debug) */
#endif

	cv_init(&pcic->pm_cv, NULL, CV_DRIVER, NULL);

	if (!ddi_getprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
	    "disable-audio", 0))
		pcic->pc_flags |= PCF_AUDIO;

	if (ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_CANSLEEP,
	    "disable-cardbus", 0))
		pcic->pc_flags &= ~PCF_CARDBUS;

	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip, PCICPROP_CTL,
	    typename);

	/*
	 * Init all socket SMI levels to 0 (no SMI)
	 */
	for (i = 0; i < PCIC_MAX_SOCKETS; i++) {
		pcic->pc_sockets[i].pcs_smi = 0;
		pcic->pc_sockets[i].pcs_debounce_id = 0;
		pcic->pc_sockets[i].pcs_pcic = pcic;
	}
	pcic->pc_lastreg = -1; /* just to make sure we are in sync */

	/*
	 * Setup the IRQ handler(s)
	 */
	switch (pcic->pc_intr_mode) {
		int xx;
	case PCIC_INTR_MODE_ISA:
	/*
	 * On a non-PCI bus, we just use whatever SMI IRQ level was
	 *	specified above, and the IO IRQ levels are allocated
	 *	dynamically.
	 */
		for (xx = 15, smi = 0; xx >= 0; xx--) {
			if (PCIC_IRQ(xx) &
			    PCIC_AVAIL_IRQS) {
				smi = pcmcia_get_intr(dip, xx);
				if (smi >= 0)
					break;
			}
		}
#if defined(PCIC_DEBUG)
		if (pcic_debug)
			cmn_err(CE_NOTE, "\tselected IRQ %d as SMI\n", smi);
#endif
		/* init to same so share is easy */
		for (i = 0; i < pcic->pc_numsockets; i++)
			pcic->pc_sockets[i].pcs_smi = smi;
		/* any special handling of IRQ levels */
		if (pcic->pc_flags & PCF_MULT_IRQ) {
			for (i = 2; i < pcic->pc_numsockets; i++) {
				if ((i & 1) == 0) {
					int xx;
					for (xx = 15, smi = 0; xx >= 0; xx--) {
						if (PCIC_IRQ(xx) &
						    PCIC_AVAIL_IRQS) {
							smi =
							    pcmcia_get_intr(dip,
							    xx);
							if (smi >= 0)
								break;
						}
					}
				}
				if (smi >= 0)
					pcic->pc_sockets[i].pcs_smi = smi;
			}
		}
		pcic->pc_intr_htblp = kmem_alloc(pcic->pc_numsockets *
		    sizeof (ddi_intr_handle_t), KM_SLEEP);
		for (i = 0, irqlevel = -1; i < pcic->pc_numsockets; i++) {
			struct intrspec *ispecp;
			struct ddi_parent_private_data *pdp;

			if (irqlevel == pcic->pc_sockets[i].pcs_smi)
				continue;
			else {
				irqlevel = pcic->pc_sockets[i].pcs_smi;
			}
			/*
			 * now convert the allocated IRQ into an intrspec
			 * and ask our parent to add it.  Don't use
			 * the ddi_add_intr since we don't have a
			 * default intrspec in all cases.
			 *
			 * note: this sort of violates DDI but we don't
			 *	 get hardware intrspecs for many of the devices.
			 *	 at the same time, we know how to allocate them
			 *	 so we do the right thing.
			 */
			if (ddi_intr_alloc(dip, &pcic->pc_intr_htblp[i],
			    DDI_INTR_TYPE_FIXED, 0, 1, &actual,
			    DDI_INTR_ALLOC_NORMAL) != DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s: ddi_intr_alloc failed",
				    ddi_get_name(dip));
				goto isa_exit1;
			}

			/*
			 * See earlier note:
			 * Since some devices don't have 'intrspec'
			 * we make one up in rootnex.
			 *
			 * However, it is not properly initialized as
			 * the data it needs is present in this driver
			 * and there is no interface to pass that up.
			 * Specially 'irqlevel' is very important and
			 * it is part of pcic struct.
			 *
			 * Set 'intrspec' up here; otherwise adding the
			 * interrupt will fail.
			 */
			pdp = ddi_get_parent_data(dip);
			ispecp = (struct intrspec *)&pdp->par_intr[0];
			ispecp->intrspec_vec = irqlevel;
			ispecp->intrspec_pri = pcic->pc_irq;

			/* Stay compatible w/ PCMCIA */
			pcic->pc_pri = (ddi_iblock_cookie_t)
			    (uintptr_t)pcic->pc_irq;
			pcic->pc_dcookie.idev_priority =
			    (uintptr_t)pcic->pc_pri;
			pcic->pc_dcookie.idev_vector = (ushort_t)irqlevel;

			(void) ddi_intr_set_pri(pcic->pc_intr_htblp[i],
			    pcic->pc_irq);

			if (i == 0) {
				mutex_init(&pcic->intr_lock, NULL, MUTEX_DRIVER,
				    DDI_INTR_PRI(pcic->pc_irq));
				mutex_init(&pcic->pc_lock, NULL, MUTEX_DRIVER,
				    NULL);
			}

			if (ddi_intr_add_handler(pcic->pc_intr_htblp[i],
			    pcic_intr, (caddr_t)pcic, NULL)) {
				cmn_err(CE_WARN,
				    "%s: ddi_intr_add_handler failed",
				    ddi_get_name(dip));
				goto isa_exit2;
			}

			if (ddi_intr_enable(pcic->pc_intr_htblp[i])) {
				cmn_err(CE_WARN, "%s: ddi_intr_enable failed",
				    ddi_get_name(dip));
				for (j = i; j < 0; j--)
					(void) ddi_intr_remove_handler(
					    pcic->pc_intr_htblp[j]);
				goto isa_exit2;
			}
		}
		break;
	case PCIC_INTR_MODE_PCI_1:
	case PCIC_INTR_MODE_PCI:
		/*
		 * If we're on a PCI bus, we route all interrupts, both SMI
		 * and IO interrupts, through a single interrupt line.
		 * Assign the SMI IRQ level to the IO IRQ level here.
		 */
		pcic->pc_pci_intr_hdlp = kmem_alloc(sizeof (ddi_intr_handle_t),
		    KM_SLEEP);
		if (ddi_intr_alloc(dip, pcic->pc_pci_intr_hdlp,
		    DDI_INTR_TYPE_FIXED, 0, 1, &actual,
		    DDI_INTR_ALLOC_NORMAL) != DDI_SUCCESS)
			goto pci_exit1;

		if (ddi_intr_get_pri(pcic->pc_pci_intr_hdlp[0],
		    &pri) != DDI_SUCCESS) {
			(void) ddi_intr_free(pcic->pc_pci_intr_hdlp[0]);
			goto pci_exit1;
		}

		pcic->pc_pri = (void *)(uintptr_t)pri;
		mutex_init(&pcic->intr_lock, NULL, MUTEX_DRIVER, pcic->pc_pri);
		mutex_init(&pcic->pc_lock, NULL, MUTEX_DRIVER, NULL);

		if (ddi_intr_add_handler(pcic->pc_pci_intr_hdlp[0],
		    pcic_intr, (caddr_t)pcic, NULL))
			goto pci_exit2;

		if (ddi_intr_enable(pcic->pc_pci_intr_hdlp[0])) {
			(void) ddi_intr_remove_handler(
			    pcic->pc_pci_intr_hdlp[0]);
			goto pci_exit2;
		}

		/* Stay compatible w/ PCMCIA */
		pcic->pc_dcookie.idev_priority = (ushort_t)pri;

		/* init to same (PCI) so share is easy */
		for (i = 0; i < pcic->pc_numsockets; i++)
			pcic->pc_sockets[i].pcs_smi = 0xF; /* any valid */
		break;
	}

	/*
	 * Setup the adapter hardware to some reasonable defaults.
	 */
	mutex_enter(&pcic->pc_lock);
	/* mark the driver state as attached */
	pcic->pc_flags |= PCF_ATTACHED;
	pcic_setup_adapter(pcic);

	for (j = 0; j < pcic->pc_numsockets; j++)
		if (ddi_intr_add_softint(dip,
		    &pcic->pc_sockets[j].pcs_cd_softint_hdl,
		    PCIC_SOFTINT_PRI_VAL, pcic_cd_softint,
		    (caddr_t)&pcic->pc_sockets[j]) != DDI_SUCCESS)
			goto pci_exit2;

#if defined(PCIC_DEBUG)
	if (pcic_debug)
		cmn_err(CE_CONT, "type = %s sockets = %d\n", typename,
		    pcic->pc_numsockets);
#endif

	pcic_nexus->an_iblock = &pcic->pc_pri;
	pcic_nexus->an_idev = &pcic->pc_dcookie;

	mutex_exit(&pcic->pc_lock);

#ifdef CARDBUS
	(void) cardbus_enable_cd_intr(dip);
	if (pcic_debug) {

		cardbus_dump_pci_config(dip);
		cardbus_dump_socket(dip);
	}

	/*
	 * Give the Cardbus misc module a chance to do it's per-adapter
	 * instance setup. Note that there is no corresponding detach()
	 * call.
	 */
	if (pcic->pc_flags & PCF_CARDBUS)
		if (cardbus_attach(dip, &pcic_cbnexus_ops) != DDI_SUCCESS) {
			cmn_err(CE_CONT,
			    "pcic_attach: cardbus_attach failed\n");
			goto pci_exit2;
		}
#endif

	/*
	 * Give the PCMCIA misc module a chance to do it's per-adapter
	 *	instance setup.
	 */
	if ((i = pcmcia_attach(dip, pcic_nexus)) != DDI_SUCCESS)
		goto pci_exit2;

	if (pcic_maxinst == -1) {
		/* This assumes that all instances run at the same IPL. */
		mutex_init(&pcic_deb_mtx, NULL, MUTEX_DRIVER, NULL);
		cv_init(&pcic_deb_cv, NULL, CV_DRIVER, NULL);
		pcic_deb_threadid = thread_create((caddr_t)NULL, 0,
		    pcic_deb_thread, (caddr_t)NULL, 0, &p0, TS_RUN,
		    v.v_maxsyspri - 2);
	}
	pcic_maxinst = max(pcic_maxinst, ddi_get_instance(dip));
	/*
	 * Setup a debounce timeout to do an initial card detect
	 * and enable interrupts.
	 */
	for (j = 0; j < pcic->pc_numsockets; j++) {
		pcic->pc_sockets[j].pcs_debounce_id =
		    pcic_add_debqueue(&pcic->pc_sockets[j],
		    drv_usectohz(pcic_debounce_time));
	}

	return (i);

isa_exit2:
	mutex_destroy(&pcic->intr_lock);
	mutex_destroy(&pcic->pc_lock);
	for (j = i; j < 0; j--)
		(void) ddi_intr_free(pcic->pc_intr_htblp[j]);
isa_exit1:
	(void) pcmcia_return_intr(dip, pcic->pc_sockets[i].pcs_smi);
	ddi_regs_map_free(&pcic->handle);
	if (pcic->pc_flags & PCF_PCIBUS)
		ddi_regs_map_free(&pcic->cfg_handle);
	kmem_free(pcic->pc_intr_htblp, pcic->pc_numsockets *
	    sizeof (ddi_intr_handle_t));
	kmem_free(pcic, sizeof (pcicdev_t));
		return (DDI_FAILURE);

pci_exit2:
	mutex_destroy(&pcic->intr_lock);
	mutex_destroy(&pcic->pc_lock);
	(void) ddi_intr_free(pcic->pc_pci_intr_hdlp[0]);
pci_exit1:
	ddi_regs_map_free(&pcic->handle);
	if (pcic->pc_flags & PCF_PCIBUS)
		ddi_regs_map_free(&pcic->cfg_handle);
	kmem_free(pcic->pc_pci_intr_hdlp, sizeof (ddi_intr_handle_t));
	kmem_free(pcic, sizeof (pcicdev_t));
	return (DDI_FAILURE);
}

/*
 * pcic_detach()
 *	request to detach from the system
 */
static int
pcic_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;
	int i;

	switch (cmd) {
	case DDI_DETACH:
		/* don't detach if the nexus still talks to us */
		if (pcic->pc_callback != NULL)
			return (DDI_FAILURE);

		/* kill off the pm simulation */
		if (pcic->pc_pmtimer)
			(void) untimeout(pcic->pc_pmtimer);

		/* turn everything off for all sockets and chips */
		for (i = 0; i < pcic->pc_numsockets; i++) {
			if (pcic->pc_sockets[i].pcs_debounce_id)
				pcic_rm_debqueue(
				    pcic->pc_sockets[i].pcs_debounce_id);
			pcic->pc_sockets[i].pcs_debounce_id = 0;

			pcic_putb(pcic, i, PCIC_MANAGEMENT_INT, 0);
			pcic_putb(pcic, i, PCIC_CARD_DETECT, 0);
			pcic_putb(pcic, i, PCIC_MAPPING_ENABLE, 0);
			/* disable interrupts and put card into RESET */
			pcic_putb(pcic, i, PCIC_INTERRUPT, 0);
		}
		(void) ddi_intr_disable(pcic->pc_pci_intr_hdlp[0]);
		(void) ddi_intr_remove_handler(pcic->pc_pci_intr_hdlp[0]);
		(void) ddi_intr_free(pcic->pc_pci_intr_hdlp[0]);
		kmem_free(pcic->pc_pci_intr_hdlp, sizeof (ddi_intr_handle_t));
		pcic->pc_flags = 0;
		mutex_destroy(&pcic->pc_lock);
		mutex_destroy(&pcic->intr_lock);
		cv_destroy(&pcic->pm_cv);
		if (pcic->pc_flags & PCF_PCIBUS)
			ddi_regs_map_free(&pcic->cfg_handle);
		if (pcic->handle)
			ddi_regs_map_free(&pcic->handle);
		kmem_free(pcic, sizeof (pcicdev_t));
		ddi_soft_state_free(pcic_soft_state_p, ddi_get_instance(dip));
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
	case DDI_PM_SUSPEND:
		/*
		 * we got a suspend event (either real or imagined)
		 * so notify the nexus proper that all existing cards
		 * should go away.
		 */
		mutex_enter(&pcic->pc_lock);
#ifdef CARDBUS
		if (pcic->pc_flags & PCF_CARDBUS) {
			for (i = 0; i < pcic->pc_numsockets; i++) {
				if ((pcic->pc_sockets[i].pcs_flags &
				    (PCS_CARD_PRESENT|PCS_CARD_ISCARDBUS)) ==
				    (PCS_CARD_PRESENT|PCS_CARD_ISCARDBUS)) {

					pcmcia_cb_suspended(
					    pcic->pc_sockets[i].pcs_socket);
				}
			}

			cardbus_save_children(ddi_get_child(dip));
		}
#endif
		/* turn everything off for all sockets and chips */
		for (i = 0; i < pcic->pc_numsockets; i++) {
			if (pcic->pc_sockets[i].pcs_debounce_id)
				pcic_rm_debqueue(
				    pcic->pc_sockets[i].pcs_debounce_id);
			pcic->pc_sockets[i].pcs_debounce_id = 0;

			pcic_putb(pcic, i, PCIC_MANAGEMENT_INT, 0);
			pcic_putb(pcic, i, PCIC_CARD_DETECT, 0);
			pcic_putb(pcic, i, PCIC_MAPPING_ENABLE, 0);
			/* disable interrupts and put card into RESET */
			pcic_putb(pcic, i, PCIC_INTERRUPT, 0);
			pcic_putb(pcic, i, PCIC_POWER_CONTROL, 0);
			if (pcic->pc_flags & PCF_CBPWRCTL)
				pcic_putcb(pcic, CB_CONTROL, 0);

			if (pcic->pc_sockets[i].pcs_flags & PCS_CARD_PRESENT) {
				pcic->pc_sockets[i].pcs_flags = PCS_STARTING;
				/*
				 * Because we are half way through a save
				 * all this does is schedule a removal event
				 * to cs for when the system comes back.
				 * This doesn't actually matter.
				 */
				if (!pcic_do_pcmcia_sr && pcic_do_removal &&
				    pcic->pc_callback) {
					PC_CALLBACK(pcic->dip, pcic->pc_cb_arg,
					    PCE_CARD_REMOVAL,
					    pcic->pc_sockets[i].pcs_socket);
				}
			}
		}

		pcic->pc_flags |= PCF_SUSPENDED;
		mutex_exit(&pcic->pc_lock);

		/*
		 * when true power management exists, save the adapter
		 * state here to enable a recovery.  For the emulation
		 * condition, the state is gone
		 */
		return (DDI_SUCCESS);

	default:
		return (EINVAL);
	}
}

static uint32_t pcic_tisysctl_onbits = ((1<<27) | (1<<15) | (1<<14));
static uint32_t pcic_tisysctl_offbits = 0;
static uint32_t pcic_default_latency = 0x40;

static void
pcic_setup_adapter(pcicdev_t *pcic)
{
	int i;
	int value, flags;

#if defined(__i386) || defined(__amd64)
	pci_regspec_t *reg;
	uchar_t bus, dev, func;
	uint_t classcode;
	int length;
#endif

	if (pcic->pc_flags & PCF_PCIBUS) {
		/*
		 * all PCI-to-PCMCIA bus bridges need memory and I/O enabled
		 */
		flags = (PCIC_ENABLE_IO | PCIC_ENABLE_MEM);
		pcic_iomem_pci_ctl(pcic->cfg_handle, pcic->cfgaddr, flags);
	}
	/* enable each socket */
	for (i = 0; i < pcic->pc_numsockets; i++) {
		pcic->pc_sockets[i].pcs_flags = 0;
		/* find out the socket capabilities (I/O vs memory) */
		value = pcic_getb(pcic, i,
		    PCIC_CHIP_REVISION) & PCIC_REV_ID_MASK;
		if (value == PCIC_REV_ID_IO || value == PCIC_REV_ID_BOTH)
			pcic->pc_sockets[i].pcs_flags |= PCS_SOCKET_IO;

		/* disable all windows just in case */
		pcic_putb(pcic, i, PCIC_MAPPING_ENABLE, 0);

		switch (pcic->pc_type) {
			uint32_t cfg32;
			uint16_t cfg16;
			uint8_t cfg;

		    /* enable extended registers for Vadem */
			case PCIC_VADEM_VG469:
			case PCIC_VADEM:

			/* enable card status change interrupt for socket */
			break;

			case PCIC_I82365SL:
			break;

			case PCIC_CL_PD6710:
			pcic_putb(pcic, 0, PCIC_MISC_CTL_2, PCIC_LED_ENABLE);
			break;

			/*
			 * On the CL_6730, we need to set up the interrupt
			 * signalling mode (PCI mode) and set the SMI and
			 * IRQ interrupt lines to PCI/level-mode.
			 */
			case PCIC_CL_PD6730:
			switch (pcic->pc_intr_mode) {
			case PCIC_INTR_MODE_PCI_1:
				clext_reg_write(pcic, i, PCIC_CLEXT_MISC_CTL_3,
				    ((clext_reg_read(pcic, i,
				    PCIC_CLEXT_MISC_CTL_3) &
				    ~PCIC_CLEXT_INT_PCI) |
				    PCIC_CLEXT_INT_PCI));
				clext_reg_write(pcic, i, PCIC_CLEXT_EXT_CTL_1,
				    (PCIC_CLEXT_IRQ_LVL_MODE |
				    PCIC_CLEXT_SMI_LVL_MODE));
				cfg = PCIC_CL_LP_DYN_MODE;
				pcic_putb(pcic, i, PCIC_MISC_CTL_2, cfg);
				break;
			case PCIC_INTR_MODE_ISA:
				break;
			}
			break;
			/*
			 * On the CL_6729, we set the SMI and IRQ interrupt
			 *	lines to PCI/level-mode. as well as program the
			 *	correct clock speed divider bit.
			 */
			case PCIC_CL_PD6729:
			switch (pcic->pc_intr_mode) {
			case PCIC_INTR_MODE_PCI_1:
				clext_reg_write(pcic, i, PCIC_CLEXT_EXT_CTL_1,
				    (PCIC_CLEXT_IRQ_LVL_MODE |
				    PCIC_CLEXT_SMI_LVL_MODE));

				break;
			case PCIC_INTR_MODE_ISA:
				break;
			}
			if (pcic->bus_speed > PCIC_PCI_25MHZ && i == 0) {
				cfg = 0;
				cfg |= PCIC_CL_TIMER_CLK_DIV;
				pcic_putb(pcic, i, PCIC_MISC_CTL_2, cfg);
			}
			break;
			case PCIC_INTEL_i82092:
			cfg = PCIC_82092_EN_TIMING;
			if (pcic->bus_speed < PCIC_SYSCLK_33MHZ)
				cfg |= PCIC_82092_PCICLK_25MHZ;
			ddi_put8(pcic->cfg_handle, pcic->cfgaddr +
			    PCIC_82092_PCICON, cfg);
			break;
			case PCIC_TI_PCI1130:
			case PCIC_TI_PCI1131:
			case PCIC_TI_PCI1250:
			case PCIC_TI_PCI1031:
			cfg = ddi_get8(pcic->cfg_handle,
			    pcic->cfgaddr + PCIC_DEVCTL_REG);
			cfg &= ~PCIC_DEVCTL_INTR_MASK;
			switch (pcic->pc_intr_mode) {
			case PCIC_INTR_MODE_ISA:
				cfg |= PCIC_DEVCTL_INTR_ISA;
				break;
			}
#ifdef PCIC_DEBUG
			if (pcic_debug) {
				cmn_err(CE_CONT, "pcic_setup_adapter: "
				    "write reg 0x%x=%x \n",
				    PCIC_DEVCTL_REG, cfg);
			}
#endif
			ddi_put8(pcic->cfg_handle,
			    pcic->cfgaddr + PCIC_DEVCTL_REG,
			    cfg);

			cfg = ddi_get8(pcic->cfg_handle,
			    pcic->cfgaddr + PCIC_CRDCTL_REG);
			cfg &= ~(PCIC_CRDCTL_PCIINTR|PCIC_CRDCTL_PCICSC|
			    PCIC_CRDCTL_PCIFUNC);
			switch (pcic->pc_intr_mode) {
			case PCIC_INTR_MODE_PCI_1:
				cfg |= PCIC_CRDCTL_PCIINTR |
				    PCIC_CRDCTL_PCICSC |
				    PCIC_CRDCTL_PCIFUNC;
				pcic->pc_flags |= PCF_USE_SMI;
				break;
			}
#ifdef PCIC_DEBUG
			if (pcic_debug) {
				cmn_err(CE_CONT, "pcic_setup_adapter: "
				    " write reg 0x%x=%x \n",
				    PCIC_CRDCTL_REG, cfg);
			}
#endif
			ddi_put8(pcic->cfg_handle,
			    pcic->cfgaddr + PCIC_CRDCTL_REG,
			    cfg);
			break;
			case PCIC_TI_PCI1221:
			case PCIC_TI_PCI1225:
			cfg = ddi_get8(pcic->cfg_handle,
			    pcic->cfgaddr + PCIC_DEVCTL_REG);
			cfg |= (PCIC_DEVCTL_INTR_DFLT | PCIC_DEVCTL_3VCAPABLE);
#ifdef PCIC_DEBUG
			if (pcic_debug) {
				cmn_err(CE_CONT, "pcic_setup_adapter: "
				    " write reg 0x%x=%x \n",
				    PCIC_DEVCTL_REG, cfg);
			}
#endif
			ddi_put8(pcic->cfg_handle,
			    pcic->cfgaddr + PCIC_DEVCTL_REG, cfg);

			cfg = ddi_get8(pcic->cfg_handle,
			    pcic->cfgaddr + PCIC_DIAG_REG);
			if (pcic->pc_type == PCIC_TI_PCI1225) {
				cfg |= (PCIC_DIAG_CSC | PCIC_DIAG_ASYNC);
			} else {
				cfg |= PCIC_DIAG_ASYNC;
			}
			pcic->pc_flags |= PCF_USE_SMI;
#ifdef PCIC_DEBUG
			if (pcic_debug) {
				cmn_err(CE_CONT, "pcic_setup_adapter: "
				    " write reg 0x%x=%x \n",
				    PCIC_DIAG_REG, cfg);
			}
#endif
			ddi_put8(pcic->cfg_handle,
			    pcic->cfgaddr + PCIC_DIAG_REG, cfg);
			break;
			case PCIC_TI_PCI1520:
			case PCIC_TI_PCI1510:
			case PCIC_TI_VENDOR:
			if (pcic->pc_intr_mode == PCIC_INTR_MODE_ISA) {
				/* functional intr routed by ExCA register */
				cfg = ddi_get8(pcic->cfg_handle,
				    pcic->cfgaddr + PCIC_BRIDGE_CTL_REG);
				cfg |= PCIC_FUN_INT_MOD_ISA;
				ddi_put8(pcic->cfg_handle,
				    pcic->cfgaddr + PCIC_BRIDGE_CTL_REG,
				    cfg);

				/* IRQ serialized interrupts */
				cfg = ddi_get8(pcic->cfg_handle,
				    pcic->cfgaddr + PCIC_DEVCTL_REG);
				cfg &= ~PCIC_DEVCTL_INTR_MASK;
				cfg |= PCIC_DEVCTL_INTR_ISA;
				ddi_put8(pcic->cfg_handle,
				    pcic->cfgaddr + PCIC_DEVCTL_REG,
				    cfg);
				break;
			}

			/* CSC interrupt routed to PCI */
			cfg = ddi_get8(pcic->cfg_handle,
			    pcic->cfgaddr + PCIC_DIAG_REG);
			cfg |= (PCIC_DIAG_CSC | PCIC_DIAG_ASYNC);
			ddi_put8(pcic->cfg_handle,
			    pcic->cfgaddr + PCIC_DIAG_REG, cfg);

#if defined(__i386) || defined(__amd64)
			/*
			 * Some TI chips have 2 cardbus slots(function0 and
			 * function1), and others may have just 1 cardbus slot.
			 * The interrupt routing register is shared between the
			 * 2 functions and can only be accessed through
			 * function0. Here we check the presence of the second
			 * cardbus slot and do the right thing.
			 */

			if (ddi_getlongprop(DDI_DEV_T_ANY, pcic->dip,
			    DDI_PROP_DONTPASS, "reg", (caddr_t)&reg,
			    &length) != DDI_PROP_SUCCESS) {
				cmn_err(CE_WARN,
				    "pcic_setup_adapter(), failed to"
				    " read reg property\n");
				break;
			}

			bus = PCI_REG_BUS_G(reg->pci_phys_hi);
			dev = PCI_REG_DEV_G(reg->pci_phys_hi);
			func = PCI_REG_FUNC_G(reg->pci_phys_hi);
			kmem_free((caddr_t)reg, length);

			if (func != 0) {
				break;
			}

			classcode = (*pci_getl_func)(bus, dev, 1,
			    PCI_CONF_REVID);
			classcode >>= 8;
			if (classcode != 0x060700 &&
			    classcode != 0x060500) {
				break;
			}

			/* Parallel PCI interrupts only */
			cfg = ddi_get8(pcic->cfg_handle,
			    pcic->cfgaddr + PCIC_DEVCTL_REG);
			cfg &= ~PCIC_DEVCTL_INTR_MASK;
			ddi_put8(pcic->cfg_handle,
			    pcic->cfgaddr + PCIC_DEVCTL_REG,
			    cfg);

			/* tie INTA and INTB together */
			cfg = ddi_get8(pcic->cfg_handle,
			    (pcic->cfgaddr + PCIC_SYSCTL_REG + 3));
			cfg |= PCIC_SYSCTL_INTRTIE;
			ddi_put8(pcic->cfg_handle, (pcic->cfgaddr +
			    PCIC_SYSCTL_REG + 3), cfg);
#endif

			break;
			case PCIC_TI_PCI1410:
			cfg = ddi_get8(pcic->cfg_handle,
			    pcic->cfgaddr + PCIC_DIAG_REG);
			cfg |= (PCIC_DIAG_CSC | PCIC_DIAG_ASYNC);
			ddi_put8(pcic->cfg_handle,
			    pcic->cfgaddr + PCIC_DIAG_REG, cfg);
			break;
			case PCIC_TOSHIBA_TOPIC100:
			case PCIC_TOSHIBA_TOPIC95:
			case PCIC_TOSHIBA_VENDOR:
			cfg = ddi_get8(pcic->cfg_handle, pcic->cfgaddr +
			    PCIC_TOSHIBA_SLOT_CTL_REG);
			cfg |= (PCIC_TOSHIBA_SCR_SLOTON |
			    PCIC_TOSHIBA_SCR_SLOTEN);
			cfg &= (~PCIC_TOSHIBA_SCR_PRT_MASK);
			cfg |= PCIC_TOSHIBA_SCR_PRT_3E2;
			ddi_put8(pcic->cfg_handle, pcic->cfgaddr +
			    PCIC_TOSHIBA_SLOT_CTL_REG, cfg);
			cfg = ddi_get8(pcic->cfg_handle, pcic->cfgaddr +
			    PCIC_TOSHIBA_INTR_CTL_REG);
			switch (pcic->pc_intr_mode) {
			case PCIC_INTR_MODE_ISA:
				cfg &= ~PCIC_TOSHIBA_ICR_SRC;
				ddi_put8(pcic->cfg_handle,
				    pcic->cfgaddr +
				    PCIC_TOSHIBA_INTR_CTL_REG, cfg);

				cfg = ddi_get8(pcic->cfg_handle,
				    pcic->cfgaddr + PCIC_BRIDGE_CTL_REG);
				cfg |= PCIC_FUN_INT_MOD_ISA;
				ddi_put8(pcic->cfg_handle,
				    pcic->cfgaddr + PCIC_BRIDGE_CTL_REG,
				    cfg);
				break;
			case PCIC_INTR_MODE_PCI_1:
				cfg |= PCIC_TOSHIBA_ICR_SRC;
				cfg &= (~PCIC_TOSHIBA_ICR_PIN_MASK);
				cfg |= PCIC_TOSHIBA_ICR_PIN_INTA;
				ddi_put8(pcic->cfg_handle,
				    pcic->cfgaddr +
				    PCIC_TOSHIBA_INTR_CTL_REG, cfg);
				break;
			}
			break;
			case PCIC_O2MICRO_VENDOR:
			cfg32 = ddi_get32(pcic->cfg_handle,
			    (uint32_t *)(pcic->cfgaddr +
			    PCIC_O2MICRO_MISC_CTL));
			switch (pcic->pc_intr_mode) {
			case PCIC_INTR_MODE_ISA:
				cfg32 |= (PCIC_O2MICRO_ISA_LEGACY |
				    PCIC_O2MICRO_INT_MOD_PCI);
				ddi_put32(pcic->cfg_handle,
				    (uint32_t *)(pcic->cfgaddr +
				    PCIC_O2MICRO_MISC_CTL),
				    cfg32);
				cfg = ddi_get8(pcic->cfg_handle,
				    pcic->cfgaddr + PCIC_BRIDGE_CTL_REG);
				cfg |= PCIC_FUN_INT_MOD_ISA;
				ddi_put8(pcic->cfg_handle,
				    pcic->cfgaddr + PCIC_BRIDGE_CTL_REG,
				    cfg);
				break;
			case PCIC_INTR_MODE_PCI_1:
				cfg32 &= ~PCIC_O2MICRO_ISA_LEGACY;
				cfg32 |= PCIC_O2MICRO_INT_MOD_PCI;
				ddi_put32(pcic->cfg_handle,
				    (uint32_t *)(pcic->cfgaddr +
				    PCIC_O2MICRO_MISC_CTL),
				    cfg32);
				break;
			}
			break;
			case PCIC_RICOH_VENDOR:
			if (pcic->pc_intr_mode == PCIC_INTR_MODE_ISA) {
				cfg16 = ddi_get16(pcic->cfg_handle,
				    (uint16_t *)(pcic->cfgaddr +
				    PCIC_RICOH_MISC_CTL_2));
				cfg16 |= (PCIC_RICOH_CSC_INT_MOD |
				    PCIC_RICOH_FUN_INT_MOD);
				ddi_put16(pcic->cfg_handle,
				    (uint16_t *)(pcic->cfgaddr +
				    PCIC_RICOH_MISC_CTL_2),
				    cfg16);

				cfg16 = ddi_get16(pcic->cfg_handle,
				    (uint16_t *)(pcic->cfgaddr +
				    PCIC_RICOH_MISC_CTL));
				cfg16 |= PCIC_RICOH_SIRQ_EN;
				ddi_put16(pcic->cfg_handle,
				    (uint16_t *)(pcic->cfgaddr +
				    PCIC_RICOH_MISC_CTL),
				    cfg16);

				cfg = ddi_get8(pcic->cfg_handle,
				    pcic->cfgaddr + PCIC_BRIDGE_CTL_REG);
				cfg |= PCIC_FUN_INT_MOD_ISA;
				ddi_put8(pcic->cfg_handle,
				    pcic->cfgaddr + PCIC_BRIDGE_CTL_REG,
				    cfg);
			}
			break;
			default:
			break;
		} /* switch */

		/*
		 * The default value in the EEPROM (loaded on reset) for
		 * MFUNC0/MFUNC1 may be incorrect. Here we make sure that
		 * MFUNC0 is connected to INTA, and MFUNC1 is connected to
		 * INTB. This applies to all TI CardBus controllers.
		 */
		if ((pcic->pc_type >> 16) == PCIC_TI_VENDORID &&
		    pcic->pc_intr_mode == PCIC_INTR_MODE_PCI_1) {
			value = ddi_get32(pcic->cfg_handle,
			    (uint32_t *)(pcic->cfgaddr + PCIC_MFROUTE_REG));
			value &= ~0xff;
			ddi_put32(pcic->cfg_handle, (uint32_t *)(pcic->cfgaddr +
			    PCIC_MFROUTE_REG), value|PCIC_TI_MFUNC_SEL);
		}

		/* setup general card status change interrupt */
		switch (pcic->pc_type) {
			case PCIC_TI_PCI1225:
			case PCIC_TI_PCI1221:
			case PCIC_TI_PCI1031:
			case PCIC_TI_PCI1520:
			case PCIC_TI_PCI1410:
				pcic_putb(pcic, i, PCIC_MANAGEMENT_INT,
				    PCIC_CHANGE_DEFAULT);
				break;
			default:
				if (pcic->pc_intr_mode ==
				    PCIC_INTR_MODE_PCI_1) {
					pcic_putb(pcic, i, PCIC_MANAGEMENT_INT,
					    PCIC_CHANGE_DEFAULT);
					break;
				} else {
					pcic_putb(pcic, i, PCIC_MANAGEMENT_INT,
					    PCIC_CHANGE_DEFAULT |
					    (pcic->pc_sockets[i].pcs_smi << 4));
					break;
				}
		}

		pcic->pc_flags |= PCF_INTRENAB;

		/* take card out of RESET */
		pcic_putb(pcic, i, PCIC_INTERRUPT, PCIC_RESET);
		/* turn power off and let CS do this */
		pcic_putb(pcic, i, PCIC_POWER_CONTROL, 0);

		/* final chip specific initialization */
		switch (pcic->pc_type) {
			case PCIC_VADEM:
			pcic_putb(pcic, i, PCIC_VG_CONTROL,
			    PCIC_VC_DELAYENABLE);
			pcic->pc_flags |= PCF_DEBOUNCE;
			/* FALLTHROUGH */
			case PCIC_I82365SL:
			pcic_putb(pcic, i, PCIC_GLOBAL_CONTROL,
			    PCIC_GC_CSC_WRITE);
			/* clear any pending interrupts */
			value = pcic_getb(pcic, i, PCIC_CARD_STATUS_CHANGE);
			pcic_putb(pcic, i, PCIC_CARD_STATUS_CHANGE, value);
			break;
		    /* The 82092 uses PCI config space to enable interrupts */
			case PCIC_INTEL_i82092:
			pcic_82092_smiirq_ctl(pcic, i, PCIC_82092_CTL_SMI,
			    PCIC_82092_INT_ENABLE);
			break;
			case PCIC_CL_PD6729:
			if (pcic->bus_speed >= PCIC_PCI_DEF_SYSCLK && i == 0) {
				value = pcic_getb(pcic, i, PCIC_MISC_CTL_2);
				pcic_putb(pcic, i, PCIC_MISC_CTL_2,
				    value | PCIC_CL_TIMER_CLK_DIV);
			}
			break;
		} /* switch */

#if defined(PCIC_DEBUG)
		if (pcic_debug)
			cmn_err(CE_CONT,
			    "socket %d value=%x, flags = %x (%s)\n",
			    i, value, pcic->pc_sockets[i].pcs_flags,
			    (pcic->pc_sockets[i].pcs_flags &
			    PCS_CARD_PRESENT) ?
			"card present" : "no card");
#endif
	}
}

/*
 * pcic_intr(caddr_t, caddr_t)
 *	interrupt handler for the PCIC style adapter
 *	handles all basic interrupts and also checks
 *	for status changes and notifies the nexus if
 *	necessary
 *
 *	On PCI bus adapters, also handles all card
 *	IO interrupts.
 */
/*ARGSUSED*/
uint32_t
pcic_intr(caddr_t arg1, caddr_t arg2)
{
	pcicdev_t *pcic = (pcicdev_t *)arg1;
	int value = 0, i, ret = DDI_INTR_UNCLAIMED;
	uint8_t status;
	uint_t io_ints;

#if defined(PCIC_DEBUG)
	pcic_err(pcic->dip, 0xf,
	    "pcic_intr: enter pc_flags=0x%x PCF_ATTACHED=0x%x"
	    " pc_numsockets=%d \n",
	    pcic->pc_flags, PCF_ATTACHED, pcic->pc_numsockets);
#endif

	if (!(pcic->pc_flags & PCF_ATTACHED))
		return (DDI_INTR_UNCLAIMED);

	mutex_enter(&pcic->intr_lock);

	if (pcic->pc_flags & PCF_SUSPENDED) {
		mutex_exit(&pcic->intr_lock);
		return (ret);
	}

	/*
	 * need to change to only ACK and touch the slot that
	 * actually caused the interrupt.  Currently everything
	 * is acked
	 *
	 * we need to look at all known sockets to determine
	 * what might have happened, so step through the list
	 * of them
	 */

	/*
	 * Set the bitmask for IO interrupts to initially include all sockets
	 */
	io_ints = (1 << pcic->pc_numsockets) - 1;

	for (i = 0; i < pcic->pc_numsockets; i++) {
		int card_type;
		pcic_socket_t *sockp;
		int value_cb = 0;

		sockp = &pcic->pc_sockets[i];
		/* get the socket's I/O addresses */

		if (sockp->pcs_flags & PCS_WAITING) {
			io_ints &= ~(1 << i);
			continue;
		}

		if (sockp->pcs_flags & PCS_CARD_IO)
			card_type = IF_IO;
		else
			card_type = IF_MEMORY;

		if (pcic->pc_io_type == PCIC_IO_TYPE_YENTA)
			value_cb = pcic_getcb(pcic, CB_STATUS_EVENT);

		value = pcic_change(pcic, i);

		if ((value != 0) || (value_cb != 0)) {
			int x = pcic->pc_cb_arg;

			ret = DDI_INTR_CLAIMED;

#if defined(PCIC_DEBUG)
			pcic_err(pcic->dip, 0x9,
			    "card_type = %d, value_cb = 0x%x\n",
			    card_type,
			    value_cb ? value_cb :
			    pcic_getcb(pcic, CB_STATUS_EVENT));
			if (pcic_debug)
				cmn_err(CE_CONT,
				    "\tchange on socket %d (%x)\n", i,
				    value);
#endif
			/* find out what happened */
			status = pcic_getb(pcic, i, PCIC_INTERFACE_STATUS);

			/* acknowledge the interrupt */
			if (value_cb)
				pcic_putcb(pcic, CB_STATUS_EVENT, value_cb);

			if (value)
				pcic_putb(pcic, i, PCIC_CARD_STATUS_CHANGE,
				    value);

			if (pcic->pc_callback == NULL) {
				/* if not callback handler, nothing to do */
				continue;
			}

			/* Card Detect */
			if (value & PCIC_CD_DETECT ||
			    value_cb & CB_PS_CCDMASK) {
				uint8_t irq;
#if defined(PCIC_DEBUG)
				if (pcic_debug)
					cmn_err(CE_CONT,
					    "\tcd_detect: status=%x,"
					    " flags=%x\n",
					    status, sockp->pcs_flags);
#else
#ifdef lint
				if (status == 0)
					status++;
#endif
#endif
				/*
				 * Turn off all interrupts for this socket here.
				 */
				irq = pcic_getb(pcic, sockp->pcs_socket,
				    PCIC_MANAGEMENT_INT);
				irq &= ~PCIC_CHANGE_MASK;
				pcic_putb(pcic, sockp->pcs_socket,
				    PCIC_MANAGEMENT_INT, irq);

				pcic_putcb(pcic, CB_STATUS_MASK, 0x0);

				/*
				 * Put the socket in debouncing state so that
				 * the leaf driver won't receive interrupts.
				 * Crucial for handling surprise-removal.
				 */
				sockp->pcs_flags |= PCS_DEBOUNCING;

				if (!sockp->pcs_cd_softint_flg) {
					sockp->pcs_cd_softint_flg = 1;
					(void) ddi_intr_trigger_softint(
					    sockp->pcs_cd_softint_hdl, NULL);
				}

				io_ints &= ~(1 << i);
			} /* PCIC_CD_DETECT */

			/* Ready/Change Detect */
			sockp->pcs_state ^= SBM_RDYBSY;
			if (card_type == IF_MEMORY && value & PCIC_RD_DETECT) {
				sockp->pcs_flags |= PCS_READY;
				PC_CALLBACK(pcic->dip, x, PCE_CARD_READY, i);
			}

			/* Battery Warn Detect */
			if (card_type == IF_MEMORY &&
			    value & PCIC_BW_DETECT &&
			    !(sockp->pcs_state & SBM_BVD2)) {
				sockp->pcs_state |= SBM_BVD2;
				PC_CALLBACK(pcic->dip, x,
				    PCE_CARD_BATTERY_WARN, i);
			}

			/* Battery Dead Detect */
			if (value & PCIC_BD_DETECT) {
				/*
				 * need to work out event if RI not enabled
				 * and card_type == IF_IO
				 */
				if (card_type == IF_MEMORY &&
				    !(sockp->pcs_state & SBM_BVD1)) {
					sockp->pcs_state |= SBM_BVD1;
					PC_CALLBACK(pcic->dip, x,
					    PCE_CARD_BATTERY_DEAD,
					    i);
				} else {
					/*
					 * information in pin replacement
					 * register if one is available
					 */
					PC_CALLBACK(pcic->dip, x,
					    PCE_CARD_STATUS_CHANGE,
					    i);
				} /* IF_MEMORY */
			} /* PCIC_BD_DETECT */
		} /* if pcic_change */
		/*
		 * for any controllers that we can detect whether a socket
		 * had an interrupt for the PC Card, we should sort that out
		 * here.
		 */
	} /* for pc_numsockets */

	/*
	 * If we're on a PCI bus, we may need to cycle through each IO
	 *	interrupt handler that is registered since they all
	 *	share the same interrupt line.
	 */


#if defined(PCIC_DEBUG)
	pcic_err(pcic->dip, 0xf,
	    "pcic_intr: pc_intr_mode=%d pc_type=%x io_ints=0x%x\n",
	    pcic->pc_intr_mode, pcic->pc_type, io_ints);
#endif

	if (io_ints) {
		if (pcic_do_io_intr(pcic, io_ints) == DDI_INTR_CLAIMED)
			ret = DDI_INTR_CLAIMED;
	}

	mutex_exit(&pcic->intr_lock);

#if defined(PCIC_DEBUG)
	pcic_err(pcic->dip, 0xf,
	    "pcic_intr: ret=%d value=%d DDI_INTR_CLAIMED=%d\n",
	    ret, value, DDI_INTR_CLAIMED);
#endif

	return (ret);
}

/*
 * pcic_change()
 *	check to see if this socket had a change in state
 *	by checking the status change register
 */
static int
pcic_change(pcicdev_t *pcic, int socket)
{
	return (pcic_getb(pcic, socket, PCIC_CARD_STATUS_CHANGE));
}

/*
 * pcic_do_io_intr - calls client interrupt handlers
 */
static int
pcic_do_io_intr(pcicdev_t *pcic, uint32_t sockets)
{
	inthandler_t *tmp;
	int ret = DDI_INTR_UNCLAIMED;

#if defined(PCIC_DEBUG)
	pcic_err(pcic->dip, 0xf,
	    "pcic_do_io_intr: pcic=%p sockets=%d irq_top=%p\n",
	    (void *)pcic, (int)sockets, (void *)pcic->irq_top);
#endif

	if (pcic->irq_top != NULL) {
		tmp = pcic->irq_current;

		do {
		int cur = pcic->irq_current->socket;
		pcic_socket_t *sockp =
		    &pcic->pc_sockets[cur];

#if defined(PCIC_DEBUG)
		pcic_err(pcic->dip, 0xf,
		    "\t pcs_flags=0x%x PCS_CARD_PRESENT=0x%x\n",
		    sockp->pcs_flags, PCS_CARD_PRESENT);
		pcic_err(pcic->dip, 0xf,
		    "\t sockets=%d cur=%d intr=%p arg1=%p "
		    "arg2=%p\n",
		    sockets, cur, (void *)pcic->irq_current->intr,
		    pcic->irq_current->arg1,
		    pcic->irq_current->arg2);
#endif
		if ((sockp->pcs_flags & PCS_CARD_PRESENT) &&
		    !(sockp->pcs_flags & PCS_DEBOUNCING) &&
		    (sockets & (1 << cur))) {

			if ((*pcic->irq_current->intr)(pcic->irq_current->arg1,
			    pcic->irq_current->arg2) == DDI_INTR_CLAIMED)
				ret = DDI_INTR_CLAIMED;

#if defined(PCIC_DEBUG)
			pcic_err(pcic->dip, 0xf,
			    "\t ret=%d DDI_INTR_CLAIMED=%d\n",
			    ret, DDI_INTR_CLAIMED);
#endif
		}


		if ((pcic->irq_current = pcic->irq_current->next) == NULL)
					pcic->irq_current = pcic->irq_top;

		} while (pcic->irq_current != tmp);

		if ((pcic->irq_current = pcic->irq_current->next) == NULL)
					pcic->irq_current = pcic->irq_top;

	} else {
		ret = DDI_INTR_UNCLAIMED;
	}

#if defined(PCIC_DEBUG)
	pcic_err(pcic->dip, 0xf,
	    "pcic_do_io_intr: exit ret=%d DDI_INTR_CLAIMED=%d\n",
	    ret, DDI_INTR_CLAIMED);
#endif

	return (ret);

}

/*
 * pcic_inquire_adapter()
 *	SocketServices InquireAdapter function
 *	get characteristics of the physical adapter
 */
/*ARGSUSED*/
static int
pcic_inquire_adapter(dev_info_t *dip, inquire_adapter_t *config)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;

	config->NumSockets = pcic->pc_numsockets;
	config->NumWindows = pcic->pc_numsockets * PCIC_NUMWINSOCK;
	config->NumEDCs = 0;
	config->AdpCaps = 0;
	config->ActiveHigh = 0;
	config->ActiveLow = PCIC_AVAIL_IRQS;
	config->NumPower = pcic->pc_numpower;
	config->power_entry = pcic->pc_power; /* until we resolve this */
#if defined(PCIC_DEBUG)
	if (pcic_debug) {
		cmn_err(CE_CONT, "pcic_inquire_adapter:\n");
		cmn_err(CE_CONT, "\tNumSockets=%d\n", config->NumSockets);
		cmn_err(CE_CONT, "\tNumWindows=%d\n", config->NumWindows);
	}
#endif
	config->ResourceFlags = 0;
	switch (pcic->pc_intr_mode) {
	case PCIC_INTR_MODE_PCI_1:
		config->ResourceFlags |= RES_OWN_IRQ | RES_IRQ_NEXUS |
		    RES_IRQ_SHAREABLE;
		break;
	}
	return (SUCCESS);
}

/*
 * pcic_callback()
 *	The PCMCIA nexus calls us via this function
 *	in order to set the callback function we are
 *	to call the nexus with
 */
/*ARGSUSED*/
static int
pcic_callback(dev_info_t *dip, int (*handler)(), int arg)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;

	if (handler != NULL) {
		pcic->pc_callback = handler;
		pcic->pc_cb_arg  = arg;
		pcic->pc_flags |= PCF_CALLBACK;
	} else {
		pcic->pc_callback = NULL;
		pcic->pc_cb_arg = 0;
		pcic->pc_flags &= ~PCF_CALLBACK;
	}
	/*
	 * we're now registered with the nexus
	 * it is acceptable to do callbacks at this point.
	 * don't call back from here though since it could block
	 */
	return (PC_SUCCESS);
}

/*
 * pcic_calc_speed (pcicdev_t *pcic, uint32_t speed)
 *	calculate the speed bits from the specified memory speed
 *	there may be more to do here
 */

static int
pcic_calc_speed(pcicdev_t *pcic, uint32_t speed)
{
	uint32_t wspeed = 1;	/* assume 1 wait state when unknown */
	uint32_t bspeed = PCIC_ISA_DEF_SYSCLK;

	switch (pcic->pc_type) {
		case PCIC_I82365SL:
		case PCIC_VADEM:
		case PCIC_VADEM_VG469:
		default:
		/* Intel chip wants it in waitstates */
		wspeed = mhztons(PCIC_ISA_DEF_SYSCLK) * 3;
		if (speed <= wspeed)
			wspeed = 0;
		else if (speed <= (wspeed += mhztons(bspeed)))
			wspeed = 1;
		else if (speed <= (wspeed += mhztons(bspeed)))
			wspeed = 2;
		else
			wspeed = 3;
		wspeed <<= 6; /* put in right bit positions */
		break;

		case PCIC_INTEL_i82092:
		wspeed = SYSMEM_82092_80NS;
		if (speed > 80)
			wspeed = SYSMEM_82092_100NS;
		if (speed > 100)
			wspeed = SYSMEM_82092_150NS;
		if (speed > 150)
			wspeed = SYSMEM_82092_200NS;
		if (speed > 200)
			wspeed = SYSMEM_82092_250NS;
		if (speed > 250)
			wspeed = SYSMEM_82092_600NS;
		wspeed <<= 5;	/* put in right bit positions */
		break;

	} /* switch */

	return (wspeed);
}

/*
 * These values are taken from the PC Card Standard Electrical Specification.
 * Generally the larger value is taken if 2 are possible.
 */
static struct pcic_card_times {
	uint16_t cycle;	/* Speed as found in the atribute space of the card. */
	uint16_t setup;	/* Corresponding address setup time. */
	uint16_t width;	/* Corresponding width, OE or WE. */
	uint16_t hold;	/* Corresponding data or address hold time. */
} pcic_card_times[] = {

/*
 * Note: The rounded up times for 250, 200 & 150 have been increased
 * due to problems with the 3-Com ethernet cards (pcelx) on UBIIi.
 * See BugID 00663.
 */

/*
 * Rounded up times           Original times from
 * that add up to the         the PCMCIA Spec.
 * cycle time.
 */
	{600, 180, 370, 140},	/* 100, 300,  70 */
	{400, 120, 300, 90},	/* Made this one up */
	{250, 100, 190, 70},	/*  30, 150,  30 */
	{200, 80, 170, 70},	/*  20, 120,  30 */
	{150, 50, 110, 40},	/*  20,  80,  20 */
	{100, 40, 80, 40},	/*  10,  60,  15 */
	{0, 10, 60, 15}		/*  10,  60,  15 */
};

/*
 * pcic_set_cdtimers
 *	This is specific to several Cirrus Logic chips
 */
static void
pcic_set_cdtimers(pcicdev_t *pcic, int socket, uint32_t speed, int tset)
{
	int cmd, set, rec, offset, clk_pulse;
	struct pcic_card_times *ctp;

	if ((tset == IOMEM_CLTIMER_SET_1) || (tset == SYSMEM_CLTIMER_SET_1))
		offset = 3;
	else
		offset = 0;

	clk_pulse = mhztons(pcic->bus_speed);
	for (ctp = pcic_card_times; speed < ctp->cycle; ctp++)
		;

	/*
	 * Add (clk_pulse/2) and an extra 1 to account for rounding errors.
	 */
	set = ((ctp->setup + 10 + 1 + (clk_pulse/2))/clk_pulse) - 1;
	if (set < 0)
		set = 0;

	cmd = ((ctp->width + 10 + 1 + (clk_pulse/2))/clk_pulse) - 1;
	if (cmd < 0)
		cmd = 0;

	rec = ((ctp->hold + 10 + 1 + (clk_pulse/2))/clk_pulse) - 2;
	if (rec < 0)
		rec = 0;

#if defined(PCIC_DEBUG)
	pcic_err(pcic->dip, 8, "pcic_set_cdtimers(%d, Timer Set %d)\n"
	    "ct=%d, cp=%d, cmd=0x%x, setup=0x%x, rec=0x%x\n",
	    (unsigned)speed, offset == 3 ? 1 : 0,
	    ctp->cycle, clk_pulse, cmd, set, rec);
#endif

	pcic_putb(pcic, socket, PCIC_TIME_COMMAND_0 + offset, cmd);
	pcic_putb(pcic, socket, PCIC_TIME_SETUP_0 + offset, set);
	pcic_putb(pcic, socket, PCIC_TIME_RECOVER_0 + offset, rec);
}

/*
 * pcic_set_window
 *	essentially the same as the Socket Services specification
 *	We use socket and not adapter since they are identifiable
 *	but the rest is the same
 *
 *	dip	pcic driver's device information
 *	window	parameters for the request
 */
static int
pcic_set_window(dev_info_t *dip, set_window_t *window)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;
	int select;
	int socket, pages, which, ret;
	pcic_socket_t *sockp = &pcic->pc_sockets[window->socket];
	ra_return_t res;
	ndi_ra_request_t req;
	uint32_t base = window->base;

#if defined(PCIC_DEBUG)
	if (pcic_debug) {
		cmn_err(CE_CONT, "pcic_set_window: entered\n");
		cmn_err(CE_CONT,
		    "\twindow=%d, socket=%d, WindowSize=%d, speed=%d\n",
		    window->window, window->socket, window->WindowSize,
		    window->speed);
		cmn_err(CE_CONT,
		    "\tbase=%x, state=%x\n", (unsigned)window->base,
		    (unsigned)window->state);
	}
#endif

	/*
	 * do some basic sanity checking on what we support
	 * we don't do paged mode
	 */
	if (window->state & WS_PAGED) {
		cmn_err(CE_WARN, "pcic_set_window: BAD_ATTRIBUTE\n");
		return (BAD_ATTRIBUTE);
	}

	/*
	 * we don't care about previous mappings.
	 * Card Services will deal with that so don't
	 * even check
	 */

	socket = window->socket;

	if (!(window->state & WS_IO)) {
		int win, tmp;
		pcs_memwin_t *memp;
#if defined(PCIC_DEBUG)
		if (pcic_debug)
			cmn_err(CE_CONT, "\twindow type is memory\n");
#endif
		/* this is memory window mapping */
		win = window->window % PCIC_NUMWINSOCK;
		tmp = window->window / PCIC_NUMWINSOCK;

		/* only windows 2-6 can do memory mapping */
		if (tmp != window->socket || win < PCIC_IOWINDOWS) {
			cmn_err(CE_CONT,
			    "\tattempt to map to non-mem window\n");
			return (BAD_WINDOW);
		}

		if (window->WindowSize == 0)
			window->WindowSize = MEM_MIN;
		else if ((window->WindowSize & (PCIC_PAGE-1)) != 0) {
			cmn_err(CE_WARN, "pcic_set_window: BAD_SIZE\n");
			return (BAD_SIZE);
		}

		mutex_enter(&pcic->pc_lock); /* protect the registers */

		memp = &sockp->pcs_windows[win].mem;
		memp->pcw_speed = window->speed;

		win -= PCIC_IOWINDOWS; /* put in right range */

		if (window->WindowSize != memp->pcw_len)
			which = memp->pcw_len;
		else
			which = 0;

		if (window->state & WS_ENABLED) {
			uint32_t wspeed;
#if defined(PCIC_DEBUG)
			if (pcic_debug) {
				cmn_err(CE_CONT,
				    "\tbase=%x, win=%d\n", (unsigned)base,
				    win);
				if (which)
					cmn_err(CE_CONT,
					    "\tneed to remap window\n");
			}
#endif

			if (which && (memp->pcw_status & PCW_MAPPED)) {
				ddi_regs_map_free(&memp->pcw_handle);
				res.ra_addr_lo = memp->pcw_base;
				res.ra_len = memp->pcw_len;
				(void) pcmcia_free_mem(memp->res_dip, &res);
				memp->pcw_status &= ~(PCW_MAPPED|PCW_ENABLED);
				memp->pcw_hostmem = NULL;
				memp->pcw_base = NULL;
				memp->pcw_len = 0;
			}

			which = window->WindowSize >> PAGE_SHIFT;

			if (!(memp->pcw_status & PCW_MAPPED)) {
				ret = 0;

				memp->pcw_base = base;
				bzero(&req, sizeof (req));
				req.ra_len = which << PAGE_SHIFT;
				req.ra_addr = (uint64_t)memp->pcw_base;
				req.ra_boundbase = pcic->pc_base;
				req.ra_boundlen  = pcic->pc_bound;
				req.ra_flags = (memp->pcw_base ?
				    NDI_RA_ALLOC_SPECIFIED : 0) |
				    NDI_RA_ALLOC_BOUNDED;
				req.ra_align_mask =
				    (PAGESIZE - 1) | (PCIC_PAGE - 1);
#if defined(PCIC_DEBUG)
					pcic_err(dip, 8,
					    "\tlen 0x%"PRIx64
					    "addr 0x%"PRIx64"bbase 0x%"PRIx64
					    " blen 0x%"PRIx64" flags 0x%x"
					    " algn 0x%"PRIx64"\n",
					    req.ra_len, req.ra_addr,
					    req.ra_boundbase,
					    req.ra_boundlen, req.ra_flags,
					    req.ra_align_mask);
#endif

				ret = pcmcia_alloc_mem(dip, &req, &res,
				    &memp->res_dip);
				if (ret == DDI_FAILURE) {
					mutex_exit(&pcic->pc_lock);
					cmn_err(CE_WARN,
					"\tpcmcia_alloc_mem() failed\n");
					return (BAD_SIZE);
				}
				memp->pcw_base = res.ra_addr_lo;
				base = memp->pcw_base;

#if defined(PCIC_DEBUG)
				if (pcic_debug)
					cmn_err(CE_CONT,
					    "\tsetwindow: new base=%x\n",
					    (unsigned)memp->pcw_base);
#endif
				memp->pcw_len = window->WindowSize;

				which = pcmcia_map_reg(pcic->dip,
				    window->child,
				    &res,
				    (uint32_t)(window->state &
				    0xffff) |
				    (window->socket << 16),
				    (caddr_t *)&memp->pcw_hostmem,
				    &memp->pcw_handle,
				    &window->attr, NULL);

				if (which != DDI_SUCCESS) {

					cmn_err(CE_WARN, "\tpcmcia_map_reg() "
					    "failed\n");

					res.ra_addr_lo = memp->pcw_base;
					res.ra_len = memp->pcw_len;
					(void) pcmcia_free_mem(memp->res_dip,
					    &res);

					mutex_exit(&pcic->pc_lock);

					return (BAD_WINDOW);
				}
				memp->pcw_status |= PCW_MAPPED;
#if defined(PCIC_DEBUG)
				if (pcic_debug)
					cmn_err(CE_CONT,
					    "\tmap=%x, hostmem=%p\n",
					    which,
					    (void *)memp->pcw_hostmem);
#endif
			} else {
				base = memp->pcw_base;
			}

			/* report the handle back to caller */
			window->handle = memp->pcw_handle;

#if defined(PCIC_DEBUG)
			if (pcic_debug) {
				cmn_err(CE_CONT,
				    "\twindow mapped to %x@%x len=%d\n",
				    (unsigned)window->base,
				    (unsigned)memp->pcw_base,
				    memp->pcw_len);
			}
#endif

			/* find the register set offset */
			select = win * PCIC_MEM_1_OFFSET;
#if defined(PCIC_DEBUG)
			if (pcic_debug)
				cmn_err(CE_CONT, "\tselect=%x\n", select);
#endif

			/*
			 * at this point, the register window indicator has
			 * been converted to be an offset from the first
			 * set of registers that are used for programming
			 * the window mapping and the offset used to select
			 * the correct set of registers to access the
			 * specified socket.  This allows basing everything
			 * off the _0 window
			 */

			/* map the physical page base address */
			which = (window->state & WS_16BIT) ? SYSMEM_DATA_16 : 0;
			which |= (window->speed <= MEM_SPEED_MIN) ?
			    SYSMEM_ZERO_WAIT : 0;

			/* need to select register set */
			select = PCIC_MEM_1_OFFSET * win;

			pcic_putb(pcic, socket,
			    PCIC_SYSMEM_0_STARTLOW + select,
			    SYSMEM_LOW(base));
			pcic_putb(pcic, socket,
			    PCIC_SYSMEM_0_STARTHI + select,
			    SYSMEM_HIGH(base) | which);

			/*
			 * Some adapters can decode window addresses greater
			 * than 16-bits worth, so handle them here.
			 */
			switch (pcic->pc_type) {
			case PCIC_INTEL_i82092:
				pcic_putb(pcic, socket,
				    PCIC_82092_CPAGE,
				    SYSMEM_EXT(base));
				break;
			case PCIC_CL_PD6729:
			case PCIC_CL_PD6730:
				clext_reg_write(pcic, socket,
				    PCIC_CLEXT_MMAP0_UA + win,
				    SYSMEM_EXT(base));
				break;
			case PCIC_TI_PCI1130:
				/*
				 * Note that the TI chip has one upper byte
				 * per socket so all windows get bound to a
				 * 16MB segment.  This must be detected and
				 * handled appropriately.  We can detect that
				 * it is done by seeing if the pc_base has
				 * changed and changing when the register
				 * is first set.  This will force the bounds
				 * to be correct.
				 */
				if (pcic->pc_bound == 0xffffffff) {
					pcic_putb(pcic, socket,
					    PCIC_TI_WINDOW_PAGE_PCI,
					    SYSMEM_EXT(base));
					pcic->pc_base = SYSMEM_EXT(base) << 24;
					pcic->pc_bound = 0x1000000;
				}
				break;
			case PCIC_TI_PCI1031:
			case PCIC_TI_PCI1131:
			case PCIC_TI_PCI1250:
			case PCIC_TI_PCI1225:
			case PCIC_TI_PCI1221:
			case PCIC_SMC_34C90:
			case PCIC_CL_PD6832:
			case PCIC_RICOH_RL5C466:
			case PCIC_TI_PCI1410:
			case PCIC_ENE_1410:
			case PCIC_TI_PCI1510:
			case PCIC_TI_PCI1520:
			case PCIC_O2_OZ6912:
			case PCIC_TI_PCI1420:
			case PCIC_ENE_1420:
			case PCIC_TI_VENDOR:
			case PCIC_TOSHIBA_TOPIC100:
			case PCIC_TOSHIBA_TOPIC95:
			case PCIC_TOSHIBA_VENDOR:
			case PCIC_RICOH_VENDOR:
			case PCIC_O2MICRO_VENDOR:
				pcic_putb(pcic, socket,
				    PCIC_YENTA_MEM_PAGE + win,
				    SYSMEM_EXT(base));
				break;
			default:
				cmn_err(CE_NOTE, "pcic_set_window: unknown "
				    "cardbus vendor:0x%X\n",
				    pcic->pc_type);
				pcic_putb(pcic, socket,
				    PCIC_YENTA_MEM_PAGE + win,
				    SYSMEM_EXT(base));

				break;
			} /* switch */

			/*
			 * specify the length of the mapped range
			 * we convert to pages (rounding up) so that
			 * the hardware gets the right thing
			 */
			pages = (window->WindowSize+PCIC_PAGE-1)/PCIC_PAGE;

			/*
			 * Setup this window's timing.
			 */
			switch (pcic->pc_type) {
			case PCIC_CL_PD6729:
			case PCIC_CL_PD6730:
			case PCIC_CL_PD6710:
			case PCIC_CL_PD6722:
				wspeed = SYSMEM_CLTIMER_SET_0;
				pcic_set_cdtimers(pcic, socket,
				    window->speed,
				    wspeed);
				break;

			case PCIC_INTEL_i82092:
			default:
				wspeed = pcic_calc_speed(pcic, window->speed);
				break;
			} /* switch */

#if defined(PCIC_DEBUG)
			if (pcic_debug)
				cmn_err(CE_CONT,
				    "\twindow %d speed bits = %x for "
				    "%dns\n",
				    win, (unsigned)wspeed, window->speed);
#endif

			pcic_putb(pcic, socket, PCIC_SYSMEM_0_STOPLOW + select,
			    SYSMEM_LOW(base +
			    (pages * PCIC_PAGE)-1));

			wspeed |= SYSMEM_HIGH(base + (pages * PCIC_PAGE)-1);
			pcic_putb(pcic, socket, PCIC_SYSMEM_0_STOPHI + select,
			    wspeed);

			/*
			 * now map the card's memory pages - we start with page
			 * 0
			 * we also default to AM -- set page might change it
			 */
			base = memp->pcw_base;
			pcic_putb(pcic, socket,
			    PCIC_CARDMEM_0_LOW + select,
			    CARDMEM_LOW(0 - (uint32_t)base));

			pcic_putb(pcic, socket,
			    PCIC_CARDMEM_0_HI + select,
			    CARDMEM_HIGH(0 - (uint32_t)base) |
			    CARDMEM_REG_ACTIVE);

			/*
			 * enable the window even though redundant
			 * and SetPage may do it again.
			 */
			select = pcic_getb(pcic, socket,
			    PCIC_MAPPING_ENABLE);
			select |= SYSMEM_WINDOW(win);
			pcic_putb(pcic, socket, PCIC_MAPPING_ENABLE, select);
			memp->pcw_offset = 0;
			memp->pcw_status |= PCW_ENABLED;
		} else {
			/*
			 * not only do we unmap the memory, the
			 * window has been turned off.
			 */
			if (which && memp->pcw_status & PCW_MAPPED) {
				ddi_regs_map_free(&memp->pcw_handle);
				res.ra_addr_lo = memp->pcw_base;
				res.ra_len = memp->pcw_len;
				(void) pcmcia_free_mem(memp->res_dip, &res);
				memp->pcw_hostmem = NULL;
				memp->pcw_status &= ~PCW_MAPPED;
			}

			/* disable current mapping */
			select = pcic_getb(pcic, socket, PCIC_MAPPING_ENABLE);
			select &= ~SYSMEM_WINDOW(win);
			pcic_putb(pcic, socket, PCIC_MAPPING_ENABLE, select);
			memp->pcw_status &= ~PCW_ENABLED;
		}
		memp->pcw_len = window->WindowSize;
		window->handle = memp->pcw_handle;
#if defined(PCIC_DEBUG)
		if (pcic_debug)
			xxdmp_all_regs(pcic, window->socket, -1);
#endif
	} else {
		/*
		 * This is a request for an IO window
		 */
		int win, tmp;
		pcs_iowin_t *winp;
				/* I/O windows */
#if defined(PCIC_DEBUG)
		if (pcic_debug)
			cmn_err(CE_CONT, "\twindow type is I/O\n");
#endif

		/* only windows 0 and 1 can do I/O */
		win = window->window % PCIC_NUMWINSOCK;
		tmp = window->window / PCIC_NUMWINSOCK;

		if (win >= PCIC_IOWINDOWS || tmp != window->socket) {
			cmn_err(CE_WARN,
			    "\twindow is out of range (%d)\n",
			    window->window);
			return (BAD_WINDOW);
		}

		mutex_enter(&pcic->pc_lock); /* protect the registers */

		winp = &sockp->pcs_windows[win].io;
		winp->pcw_speed = window->speed;
		if (window->WindowSize != 1 && window->WindowSize & 1) {
			/* we don't want an odd-size window */
			window->WindowSize++;
		}
		winp->pcw_len = window->WindowSize;

		if (window->state & WS_ENABLED) {
			if (winp->pcw_status & PCW_MAPPED) {
				ddi_regs_map_free(&winp->pcw_handle);
				res.ra_addr_lo = winp->pcw_base;
				res.ra_len = winp->pcw_len;
				(void) pcmcia_free_io(winp->res_dip, &res);
				winp->pcw_status &= ~(PCW_MAPPED|PCW_ENABLED);
			}

			/*
			 * if the I/O address wasn't allocated, allocate
			 *	it now. If it was allocated, it better
			 *	be free to use.
			 * The winp->pcw_offset value is set and used
			 *	later on if the particular adapter
			 *	that we're running on has the ability
			 *	to translate IO accesses to the card
			 *	(such as some adapters  in the Cirrus
			 *	Logic family).
			 */
			winp->pcw_offset = 0;

			/*
			 * Setup the request parameters for the
			 *	requested base and length. If
			 *	we're on an adapter that has
			 *	IO window offset registers, then
			 *	we don't need a specific base
			 *	address, just a length, and then
			 *	we'll cause the correct IO address
			 *	to be generated on the socket by
			 *	setting up the IO window offset
			 *	registers.
			 * For adapters that support this capability, we
			 *	always use the IO window offset registers,
			 *	even if the passed base/length would be in
			 *	range.
			 */
			base = window->base;
			bzero(&req, sizeof (req));
			req.ra_len = window->WindowSize;

			req.ra_addr = (uint64_t)
			    ((pcic->pc_flags & PCF_IO_REMAP) ? 0 : base);
			req.ra_flags = (req.ra_addr) ?
			    NDI_RA_ALLOC_SPECIFIED : 0;

			req.ra_flags |= NDI_RA_ALIGN_SIZE;
			/* need to rethink this */
			req.ra_boundbase = pcic->pc_iobase;
			req.ra_boundlen = pcic->pc_iobound;
			req.ra_flags |= NDI_RA_ALLOC_BOUNDED;

#if defined(PCIC_DEBUG)
				pcic_err(dip, 8,
				    "\tlen 0x%"PRIx64" addr 0x%"PRIx64
				    "bbase 0x%"PRIx64
				    "blen 0x%"PRIx64" flags 0x%x algn 0x%"
				    PRIx64"\n",
				    req.ra_len, (uint64_t)req.ra_addr,
				    req.ra_boundbase,
				    req.ra_boundlen, req.ra_flags,
				    req.ra_align_mask);
#endif

			/*
			 * Try to allocate the space. If we fail this,
			 *	return the appropriate error depending
			 *	on whether the caller specified a
			 *	specific base address or not.
			 */
			if (pcmcia_alloc_io(dip, &req, &res,
			    &winp->res_dip) == DDI_FAILURE) {
				winp->pcw_status &= ~PCW_ENABLED;
				mutex_exit(&pcic->pc_lock);
				cmn_err(CE_WARN, "Failed to alloc I/O:\n"
				    "\tlen 0x%" PRIx64 " addr 0x%" PRIx64
				    "bbase 0x%" PRIx64
				    "blen 0x%" PRIx64 "flags 0x%x"
				    "algn 0x%" PRIx64 "\n",
				    req.ra_len, req.ra_addr,
				    req.ra_boundbase,
				    req.ra_boundlen, req.ra_flags,
				    req.ra_align_mask);

				return (base?BAD_BASE:BAD_SIZE);
			} /* pcmcia_alloc_io */

			/*
			 * Don't change the original base. Either we use
			 * the offset registers below (PCF_IO_REMAP is set)
			 * or it was allocated correctly anyway.
			 */
			winp->pcw_base = res.ra_addr_lo;

#if defined(PCIC_DEBUG)
				pcic_err(dip, 8,
				    "\tsetwindow: new base=%x orig base 0x%x\n",
				    (unsigned)winp->pcw_base, base);
#endif

			if ((which = pcmcia_map_reg(pcic->dip,
			    window->child,
			    &res,
			    (uint32_t)(window->state &
			    0xffff) |
			    (window->socket << 16),
			    (caddr_t *)&winp->pcw_hostmem,
			    &winp->pcw_handle,
			    &window->attr,
			    base)) != DDI_SUCCESS) {

				cmn_err(CE_WARN, "pcmcia_map_reg()"
				    "failed\n");

					res.ra_addr_lo = winp->pcw_base;
					res.ra_len = winp->pcw_len;
					(void) pcmcia_free_io(winp->res_dip,
					    &res);

					mutex_exit(&pcic->pc_lock);
					return (BAD_WINDOW);
			}

			window->handle = winp->pcw_handle;
			winp->pcw_status |= PCW_MAPPED;

			/* find the register set offset */
			select = win * PCIC_IO_OFFSET;

#if defined(PCIC_DEBUG)
			if (pcic_debug) {
				cmn_err(CE_CONT,
				    "\tenable: window=%d, select=%x, "
				    "base=%x, handle=%p\n",
				    win, select,
				    (unsigned)window->base,
				    (void *)window->handle);
			}
#endif
			/*
			 * at this point, the register window indicator has
			 * been converted to be an offset from the first
			 * set of registers that are used for programming
			 * the window mapping and the offset used to select
			 * the correct set of registers to access the
			 * specified socket.  This allows basing everything
			 * off the _0 window
			 */

			/* map the I/O base in */
			pcic_putb(pcic, socket,
			    PCIC_IO_ADDR_0_STARTLOW + select,
			    LOW_BYTE((uint32_t)winp->pcw_base));
			pcic_putb(pcic, socket,
			    PCIC_IO_ADDR_0_STARTHI + select,
			    HIGH_BYTE((uint32_t)winp->pcw_base));

			pcic_putb(pcic, socket,
			    PCIC_IO_ADDR_0_STOPLOW + select,
			    LOW_BYTE((uint32_t)winp->pcw_base +
			    window->WindowSize - 1));
			pcic_putb(pcic, socket,
			    PCIC_IO_ADDR_0_STOPHI + select,
			    HIGH_BYTE((uint32_t)winp->pcw_base +
			    window->WindowSize - 1));

			/*
			 * We've got the requested IO space, now see if we
			 *	need to adjust the IO window offset registers
			 *	so that the correct IO address is generated
			 *	at the socket. If this window doesn't have
			 *	this capability, then we're all done setting
			 *	up the IO resources.
			 */
			if (pcic->pc_flags & PCF_IO_REMAP) {


				/*
				 * Note that only 16 bits are used to program
				 * the registers but leave 32 bits on pcw_offset
				 * so that we can generate the original base
				 * in get_window()
				 */
				winp->pcw_offset = (base - winp->pcw_base);

				pcic_putb(pcic, socket,
				    PCIC_IO_OFFSET_LOW +
				    (win * PCIC_IO_OFFSET_OFFSET),
				    winp->pcw_offset & 0x0ff);
				pcic_putb(pcic, socket,
				    PCIC_IO_OFFSET_HI +
				    (win * PCIC_IO_OFFSET_OFFSET),
				    (winp->pcw_offset >> 8) & 0x0ff);

			} /* PCF_IO_REMAP */

			/* now get the other details (size, etc) right */

			/*
			 * Set the data size control bits here. Most of the
			 *	adapters will ignore IOMEM_16BIT when
			 *	IOMEM_IOCS16 is set, except for the Intel
			 *	82092, which only pays attention to the
			 *	IOMEM_16BIT bit. Sigh... Intel can't even
			 *	make a proper clone of their own chip.
			 * The 82092 also apparently can't set the timing
			 *	of I/O windows.
			 */
			which = (window->state & WS_16BIT) ?
			    (IOMEM_16BIT | IOMEM_IOCS16) : 0;

			switch (pcic->pc_type) {
			case PCIC_CL_PD6729:
			case PCIC_CL_PD6730:
			case PCIC_CL_PD6710:
			case PCIC_CL_PD6722:
			case PCIC_CL_PD6832:
				/*
				 * Select Timer Set 1 - this will take
				 *	effect when the PCIC_IO_CONTROL
				 *	register is written to later on;
				 *	the call to pcic_set_cdtimers
				 *	just sets up the timer itself.
				 */
				which |= IOMEM_CLTIMER_SET_1;
				pcic_set_cdtimers(pcic, socket,
				    window->speed,
				    IOMEM_CLTIMER_SET_1);
				which |= IOMEM_IOCS16;
				break;
			case PCIC_TI_PCI1031:

				if (window->state & WS_16BIT)
					which |= IOMEM_WAIT16;

				break;
			case PCIC_TI_PCI1130:

				if (window->state & WS_16BIT)
					which |= IOMEM_WAIT16;

				break;
			case PCIC_INTEL_i82092:
				break;
			default:
				if (window->speed >
				    mhztons(pcic->bus_speed) * 3)
					which |= IOMEM_WAIT16;
#ifdef notdef
				if (window->speed <
				    mhztons(pcic->bus_speed) * 6)
					which |= IOMEM_ZERO_WAIT;
#endif
				break;
			} /* switch (pc_type) */

			/*
			 * Setup the data width and timing
			 */
			select = pcic_getb(pcic, socket, PCIC_IO_CONTROL);
			select &= ~(PCIC_IO_WIN_MASK << (win * 4));
			select |= IOMEM_SETWIN(win, which);
			pcic_putb(pcic, socket, PCIC_IO_CONTROL, select);

			/*
			 * Enable the IO window
			 */
			select = pcic_getb(pcic, socket, PCIC_MAPPING_ENABLE);
			pcic_putb(pcic, socket, PCIC_MAPPING_ENABLE,
			    select | IOMEM_WINDOW(win));

			winp->pcw_status |= PCW_ENABLED;

#if defined(PCIC_DEBUG)
			if (pcic_debug) {
				cmn_err(CE_CONT,
				    "\twhich = %x, select = %x (%x)\n",
				    which, select,
				    IOMEM_SETWIN(win, which));
				xxdmp_all_regs(pcic, window->socket * 0x40, 24);
			}
#endif
		} else {
			/*
			 * not only do we unmap the IO space, the
			 * window has been turned off.
			 */
			if (winp->pcw_status & PCW_MAPPED) {
				ddi_regs_map_free(&winp->pcw_handle);
				res.ra_addr_lo = winp->pcw_base;
				res.ra_len = winp->pcw_len;
				(void) pcmcia_free_io(winp->res_dip, &res);
				winp->pcw_status &= ~PCW_MAPPED;
			}

			/* disable current mapping */
			select = pcic_getb(pcic, socket,
			    PCIC_MAPPING_ENABLE);
			pcic_putb(pcic, socket, PCIC_MAPPING_ENABLE,
			    select &= ~IOMEM_WINDOW(win));
			winp->pcw_status &= ~PCW_ENABLED;

			winp->pcw_base = 0;
			winp->pcw_len = 0;
			winp->pcw_offset = 0;
			window->base = 0;
			/* now make sure we don't accidentally re-enable */
			/* find the register set offset */
			select = win * PCIC_IO_OFFSET;
			pcic_putb(pcic, socket,
			    PCIC_IO_ADDR_0_STARTLOW + select, 0);
			pcic_putb(pcic, socket,
			    PCIC_IO_ADDR_0_STARTHI + select, 0);
			pcic_putb(pcic, socket,
			    PCIC_IO_ADDR_0_STOPLOW + select, 0);
			pcic_putb(pcic, socket,
			    PCIC_IO_ADDR_0_STOPHI + select, 0);
		}
	}
	mutex_exit(&pcic->pc_lock);

	return (SUCCESS);
}

/*
 * pcic_card_state()
 *	compute the instantaneous Card State information
 */
static int
pcic_card_state(pcicdev_t *pcic, pcic_socket_t *sockp)
{
	int value, result;
#if defined(PCIC_DEBUG)
	int orig_value;
#endif

	mutex_enter(&pcic->pc_lock); /* protect the registers */

	value = pcic_getb(pcic, sockp->pcs_socket, PCIC_INTERFACE_STATUS);

#if defined(PCIC_DEBUG)
	orig_value = value;
	if (pcic_debug >= 8)
		cmn_err(CE_CONT, "pcic_card_state(%p) if status = %b for %d\n",
		    (void *)sockp,
		    value,
		    "\020\1BVD1\2BVD2\3CD1\4CD2\5WP\6RDY\7PWR\10~GPI",
		    sockp->pcs_socket);
#endif
	/*
	 * Lie to socket services if we are not ready.
	 * This is when we are starting up or during debounce timeouts
	 * or if the card is a cardbus card.
	 */
	if (!(sockp->pcs_flags & (PCS_STARTING|PCS_CARD_ISCARDBUS)) &&
	    !sockp->pcs_debounce_id &&
	    (value & PCIC_ISTAT_CD_MASK) == PCIC_CD_PRESENT_OK) {
		result = SBM_CD;

		if (value & PCIC_WRITE_PROTECT || !(value & PCIC_POWER_ON))
			result |= SBM_WP;
		if (value & PCIC_POWER_ON) {
			if (value & PCIC_READY)
				result |= SBM_RDYBSY;
			value = (~value) & (PCIC_BVD1 | PCIC_BVD2);
			if (value & PCIC_BVD1)
				result |= SBM_BVD1;
			if (value & PCIC_BVD2)
				result |= SBM_BVD2;
		}
	} else
		result = 0;

	mutex_exit(&pcic->pc_lock);

#if defined(PCIC_DEBUG)
	pcic_err(pcic->dip, 8,
	    "pcic_card_state(%p) if status = %b for %d (rval=0x%x)\n",
	    (void *) sockp, orig_value,
	    "\020\1BVD1\2BVD2\3CD1\4CD2\5WP\6RDY\7PWR\10~GPI",
	    sockp->pcs_socket, result);
#endif

	return (result);
}

/*
 * pcic_set_page()
 *	SocketServices SetPage function
 *	set the page of PC Card memory that should be in the mapped
 *	window
 */
/*ARGSUSED*/
static int
pcic_set_page(dev_info_t *dip, set_page_t *page)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;
	int select;
	int which, socket, window;
	uint32_t base;
	pcs_memwin_t *memp;

	/* get real socket/window numbers */
	window = page->window % PCIC_NUMWINSOCK;
	socket = page->window / PCIC_NUMWINSOCK;

#if defined(PCIC_DEBUG)
	if (pcic_debug) {
		cmn_err(CE_CONT,
		    "pcic_set_page: window=%d, socket=%d, page=%d\n",
		    window, socket, page->page);
	}
#endif
	/* only windows 2-6 work on memory */
	if (window < PCIC_IOWINDOWS)
		return (BAD_WINDOW);

	/* only one page supported (but any size) */
	if (page->page != 0)
		return (BAD_PAGE);

	mutex_enter(&pcic->pc_lock); /* protect the registers */

	memp = &pcic->pc_sockets[socket].pcs_windows[window].mem;
	window -= PCIC_IOWINDOWS;

#if defined(PCIC_DEBUG)
	if (pcic_debug)
		cmn_err(CE_CONT, "\tpcw_base=%x, pcw_hostmem=%p, pcw_len=%x\n",
		    (uint32_t)memp->pcw_base,
		    (void *)memp->pcw_hostmem, memp->pcw_len);
#endif

	/* window must be enabled */
	if (!(memp->pcw_status & PCW_ENABLED))
		return (BAD_ATTRIBUTE);

	/* find the register set offset */
	select = window * PCIC_MEM_1_OFFSET;
#if defined(PCIC_DEBUG)
	if (pcic_debug)
		cmn_err(CE_CONT, "\tselect=%x\n", select);
#endif

	/*
	 * now map the card's memory pages - we start with page 0
	 */

	which = 0;		/* assume simple case */
	if (page->state & PS_ATTRIBUTE) {
		which |= CARDMEM_REG_ACTIVE;
		memp->pcw_status |= PCW_ATTRIBUTE;
	} else {
		memp->pcw_status &= ~PCW_ATTRIBUTE;
	}

	/*
	 * if caller says Write Protect, enforce it.
	 */
	if (page->state & PS_WP) {
		which |= CARDMEM_WRITE_PROTECT;
		memp->pcw_status |= PCW_WP;
	} else {
		memp->pcw_status &= ~PCW_WP;
	}
#if defined(PCIC_DEBUG)
	if (pcic_debug) {
		cmn_err(CE_CONT, "\tmemory type = %s\n",
		    (which & CARDMEM_REG_ACTIVE) ? "attribute" : "common");
		if (which & CARDMEM_WRITE_PROTECT)
			cmn_err(CE_CONT, "\twrite protect\n");
		cmn_err(CE_CONT, "\tpage offset=%x pcw_base=%x (%x)\n",
		    (unsigned)page->offset,
		    (unsigned)memp->pcw_base,
		    (int)page->offset - (int)memp->pcw_base & 0xffffff);
	}
#endif
	/* address computation based on 64MB range and not larger */
	base = (uint32_t)memp->pcw_base & 0x3ffffff;
	pcic_putb(pcic, socket, PCIC_CARDMEM_0_LOW + select,
	    CARDMEM_LOW((int)page->offset - (int)base));
	(void) pcic_getb(pcic, socket, PCIC_CARDMEM_0_LOW + select);
	pcic_putb(pcic, socket, PCIC_CARDMEM_0_HI + select,
	    CARDMEM_HIGH((int)page->offset - base) | which);
	(void) pcic_getb(pcic, socket, PCIC_CARDMEM_0_HI + select);

	/*
	 * while not really necessary, this just makes sure
	 * nothing turned the window off behind our backs
	 */
	which = pcic_getb(pcic, socket, PCIC_MAPPING_ENABLE);
	which |= SYSMEM_WINDOW(window);
	pcic_putb(pcic, socket, PCIC_MAPPING_ENABLE, which);
	(void) pcic_getb(pcic, socket, PCIC_MAPPING_ENABLE);

	memp->pcw_offset = (off_t)page->offset;

#if defined(PCIC_DEBUG)
	if (pcic_debug) {
		cmn_err(CE_CONT, "\tbase=%p, *base=%x\n",
		    (void *)memp->pcw_hostmem,
		    (uint32_t)*memp->pcw_hostmem);

		xxdmp_all_regs(pcic, socket, -1);

		cmn_err(CE_CONT, "\tbase=%p, *base=%x\n",
		    (void *)memp->pcw_hostmem,
		    (uint32_t)*memp->pcw_hostmem);
	}
#endif

	if (which & PCW_ATTRIBUTE)
		pcic_mswait(pcic, socket, 2);

	mutex_exit(&pcic->pc_lock);

	return (SUCCESS);
}

/*
 * pcic_set_vcc_level()
 *
 *	set voltage based on adapter information
 *
 *	this routine implements a limited solution for support of 3.3v cards.
 *	the general solution, which would fully support the pcmcia spec
 *	as far as allowing client drivers to request which voltage levels
 *	to be set, requires more framework support and driver changes - ess
 */
static int
pcic_set_vcc_level(pcicdev_t *pcic, set_socket_t *socket)
{
	uint32_t socket_present_state;

#if defined(PCIC_DEBUG)
	if (pcic_debug) {
		cmn_err(CE_CONT,
		    "pcic_set_vcc_level(pcic=%p, VccLevel=%d)\n",
		    (void *)pcic, socket->VccLevel);
	}
#endif

	/*
	 * check VccLevel
	 * if this is zero, power is being turned off
	 * if it is non-zero, power is being turned on.
	 */
	if (socket->VccLevel == 0) {
		return (0);
	}

	/*
	 * range checking for sanity's sake
	 */
	if (socket->VccLevel >= pcic->pc_numpower) {
		return (BAD_VCC);
	}

	switch (pcic->pc_io_type) {
	/*
	 * Yenta-compliant adapters have vcc info in the extended registers
	 * Other adapters can be added as needed, but the 'default' case
	 * has been left as it was previously so as not to break existing
	 * adapters.
	 */
	case PCIC_IO_TYPE_YENTA:
		/*
		 * Here we ignore the VccLevel passed in and read the
		 * card type from the adapter socket present state register
		 */
		socket_present_state =
		    ddi_get32(pcic->handle, (uint32_t *)(pcic->ioaddr +
		    PCIC_PRESENT_STATE_REG));
#if defined(PCIC_DEBUG)
		if (pcic_debug) {
			cmn_err(CE_CONT,
			    "socket present state = 0x%x\n",
			    socket_present_state);
		}
#endif
		switch (socket_present_state & PCIC_VCC_MASK) {
			case PCIC_VCC_3VCARD:
				/* fall through */
			case PCIC_VCC_3VCARD|PCIC_VCC_5VCARD:
				socket->VccLevel = PCIC_VCC_3VLEVEL;
				return
				    (POWER_3VCARD_ENABLE|POWER_OUTPUT_ENABLE);
			case PCIC_VCC_5VCARD:
				socket->VccLevel = PCIC_VCC_5VLEVEL;
				return
				    (POWER_CARD_ENABLE|POWER_OUTPUT_ENABLE);
			default:
				/*
				 * if no card is present, this can be the
				 * case of a client making a SetSocket call
				 * after card removal. In this case we return
				 * the current power level
				 */
				return ((unsigned)ddi_get8(pcic->handle,
				    pcic->ioaddr + CB_R2_OFFSET +
				    PCIC_POWER_CONTROL));
		}

	default:

		switch (socket->VccLevel) {
		case PCIC_VCC_3VLEVEL:
			return (BAD_VCC);
		case PCIC_VCC_5VLEVEL:
			/* enable Vcc */
			return (POWER_CARD_ENABLE|POWER_OUTPUT_ENABLE);
		default:
			return (BAD_VCC);
		}
	}
}


/*
 * pcic_set_socket()
 *	Socket Services SetSocket call
 *	sets basic socket configuration
 */
static int
pcic_set_socket(dev_info_t *dip, set_socket_t *socket)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;
	pcic_socket_t *sockp = &pcic->pc_sockets[socket->socket];
	int irq, interrupt, mirq;
	int powerlevel = 0;
	int ind, value, orig_pwrctl;

#if defined(PCIC_DEBUG)
	if (pcic_debug) {
		cmn_err(CE_CONT,
		    "pcic_set_socket(dip=%p, socket=%d)"
		    " Vcc=%d Vpp1=%d Vpp2=%d\n", (void *)dip,
		    socket->socket, socket->VccLevel, socket->Vpp1Level,
		    socket->Vpp2Level);
	}
#endif
	/*
	 * check VccLevel, etc. before setting mutex
	 * if this is zero, power is being turned off
	 * if it is non-zero, power is being turned on.
	 * the default case is to assume Vcc only.
	 */

	/* this appears to be very implementation specific */

	if (socket->Vpp1Level != socket->Vpp2Level)
		return (BAD_VPP);

	if (socket->VccLevel == 0 || !(sockp->pcs_flags & PCS_CARD_PRESENT)) {
		powerlevel = 0;
		sockp->pcs_vcc = 0;
		sockp->pcs_vpp1 = 0;
		sockp->pcs_vpp2 = 0;
	} else {
#if defined(PCIC_DEBUG)
		pcic_err(dip, 9, "\tVcc=%d Vpp1Level=%d, Vpp2Level=%d\n",
		    socket->VccLevel, socket->Vpp1Level, socket->Vpp2Level);
#endif
		/* valid Vcc power level? */
		if (socket->VccLevel >= pcic->pc_numpower)
			return (BAD_VCC);

		switch (pcic_power[socket->VccLevel].PowerLevel) {
		case 33:	/* 3.3V */
		case 60:	/* for bad CIS in Option GPRS card */
			if (!(pcic->pc_flags & PCF_33VCAP)) {
				cmn_err(CE_WARN,
				    "%s%d: Bad Request for 3.3V "
				    "(Controller incapable)\n",
				    ddi_get_name(pcic->dip),
				    ddi_get_instance(pcic->dip));
				return (BAD_VCC);
			}
			/* FALLTHROUGH */
		case 50:	/* 5V */
			if ((pcic->pc_io_type == PCIC_IO_TYPE_YENTA) &&
			    pcic_getcb(pcic, CB_PRESENT_STATE) &
			    CB_PS_33VCARD) {
				/*
				 * This is actually a 3.3V card.
				 * Solaris Card Services
				 * doesn't understand 3.3V
				 * so we cheat and change
				 * the setting to the one appropriate to 3.3V.
				 * Note that this is the entry number
				 * in the pcic_power[] array.
				 */
				sockp->pcs_vcc = PCIC_VCC_3VLEVEL;
			} else
				sockp->pcs_vcc = socket->VccLevel;
			break;
		default:
			return (BAD_VCC);
		}

		/* enable Vcc */
		powerlevel = POWER_CARD_ENABLE;

#if defined(PCIC_DEBUG)
		if (pcic_debug) {
			cmn_err(CE_CONT, "\tVcc=%d powerlevel=%x\n",
			    socket->VccLevel, powerlevel);
		}
#endif
		ind = 0;		/* default index to 0 power */
		if ((int)socket->Vpp1Level >= 0 &&
		    socket->Vpp1Level < pcic->pc_numpower) {
			if (!(pcic_power[socket->Vpp1Level].ValidSignals
			    & VPP1)) {
				return (BAD_VPP);
			}
			ind = pcic_power[socket->Vpp1Level].PowerLevel/10;
			powerlevel |= pcic_vpp_levels[ind];
			sockp->pcs_vpp1 = socket->Vpp1Level;
		}
		if ((int)socket->Vpp2Level >= 0 &&
		    socket->Vpp2Level < pcic->pc_numpower) {
			if (!(pcic_power[socket->Vpp2Level].ValidSignals
			    & VPP2)) {
				return (BAD_VPP);
			}
			ind = pcic_power[socket->Vpp2Level].PowerLevel/10;
			powerlevel |= (pcic_vpp_levels[ind] << 2);
			sockp->pcs_vpp2 = socket->Vpp2Level;
		}

		if (pcic->pc_flags & PCF_VPPX) {
			/*
			 * this adapter doesn't allow separate Vpp1/Vpp2
			 * if one is turned on, both are turned on and only
			 * the Vpp1 bits should be set
			 */
			if (sockp->pcs_vpp2 != sockp->pcs_vpp1) {
				/* must be the same if one not zero */
				if (sockp->pcs_vpp1 != 0 &&
				    sockp->pcs_vpp2 != 0) {
					cmn_err(CE_WARN,
					    "%s%d: Bad Power Request "
					    "(Vpp1/2 not the same)\n",
					    ddi_get_name(pcic->dip),
					    ddi_get_instance(pcic->dip));
					return (BAD_VPP);
				}
			}
			powerlevel &= ~(3<<2);
		}

#if defined(PCIC_DEBUG)
		if (pcic_debug) {
			cmn_err(CE_CONT, "\tpowerlevel=%x, ind=%x\n",
			    powerlevel, ind);
		}
#endif
	}
	mutex_enter(&pcic->pc_lock); /* protect the registers */

	/* turn socket->IREQRouting off while programming */
	interrupt = pcic_getb(pcic, socket->socket, PCIC_INTERRUPT);
	interrupt &= ~PCIC_INTR_MASK;
	if (pcic->pc_flags & PCF_USE_SMI)
		interrupt |= PCIC_INTR_ENABLE;
	pcic_putb(pcic, socket->socket, PCIC_INTERRUPT, interrupt);

	switch (pcic->pc_type) {
		case PCIC_INTEL_i82092:
		pcic_82092_smiirq_ctl(pcic, socket->socket, PCIC_82092_CTL_IRQ,
		    PCIC_82092_INT_DISABLE);
		break;
		default:
		break;
	} /* switch */

	/* the SCIntMask specifies events to detect */
	mirq = pcic_getb(pcic, socket->socket, PCIC_MANAGEMENT_INT);

#if defined(PCIC_DEBUG)
	if (pcic_debug)
		cmn_err(CE_CONT,
		    "\tSCIntMask=%x, interrupt=%x, mirq=%x\n",
		    socket->SCIntMask, interrupt, mirq);
#endif
	mirq &= ~(PCIC_BD_DETECT|PCIC_BW_DETECT|PCIC_RD_DETECT);
	pcic_putb(pcic, socket->socket, PCIC_MANAGEMENT_INT,
	    mirq & ~PCIC_CHANGE_MASK);

	/* save the mask we want to use */
	sockp->pcs_intmask = socket->SCIntMask;

	/*
	 * Until there is a card present it's not worth enabling
	 * any interrupts except "Card detect". This is done
	 * elsewhere in the driver so don't change things if
	 * there is no card!
	 */
	if (sockp->pcs_flags & PCS_CARD_PRESENT) {

		/* now update the hardware to reflect events desired */
		if (sockp->pcs_intmask & SBM_BVD1 || socket->IFType == IF_IO)
			mirq |= PCIC_BD_DETECT;

		if (sockp->pcs_intmask & SBM_BVD2)
			mirq |= PCIC_BW_DETECT;

		if (sockp->pcs_intmask & SBM_RDYBSY)
			mirq |= PCIC_RD_DETECT;

		if (sockp->pcs_intmask & SBM_CD)
			mirq |= PCIC_CD_DETECT;
	}

	if (sockp->pcs_flags & PCS_READY) {
		/*
		 * card just came ready.
		 * make sure enough time elapses
		 * before touching it.
		 */
		sockp->pcs_flags &= ~PCS_READY;
		pcic_mswait(pcic, socket->socket, 10);
	}

#if defined(PCIC_DEBUG)
	if (pcic_debug) {
		cmn_err(CE_CONT, "\tstatus change set to %x\n", mirq);
	}
#endif

	switch (pcic->pc_type) {
		case PCIC_I82365SL:
		case PCIC_VADEM:
		case PCIC_VADEM_VG469:
		/*
		 * The Intel version has different options. This is a
		 * special case of GPI which might be used for eject
		 */

		irq = pcic_getb(pcic, socket->socket, PCIC_CARD_DETECT);
		if (sockp->pcs_intmask & (SBM_EJECT|SBM_INSERT) &&
		    pcic->pc_flags & PCF_GPI_EJECT) {
			irq |= PCIC_GPI_ENABLE;
		} else {
			irq &= ~PCIC_GPI_ENABLE;
		}
		pcic_putb(pcic, socket->socket, PCIC_CARD_DETECT, irq);
		break;
		case PCIC_CL_PD6710:
		case PCIC_CL_PD6722:
		if (socket->IFType == IF_IO) {
			pcic_putb(pcic, socket->socket, PCIC_MISC_CTL_2, 0x0);
			value = pcic_getb(pcic, socket->socket,
			    PCIC_MISC_CTL_1);
			if (pcic->pc_flags & PCF_AUDIO)
				value |= PCIC_MC_SPEAKER_ENB;
			pcic_putb(pcic, socket->socket, PCIC_MISC_CTL_1,
			    value);
		} else {
			value = pcic_getb(pcic, socket->socket,
			    PCIC_MISC_CTL_1);
			value &= ~PCIC_MC_SPEAKER_ENB;
			pcic_putb(pcic, socket->socket, PCIC_MISC_CTL_1,
			    value);
		}
		break;
		case PCIC_CL_PD6729:
		case PCIC_CL_PD6730:
		case PCIC_CL_PD6832:
		value = pcic_getb(pcic, socket->socket, PCIC_MISC_CTL_1);
		if ((socket->IFType == IF_IO) && (pcic->pc_flags & PCF_AUDIO)) {
			value |= PCIC_MC_SPEAKER_ENB;
		} else {
			value &= ~PCIC_MC_SPEAKER_ENB;
		}

		if (pcic_power[sockp->pcs_vcc].PowerLevel == 33)
			value |= PCIC_MC_3VCC;
		else
			value &= ~PCIC_MC_3VCC;

		pcic_putb(pcic, socket->socket, PCIC_MISC_CTL_1, value);
		break;

		case PCIC_O2_OZ6912:
		value = pcic_getcb(pcic, CB_MISCCTRL);
		if ((socket->IFType == IF_IO) && (pcic->pc_flags & PCF_AUDIO))
			value |= (1<<25);
		else
			value &= ~(1<<25);
		pcic_putcb(pcic, CB_MISCCTRL, value);
		if (pcic_power[sockp->pcs_vcc].PowerLevel == 33)
			powerlevel |= 0x08;
		break;

		case PCIC_TI_PCI1250:
		case PCIC_TI_PCI1221:
		case PCIC_TI_PCI1225:
		case PCIC_TI_PCI1410:
		case PCIC_ENE_1410:
		case PCIC_TI_PCI1510:
		case PCIC_TI_PCI1520:
		case PCIC_TI_PCI1420:
		case PCIC_ENE_1420:
		value = ddi_get8(pcic->cfg_handle,
		    pcic->cfgaddr + PCIC_CRDCTL_REG);
		if ((socket->IFType == IF_IO) && (pcic->pc_flags & PCF_AUDIO)) {
			value |= PCIC_CRDCTL_SPKR_ENBL;
		} else {
			value &= ~PCIC_CRDCTL_SPKR_ENBL;
		}
		ddi_put8(pcic->cfg_handle,
		    pcic->cfgaddr + PCIC_CRDCTL_REG, value);
		if (pcic_power[sockp->pcs_vcc].PowerLevel == 33)
			powerlevel |= 0x08;
		break;
	}

	/*
	 * ctlind processing -- we can ignore this
	 * there aren't any outputs on the chip for this and
	 * the GUI will display what it thinks is correct
	 */

	/*
	 * If outputs are enabled and the power is going off
	 * turn off outputs first.
	 */

	/* power setup -- if necessary */
	orig_pwrctl = pcic_getb(pcic, socket->socket, PCIC_POWER_CONTROL);
	if ((orig_pwrctl & POWER_OUTPUT_ENABLE) && sockp->pcs_vcc == 0) {
		orig_pwrctl &= ~POWER_OUTPUT_ENABLE;
		pcic_putb(pcic, socket->socket,
		    PCIC_POWER_CONTROL, orig_pwrctl);
		(void) pcic_getb(pcic, socket->socket, PCIC_POWER_CONTROL);
	}

	if (pcic->pc_flags & PCF_CBPWRCTL) {
		value = pcic_cbus_powerctl(pcic, socket->socket);
		powerlevel = 0;
	} else
		value = pcic_exca_powerctl(pcic, socket->socket, powerlevel);

	if (value != SUCCESS) {
		mutex_exit(&pcic->pc_lock);
		return (value);
	}

	/*
	 * If outputs were disabled and the power is going on
	 * turn on outputs afterwards.
	 */
	if (!(orig_pwrctl & POWER_OUTPUT_ENABLE) && sockp->pcs_vcc != 0) {
		orig_pwrctl = pcic_getb(pcic, socket->socket,
		    PCIC_POWER_CONTROL);
		orig_pwrctl |= POWER_OUTPUT_ENABLE;
		pcic_putb(pcic, socket->socket,
		    PCIC_POWER_CONTROL, orig_pwrctl);
		(void) pcic_getb(pcic, socket->socket, PCIC_POWER_CONTROL);
	}

	/*
	 * Once we have done the power stuff can re-enable management
	 * interrupts.
	 */
	pcic_putb(pcic, socket->socket, PCIC_MANAGEMENT_INT, mirq);

#if defined(PCIC_DEBUG)
	pcic_err(dip, 8, "\tmanagement int set to %x pwrctl to 0x%x "
	    "cbctl 0x%x\n",
	    mirq, pcic_getb(pcic, socket->socket, PCIC_POWER_CONTROL),
	    pcic_getcb(pcic, CB_CONTROL));
#endif

	/* irq processing */
	if (socket->IFType == IF_IO) {
		/* IRQ only for I/O */
		irq = socket->IREQRouting & PCIC_INTR_MASK;
		value = pcic_getb(pcic, socket->socket, PCIC_INTERRUPT);
		value &= ~PCIC_INTR_MASK;

		/* to enable I/O operation */
		value |= PCIC_IO_CARD | PCIC_RESET;
		sockp->pcs_flags |= PCS_CARD_IO;
		if (irq != sockp->pcs_irq) {
			if (sockp->pcs_irq != 0)
				cmn_err(CE_CONT,
				    "SetSocket: IRQ mismatch %x != %x!\n",
				    irq, sockp->pcs_irq);
			else
				sockp->pcs_irq = irq;
		}
		irq = sockp->pcs_irq;

		pcic_putb(pcic, socket->socket, PCIC_INTERRUPT, value);
		if (socket->IREQRouting & IRQ_ENABLE) {
			pcic_enable_io_intr(pcic, socket->socket, irq);
			sockp->pcs_flags |= PCS_IRQ_ENABLED;
		} else {
			pcic_disable_io_intr(pcic, socket->socket);
			sockp->pcs_flags &= ~PCS_IRQ_ENABLED;
		}
#if defined(PCIC_DEBUG)
		if (pcic_debug) {
			cmn_err(CE_CONT,
			    "\tsocket type is I/O and irq %x is %s\n", irq,
			    (socket->IREQRouting & IRQ_ENABLE) ?
			    "enabled" : "not enabled");
			xxdmp_all_regs(pcic, socket->socket, 20);
		}
#endif
	} else {
		/* make sure I/O mode is off */

		sockp->pcs_irq = 0;

		value = pcic_getb(pcic, socket->socket, PCIC_INTERRUPT);
		value &= ~PCIC_IO_CARD;
		pcic_putb(pcic, socket->socket, PCIC_INTERRUPT, value);
		pcic_disable_io_intr(pcic, socket->socket);
		sockp->pcs_flags &= ~(PCS_CARD_IO|PCS_IRQ_ENABLED);
	}

	sockp->pcs_state &= ~socket->State;

	mutex_exit(&pcic->pc_lock);
	return (SUCCESS);
}

/*
 * pcic_inquire_socket()
 *	SocketServices InquireSocket function
 *	returns basic characteristics of the socket
 */
/*ARGSUSED*/
static int
pcic_inquire_socket(dev_info_t *dip, inquire_socket_t *socket)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;
	int value;

	socket->SCIntCaps = PCIC_DEFAULT_INT_CAPS;
	socket->SCRptCaps = PCIC_DEFAULT_RPT_CAPS;
	socket->CtlIndCaps = PCIC_DEFAULT_CTL_CAPS;
	value = pcic->pc_sockets[socket->socket].pcs_flags;
	socket->SocketCaps = (value & PCS_SOCKET_IO) ? IF_IO : IF_MEMORY;
	socket->ActiveHigh = 0;
	/* these are the usable IRQs */
	socket->ActiveLow = 0xfff0;
	return (SUCCESS);
}

/*
 * pcic_inquire_window()
 *	SocketServices InquireWindow function
 *	returns detailed characteristics of the window
 *	this is where windows get tied to sockets
 */
/*ARGSUSED*/
static int
pcic_inquire_window(dev_info_t *dip, inquire_window_t *window)
{
	int type, socket;

	type = window->window % PCIC_NUMWINSOCK;
	socket = window->window / PCIC_NUMWINSOCK;

#if defined(PCIC_DEBUG)
	if (pcic_debug >= 8)
		cmn_err(CE_CONT,
		    "pcic_inquire_window: window = %d/%d socket=%d\n",
		    window->window, type, socket);
#endif
	if (type < PCIC_IOWINDOWS) {
		window->WndCaps = WC_IO|WC_WAIT;
		type = IF_IO;
	} else {
		window->WndCaps = WC_COMMON|WC_ATTRIBUTE|WC_WAIT;
		type = IF_MEMORY;
	}

	/* initialize the socket map - one socket per window */
	PR_ZERO(window->Sockets);
	PR_SET(window->Sockets, socket);

	if (type == IF_IO) {
		iowin_char_t *io;
		io = &window->iowin_char;
		io->IOWndCaps = WC_BASE|WC_SIZE|WC_WENABLE|WC_8BIT|
		    WC_16BIT;
		io->FirstByte = (baseaddr_t)IOMEM_FIRST;
		io->LastByte = (baseaddr_t)IOMEM_LAST;
		io->MinSize = IOMEM_MIN;
		io->MaxSize = IOMEM_MAX;
		io->ReqGran = IOMEM_GRAN;
		io->AddrLines = IOMEM_DECODE;
		io->EISASlot = 0;
	} else {
		mem_win_char_t *mem;
		mem = &window->mem_win_char;
		mem->MemWndCaps = WC_BASE|WC_SIZE|WC_WENABLE|WC_8BIT|
		    WC_16BIT|WC_WP;

		mem->FirstByte = (baseaddr_t)MEM_FIRST;
		mem->LastByte = (baseaddr_t)MEM_LAST;

		mem->MinSize = MEM_MIN;
		mem->MaxSize = MEM_MAX;
		mem->ReqGran = PCIC_PAGE;
		mem->ReqBase = 0;
		mem->ReqOffset = PCIC_PAGE;
		mem->Slowest = MEM_SPEED_MAX;
		mem->Fastest = MEM_SPEED_MIN;
	}
	return (SUCCESS);
}

/*
 * pcic_get_adapter()
 *	SocketServices GetAdapter function
 *	this is nearly a no-op.
 */
/*ARGSUSED*/
static int
pcic_get_adapter(dev_info_t *dip, get_adapter_t *adapt)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;

	if (pcic->pc_flags & PCF_INTRENAB)
		adapt->SCRouting = IRQ_ENABLE;
	adapt->state = 0;
	return (SUCCESS);
}

/*
 * pcic_get_page()
 *	SocketServices GetPage function
 *	returns info about the window
 */
/*ARGSUSED*/
static int
pcic_get_page(dev_info_t *dip, get_page_t *page)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;
	int socket, window;
	pcs_memwin_t *winp;

	socket = page->window / PCIC_NUMWINSOCK;
	window = page->window % PCIC_NUMWINSOCK;

	/* I/O windows are the first two */
	if (window < PCIC_IOWINDOWS || socket >= pcic->pc_numsockets) {
		return (BAD_WINDOW);
	}

	winp = &pcic->pc_sockets[socket].pcs_windows[window].mem;

	if (page->page != 0)
		return (BAD_PAGE);

	page->state = 0;
	if (winp->pcw_status & PCW_ENABLED)
		page->state |= PS_ENABLED;
	if (winp->pcw_status & PCW_ATTRIBUTE)
		page->state |= PS_ATTRIBUTE;
	if (winp->pcw_status & PCW_WP)
		page->state |= PS_WP;

	page->offset = (off_t)winp->pcw_offset;

	return (SUCCESS);
}

/*
 * pcic_get_socket()
 *	SocketServices GetSocket
 *	returns information about the current socket setting
 */
/*ARGSUSED*/
static int
pcic_get_socket(dev_info_t *dip, get_socket_t *socket)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;
	int socknum, irq_enabled;
	pcic_socket_t *sockp;

	socknum = socket->socket;
	sockp = &pcic->pc_sockets[socknum];

	socket->SCIntMask = sockp->pcs_intmask;
	sockp->pcs_state = pcic_card_state(pcic, sockp);

	socket->state = sockp->pcs_state;
	if (socket->state & SBM_CD) {
		socket->VccLevel = sockp->pcs_vcc;
		socket->Vpp1Level = sockp->pcs_vpp1;
		socket->Vpp2Level = sockp->pcs_vpp2;
		irq_enabled = (sockp->pcs_flags & PCS_IRQ_ENABLED) ?
		    IRQ_ENABLE : 0;
		socket->IRQRouting = sockp->pcs_irq | irq_enabled;
		socket->IFType = (sockp->pcs_flags & PCS_CARD_IO) ?
		    IF_IO : IF_MEMORY;
	} else {
		socket->VccLevel = 0;
		socket->Vpp1Level = 0;
		socket->Vpp2Level = 0;
		socket->IRQRouting = 0;
		socket->IFType = IF_MEMORY;
	}
	socket->CtlInd = 0;	/* no indicators */

	return (SUCCESS);
}

/*
 * pcic_get_status()
 *	SocketServices GetStatus
 *	returns status information about the PC Card in
 *	the selected socket
 */
/*ARGSUSED*/
static int
pcic_get_status(dev_info_t *dip, get_ss_status_t *status)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;
	int socknum, irq_enabled;
	pcic_socket_t *sockp;

	socknum = status->socket;
	sockp = &pcic->pc_sockets[socknum];

	status->CardState = pcic_card_state(pcic, sockp);
	status->SocketState = sockp->pcs_state;
	status->CtlInd = 0;	/* no indicators */

	if (sockp->pcs_flags & PCS_CARD_PRESENT)
		status->SocketState |= SBM_CD;
	if (status->CardState & SBM_CD) {
		irq_enabled = (sockp->pcs_flags & PCS_CARD_ENABLED) ?
		    IRQ_ENABLE : 0;
		status->IRQRouting = sockp->pcs_irq | irq_enabled;
		status->IFType = (sockp->pcs_flags & PCS_CARD_IO) ?
		    IF_IO : IF_MEMORY;
	} else {
		status->IRQRouting = 0;
		status->IFType = IF_MEMORY;
	}

#if defined(PCIC_DEBUG)
	if (pcic_debug >= 8)
		cmn_err(CE_CONT, "pcic_get_status: socket=%d, CardState=%x,"
		    "SocketState=%x\n",
		    socknum, status->CardState, status->SocketState);
#endif
	switch (pcic->pc_type) {
	uint32_t present_state;
	case PCIC_TI_PCI1410:
	case PCIC_TI_PCI1520:
	case PCIC_TI_PCI1420:
	case PCIC_ENE_1420:
	case PCIC_TOSHIBA_TOPIC100:
	case PCIC_TOSHIBA_TOPIC95:
	case PCIC_TOSHIBA_VENDOR:
	case PCIC_O2MICRO_VENDOR:
	case PCIC_TI_VENDOR:
	case PCIC_RICOH_VENDOR:
		present_state = pcic_getcb(pcic, CB_PRESENT_STATE);
		if (present_state & PCIC_CB_CARD)
			status->IFType = IF_CARDBUS;
#if defined(PCIC_DEBUG)
		if (pcic_debug >= 8)
			cmn_err(CE_CONT,
			    "pcic_get_status: present_state=0x%x\n",
			    present_state);
#endif
		break;
	default:
		break;
	}

	return (SUCCESS);
}

/*
 * pcic_get_window()
 *	SocketServices GetWindow function
 *	returns state information about the specified window
 */
/*ARGSUSED*/
static int
pcic_get_window(dev_info_t *dip, get_window_t *window)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;
	int socket, win;
	pcic_socket_t *sockp;
	pcs_memwin_t *winp;

	socket = window->window / PCIC_NUMWINSOCK;
	win = window->window % PCIC_NUMWINSOCK;
#if defined(PCIC_DEBUG)
	if (pcic_debug) {
		cmn_err(CE_CONT, "pcic_get_window(socket=%d, window=%d)\n",
		    socket, win);
	}
#endif

	if (socket > pcic->pc_numsockets)
		return (BAD_WINDOW);

	sockp = &pcic->pc_sockets[socket];
	winp = &sockp->pcs_windows[win].mem;

	window->socket = socket;
	window->size = winp->pcw_len;
	window->speed = winp->pcw_speed;
	window->handle = (ddi_acc_handle_t)winp->pcw_handle;
	window->base = (uint32_t)winp->pcw_base + winp->pcw_offset;

	if (win >= PCIC_IOWINDOWS) {
		window->state = 0;
	} else {
		window->state = WS_IO;
	}
	if (winp->pcw_status & PCW_ENABLED)
		window->state |= WS_ENABLED;

	if (winp->pcw_status & PCS_CARD_16BIT)
		window->state |= WS_16BIT;
#if defined(PCIC_DEBUG)
	if (pcic_debug)
		cmn_err(CE_CONT, "\tsize=%d, speed=%d, base=%p, state=%x\n",
		    window->size, (unsigned)window->speed,
		    (void *)window->handle, window->state);
#endif

	return (SUCCESS);
}

/*
 * pcic_ll_reset
 *	low level reset
 *	separated out so it can be called when already locked
 *
 *	There are two variables that control the RESET timing:
 *		pcic_prereset_time - time in mS before asserting RESET
 *		pcic_reset_time - time in mS to assert RESET
 *
 */
int pcic_prereset_time = 1;
int pcic_reset_time = 10;
int pcic_postreset_time = 20;
int pcic_vpp_is_vcc_during_reset = 0;

static int
pcic_ll_reset(pcicdev_t *pcic, int socket)
{
	int windowbits, iobits;
	uint32_t pwr;

	/* save windows that were on */
	windowbits = pcic_getb(pcic, socket, PCIC_MAPPING_ENABLE);
	if (pcic_reset_time == 0)
		return (windowbits);
	/* turn all windows off */
	pcic_putb(pcic, socket, PCIC_MAPPING_ENABLE, 0);

#if defined(PCIC_DEBUG)
	pcic_err(pcic->dip, 6,
	    "pcic_ll_reset(socket %d) powerlevel=%x cbctl 0x%x cbps 0x%x\n",
	    socket, pcic_getb(pcic, socket, PCIC_POWER_CONTROL),
	    pcic_getcb(pcic, CB_CONTROL),
	    pcic_getcb(pcic, CB_PRESENT_STATE));
#endif

	if (pcic_vpp_is_vcc_during_reset) {

	/*
	 * Set VPP to VCC for the duration of the reset - for aironet
	 * card.
	 */
		if (pcic->pc_flags & PCF_CBPWRCTL) {
		pwr = pcic_getcb(pcic, CB_CONTROL);
		pcic_putcb(pcic, CB_CONTROL, (pwr&~CB_C_VPPMASK)|CB_C_VPPVCC);
		(void) pcic_getcb(pcic, CB_CONTROL);
		} else {
		pwr = pcic_getb(pcic, socket, PCIC_POWER_CONTROL);
		pcic_putb(pcic, socket, PCIC_POWER_CONTROL,
		    pwr | 1);
		(void) pcic_getb(pcic, socket, PCIC_POWER_CONTROL);
		}
	}

	if (pcic_prereset_time > 0) {
		pcic_err(pcic->dip, 8, "pcic_ll_reset pre_wait %d mS\n",
		    pcic_prereset_time);
		pcic_mswait(pcic, socket, pcic_prereset_time);
	}

	/* turn interrupts off and start a reset */
	pcic_err(pcic->dip, 8,
	    "pcic_ll_reset turn interrupts off and start a reset\n");
	iobits = pcic_getb(pcic, socket, PCIC_INTERRUPT);
	iobits &= ~(PCIC_INTR_MASK | PCIC_RESET);
	pcic_putb(pcic, socket, PCIC_INTERRUPT, iobits);
	(void) pcic_getb(pcic, socket, PCIC_INTERRUPT);

	switch (pcic->pc_type) {
		case PCIC_INTEL_i82092:
		pcic_82092_smiirq_ctl(pcic, socket, PCIC_82092_CTL_IRQ,
		    PCIC_82092_INT_DISABLE);
		break;
		default:
		break;
	} /* switch */

	pcic->pc_sockets[socket].pcs_state = 0;

	if (pcic_reset_time > 0) {
		pcic_err(pcic->dip, 8, "pcic_ll_reset reset_wait %d mS\n",
		    pcic_reset_time);
		pcic_mswait(pcic, socket, pcic_reset_time);
	}

	pcic_err(pcic->dip, 8, "pcic_ll_reset take it out of reset now\n");

	/* take it out of RESET now */
	pcic_putb(pcic, socket, PCIC_INTERRUPT, PCIC_RESET | iobits);
	(void) pcic_getb(pcic, socket, PCIC_INTERRUPT);

	/*
	 * can't access the card for 20ms, but we really don't
	 * want to sit around that long. The pcic is still usable.
	 * memory accesses must wait for RDY to come up.
	 */
	if (pcic_postreset_time > 0) {
		pcic_err(pcic->dip, 8, "pcic_ll_reset post_wait %d mS\n",
		    pcic_postreset_time);
		pcic_mswait(pcic, socket, pcic_postreset_time);
	}

	if (pcic_vpp_is_vcc_during_reset > 1) {

	/*
	 * Return VPP power to whatever it was before.
	 */
		if (pcic->pc_flags & PCF_CBPWRCTL) {
		pcic_putcb(pcic, CB_CONTROL, pwr);
		(void) pcic_getcb(pcic, CB_CONTROL);
		} else {
		pcic_putb(pcic, socket, PCIC_POWER_CONTROL, pwr);
		(void) pcic_getb(pcic, socket, PCIC_POWER_CONTROL);
		}
	}

	pcic_err(pcic->dip, 7, "pcic_ll_reset returning 0x%x\n", windowbits);

	return (windowbits);
}

/*
 * pcic_reset_socket()
 *	SocketServices ResetSocket function
 *	puts the PC Card in the socket into the RESET state
 *	and then takes it out after the the cycle time
 *	The socket is back to initial state when done
 */
static int
pcic_reset_socket(dev_info_t *dip, int socket, int mode)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;
	int value;
	int i, mint;
	pcic_socket_t *sockp;

#if defined(PCIC_DEBUG)
	if (pcic_debug >= 8)
		cmn_err(CE_CONT, "pcic_reset_socket(%p, %d, %d/%s)\n",
		    (void *)dip, socket, mode,
		    mode == RESET_MODE_FULL ? "full" : "partial");
#endif

	mutex_enter(&pcic->pc_lock); /* protect the registers */

	/* Turn off management interupts. */
	mint = pcic_getb(pcic, socket, PCIC_MANAGEMENT_INT);
	pcic_putb(pcic, socket, PCIC_MANAGEMENT_INT, mint & ~PCIC_CHANGE_MASK);

	sockp = &pcic->pc_sockets[socket];

	value = pcic_ll_reset(pcic, socket);
	if (mode == RESET_MODE_FULL) {
		/* disable and unmap all mapped windows */
		for (i = 0; i < PCIC_NUMWINSOCK; i++) {
			if (i < PCIC_IOWINDOWS) {
				if (sockp->pcs_windows[i].io.pcw_status &
				    PCW_MAPPED) {
					pcs_iowin_t *io;
					io = &sockp->pcs_windows[i].io;
					io->pcw_status &= ~PCW_ENABLED;
				}
			} else {
				if (sockp->pcs_windows[i].mem.pcw_status &
				    PCW_MAPPED) {
					pcs_memwin_t *mem;
					mem = &sockp->pcs_windows[i].mem;
					mem->pcw_status &= ~PCW_ENABLED;
				}
			}
		}
	} else {
				/* turn windows back on */
		pcic_putb(pcic, socket, PCIC_MAPPING_ENABLE, value);
		/* wait the rest of the time here */
		pcic_mswait(pcic, socket, 10);
	}
	pcic_putb(pcic, socket, PCIC_MANAGEMENT_INT, mint);
	mutex_exit(&pcic->pc_lock);
	return (SUCCESS);
}

/*
 * pcic_set_interrupt()
 *	SocketServices SetInterrupt function
 */
static int
pcic_set_interrupt(dev_info_t *dip, set_irq_handler_t *handler)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;
	int value = DDI_SUCCESS;
	inthandler_t *intr;

#if defined(PCIC_DEBUG)
	if (pcic_debug) {
		cmn_err(CE_CONT,
		    "pcic_set_interrupt: entered pc_intr_mode=0x%x\n",
		    pcic->pc_intr_mode);
		cmn_err(CE_CONT,
		    "\t irq_top=%p handler=%p handler_id=%x\n",
		    (void *)pcic->irq_top, (void *)handler->handler,
		    handler->handler_id);
	}
#endif

	/*
	 * If we're on a PCI bus, we route all IO IRQs through a single
	 *	PCI interrupt (typically INT A#) so we don't have to do
	 *	much other than add the caller to general interrupt handler
	 *	and set some state.
	 */

	intr = kmem_zalloc(sizeof (inthandler_t), KM_NOSLEEP);
	if (intr == NULL)
		return (NO_RESOURCE);

	switch (pcic->pc_intr_mode) {
	case PCIC_INTR_MODE_PCI_1:
		/*
		 * We only allow above-lock-level IO IRQ handlers
		 *	in the PCI bus case.
		 */

		mutex_enter(&pcic->intr_lock);

		if (pcic->irq_top == NULL) {
			pcic->irq_top = intr;
			pcic->irq_current = pcic->irq_top;
		} else {
			while (pcic->irq_current->next != NULL)
			pcic->irq_current = pcic->irq_current->next;
			pcic->irq_current->next = intr;
			pcic->irq_current = pcic->irq_current->next;
		}

		pcic->irq_current->intr =
		    (ddi_intr_handler_t *)handler->handler;
		pcic->irq_current->handler_id = handler->handler_id;
		pcic->irq_current->arg1 = handler->arg1;
		pcic->irq_current->arg2 = handler->arg2;
		pcic->irq_current->socket = handler->socket;

		mutex_exit(&pcic->intr_lock);

		handler->iblk_cookie = &pcic->pc_pri;
		handler->idev_cookie = &pcic->pc_dcookie;
		break;

	default:
		intr->intr = (ddi_intr_handler_t *)handler->handler;
		intr->handler_id = handler->handler_id;
		intr->arg1 = handler->arg1;
		intr->arg2 = handler->arg2;
		intr->socket = handler->socket;
		intr->irq = handler->irq;

		/*
		 * need to revisit this to see if interrupts can be
		 * shared someday. Note that IRQ is set in the common
		 * code.
		 */
		mutex_enter(&pcic->pc_lock);
		if (pcic->pc_handlers == NULL) {
			pcic->pc_handlers = intr;
			intr->next = intr->prev = intr;
		} else {
			insque(intr, pcic->pc_handlers);
		}
		mutex_exit(&pcic->pc_lock);

		break;
	}

	/*
	 * need to fill in cookies in event of multiple high priority
	 * interrupt handlers on same IRQ
	 */

#if defined(PCIC_DEBUG)
	if (pcic_debug) {
		cmn_err(CE_CONT,
		    "pcic_set_interrupt: exit irq_top=%p value=%d\n",
		    (void *)pcic->irq_top, value);
	}
#endif

	if (value == DDI_SUCCESS) {
		return (SUCCESS);
	} else {
		return (BAD_IRQ);
	}
}

/*
 * pcic_clear_interrupt()
 *	SocketServices ClearInterrupt function
 *
 *	Interrupts for PCIC are complicated by the fact that we must
 *	follow several different models for interrupts.
 *	ISA: there is an interrupt per adapter and per socket and
 *		they can't be shared.
 *	PCI: some adapters have one PCI interrupt available while others
 *		have up to 4.  Solaris may or may not allow us to use more
 *		than 1 so we essentially share them all at this point.
 *	Hybrid: PCI bridge but interrupts wired to host interrupt controller.
 *		This is like ISA but we have to fudge and create an intrspec
 *		that PCI's parent understands and bypass the PCI nexus.
 *	multifunction: this requires sharing the interrupts on a per-socket
 *		basis.
 */
static int
pcic_clear_interrupt(dev_info_t *dip, clear_irq_handler_t *handler)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;
	inthandler_t *intr, *prev, *current;
	int i;

	/*
	 * If we're on a PCI bus, we route all IO IRQs through a single
	 *	PCI interrupt (typically INT A#) so we don't have to do
	 *	much other than remove the caller from the general
	 *	interrupt handler callout list.
	 */

#if defined(PCIC_DEBUG)
	if (pcic_debug) {
		cmn_err(CE_CONT,
		    "pcic_clear_interrupt: entered pc_intr_mode=0x%x\n",
		    pcic->pc_intr_mode);
		cmn_err(CE_CONT,
		    "\t irq_top=%p handler=%p handler_id=%x\n",
		    (void *)pcic->irq_top, (void *)handler->handler,
		    handler->handler_id);
	}
#endif

	switch (pcic->pc_intr_mode) {
	case PCIC_INTR_MODE_PCI_1:

		mutex_enter(&pcic->intr_lock);
		if (pcic->irq_top == NULL) {
			mutex_exit(&pcic->intr_lock);
			return (BAD_IRQ);
		}

		intr = NULL;
		pcic->irq_current = pcic->irq_top;

		while ((pcic->irq_current != NULL) &&
		    (pcic->irq_current->handler_id !=
		    handler->handler_id)) {
			intr = pcic->irq_current;
			pcic->irq_current = pcic->irq_current->next;
		}

		if (pcic->irq_current == NULL) {
			mutex_exit(&pcic->intr_lock);
			return (BAD_IRQ);
		}

		if (intr != NULL) {
			intr->next = pcic->irq_current->next;
		} else {
			pcic->irq_top = pcic->irq_current->next;
		}

		current = pcic->irq_current;
		pcic->irq_current = pcic->irq_top;
		mutex_exit(&pcic->intr_lock);
		kmem_free(current, sizeof (inthandler_t));

		break;

	default:

		mutex_enter(&pcic->pc_lock);
		intr = pcic_handlers;
		prev = (inthandler_t *)&pcic_handlers;

		while (intr != NULL) {
			if (intr->handler_id == handler->handler_id) {
			i = intr->irq & PCIC_INTR_MASK;
			if (--pcic_irq_map[i].count == 0) {
				/* multi-handler form */
				(void) ddi_intr_disable(pcic->pc_intr_htblp[i]);
				(void) ddi_intr_remove_handler(
				    pcic->pc_intr_htblp[i]);
				(void) ddi_intr_free(pcic->pc_intr_htblp[i]);
				(void) pcmcia_return_intr(pcic->dip, i);
#if defined(PCIC_DEBUG)
				if (pcic_debug) {
					cmn_err(CE_CONT,
					    "removing interrupt %d at %s "
					    "priority\n", i, "high");
					cmn_err(CE_CONT,
					    "ddi_remove_intr(%p, %x, %p)\n",
					    (void *)dip,
					    0,
					    (void *)intr->iblk_cookie);
				}
#endif
			}
			prev->next = intr->next;
			kmem_free(intr, sizeof (inthandler_t));
			intr = prev->next;
			} else {
			prev = intr;
			intr = intr->next;
			} /* if (handler_id) */
		} /* while */

		mutex_exit(&pcic->pc_lock);
	}

#if defined(PCIC_DEBUG)
	if (pcic_debug) {
		cmn_err(CE_CONT,
		    "pcic_clear_interrupt: exit irq_top=%p\n",
		    (void *)pcic->irq_top);
	}
#endif


	return (SUCCESS);
}

struct intel_regs {
	char *name;
	int   off;
	char *fmt;
} iregs[] = {
	{"ident     ", 0},
	{"if-status ", 1, "\020\1BVD1\2BVD2\3CD1\4CD2\5WP\6RDY\7PWR\10~GPI"},
	{"power     ", 2, "\020\1Vpp1c0\2Vpp1c1\3Vpp2c0\4Vpp2c1\5PE\6AUTO"
		"\7DRD\10OE"},
	{"cardstatus", 4, "\020\1BD\2BW\3RC\4CD\5GPI\6R1\7R2\010R3"},
	{"enable    ", 6, "\020\1MW0\2MW1\3MW2\4MW3\5MW4\6MEM16\7IO0\10IO1"},
	{"cd-gcr    ", 0x16, "\020\1MDI16\2CRE\3GPIE\4GPIT\5CDR\6S/W"},
	{"GCR       ", 0x1e, "\020\1PD\2LEVEL\3WCSC\4PLS14"},
	{"int-gcr   ", 3, "\020\5INTR\6IO\7~RST\10RI"},
	{"management", 5, "\020\1BDE\2BWE\3RE\4CDE"},
	{"volt-sense", 0x1f, "\020\1A_VS1\2A_VS2\3B_VS1\4B_VS2"},
	{"volt-sel  ", 0x2f, "\020\5EXTCONF\6BUSSELECT\7MIXEDV\10ISAV"},
	{"VG ext A  ", 0x3c, "\20\3IVS\4CABLE\5CSTEP\6TEST\7RIO"},
	{"io-ctrl   ", 7, "\020\1DS0\2IOCS0\3ZWS0\4WS0\5DS1\6IOS1\7ZWS1\10WS1"},
	{"io0-slow  ", 8},
	{"io0-shi   ", 9},
	{"io0-elow  ", 0xa},
	{"io0-ehi   ", 0xb},
	{"io1-slow  ", 0xc},
	{"io1-shi   ", 0xd},
	{"io1-elow  ", 0xe},
	{"io1-ehi   ", 0xf},
	{"mem0-slow ", 0x10},
	{"mem0-shi  ", 0x11, "\020\7ZW\10DS"},
	{"mem0-elow ", 0x12},
	{"mem0-ehi  ", 0x13, "\020\7WS0\10WS1"},
	{"card0-low ", 0x14},
	{"card0-hi  ", 0x15, "\020\7AM\10WP"},
	{"mem1-slow ", 0x18},
	{"mem1-shi  ", 0x19, "\020\7ZW\10DS"},
	{"mem1-elow ", 0x1a},
	{"mem1-ehi  ", 0x1b, "\020\7WS0\10WS1"},
	{"card1-low ", 0x1c},
	{"card1-hi  ", 0x1d, "\020\7AM\10WP"},
	{"mem2-slow ", 0x20},
	{"mem2-shi  ", 0x21, "\020\7ZW\10DS"},
	{"mem2-elow ", 0x22},
	{"mem2-ehi  ", 0x23, "\020\7WS0\10WS1"},
	{"card2-low ", 0x24},
	{"card2-hi  ", 0x25, "\020\7AM\10WP"},
	{"mem3-slow ", 0x28},
	{"mem3-shi  ", 0x29, "\020\7ZW\10DS"},
	{"mem3-elow ", 0x2a},
	{"mem3-ehi  ", 0x2b, "\020\7WS0\10WS1"},
	{"card3-low ", 0x2c},
	{"card3-hi  ", 0x2d, "\020\7AM\10WP"},

	{"mem4-slow ", 0x30},
	{"mem4-shi  ", 0x31, "\020\7ZW\10DS"},
	{"mem4-elow ", 0x32},
	{"mem4-ehi  ", 0x33, "\020\7WS0\10WS1"},
	{"card4-low ", 0x34},
	{"card4-hi  ", 0x35, "\020\7AM\10WP"},
	{"mpage0    ", 0x40},
	{"mpage1    ", 0x41},
	{"mpage2    ", 0x42},
	{"mpage3    ", 0x43},
	{"mpage4    ", 0x44},
	{NULL},
};

static struct intel_regs cregs[] = {
	{"misc-ctl1 ", 0x16, "\20\2VCC3\3PMI\4PSI\5SPKR\10INPACK"},
	{"fifo      ", 0x17, "\20\6DIOP\7DMEMP\10EMPTY"},
	{"misc-ctl2 ", 0x1e, "\20\1XCLK\2LOW\3SUSP\4CORE5V\5TCD\10RIOUT"},
	{"chip-info ", 0x1f, "\20\6DUAL"},
	{"IO-offlow0", 0x36},
	{"IO-offhi0 ", 0x37},
	{"IO-offlow1", 0x38},
	{"IO-offhi1 ", 0x39},
	NULL,
};

static struct intel_regs cxregs[] = {
	{"ext-ctl-1 ", 0x03,
		"\20\1VCCLCK\2AUTOCLR\3LED\4INVIRQC\5INVIRQM\6PUC"},
	{"misc-ctl3 ", 0x25, "\20\5HWSUSP"},
	{"mem0-up   ", 0x05},
	{"mem1-up   ", 0x06},
	{"mem2-up   ", 0x07},
	{"mem3-up   ", 0x08},
	{"mem4-up   ", 0x09},
	{NULL}
};

void
xxdmp_cl_regs(pcicdev_t *pcic, int socket, uint32_t len)
{
	int i, value, j;
	char buff[256];
	char *fmt;

	cmn_err(CE_CONT, "--------- Cirrus Logic Registers --------\n");
	for (buff[0] = '\0', i = 0; cregs[i].name != NULL && len-- != 0; i++) {
		int sval;
		if (cregs[i].off == PCIC_MISC_CTL_2)
			sval = 0;
		else
			sval = socket;
		value = pcic_getb(pcic, sval, cregs[i].off);
		if (i & 1) {
			if (cregs[i].fmt)
				fmt = "%s\t%s\t%b\n";
			else
				fmt = "%s\t%s\t%x\n";
			cmn_err(CE_CONT, fmt, buff,
			    cregs[i].name, value, cregs[i].fmt);
			buff[0] = '\0';
		} else {
			if (cregs[i].fmt)
				fmt = "\t%s\t%b";
			else
				fmt = "\t%s\t%x";
			(void) sprintf(buff, fmt,
			    cregs[i].name, value, cregs[i].fmt);
			for (j = strlen(buff); j < 40; j++)
				buff[j] = ' ';
			buff[40] = '\0';
		}
	}
	cmn_err(CE_CONT, "%s\n", buff);

	i = pcic_getb(pcic, socket, PCIC_TIME_SETUP_0);
	j = pcic_getb(pcic, socket, PCIC_TIME_SETUP_1);
	cmn_err(CE_CONT, "\tsetup-tim0\t%x\tsetup-tim1\t%x\n", i, j);

	i = pcic_getb(pcic, socket, PCIC_TIME_COMMAND_0);
	j = pcic_getb(pcic, socket, PCIC_TIME_COMMAND_1);
	cmn_err(CE_CONT, "\tcmd-tim0  \t%x\tcmd-tim1  \t%x\n", i, j);

	i = pcic_getb(pcic, socket, PCIC_TIME_RECOVER_0);
	j = pcic_getb(pcic, socket, PCIC_TIME_RECOVER_1);
	cmn_err(CE_CONT, "\trcvr-tim0 \t%x\trcvr-tim1 \t%x\n", i, j);

	cmn_err(CE_CONT, "--------- Extended Registers  --------\n");

	for (buff[0] = '\0', i = 0; cxregs[i].name != NULL && len-- != 0; i++) {
		value = clext_reg_read(pcic, socket, cxregs[i].off);
		if (i & 1) {
			if (cxregs[i].fmt)
				fmt = "%s\t%s\t%b\n";
			else
				fmt = "%s\t%s\t%x\n";
			cmn_err(CE_CONT, fmt, buff,
			    cxregs[i].name, value, cxregs[i].fmt);
			buff[0] = '\0';
		} else {
			if (cxregs[i].fmt)
				fmt = "\t%s\t%b";
			else
				fmt = "\t%s\t%x";
			(void) sprintf(buff, fmt,
			    cxregs[i].name, value, cxregs[i].fmt);
			for (j = strlen(buff); j < 40; j++)
				buff[j] = ' ';
			buff[40] = '\0';
		}
	}
}

#if defined(PCIC_DEBUG)
static void
xxdmp_all_regs(pcicdev_t *pcic, int socket, uint32_t len)
{
	int i, value, j;
	char buff[256];
	char *fmt;

#if defined(PCIC_DEBUG)
	if (pcic_debug < 2)
		return;
#endif
	cmn_err(CE_CONT,
	    "----------- PCIC Registers for socket %d---------\n",
	    socket);
	cmn_err(CE_CONT,
	    "\tname       value	                name       value\n");

	for (buff[0] = '\0', i = 0; iregs[i].name != NULL && len-- != 0; i++) {
		value = pcic_getb(pcic, socket, iregs[i].off);
		if (i & 1) {
			if (iregs[i].fmt)
				fmt = "%s\t%s\t%b\n";
			else
				fmt = "%s\t%s\t%x\n";
			cmn_err(CE_CONT, fmt, buff,
			    iregs[i].name, value, iregs[i].fmt);
			buff[0] = '\0';
		} else {
			if (iregs[i].fmt)
				fmt = "\t%s\t%b";
			else
				fmt = "\t%s\t%x";
			(void) sprintf(buff, fmt,
			    iregs[i].name, value, iregs[i].fmt);
			for (j = strlen(buff); j < 40; j++)
				buff[j] = ' ';
			buff[40] = '\0';
		}
	}
	switch (pcic->pc_type) {
	case PCIC_CL_PD6710:
	case PCIC_CL_PD6722:
	case PCIC_CL_PD6729:
	case PCIC_CL_PD6832:
		(void) xxdmp_cl_regs(pcic, socket, 0xFFFF);
		break;
	}
	cmn_err(CE_CONT, "%s\n", buff);
}
#endif

/*
 * pcic_mswait(ms)
 *	sleep ms milliseconds
 *	call drv_usecwait once for each ms
 */
static void
pcic_mswait(pcicdev_t *pcic, int socket, int ms)
{
	if (ms) {
		pcic->pc_sockets[socket].pcs_flags |= PCS_WAITING;
		pcic_mutex_exit(&pcic->pc_lock);
		delay(drv_usectohz(ms*1000));
		pcic_mutex_enter(&pcic->pc_lock);
		pcic->pc_sockets[socket].pcs_flags &= ~PCS_WAITING;
	}
}

/*
 * pcic_check_ready(pcic, index, off)
 *      Wait for card to come ready
 *      We only wait if the card is NOT in RESET
 *      and power is on.
 */
static boolean_t
pcic_check_ready(pcicdev_t *pcic, int socket)
{
	int ifstate, intstate;

	intstate = pcic_getb(pcic, socket, PCIC_INTERRUPT);
	ifstate = pcic_getb(pcic, socket, PCIC_INTERFACE_STATUS);

	if ((intstate & PCIC_RESET) &&
	    ((ifstate & (PCIC_READY|PCIC_POWER_ON|PCIC_ISTAT_CD_MASK)) ==
	    (PCIC_READY|PCIC_POWER_ON|PCIC_CD_PRESENT_OK)))
		return (B_TRUE);

#ifdef  PCIC_DEBUG
	pcic_err(NULL, 5, "pcic_check_read: Card not ready, intstate = 0x%x, "
	    "ifstate = 0x%x\n", intstate, ifstate);
	if (pcic_debug) {
		pcic_debug += 4;
		xxdmp_all_regs(pcic, socket, -1);
		pcic_debug -= 4;
	}
#endif
	return (B_FALSE);
}

/*
 * Cirrus Logic extended register read/write routines
 */
static int
clext_reg_read(pcicdev_t *pcic, int sn, uchar_t ext_reg)
{
	int val;

	switch (pcic->pc_io_type) {
	case PCIC_IO_TYPE_YENTA:
		val = ddi_get8(pcic->handle,
		    pcic->ioaddr + CB_CLEXT_OFFSET + ext_reg);
		break;
	default:
		pcic_putb(pcic, sn, PCIC_CL_EXINDEX, ext_reg);
		val = pcic_getb(pcic, sn, PCIC_CL_EXINDEX + 1);
		break;
	}

	return (val);
}

static void
clext_reg_write(pcicdev_t *pcic, int sn, uchar_t ext_reg, uchar_t value)
{
	switch (pcic->pc_io_type) {
	case PCIC_IO_TYPE_YENTA:
		ddi_put8(pcic->handle,
		    pcic->ioaddr + CB_CLEXT_OFFSET + ext_reg, value);
		break;
	default:
		pcic_putb(pcic, sn, PCIC_CL_EXINDEX, ext_reg);
		pcic_putb(pcic, sn, PCIC_CL_EXINDEX + 1, value);
		break;
	}
}

/*
 * Misc PCI functions
 */
static void
pcic_iomem_pci_ctl(ddi_acc_handle_t handle, uchar_t *cfgaddr, unsigned flags)
{
	unsigned cmd;

	if (flags & (PCIC_ENABLE_IO | PCIC_ENABLE_MEM)) {
		cmd = ddi_get16(handle, (ushort_t *)(cfgaddr + 4));
		if ((cmd & (PCI_COMM_IO|PCI_COMM_MAE)) ==
		    (PCI_COMM_IO|PCI_COMM_MAE))
			return;

		if (flags & PCIC_ENABLE_IO)
			cmd |= PCI_COMM_IO;

		if (flags & PCIC_ENABLE_MEM)
			cmd |= PCI_COMM_MAE;

		ddi_put16(handle, (ushort_t *)(cfgaddr + 4), cmd);
	} /* if (PCIC_ENABLE_IO | PCIC_ENABLE_MEM) */
}

/*
 * pcic_find_pci_type - Find and return PCI-PCMCIA adapter type
 */
static int
pcic_find_pci_type(pcicdev_t *pcic)
{
	uint32_t vend, device;

	vend = ddi_getprop(DDI_DEV_T_ANY, pcic->dip,
	    DDI_PROP_CANSLEEP|DDI_PROP_DONTPASS,
	    "vendor-id", -1);
	device = ddi_getprop(DDI_DEV_T_ANY, pcic->dip,
	    DDI_PROP_CANSLEEP|DDI_PROP_DONTPASS,
	    "device-id", -1);

	device = PCI_ID(vend, device);
	pcic->pc_type = device;
	pcic->pc_chipname = "PCI:unknown";

	switch (device) {
	case PCIC_INTEL_i82092:
		pcic->pc_chipname = PCIC_TYPE_i82092;
		break;
	case PCIC_CL_PD6729:
		pcic->pc_chipname = PCIC_TYPE_PD6729;
		/*
		 * Some 6730's incorrectly identify themselves
		 *	as a 6729, so we need to do some more tests
		 *	here to see if the device that's claiming
		 *	to be a 6729 is really a 6730.
		 */
		if ((clext_reg_read(pcic, 0, PCIC_CLEXT_MISC_CTL_3) &
		    PCIC_CLEXT_MISC_CTL_3_REV_MASK) ==
		    0) {
			pcic->pc_chipname = PCIC_TYPE_PD6730;
			pcic->pc_type = PCIC_CL_PD6730;
		}
		break;
	case PCIC_CL_PD6730:
		pcic->pc_chipname = PCIC_TYPE_PD6730;
		break;
	case PCIC_CL_PD6832:
		pcic->pc_chipname = PCIC_TYPE_PD6832;
		break;
	case PCIC_SMC_34C90:
		pcic->pc_chipname = PCIC_TYPE_34C90;
		break;
	case PCIC_TOSHIBA_TOPIC95:
		pcic->pc_chipname = PCIC_TYPE_TOPIC95;
		break;
	case PCIC_TOSHIBA_TOPIC100:
		pcic->pc_chipname = PCIC_TYPE_TOPIC100;
		break;
	case PCIC_TI_PCI1031:
		pcic->pc_chipname = PCIC_TYPE_PCI1031;
		break;
	case PCIC_TI_PCI1130:
		pcic->pc_chipname = PCIC_TYPE_PCI1130;
		break;
	case PCIC_TI_PCI1131:
		pcic->pc_chipname = PCIC_TYPE_PCI1131;
		break;
	case PCIC_TI_PCI1250:
		pcic->pc_chipname = PCIC_TYPE_PCI1250;
		break;
	case PCIC_TI_PCI1225:
		pcic->pc_chipname = PCIC_TYPE_PCI1225;
		break;
	case PCIC_TI_PCI1410:
		pcic->pc_chipname = PCIC_TYPE_PCI1410;
		break;
	case PCIC_TI_PCI1510:
		pcic->pc_chipname = PCIC_TYPE_PCI1510;
		break;
	case PCIC_TI_PCI1520:
		pcic->pc_chipname = PCIC_TYPE_PCI1520;
		break;
	case PCIC_TI_PCI1221:
		pcic->pc_chipname = PCIC_TYPE_PCI1221;
		break;
	case PCIC_TI_PCI1050:
		pcic->pc_chipname = PCIC_TYPE_PCI1050;
		break;
	case PCIC_ENE_1410:
		pcic->pc_chipname = PCIC_TYPE_1410;
		break;
	case PCIC_O2_OZ6912:
		pcic->pc_chipname = PCIC_TYPE_OZ6912;
		break;
	case PCIC_RICOH_RL5C466:
		pcic->pc_chipname = PCIC_TYPE_RL5C466;
		break;
	case PCIC_TI_PCI1420:
		pcic->pc_chipname = PCIC_TYPE_PCI1420;
		break;
	case PCIC_ENE_1420:
		pcic->pc_chipname = PCIC_TYPE_1420;
		break;
	default:
		switch (PCI_ID(vend, (uint32_t)0)) {
		case PCIC_TOSHIBA_VENDOR:
			pcic->pc_chipname = PCIC_TYPE_TOSHIBA;
			pcic->pc_type = PCIC_TOSHIBA_VENDOR;
			break;
		case PCIC_TI_VENDOR:
			pcic->pc_chipname = PCIC_TYPE_TI;
			pcic->pc_type = PCIC_TI_VENDOR;
			break;
		case PCIC_O2MICRO_VENDOR:
			pcic->pc_chipname = PCIC_TYPE_O2MICRO;
			pcic->pc_type = PCIC_O2MICRO_VENDOR;
			break;
		case PCIC_RICOH_VENDOR:
			pcic->pc_chipname = PCIC_TYPE_RICOH;
			pcic->pc_type = PCIC_RICOH_VENDOR;
			break;
		default:
			if (!(pcic->pc_flags & PCF_CARDBUS))
				return (DDI_FAILURE);
			pcic->pc_chipname = PCIC_TYPE_YENTA;
			break;
		}
	}
	return (DDI_SUCCESS);
}

static void
pcic_82092_smiirq_ctl(pcicdev_t *pcic, int socket, int intr, int state)
{
	uchar_t ppirr = ddi_get8(pcic->cfg_handle,
	    pcic->cfgaddr + PCIC_82092_PPIRR);
	uchar_t val;

	if (intr == PCIC_82092_CTL_SMI) {
		val = PCIC_82092_SMI_CTL(socket,
		    PCIC_82092_INT_DISABLE);
		ppirr &= ~val;
		val = PCIC_82092_SMI_CTL(socket, state);
		ppirr |= val;
	} else {
		val = PCIC_82092_IRQ_CTL(socket,
		    PCIC_82092_INT_DISABLE);
		ppirr &= ~val;
		val = PCIC_82092_IRQ_CTL(socket, state);
		ppirr |= val;
	}
	ddi_put8(pcic->cfg_handle, pcic->cfgaddr + PCIC_82092_PPIRR,
	    ppirr);
}

static uint_t
pcic_cd_softint(caddr_t arg1, caddr_t arg2)
{
	pcic_socket_t *sockp = (pcic_socket_t *)arg1;
	uint_t rc = DDI_INTR_UNCLAIMED;

	_NOTE(ARGUNUSED(arg2))

	mutex_enter(&sockp->pcs_pcic->pc_lock);
	if (sockp->pcs_cd_softint_flg) {
		uint8_t status;
		sockp->pcs_cd_softint_flg = 0;
		rc = DDI_INTR_CLAIMED;
		status = pcic_getb(sockp->pcs_pcic, sockp->pcs_socket,
		    PCIC_INTERFACE_STATUS);
		pcic_handle_cd_change(sockp->pcs_pcic, sockp, status);
	}
	mutex_exit(&sockp->pcs_pcic->pc_lock);
	return (rc);
}

int pcic_debounce_cnt = PCIC_REM_DEBOUNCE_CNT;
int pcic_debounce_intr_time = PCIC_REM_DEBOUNCE_TIME;
int pcic_debounce_cnt_ok = PCIC_DEBOUNCE_OK_CNT;

#ifdef CARDBUS
static uint32_t pcic_cbps_on = 0;
static uint32_t pcic_cbps_off = CB_PS_NOTACARD | CB_PS_CCDMASK |
				CB_PS_XVCARD | CB_PS_YVCARD;
#else
static uint32_t pcic_cbps_on = CB_PS_16BITCARD;
static uint32_t pcic_cbps_off = CB_PS_NOTACARD | CB_PS_CCDMASK |
				CB_PS_CBCARD |
				CB_PS_XVCARD | CB_PS_YVCARD;
#endif
static void
pcic_handle_cd_change(pcicdev_t *pcic, pcic_socket_t *sockp, uint8_t status)
{
	boolean_t	do_debounce = B_FALSE;
	int		debounce_time = drv_usectohz(pcic_debounce_time);
	uint8_t		irq;
	timeout_id_t	debounce;

	/*
	 * Always reset debounce but may need to check original state later.
	 */
	debounce = sockp->pcs_debounce_id;
	sockp->pcs_debounce_id = 0;

	/*
	 * Check to see whether a card is present or not. There are
	 *	only two states that we are concerned with - the state
	 *	where both CD pins are asserted, which means that the
	 *	card is fully seated, and the state where neither CD
	 *	pin is asserted, which means that the card is not
	 *	present.
	 * The CD signals are generally very noisy and cause a lot of
	 *	contact bounce as the card is being inserted and
	 *	removed, so we need to do some software debouncing.
	 */

#ifdef PCIC_DEBUG
		pcic_err(pcic->dip, 6,
		    "pcic%d handle_cd_change: socket %d card status 0x%x"
		    " deb 0x%p\n", ddi_get_instance(pcic->dip),
		    sockp->pcs_socket, status, debounce);
#endif
	switch (status & PCIC_ISTAT_CD_MASK) {
	case PCIC_CD_PRESENT_OK:
		sockp->pcs_flags &= ~(PCS_CARD_REMOVED|PCS_CARD_CBREM);
		if (!(sockp->pcs_flags & PCS_CARD_PRESENT)) {
		uint32_t cbps;
#ifdef PCIC_DEBUG
		pcic_err(pcic->dip, 8, "New card (0x%x)\n", sockp->pcs_flags);
#endif
		cbps = pcic_getcb(pcic, CB_PRESENT_STATE);
#ifdef PCIC_DEBUG
		pcic_err(pcic->dip, 8, "CBus PS (0x%x)\n", cbps);
#endif
		/*
		 * Check the CB bits are sane.
		 */
		if ((cbps & pcic_cbps_on) != pcic_cbps_on ||
		    cbps & pcic_cbps_off) {
			cmn_err(CE_WARN,
			    "%s%d: Odd Cardbus Present State 0x%x\n",
			    ddi_get_name(pcic->dip),
			    ddi_get_instance(pcic->dip),
			    cbps);
			pcic_putcb(pcic, CB_EVENT_FORCE, CB_EF_CVTEST);
			debounce = 0;
			debounce_time = drv_usectohz(1000000);
		}
		if (debounce) {
			sockp->pcs_flags |= PCS_CARD_PRESENT;
			if (pcic_do_insertion) {

				cbps = pcic_getcb(pcic, CB_PRESENT_STATE);

				if (cbps & CB_PS_16BITCARD) {
					pcic_err(pcic->dip,
					    8, "16 bit card inserted\n");
					sockp->pcs_flags |= PCS_CARD_IS16BIT;
					/* calls pcm_adapter_callback() */
					if (pcic->pc_callback) {

						(void) ddi_prop_update_string(
						    DDI_DEV_T_NONE,
						    pcic->dip, PCM_DEVICETYPE,
						    "pccard");
						PC_CALLBACK(pcic->dip,
						    pcic->pc_cb_arg,
						    PCE_CARD_INSERT,
						    sockp->pcs_socket);
					}
				} else if (cbps & CB_PS_CBCARD) {
					pcic_err(pcic->dip,
					    8, "32 bit card inserted\n");

					if (pcic->pc_flags & PCF_CARDBUS) {
						sockp->pcs_flags |=
						    PCS_CARD_ISCARDBUS;
#ifdef CARDBUS
						if (!pcic_load_cardbus(pcic,
						    sockp)) {
							pcic_unload_cardbus(
							    pcic, sockp);
						}

#else
						cmn_err(CE_NOTE,
						    "32 bit Cardbus not"
						    " supported in"
						    " this device driver\n");
#endif
					} else {
						/*
						 * Ignore the card
						 */
						cmn_err(CE_NOTE,
						    "32 bit Cardbus not"
						    " supported on this"
						    " device\n");
					}
				} else {
					cmn_err(CE_NOTE,
					    "Unsupported PCMCIA card"
					    " inserted\n");
				}
			}
		} else {
			do_debounce = B_TRUE;
		}
		} else {
		/*
		 * It is possible to come through here if the system
		 * starts up with cards already inserted. Do nothing
		 * and don't worry about it.
		 */
#ifdef PCIC_DEBUG
		pcic_err(pcic->dip, 5,
		    "pcic%d: Odd card insertion indication on socket %d\n",
		    ddi_get_instance(pcic->dip),
		    sockp->pcs_socket);
#endif
		}
		break;

	default:
		if (!(sockp->pcs_flags & PCS_CARD_PRESENT)) {
		/*
		 * Someone has started to insert a card so delay a while.
		 */
		do_debounce = B_TRUE;
		break;
		}
		/*
		 * Otherwise this is basically the same as not present
		 * so fall through.
		 */

		/* FALLTHRU */
	case 0:
		if (sockp->pcs_flags & PCS_CARD_PRESENT) {
			if (pcic->pc_flags & PCF_CBPWRCTL) {
				pcic_putcb(pcic, CB_CONTROL, 0);
			} else {
				pcic_putb(pcic, sockp->pcs_socket,
				    PCIC_POWER_CONTROL, 0);
			(void) pcic_getb(pcic, sockp->pcs_socket,
			    PCIC_POWER_CONTROL);
		}
#ifdef PCIC_DEBUG
		pcic_err(pcic->dip, 8, "Card removed\n");
#endif
		sockp->pcs_flags &= ~PCS_CARD_PRESENT;

		if (sockp->pcs_flags & PCS_CARD_IS16BIT) {
			sockp->pcs_flags &= ~PCS_CARD_IS16BIT;
			if (pcic_do_removal && pcic->pc_callback) {
				PC_CALLBACK(pcic->dip, pcic->pc_cb_arg,
				    PCE_CARD_REMOVAL, sockp->pcs_socket);
			}
		}
		if (sockp->pcs_flags & PCS_CARD_ISCARDBUS) {
			sockp->pcs_flags &= ~PCS_CARD_ISCARDBUS;
			sockp->pcs_flags |= PCS_CARD_CBREM;
		}
		sockp->pcs_flags |= PCS_CARD_REMOVED;

		do_debounce = B_TRUE;
		}
		if (debounce && (sockp->pcs_flags & PCS_CARD_REMOVED)) {
			if (sockp->pcs_flags & PCS_CARD_CBREM) {
		/*
		 * Ensure that we do the unloading in the
		 * debounce handler, that way we're not doing
		 * nasty things in an interrupt handler. e.g.
		 * a USB device will wait for data which will
		 * obviously never come because we've
		 * unplugged the device, but the wait will
		 * wait forever because no interrupts can
		 * come in...
		 */
#ifdef CARDBUS
			pcic_unload_cardbus(pcic, sockp);
			/* pcic_dump_all(pcic); */
#endif
			sockp->pcs_flags &= ~PCS_CARD_CBREM;
			}
			sockp->pcs_flags &= ~PCS_CARD_REMOVED;
		}
		break;
	} /* switch */

	if (do_debounce) {
	/*
	 * Delay doing
	 * anything for a while so that things can settle
	 * down a little. Interrupts are already disabled.
	 * Reset the state and we'll reevaluate the
	 * whole kit 'n kaboodle when the timeout fires
	 */
#ifdef PCIC_DEBUG
		pcic_err(pcic->dip, 8, "Queueing up debounce timeout for "
		    "socket %d.%d\n",
		    ddi_get_instance(pcic->dip),
		    sockp->pcs_socket);
#endif
		sockp->pcs_debounce_id =
		    pcic_add_debqueue(sockp, debounce_time);

	/*
	 * We bug out here without re-enabling interrupts. They will
	 * be re-enabled when the debounce timeout swings through
	 * here.
	 */
		return;
	}

	/*
	 * Turn on Card detect interrupts. Other interrupts will be
	 * enabled during set_socket calls.
	 *
	 * Note that set_socket only changes interrupt settings when there
	 * is a card present.
	 */
	irq = pcic_getb(pcic, sockp->pcs_socket, PCIC_MANAGEMENT_INT);
	irq |= PCIC_CD_DETECT;
	pcic_putb(pcic, sockp->pcs_socket, PCIC_MANAGEMENT_INT, irq);
	pcic_putcb(pcic, CB_STATUS_MASK, CB_SE_CCDMASK);

	/* Out from debouncing state */
	sockp->pcs_flags &= ~PCS_DEBOUNCING;

	pcic_err(pcic->dip, 7, "Leaving pcic_handle_cd_change\n");
}

/*
 * pcic_getb()
 *	get an I/O byte based on the yardware decode method
 */
static uint8_t
pcic_getb(pcicdev_t *pcic, int socket, int reg)
{
	int work;

#if defined(PCIC_DEBUG)
	if (pcic_debug == 0x7fff) {
		cmn_err(CE_CONT, "pcic_getb0: pcic=%p socket=%d reg=%d\n",
		    (void *)pcic, socket, reg);
		cmn_err(CE_CONT, "pcic_getb1: type=%d handle=%p ioaddr=%p \n",
		    pcic->pc_io_type, (void *)pcic->handle,
		    (void *)pcic->ioaddr);
	}
#endif

	switch (pcic->pc_io_type) {
	case PCIC_IO_TYPE_YENTA:
		return (ddi_get8(pcic->handle,
		    pcic->ioaddr + CB_R2_OFFSET + reg));
	default:
		work = (socket * PCIC_SOCKET_1) | reg;
		ddi_put8(pcic->handle, pcic->ioaddr, work);
		return (ddi_get8(pcic->handle, pcic->ioaddr + 1));
	}
}

static void
pcic_putb(pcicdev_t *pcic, int socket, int reg, int8_t value)
{
	int work;

#if defined(PCIC_DEBUG)
	if (pcic_debug == 0x7fff) {
		cmn_err(CE_CONT,
		    "pcic_putb0: pcic=%p socket=%d reg=%d value=%x \n",
		    (void *)pcic, socket, reg, value);
		cmn_err(CE_CONT,
		    "pcic_putb1: type=%d handle=%p ioaddr=%p \n",
		    pcic->pc_io_type, (void *)pcic->handle,
		    (void *)pcic->ioaddr);
	}
#endif


	switch (pcic->pc_io_type) {
	case PCIC_IO_TYPE_YENTA:
		ddi_put8(pcic->handle, pcic->ioaddr + CB_R2_OFFSET + reg,
		    value);
		break;
	default:
		work = (socket * PCIC_SOCKET_1) | reg;
		ddi_put8(pcic->handle, pcic->ioaddr, work);
		ddi_put8(pcic->handle, pcic->ioaddr + 1, value);
		break;
	}
}

/*
 * chip identification functions
 */

/*
 * chip identification: Cirrus Logic PD6710/6720/6722
 */
static int
pcic_ci_cirrus(pcicdev_t *pcic)
{
	int value1, value2;

	/* Init the CL id mode */
	value1 = pcic_getb(pcic, 0, PCIC_CHIP_INFO);
	pcic_putb(pcic, 0, PCIC_CHIP_INFO, 0);
	value1 = pcic_getb(pcic, 0, PCIC_CHIP_INFO);
	value2 = pcic_getb(pcic, 0, PCIC_CHIP_INFO);

	if ((value1 & PCIC_CI_ID) == PCIC_CI_ID &&
	    (value2 & PCIC_CI_ID) == 0) {
		/* chip is a Cirrus Logic and not Intel */
		pcic->pc_type = PCIC_CL_PD6710;
		if (value1 & PCIC_CI_SLOTS)
			pcic->pc_chipname = PCIC_TYPE_PD6720;
		else
			pcic->pc_chipname = PCIC_TYPE_PD6710;
		/* now fine tune things just in case a 6722 */
		value1 = clext_reg_read(pcic, 0, PCIC_CLEXT_DMASK_0);
		if (value1 == 0) {
			clext_reg_write(pcic, 0, PCIC_CLEXT_SCRATCH, 0x55);
			value1 = clext_reg_read(pcic, 0, PCIC_CLEXT_SCRATCH);
			if (value1 == 0x55) {
				pcic->pc_chipname = PCIC_TYPE_PD6722;
				pcic->pc_type = PCIC_CL_PD6722;
				clext_reg_write(pcic, 0, PCIC_CLEXT_SCRATCH, 0);
			}
		}
		return (1);
	}
	return (0);
}

/*
 * chip identification: Vadem (VG365/465/468/469)
 */

static void
pcic_vadem_enable(pcicdev_t *pcic)
{
	ddi_put8(pcic->handle, pcic->ioaddr, PCIC_VADEM_P1);
	ddi_put8(pcic->handle, pcic->ioaddr, PCIC_VADEM_P2);
	ddi_put8(pcic->handle, pcic->ioaddr, pcic->pc_lastreg);
}

static int
pcic_ci_vadem(pcicdev_t *pcic)
{
	int value;

	pcic_vadem_enable(pcic);
	value = pcic_getb(pcic, 0, PCIC_CHIP_REVISION);
	pcic_putb(pcic, 0, PCIC_CHIP_REVISION, 0xFF);
	if (pcic_getb(pcic, 0, PCIC_CHIP_REVISION) ==
	    (value | PCIC_VADEM_D3) ||
	    (pcic_getb(pcic, 0, PCIC_CHIP_REVISION) & PCIC_REV_MASK) ==
	    PCIC_VADEM_469) {
		int vadem, new;
		pcic_vadem_enable(pcic);
		vadem = pcic_getb(pcic, 0, PCIC_VG_DMA) &
		    ~(PCIC_V_UNLOCK | PCIC_V_VADEMREV);
		new = vadem | (PCIC_V_VADEMREV|PCIC_V_UNLOCK);
		pcic_putb(pcic, 0, PCIC_VG_DMA, new);
		value = pcic_getb(pcic, 0, PCIC_CHIP_REVISION);

		/* want to lock but leave mouse or other on */
		pcic_putb(pcic, 0, PCIC_VG_DMA, vadem);
		switch (value & PCIC_REV_MASK) {
		case PCIC_VADEM_365:
			pcic->pc_chipname = PCIC_VG_365;
			pcic->pc_type = PCIC_VADEM;
			break;
		case PCIC_VADEM_465:
			pcic->pc_chipname = PCIC_VG_465;
			pcic->pc_type = PCIC_VADEM;
			pcic->pc_flags |= PCF_1SOCKET;
			break;
		case PCIC_VADEM_468:
			pcic->pc_chipname = PCIC_VG_468;
			pcic->pc_type = PCIC_VADEM;
			break;
		case PCIC_VADEM_469:
			pcic->pc_chipname = PCIC_VG_469;
			pcic->pc_type = PCIC_VADEM_VG469;
			break;
		}
		return (1);
	}
	return (0);
}

/*
 * chip identification: Ricoh
 */
static int
pcic_ci_ricoh(pcicdev_t *pcic)
{
	int value;

	value = pcic_getb(pcic, 0, PCIC_RF_CHIP_IDENT);
	switch (value) {
	case PCIC_RF_296:
		pcic->pc_type = PCIC_RICOH;
		pcic->pc_chipname = PCIC_TYPE_RF5C296;
		return (1);
	case PCIC_RF_396:
		pcic->pc_type = PCIC_RICOH;
		pcic->pc_chipname = PCIC_TYPE_RF5C396;
		return (1);
	}
	return (0);
}


/*
 * set up available address spaces in busra
 */
static void
pcic_init_assigned(dev_info_t *dip)
{
	pcm_regs_t *pcic_avail_p;
	pci_regspec_t *pci_avail_p, *regs;
	int len, entries, rlen;
	dev_info_t *pdip;

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "available", (caddr_t)&pcic_avail_p, &len) == DDI_PROP_SUCCESS) {
		/*
		 * found "available" property at the cardbus/pcmcia node
		 * need to translate address space entries from pcmcia
		 * format to pci format
		 */
		entries = len / sizeof (pcm_regs_t);
		pci_avail_p = kmem_alloc(sizeof (pci_regspec_t) * entries,
		    KM_SLEEP);
		if (pcic_apply_avail_ranges(dip, pcic_avail_p, pci_avail_p,
		    entries) == DDI_SUCCESS)
			(void) pci_resource_setup_avail(dip, pci_avail_p,
			    entries);
		kmem_free(pcic_avail_p, len);
		kmem_free(pci_avail_p, entries * sizeof (pci_regspec_t));
		return;
	}

	/*
	 * "legacy" platforms will have "available" property in pci node
	 */
	for (pdip = ddi_get_parent(dip); pdip; pdip = ddi_get_parent(pdip)) {
		if (ddi_getlongprop(DDI_DEV_T_ANY, pdip, DDI_PROP_DONTPASS,
		    "available", (caddr_t)&pci_avail_p, &len) ==
		    DDI_PROP_SUCCESS) {
			/* (void) pci_resource_setup(pdip); */
			kmem_free(pci_avail_p, len);
			break;
		}
	}

	if (pdip == NULL) {
		int len;
		char bus_type[16] = "(unknown)";
		dev_info_t *par;

		cmn_err(CE_CONT,
		    "?pcic_init_assigned: no available property for pcmcia\n");

		/*
		 * This code is taken from pci_resource_setup() but does
		 * not attempt to use the "available" property to populate
		 * the ndi maps that are created.
		 * The fact that we will actually
		 * free some resource below (that was allocated by OBP)
		 * should be enough to be going on with.
		 */
		for (par = dip; par != NULL; par = ddi_get_parent(par)) {
			len = sizeof (bus_type);

			if ((ddi_prop_op(DDI_DEV_T_ANY, par,
			    PROP_LEN_AND_VAL_BUF,
			    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
			    "device_type",
			    (caddr_t)&bus_type, &len) == DDI_SUCCESS) &&
			    (strcmp(bus_type, DEVI_PCI_NEXNAME) == 0 ||
			    strcmp(bus_type, DEVI_PCIEX_NEXNAME) == 0))
				break;
		}
		if (par != NULL &&
		    (ndi_ra_map_setup(par, NDI_RA_TYPE_MEM) != NDI_SUCCESS ||
		    ndi_ra_map_setup(par, NDI_RA_TYPE_IO) != NDI_SUCCESS))
			par = NULL;
	} else {
#ifdef CARDBUS
		cardbus_bus_range_t *bus_range;
		int k;

		if (ddi_getlongprop(DDI_DEV_T_ANY, pdip, 0, "bus-range",
		    (caddr_t)&bus_range, &k) == DDI_PROP_SUCCESS) {
			if (bus_range->lo != bus_range->hi)
				pcic_err(pdip, 9, "allowable bus range is "
				    "%u->%u\n", bus_range->lo, bus_range->hi);
			else {
				pcic_err(pdip, 0,
				    "!No spare PCI bus numbers, range is "
				    "%u->%u, cardbus isn't usable\n",
				    bus_range->lo, bus_range->hi);
			}
			kmem_free(bus_range, k);
		} else
			pcic_err(pdip, 0, "!No bus-range property seems to "
			    "have been set up\n");
#endif
		/*
		 * Have a valid parent with the "available" property
		 */
		(void) pci_resource_setup(pdip);
	}

	if ((strcmp(ddi_get_name(dip), "pcma") == 0) &&
	    ddi_getlongprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
	    "assigned-addresses",
	    (caddr_t)&regs, &rlen) == DDI_SUCCESS) {
		ra_return_t ra;

		/*
		 * On the UltraBook IIi the ranges are assigned under
		 * openboot. If we don't free them here the first I/O
		 * space that can be used is up above 0x10000 which
		 * doesn't work for this driver due to restrictions
		 * on the PCI I/O addresses the controllers can cope with.
		 * They are never going to be used by anything else
		 * so free them up to the general pool. AG.
		 */
		pcic_err(dip, 1, "Free assigned addresses\n");

		if ((PCI_REG_ADDR_G(regs[0].pci_phys_hi) ==
		    PCI_REG_ADDR_G(PCI_ADDR_MEM32)) &&
		    regs[0].pci_size_low == 0x1000000) {
			ra.ra_addr_lo = regs[0].pci_phys_low;
			ra.ra_len = regs[0].pci_size_low;
			(void) pcmcia_free_mem(dip, &ra);
		}
		if ((PCI_REG_ADDR_G(regs[1].pci_phys_hi) ==
		    PCI_REG_ADDR_G(PCI_ADDR_IO)) &&
		    (regs[1].pci_size_low == 0x8000 ||
		    regs[1].pci_size_low == 0x4000))   /* UB-IIi || UB-I */
		{
			ra.ra_addr_lo = regs[1].pci_phys_low;
			ra.ra_len = regs[1].pci_size_low;
			(void) pcmcia_free_io(dip, &ra);
		}
		kmem_free((caddr_t)regs, rlen);
	}
}

/*
 * translate "available" from pcmcia format to pci format
 */
static int
pcic_apply_avail_ranges(dev_info_t *dip, pcm_regs_t *pcic_p,
    pci_regspec_t *pci_p, int entries)
{
	int i, range_len, range_entries;
	pcic_ranges_t *pcic_range_p;

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "ranges",
	    (caddr_t)&pcic_range_p, &range_len) != DDI_PROP_SUCCESS) {
		cmn_err(CE_CONT, "?pcic_apply_avail_ranges: "
		    "no ranges property for pcmcia\n");
		return (DDI_FAILURE);
	}

	range_entries = range_len / sizeof (pcic_ranges_t);

	/* for each "available" entry to be translated */
	for (i = 0; i < entries; i++, pcic_p++, pci_p++) {
		int j;
		pcic_ranges_t *range_p = pcic_range_p;
		pci_p->pci_phys_hi = -1u; /* default invalid value */

		/* for each "ranges" entry to be searched */
		for (j = 0; j < range_entries; j++, range_p++) {
			uint64_t range_end = range_p->pcic_range_caddrlo +
			    range_p->pcic_range_size;
			uint64_t avail_end = pcic_p->phys_lo + pcic_p->phys_len;

			if ((range_p->pcic_range_caddrhi != pcic_p->phys_hi) ||
			    (range_p->pcic_range_caddrlo > pcic_p->phys_lo) ||
			    (range_end < avail_end))
				continue;

			pci_p->pci_phys_hi = range_p->pcic_range_paddrhi;
			pci_p->pci_phys_mid = range_p->pcic_range_paddrmid;
			pci_p->pci_phys_low = range_p->pcic_range_paddrlo
			    + (pcic_p->phys_lo - range_p->pcic_range_caddrlo);
			pci_p->pci_size_hi = 0;
			pci_p->pci_size_low = pcic_p->phys_len;
		}
	}
	kmem_free(pcic_range_p, range_len);
	return (DDI_SUCCESS);
}

static int
pcic_open(dev_t *dev, int flag, int otyp, cred_t *cred)
{
#ifdef CARDBUS
	if (cardbus_is_cb_minor(*dev))
		return (cardbus_open(dev, flag, otyp, cred));
#endif
	return (EINVAL);
}

static int
pcic_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
#ifdef CARDBUS
	if (cardbus_is_cb_minor(dev))
		return (cardbus_close(dev, flag, otyp, cred));
#endif
	return (EINVAL);
}

static int
pcic_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred,
	int *rval)
{
#ifdef CARDBUS
	if (cardbus_is_cb_minor(dev))
		return (cardbus_ioctl(dev, cmd, arg, mode, cred, rval));
#endif
	return (EINVAL);
}


static boolean_t
pcic_load_cardbus(pcicdev_t *pcic, const pcic_socket_t *sockp)
{
	uint32_t present_state;
	dev_info_t *dip = pcic->dip;
	set_socket_t s;
	get_socket_t g;
	boolean_t retval;
	unsigned vccLevel;

	pcic_err(dip, 8, "entering pcic_load_cardbus\n");

	pcic_mutex_exit(&pcic->pc_lock);

	bzero(&s, sizeof (set_socket_t));
	s.socket = sockp->pcs_socket;
	s.SCIntMask = SBM_CD|SBM_RDYBSY;
	s.IFType = IF_CARDBUS;
	s.State = (unsigned)~0;

	present_state = pcic_getcb(pcic, CB_PRESENT_STATE);
	if (present_state & PCIC_VCC_3VCARD)
		s.VccLevel = PCIC_VCC_3VLEVEL;
	else if (present_state & PCIC_VCC_5VCARD)
		s.VccLevel = PCIC_VCC_5VLEVEL;
	else {
		cmn_err(CE_CONT,
		    "pcic_load_cardbus: unsupported card voltage\n");
		goto failure;
	}
	vccLevel = s.VccLevel;
	s.Vpp1Level = s.Vpp2Level = 0;

	if (pcic_set_socket(dip, &s) != SUCCESS)
		goto failure;

	if (pcic_reset_socket(dip, sockp->pcs_socket,
	    RESET_MODE_CARD_ONLY) != SUCCESS)
		goto failure;

	bzero(&g, sizeof (get_socket_t));
	g.socket = sockp->pcs_socket;
	if (pcic_get_socket(dip, &g) != SUCCESS)
		goto failure;

	bzero(&s, sizeof (set_socket_t));
	s.socket = sockp->pcs_socket;
	s.SCIntMask = SBM_CD;
	s.IREQRouting = g.IRQRouting;
	s.IFType = g.IFType;
	s.CtlInd = g.CtlInd;
	s.State = (unsigned)~0;
	s.VccLevel = vccLevel;
	s.Vpp1Level = s.Vpp2Level = 0;

	retval = pcic_set_socket(dip, &s);
	pcmcia_cb_resumed(s.socket);
	if (retval != SUCCESS)
		goto failure;

	retval = cardbus_load_cardbus(dip, sockp->pcs_socket, pcic->pc_base);
	goto exit;

failure:
	retval = B_FALSE;

exit:
	pcic_mutex_enter(&pcic->pc_lock);
	pcic_err(dip, 8, "exit pcic_load_cardbus (%s)\n",
	    retval ? "success" : "failure");
	return (retval);
}

static void
pcic_unload_cardbus(pcicdev_t *pcic, const pcic_socket_t *sockp)
{
	dev_info_t *dip = pcic->dip;
	set_socket_t s;

	pcic_mutex_exit(&pcic->pc_lock);

	cardbus_unload_cardbus(dip);

	bzero(&s, sizeof (set_socket_t));
	s.socket = sockp->pcs_socket;
	s.SCIntMask = SBM_CD|SBM_RDYBSY;
	s.IREQRouting = 0;
	s.IFType = IF_MEMORY;
	s.CtlInd = 0;
	s.State = 0;
	s.VccLevel = s.Vpp1Level = s.Vpp2Level = 0;

	(void) pcic_set_socket(dip, &s);

	pcic_mutex_enter(&pcic->pc_lock);
}

static uint32_t
pcic_getcb(pcicdev_t *pcic, int reg)
{
	ASSERT(pcic->pc_io_type == PCIC_IO_TYPE_YENTA);

	return (ddi_get32(pcic->handle,
	    (uint32_t *)(pcic->ioaddr + CB_CB_OFFSET + reg)));
}

static void
pcic_putcb(pcicdev_t *pcic, int reg, uint32_t value)
{
	ASSERT(pcic->pc_io_type == PCIC_IO_TYPE_YENTA);

	ddi_put32(pcic->handle,
	    (uint32_t *)(pcic->ioaddr + CB_CB_OFFSET + reg), value);
}

static void
pcic_enable_io_intr(pcicdev_t *pcic, int socket, int irq)
{
	uint8_t value;
	uint16_t brdgctl;

	value = pcic_getb(pcic, socket, PCIC_INTERRUPT) & ~PCIC_INTR_MASK;
	pcic_putb(pcic, socket, PCIC_INTERRUPT, value | irq);

	switch (pcic->pc_type) {
	case PCIC_INTEL_i82092:
		pcic_82092_smiirq_ctl(pcic, socket, PCIC_82092_CTL_IRQ,
		    PCIC_82092_INT_ENABLE);
		break;
	case PCIC_O2_OZ6912:
		value = pcic_getb(pcic, 0, PCIC_CENTDMA);
		value |= 0x8;
		pcic_putb(pcic, 0, PCIC_CENTDMA, value);
		break;
	case PCIC_CL_PD6832:
	case PCIC_TI_PCI1250:
	case PCIC_TI_PCI1221:
	case PCIC_TI_PCI1225:
	case PCIC_TI_PCI1410:
	case PCIC_ENE_1410:
	case PCIC_TI_PCI1510:
	case PCIC_TI_PCI1520:
	case PCIC_TI_PCI1420:
	case PCIC_ENE_1420:
		/* route card functional interrupts to PCI interrupts */
		brdgctl = ddi_get16(pcic->cfg_handle,
		    (uint16_t *)(pcic->cfgaddr + PCI_CBUS_BRIDGE_CTRL));
		pcic_err(NULL, 1,
		    "pcic_enable_io_intr brdgctl(0x%x) was: 0x%x\n",
		    PCI_CBUS_BRIDGE_CTRL, brdgctl);
		brdgctl &= ~PCIC_BRDGCTL_INTR_MASK;
		ddi_put16(pcic->cfg_handle,
		    (uint16_t *)(pcic->cfgaddr + PCI_CBUS_BRIDGE_CTRL),
		    brdgctl);
		/* Flush the write */
		(void) ddi_get16(pcic->cfg_handle,
		    (uint16_t *)(pcic->cfgaddr + PCI_CBUS_BRIDGE_CTRL));
		break;
	default:
		break;
	}
}

static void
pcic_disable_io_intr(pcicdev_t *pcic, int socket)
{
	uint8_t value;
	uint16_t brdgctl;

	value = pcic_getb(pcic, socket, PCIC_INTERRUPT) & ~PCIC_INTR_MASK;
	pcic_putb(pcic, socket, PCIC_INTERRUPT, value);

	switch (pcic->pc_type) {
	case PCIC_INTEL_i82092:
		pcic_82092_smiirq_ctl(pcic, socket, PCIC_82092_CTL_IRQ,
		    PCIC_82092_INT_DISABLE);
		break;
	case PCIC_O2_OZ6912:
		value = pcic_getb(pcic, 0, PCIC_CENTDMA);
		value &= ~0x8;
		pcic_putb(pcic, 0, PCIC_CENTDMA, value);
		/* Flush the write */
		(void) pcic_getb(pcic, 0, PCIC_CENTDMA);
		break;
	case PCIC_CL_PD6832:
	case PCIC_TI_PCI1250:
	case PCIC_TI_PCI1221:
	case PCIC_TI_PCI1225:
	case PCIC_TI_PCI1410:
	case PCIC_ENE_1410:
	case PCIC_TI_PCI1510:
	case PCIC_TI_PCI1520:
	case PCIC_TI_PCI1420:
	case PCIC_ENE_1420:
		/*
		 * This maps I/O interrupts to ExCA which
		 * have been turned off by the write to
		 * PCIC_INTERRUPT above. It would appear to
		 * be the only way to actually turn I/O Ints off
		 * while retaining CS Ints.
		 */
		brdgctl = ddi_get16(pcic->cfg_handle,
		    (uint16_t *)(pcic->cfgaddr + PCI_CBUS_BRIDGE_CTRL));
		pcic_err(NULL, 1,
		    "pcic_disable_io_intr brdgctl(0x%x) was: 0x%x\n",
		    PCI_CBUS_BRIDGE_CTRL, brdgctl);
		brdgctl |= PCIC_BRDGCTL_INTR_MASK;
		ddi_put16(pcic->cfg_handle,
		    (uint16_t *)(pcic->cfgaddr + PCI_CBUS_BRIDGE_CTRL),
		    brdgctl);
		/* Flush the write */
		(void) ddi_get16(pcic->cfg_handle,
		    (uint16_t *)(pcic->cfgaddr + PCI_CBUS_BRIDGE_CTRL));
		break;
	default:
		break;
	}
}

static void
pcic_cb_enable_intr(dev_info_t *dip)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;

	mutex_enter(&pcic->pc_lock);
	pcic_enable_io_intr(pcic, 0, pcic->pc_sockets[0].pcs_irq);
	mutex_exit(&pcic->pc_lock);
}

static void
pcic_cb_disable_intr(dev_info_t *dip)
{
	anp_t *anp = ddi_get_driver_private(dip);
	pcicdev_t *pcic = anp->an_private;

	mutex_enter(&pcic->pc_lock);
	pcic_disable_io_intr(pcic, 0);
	mutex_exit(&pcic->pc_lock);
}

static int
log_pci_cfg_err(ushort_t e, int bridge_secondary)
{
	int	nerr = 0;
	if (e & PCI_STAT_PERROR) {
		nerr++;
		cmn_err(CE_CONT, "detected parity error.\n");
	}
	if (e & PCI_STAT_S_SYSERR) {
		nerr++;
		if (bridge_secondary)
			cmn_err(CE_CONT, "received system error.\n");
		else
			cmn_err(CE_CONT, "signalled system error.\n");
	}
	if (e & PCI_STAT_R_MAST_AB) {
		nerr++;
		cmn_err(CE_CONT, "received master abort.\n");
	}
	if (e & PCI_STAT_R_TARG_AB)
		cmn_err(CE_CONT, "received target abort.\n");
	if (e & PCI_STAT_S_TARG_AB)
		cmn_err(CE_CONT, "signalled target abort\n");
	if (e & PCI_STAT_S_PERROR) {
		nerr++;
		cmn_err(CE_CONT, "signalled parity error\n");
	}
	return (nerr);
}

#if defined(__sparc)
static int
pcic_fault(enum pci_fault_ops op, void *arg)
{
	pcicdev_t *pcic = (pcicdev_t *)arg;
	ushort_t pci_cfg_stat =
	    pci_config_get16(pcic->cfg_handle, PCI_CONF_STAT);
	ushort_t pci_cfg_sec_stat =
	    pci_config_get16(pcic->cfg_handle, 0x16);
	char	nm[24];
	int	nerr = 0;

	cardbus_dump_pci_config(pcic->dip);

	switch (op) {
	case FAULT_LOG:
		(void) sprintf(nm, "%s-%d", ddi_driver_name(pcic->dip),
		    ddi_get_instance(pcic->dip));

		cmn_err(CE_WARN, "%s: PCIC fault log start:\n", nm);
		cmn_err(CE_WARN, "%s: primary err (%x):\n", nm, pci_cfg_stat);
		nerr += log_pci_cfg_err(pci_cfg_stat, 0);
		cmn_err(CE_WARN, "%s: sec err (%x):\n", nm, pci_cfg_sec_stat);
		nerr += log_pci_cfg_err(pci_cfg_sec_stat, 1);
		cmn_err(CE_CONT, "%s: PCI fault log end.\n", nm);
		return (nerr);
	case FAULT_POKEFINI:
	case FAULT_RESET:
		pci_config_put16(pcic->cfg_handle,
		    PCI_CONF_STAT, pci_cfg_stat);
		pci_config_put16(pcic->cfg_handle, 0x16, pci_cfg_sec_stat);
		break;
	case FAULT_POKEFLT:
		if (!(pci_cfg_stat & PCI_STAT_S_SYSERR))
			return (1);
		if (!(pci_cfg_sec_stat & PCI_STAT_R_MAST_AB))
			return (1);
		break;
	default:
		break;
	}
	return (DDI_SUCCESS);
}
#endif

static void
pcic_do_resume(pcicdev_t *pcic)
{
	int	i, interrupt;
	uint8_t cfg;


#if defined(PCIC_DEBUG)
	pcic_err(NULL, 6, "pcic_do_resume(): entered\n");
#endif

	pcic_mutex_enter(&pcic->pc_lock); /* protect the registers */
	for (i = 0; i < pcic->pc_numsockets; i++) {
		/* Enable interrupts  on PCI if needs be */
		interrupt = pcic_getb(pcic, i, PCIC_INTERRUPT);
		if (pcic->pc_flags & PCF_USE_SMI)
			interrupt |= PCIC_INTR_ENABLE;
		pcic_putb(pcic, i, PCIC_INTERRUPT,
		    PCIC_RESET | interrupt);
		pcic->pc_sockets[i].pcs_debounce_id =
		    pcic_add_debqueue(&pcic->pc_sockets[i],
		    drv_usectohz(pcic_debounce_time));
	}
	pcic_mutex_exit(&pcic->pc_lock); /* protect the registers */
	if (pcic_do_pcmcia_sr)
		(void) pcmcia_wait_insert(pcic->dip);
	/*
	 * The CardBus controller may be in RESET state after the
	 * system is resumed from sleeping. The RESET bit is in
	 * the Bridge Control register. This is true for all(TI,
	 * Toshiba ToPIC95/97, RICOH, and O2Micro) CardBus
	 * controllers. Need to clear the RESET bit explicitly.
	 */
	cfg = ddi_get8(pcic->cfg_handle,
	    pcic->cfgaddr + PCIC_BRIDGE_CTL_REG);
	if (cfg & (1<<6)) {
		cfg &= ~(1<<6);
		ddi_put8(pcic->cfg_handle,
		    pcic->cfgaddr + PCIC_BRIDGE_CTL_REG,
		    cfg);
		cfg = ddi_get8(pcic->cfg_handle,
		    pcic->cfgaddr + PCIC_BRIDGE_CTL_REG);
		if (cfg & (1<<6)) {
			pcic_err(pcic->dip, 1,
			    "Failed to take pcic out of reset");
		}
	}

}

static void
pcic_debounce(pcic_socket_t *pcs)
{
	uint8_t status, stschng;

	pcic_mutex_enter(&pcs->pcs_pcic->pc_lock);
	pcs->pcs_flags &= ~PCS_STARTING;
	stschng = pcic_getb(pcs->pcs_pcic, pcs->pcs_socket,
	    PCIC_CARD_STATUS_CHANGE);
	status = pcic_getb(pcs->pcs_pcic, pcs->pcs_socket,
	    PCIC_INTERFACE_STATUS);
#ifdef PCIC_DEBUG
	pcic_err(pcs->pcs_pcic->dip, 8,
	    "pcic_debounce(0x%p, dip=0x%p) socket %d st 0x%x "
	    "chg 0x%x flg 0x%x\n",
	    (void *)pcs, (void *) pcs->pcs_pcic->dip, pcs->pcs_socket,
	    status, stschng, pcs->pcs_flags);
#endif

	pcic_putb(pcs->pcs_pcic, pcs->pcs_socket, PCIC_CARD_STATUS_CHANGE,
	    PCIC_CD_DETECT);
	pcic_handle_cd_change(pcs->pcs_pcic, pcs, status);
	pcic_mutex_exit(&pcs->pcs_pcic->pc_lock);
}

static void
pcic_deb_thread()
{
	callb_cpr_t cprinfo;
	struct debounce *debp;
	clock_t lastt;

	CALLB_CPR_INIT(&cprinfo, &pcic_deb_mtx,
	    callb_generic_cpr, "pcic debounce thread");
	mutex_enter(&pcic_deb_mtx);
	while (pcic_deb_threadid) {
		while (pcic_deb_queue) {
#ifdef PCIC_DEBUG
			pcic_dump_debqueue("Thread");
#endif
			debp = pcic_deb_queue;
			(void) drv_getparm(LBOLT, &lastt);
			if (lastt >= debp->expire) {
				pcic_deb_queue = debp->next;
				mutex_exit(&pcic_deb_mtx);
				pcic_debounce(debp->pcs);
				mutex_enter(&pcic_deb_mtx);
				kmem_free(debp, sizeof (*debp));
			} else {
				(void) cv_timedwait(&pcic_deb_cv,
				    &pcic_deb_mtx, debp->expire);
			}
		}
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		cv_wait(&pcic_deb_cv, &pcic_deb_mtx);
		CALLB_CPR_SAFE_END(&cprinfo, &pcic_deb_mtx);
	}
	pcic_deb_threadid = (kthread_t *)1;
	cv_signal(&pcic_deb_cv);
	CALLB_CPR_EXIT(&cprinfo);	/* Also exits the mutex */
	thread_exit();
}

static void *
pcic_add_debqueue(pcic_socket_t *pcs, int clocks)
{
	clock_t lbolt;
	struct debounce *dbp, **dbpp = &pcic_deb_queue;

	(void) drv_getparm(LBOLT, &lbolt);
	dbp = kmem_alloc(sizeof (struct debounce), KM_SLEEP);

	dbp->expire = lbolt + clocks;
	dbp->pcs = pcs;
	mutex_enter(&pcic_deb_mtx);
	while (*dbpp) {
		if (dbp->expire > (*dbpp)->expire)
			dbpp = &((*dbpp)->next);
		else
			break;
	}
	dbp->next = *dbpp;
	*dbpp = dbp;
#ifdef PCIC_DEBUG
	pcic_dump_debqueue("Add");
#endif
	cv_signal(&pcic_deb_cv);
	mutex_exit(&pcic_deb_mtx);
	return (dbp);
}

static void
pcic_rm_debqueue(void *id)
{
	struct debounce *dbp, **dbpp = &pcic_deb_queue;

	dbp = (struct debounce *)id;
	mutex_enter(&pcic_deb_mtx);
	while (*dbpp) {
		if (*dbpp == dbp) {
			*dbpp = dbp->next;
			kmem_free(dbp, sizeof (*dbp));
#ifdef PCIC_DEBUG
			pcic_dump_debqueue("Remove");
#endif
			cv_signal(&pcic_deb_cv);
			mutex_exit(&pcic_deb_mtx);
			return;
		}
		dbpp = &((*dbpp)->next);
	}
	pcic_err(NULL, 6, "pcic: Failed to find debounce id 0x%p\n", id);
	mutex_exit(&pcic_deb_mtx);
}


static int	pcic_powerdelay = 0;

static int
pcic_exca_powerctl(pcicdev_t *pcic, int socket, int powerlevel)
{
	int	ind, value, orig_pwrctl;

	/* power setup -- if necessary */
	orig_pwrctl = pcic_getb(pcic, socket, PCIC_POWER_CONTROL);

#if defined(PCIC_DEBUG)
	pcic_err(pcic->dip, 6,
	    "pcic_exca_powerctl(socket %d) powerlevel=%x orig 0x%x\n",
	    socket, powerlevel, orig_pwrctl);
#endif
	/* Preserve the PCIC_OUTPUT_ENABLE (control lines output enable) bit. */
	powerlevel = (powerlevel & ~POWER_OUTPUT_ENABLE) |
	    (orig_pwrctl & POWER_OUTPUT_ENABLE);
	if (powerlevel != orig_pwrctl) {
		if (powerlevel & ~POWER_OUTPUT_ENABLE) {
			int	ifs;
			/*
			 * set power to socket
			 * note that the powerlevel was calculated earlier
			 */
			pcic_putb(pcic, socket, PCIC_POWER_CONTROL, powerlevel);
			(void) pcic_getb(pcic, socket, PCIC_POWER_CONTROL);

			/*
			 * this second write to the power control register
			 * is needed to resolve a problem on
			 * the IBM ThinkPad 750
			 * where the first write doesn't latch.
			 * The second write appears to always work and
			 * doesn't hurt the operation of other chips
			 * so we can just use it -- this is good since we can't
			 * determine what chip the 750 actually uses
			 * (I suspect an early Ricoh).
			 */
			pcic_putb(pcic, socket, PCIC_POWER_CONTROL, powerlevel);

			value = pcic_getb(pcic, socket, PCIC_POWER_CONTROL);
			pcic_mswait(pcic, socket, pcic_powerdelay);
#if defined(PCIC_DEBUG)
			pcic_err(pcic->dip, 8,
			    "\tpowerlevel reg = %x (ifs %x)\n",
			    value, pcic_getb(pcic, socket,
			    PCIC_INTERFACE_STATUS));
			pcic_err(pcic->dip, 8,
			    "CBus regs: PS 0x%x, Control 0x%x\n",
			    pcic_getcb(pcic, CB_PRESENT_STATE),
			    pcic_getcb(pcic, CB_CONTROL));
#endif
			/*
			 * since power was touched, make sure it says it
			 * is on.  This lets it become stable.
			 */
			for (ind = 0; ind < 20; ind++) {
				ifs = pcic_getb(pcic, socket,
				    PCIC_INTERFACE_STATUS);
				if (ifs & PCIC_POWER_ON)
					break;
				else {
					pcic_putb(pcic, socket,
					    PCIC_POWER_CONTROL, 0);
					(void) pcic_getb(pcic, socket,
					    PCIC_POWER_CONTROL);
					pcic_mswait(pcic, socket, 40);
					if (ind == 10) {
						pcic_putcb(pcic, CB_EVENT_FORCE,
						    CB_EF_CVTEST);
						pcic_mswait(pcic, socket, 100);
					}
					pcic_putb(pcic, socket,
					    PCIC_POWER_CONTROL,
					    powerlevel & ~POWER_OUTPUT_ENABLE);
					(void) pcic_getb(pcic, socket,
					    PCIC_POWER_CONTROL);
					pcic_mswait(pcic, socket,
					    pcic_powerdelay);
					pcic_putb(pcic, socket,
					    PCIC_POWER_CONTROL, powerlevel);
					(void) pcic_getb(pcic, socket,
					    PCIC_POWER_CONTROL);
					pcic_mswait(pcic, socket,
					    pcic_powerdelay);
				}
			}

			if (!(ifs & PCIC_POWER_ON)) {
				cmn_err(CE_WARN,
				    "pcic socket %d: Power didn't get turned"
				    "on!\nif status 0x%x pwrc 0x%x(x%x) "
				    "misc1 0x%x igc 0x%x ind %d\n",
				    socket, ifs,
				    pcic_getb(pcic, socket, PCIC_POWER_CONTROL),
				    orig_pwrctl,
				    pcic_getb(pcic, socket, PCIC_MISC_CTL_1),
				    pcic_getb(pcic, socket, PCIC_INTERRUPT),
				    ind);
				return (BAD_VCC);
			}
#if defined(PCIC_DEBUG)
			pcic_err(pcic->dip, 8,
			    "\tind = %d, if status %x pwrc 0x%x "
			    "misc1 0x%x igc 0x%x\n",
			    ind, ifs,
			    pcic_getb(pcic, socket, PCIC_POWER_CONTROL),
			    pcic_getb(pcic, socket, PCIC_MISC_CTL_1),
			    pcic_getb(pcic, socket, PCIC_INTERRUPT));
#endif
		} else {
			/* explicitly turned off the power */
			pcic_putb(pcic, socket, PCIC_POWER_CONTROL, powerlevel);
			(void) pcic_getb(pcic, socket, PCIC_POWER_CONTROL);
		}
	}
	return (SUCCESS);
}

static int pcic_cbdoreset_during_poweron = 1;
static int
pcic_cbus_powerctl(pcicdev_t *pcic, int socket)
{
	uint32_t cbctl = 0, orig_cbctl, cbstev, cbps;
	int ind, iobits;
	pcic_socket_t *sockp = &pcic->pc_sockets[socket];

	pcic_putcb(pcic, CB_STATUS_EVENT, CB_SE_POWER_CYCLE);

	ind = pcic_power[sockp->pcs_vpp1].PowerLevel/10;
	cbctl |= pcic_cbv_levels[ind];

	ind = pcic_power[sockp->pcs_vcc].PowerLevel/10;
	cbctl |= (pcic_cbv_levels[ind]<<4);

	orig_cbctl = pcic_getcb(pcic, CB_CONTROL);

#if defined(PCIC_DEBUG)
	pcic_err(pcic->dip, 6,
	    "pcic_cbus_powerctl(socket %d) vcc %d vpp1 %d "
	    "cbctl 0x%x->0x%x\n",
	    socket, sockp->pcs_vcc, sockp->pcs_vpp1, orig_cbctl, cbctl);
#endif
	if (cbctl != orig_cbctl) {
		if (pcic_cbdoreset_during_poweron &&
		    (orig_cbctl & (CB_C_VCCMASK|CB_C_VPPMASK)) == 0) {
			iobits = pcic_getb(pcic, socket, PCIC_INTERRUPT);
			pcic_putb(pcic, socket, PCIC_INTERRUPT,
			    iobits & ~PCIC_RESET);
		}
		pcic_putcb(pcic, CB_CONTROL, cbctl);

		if ((cbctl & CB_C_VCCMASK) == (orig_cbctl & CB_C_VCCMASK)) {
		pcic_mswait(pcic, socket, pcic_powerdelay);
		return (SUCCESS);
		}
		for (ind = 0; ind < 20; ind++) {
		cbstev = pcic_getcb(pcic, CB_STATUS_EVENT);

		if (cbstev & CB_SE_POWER_CYCLE) {

		/*
		 * delay 400 ms: though the standard defines that the Vcc
		 * set-up time is 20 ms, some PC-Card bridge requires longer
		 * duration.
		 * Note: We should check the status AFTER the delay to give time
		 * for things to stabilize.
		 */
			pcic_mswait(pcic, socket, 400);

			cbps = pcic_getcb(pcic, CB_PRESENT_STATE);
			if (cbctl && !(cbps & CB_PS_POWER_CYCLE)) {
			/* break; */
			cmn_err(CE_WARN, "cbus_powerctl: power off??\n");
			}
			if (cbctl & CB_PS_BADVCC) {
			cmn_err(CE_WARN, "cbus_powerctl: bad power request\n");
			break;
			}

#if defined(PCIC_DEBUG)
			pcic_err(pcic->dip, 8,
			    "cbstev = 0x%x cbps = 0x%x cbctl 0x%x(0x%x)",
			    cbstev, pcic_getcb(pcic, CB_PRESENT_STATE),
			    cbctl, orig_cbctl);
#endif
			if (pcic_cbdoreset_during_poweron &&
			    (orig_cbctl & (CB_C_VCCMASK|CB_C_VPPMASK)) == 0) {
				pcic_putb(pcic, socket, PCIC_INTERRUPT, iobits);
			}
			return (SUCCESS);
		}
		pcic_mswait(pcic, socket, 40);
		}
		if (pcic_cbdoreset_during_poweron &&
		    (orig_cbctl & (CB_C_VCCMASK|CB_C_VPPMASK)) == 0) {
			pcic_putb(pcic, socket, PCIC_INTERRUPT, iobits);
		}
		cmn_err(CE_WARN,
		    "pcic socket %d: Power didn't get turned on/off!\n"
		    "cbstev = 0x%x cbps = 0x%x cbctl 0x%x(0x%x) "
		    "vcc %d vpp1 %d", socket, cbstev,
		    pcic_getcb(pcic, CB_PRESENT_STATE),
		    cbctl, orig_cbctl, sockp->pcs_vcc, sockp->pcs_vpp1);
		return (BAD_VCC);
	}
	return (SUCCESS);
}

static int	pcic_do_pprintf = 0;

static void
pcic_dump_debqueue(char *msg)
{
	struct debounce *debp = pcic_deb_queue;
	clock_t lbolt;

	(void) drv_getparm(LBOLT, &lbolt);
	pcic_err(NULL, 6, debp ? "pcic debounce list (%s) lbolt 0x%x:\n" :
	    "pcic debounce_list (%s) EMPTY lbolt 0x%x\n", msg, lbolt);
	while (debp) {
		pcic_err(NULL, 6, "%p: exp 0x%x next 0x%p id 0x%p\n",
		    (void *) debp, (int)debp->expire, (void *) debp->next,
		    debp->pcs->pcs_debounce_id);
		debp = debp->next;
	}
}


/* PRINTFLIKE3 */
static void
pcic_err(dev_info_t *dip, int level, const char *fmt, ...)
{
	if (pcic_debug && (level <= pcic_debug)) {
		va_list adx;
		int	instance;
		char	buf[256];
		const char	*name;
#if !defined(PCIC_DEBUG)
		int	ce;
		char	qmark = 0;

		if (level <= 3)
			ce = CE_WARN;
		else
			ce = CE_CONT;
		if (level == 4)
			qmark = 1;
#endif

		if (dip) {
			instance = ddi_get_instance(dip);
			/* name = ddi_binding_name(dip); */
			name = ddi_driver_name(dip);
		} else {
			instance = 0;
			name = "";
		}

		va_start(adx, fmt);
		(void) vsprintf(buf, fmt, adx);
		va_end(adx);

#if defined(PCIC_DEBUG)
		if (pcic_do_pprintf) {
			if (dip) {
				if (instance >= 0)
					prom_printf("%s(%d),0x%p: %s", name,
					    instance, (void *)dip, buf);
				else
					prom_printf("%s,0x%p: %s",
					    name, (void *)dip, buf);
			} else
				prom_printf(buf);
		} else {
			if (dip) {
				if (instance >= 0)
					cmn_err(CE_CONT, "%s(%d),0x%p: %s",
					    name, instance, (void *) dip, buf);
				else
					cmn_err(CE_CONT, "%s,0x%p: %s",
					    name, (void *) dip, buf);
			} else
				cmn_err(CE_CONT, buf);
		}
#else
		if (dip)
			cmn_err(ce, qmark ? "?%s%d: %s" : "%s%d: %s", name,
			    instance, buf);
		else
			cmn_err(ce, qmark ? "?%s" : buf, buf);
#endif
	}
}
