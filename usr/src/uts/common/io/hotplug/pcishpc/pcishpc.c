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
 * PCISHPC - The Standard PCI HotPlug Controller driver module. This driver
 * can be used with PCI HotPlug controllers that are compatible
 * with the PCI SHPC specification 1.x.
 */

#include <sys/note.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/varargs.h>
#include <sys/hwconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci.h>
#include <sys/callb.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/hotplug/pci/pcishpc.h>
#include <sys/hotplug/pci/pcishpc_regs.h>
#include <sys/hotplug/hpcsvc.h>


/* General Register bit weights for the 32-bit SHPC registers */
#define	REG_BIT0	0x00000001
#define	REG_BIT1	0x00000002
#define	REG_BIT2	0x00000004
#define	REG_BIT3	0x00000008
#define	REG_BIT4	0x00000010
#define	REG_BIT5	0x00000020
#define	REG_BIT6	0x00000040
#define	REG_BIT7	0x00000080
#define	REG_BIT8	0x00000100
#define	REG_BIT9	0x00000200
#define	REG_BIT10	0x00000400
#define	REG_BIT11	0x00000800
#define	REG_BIT12	0x00001000
#define	REG_BIT13	0x00002000
#define	REG_BIT14	0x00004000
#define	REG_BIT15	0x00008000
#define	REG_BIT16	0x00010000
#define	REG_BIT17	0x00020000
#define	REG_BIT18	0x00040000
#define	REG_BIT19	0x00080000
#define	REG_BIT20	0x00100000
#define	REG_BIT21	0x00200000
#define	REG_BIT22	0x00400000
#define	REG_BIT23	0x00800000
#define	REG_BIT24	0x01000000
#define	REG_BIT25	0x02000000
#define	REG_BIT26	0x04000000
#define	REG_BIT27	0x08000000
#define	REG_BIT28	0x10000000
#define	REG_BIT29	0x20000000
#define	REG_BIT30	0x40000000
#define	REG_BIT31	0x80000000

/* Definitions used with the SHPC SHPC_SLOTS_AVAIL_I_REG register */
#define	SHPC_AVAIL_33MHZ_CONV_SPEED_SHIFT	0
#define	SHPC_AVAIL_66MHZ_PCIX_SPEED_SHIFT	8
#define	SHPC_AVAIL_100MHZ_PCIX_SPEED_SHIFT	16
#define	SHPC_AVAIL_133MHZ_PCIX_SPEED_SHIFT	24
#define	SHPC_AVAIL_SPEED_MASK			0x1F

/* Definitions used with the SHPC SHPC_SLOTS_AVAIL_II_REG register */
#define	SHPC_AVAIL_66MHZ_CONV_SPEED_SHIFT	0

/* Register bits used with the SHPC SHPC_PROF_IF_SBCR_REG register */
#define	SHPC_SBCR_33MHZ_CONV_SPEED	0
#define	SHPC_SBCR_66MHZ_CONV_SPEED	REG_BIT0
#define	SHPC_SBCR_66MHZ_PCIX_SPEED	REG_BIT1
#define	SHPC_SBCR_100MHZ_PCIX_SPEED	(REG_BIT0|REG_BIT1)
#define	SHPC_SBCR_133MHZ_PCIX_SPEED	REG_BIT2
#define	SHPC_SBCR_SPEED_MASK		(REG_BIT0|REG_BIT1|REG_BIT2)

/* Register bits used with the SHPC SHPC_COMMAND_STATUS_REG register */
#define	SHPC_COMM_STS_ERR_INVALID_SPEED		REG_BIT19
#define	SHPC_COMM_STS_ERR_INVALID_COMMAND	REG_BIT18
#define	SHPC_COMM_STS_ERR_MRL_OPEN		REG_BIT17
#define	SHPC_COMM_STS_ERR_MASK			(REG_BIT17|REG_BIT18|REG_BIT19)
#define	SHPC_COMM_STS_CTRL_BUSY			REG_BIT16
#define	SHPC_COMM_STS_SET_SPEED			REG_BIT6

/* Register bits used with the SHPC SHPC_CTRL_SERR_INT_REG register */
#define	SHPC_SERR_INT_GLOBAL_IRQ_MASK	REG_BIT0
#define	SHPC_SERR_INT_GLOBAL_SERR_MASK	REG_BIT1
#define	SHPC_SERR_INT_CMD_COMPLETE_MASK	REG_BIT2
#define	SHPC_SERR_INT_ARBITER_SERR_MASK	REG_BIT3
#define	SHPC_SERR_INT_CMD_COMPLETE_IRQ	REG_BIT16
#define	SHPC_SERR_INT_ARBITER_IRQ	REG_BIT17
#define	SHPC_SERR_INT_MASK_ALL		(REG_BIT0|REG_BIT1|REG_BIT2|REG_BIT3)

/* Register bits used with the SHPC SHPC_LOGICAL_SLOT_REGS register */
#define	SHPC_SLOT_POWER_ONLY		REG_BIT0
#define	SHPC_SLOT_ENABLED		REG_BIT1
#define	SHPC_SLOT_DISABLED		(REG_BIT0 | REG_BIT1)
#define	SHPC_SLOT_STATE_MASK		(REG_BIT0 | REG_BIT1)
#define	SHPC_SLOT_MRL_STATE_MASK	REG_BIT8
#define	SHPC_SLOT_66MHZ_CONV_CAPABLE	REG_BIT9
#define	SHPC_SLOT_CARD_EMPTY_MASK	(REG_BIT10 | REG_BIT11)
#define	SHPC_SLOT_66MHZ_PCIX_CAPABLE	REG_BIT12
#define	SHPC_SLOT_100MHZ_PCIX_CAPABLE	REG_BIT13
#define	SHPC_SLOT_133MHZ_PCIX_CAPABLE	(REG_BIT12 | REG_BIT13)
#define	SHPC_SLOT_PCIX_CAPABLE_MASK	(REG_BIT12 | REG_BIT13)
#define	SHPC_SLOT_PCIX_CAPABLE_SHIFT	12
#define	SHPC_SLOT_PRESENCE_DETECTED	REG_BIT16
#define	SHPC_SLOT_ISO_PWR_DETECTED	REG_BIT17
#define	SHPC_SLOT_ATTN_DETECTED		REG_BIT18
#define	SHPC_SLOT_MRL_DETECTED		REG_BIT19
#define	SHPC_SLOT_POWER_DETECTED	REG_BIT20
#define	SHPC_SLOT_PRESENCE_MASK		REG_BIT24
#define	SHPC_SLOT_ISO_PWR_MASK		REG_BIT25
#define	SHPC_SLOT_ATTN_MASK		REG_BIT26
#define	SHPC_SLOT_MRL_MASK		REG_BIT27
#define	SHPC_SLOT_POWER_MASK		REG_BIT28
#define	SHPC_SLOT_MRL_SERR_MASK		REG_BIT29
#define	SHPC_SLOT_POWER_SERR_MASK	REG_BIT30
#define	SHPC_SLOT_MASK_ALL		(REG_BIT24|REG_BIT25|REG_BIT26|\
					REG_BIT27|REG_BIT28|REG_BIT30)

/* Register bits used with the SHPC SHPC_IRQ_LOCATOR_REG register. */
#define	SHPC_IRQ_CMD_COMPLETE		REG_BIT0
#define	SHPC_IRQ_SLOT_N_PENDING		REG_BIT1

/* Register bits used with the SHPC SHPC_SERR_LOCATOR_REG register. */
#define	SHPC_IRQ_SERR_ARBITER_PENDING	REG_BIT0
#define	SHPC_IRQ_SERR_SLOT_N_PENDING	REG_BIT1

/* Register bits used with the SHPC SHPC_SLOT_CONFIGURATION_REG register */
#define	SHPC_SLOT_CONFIG_MRL_SENSOR		REG_BIT30
#define	SHPC_SLOT_CONFIG_ATTN_BUTTON		REG_BIT31
#define	SHPC_SLOT_CONFIG_PHY_SLOT_NUM_SHIFT	16
#define	SHPC_SLOT_CONFIG_PHY_SLOT_NUM_MASK	0x3FF
#define	SHPC_SLOT_CONFIG_PHY_SLOT_NUM(reg)	(((reg) >> 16) & 0x3FF)

/* Max PCISHPC controller slots */
#define	MAX_SHPC_SLOTS	31

/* PCISHPC controller command complete delay in microseconds. */
#define	SHPC_COMMAND_WAIT_TIME			10000

/*
 * Power good wait time after issuing a command to change the slot state
 * to power only state.
 */
#define	SHPC_POWER_GOOD_WAIT_TIME		220000

/* reset delay to 1 sec. */
static int pcishpc_reset_delay = 1000000;

/* PCISHPC controller softstate structure */
typedef struct pcishpc_ctrl {
	dev_info_t	*shpc_dip;		/* DIP for SHPC Nexus */
	ddi_acc_handle_t shpc_config_hdl;	/* SHPC DDI cfg handle */
	kmutex_t	shpc_intr_mutex;	/* Interrupt mutex lock */
	boolean_t	interrupt_installed;	/* Interrupt installed */
	boolean_t	command_complete;	/* Got a cmd complete IRQ */
	kcondvar_t	cmd_comp_cv;
	boolean_t	arbiter_timeout;	/* Got a Arb timeout IRQ */
	kmutex_t	shpc_mutex;		/* Mutex for this SHPC */
	char		nexus_path[MAXNAMELEN]; /* Pathname of Nexus */
	uint32_t	shpc_bus;		/* SHPC bus */
	uint32_t	shpc_dev;		/* SHPC device */
	uint32_t	shpc_func;		/* SHPC function */
	uint8_t		shpc_dword_select;	/* SHPC register offset */
	uint8_t		shpc_dword_data_reg;	/* SHPC data register */
	uint32_t	shpc_slots_avail1_reg;	/* SHPC Slots Available1 Reg */
	uint32_t	shpc_slots_avail2_reg;	/* SHPC Slots Available2 Reg */
	uint32_t	numSlotsImpl;		/* # of HP Slots Implemented */
	uint32_t	numSlotsConn;		/* # of HP Slots Connected */
	int		currBusSpeed;		/* Current Bus Speed */
	uint32_t	deviceStart;		/* 1st PCI Device # */
	uint32_t	physStart;		/* 1st Phys Device # */
	uint32_t	deviceIncreases;	/* Device # Increases */
	struct pcishpc	*slots[MAX_SHPC_SLOTS]; /* Slot pointers */
	boolean_t	has_attn;		/* Do we have attn btn?	*/
	boolean_t	has_mrl;		/* Do we have MRL? */
	struct pcishpc_ctrl *nextp;		/* Linked list pointer */
} pcishpc_ctrl_t;

/* PCISHPC slot softstate structure */
typedef struct pcishpc {
	pcishpc_ctrl_t	*ctrl;			/* SHPC ctrl for this slot */
	hpc_slot_info_t	slot_info;		/* HPS framework slot info */
	hpc_slot_t	slot_handle;		/* HPS framework handle */
	hpc_slot_ops_t	 *slot_ops;		/* HPS framework callbacks */
	uint32_t  fault_led_state;		/* Fault LED state */
	uint32_t  power_led_state;		/* Power LED state */
	uint32_t  attn_led_state;		/* Attn LED state */
	uint32_t  active_led_state;		/* Active LED state */
	hpc_slot_state_t slot_state;		/* Slot State */
	uint32_t  deviceNum;			/* PCI device num for slot */
	uint32_t  slotNum;			/* SHPC slot number */
	uint32_t  phy_slot_num;			/* physical slot number */
	uint32_t  slot_events;			/* Slot event(s) IRQ */
	kcondvar_t attn_btn_cv;			/* ATTN button pressed intr */
	boolean_t attn_btn_pending;
	kthread_t *attn_btn_threadp;		/* ATTN button event thread */
	boolean_t attn_btn_thread_exit;
	struct pcishpc *nextp;			/* Linked list pointer */
} pcishpc_t;
/* mutex to protect the shpc_head and shpc_ctrl_head linked lists */
static kmutex_t pcishpc_list_mutex;

/* Pointer to a linked list of shpc slot softstate structures */
static pcishpc_t *pcishpc_head = NULL;

/* Pointer to a linked list of shpc controller softstate structures */
static pcishpc_ctrl_t *pcishpc_ctrl_head = NULL;

/* mutex to protect access to the controller */
static kmutex_t pcishpc_control_mutex;

/* SHPC static function prototypes */
static pcishpc_ctrl_t *pcishpc_create_controller(dev_info_t *dip);
static int	 pcishpc_destroy_controller(dev_info_t *dip);
static pcishpc_ctrl_t *pcishpc_get_controller(dev_info_t *dip);
static pcishpc_t	*pcishpc_create_slot(pcishpc_ctrl_t *ctrl_p);
static int	pcishpc_destroy_slots(pcishpc_ctrl_t *ctrl_p);
static pcishpc_t	*pcishpc_hpc_get_slot_state(hpc_slot_t slot);
static int	pcishpc_setup_controller(pcishpc_ctrl_t *ctrl_p);
static int	pcishpc_register_slot(pcishpc_ctrl_t *ctrl_p, int slot);
static int	pcishpc_connect(caddr_t ops_arg,
					hpc_slot_t slot_hdl, void *data,
					uint_t flags);
static int	pcishpc_disconnect(caddr_t ops_arg,
					hpc_slot_t slot_hdl, void *data,
					uint_t flags);
static int	pcishpc_pci_control(caddr_t ops_arg, hpc_slot_t slot_hdl,
				int request, caddr_t arg);
static int	pcishpc_setled(pcishpc_t *pcishpc_p, hpc_led_t led,
				hpc_led_state_t state);
static int	pcishpc_set_power_state(pcishpc_t *pcishpc_p,
					hpc_slot_state_t state);
static int	pcishpc_set_bus_speed(pcishpc_t *pcishpc_p);
static int	pcishpc_probe_controller(pcishpc_ctrl_t *pcishpc_p);
static int	pcishpc_get_pci_info(pcishpc_ctrl_t *pcishpc_p);
static void	pcishpc_get_slot_state(pcishpc_t *pcishpc_p);
static int	pcishpc_process_intr(pcishpc_ctrl_t *ctrl_p);
static int	pcishpc_enable_irqs(pcishpc_ctrl_t *ctrl_p);
static int	pcishpc_disable_irqs(pcishpc_ctrl_t *ctrl_p);
static void	pcishpc_set_soft_int(pcishpc_ctrl_t *ctrl_p);
static int	pcishpc_wait_busy(pcishpc_ctrl_t *ctrl_p);
static int	pcishpc_issue_command(pcishpc_ctrl_t *ctrl_p,
				uint32_t cmd_code);
static int	pcishpc_led_shpc_to_hpc(int state);
static int	pcishpc_led_hpc_to_shpc(int state);
static int	pcishpc_slot_shpc_to_hpc(int state);
static int	pcishpc_slot_hpc_to_shpc(int state);
static char	*pcishpc_textledstate(hpc_led_state_t state);
static char	*pcishpc_textslotstate(hpc_slot_state_t state);
static char	*pcishpc_textrequest(int request);
static int	pcishpc_set_slot_state(pcishpc_t *pcishpc_p);
static void	pcishpc_dump_regs(pcishpc_ctrl_t *ctrl_p);
static void	pcishpc_write_reg(pcishpc_ctrl_t *ctrl_p, int reg,
				uint32_t data);
static uint32_t	pcishpc_read_reg(pcishpc_ctrl_t *ctrl_p, int reg);
static void	pcishpc_debug(char *fmt, ...);

static void pcishpc_attn_btn_handler(pcishpc_t *pcishpc_p);
static void pcishpc_set_slot_name(pcishpc_ctrl_t *ctrl_p, int slot);

static int pcishpc_debug_enabled = 0;

/* Module operations information for the kernel */
extern struct mod_ops mod_miscops;
static struct modlmisc modlmisc = {
	&mod_miscops,
	"PCI SHPC hotplug module",
};

/* Module linkage information for the kernel */
static struct modlinkage modlinkage = {
	MODREV_1,
	&modlmisc,
	NULL
};

int
_init(void)
{
	int rc;

	if ((rc = mod_install(&modlinkage)) != 0) {
		pcishpc_debug("pcishpc: install error=%d", rc);
		return (rc);
	}

	/* Init the shpc driver list mutex. */
	mutex_init(&pcishpc_list_mutex, NULL, MUTEX_DRIVER, NULL);
	/* Init the shpc control mutex. */
	mutex_init(&pcishpc_control_mutex, NULL, MUTEX_DRIVER, NULL);

	pcishpc_debug("pcishpc: installed");
	return (rc);
}

int
_fini(void)
{
	pcishpc_debug("pcishpc: _fini called()");
	/* XXX - to be fixed later */
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	pcishpc_debug("pcishpc: _info called()");
	return (mod_info(&modlinkage, modinfop));
}


/*
 * pcishpc_create_controller()
 *
 * This function allocates and creates an SHPC controller state structure
 * and adds it to the linked list of controllers.
 */
static pcishpc_ctrl_t *
pcishpc_create_controller(dev_info_t *dip)
{
	pcishpc_ctrl_t *ctrl_p;

	pcishpc_debug("pcishpc: create controller for %s#%d",
			ddi_driver_name(dip), ddi_get_instance(dip));

	ctrl_p = kmem_zalloc(sizeof (pcishpc_ctrl_t), KM_SLEEP);

	ctrl_p->interrupt_installed = B_FALSE;
	ctrl_p->shpc_dip = dip;

	(void) ddi_pathname(dip, ctrl_p->nexus_path);

	/* Get the PCI BUS,DEVICE,FUNCTION for this SHPC controller. */
	if (pcishpc_get_pci_info(ctrl_p) != DDI_SUCCESS) {

		pcishpc_debug("pcishpc_create_controller() "
			"Error: pcishpc_get_pci_info() failed");
		kmem_free(ctrl_p, sizeof (pcishpc_ctrl_t));
		return (NULL);
	}

	if (pci_config_setup(dip, &ctrl_p->shpc_config_hdl) != DDI_SUCCESS) {
		pcishpc_debug("pcishpc_create_controller() "
			"Error: Unable to map SHPC PCI Config registers");
		kmem_free(ctrl_p, sizeof (pcishpc_ctrl_t));
		return (NULL);
	}

	/* Make sure the SHPC is listed in the PCI capibilities list. */
	if (pcishpc_probe_controller(ctrl_p) != DDI_SUCCESS) {
		pcishpc_debug("pcishpc_create_controller() "
			"Error: Unable to find SHPC controller");
		pci_config_teardown(&ctrl_p->shpc_config_hdl);
		kmem_free(ctrl_p, sizeof (pcishpc_ctrl_t));
		return (NULL);
	}

	/* Init the interrupt mutex */
	mutex_init(&ctrl_p->shpc_intr_mutex, NULL, MUTEX_DRIVER,
		(void *)PCISHPC_INTR_PRI);

	/* Interrupts are now enabled. */
	ctrl_p->interrupt_installed = B_TRUE;

	/* Init the shpc controller's mutex. */
	mutex_init(&ctrl_p->shpc_mutex, NULL, MUTEX_DRIVER, NULL);

	mutex_enter(&pcishpc_list_mutex);

	/* Insert new softstate into linked list of current soft states. */
	ctrl_p->nextp  = pcishpc_ctrl_head;
	pcishpc_ctrl_head = ctrl_p;

	mutex_exit(&pcishpc_list_mutex);

	pcishpc_debug("pcishpc_create_controller() success");

	return (ctrl_p);
}


/*
 * pcishpc_probe_controller()
 *
 * This function probes to make sure there is indeed an SHPC controller.
 */
static int
pcishpc_probe_controller(pcishpc_ctrl_t *ctrl_p)
{
	uint8_t cap_ptr;
	uint8_t cap_id;
	uint16_t status;

	status = pci_config_get16(ctrl_p->shpc_config_hdl, PCI_CONF_STAT);
	if (!(status & PCI_STAT_CAP)) {
		return (DDI_FAILURE);
	}

	/* Get a pointer to the PCI capabilities list. */
	cap_ptr = pci_config_get8(ctrl_p->shpc_config_hdl, PCI_BCNF_CAP_PTR);

	cap_ptr &= 0xFC;

	/* Walk PCI capabilities list searching for the SHPC capability. */
	while (cap_ptr != PCI_CAP_NEXT_PTR_NULL) {
		cap_id = pci_config_get8(ctrl_p->shpc_config_hdl, cap_ptr);

		pcishpc_debug("pcishpc_probe_controller() capability @ "
				"pointer=%02x (id=%02x)", cap_ptr, cap_id);

		if (cap_id == PCI_CAP_ID_PCI_HOTPLUG) {
			/* Save the SHPC register offset. */
			ctrl_p->shpc_dword_select	= cap_ptr+2;
			/* Save the SHPC data register. */
			ctrl_p->shpc_dword_data_reg = cap_ptr+4;
			break;
		}

		/* Get the pointer to the next capability. */
		cap_ptr = pci_config_get8(ctrl_p->shpc_config_hdl,
			cap_ptr+1);

		cap_ptr &= 0xFC;
	}

	if (cap_ptr == PCI_CAP_NEXT_PTR_NULL) {
		return (DDI_FAILURE);
	}

	pcishpc_debug("pcishpc_probe_controller() Found SHPC capibility");

	return (DDI_SUCCESS);
}


/*
 * pcishpc_destroy_controller()
 *
 * This function deallocates all of the SHPC controller resources.
 */
static int
pcishpc_destroy_controller(dev_info_t *dip)
{
	pcishpc_ctrl_t *ctrl_p;
	pcishpc_ctrl_t **ctrl_pp;

	pcishpc_debug("pcishpc_destroy_controller() called(dip=%p)", dip);

	mutex_enter(&pcishpc_list_mutex);

	ctrl_pp = &pcishpc_ctrl_head;

	/* Walk the linked list of softstates. */
	while ((ctrl_p = *ctrl_pp) != NULL) {
		if (ctrl_p->shpc_dip == dip) {
			/*
			 * Deallocate the slot state structures for
			 * this controller.
			 */
			(void) pcishpc_destroy_slots(ctrl_p);

			*ctrl_pp = ctrl_p->nextp;

			pci_config_teardown(&ctrl_p->shpc_config_hdl);

			cv_destroy(&ctrl_p->cmd_comp_cv);

			mutex_destroy(&ctrl_p->shpc_mutex);
			mutex_destroy(&ctrl_p->shpc_intr_mutex);
			kmem_free(ctrl_p, sizeof (pcishpc_ctrl_t));
			mutex_exit(&pcishpc_list_mutex);

			pcishpc_debug("pcishpc_destroy_controller() success");
			return (DDI_SUCCESS);
		}
		ctrl_pp = &(ctrl_p->nextp);
	}

	mutex_exit(&pcishpc_list_mutex);

	pcishpc_debug("pcishpc_destroy_controller() not found");

	return (DDI_FAILURE);
}


/*
 * pcishpc_intr()
 *
 * This is the SHPC controller interrupt handler.
 */
int
pcishpc_intr(dev_info_t *dip)
{
	pcishpc_ctrl_t *ctrl_p = pcishpc_get_controller(dip);
	int slot;
	uint32_t irq_locator, irq_serr_locator, reg;
	boolean_t slot_event = B_FALSE;

	pcishpc_debug("pcishpc_intr() called");

	if (ctrl_p->interrupt_installed == B_TRUE) {
		mutex_enter(&ctrl_p->shpc_intr_mutex);

		pcishpc_debug("pcishpc_intr() interrupt received");

		reg = pcishpc_read_reg(ctrl_p, SHPC_CTRL_SERR_INT_REG);

		if (reg & SHPC_SERR_INT_CMD_COMPLETE_IRQ) {
			pcishpc_debug("pcishpc_intr() "
				"SHPC_SERR_INT_CMD_COMPLETE_IRQ detected");
			ctrl_p->command_complete = B_TRUE;
			cv_signal(&ctrl_p->cmd_comp_cv);
		}

		if (reg & SHPC_SERR_INT_ARBITER_IRQ) {
			pcishpc_debug("pcishpc_intr() SHPC_SERR_INT_ARBITER_IRQ"
					" detected");
			ctrl_p->arbiter_timeout = B_TRUE;
		}

		/* Write back the SERR INT register to acknowledge the IRQs. */
		pcishpc_write_reg(ctrl_p, SHPC_CTRL_SERR_INT_REG, reg);

		irq_locator = pcishpc_read_reg(ctrl_p, SHPC_IRQ_LOCATOR_REG);

		irq_serr_locator = pcishpc_read_reg(ctrl_p,
					SHPC_SERR_LOCATOR_REG);

		/* Check for slot events that might have occured. */
		for (slot = 0; slot < ctrl_p->numSlotsImpl; slot++) {
			if ((irq_locator & (SHPC_IRQ_SLOT_N_PENDING<<slot)) ||
					(irq_serr_locator &
					(SHPC_IRQ_SERR_SLOT_N_PENDING<<slot))) {
				pcishpc_debug("pcishpc_intr() slot %d and "
						"pending IRQ", slot+1);

				/*
				 * Note that we will need to generate a
				 * slot event interrupt.
				 */
				slot_event = B_TRUE;

				reg = pcishpc_read_reg(ctrl_p,
						SHPC_LOGICAL_SLOT_REGS+slot);

				/* Record any pending slot interrupts/events. */
				ctrl_p->slots[slot]->slot_events |= reg;

				/* Acknoledge any slot interrupts */
				pcishpc_write_reg(ctrl_p,
					SHPC_LOGICAL_SLOT_REGS+slot, reg);
			}
		}

		if (slot_event == B_TRUE) {
			pcishpc_debug("pcishpc_intr() slot(s) have event(s)");
			(void) pcishpc_process_intr(ctrl_p);
		} else {
			pcishpc_debug("pcishpc_intr() No slot event(s)");
		}

		mutex_exit(&ctrl_p->shpc_intr_mutex);

		pcishpc_debug("pcishpc_intr() claimed");

		return (DDI_INTR_CLAIMED);
	}

	pcishpc_debug("pcishpc_intr() unclaimed");

	return (DDI_INTR_UNCLAIMED);
}

/*
 * pcishpc_process_intr()
 *
 * This is the SHPC soft interrupt handler.
 */
static int
pcishpc_process_intr(pcishpc_ctrl_t *ctrl_p)
{
	int slot;

	mutex_enter(&ctrl_p->shpc_mutex);

	pcishpc_debug("pcishpc_process_intr() called");

	/* XXX - add event handling code here */
	for (slot = 0; slot < ctrl_p->numSlotsImpl; slot++) {
		if (ctrl_p->slots[slot]->slot_events &
				SHPC_SLOT_PRESENCE_DETECTED)
			pcishpc_debug("slot %d: SHPC_SLOT_PRESENCE_DETECTED",
					slot+1);

		if (ctrl_p->slots[slot]->slot_events &
				SHPC_SLOT_ISO_PWR_DETECTED)
			pcishpc_debug("slot %d: SHPC_SLOT_ISO_PWR_DETECTED",
					slot+1);

		if (ctrl_p->slots[slot]->slot_events &
		    SHPC_SLOT_ATTN_DETECTED) {
			pcishpc_debug("slot %d: SHPC_SLOT_ATTN_DETECTED",
					slot+1);
			/*
			 * if ATTN button event is still pending
			 * then cancel it
			 */
			if (ctrl_p->slots[slot]->attn_btn_pending == B_TRUE)
				ctrl_p->slots[slot]->attn_btn_pending = B_FALSE;

			/* wake up the ATTN event handler */
			cv_signal(&ctrl_p->slots[slot]->attn_btn_cv);
		}

		if (ctrl_p->slots[slot]->slot_events & SHPC_SLOT_MRL_DETECTED)
			pcishpc_debug("slot %d: SHPC_SLOT_MRL_DETECTED",
					slot+1);

		if (ctrl_p->slots[slot]->slot_events & SHPC_SLOT_POWER_DETECTED)
			pcishpc_debug("slot %d: SHPC_SLOT_POWER_DETECTED",
					slot+1);

		/* Clear the events now that we've processed all of them. */
		ctrl_p->slots[slot]->slot_events = 0;
	}

	mutex_exit(&ctrl_p->shpc_mutex);

	return (DDI_INTR_CLAIMED);
}


/*
 * pcishpc_get_controller()
 *
 * This function retrieves the hot plug SHPC controller soft state.
 */
static pcishpc_ctrl_t *
pcishpc_get_controller(dev_info_t *dip)
{
	pcishpc_ctrl_t *ctrl_p;

	pcishpc_debug("pcishpc_get_controller() called (dip=%p)", dip);

	mutex_enter(&pcishpc_list_mutex);

	ctrl_p = pcishpc_ctrl_head;

	while (ctrl_p) {
		if (ctrl_p->shpc_dip == dip)
			break;
		ctrl_p = ctrl_p->nextp;
	}

	mutex_exit(&pcishpc_list_mutex);

	pcishpc_debug("pcishpc_get_controller() (ctrl_p=%llx)", ctrl_p);

	return (ctrl_p);
}


/*
 * pcishpc_hpc_get_slot_state()
 *
 * This function retrieves the hot plug SHPC soft state from the
 * the HPS framework slot handle.
 */
static pcishpc_t *
pcishpc_hpc_get_slot_state(hpc_slot_t slot)
{
	pcishpc_t *pcishpc_p;

	pcishpc_debug("pcishpc_hpc_get_slot_state() called (hpc_slot=%x)",
		slot);

	mutex_enter(&pcishpc_list_mutex);

	pcishpc_p = pcishpc_head;

	while (pcishpc_p) {
		if (pcishpc_p->slot_handle == slot) {
			pcishpc_debug("pcishpc_hpc_get_slot_state() found "
					"(pcishpc=%x)", pcishpc_p);
			mutex_exit(&pcishpc_list_mutex);
			return (pcishpc_p);
		}
		pcishpc_p = pcishpc_p->nextp;
	}

	mutex_exit(&pcishpc_list_mutex);

	pcishpc_debug("pcishpc_hpc_get_slot_state() failed (slot=%x)", slot);

	return (NULL);
}


/*
 * pcishpc_get_pci_info()
 *
 * Read the PCI Bus, PCI Device, and PCI function for the SHPC controller.
 */
static int
pcishpc_get_pci_info(pcishpc_ctrl_t *pcishpc_p)
{
	pci_regspec_t *regspec;
	int reglen;

	pcishpc_debug("pcishpc_get_pci_info() called");

	if (ddi_getlongprop(DDI_DEV_T_NONE, pcishpc_p->shpc_dip,
			DDI_PROP_DONTPASS, "reg", (caddr_t)&regspec, &reglen)
				!= DDI_SUCCESS) {
		pcishpc_debug("pcishpc_get_pci_info() failed to get regspec.");
		return (DDI_FAILURE);
	}

	pcishpc_p->shpc_bus  = PCI_REG_BUS_G(regspec[0].pci_phys_hi);
	pcishpc_p->shpc_dev  = PCI_REG_DEV_G(regspec[0].pci_phys_hi);
	pcishpc_p->shpc_func = PCI_REG_FUNC_G(regspec[0].pci_phys_hi);

	kmem_free(regspec, reglen);

	pcishpc_debug("pcishpc_get_pci_info() %s%d: bus=%d, dev=%d, func=%d",
			ddi_driver_name(pcishpc_p->shpc_dip),
			ddi_get_instance(pcishpc_p->shpc_dip),
			pcishpc_p->shpc_bus, pcishpc_p->shpc_dev,
				pcishpc_p->shpc_func);

	return (DDI_SUCCESS);
}


/*
 * pcishpc_init()
 *
 * Install and configure an SHPC controller and register the HotPlug slots
 * with the Solaris HotPlug framework. This function is usually called by
 * a PCI bridge Nexus driver that has a built in SHPC controller.
 */
int
pcishpc_init(dev_info_t *dip)
{
	pcishpc_ctrl_t *ctrl_p;
	int i;

	pcishpc_debug("pcishpc_init() called from %s#%d",
			ddi_driver_name(dip), ddi_get_instance(dip));

	mutex_enter(&pcishpc_control_mutex);

	if (pcishpc_get_controller(dip) != NULL) {
		pcishpc_debug("pcishpc_init() shpc instance already "
				"initialized!");
		mutex_exit(&pcishpc_control_mutex);
		return (DDI_SUCCESS);
	}

	/* Initialize soft state structure for the SHPC instance. */
	ctrl_p = pcishpc_create_controller(dip);

	if (ctrl_p == NULL) {
		pcishpc_debug("pcishpc_init() failed to create shpc softstate");
		mutex_exit(&pcishpc_control_mutex);
		return (DDI_FAILURE);
	}

	if (pcishpc_setup_controller(ctrl_p) != DDI_SUCCESS) {
		pcishpc_debug("pcishpc_init() failed to setup controller");
		(void) pcishpc_destroy_controller(dip);
		mutex_exit(&pcishpc_control_mutex);
		return (DDI_FAILURE);
	}

#if 0
	pcishpc_debug("%s%d: P2P bridge register dump:",
		ddi_driver_name(dip), ddi_get_instance(dip));

	for (i = 0; i < 0x100; i += 4) {
		pcishpc_debug("SHPC Cfg reg 0x%02x: %08x", i,
			pci_config_get32(ctrl_p->shpc_config_hdl, i));
	}
#endif

	/* Setup each HotPlug slot on this SHPC controller. */
	for (i = 0; i < ctrl_p->numSlotsImpl; i++) {
		if (pcishpc_register_slot(ctrl_p, i) != DDI_SUCCESS) {
			pcishpc_debug("pcishpc_init() failed to register "
				"slot %d", i);
			(void) pcishpc_destroy_controller(dip);
			mutex_exit(&pcishpc_control_mutex);
			return (DDI_FAILURE);
		}
	}

	(void) pcishpc_enable_irqs(ctrl_p);

	if (pcishpc_debug_enabled) {
		/* Dump out the SHPC registers. */
		pcishpc_dump_regs(ctrl_p);
	}

	mutex_exit(&pcishpc_control_mutex);

	pcishpc_debug("pcishpc_init() success(dip=%p)", dip);
	return (DDI_SUCCESS);
}


/*
 * pcishpc_enable_irqs()
 *
 * Enable/unmask the different IRQ's we support from the SHPC controller.
 */
static int
pcishpc_enable_irqs(pcishpc_ctrl_t *ctrl_p)
{
	uint32_t reg;
	int slot;

	reg = pcishpc_read_reg(ctrl_p, SHPC_CTRL_SERR_INT_REG);

	/* Enable all interrupts. */
	reg &= ~SHPC_SERR_INT_MASK_ALL;

	pcishpc_write_reg(ctrl_p, SHPC_CTRL_SERR_INT_REG, reg);

	/* Unmask the interrupts for each slot. */
	for (slot = 0; slot < ctrl_p->numSlotsImpl; slot++) {
		ctrl_p->slots[slot]->slot_events = 0;

		reg = pcishpc_read_reg(ctrl_p, SHPC_LOGICAL_SLOT_REGS+slot);
		if ((reg & SHPC_SLOT_STATE_MASK) == SHPC_SLOT_ENABLED) {
			reg &= ~(SHPC_SLOT_MASK_ALL | SHPC_SLOT_MRL_SERR_MASK);
			ctrl_p->numSlotsConn++;
			if (ctrl_p->currBusSpeed == -1)
				ctrl_p->currBusSpeed = pcishpc_read_reg(ctrl_p,
				    SHPC_PROF_IF_SBCR_REG) &
				    SHPC_SBCR_SPEED_MASK;
		} else {
			reg &= ~(SHPC_SLOT_MASK_ALL);
		}

		/* Enable/Unmask all slot interrupts. */
		pcishpc_write_reg(ctrl_p, SHPC_LOGICAL_SLOT_REGS+slot, reg);
	}

	pcishpc_debug("pcishpc_enable_irqs: ctrl_p 0x%p, "
	    "current bus speed 0x%x, slots connected 0x%x\n", ctrl_p,
	    ctrl_p->currBusSpeed, ctrl_p->numSlotsConn);

	return (DDI_SUCCESS);
}


/*
 * pcishpc_disable_irqs()
 *
 * Disable/Mask the different IRQ's we support from the SHPC controller.
 */
static int
pcishpc_disable_irqs(pcishpc_ctrl_t *ctrl_p)
{
	uint32_t reg;
	int slot;

	reg = pcishpc_read_reg(ctrl_p, SHPC_CTRL_SERR_INT_REG);

	/* Mask all interrupts. */
	reg |= SHPC_SERR_INT_MASK_ALL;

	pcishpc_write_reg(ctrl_p, SHPC_CTRL_SERR_INT_REG, reg);

	/* Unmask the interrupts for each slot. */
	for (slot = 0; slot < ctrl_p->numSlotsImpl; slot++) {
		reg = pcishpc_read_reg(ctrl_p, SHPC_LOGICAL_SLOT_REGS+slot);

		/* Disable/Mask all slot interrupts. */
		reg |= SHPC_SLOT_MASK_ALL;

		pcishpc_write_reg(ctrl_p, SHPC_LOGICAL_SLOT_REGS+slot, reg);
	}

	pcishpc_debug("pcishpc_disable_irqs: ctrl_p 0x%p, "
	    "current bus speed 0x%x, slots connected 0x%x\n", ctrl_p,
	    ctrl_p->currBusSpeed, ctrl_p->numSlotsConn);

	return (DDI_SUCCESS);
}


/*
 * pcishpc_register_slot()
 *
 * Create and register a slot with the Solaris HotPlug framework.
 */
static int
pcishpc_register_slot(pcishpc_ctrl_t *ctrl_p, int slot)
{
	pcishpc_t *pcishpc_p;

	pcishpc_p = pcishpc_create_slot(ctrl_p);

	ctrl_p->slots[slot] = pcishpc_p;

	pcishpc_p->slot_ops = hpc_alloc_slot_ops(KM_SLEEP);

	pcishpc_p->slot_ops->hpc_version = HPC_SLOT_OPS_VERSION;

	pcishpc_p->slotNum = slot;

	/* Setup the PCI device # for this SHPC slot. */
	if (ctrl_p->deviceIncreases)
		pcishpc_p->deviceNum = ctrl_p->deviceStart + pcishpc_p->slotNum;
	else
		pcishpc_p->deviceNum = ctrl_p->deviceStart - pcishpc_p->slotNum;

	/* Setup the HPS framework slot ops callbacks for the SHPC driver. */
	pcishpc_p->slot_ops->hpc_op_connect	 = pcishpc_connect;
	pcishpc_p->slot_ops->hpc_op_disconnect = pcishpc_disconnect;
	pcishpc_p->slot_ops->hpc_op_control	 = pcishpc_pci_control;
	/* PCI HPC drivers do not support the insert/remove callbacks. */
	pcishpc_p->slot_ops->hpc_op_insert	  = NULL;
	pcishpc_p->slot_ops->hpc_op_remove	  = NULL;

	/* Setup the HPS framework slot information. */
	pcishpc_p->slot_info.version = HPC_SLOT_OPS_VERSION;
	pcishpc_p->slot_info.slot_type = HPC_SLOT_TYPE_PCI;
	/* Do not auto enable the deivce in this slot. */
	pcishpc_p->slot_info.slot_flags = HPC_SLOT_NO_AUTO_ENABLE |
						HPC_SLOT_CREATE_DEVLINK;

	pcishpc_p->slot_info.slot.pci.device_number = pcishpc_p->deviceNum;
	pcishpc_p->slot_info.slot.pci.slot_capabilities = HPC_SLOT_64BITS;

	/* setup thread for handling ATTN button events */
	if (ctrl_p->has_attn) {
		pcishpc_debug("pcishpc_register_slot: "
		    "setting up ATTN button event "
		    "handler thread for slot %d\n", slot);
		cv_init(&pcishpc_p->attn_btn_cv, NULL, CV_DRIVER, NULL);
		pcishpc_p->attn_btn_pending = B_FALSE;
		pcishpc_p->attn_btn_threadp = thread_create(NULL, 0,
		    pcishpc_attn_btn_handler,
		    (void *)pcishpc_p, 0, &p0, TS_RUN, minclsyspri);
		pcishpc_p->attn_btn_thread_exit = B_FALSE;
	}

	/* setup the slot name (used for ap-id) */
	pcishpc_set_slot_name(ctrl_p, slot);

	pcishpc_get_slot_state(pcishpc_p);

	/* Register this SHPC slot with the HPS framework. */
	if (hpc_slot_register(ctrl_p->shpc_dip, ctrl_p->nexus_path,
		&pcishpc_p->slot_info, &pcishpc_p->slot_handle,
			pcishpc_p->slot_ops, (caddr_t)pcishpc_p, 0) != 0) {

		pcishpc_debug("pcishpc_register_slot() failed to Register "
			"slot");

		hpc_free_slot_ops(pcishpc_p->slot_ops);
		pcishpc_p->slot_ops = NULL;

		return (DDI_FAILURE);
	}

	pcishpc_debug("pcishpc_register_slot() success for slot %d", slot);

	return (DDI_SUCCESS);
}


/*
 * pcishpc_create_slot()
 *
 * Allocate and add a new HotPlug slot state structure to the linked list.
 */
static pcishpc_t *
pcishpc_create_slot(pcishpc_ctrl_t *ctrl_p)
{
	pcishpc_t *pcishpc_p;

	pcishpc_debug("pcishpc_create_slot() called(ctrl_p=%x)", ctrl_p);

	/* Allocate a new slot structure. */
	pcishpc_p = kmem_zalloc(sizeof (pcishpc_t), KM_SLEEP);

	pcishpc_p->ctrl = ctrl_p;

	mutex_enter(&pcishpc_list_mutex);

	/* Insert new slot into linked list of current slots. */
	pcishpc_p->nextp  = pcishpc_head;
	pcishpc_head = pcishpc_p;

	mutex_exit(&pcishpc_list_mutex);

	pcishpc_debug("pcishpc_create_slot() success");
	return (pcishpc_p);
}

/*
 * pcishpc_setup_controller()
 *
 * Get the number of HotPlug Slots, and the PCI device information
 * for this HotPlug controller.
 */
static int
pcishpc_setup_controller(pcishpc_ctrl_t *ctrl_p)
{
	uint32_t config;
	dev_info_t *ppdip;

	config = pcishpc_read_reg(ctrl_p, SHPC_SLOT_CONFIGURATION_REG);

	/* Get the number of HotPlug slots implemented */
	ctrl_p->numSlotsImpl = ((config)&31);

	/*
	 * Initilize the current bus speed and number of hotplug slots
	 * currently connected.
	 */
	ctrl_p->currBusSpeed = -1;
	ctrl_p->numSlotsConn = 0;

	/* Save the value of Slots Available 1 and 2 registers */
	ctrl_p->shpc_slots_avail1_reg = pcishpc_read_reg(ctrl_p,
	    SHPC_SLOTS_AVAIL_I_REG);
	ctrl_p->shpc_slots_avail2_reg = pcishpc_read_reg(ctrl_p,
	    SHPC_SLOTS_AVAIL_II_REG);

	/* Get the first PCI device Number used. */
	/*
	 * PCI-X I/O boat workaround.
	 * The register doesn't set up the correct value.
	 */
	ppdip = ddi_get_parent(ddi_get_parent(ctrl_p->shpc_dip));
	if ((ddi_prop_get_int(DDI_DEV_T_ANY, ppdip, DDI_PROP_DONTPASS,
	    "vendor-id", -1) == 0x108e) &&
	    (ddi_prop_get_int(DDI_DEV_T_ANY, ppdip, DDI_PROP_DONTPASS,
	    "device-id", -1) == 0x9010))
		ctrl_p->deviceStart = 4;
	else
		ctrl_p->deviceStart = ((config>>8)&31);

	/* Get the first Physical device number. */
	ctrl_p->physStart = ((config>>16)&0x7ff);
	/* Check if the device numbers increase or decrease. */
	ctrl_p->deviceIncreases = ((config>>29)&0x1);

	ctrl_p->has_attn =
		(config & SHPC_SLOT_CONFIG_ATTN_BUTTON) ? B_TRUE : B_FALSE;
	ctrl_p->has_mrl =
		(config & SHPC_SLOT_CONFIG_MRL_SENSOR) ? B_TRUE : B_FALSE;

	cv_init(&ctrl_p->cmd_comp_cv, NULL, CV_DRIVER, NULL);
	ctrl_p->command_complete = B_FALSE;
	ctrl_p->arbiter_timeout = B_FALSE;

	if (ctrl_p->numSlotsImpl > MAX_SHPC_SLOTS) {
		pcishpc_debug("pcishpc_setup_controller() too many SHPC "
			"slots error");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * pcishpc_uninit()
 * Unload the HogPlug controller driver and deallocate all resources.
 */
int
pcishpc_uninit(dev_info_t *dip)
{
	pcishpc_ctrl_t *ctrl_p;

	pcishpc_debug("pcishpc_uninit() called(dip=%p)", dip);

	mutex_enter(&pcishpc_control_mutex);

	ctrl_p = pcishpc_get_controller(dip);

	if (!ctrl_p) {
		pcishpc_debug("pcishpc_uninit() Unable to find softstate");
		mutex_exit(&pcishpc_control_mutex);
		return (DDI_FAILURE);
	}

	(void) pcishpc_disable_irqs(ctrl_p);
	ctrl_p->interrupt_installed = B_FALSE;

	(void) pcishpc_destroy_controller(dip);

	mutex_exit(&pcishpc_control_mutex);

	pcishpc_debug("pcishpc_uninit() success(dip=%p)", dip);

	return (DDI_SUCCESS);
}

/*
 * pcishpc_destroy_slots()
 *
 * Free up all of the slot resources for this controller.
 */
static int
pcishpc_destroy_slots(pcishpc_ctrl_t *ctrl_p)
{
	pcishpc_t *pcishpc_p;
	pcishpc_t **pcishpc_pp;

	pcishpc_debug("pcishpc_destroy_slots() called(ctrl_p=%p)", ctrl_p);

	pcishpc_pp = &pcishpc_head;

	while ((pcishpc_p = *pcishpc_pp) != NULL) {
		if (pcishpc_p->ctrl == ctrl_p) {
			if (pcishpc_p->attn_btn_threadp != NULL) {
				mutex_enter(&ctrl_p->shpc_mutex);
				pcishpc_p->attn_btn_thread_exit = B_TRUE;
				cv_signal(&pcishpc_p->attn_btn_cv);
				pcishpc_debug("pcishpc_destroy_slots: "
				    "waiting for ATTN thread exit\n");
				cv_wait(&pcishpc_p->attn_btn_cv,
				    &ctrl_p->shpc_mutex);
				pcishpc_debug("pcishpc_destroy_slots: "
				    "ATTN thread exit\n");
				cv_destroy(&pcishpc_p->attn_btn_cv);
				pcishpc_p->attn_btn_threadp = NULL;
				mutex_exit(&ctrl_p->shpc_mutex);
			}

			*pcishpc_pp = pcishpc_p->nextp;

			pcishpc_debug("pcishpc_destroy_slots() (shpc_p=%p) "
			    "destroyed", pcishpc_p);
			if (pcishpc_p->slot_ops)
				if (hpc_slot_unregister(
				    &pcishpc_p->slot_handle) != 0) {
					pcishpc_debug("pcishpc_destroy_slots() "
					    "failed to unregister slot");
					return (DDI_FAILURE);
				} else {
					hpc_free_slot_ops(pcishpc_p->slot_ops);
					pcishpc_p->slot_ops = NULL;
				}
			kmem_free(pcishpc_p, sizeof (pcishpc_t));
		} else
			pcishpc_pp = &(pcishpc_p->nextp);
	}

	return (DDI_SUCCESS);
}


/*
 * pcishpc_connect()
 *
 * Called by Hot Plug Services to connect a slot on the bus.
 */
/*ARGSUSED*/
static int
pcishpc_connect(caddr_t ops_arg, hpc_slot_t slot_hdl, void *data, uint_t flags)
{
	pcishpc_t *pcishpc_p;
	uint32_t status;

	pcishpc_debug("pcishpc_connect called()");

	pcishpc_p = pcishpc_hpc_get_slot_state(slot_hdl);

	if (!pcishpc_p) {
		pcishpc_debug("pcishpc_connect() "
			"Failed to find soft state for slot_hdl %x", slot_hdl);
		return (HPC_ERR_FAILED);
	}

	mutex_enter(&pcishpc_p->ctrl->shpc_mutex);

	/* make sure the MRL sensor is closed */
	status = pcishpc_read_reg(pcishpc_p->ctrl,
		SHPC_LOGICAL_SLOT_REGS+pcishpc_p->slotNum);

	if (status & SHPC_SLOT_MRL_STATE_MASK) {
		pcishpc_debug("pcishpc_connect() failed: MRL open");
		goto cleanup;
	}

	if (pcishpc_set_power_state(pcishpc_p, HPC_SLOT_CONNECTED) !=
				DDI_SUCCESS) {
		pcishpc_debug("pcishpc_connect() failed: set power state");
		goto cleanup;
	}

	mutex_exit(&pcishpc_p->ctrl->shpc_mutex);

	pcishpc_debug("pcishpc_connect() success!");

	return (HPC_SUCCESS);

cleanup:
	mutex_exit(&pcishpc_p->ctrl->shpc_mutex);
	return (HPC_ERR_FAILED);
}


/*
 * pcishpc_set_power_state()
 *
 * Changed a slot's power state.
 */
static int
pcishpc_set_power_state(pcishpc_t *pcishpc_p, hpc_slot_state_t state)
{
	pcishpc_get_slot_state(pcishpc_p);

	/* Check to see if the slot is already in this state. */
	if (pcishpc_p->slot_state == state) {
		pcishpc_debug("pcishpc_set_power_state() slot already in "
			"this state");
		return (DDI_SUCCESS);
	}

	if ((pcishpc_p->slot_state == HPC_SLOT_EMPTY) &&
	    ((state == HPC_SLOT_CONNECTED) ||
	    (state == HPC_SLOT_DISCONNECTED))) {
		pcishpc_debug("pcishpc_set_power_state() slot in "
		    "empty state");
		return (DDI_FAILURE);
	}

	/* Set the Power LED to blink. */
	(void) pcishpc_setled(pcishpc_p, HPC_POWER_LED, HPC_LED_BLINK);

	/* Turn all other LEDS off. */
	(void) pcishpc_setled(pcishpc_p, HPC_FAULT_LED, HPC_LED_OFF);
	(void) pcishpc_setled(pcishpc_p, HPC_ATTN_LED, HPC_LED_OFF);
	(void) pcishpc_setled(pcishpc_p, HPC_ACTIVE_LED, HPC_LED_OFF);

	/* Set the slot state to the new slot state. */
	pcishpc_p->slot_state = state;

	/* Set the bus speed only if the bus segment is not running */
	if (state == HPC_SLOT_CONNECTED) {
		if (pcishpc_set_bus_speed(pcishpc_p) != DDI_SUCCESS)
			return (DDI_FAILURE);

		pcishpc_p->ctrl->numSlotsConn++;
	} else {
		if (--pcishpc_p->ctrl->numSlotsConn == 0)
			pcishpc_p->ctrl->currBusSpeed = -1;
	}

	pcishpc_debug("pcishpc_set_power_state(): ctrl_p 0x%p, "
	    "pcishpc_p 0x%p, slot state 0x%x,  current bus speed 0x%x, "
	    "slots connected 0x%x\n", pcishpc_p->ctrl, pcishpc_p, state,
	    pcishpc_p->ctrl->currBusSpeed, pcishpc_p->ctrl->numSlotsConn);

	/* Mask or Unmask MRL Sensor SEER bit based on new slot state */
	if (pcishpc_p->ctrl->has_mrl == B_TRUE) {
		uint32_t reg;

		reg = pcishpc_read_reg(pcishpc_p->ctrl,
		    SHPC_LOGICAL_SLOT_REGS+pcishpc_p->slotNum);
		reg = (state == HPC_SLOT_CONNECTED) ?
		    (reg & ~SHPC_SLOT_MRL_SERR_MASK) :
		    (reg | SHPC_SLOT_MRL_SERR_MASK);

		pcishpc_write_reg(pcishpc_p->ctrl,
		    SHPC_LOGICAL_SLOT_REGS+pcishpc_p->slotNum, reg);
	}

	/* Update the hardweare slot state. */
	if (pcishpc_set_slot_state(pcishpc_p) != DDI_SUCCESS) {
		pcishpc_debug("pcishpc_set_power_state() failed");
		(void) pcishpc_setled(pcishpc_p, HPC_POWER_LED, HPC_LED_OFF);
		pcishpc_get_slot_state(pcishpc_p);
		return (DDI_FAILURE);
	}

	/* Turn the Power LED ON for a connected slot. */
	if (state == HPC_SLOT_CONNECTED) {
		(void) pcishpc_setled(pcishpc_p, HPC_POWER_LED, HPC_LED_ON);
	}

	/* Turn the Power LED OFF for a disconnected slot. */
	if (state == HPC_SLOT_DISCONNECTED) {
		(void) pcishpc_setled(pcishpc_p, HPC_POWER_LED, HPC_LED_OFF);
	}

	/* Turn all other LEDS off. */
	(void) pcishpc_setled(pcishpc_p, HPC_FAULT_LED, HPC_LED_OFF);
	(void) pcishpc_setled(pcishpc_p, HPC_ATTN_LED, HPC_LED_OFF);
	(void) pcishpc_setled(pcishpc_p, HPC_ACTIVE_LED, HPC_LED_OFF);

	pcishpc_debug("pcishpc_set_power_state() success!");

	pcishpc_get_slot_state(pcishpc_p);

	/* delay after powerON to let the device initialize itself */
	delay(drv_usectohz(pcishpc_reset_delay));

	return (DDI_SUCCESS);
}

/*
 * pcishpc_set_bus_speed()
 *
 * Set the bus speed and mode.
 */
static int
pcishpc_set_bus_speed(pcishpc_t *pcishpc_p)
{
	pcishpc_ctrl_t	*ctrl_p = pcishpc_p->ctrl;
	int		curr_speed = ctrl_p->currBusSpeed;
	int		speed = -1;
	int		avail_slots;
	uint32_t	status;

	/* Make sure that the slot is in a correct state */
	status = pcishpc_read_reg(ctrl_p,
	    SHPC_LOGICAL_SLOT_REGS+pcishpc_p->slotNum);

	/* Return failure if the slot is empty */
	if ((status & SHPC_SLOT_CARD_EMPTY_MASK) ==
	    SHPC_SLOT_CARD_EMPTY_MASK) {
		pcishpc_debug("pcishpc_set_bus_speed() failed: "
		    "the slot is empty.");
		return (DDI_FAILURE);
	}

	/* Return failure if the slot is not in disabled state */
	if ((status & SHPC_SLOT_STATE_MASK) != SHPC_SLOT_DISABLED) {
		pcishpc_debug("pcishpc_set_bus_speed() failed: "
		    "incorrect slot state.");
		return (DDI_FAILURE);
	}

	/* Set the "power-only" mode for the slot */
	if (pcishpc_issue_command(ctrl_p, ((1+pcishpc_p->slotNum)<<8) |
	    SHPC_SLOT_POWER_ONLY) != DDI_SUCCESS) {
		pcishpc_debug("pcishpc_set_bus_speed() failed to set "
		    "the slot %d in the power-only mode", pcishpc_p->slotNum);
		return (DDI_FAILURE);
	}

	/* Wait for power good */
	delay(drv_usectohz(SHPC_POWER_GOOD_WAIT_TIME));

	/* Make sure that the slot is in "power-only" state */
	status = pcishpc_read_reg(ctrl_p,
	    SHPC_LOGICAL_SLOT_REGS+pcishpc_p->slotNum);

	if ((status & SHPC_SLOT_STATE_MASK) != SHPC_SLOT_POWER_ONLY) {
		pcishpc_debug("pcishpc_set_bus_speed() "
		    "power-only failed: incorrect slot state.");
		return (DDI_FAILURE);
	}

	/*
	 * Check if SHPC has available slots and select the highest
	 * available bus speed for the slot.
	 *
	 * The bus speed codes are:
	 * 100 - 133Mhz; <--+
	 * 011 - 100Mhz; <--+   PCI-X
	 * 010 - 66Mhz;  <--+
	 *
	 * 001 - 66Mhz;  <--+
	 * 000 - 33Mhz   <--+   Conv PCI
	 */
	switch (status & SHPC_SLOT_PCIX_CAPABLE_MASK) {
	case SHPC_SLOT_133MHZ_PCIX_CAPABLE:
		avail_slots = (ctrl_p->shpc_slots_avail1_reg >>
		    SHPC_AVAIL_133MHZ_PCIX_SPEED_SHIFT) & SHPC_AVAIL_SPEED_MASK;

		if (((curr_speed == -1) && avail_slots) ||
		    (curr_speed == SHPC_SBCR_133MHZ_PCIX_SPEED)) {
			speed = SHPC_SBCR_133MHZ_PCIX_SPEED;
			break;
		}
		/* FALLTHROUGH */
	case SHPC_SLOT_100MHZ_PCIX_CAPABLE:
		avail_slots = (ctrl_p->shpc_slots_avail1_reg >>
		    SHPC_AVAIL_100MHZ_PCIX_SPEED_SHIFT) & SHPC_AVAIL_SPEED_MASK;

		if (((curr_speed == -1) && avail_slots) ||
		    (curr_speed == SHPC_SBCR_100MHZ_PCIX_SPEED)) {
			speed = SHPC_SBCR_100MHZ_PCIX_SPEED;
			break;
		}
		/* FALLTHROUGH */
	case SHPC_SLOT_66MHZ_PCIX_CAPABLE:
		avail_slots = (ctrl_p->shpc_slots_avail1_reg >>
		    SHPC_AVAIL_66MHZ_PCIX_SPEED_SHIFT) & SHPC_AVAIL_SPEED_MASK;

		if (((curr_speed == -1) && avail_slots) ||
		    (curr_speed == SHPC_SBCR_66MHZ_PCIX_SPEED)) {
			speed = SHPC_SBCR_66MHZ_PCIX_SPEED;
			break;
		}
		/* FALLTHROUGH */
	default:
		avail_slots = (ctrl_p->shpc_slots_avail2_reg >>
		    SHPC_AVAIL_66MHZ_CONV_SPEED_SHIFT) & SHPC_AVAIL_SPEED_MASK;

		if ((status & SHPC_SLOT_66MHZ_CONV_CAPABLE) &&
		    (((curr_speed == -1) && avail_slots) ||
		    (curr_speed == SHPC_SBCR_66MHZ_CONV_SPEED))) {
			speed = SHPC_SBCR_66MHZ_CONV_SPEED;
		} else {
			avail_slots = (ctrl_p->shpc_slots_avail1_reg >>
			    SHPC_AVAIL_33MHZ_CONV_SPEED_SHIFT) &
			    SHPC_AVAIL_SPEED_MASK;

			if (((curr_speed == -1) && (avail_slots)) ||
			    (curr_speed == SHPC_SBCR_33MHZ_CONV_SPEED)) {
				speed = SHPC_SBCR_33MHZ_CONV_SPEED;
			} else {
				pcishpc_debug("pcishpc_set_bus_speed() "
				    " failed to set the bus speed, slot# %d",
				    pcishpc_p->slotNum);
				return (DDI_FAILURE);
			}
		}
		break;
	}

	/*
	 * If the bus segment is already running, check to see the card
	 * in the slot can support the current bus speed.
	 */
	if (curr_speed == speed) {
		/*
		 * Check to see there is any slot available for the current
		 * bus speed. Otherwise, we need fail the current slot connect
		 * request.
		 */
		return ((avail_slots <= ctrl_p->numSlotsConn) ?
		    DDI_FAILURE : DDI_SUCCESS);
	}

	/* Set the bus speed */
	if (pcishpc_issue_command(ctrl_p, SHPC_COMM_STS_SET_SPEED |
	    speed) == DDI_FAILURE) {
		pcishpc_debug("pcishpc_set_bus_speed() failed "
		    "to set bus %d speed", pcishpc_p->slotNum);
		return (DDI_FAILURE);
	}

	/* Check the current bus speed */
	status = pcishpc_read_reg(ctrl_p, SHPC_PROF_IF_SBCR_REG) &
	    SHPC_SBCR_SPEED_MASK;
	if ((status & SHPC_SBCR_SPEED_MASK) != speed) {
		pcishpc_debug("pcishpc_set_bus_speed() an incorrect "
		    "bus speed, slot = 0x%x, speed = 0x%x",
		    pcishpc_p->slotNum, status & SHPC_SBCR_SPEED_MASK);
		return (DDI_FAILURE);
	}


	/* Save the current bus speed */
	ctrl_p->currBusSpeed = speed;

	return (DDI_SUCCESS);
}

/*
 * pcishpc_disconnect()
 *
 * Called by Hot Plug Services to disconnect a slot on the bus.
 */
/*ARGSUSED*/
static int
pcishpc_disconnect(caddr_t ops_arg, hpc_slot_t slot_hdl, void *data,
	uint_t flags)
{
	pcishpc_t *pcishpc_p;

	pcishpc_debug("pcishpc_disconnect called()");

	pcishpc_p = pcishpc_hpc_get_slot_state(slot_hdl);

	if (!pcishpc_p) {
		pcishpc_debug("pcishpc_disconnect() "
			"Failed to find soft state for slot_hdl %x", slot_hdl);
		return (HPC_ERR_FAILED);
	}

	mutex_enter(&pcishpc_p->ctrl->shpc_mutex);

	if (pcishpc_set_power_state(pcishpc_p, HPC_SLOT_DISCONNECTED)
					!= DDI_SUCCESS) {
		pcishpc_debug("pcishpc_disconnect() failed");
		goto cleanup;
	}

	mutex_exit(&pcishpc_p->ctrl->shpc_mutex);

	pcishpc_debug("pcishpc_disconnect() success!");

	return (HPC_SUCCESS);

cleanup:
	mutex_exit(&pcishpc_p->ctrl->shpc_mutex);
	return (HPC_ERR_FAILED);
}


/*
 * pcishpc_pci_control()
 *
 * Called by Hot Plug Services to perform a attachment point specific
 * operation on a Hot Pluggable Standard PCI Slot.
 */
/*ARGSUSED*/
static int
pcishpc_pci_control(caddr_t ops_arg, hpc_slot_t slot_hdl, int request,
		caddr_t arg)
{
	hpc_slot_state_t *hpc_slot_state;
	hpc_board_type_t *hpc_board_type;
	hpc_led_info_t	*hpc_led_info;
	pcishpc_t		*pcishpc_p;
	int ret = HPC_SUCCESS;

	pcishpc_debug("pcishpc_pci_control called(Request %s)",
		pcishpc_textrequest(request));

	pcishpc_p = pcishpc_hpc_get_slot_state(slot_hdl);

	if (!pcishpc_p) {
		pcishpc_debug("pcishpc_pci_control() Error: "
			"Failed to find soft state for slot_hdl %x", slot_hdl);
		return (HPC_ERR_FAILED);
	}

	mutex_enter(&pcishpc_p->ctrl->shpc_mutex);

	switch (request) {
		case HPC_CTRL_GET_SLOT_STATE:
			hpc_slot_state = (hpc_slot_state_t *)arg;
			pcishpc_get_slot_state(pcishpc_p);
			*hpc_slot_state = pcishpc_p->slot_state;
			pcishpc_debug("pcishpc_pci_control() - "
				"HPC_CTRL_GET_SLOT_STATE (state=%s)",
				pcishpc_textslotstate(pcishpc_p->slot_state));
			break;

		case HPC_CTRL_GET_BOARD_TYPE:
			hpc_board_type = (hpc_board_type_t *)arg;
			pcishpc_debug("pcishpc_pci_control() - "
					"HPC_CTRL_GET_BOARD_TYPE");
			pcishpc_get_slot_state(pcishpc_p);
			/*
			 * The HPS framework does not know what board
			 * type is plugged in.
			 */
			if (pcishpc_p->slot_state == HPC_SLOT_EMPTY)
				*hpc_board_type = HPC_BOARD_UNKNOWN;
			else
				*hpc_board_type = HPC_BOARD_PCI_HOTPLUG;
			break;

		case HPC_CTRL_GET_LED_STATE:
			hpc_led_info = (hpc_led_info_t *)arg;

			pcishpc_get_slot_state(pcishpc_p);

			switch (hpc_led_info->led) {
				case HPC_FAULT_LED:
					hpc_led_info->state =
						pcishpc_p->fault_led_state;
					pcishpc_debug("pcishpc_pci_control() - "
						"GET_LED FAULT (state=%s)",
						pcishpc_textledstate(
							hpc_led_info->state));
					break;

				case HPC_POWER_LED:
					hpc_led_info->state =
						pcishpc_p->power_led_state;
					pcishpc_debug("pcishpc_pci_control() - "
						"GET_LED POWER (state=%s)",
						pcishpc_textledstate(
							hpc_led_info->state));
					break;

				case HPC_ATTN_LED:
					hpc_led_info->state =
						pcishpc_p->attn_led_state;
					pcishpc_debug("pcishpc_pci_control() - "
						"GET_LED ATTN(state = %s)",
						pcishpc_textledstate(
							hpc_led_info->state));
					break;

				case HPC_ACTIVE_LED:
					hpc_led_info->state =
						pcishpc_p->active_led_state;
					pcishpc_debug("pcishpc_pci_control() - "
						"GET_LED ACTIVE(state = %s)",
						pcishpc_textledstate(
							hpc_led_info->state));
					break;

				default:
					pcishpc_debug("pcishpc_pci_control() "
						"Error: GET_LED - "
						"Invalid LED %x",
							hpc_led_info->led);
					ret = HPC_ERR_NOTSUPPORTED;
					break;
				}
			break;

		case HPC_CTRL_SET_LED_STATE:
			hpc_led_info = (hpc_led_info_t *)arg;
			switch (hpc_led_info->led) {
				case HPC_ATTN_LED:
					(void) pcishpc_setled(pcishpc_p,
					    hpc_led_info->led,
					    hpc_led_info->state);
					break;
				case HPC_POWER_LED:
					pcishpc_debug("pcishpc_pci_control() "
					    "Error: SET_LED - power LED");
					ret = HPC_ERR_NOTSUPPORTED;
					break;
				case HPC_FAULT_LED:
				case HPC_ACTIVE_LED:
					break;
				default:
					pcishpc_debug("pcishpc_pci_control() "
					    "Error: SET_LED - Unknown LED %x",
					    hpc_led_info->led);
					ret = HPC_ERR_NOTSUPPORTED;
					break;
				}
			break;

		case HPC_CTRL_DEV_UNCONFIG_FAILURE:
		case HPC_CTRL_DEV_CONFIG_FAILURE:
			pcishpc_debug("pcishpc_pci_control() Config/Unconfig "
				"failed.");
			(void) pcishpc_setled(pcishpc_p, HPC_ATTN_LED,
				HPC_LED_BLINK);
			break;

		case HPC_CTRL_ENABLE_AUTOCFG:
		case HPC_CTRL_DISABLE_AUTOCFG:
		case HPC_CTRL_DISABLE_SLOT:
		case HPC_CTRL_DEV_UNCONFIGURED:
		case HPC_CTRL_ENABLE_SLOT:
		case HPC_CTRL_DISABLE_ENUM:
		case HPC_CTRL_DEV_UNCONFIG_START:
		case HPC_CTRL_DEV_CONFIG_START:
		case HPC_CTRL_DEV_CONFIGURED:
			pcishpc_debug("pcishpc_pci_control() - %s",
				pcishpc_textrequest(request));
			break;

		case HPC_CTRL_ENABLE_ENUM:
		default:
			pcishpc_debug("pcishpc_pci_control() - Error: "
				"request (%d) NOT SUPPORTED", request);
			ret = HPC_ERR_NOTSUPPORTED;
			break;
	}

	mutex_exit(&pcishpc_p->ctrl->shpc_mutex);
	return (ret);
}


/*
 * pcishpc_setled()
 *
 * Change the state of a slot's LED.
 */
static int
pcishpc_setled(pcishpc_t *pcishpc_p, hpc_led_t led, hpc_led_state_t state)
{
	switch (led) {
		case HPC_FAULT_LED:
			pcishpc_debug("pcishpc_setled() - HPC_FAULT_LED "
				"(set %s)", pcishpc_textledstate(state));
			pcishpc_p->fault_led_state = state;
			break;

		case HPC_POWER_LED:
			pcishpc_debug("pcishpc_setled() - HPC_POWER_LED "
				"(set %s)", pcishpc_textledstate(state));
			pcishpc_p->power_led_state = state;
			break;

		case HPC_ATTN_LED:
			pcishpc_debug("pcishpc_setled() - HPC_ATTN_LED "
				"(set %s)", pcishpc_textledstate(state));
			pcishpc_p->attn_led_state = state;
			break;

		case HPC_ACTIVE_LED:
			pcishpc_debug("pcishpc_setled() - HPC_ACTIVE_LED "
				"(set %s)", pcishpc_textledstate(state));
			pcishpc_p->active_led_state = state;
			break;
	}

	return (pcishpc_set_slot_state(pcishpc_p));
}


/*
 * pcishpc_set_slot_state()
 *
 * Updates the slot's state and leds.
 */
static int
pcishpc_set_slot_state(pcishpc_t *pcishpc_p)
{
	uint32_t reg;
	uint32_t cmd_code;
	hpc_slot_state_t slot_state;

	reg = pcishpc_read_reg(pcishpc_p->ctrl,
		SHPC_LOGICAL_SLOT_REGS+pcishpc_p->slotNum);

	/* Default all states to unchanged. */
	cmd_code = ((1+pcishpc_p->slotNum)<<8);

	/* Has the slot state changed? */
	if ((reg & SHPC_SLOT_CARD_EMPTY_MASK) == SHPC_SLOT_CARD_EMPTY_MASK)
		slot_state = HPC_SLOT_EMPTY;
	else
		slot_state = pcishpc_slot_shpc_to_hpc(reg & 3);
	if (pcishpc_p->slot_state != slot_state) {
		pcishpc_debug("pcishpc_set_slot_state() Slot State changed");
		/* Set the new slot state in the Slot operation command. */
		cmd_code |= pcishpc_slot_hpc_to_shpc(pcishpc_p->slot_state);
	}

	/* Has the Power LED state changed? */
	if (pcishpc_p->power_led_state != pcishpc_led_shpc_to_hpc((reg>>2)&3)) {
		pcishpc_debug("pcishpc_set_slot_state() Power LED State "
				"changed");
		/* Set the new power led state in the Slot operation command. */
		cmd_code |=
			(pcishpc_led_hpc_to_shpc(pcishpc_p->power_led_state)
					<< 2);
	}

	/* Has the Attn LED state changed? */
	if (pcishpc_p->attn_led_state != pcishpc_led_shpc_to_hpc((reg>>4)&3)) {
		pcishpc_debug("pcishpc_set_slot_state() Attn LED State "
			"changed");
		/* Set the new attn led state in the Slot operation command. */
		cmd_code |= (pcishpc_led_hpc_to_shpc(pcishpc_p->attn_led_state)
				<< 4);
	}

	return (pcishpc_issue_command(pcishpc_p->ctrl, cmd_code));
}


/*
 * pcishpc_wait_busy()
 *
 * Wait until the SHPC controller is not busy.
 */
static int
pcishpc_wait_busy(pcishpc_ctrl_t *ctrl_p)
{
	uint32_t	status;

	/* Wait until SHPC controller is NOT busy */
	/*CONSTCOND*/
	while (1) {
		status = pcishpc_read_reg(ctrl_p, SHPC_COMMAND_STATUS_REG);

		/* Is there an MRL Sensor error? */
		if ((status & SHPC_COMM_STS_ERR_MASK) ==
		    SHPC_COMM_STS_ERR_MRL_OPEN) {
			pcishpc_debug("pcishpc_wait_busy() ERROR: MRL Sensor "
				"error");
			break;
		}

		/* Is there an Invalid command error? */
		if ((status & SHPC_COMM_STS_ERR_MASK) ==
		    SHPC_COMM_STS_ERR_INVALID_COMMAND) {
			pcishpc_debug("pcishpc_wait_busy() ERROR: Invalid "
				"command error");
			break;
		}

		/* Is there an Invalid Speed/Mode error? */
		if ((status & SHPC_COMM_STS_ERR_MASK) ==
		    SHPC_COMM_STS_ERR_INVALID_SPEED) {
			pcishpc_debug("pcishpc_wait_busy() ERROR: Invalid "
				"Speed/Mode error");
			break;
		}

		/* Is the SHPC controller not BUSY? */
		if (!(status & SHPC_COMM_STS_CTRL_BUSY)) {
			/* Return Success. */
			return (DDI_SUCCESS);
		}

		pcishpc_debug("pcishpc_wait_busy() SHPC controller busy. "
			"Waiting");

		/* Wait before polling the status register again. */
		delay(drv_usectohz(SHPC_COMMAND_WAIT_TIME));
	}

	return (DDI_FAILURE);
}


/*
 * pcishpc_issue_command()
 *
 * Sends a command to the SHPC controller.
 */
static int
pcishpc_issue_command(pcishpc_ctrl_t *ctrl_p, uint32_t cmd_code)
{
	int	retCode;

	pcishpc_debug("pcishpc_issue_command() cmd_code=%02x", cmd_code);

	mutex_enter(&ctrl_p->shpc_intr_mutex);

	ctrl_p->command_complete = B_FALSE;

	/* Write the command to the SHPC controller. */
	pcishpc_write_reg(ctrl_p, SHPC_COMMAND_STATUS_REG, cmd_code);

	while (ctrl_p->command_complete == B_FALSE)
		cv_wait(&ctrl_p->cmd_comp_cv, &ctrl_p->shpc_intr_mutex);

	/* Wait until the SHPC controller processes the command. */
	retCode = pcishpc_wait_busy(ctrl_p);

	/* Make sure the command completed. */
	if (retCode == DDI_SUCCESS) {
		/* Did the command fail to generate the command complete IRQ? */
		if (ctrl_p->command_complete != B_TRUE) {
			pcishpc_debug("pcishpc_issue_command() Failed on "
				"generate cmd complete IRQ");
			retCode = DDI_FAILURE;
		}
	}

	mutex_exit(&ctrl_p->shpc_intr_mutex);

	if (retCode == DDI_FAILURE)
		pcishpc_debug("pcishpc_issue_command() Failed on cmd_code=%02x",
				cmd_code);
	else
		pcishpc_debug("pcishpc_issue_command() Success on "
			"cmd_code=%02x", cmd_code);

	return (retCode);
}

/*
 * pcishpc_led_shpc_to_hpc()
 *
 * Convert from SHPC indicator status to HPC indicator status.
 */
static int
pcishpc_led_shpc_to_hpc(int state)
{
	switch (state) {
		case 1:	/* SHPC On bits b01 */
			return (HPC_LED_ON);
		case 2:	/* SHPC Blink bits b10 */
			return (HPC_LED_BLINK);
		case 3:	/* SHPC Off bits b11 */
			return (HPC_LED_OFF);
	}

	return (HPC_LED_OFF);
}


/*
 * pcishpc_led_hpc_to_shpc()
 *
 * Convert from HPC indicator status to SHPC indicator status.
 */
static int
pcishpc_led_hpc_to_shpc(int state)
{
	switch (state) {
		case HPC_LED_ON:
			return (1); /* SHPC On bits b01 */
		case HPC_LED_BLINK:
			return (2); /* SHPC Blink bits b10 */
		case HPC_LED_OFF:
			return (3); /* SHPC Off bits b11 */
	}

	return (3); /* SHPC Off bits b11 */
}

/*
 * pcishpc_slot_shpc_to_hpc()
 *
 * Convert from SHPC slot state to HPC slot state.
 */
static int
pcishpc_slot_shpc_to_hpc(int state)
{
	switch (state) {
		case 0: /* SHPC Reserved */
			return (HPC_SLOT_EMPTY);

		case 1: /* SHPC Powered Only */
			return (HPC_SLOT_UNKNOWN);

		case 2: /* SHPC Enabled */
			return (HPC_SLOT_CONNECTED);

		case 3: /* SHPC Disabled */
			return (HPC_SLOT_DISCONNECTED);
	}

	/* Unknown slot state. */
	return (HPC_SLOT_UNKNOWN);
}


/*
 * pcishpc_slot_hpc_to_shpc()
 *
 * Convert from HPC slot state to SHPC slot state.
 */
static int
pcishpc_slot_hpc_to_shpc(int state)
{
	switch (state) {
		case HPC_SLOT_EMPTY:
			return (0); /* SHPC Reserved */

		case HPC_SLOT_UNKNOWN:
			return (1); /* SHPC Powered Only */

		case HPC_SLOT_CONNECTED:
			return (2); /* SHPC Enabled */

		case HPC_SLOT_DISCONNECTED:
			return (3); /* SHPC Disabled */
	}

	/* Known slot state is reserved. */
	return (0);
}


/*
 * pcishpc_get_slot_state()
 *
 * Get the state of the slot.
 */
static void
pcishpc_get_slot_state(pcishpc_t *pcishpc_p)
{
	uint32_t reg;

	/* Read the logical slot register for this Slot. */
	reg = pcishpc_read_reg(pcishpc_p->ctrl,
		SHPC_LOGICAL_SLOT_REGS+pcishpc_p->slotNum);

	/* Convert from the SHPC slot state to the HPC slot state. */
	if ((reg & SHPC_SLOT_CARD_EMPTY_MASK) == SHPC_SLOT_CARD_EMPTY_MASK)
		pcishpc_p->slot_state = HPC_SLOT_EMPTY;
	else
		pcishpc_p->slot_state = pcishpc_slot_shpc_to_hpc(reg & 3);

	/* Convert from the SHPC Power LED state to the HPC Power LED state. */
	pcishpc_p->power_led_state  = pcishpc_led_shpc_to_hpc((reg>>2)&3);

	/* Convert from the SHPC Attn LED state to the HPC Attn LED state. */
	pcishpc_p->attn_led_state	= pcishpc_led_shpc_to_hpc((reg>>4)&3);

	/* We don't have a fault LED so just default it to OFF. */
	pcishpc_p->fault_led_state  = HPC_LED_OFF;

	/* We don't have an active LED so just default it to OFF. */
	pcishpc_p->active_led_state = HPC_LED_OFF;
}

/*
 * pcishpc_textledstate()
 *
 * Convert the led state into a text message.
 */
static char *
pcishpc_textledstate(hpc_led_state_t state)
{
	/* Convert an HPC led state into a textual string. */
	switch (state) {
		case HPC_LED_OFF:
			return ("off");

		case HPC_LED_ON:
			return ("on");

		case HPC_LED_BLINK:
			return ("blink");
	}
	return ("unknown");
}

/*
 * pcishpc_textrequest()
 *
 * Convert the request into a text message.
 */
static char *
pcishpc_textrequest(int request)
{
	/* Convert an HPC request into a textual string. */
	switch (request) {
		case HPC_CTRL_GET_LED_STATE:
			return ("HPC_CTRL_GET_LED_STATE");
		case HPC_CTRL_SET_LED_STATE:
			return ("HPC_CTRL_SET_LED_STATE");
		case HPC_CTRL_GET_SLOT_STATE:
			return ("HPC_CTRL_GET_SLOT_STATE");
		case HPC_CTRL_DEV_CONFIGURED:
			return ("HPC_CTRL_DEV_CONFIGURED");
		case HPC_CTRL_DEV_UNCONFIGURED:
			return ("HPC_CTRL_DEV_UNCONFIGURED");
		case HPC_CTRL_GET_BOARD_TYPE:
			return ("HPC_CTRL_GET_BOARD_TYPE");
		case HPC_CTRL_DISABLE_AUTOCFG:
			return ("HPC_CTRL_DISABLE_AUTOCFG");
		case HPC_CTRL_ENABLE_AUTOCFG:
			return ("HPC_CTRL_ENABLE_AUTOCFG");
		case HPC_CTRL_DISABLE_SLOT:
			return ("HPC_CTRL_DISABLE_SLOT");
		case HPC_CTRL_ENABLE_SLOT:
			return ("HPC_CTRL_ENABLE_SLOT");
		case HPC_CTRL_DISABLE_ENUM:
			return ("HPC_CTRL_DISABLE_ENUM");
		case HPC_CTRL_ENABLE_ENUM:
			return ("HPC_CTRL_ENABLE_ENUM");
		case HPC_CTRL_DEV_CONFIG_FAILURE:
			return ("HPC_CTRL_DEV_CONFIG_FAILURE");
		case HPC_CTRL_DEV_UNCONFIG_FAILURE:
			return ("HPC_CTRL_DEV_UNCONFIG_FAILURE");
		case HPC_CTRL_DEV_CONFIG_START:
			return ("HPC_CTRL_DEV_CONFIG_START");
		case HPC_CTRL_DEV_UNCONFIG_START:
			return ("HPC_CTRL_DEV_UNCONFIG_START");
	}
	return ("Unknown");
}

/*
 * pcishpc_textslotstate()
 *
 * Convert the request into a text message.
 */
static char *
pcishpc_textslotstate(hpc_slot_state_t state)
{
	/* Convert an HPC slot state into a textual string. */
	switch (state) {
		case HPC_SLOT_EMPTY:
			return ("HPC_SLOT_EMPTY");
		case HPC_SLOT_DISCONNECTED:
			return ("HPC_SLOT_DISCONNECTED");
		case HPC_SLOT_CONNECTED:
			return ("HPC_SLOT_CONNECTED");
		case HPC_SLOT_UNKNOWN:
			return ("HPC_SLOT_UNKNOWN");
	}
	return ("Unknown");
}


/*
 * pcishpc_write_reg()
 *
 * Write to a SHPC controller register.
 */
static void
pcishpc_write_reg(pcishpc_ctrl_t *ctrl_p, int reg, uint32_t data)
{
	/* Setup the SHPC dword select register. */
	pci_config_put8(ctrl_p->shpc_config_hdl,
		ctrl_p->shpc_dword_select, (uint8_t)reg);

	/* Read back the SHPC dword select register and verify. */
	if (pci_config_get8(ctrl_p->shpc_config_hdl,
		ctrl_p->shpc_dword_select) != (uint8_t)reg) {
		pcishpc_debug("pcishpc_write_reg() - Failed writing "
				"DWORD select reg");
		return;
	}

	/* Write to the SHPC dword data register. */
	pci_config_put32(ctrl_p->shpc_config_hdl,
		ctrl_p->shpc_dword_data_reg, data);

	/*
	 * Issue a read of the VendorID/DeviceID just to force the previous
	 * write to complete. This is probably not necessary, but it does
	 * help enforce ordering if there is an issue.
	 */
	(void) pci_config_get16(ctrl_p->shpc_config_hdl, PCI_CONF_VENID);
}


/*
 * pcishpc_read_reg()
 *
 * Read from a SHPC controller register.
 */
static uint32_t
pcishpc_read_reg(pcishpc_ctrl_t *ctrl_p, int reg)
{
	/* Setup the SHPC dword select register. */
	pci_config_put8(ctrl_p->shpc_config_hdl,
		ctrl_p->shpc_dword_select, (uint8_t)reg);

	/* Read back the SHPC dword select register and verify. */
	if (pci_config_get8(ctrl_p->shpc_config_hdl,
		ctrl_p->shpc_dword_select) != (uint8_t)reg) {
		pcishpc_debug("pcishpc_read_reg() - Failed writing DWORD "
			"select reg");
		return (0xFFFFFFFF);
	}

	/* Read from the SHPC dword data register. */
	return (pci_config_get32(ctrl_p->shpc_config_hdl,
		ctrl_p->shpc_dword_data_reg));
}


/*
 * pcishpc_debug()
 *
 * Controls debug output if enabled.
 */
static void
pcishpc_debug(char *fmt, ...)
{
	va_list ap;

	if (pcishpc_debug_enabled) {
		va_start(ap, fmt);
		vcmn_err(CE_WARN, fmt, ap);
		va_end(ap);
	}
}


/*
 * pcishpc_dump_regs()
 *
 * Dumps all of the SHPC controller registers.
 */
static void
pcishpc_dump_regs(pcishpc_ctrl_t *ctrl_p)
{
	int slot, numSlots;
	uint32_t reg;
	char *state;

	cmn_err(CE_WARN, "pcishpc_dump_regs() called:");
	cmn_err(CE_WARN, "================================================"
			"==========");

	cmn_err(CE_WARN, "SHPC Base Offset				"
		": 0x%08x", pcishpc_read_reg(ctrl_p, SHPC_BASE_OFFSET_REG));

	reg = pcishpc_read_reg(ctrl_p, SHPC_SLOTS_AVAIL_I_REG);

	cmn_err(CE_WARN, "Number of PCIX slots avail (33 Mhz)		 : %d",
		(reg & 31));

	cmn_err(CE_WARN, "Number of PCIX slots avail (66 Mhz)		 : %d",
		((reg>>8) & 31));

	cmn_err(CE_WARN, "Number of PCIX slots avail (100 Mhz)		: %d",
		((reg>>16) & 31));

	cmn_err(CE_WARN, "Number of PCIX slots avail (133 Mhz)		: %d",
		((reg>>24) & 31));

	reg = pcishpc_read_reg(ctrl_p, SHPC_SLOTS_AVAIL_II_REG);

	cmn_err(CE_WARN, "Number of conventional PCI slots (66 Mhz) : %d",
		(reg & 31));

	reg = pcishpc_read_reg(ctrl_p, SHPC_SLOT_CONFIGURATION_REG);

	numSlots = (reg & 31);

	cmn_err(CE_WARN, "Number of Slots connected to this port	 : %d",
			numSlots);

	cmn_err(CE_WARN, "PCI Device # for First HotPlug Slot		 : %d",
		((reg>>8) & 31));

	cmn_err(CE_WARN, "Physical Slot # for First PCI Device #	 : %d",
		((reg>>16) & 0x7ff));

	cmn_err(CE_WARN, "Physical Slot Number Up/Down			"
			": %d", ((reg>>29) & 0x1));

	cmn_err(CE_WARN, "MRL Sensor Implemented			"
			": %s", (reg & SHPC_SLOT_CONFIG_MRL_SENSOR) ? "Yes" :
				"No");

	cmn_err(CE_WARN, "Attention Button Implemented			"
			": %s", (reg & SHPC_SLOT_CONFIG_ATTN_BUTTON) ? "Yes" :
				"No");

	reg = pcishpc_read_reg(ctrl_p, SHPC_PROF_IF_SBCR_REG);

	switch (reg & 7) {
		case 0:
			state = "33Mhz Conventional PCI";
			break;
		case 1:
			state = "66Mhz Conventional PCI";
			break;
		case 2:
			state = "66Mhz PCI-X";
			break;
		case 3:
			state = "100Mhz PCI-X";
			break;
		case 4:
			state = "133Mhz PCI-X";
			break;
		default:
			state = "Reserved (Error)";
			break;
	}

	cmn_err(CE_WARN, "Current Port Operation Mode		"
		": %s", state);

	cmn_err(CE_WARN, "SHPC Interrupt Message Number		"
			": %d", ((reg>>16) &31));

	cmn_err(CE_WARN, "SHPC Programming Interface		"
			": %d", ((reg>>24) & 0xff));

	reg = pcishpc_read_reg(ctrl_p, SHPC_COMMAND_STATUS_REG);

	cmn_err(CE_WARN, "SHPC Command Code			"
			": %d", (reg & 0xff));

	cmn_err(CE_WARN, "SHPC Target Slot			"
			": %d", ((reg>>8) & 31));

	cmn_err(CE_WARN, "SHPC Controller Busy			"
			": %s", ((reg>>16) & 1) ? "Yes" : "No");

	cmn_err(CE_WARN, "SHPC Controller Err: MRL Sensor		"
			": %s", ((reg>>17) & 1) ? "Yes" : "No");

	cmn_err(CE_WARN, "SHPC Controller Err: Invalid Command		: %s",
		((reg>>18) & 1) ? "Yes" : "No");

	cmn_err(CE_WARN, "SHPC Controller Err: Invalid Speed/Mode	: %s",
		((reg>>19) & 1) ? "Yes" : "No");

	reg = pcishpc_read_reg(ctrl_p, SHPC_IRQ_LOCATOR_REG);

	cmn_err(CE_WARN, "Command Completion Interrupt Pending		: %s",
		(reg & SHPC_IRQ_CMD_COMPLETE) ? "Yes" : "No");

	for (slot = 0; slot < numSlots; slot++) {
		cmn_err(CE_WARN, "Slot %d Interrupt Pending		"
			": %s", slot+1,
			(reg & (SHPC_IRQ_SLOT_N_PENDING<<slot)) ? "Yes" : "No");
	}

	reg = pcishpc_read_reg(ctrl_p, SHPC_SERR_LOCATOR_REG);

	cmn_err(CE_WARN, "Arbiter SERR Pending				"
			": %s", (reg & SHPC_IRQ_SERR_ARBITER_PENDING) ?
				"Yes" : "No");

	for (slot = 0; slot < numSlots; slot++) {
		cmn_err(CE_WARN, "Slot %d SERR Pending			"
				": %s", slot+1, (reg &
					(SHPC_IRQ_SERR_SLOT_N_PENDING<<slot)) ?
						"Yes" : "No");
	}

	reg = pcishpc_read_reg(ctrl_p, SHPC_CTRL_SERR_INT_REG);

	cmn_err(CE_WARN, "Global Interrupt Mask				"
			": %s", (reg & SHPC_SERR_INT_GLOBAL_IRQ_MASK) ?
				"Yes" : "No");

	cmn_err(CE_WARN, "Global SERR Mask				"
			": %s", (reg & SHPC_SERR_INT_GLOBAL_SERR_MASK) ?
				"Yes" : "No");

	cmn_err(CE_WARN, "Command Completion Interrupt Mask		"
			": %s", (reg & SHPC_SERR_INT_CMD_COMPLETE_MASK) ?
				"Yes" : "No");

	cmn_err(CE_WARN, "Arbiter SERR Mask				"
			": %s", (reg & SHPC_SERR_INT_ARBITER_SERR_MASK) ?
				"Yes" : "No");

	cmn_err(CE_WARN, "Command Completion Detected			"
			": %s", (reg & SHPC_SERR_INT_CMD_COMPLETE_IRQ) ?
				"Yes" : "No");

	cmn_err(CE_WARN, "Arbiter Timeout Detected			"
			": %s", (reg & SHPC_SERR_INT_ARBITER_IRQ) ?
				"Yes" : "No");


	for (slot = 0; slot < numSlots; slot++) {
		cmn_err(CE_WARN, "Logical Slot %d Registers:", slot+1);
		cmn_err(CE_WARN, "------------------------------------");

		reg = pcishpc_read_reg(ctrl_p, SHPC_LOGICAL_SLOT_REGS+slot);

		cmn_err(CE_WARN, "Slot %d state				"
				": %s", slot+1,
				pcishpc_textslotstate(pcishpc_slot_shpc_to_hpc(
					(reg & 3))));

		cmn_err(CE_WARN, "Slot %d Power Indicator State		"
				": %s", slot+1,
				pcishpc_textledstate(pcishpc_led_shpc_to_hpc(
					(reg>>2) &3)));

		cmn_err(CE_WARN, "Slot %d Attention Indicator State	"
			": %s", slot+1,
			pcishpc_textledstate(pcishpc_led_shpc_to_hpc(
					(reg>>4)&3)));

		cmn_err(CE_WARN, "Slot %d Power Fault			"
			": %s", slot+1, ((reg>>6)&1) ? "Fault Detected" :
				"No Fault");
		cmn_err(CE_WARN, "Slot %d Attention Button		"
			": %s", slot+1, ((reg>>7)&1) ? "Depressed" :
				"Not Depressed");
		cmn_err(CE_WARN, "Slot %d MRL Sensor			"
				": %s", slot+1, ((reg>>8)&1) ? "Not Closed" :
					"Closed");
		cmn_err(CE_WARN, "Slot %d 66mhz Capable			"
			": %s", slot+1, ((reg>>9)&1) ? "66mhz" : "33mgz");

		switch ((reg>>10)&3) {
			case 0:
				state = "Card Present 7.5W";
				break;
			case 1:
				state = "Card Present 15W";
				break;
			case 2:
				state = "Card Present 25W";
				break;
			case 3:
				state = "Slot Empty";
				break;
		}

		cmn_err(CE_WARN, "Slot %d PRSNT1#/PRSNT2#		"
				": %s", slot+1, state);

		switch ((reg>>12)&3) {
			case 0:
				state = "Non PCI-X";
				break;
			case 1:
				state = "66mhz PCI-X";
				break;
			case 2:
				state = "Reserved";
				break;
			case 3:
				state = "133mhz PCI-X";
				break;
		}

		cmn_err(CE_WARN, "Slot %d Card Presence Change Detected	  : %s",
			slot+1, (reg & SHPC_SLOT_PRESENCE_DETECTED) ? "Yes" :
				"No");
		cmn_err(CE_WARN, "Slot %d Isolated Power Fault Detected	  : %s",
			slot+1, (reg & SHPC_SLOT_ISO_PWR_DETECTED) ? "Yes" :
				"No");
		cmn_err(CE_WARN, "Slot %d Attention Button Press Detected"
				": %s", slot+1,
				(reg & SHPC_SLOT_ATTN_DETECTED) ? "Yes" : "No");
		cmn_err(CE_WARN, "Slot %d MRL Sensor Change Detected	"
			": %s", slot+1,
			(reg & SHPC_SLOT_MRL_DETECTED) ? "Yes" : "No");
		cmn_err(CE_WARN, "Slot %d Connected Power Fault Detected"
			": %s", slot+1,
			(reg & SHPC_SLOT_POWER_DETECTED) ? "Yes" : "No");

		cmn_err(CE_WARN, "Slot %d Card Presence IRQ Masked	"
			": %s", slot+1,
			(reg & SHPC_SLOT_PRESENCE_MASK) ? "Yes" : "No");
		cmn_err(CE_WARN, "Slot %d Isolated Power Fault IRQ Masked"
			": %s", slot+1,
			(reg & SHPC_SLOT_ISO_PWR_MASK) ? "Yes" : "No");
		cmn_err(CE_WARN, "Slot %d Attention Button IRQ Masked	"
			": %s", slot+1, (reg & SHPC_SLOT_ATTN_MASK) ? "Yes" :
				"No");
		cmn_err(CE_WARN, "Slot %d MRL Sensor IRQ Masked		"
			": %s", slot+1,
			(reg & SHPC_SLOT_MRL_MASK) ? "Yes" : "No");
		cmn_err(CE_WARN, "Slot %d Connected Power Fault IRQ Masked"
			" : %s", slot+1,
			(reg & SHPC_SLOT_POWER_MASK) ? "Yes" : "No");
		cmn_err(CE_WARN, "Slot %d MRL Sensor SERR Masked "
			": %s", slot+1,
			(reg & SHPC_SLOT_MRL_SERR_MASK) ? "Yes" : "No");
		cmn_err(CE_WARN, "Slot %d Connected Power Fault SERR Masked :"
			"%s", slot+1,
			(reg & SHPC_SLOT_POWER_SERR_MASK) ? "Yes" : "No");
	}
}

static void
pcishpc_attn_btn_handler(pcishpc_t *pcishpc_p)
{
	hpc_led_state_t power_led_state;
	callb_cpr_t cprinfo;

	pcishpc_debug("pcishpc_attn_btn_handler: thread started\n");

	CALLB_CPR_INIT(&cprinfo, &pcishpc_p->ctrl->shpc_mutex,
	    callb_generic_cpr, "pcishpc_attn_btn_handler");

	mutex_enter(&pcishpc_p->ctrl->shpc_mutex);

	/* wait for ATTN button event */
	cv_wait(&pcishpc_p->attn_btn_cv, &pcishpc_p->ctrl->shpc_mutex);

	while (pcishpc_p->attn_btn_thread_exit == B_FALSE) {
		if (pcishpc_p->attn_btn_pending == B_TRUE) {
			/* get the current state of power LED */
			power_led_state = pcishpc_p->power_led_state;

			/* Blink the Power LED while we wait for 5 seconds */
			(void) pcishpc_setled(pcishpc_p, HPC_POWER_LED,
			    HPC_LED_BLINK);

			/* wait for 5 seconds before taking any action */
			if (cv_timedwait(&pcishpc_p->attn_btn_cv,
			    &pcishpc_p->ctrl->shpc_mutex,
			    ddi_get_lbolt() + SEC_TO_TICK(5)) == -1) {
				/*
				 * It is a time out;
				 * make sure the ATTN pending flag is
				 * still ON before sending the event
				 * to HPS framework.
				 */
				if (pcishpc_p->attn_btn_pending == B_TRUE) {
					/*
					 * send the ATTN button event
					 * to HPS framework
					 */
					pcishpc_p->attn_btn_pending = B_FALSE;
					(void) hpc_slot_event_notify(
					    pcishpc_p->slot_handle,
					    HPC_EVENT_SLOT_ATTN,
					    HPC_EVENT_NORMAL);
				}
			}

			/* restore the power LED state ??? XXX */
			(void) pcishpc_setled(pcishpc_p, HPC_POWER_LED,
			    power_led_state);
			continue;
		}

		/* wait for another ATTN button event */
		cv_wait(&pcishpc_p->attn_btn_cv, &pcishpc_p->ctrl->shpc_mutex);
	}

	pcishpc_debug("pcishpc_attn_btn_handler: thread exit\n");
	cv_signal(&pcishpc_p->attn_btn_cv);
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}

/*
 * setup slot name/slot-number info.
 */
static void
pcishpc_set_slot_name(pcishpc_ctrl_t *ctrl_p, int slot)
{
	pcishpc_t *p = ctrl_p->slots[slot];
	uchar_t *slotname_data;
	int *slotnum;
	uint_t count;
	int len;
	uchar_t *s;
	uint32_t bit_mask;
	int pci_id_cnt, pci_id_bit;
	int slots_before, found;
	int invalid_slotnum = 0;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, ctrl_p->shpc_dip,
		DDI_PROP_DONTPASS, "physical-slot#", &slotnum, &count) ==
		DDI_PROP_SUCCESS) {
		p->phy_slot_num = slotnum[0];
		ddi_prop_free(slotnum);
	} else {
		if (ctrl_p->deviceIncreases)
			p->phy_slot_num = ctrl_p->physStart + slot;
		else
			p->phy_slot_num = ctrl_p->physStart - slot;

		if ((ndi_prop_update_int(DDI_DEV_T_NONE, ctrl_p->shpc_dip,
			"physical-slot#", p->phy_slot_num)) != DDI_SUCCESS) {
			pcishpc_debug("pcishpc_set_slot_name(): failed to "
				"create phyical-slot#%d", p->phy_slot_num);
			}
	}

	if (!p->phy_slot_num) { /* platform may not have initialized it */
		p->phy_slot_num = pci_config_get8(ctrl_p->shpc_config_hdl,
				PCI_BCNF_SECBUS);
		invalid_slotnum = 1;
	}

	/*
	 * construct the slot_name:
	 * 	if "slot-names" property exists then use that name
	 *	else if valid slot number exists then it is "pci<slot-num>".
	 *	else it will be "pci<sec-bus-number>dev<dev-number>"
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, ctrl_p->shpc_dip, DDI_PROP_DONTPASS,
		"slot-names", (caddr_t)&slotname_data,
		&len) == DDI_PROP_SUCCESS) {

		bit_mask = slotname_data[3] | (slotname_data[2] << 8) |
		    (slotname_data[1] << 16) | (slotname_data[0] << 24);

		pci_id_bit = 1;
		pci_id_cnt = slots_before = found = 0;

		/*
		 * Walk the bit mask until we find the bit that corresponds
		 * to our slots device number.  We count how many bits
		 * we find before we find our slot's bit.
		 */
		while (!found && (pci_id_cnt < 32)) {

			while (p->deviceNum != pci_id_cnt) {

				/*
				 * Find the next bit set.
				 */
				while (!(bit_mask & pci_id_bit) &&
				    (pci_id_cnt < 32)) {
					pci_id_bit = pci_id_bit << 1;
					pci_id_cnt++;
				}

				if (p->deviceNum != pci_id_cnt)
					slots_before++;
				else
					found = 1;
			}
		}

		if (pci_id_cnt < 32) {

			/*
			 * Set ptr to first string.
			 */
			s = slotname_data + 4;

			/*
			 * Increment past all the strings for the slots
			 * before ours.
			 */
			while (slots_before) {
				while (*s != NULL)
					s++;
				s++;
				slots_before--;
			}

			(void) sprintf(p->slot_info.pci_slot_name, (char *)s);

			kmem_free(slotname_data, len);
			return;
		}

		/* slot-names entry not found */
		pcishpc_debug("pcishpc_set_slot_name(): "
			"No slot-names entry found for slot #%d",
			p->phy_slot_num);
		kmem_free(slotname_data, len);
	}

	if (invalid_slotnum)
	    (void) sprintf(p->slot_info.pci_slot_name, "pci%d",
		p->deviceNum);
	else
	    (void) sprintf(p->slot_info.pci_slot_name, "pci%d",
		p->phy_slot_num);
}
