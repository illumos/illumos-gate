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
 *     Starcat Specific Glue for Safari Configurator
 */

#include <sys/isa_defs.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/hwconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/safari_pcd.h>
#include <sys/gp2cfg.h>
#include <sys/gptwo_cpu.h>
#include <sys/gptwo_pci.h>
#include <sys/sc_gptwocfg.h>
#include <post/scat_dcd.h>
#include <sys/machsystm.h>

int sc_gptwocfg_debug = 0;

#define	SC_DEBUG(level, args) if (sc_gptwocfg_debug >= level) cmn_err args

typedef struct sc_gptwocfg_config {
	int				board;
	struct gptwocfg_config		*port_cookie;
	gptwo_aid_t			portid;
	struct sc_gptwocfg_config	*link;
	struct sc_gptwocfg_config	*next;
} sc_gptwocfg_config_t;

static kmutex_t sc_gptwo_config_list_lock;
static sc_gptwocfg_config_t *sc_gptwo_config_list;
static dev_info_t *sc_find_axq_node(uint_t);
static sc_gptwocfg_cookie_t sc_configure(uint_t, int);
static spcd_t *sc_get_common_pcd(uint_t, uint_t);
static void sc_free_common_pcd(spcd_t *);
static gptwo_new_nodes_t *sc_gptwocfg_configure_axq(dev_info_t *, uint_t, int);
static gptwocfg_config_t *sc_gptwocfg_unconfigure_axq(gptwocfg_config_t *);
static void dump_config(sc_gptwocfg_config_t *);
static void dump_pcd(spcd_t *);
static uint_t sc_get_agent_id(spcd_t *, uint_t, uint_t, uint_t);
static char *rsv_string(prdrsv_t);

extern gptwo_new_nodes_t *gptwocfg_allocate_node_list(int);
extern void gptwocfg_free_node_list(gptwo_new_nodes_t *);

static uint8_t *get_memlayout(uint32_t, uint32_t *);

#ifdef NO_IOSRAM
int iosram_rd(uint32_t, uint32_t, uint32_t, caddr_t);
#else
extern int iosram_rd(uint32_t, uint32_t, uint32_t, caddr_t);
#endif
extern void gptwocfg_devi_attach_to_parent(dev_info_t *);

/*
 * Module control operations
 */

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops, /* Type of module */
	"Sun Fire 15000 gptwocfg"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init()
{
	int err = 0;

	mutex_init(&sc_gptwo_config_list_lock, NULL, MUTEX_DRIVER, NULL);
	sc_gptwo_config_list = NULL;

	/*
	 * CPU/PCI devices are already registered by their respective modules,
	 * so all we need to do now is install.
	 */
	if ((err = mod_install(&modlinkage)) != 0) {
		SC_DEBUG(1, (CE_WARN, "sc_gptwocfg failed to load, error=%d\n",
		    err));
		mutex_destroy(&sc_gptwo_config_list_lock);
	} else {
		SC_DEBUG(1, (CE_WARN, "sc_gptwocfg has been loaded.\n"));
	}
	return (err);
}

int
_fini(void)
{
	mutex_destroy(&sc_gptwo_config_list_lock);
	return (mod_remove(&modlinkage));
}

int
_info(modinfop)
struct modinfo *modinfop;
{
	return (mod_info(&modlinkage, modinfop));
}

static spcd_t *
sc_get_common_pcd(uint_t expander, uint_t prd_slot)
{
	spcd_t *pcd;
	gdcd_t *gdcd;
	int portid;
	int i, j, slot;
	int dimm;
	char *label1, *label2;

	SC_DEBUG(1, (CE_WARN, "sc_get_common_pcd() expander=%d prd_slot=%d\n",
	    expander, prd_slot));

	gdcd = (gdcd_t *)kmem_zalloc(sizeof (gdcd_t), KM_SLEEP);

	/*
	 * Get the Starcat Specific Global DCD Structure from the golden
	 * IOSRAM.
	 */
	if (iosram_rd(GDCD_MAGIC, 0, sizeof (gdcd_t), (caddr_t)gdcd)) {
		cmn_err(CE_WARN, "sc_gptwocfg: Unable To Read GDCD "
		    "From IOSRAM\n");
		kmem_free(gdcd, sizeof (gdcd_t));
		return (NULL);
	}

	if (gdcd->h.dcd_magic != GDCD_MAGIC) {

		cmn_err(CE_WARN, "sc_gptwocfg: GDCD Bad Magic 0x%x\n",
		    gdcd->h.dcd_magic);

		kmem_free(gdcd, sizeof (gdcd_t));
		return (NULL);
	}

	if (gdcd->h.dcd_version != DCD_VERSION) {
		cmn_err(CE_WARN, "sc_gptwocfg: GDCD Bad Version: "
		    "GDCD Version 0x%x Expecting 0x%x\n",
		    gdcd->h.dcd_version, DCD_VERSION);

		kmem_free(gdcd, sizeof (gdcd_t));
		return (NULL);
	}

	pcd = (spcd_t *)kmem_zalloc(sizeof (spcd_t), KM_SLEEP);

	/*
	 * Copy various information from the platform specific Port
	 * Resource Descriptor (PRD) To the platform independent
	 * Port Configuration Descriptor.
	 */
	pcd->spcd_magic = PCD_MAGIC;
	pcd->spcd_version = PCD_VERSION;
	pcd->spcd_ptype = gdcd->dcd_prd[expander][prd_slot].prd_ptype;
	pcd->spcd_ver_reg = gdcd->dcd_prd[expander][prd_slot].prd_ver_reg;

	if (pcd->spcd_ptype == SAFPTYPE_CPU) {
		/*
		 * This will calculate the cpu speed based on the
		 * the actual frequency ratio * interconnect frequency
		 * converted to Mhz.
		 */
		pcd->spcd_afreq = gdcd->dcd_prd[expander][prd_slot].
		    prd_afreq_ratio *
		    (uint16_t)((gdcd->dcd_intercon_freq + 500000) / 1000000);
	} else {
		/*
		 * For non-cpu devices, just pass through the frequency
		 * unchanged.
		 */
		pcd->spcd_afreq =
		    gdcd->dcd_prd[expander][prd_slot].prd_afreq_ratio;
	}

	pcd->spcd_cache = gdcd->dcd_prd[expander][prd_slot].prd_cache;

	SC_DEBUG(1, (CE_WARN, "Safari Device Status status=0x%x\n",
	    gdcd->dcd_prd[expander][prd_slot].prd_prsv));

	/*
	 * Fill in the entire port status.
	 */
	if (RSV_GOOD(gdcd->dcd_prd[expander][prd_slot].prd_prsv)) {
		pcd->spcd_prsv = SPCD_RSV_PASS;
	} else {
		pcd->spcd_prsv = SPCD_RSV_FAIL;
	}

	/*
	 * Fill in the per agent status.
	 */
	if (gdcd->dcd_prd[expander][prd_slot].prd_agent[1] == RSV_UNKNOWN) {
		pcd->spcd_agent[0] = pcd->spcd_prsv;
		pcd->spcd_agent[1] = SPCD_RSV_FAIL;
	} else {
		for (i = 0; i < AGENTS_PER_PORT; i++) {

			if (RSV_GOOD(
			    gdcd->dcd_prd[expander][prd_slot].prd_agent[i]))
				pcd->spcd_agent[i] = SPCD_RSV_PASS;
			else
				pcd->spcd_agent[i] = SPCD_RSV_FAIL;
		}
	}

	/*
	 * If this is a CPU device calculate the cpuid for it.  For Starcat
	 * the cpuid is in the following format.
	 *
	 * EEEEEPPAPP
	 *
	 * where:	EEEEE is the expander
	 *		PP_PP is the portid
	 *		__A__ is the sub-agent identifier.
	 */
	if (pcd->spcd_ptype == SAFPTYPE_CPU) {
		for (i = 0; i < AGENTS_PER_PORT; i++) {
			switch (prd_slot) {
			case 0:
			case 1:
			case 2:
			case 3:
				portid = (expander << 5) | prd_slot;
				break;
			case 4: /* Maxcat */
				portid = (expander << 5) | 8;
				break;
			case 5: /* Maxcat */
				portid = (expander << 5) | 9;
				break;
			default:
				cmn_err(CE_WARN, "sc_gptwocfg: invalid "
				    "prd_slot=%d\n", prd_slot);
			}
			pcd->spcd_cpuid[i] = (i << 2) | portid;
		}
	}

	/*
	 * Starcat does not have ports with UPA devices so
	 * spcd_upadev structure will not be filled in.
	 */

	/*
	 * Fill in IO Bus Status
	 */
	for (i = 0; i < IOBUS_PER_PORT; i++) {

		SC_DEBUG(1, (CE_WARN, "   IO Bus Status "
		    "bus=%d status=0x%x\n", i,
		    gdcd->dcd_prd[expander][prd_slot].prd_iobus_rsv[i]));

		if (RSV_GOOD(
		    gdcd->dcd_prd[expander][prd_slot].prd_iobus_rsv[i])) {
			pcd->spcd_iobus_rsv[i] = SPCD_RSV_PASS;
		} else {
			pcd->spcd_iobus_rsv[i] = SPCD_RSV_FAIL;
		}

		for (j = 0; j < IOCARD_PER_BUS; j++)
			pcd->spcd_iocard_rsv[i][j] = SPCD_RSV_FAIL;

		/*
		 * Fill in IO Card Status
		 */
		for (j = 0; j < IOCARD_PER_BUS; j++) {

			SC_DEBUG(1, (CE_WARN, "       Card Status bus=%d "
			    "slot=%d status=0x%x\n", i, j,
			    gdcd->dcd_prd[expander][prd_slot].
			    prd_iocard_rsv[i][j]));

			if (j == 1)
				continue;

			if (j == 0)
				slot = 1;
			else
				slot = j;

			/*
			 * If POST marked the card as GOOD or if the slot
			 * is empty, we want to probe for the device.
			 */
			if (RSV_GOOD(gdcd->dcd_prd[expander][prd_slot].
			    prd_iocard_rsv[i][j]) ||
			    (gdcd->dcd_prd[expander][prd_slot].
			    prd_iocard_rsv[i][j] == RSV_MISS) ||
			    (gdcd->dcd_prd[expander][prd_slot].
			    prd_iocard_rsv[i][j] == RSV_EMPTY_CASSETTE))
				pcd->spcd_iocard_rsv[i][slot] = SPCD_RSV_PASS;
			else
				pcd->spcd_iocard_rsv[i][slot] = SPCD_RSV_FAIL;
		}
	}

	/*
	 * Fill in WIC Link Status
	 */
	for (i = 0; i < LINKS_PER_PORT; i++) {
		if (RSV_GOOD(
		    gdcd->dcd_prd[expander][prd_slot].prd_wic_links[i])) {
			pcd->spcd_wic_links[i] = SPCD_RSV_PASS;

		} else {
			pcd->spcd_wic_links[i] = SPCD_RSV_FAIL;
		}
	}

	/*
	 * Get data for the "bank-status" property.
	 */
	pcd->sprd_bank_rsv[0] =
	    rsv_string(gdcd->dcd_prd[expander][prd_slot].prd_bank_rsv[0][0]);
	pcd->sprd_bank_rsv[1] =
	    rsv_string(gdcd->dcd_prd[expander][prd_slot].prd_bank_rsv[1][0]);
	pcd->sprd_bank_rsv[2] =
	    rsv_string(gdcd->dcd_prd[expander][prd_slot].prd_bank_rsv[0][1]);
	pcd->sprd_bank_rsv[3] =
	    rsv_string(gdcd->dcd_prd[expander][prd_slot].prd_bank_rsv[1][1]);

	dimm = 0;
	for (i = 0; i < PMBANKS_PER_PORT; i++) {
		for (j = 0; j < DIMMS_PER_PMBANK; j++) {
			if (dimm < MAX_DIMMS_PER_PORT) {
				pcd->sprd_dimm[dimm] = rsv_string(
				    gdcd->dcd_prd[expander][prd_slot].
				    prd_dimm[i][j]);
				dimm++;
			}
		}
	}

	/*
	 * Get data for the "ecache-dimm-label" property.
	 *
	 * Right now it is hardcoded, but we should eventually get this
	 * from the SC.
	 */
	label1 = NULL;
	label2 = NULL;

	switch (prd_slot) {
	case 0:
		label1 = "4400";
		label2 = "4300";
		break;
	case 1:
		label1 = "5400";
		label2 = "5300";
		break;
	case 2:
		label1 = "6400";
		label2 = "6300";
		break;
	case 3:
		label1 = "7400";
		label2 = "7300";
		break;

	/*
	 * Maxcat labels.
	 */
	case 4:
		label1 = "6400";
		label2 = "6300";
		break;
	case 5:
		label1 = "7400";
		label2 = "7300";
		break;
	}

	i = 0;
	if (label1) {
		pcd->sprd_ecache_dimm_label[i] =
		    kmem_alloc(strlen(label1) + 1, KM_SLEEP);

		(void) strcpy(pcd->sprd_ecache_dimm_label[i], label1);

		i++;
	}
	if (label2) {
		pcd->sprd_ecache_dimm_label[i] =
		    kmem_alloc(strlen(label2) + 1, KM_SLEEP);

		(void) strcpy(pcd->sprd_ecache_dimm_label[i], label2);

		i++;

	}

	kmem_free(gdcd, sizeof (gdcd_t));

#ifdef DEBUG
	dump_pcd(pcd);
#endif

	return (pcd);
}

void
sc_free_common_pcd(spcd_t *pcd)
{
	int i;

	SC_DEBUG(1, (CE_WARN, "sc_free_common_pcd pcd=%p\n", pcd));

	if (pcd->memory_layout && pcd->memory_layout_size) {
		SC_DEBUG(1, (CE_WARN, "sc_free_common_pcd: memory_layout %p "
		    "size=%x", pcd->memory_layout, pcd->memory_layout_size));
		kmem_free(pcd->memory_layout, pcd->memory_layout_size);
	}

	for (i = 0; i < MAX_BANKS_PER_PORT; i++) {
		if (pcd->sprd_bank_rsv[i]) {
			kmem_free(pcd->sprd_bank_rsv[i],
			    strlen(pcd->sprd_bank_rsv[i]) + 1);

			pcd->sprd_bank_rsv[i] = NULL;
		}
	}

	for (i = 0; i < MAX_DIMMS_PER_PORT; i++) {
		if (pcd->sprd_dimm[i]) {
			kmem_free(pcd->sprd_dimm[i],
			    strlen(pcd->sprd_dimm[i]) + 1);

			pcd->sprd_dimm[i] = NULL;
		}
		if (pcd->sprd_ecache_dimm_label[i]) {
			kmem_free(pcd->sprd_ecache_dimm_label[i],
			    strlen(pcd->sprd_ecache_dimm_label[i]) + 1);

			pcd->sprd_ecache_dimm_label[i] = NULL;
		}
	}

	kmem_free(pcd, sizeof (spcd_t));
}

sc_gptwocfg_cookie_t
sc_probe_board(uint_t board)
{
	return (sc_configure(board, 1));
}

static sc_gptwocfg_cookie_t
sc_configure(uint_t board, int create_nodes)
{
	spcd_t *pcd;
	dev_info_t *ap, *axq_dip;
	uint_t agent_id;
	uint_t prd_slot, prd_slot_start, prd_slot_end;
	uint_t expander, slot;
	gptwo_new_nodes_t *new_nodes;
	gptwocfg_config_t *port_cookie;
	struct sc_gptwocfg_config *board_config, *last, *new;
	int created_node = 0;
	uint32_t size;

	SC_DEBUG(1, (CE_WARN, "sc_configure: board=%d, create_nodes=%d\n",
	    board, create_nodes));

	if (board > 35) {
		SC_DEBUG(1, (CE_WARN, "sc_gptwocfg - probe_board - "
		    "invalid board 0x%x\n", board));
		return (NULL);
	}

	slot = board & 1;	/* Extract Slot Number */
	expander = board >> 1;	/* Extract Expander Number */

	SC_DEBUG(1, (CE_WARN, "sc_configure: exp=0x%x slot=0x%x\n",
	    expander, slot));

	/*
	 * Get the Attachment Point.  For Starcat the parent of all
	 * Safari children is root node.
	 */
	ap = ddi_root_node();

	/*
	 * Get the agent id of the AXQ.
	 */
	agent_id = (expander << 5) | 0x1e | slot;

	/*
	 * Look to see if the board is already configured by searching for
	 * its AXQ.
	 */
	if (create_nodes && (axq_dip = sc_find_axq_node(agent_id))) {
		ddi_release_devi(axq_dip);
		cmn_err(CE_WARN, "Board %d AXQ is already configured\n",
		    board);
		return (NULL);
	}

	/*
	 * Probe AXQ first
	 */
	SC_DEBUG(1, (CE_WARN, "sc_configure: Probing AXQ exp=0x%x brd=0x%x\n",
	    expander, slot));

	/*
	 * The generic gptwocfg does not support the AXQ, so we need
	 * to configure it. The AXQ branch is returned held.
	 */
	new_nodes = sc_gptwocfg_configure_axq(ap, agent_id, create_nodes);

	if (new_nodes == NULL) {
		SC_DEBUG(1, (CE_WARN, "sc_configure: Can not probe AXQ\n"));
		return (NULL);
	}

	port_cookie = kmem_zalloc(sizeof (gptwocfg_config_t), KM_SLEEP);

	/*
	 * Build a cookie for the AXQ.
	 */
	port_cookie->gptwo_ap = ap;
	port_cookie->gptwo_portid = agent_id;
	port_cookie->gptwo_nodes = new_nodes;

	board_config = kmem_zalloc(sizeof (sc_gptwocfg_config_t), KM_SLEEP);

	board_config->port_cookie = port_cookie;
	board_config->board = board;
	board_config->portid = agent_id;
	board_config->link = NULL;
	last = board_config;

	mutex_enter(&sc_gptwo_config_list_lock);
	board_config->next = sc_gptwo_config_list;
	sc_gptwo_config_list = board_config;
	mutex_exit(&sc_gptwo_config_list_lock);

	SC_DEBUG(1, (CE_WARN, "sc_configure: AXQ Probing Complete. "
	    "%d nodes added\n", new_nodes->gptwo_number_of_nodes));

	/*
	 * Determine the starting ending slots of the PRD array.
	 */
	switch (slot) {
	case 0:		/* Full Bandwidth Slot */
		prd_slot_start = 0;
		prd_slot_end = 3;
		break;
	case 1:		/* Half Bandwidth Slot */
		prd_slot_start = 4;
		prd_slot_end = 5;
		break;
	default:
		SC_DEBUG(1, (CE_WARN, "Unknown Board Address - "
		    "Can not probe\n"));
		return (board_config);
	}

	/*
	 * For each valid PRD entry, determine the agent id which is based
	 * on what type of device is described by the slot, and then
	 * call the safari configurator.
	 */
	for (prd_slot = prd_slot_start; prd_slot <= prd_slot_end; prd_slot++) {

		pcd = sc_get_common_pcd(expander, prd_slot);

		if (pcd == NULL) {

			/*
			 * We can not get a PCD for this port so skip it.
			 */
			cmn_err(CE_WARN, "sc_gptwocfg: Can not get PCD "
			    "expander 0x%x prd slot 0x%x\n",
			    expander, prd_slot);

			return (board_config);
		}

		/*
		 * Only configure good devices.
		 */
		if (pcd->spcd_prsv == SPCD_RSV_PASS) {
			/*
			 * Determine the agent id.
			 */
			agent_id = sc_get_agent_id(
			    pcd, expander, slot, prd_slot);

			pcd->memory_layout = get_memlayout(agent_id, &size);
			pcd->memory_layout_size = size;

			/*
			 * Call Platform Independent gptwo configurator to
			 * create node and properties.
			 */
			if (create_nodes) {
				port_cookie =
				    gptwocfg_configure(ap, pcd, agent_id);
				if (port_cookie)
					created_node++;
			}

			new = kmem_zalloc
			    (sizeof (sc_gptwocfg_config_t), KM_SLEEP);

			/*
			 * XXX Shouldn't port_cookie be NULL if
			 * !create_nodes ?
			 */
			new->port_cookie = port_cookie;
			new->portid = agent_id;
			new->link = NULL;
			last->link = new;
			last = new;
		} else {
			SC_DEBUG(1, (CE_WARN, "sc_configure: Bad Agent "
			    "Exp=0x%x PRD Slot=0x%x  prsv Status=0x%x\n",
			    expander, prd_slot, pcd->spcd_prsv));
		}

		sc_free_common_pcd(pcd);

	} /* for loop */

	dump_config(board_config);

	if (create_nodes && !created_node) {
		SC_DEBUG(1, (CE_WARN, "sc_configure: GPTWO Devices failed "
		    "to configure - unprobing board %d\n", board));
		board_config = sc_unprobe_board(board);
	}

	SC_DEBUG(1, (CE_WARN, "sc_configure: Returning 0x%p\n",
	    board_config));

	return (board_config);
}

sc_gptwocfg_cookie_t
sc_unprobe_board(uint_t board)
{
	sc_gptwocfg_config_t *board_config, *axq_config, *prior_config;
	gptwocfg_cookie_t port_cookie;

	SC_DEBUG(1, (CE_WARN, "sc_unprobe_board: board=%d\n", board));

	if (board > 35) {
		SC_DEBUG(1, (CE_WARN, "sc_unprobe_board: "
		    "invalid board 0x%x\n", board));
		return (NULL);
	}
	mutex_enter(&sc_gptwo_config_list_lock);
	board_config = sc_gptwo_config_list;
	while (board_config != NULL) {
		if (board_config->board == board) {
			break;
		}
		board_config = board_config->next;
	}
	mutex_exit(&sc_gptwo_config_list_lock);

	if (board_config == NULL) {

		SC_DEBUG(1, (CE_WARN, "sc_unprobe_board: No "
		    "config structure board=0x%x\n", board));

		/*
		 * Configure the board without creating nodes.
		 */
		board_config = sc_configure(board, 0);

		if (board_config == NULL) {

			cmn_err(CE_WARN, "sc_gptwocfg: sc_unprobe_board: "
			    "Unable to unconfigure board %d - board is not "
			    "configured\n", board);

			return (NULL);
		}
	}

	axq_config = board_config;

	/*
	 * Walk the link of ports on this board and unconfigure them.
	 * Save the AXQ for last.
	 */
	while (board_config->link != NULL) {
		prior_config = board_config;
		board_config = board_config->link;

		SC_DEBUG(1, (CE_WARN, "sc_unprobe_board: "
		    "calling gptwocfg_unconfigure(ap=0x%p portid=0x%x)\n",
		    ddi_root_node(), board_config->portid));

		port_cookie = gptwocfg_unconfigure(ddi_root_node(),
		    board_config->portid);

		SC_DEBUG(1, (CE_WARN, "sc_unprobe_board: "
		    "gptwocfg_unconfigure returned cookie=0x%p\n",
		    port_cookie));

		if (port_cookie == NULL) {
			/*
			 * Can be removed from list.
			 */
			prior_config->link = board_config->link;
			kmem_free(board_config, sizeof (sc_gptwocfg_config_t));
			board_config = prior_config;
		} else {
			board_config->port_cookie = port_cookie;
		}
	}

	if (axq_config->link == NULL) {

		/*
		 * If all the other Safari devices have been successfully
		 * unconfigured, then the AXQ can be unconfigured.
		 */
		axq_config->port_cookie =
		    sc_gptwocfg_unconfigure_axq(axq_config->port_cookie);

		if (axq_config->port_cookie == NULL) {

			/*
			 * If the AXQ was successfully unconfigured, then
			 * the board is removed from the configured list.
			 */
			mutex_enter(&sc_gptwo_config_list_lock);
			if (sc_gptwo_config_list == axq_config) {
				sc_gptwo_config_list = axq_config->next;
			} else {
				board_config = sc_gptwo_config_list;
				while (board_config->next != axq_config) {
					board_config = board_config->next;
				}
				board_config->next = axq_config->next;
			}
			mutex_exit(&sc_gptwo_config_list_lock);
			kmem_free(axq_config, sizeof (sc_gptwocfg_config_t));
			axq_config = NULL;
		}
	}
	dump_config(axq_config);
	return (axq_config);
}

int
sc_next_node(sc_gptwocfg_cookie_t c, dev_info_t *previous, dev_info_t **next)
{
	dev_info_t *dip;
	sc_gptwocfg_config_t *cookie;

	SC_DEBUG(1, (CE_WARN, "sccfg: sccfg_next_node"
	    "(c=0x%p, previous=0x%p, next=0x%p)\n", c, previous, next));

	cookie = (sc_gptwocfg_config_t *)c;

	if (cookie == NULL) {
		cmn_err(CE_WARN, "sccfg: sccfg_next_node - "
		    "Invalid Cookie\n");
		return (0);
	}
	if (previous == NULL) {
		/*
		 * Start with the AXQ node.
		 */
		if (gptwocfg_next_node(cookie->port_cookie, NULL, &dip)) {
			*next = dip;
			return (1);
		} else {
			return (0);
		}
	}

	while (cookie != NULL) {
		if (gptwocfg_next_node(cookie->port_cookie, previous, &dip)) {
			if ((dip == NULL) && (cookie->link == NULL)) {
				*next = NULL;
				return (1);
			}
			if (dip != NULL) {
				*next = dip;
				return (1);
			}

			/* dip == NULL */

			previous = NULL;
		}
		cookie = cookie->link;
	}

	return (0);
}

static dev_info_t *
sc_find_axq_node(uint_t axq_id)
{
	char *name;
	int size;
	gptwo_regspec_t *reg;
	dev_info_t *dip;
	uint_t id;
	int circ;

	SC_DEBUG(1, (CE_CONT, "sc_find_axq_node: id=0x%x\n", axq_id));

	/*
	 * Hold root node busy to walk its child list
	 */
	ndi_devi_enter(ddi_root_node(), &circ);

	dip = ddi_get_child(ddi_root_node());

	while (dip != NULL) {

		SC_DEBUG(1, (CE_CONT, "Searching dip=0x%p for our AXQ\n",
		    dip));

		if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "name", (caddr_t)&name, &size)
		    != DDI_PROP_SUCCESS) {

			/*
			 * This node does not have a name property.
			 */
			SC_DEBUG(1, (CE_CONT, "dip=0x%p does not have a "
			    "'name' property\n", dip));

			dip = ddi_get_next_sibling(dip);
			continue;
		}

		SC_DEBUG(1, (CE_CONT, "dip=0x%p name=%s\n", dip, name));

		if (strcmp(name, "address-extender-queue")) {

			/*
			 * This node is not a AXQ node.
			 */
			SC_DEBUG(1, (CE_CONT, "dip=0x%p is not an AXQ "
			    "node\n", dip));
			kmem_free(name, size);
			dip = ddi_get_next_sibling(dip);
			continue;
		}
		kmem_free(name, size);

		if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "reg", (caddr_t)&reg, &size)
		    != DDI_PROP_SUCCESS) {

			/*
			 * This AXQ node does not have a reg property.
			 */
			SC_DEBUG(1, (CE_CONT, "dip=0x%p (AXQ Node) does "
			    "have a 'reg' property\n", dip));
			dip = ddi_get_next_sibling(dip);
			continue;
		}

		id = ((reg[0].gptwo_phys_hi & 1) << 9) |
		    ((reg[0].gptwo_phys_low & 0xff800000) >> 23);

		kmem_free(reg, size);

		if (axq_id != id) {

			/*
			 * This is the wrong AXQ node.
			 */
			SC_DEBUG(1, (CE_CONT, "dip=0x%p Wrong node id=0x%x\n",
			    dip, id));

			dip = ddi_get_next_sibling(dip);
			continue;

		}

		/*
		 * The correct AXQ node was found.
		 */
		SC_DEBUG(1, (CE_CONT, "dip=0x%p Found AXQ Node\n", dip));
		ndi_hold_devi(dip);
		break;
	}
	ndi_devi_exit(ddi_root_node(), circ);

	SC_DEBUG(1, (CE_CONT, "sc_find_axq_node: Returning 0x%p\n", dip));

	return (dip);
}

struct axq_arg {
	uint_t id;
	dev_info_t *axq_dip;
};

/*ARGSUSED*/
static int
axq_set_prop(dev_info_t *axq_dip, void *arg, uint_t flags)
{
	struct axq_arg *aqp = (struct axq_arg *)arg;
	gptwo_regspec_t	reg[2];
	uint_t		id;

	ASSERT(aqp);

	id = aqp->id;

	if (ndi_prop_update_string(DDI_DEV_T_NONE, axq_dip,
	    "name", "address-extender-queue") != DDI_SUCCESS) {
		SC_DEBUG(1, (CE_CONT, "gptwocfg_configure_pci: failed "
		    "to create name property\n"));
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_string(DDI_DEV_T_NONE, axq_dip,
	    "device_type", "address-extender-queue") != DDI_SUCCESS) {
		SC_DEBUG(1, (CE_CONT, "gptwocfg_configure_pci: failed "
		    "to create device_type property\n"));
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_string(DDI_DEV_T_NONE, axq_dip,
	    "compatible", "SUNW,axq") != DDI_SUCCESS) {
		SC_DEBUG(1, (CE_CONT, "sc_gptwocfg: failed "
		    "to create compatible property\n"));
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, axq_dip,
	    "portid", id) != DDI_SUCCESS) {
		SC_DEBUG(1, (CE_CONT, "gptwocfg_configure_pci: failed "
		    "to create portid property\n"));
		return (DDI_WALK_ERROR);
	}

	reg[0].gptwo_phys_hi = 0x400 | (id >> 9);
	reg[0].gptwo_phys_low = (id << 23);
	reg[0].gptwo_size_hi = 0;
	reg[0].gptwo_size_low = 0x520;

	reg[1].gptwo_phys_hi = 0x401;
	reg[1].gptwo_phys_low = 0xf0000000;
	reg[1].gptwo_size_hi = 0;
	reg[1].gptwo_size_low = 0x520;

	if (ndi_prop_update_int_array(DDI_DEV_T_NONE,
	    axq_dip, "reg", (int *)&reg,
	    (sizeof (gptwo_regspec_t) * 2)/sizeof (int)) != DDI_SUCCESS) {
		SC_DEBUG(1, (CE_CONT, "gptwocfg_configure_pci: failed "
		    "to create reg property\n"));
		return (DDI_WALK_ERROR);
	}

	return (DDI_WALK_TERMINATE);
}

/*ARGSUSED*/
static void
get_axq_dip(dev_info_t *rdip, void *arg, uint_t flags)
{
	struct axq_arg *aqp = (struct axq_arg *)arg;

	ASSERT(aqp);

	aqp->axq_dip = rdip;
}

static gptwo_new_nodes_t *
sc_gptwocfg_configure_axq(dev_info_t *ap, uint_t id, int create_nodes)
{
	struct axq_arg arg = {0};
	devi_branch_t b = {0};
	dev_info_t *axq_dip, *fdip = NULL;
	gptwo_new_nodes_t *new_nodes = NULL;
	int rv;

	SC_DEBUG(1, (CE_CONT, "gptwocfg_configure_axq: id=0x%x "
	    "create_nodes=%d\n", id, create_nodes));

	if (!create_nodes) {
		axq_dip = sc_find_axq_node(id);

		if (axq_dip) {
			new_nodes = gptwocfg_allocate_node_list(1);
			new_nodes->gptwo_nodes[0] = axq_dip;
			ASSERT(!e_ddi_branch_held(axq_dip));
			e_ddi_branch_hold(axq_dip);
			/*
			 * Release hold from sc_find_axq_node()
			 */
			ddi_release_devi(axq_dip);
		}

		SC_DEBUG(1, (CE_CONT, "gptwocfg_configure_axq: "
		    "Returning 0x%p\n", new_nodes));

		return (new_nodes);
	}

	arg.id = id;
	arg.axq_dip = NULL;

	b.arg = &arg;
	b.type = DEVI_BRANCH_SID;
	b.create.sid_branch_create = axq_set_prop;
	b.devi_branch_callback = get_axq_dip;

	rv = e_ddi_branch_create(ap, &b, &fdip, DEVI_BRANCH_CONFIGURE);
	if (rv != 0) {
		char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		/*
		 * If non-NULL, fdip is held and must be released.
		 */
		if (fdip != NULL) {
			(void) ddi_pathname(fdip, path);
			ddi_release_devi(fdip);
		} else {
			(void) ddi_pathname(ap, path);
		}

		SC_DEBUG(1, (CE_WARN, "e_ddi_branch_create failed: "
		    "path=%s, dip=%p, rv=%d", path, fdip ? (void *)fdip :
		    (void *)ap, rv));

		kmem_free(path, MAXPATHLEN);

		return (NULL);
	}

	axq_dip = arg.axq_dip;

	new_nodes = gptwocfg_allocate_node_list(1);
	new_nodes->gptwo_nodes[0] = axq_dip;

	return (new_nodes);
}

static gptwocfg_config_t *
sc_gptwocfg_unconfigure_axq(gptwocfg_config_t *config)
{
	int i;
	int failure = 0;
	dev_info_t *saf_dip;

	if (config == NULL) {
		cmn_err(CE_WARN, "sc_gptwocfg: sc_gptwocfg_unconfigure_axq: "
		    "Invalid AXQ\n");
		return (NULL);
	}
	for (i = 0; i < config->gptwo_nodes->gptwo_number_of_nodes; i++) {
		int rv;
		dev_info_t *fdip = NULL;

		saf_dip = config->gptwo_nodes->gptwo_nodes[i];
		ASSERT(e_ddi_branch_held(saf_dip));
		rv = e_ddi_branch_destroy(saf_dip, &fdip, 0);
		if (rv != 0) {
			char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

			/*
			 * If non-NULL, fdip is held and must be released.
			 */
			if (fdip != NULL) {
				(void) ddi_pathname(fdip, path);
				ddi_release_devi(fdip);
			} else {
				(void) ddi_pathname(saf_dip, path);
			}

			cmn_err(CE_CONT, "AXQ node removal failed: "
			    "path=%s, dip=%p, rv=%d\n", path,
			    fdip ? (void *)fdip : (void *)saf_dip, rv);

			kmem_free(path, MAXPATHLEN);
			failure = 1;
		} else {
			config->gptwo_nodes->gptwo_nodes[i] = NULL;
		}
	}
	if (!failure) {
		gptwocfg_free_node_list(config->gptwo_nodes);

		kmem_free(config, sizeof (gptwocfg_config_t));
		config = NULL;
	}
	return (config);
}

static uint_t
sc_get_agent_id(spcd_t *pcd, uint_t expander, uint_t slot, uint_t prd_slot)
{
	uint_t agent_id;

	switch (pcd->spcd_ptype) {
	case SAFPTYPE_CPU:
		if (slot == 0) {
			agent_id = prd_slot;
		} else {
			if (prd_slot == 4) {
				agent_id = 8;
			} else {
				agent_id = 9;
			}
		}
		break;

	case SAFPTYPE_sPCI:
	case SAFPTYPE_cPCI:
	case SAFPTYPE_PCIX:
		if (prd_slot == 4) {
			agent_id = 0x1c;
		} else {
			agent_id = 0x1d;
		}
		break;
	case SAFPTYPE_WCI:
		agent_id = 0x1d;
		break;
	default:
		cmn_err(CE_WARN, "sc_gptwocfg: Invalid Safari Port "
		    "Type 0x%x Slot 0x%x\n",
		    pcd->spcd_ptype, prd_slot);
	} /* switch */

	agent_id |= (expander << 5);

	SC_DEBUG(1, (CE_CONT, "sc_get_agent_id(pcd=0x%p, expander=0x%x, "
	    "prd_slot=0x%x) Returning agent_id=0x%x\n", pcd, expander,
	    prd_slot, agent_id));

	return (agent_id);
}

static void
dump_config(sc_gptwocfg_config_t *board_config)
{
	gptwocfg_config_t *port;

	SC_DEBUG(1, (CE_CONT, "dump_config 0x%p", board_config));
	while (board_config != NULL) {
		SC_DEBUG(1, (CE_CONT, "************* 0x%p ************\n",
		    board_config));
		SC_DEBUG(1, (CE_CONT, "port_cookie - 0x%p\n",
		    board_config->port_cookie));

		port = board_config->port_cookie;
		if (port) {
			SC_DEBUG(1, (CE_CONT, "     ap     - 0x%p\n",
			    port->gptwo_ap));
			SC_DEBUG(1, (CE_CONT, "     portid - 0x%x\n",
			    port->gptwo_portid));
		}
		SC_DEBUG(1, (CE_CONT, "portid      - 0x%x\n",
		    board_config->portid));
		SC_DEBUG(1, (CE_CONT, "board      - 0x%x\n",
		    board_config->board));
		SC_DEBUG(1, (CE_CONT, "link        - 0x%p\n",
		    board_config->link));
		SC_DEBUG(1, (CE_CONT, "next        - 0x%p\n",
		    board_config->next));
		board_config = board_config->link;
	}
}

static void
dump_pcd(spcd_t *pcd)
{
	int i;

	SC_DEBUG(1, (CE_CONT, "dump_pcd 0x%p", pcd));
	SC_DEBUG(1, (CE_CONT, "     magic   - 0x%x\n", pcd->spcd_magic));
	SC_DEBUG(1, (CE_CONT, "     version - 0x%x\n", pcd->spcd_version));
	SC_DEBUG(1, (CE_CONT, "     ver.reg - 0x%lx\n", pcd->spcd_ver_reg));
	SC_DEBUG(1, (CE_CONT, "     afreq   - %d\n", pcd->spcd_afreq));
	switch (pcd->spcd_ptype) {
	case SAFPTYPE_CPU:
		SC_DEBUG(1, (CE_CONT, "     ptype   - CPU\n"));
		break;
	case SAFPTYPE_sPCI:
		SC_DEBUG(1, (CE_CONT, "     ptype   - sPCI\n"));
		break;
	case SAFPTYPE_cPCI:
		SC_DEBUG(1, (CE_CONT, "     ptype   - cPCI\n"));
		break;
	case SAFPTYPE_PCIX:
		SC_DEBUG(1, (CE_CONT, "     ptype   - sPCI+\n"));
		break;
	case SAFPTYPE_WCI:
		SC_DEBUG(1, (CE_CONT, "     ptype   - WIC\n"));
		break;
	default:
		SC_DEBUG(1, (CE_CONT, "     ptype   - 0x%x\n",
		    pcd->spcd_ptype));
		break;
	}
	SC_DEBUG(1, (CE_CONT, "     cache   - %d\n", pcd->spcd_cache));

	if (pcd->spcd_prsv == SPCD_RSV_PASS) {
		SC_DEBUG(1, (CE_CONT, "     prsv    - SPCD_RSV_PASS\n"));
	} else {
		SC_DEBUG(1, (CE_CONT, "     prsv    - 0x%x (FAIL)\n",
		    pcd->spcd_prsv));
	}

	for (i = 0; i < AGENTS_PER_PORT; i++) {
		if (pcd->spcd_agent[i] == SPCD_RSV_PASS) {
			SC_DEBUG(1, (CE_CONT, "     agent[%d]    "
			    "- SPCD_RSV_PASS\n", i));
		} else {
			SC_DEBUG(1, (CE_CONT, "     agent[%d]    "
			    "- 0x%x (FAIL)\n", i, pcd->spcd_agent[i]));
		}
	}

	if (pcd->spcd_ptype == SAFPTYPE_CPU) {
		for (i = 0; i < AGENTS_PER_PORT; i++) {
			SC_DEBUG(1, (CE_CONT, "     cpuid[%d] - 0x%x\n",
			    i, pcd->spcd_cpuid[i]));
		}
	}

	SC_DEBUG(1, (CE_CONT, "     Banks\n"));
	for (i = 0; i < MAX_BANKS_PER_PORT; i++) {
		if (pcd->sprd_bank_rsv[i]) {
			SC_DEBUG(1, (CE_CONT, "       %d %s\n", i,
			    pcd->sprd_bank_rsv[i]));
		}
	}

	SC_DEBUG(1, (CE_CONT, "     Dimms\n"));
	for (i = 0; i < MAX_DIMMS_PER_PORT; i++) {
		if (pcd->sprd_dimm[i]) {
			SC_DEBUG(1, (CE_CONT, "       %d %s\n", i,
			    pcd->sprd_dimm[i]));
		}
	}
	SC_DEBUG(1, (CE_CONT, "     Ecache Dimm Labels\n"));
	for (i = 0; i < MAX_DIMMS_PER_PORT; i++) {
		if (pcd->sprd_ecache_dimm_label[i]) {
			SC_DEBUG(1, (CE_CONT, "       %d %s\n", i,
			    pcd->sprd_ecache_dimm_label[i]));
		}
	}
}


typedef struct {
	char Jnumber[8][8];
	uint8_t sym_flag;
	uint8_t d_dimmtable[144];
	uint8_t d_pintable[576];
}m_layout;

/*
 * Use 2 bits to represent each bit at a cache line. The table
 * is in big endian order, i.e.
 *      dimmtable[0], ... , dimmtable[143]
 * Q0:data-bits[127 126 125 124], ... , MtagEcc[3 2 1 0]
 *                      .
 *                      .
 * Q3:data-bits[127 126 125 124], ... , MtagEcc[3 2 1 0]
 */
uint8_t J_dimm_pinTable[] = {
/* Jnumber */
/*  0 */	0x4a, 0x31, 0x33, 0x33, 0x30, 0x30, 0x00, 0x00,
/*  1 */	0x4a, 0x31, 0x33, 0x34, 0x30, 0x30, 0x00, 0x00,
/*  2 */	0x4a, 0x31, 0x33, 0x35, 0x30, 0x30, 0x00, 0x00,
/*  3 */	0x4a, 0x31, 0x33, 0x36, 0x30, 0x30, 0x00, 0x00,
/*  4 */	0x4a, 0x31, 0x33, 0x33, 0x30, 0x31, 0x00, 0x00,
/*  5 */	0x4a, 0x31, 0x33, 0x34, 0x30, 0x31, 0x00, 0x00,
/*  6 */	0x4a, 0x31, 0x33, 0x35, 0x30, 0x31, 0x00, 0x00,
/*  7 */	0x4a, 0x31, 0x33, 0x36, 0x30, 0x31, 0x00, 0x00,
/* flag */	0x01,
/*  -- Q0 --  */
/*  0 */	0x00, 0x55, 0xaa, 0xff, 0x00, 0x55, 0xaa, 0xff,
/*  1 */	0x00, 0xaa, 0xff, 0x00, 0x56, 0xaf, 0x00, 0x55,
/*  2 */	0xaa, 0x55, 0xaf, 0xc0, 0x55, 0xaa, 0xff, 0x00,
/*  3 */	0x55, 0xff, 0x00, 0x55, 0xaa, 0xff, 0x6d, 0x80,
/*  4 */	0xe7, 0xe3, 0x9b, 0x1b,
/*  -- Q1 --  */
/*  0 */	0x00, 0x55, 0xaa, 0xff, 0x00, 0x55, 0xaa, 0xff,
/*  1 */	0x00, 0xaa, 0xff, 0x00, 0x56, 0xaf, 0x00, 0x55,
/*  2 */	0xaa, 0x55, 0xaf, 0xc0, 0x55, 0xaa, 0xff, 0x00,
/*  3 */	0x55, 0xff, 0x00, 0x55, 0xaa, 0xff, 0x6d, 0x80,
/*  4 */	0xe7, 0xe3, 0x9b, 0x1b,
/*  -- Q2 --  */
/*  0 */	0x00, 0x55, 0xaa, 0xff, 0x00, 0x55, 0xaa, 0xff,
/*  1 */	0x00, 0xaa, 0xff, 0x00, 0x56, 0xaf, 0x00, 0x55,
/*  2 */	0xaa, 0x55, 0xaf, 0xc0, 0x55, 0xaa, 0xff, 0x00,
/*  3 */	0x55, 0xff, 0x00, 0x55, 0xaa, 0xff, 0x6d, 0x80,
/*  4 */	0xe7, 0xe3, 0x9b, 0x1b,
/*  -- Q3 --  */
/*  0 */	0x00, 0x55, 0xaa, 0xff, 0x00, 0x55, 0xaa, 0xff,
/*  1 */	0x00, 0xaa, 0xff, 0x00, 0x56, 0xaf, 0x00, 0x55,
/*  2 */	0xaa, 0x55, 0xaf, 0xc0, 0x55, 0xaa, 0xff, 0x00,
/*  3 */	0x55, 0xff, 0x00, 0x55, 0xaa, 0xff, 0x6d, 0x80,
/*  4 */	0xe7, 0xe3, 0x9b, 0x1b,
/*
 * In the following order
 *      pintable[0], ..., pintable[575]
 * Quadword3, Quadword2, Quadword1, Quadword0
 *      MtagEcc, Mtag, Ecc, Data
 */
/* -- Q3 -- */
/*  0  */	227, 227, 227, 227, 111, 111, 111,  22,
/*  1  */	22,  32, 138, 222,  81, 117, 117, 117,
/*  2  */	111, 222, 106, 222, 222, 106, 106, 106,
/*  3  */	217, 101, 212,  96, 217, 101, 212,  96,
/*  4  */	217, 101, 212,  96, 217, 101, 212,  96,
/*  5  */	207,  91, 202,  86, 187,  71, 158,  42,
/*  6  */	187,  71, 158,  42, 153,  37, 148,  32,
/*  7  */	153,  37, 148,  32, 153,  37, 148,  32,
/*  8  */	153,  37, 148, 143,  27, 138, 143,  27,
/*  9  */	143,  27, 138,  22, 207,  91, 202,  86,
/*  10 */	207,  91, 202,  86, 207,  91, 202,  86,
/*  11 */	192,  76,  81, 192,  76,  81, 192,  76,
/*  12 */	197,  81, 192,  76, 187,  71, 158,  42,
/*  13 */	187,  71, 158,  42, 143,  27, 138,  22,
/*  14 */	133,  17, 128,  12, 133,  17, 128,  12,
/*  15 */	133,  17, 128,  12, 133,  17, 128,  12,
/*  16 */	123,  07, 118,   2, 123,  07, 118,   2,
/*  17 */	123,  07, 118,   2, 123,  07, 118,   2,
/* -- Q2 -- */
/*  0  */	228, 228, 228, 228, 112, 112, 112,  23,
/*  1  */	23,  33, 139, 223,  82, 118, 118, 118,
/*  2  */	112, 223, 107, 223, 223, 107, 107, 107,
/*  3  */	218, 102, 213,  97, 218, 102, 213,  97,
/*  4  */	218, 102, 213,  97, 218, 102, 213,  97,
/*  5  */	208,  92, 203,  87, 188,  72, 159,  43,
/*  6  */	188,  72, 159,  43, 154,  38, 149,  33,
/*  7  */	154,  38, 149,  33, 154,  38, 149,  33,
/*  8  */	154,  38, 149, 144,  28, 139, 144,  28,
/*  9  */	144,  28, 139,  23, 208,  92, 203,  87,
/*  10 */	208,  92, 203,  87, 208,  92, 203,  87,
/*  11 */	193,  77,  82, 193,  77,  82, 193,  77,
/*  12 */	198,  82, 193,  77, 188,  72, 159,  43,
/*  13 */	188,  72, 159,  43, 144,  28, 139,  23,
/*  14 */	134,  18, 129,  13, 134,  18, 129,  13,
/*  15 */	134,  18, 129,  13, 134,  18, 129,  13,
/*  16 */	124,   8, 119,   3, 124,   8, 119,   3,
/*  17 */	124,   8, 119,   3, 124,   8, 119,   3,
/* -- Q1 -- */
/*  0  */	229, 229, 229, 229, 113, 113, 113,  24,
/*  1  */	24,  34, 140, 224,  83, 119, 119, 119,
/*  2  */	113, 224, 108, 224, 224, 108, 108, 108,
/*  3  */	219, 103, 214,  98, 219, 103, 214,  98,
/*  4  */	219, 103, 214,  98, 219, 103, 214,  98,
/*  5  */	209,  93, 204,  88, 189,  73, 160,  44,
/*  6  */	189,  73, 160,  44, 155,  39, 150,  34,
/*  7  */	155,  39, 150,  34, 155,  39, 150,  34,
/*  8  */	155,  39, 150, 145,  29, 140, 145,  29,
/*  9  */	145,  29, 140,  24, 209,  93, 204,  88,
/*  10 */	209,  93, 204,  88, 209,  93, 204,  88,
/*  11 */	194,  78,  83, 194,  78,  83, 194,  78,
/*  12 */	199,  83, 194,  78, 189,  73, 160,  44,
/*  13 */	189,  73, 160,  44, 145,  29, 140,  24,
/*  14 */	135,  19, 130,  14, 135,  19, 130,  14,
/*  15 */	135,  19, 130,  14, 135,  19, 130,  14,
/*  16 */	125,   9, 120,   4, 125,   9, 120,   4,
/*  17 */	125,   9, 120,   4, 125,   9, 120,   4,
/* -- Q0 -- */
/*  0  */	230, 230, 230, 230, 114, 114, 114,  25,
/*  1  */	25,  35, 141, 225,  84, 200, 200, 200,
/*  2  */	114, 225, 109, 225, 225, 109, 109, 109,
/*  3  */	220, 104, 215,  99, 220, 104, 215,  99,
/*  4  */	220, 104, 215,  99, 220, 104, 215,  99,
/*  5  */	210,  94, 205,  89, 190,  74, 161,  45,
/*  6  */	190,  74, 161,  45, 156,  40, 151,  35,
/*  7  */	156,  40, 151,  35, 156,  40, 151,  35,
/*  8  */	156,  40, 151, 146,  30, 141, 146,  30,
/*  9  */	146,  30, 141,  25, 210,  94, 205,  89,
/*  10 */	210,  94, 205,  89, 210,  94, 205,  89,
/*  11 */	195,  79,  84, 195,  79,  84, 195,  79,
/*  12 */	200,  84, 195,  79, 190,  74, 161,  45,
/*  13 */	190,  74, 161,  45, 146,  30, 141,  25,
/*  14 */	136,  20, 131,  15, 136,  20, 131,  15,
/*  15 */	136,  20, 131,  15, 136,  20, 131,  15,
/*  16 */	126,  10, 121,   5, 126,  10, 121,   5,
/*  17 */	126,  10, 121,   5, 126,  10, 121,   5
};

/*
 *  This table is for internal reference
 *
 * pintable_internal[]= {
 * -- Q0 --
 * 0  143,143,143,143,139,139,139,35
 * 1  35,51,39,135,91,95,95,95
 * 2  139,135,131,135,135,131,131,131
 * 3  127,123,119,115,127,123,119,115
 * 4  127,123,119,115,127,123,119,115
 * 5  111,107,103,99,79,75,71,67
 * 6  79,75,71,67,63,59,55,51
 * 7  63,59,55,51,63,59,55,51
 * 8  63,59,55,47,43,39,47,43
 * 9  47,43,39,35,111,107,103,99
 * 10  111,107,103,99,111,107,103,99
 * 11  87,83,91,87,83,91,87,83
 * 12  95,91,87,83,79,75,71,67
 * 13  79,75,71,67,47,43,39,35
 * 14  31,27,23,19,31,27,23,19
 * 15  31,27,23,19,31,27,23,19
 * 16  15,11,7,3,15,11,7,3
 * 17  15,11,7,3,15,11,7,3
 * }
 */

char *dimm_Jno[] = {
/* P0 */	"J13300", "J13400", "J13500", "J13600",
		"J13301", "J13401", "J13501", "J13601",
/* P1 */	"J14300", "J14400", "J14500", "J14600",
		"J14301", "J14401", "J14501", "J14601",
/* P2 */	"J15300", "J15400", "J15500", "J15600",
		"J15301", "J15401", "J15501", "J15601",
/* P3 */	"J16300", "J16400", "J16500", "J16600",
		"J16301", "J16401", "J16501", "J16601",
		NULL
	};


static uint8_t *
get_memlayout(uint32_t cpuid, uint32_t *len)
{
	m_layout *LayoutBuf;

	if ((LayoutBuf = (m_layout *)kmem_zalloc(sizeof (m_layout),
	    KM_SLEEP)) == NULL) {
		*len = 0;
		return (NULL);
	}

	bcopy(J_dimm_pinTable, LayoutBuf, sizeof (m_layout));

	*len = sizeof (m_layout);
	cpuid &= 0x03;	/* last 2 bits of a 10 bit number */

	bcopy(dimm_Jno[cpuid << 3], LayoutBuf->Jnumber[0], 64);

	return ((uint8_t *)LayoutBuf);
}

static char *
rsv_string(prdrsv_t rsv)
{
	char *buffer;
	char *status;

	switch (rsv) {
	case RSV_UNKNOWN:
		buffer = "unknown";
		break;
	case RSV_PRESENT:
		buffer = "okay";
		break;
	case RSV_CRUNCH:
		buffer = "disabled";
		break;
	case RSV_UNDEFINED:
		buffer = "undefined";
		break;
	case RSV_MISS:
		buffer = "missing";
		break;
	case RSV_EMPTY_CASSETTE:
		buffer = "disabled";
		break;
	case RSV_MISCONFIG:
		buffer = "misconfigured";
		break;
	case RSV_FAIL_OBP:
		buffer = "fail-obp";
		break;
	case RSV_BLACK:
		buffer = "blacklisted";
		break;
	case RSV_RED:
		buffer = "redlisted";
		break;
	case RSV_EXCLUDED:
		buffer = "disabled";
		break;
	case RSV_UNCONFIG:
		buffer = "disabled";
		break;
	case RSV_PASS:
		buffer = "okay";
		break;
	case RSV_FAIL:
	default:
		buffer = "fail";
		break;
	}

	status = kmem_alloc(strlen(buffer) + 1, KM_SLEEP);
	(void) strcpy(status, buffer);

	return (status);
}
