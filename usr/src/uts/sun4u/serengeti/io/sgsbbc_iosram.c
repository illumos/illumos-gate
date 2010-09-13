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
 * Driver for handling Serengeti I/O SRAM
 * for Solaris <-> SC comm.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/dditypes.h>
#include <sys/sunndi.h>
#include <sys/param.h>
#include <sys/mutex.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/sunddi.h>
#include <sys/ddi.h>

#include <sys/serengeti.h>
#include <sys/sgsbbc_priv.h>
#include <sys/sgsbbc_iosram_priv.h>
#include <sys/sgsbbc_mailbox_priv.h>

/*
 * Local stuff
 */
static int iosram_rw(int, uint32_t, caddr_t, uint32_t, int);
static int iosram_convert_key(char *);
static int iosram_switch_intr(void);
static int tunnel_init(sbbc_softstate_t *, tunnel_t *);
static void tunnel_fini(tunnel_t *);
static void tunnel_commit(sbbc_softstate_t *, tunnel_t *);
static void clear_break();

#define	IOSRAM_GETB(tunnel, buf, sram, count) \
	ddi_rep_get8(tunnel->reg_handle, buf, sram, count, DDI_DEV_AUTOINCR)

#define	IOSRAM_PUTB(tunnel, buf, sram, count) \
	ddi_rep_put8(tunnel->reg_handle, buf, sram, count, DDI_DEV_AUTOINCR)

#define	IOSRAM_PUT(tunnel, sram, buf, size) \
	/* CSTYLED */ \
	ddi_put##size(tunnel->reg_handle, (uint##size##_t *)sram, \
	/* CSTYLED */ \
	*((uint##size##_t *)buf))

#define	IOSRAM_GET(tunnel, sram, buf, size) \
	/* CSTYLED */ \
	*(uint##size##_t *)buf = ddi_get##size(tunnel->reg_handle, \
	/* CSTYLED */ \
	(uint##size##_t *)sram)

/*
 * sgsbbc_iosram_is_chosen(struct sbbc_softstate *softsp)
 *
 *      Looks up "chosen" node property to
 *      determine if it is the chosen IOSRAM.
 */
int
sgsbbc_iosram_is_chosen(sbbc_softstate_t *softsp)
{
	char		pn[MAXNAMELEN];
	char		chosen_iosram[MAXNAMELEN];
	int		nodeid;
	int		chosen;
	uint_t		tunnel;
	extern		pnode_t chosen_nodeid;

	ASSERT(chosen_nodeid);

	nodeid = chosen_nodeid;
	(void) prom_getprop(nodeid, "iosram", (caddr_t)&tunnel);

	/*
	 * get the full OBP pathname of this node
	 */
	if (prom_phandle_to_path((phandle_t)tunnel, chosen_iosram,
		sizeof (chosen_iosram)) < 0) {
		cmn_err(CE_NOTE, "prom_phandle_to_path(%x) failed\n", tunnel);
		return (0);
	}

	SGSBBC_DBG_ALL("sgsbbc_iosram(%d): prom_phandle_to_path(%x) is '%s'\n",
	softsp->sbbc_instance, nodeid, chosen_iosram);

	(void) ddi_pathname(softsp->dip, pn);
	SGSBBC_DBG_ALL("sgsbbc_iosram(%d): ddi_pathname(%p) is '%s'\n",
	    softsp->sbbc_instance, (void *)softsp->dip, pn);

	chosen = (strcmp(chosen_iosram, pn) == 0) ? 1 : 0;
	SGSBBC_DBG_ALL("sgsbbc_iosram(%d): ... %s\n", softsp->sbbc_instance,
	    chosen? "MASTER" : "SLAVE");
	SGSBBC_DBG_ALL("sgsbbc_iosram(%d): ... %s\n", softsp->sbbc_instance,
	    (chosen ? "MASTER" : "SLAVE"));

	return (chosen);
}

void
iosram_init()
{
	int	i;

	if ((master_iosram = kmem_zalloc(sizeof (struct chosen_iosram),
	    KM_NOSLEEP)) == NULL) {
		prom_printf("Can't allocate space for Chosen IOSRAM\n");
		panic("Can't allocate space for Chosen IOSRAM");
	}

	if ((master_iosram->tunnel = kmem_zalloc(sizeof (tunnel_t),
	    KM_NOSLEEP)) == NULL) {
		prom_printf("Can't allocate space for tunnel\n");
		panic("Can't allocate space for tunnel");
	}

	master_iosram->iosram_sbbc = NULL;

	for (i = 0; i < SBBC_MAX_KEYS; i++) {
		master_iosram->tunnel->tunnel_keys[i].key = 0;
		master_iosram->tunnel->tunnel_keys[i].base = NULL;
		master_iosram->tunnel->tunnel_keys[i].size = 0;
	}

	for (i = 0; i < SBBC_MAX_INTRS; i++)
		master_iosram->intrs[i].sbbc_handler = NULL;

	mutex_init(&master_iosram->iosram_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&master_iosram->tunnel_lock, NULL, RW_DEFAULT, NULL);
}
void
iosram_fini()
{
	struct	tunnel_key	*tunnel;
	int			i;

	rw_destroy(&master_iosram->tunnel_lock);
	mutex_destroy(&master_iosram->iosram_lock);

	/*
	 * destroy any tunnel maps
	 */
	for (i = 0; i < SBBC_MAX_KEYS; i++) {
		tunnel = &master_iosram->tunnel->tunnel_keys[i];
		if (tunnel->base != NULL) {
			ddi_regs_map_free(&tunnel->reg_handle);
			tunnel->base = NULL;
		}
	}

	kmem_free(master_iosram->tunnel, sizeof (tunnel_t));

	kmem_free(master_iosram, sizeof (struct chosen_iosram));

	master_iosram = NULL;
}

static void
check_iosram_ver(uint16_t version)
{
	uint8_t	max_ver = MAX_IOSRAM_TOC_VER;
	uint8_t	major_ver =
		(version >> IOSRAM_TOC_VER_SHIFT) & IOSRAM_TOC_VER_MASK;

	SGSBBC_DBG_ALL("IOSRAM TOC version: %d.%d\n", major_ver,
		version & IOSRAM_TOC_VER_MASK);
	SGSBBC_DBG_ALL("Max supported IOSRAM TOC version: %d\n", max_ver);
	if (major_ver > max_ver) {
		panic("Up-rev System Controller version.\n"
		    "You must restore an earlier revision of System "
		    "Controller firmware, or upgrade Solaris.\n"
		    "Please consult the System Controller release notice "
		    "for additional details.");
	}
}

static void
tunnel_commit(sbbc_softstate_t *softsp, tunnel_t *new_tunnel)
{
	ASSERT(MUTEX_HELD(&master_iosram->iosram_lock));

	master_iosram->iosram_sbbc = softsp;
	master_iosram->tunnel = new_tunnel;
	softsp->chosen = TRUE;

	/*
	 * SBBC has pointer to interrupt handlers for simplicity
	 */
	softsp->intr_hdlrs = master_iosram->intrs;
}

static int
tunnel_init(sbbc_softstate_t *softsp, tunnel_t *new_tunnel)
{
	struct iosram_toc		*toc = NULL;
	int				i, key;
	struct	tunnel_key		*tunnel;
	ddi_acc_handle_t		toc_handle;
	struct ddi_device_acc_attr	attr;

	ASSERT(MUTEX_HELD(&master_iosram->iosram_lock));

	if ((softsp == (sbbc_softstate_t *)NULL) ||
		(new_tunnel == (tunnel_t *)NULL)) {

		return (DDI_FAILURE);
	}

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	SGSBBC_DBG_ALL("map in the IOSRAM TOC at offset %x\n",
		softsp->sram_toc);

	/*
	 * First map in the TOC, then set up the tunnel
	 */
	if (ddi_regs_map_setup(softsp->dip, RNUM_SBBC_REGS,
		(caddr_t *)&toc,
		SBBC_SRAM_OFFSET + softsp->sram_toc,
		sizeof (struct iosram_toc),
		&attr, &toc_handle) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "sbbc%d: unable to map SRAM "
			    "registers", ddi_get_instance(softsp->dip));
			return (DDI_FAILURE);
	}
	SGSBBC_DBG_ALL("dip=%p mapped TOC %p\n", (void *)softsp->dip,
	    (void *)toc);

	check_iosram_ver(toc->iosram_version);

	for (i = 0; i < toc->iosram_tagno; i++) {
		key = iosram_convert_key(toc->iosram_keys[i].key);
		if ((key > 0) && (key < SBBC_MAX_KEYS)) {
			tunnel = &new_tunnel->tunnel_keys[key];
			tunnel->key = key;
			tunnel->size = toc->iosram_keys[i].size;
			/*
			 * map in the SRAM area using the offset
			 * from the base of SRAM + SRAM offset into
			 * the register property for the SBBC base
			 * address
			 */
			if (ddi_regs_map_setup(softsp->dip, RNUM_SBBC_REGS,
				(caddr_t *)&tunnel->base,
				SBBC_SRAM_OFFSET + toc->iosram_keys[i].offset,
				toc->iosram_keys[i].size, &attr,
				&tunnel->reg_handle) != DDI_SUCCESS) {
				cmn_err(CE_WARN, "sbbc%d: unable to map SRAM "
				    "registers", ddi_get_instance(softsp->dip));
				return (DDI_FAILURE);
			}
			SGSBBC_DBG_ALL("%d: key %s size %d offset %x addr %p\n",
			    i, toc->iosram_keys[i].key,
			    toc->iosram_keys[i].size,
			    toc->iosram_keys[i].offset,
			    (void *)tunnel->base);

		}
	}


	if (toc != NULL) {
		ddi_regs_map_free(&toc_handle);
	}

	/*
	 * Set up the 'interrupt reason' SRAM pointers
	 * for the SBBC interrupt handler
	 */
	if (INVALID_KEY(new_tunnel, SBBC_SC_INTR_KEY)) {
		/*
		 * Can't really do much if these are not here
		 */
		prom_printf("No Interrupt Reason Fields set by SC\n");
		cmn_err(CE_WARN, "No Interrupt Reason Fields set by SC");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Unmap a tunnel
 */
static void
tunnel_fini(tunnel_t *tunnel)
{
	int	i;
	struct	tunnel_key	*tunnel_key;

	/*
	 * Unmap the tunnel
	 */
	for (i = 0; i < SBBC_MAX_KEYS; i++) {
		tunnel_key = &tunnel->tunnel_keys[i];
		if (tunnel_key->base != NULL) {
			ddi_regs_map_free(&tunnel_key->reg_handle);
			tunnel_key->base = NULL;
		}
	}
}

static void
clear_break()
{
	struct tunnel_key	tunnel_key;
	uint32_t		*intr_in_reason;
	ddi_acc_handle_t	intr_in_handle;

	ASSERT(MUTEX_HELD(&master_iosram->iosram_lock));

	tunnel_key = master_iosram->tunnel->tunnel_keys[SBBC_SC_INTR_KEY];
	intr_in_reason = (uint32_t *)tunnel_key.base;
	intr_in_handle = tunnel_key.reg_handle;
	ddi_put32(intr_in_handle, intr_in_reason,
		ddi_get32(intr_in_handle, intr_in_reason) & ~SBBC_CONSOLE_BRK);
}

int
iosram_tunnel_init(sbbc_softstate_t *softsp)
{
	int	rc;

	ASSERT(master_iosram);

	mutex_enter(&master_iosram->iosram_lock);

	if ((rc = tunnel_init(softsp, master_iosram->tunnel)) == DDI_SUCCESS) {
		tunnel_commit(softsp, master_iosram->tunnel);
		clear_break();
	}


	mutex_exit(&master_iosram->iosram_lock);

	return (rc);
}

int
iosram_read(int key, uint32_t offset, caddr_t buf, uint32_t size)
{
	return (iosram_rw(key, offset, buf, size, FREAD));
}

int
iosram_write(int key, uint32_t offset, caddr_t buf, uint32_t size)
{
	return (iosram_rw(key, offset, buf, size, FWRITE));
}


static int
iosram_rw(int key, uint32_t offset, caddr_t buf, uint32_t size, int flag)
{
	struct	tunnel_key	*tunnel;
	caddr_t 		sram_src;

	/*
	 * Return right away if there is nothing to read/write.
	 */
	if (size == 0)
		return (0);

	rw_enter(&master_iosram->tunnel_lock, RW_READER);

	/*
	 * Key not matched ?
	 */
	if (INVALID_KEY(master_iosram->tunnel, key)) {
		rw_exit(&master_iosram->tunnel_lock);
		return (ENXIO);
	}

	tunnel = &master_iosram->tunnel->tunnel_keys[key];
	if ((offset + size) > tunnel->size) {
		rw_exit(&master_iosram->tunnel_lock);
		return (EFBIG);
	}

	sram_src = tunnel->base + offset;

	/*
	 * Atomic reads/writes might be necessary for some clients.
	 * We assume that such clients could guarantee their buffers
	 * are aligned at the boundary of the request sizes.  We also
	 * assume that the source/destination of such requests are
	 * aligned at the right boundaries in IOSRAM.  If either
	 * condition fails, byte access is performed.
	 */
	if (flag == FREAD) {
		switch (size) {
		case sizeof (uint16_t):
		case sizeof (uint32_t):
		case sizeof (uint64_t):
			if (IS_P2ALIGNED(sram_src, size) &&
				IS_P2ALIGNED(buf, size)) {

				if (size == sizeof (uint16_t))
					IOSRAM_GET(tunnel, sram_src, buf, 16);
				else if (size == sizeof (uint32_t))
					IOSRAM_GET(tunnel, sram_src, buf, 32);
				else
					IOSRAM_GET(tunnel, sram_src, buf, 64);
				break;
			}
			/* FALLTHRU */
		default:
			IOSRAM_GETB(tunnel, (uint8_t *)buf,
				(uint8_t *)sram_src, (size_t)size);
			break;
		}
	} else {
		switch (size) {
		case sizeof (uint16_t):
		case sizeof (uint32_t):
		case sizeof (uint64_t):
			if (IS_P2ALIGNED(sram_src, size) &&
				IS_P2ALIGNED(buf, size)) {

				if (size == sizeof (uint16_t))
					IOSRAM_PUT(tunnel, sram_src, buf, 16);
				else if (size == sizeof (uint32_t))
					IOSRAM_PUT(tunnel, sram_src, buf, 32);
				else
					IOSRAM_PUT(tunnel, sram_src, buf, 64);
				break;
			}
			/* FALLTHRU */
		default:
			IOSRAM_PUTB(tunnel, (uint8_t *)buf,
				(uint8_t *)sram_src, (size_t)size);
			break;
		}
	}

	rw_exit(&master_iosram->tunnel_lock);
	return (0);

}

int
iosram_size(int key)
{
	int size = -1;

	rw_enter(&master_iosram->tunnel_lock, RW_READER);

	/*
	 * Key not matched ?
	 */
	if (!INVALID_KEY(master_iosram->tunnel, key))
		size = master_iosram->tunnel->tunnel_keys[key].size;

	rw_exit(&master_iosram->tunnel_lock);

	return (size);
}

/*
 * Generate an interrupt to the SC using the SBBC EPLD
 *
 * Note: intr_num can be multiple interrupts OR'ed together
 */
int
iosram_send_intr(uint32_t intr_num)
{

	int		rc = 0;
	uint32_t	intr_reason;
	uint32_t	intr_enabled;

	/*
	 * Verify that we have already set up the master sbbc
	 */
	if (master_iosram == NULL)
		return (ENXIO);

	/*
	 * Grab the lock to prevent tunnel switch in the middle
	 * of sending an interrupt.
	 */
	mutex_enter(&master_iosram->iosram_lock);

	if (master_iosram->iosram_sbbc == NULL) {
		rc = ENXIO;
		goto send_intr_exit;
	}

	if ((rc = sbbc_send_intr(master_iosram->iosram_sbbc, FALSE)) != 0) {
		/*
		 * previous interrupts have not been cleared yet by the SC
		 */
		goto send_intr_exit;
	}

	/*
	 * Set a bit in the interrupt reason field
	 * call back into the sbbc handler to hit the EPLD
	 *
	 * First check the interrupts enabled by the SC
	 */
	if ((rc = iosram_read(SBBC_INTR_SC_ENABLED_KEY, 0,
		(caddr_t)&intr_enabled, sizeof (intr_enabled))) != 0) {

		goto send_intr_exit;
	}

	if ((intr_enabled & intr_num) != intr_num) {
		/*
		 * at least one of the interrupts is
		 * not enabled by the SC
		 */
		rc = ENOTSUP;
		goto send_intr_exit;
	}

	if ((rc = iosram_read(SBBC_INTR_SC_KEY, 0,
		(caddr_t)&intr_reason, sizeof (intr_reason))) != 0) {

		goto send_intr_exit;
	}

	if ((intr_reason & intr_num) == intr_num) {
		/*
		 * All interrupts specified are already pending
		 */
		rc = EBUSY;
		goto send_intr_exit;
	}

	intr_reason |= intr_num;

	if ((rc = iosram_write(SBBC_INTR_SC_KEY, 0,
		(caddr_t)&intr_reason, sizeof (intr_reason))) != 0) {

		goto send_intr_exit;
	}

	/*
	 * Hit the EPLD interrupt bit
	 */

	rc = sbbc_send_intr(master_iosram->iosram_sbbc, TRUE);

send_intr_exit:

	mutex_exit(&master_iosram->iosram_lock);

	return (rc);
}

/*
 * Register an interrupt handler
 */
int
iosram_reg_intr(uint32_t intr_num, sbbc_intrfunc_t intr_handler,
		caddr_t arg, uint_t *state, kmutex_t *lock)
{
	sbbc_softstate_t	*softsp;
	int			rc = 0;
	sbbc_intrs_t		*intr;
	int			intr_no;
	uint32_t		intr_enabled;

	/*
	 * Verify that we have already set up the master sbbc
	 */
	if (master_iosram == NULL)
		return (ENXIO);

	/*
	 * determine which bit is this intr_num for ?
	 */
	for (intr_no = 0; intr_no < SBBC_MAX_INTRS; intr_no++) {
		if (intr_num == (1 << intr_no))
			break;
	}

	/*
	 * Check the parameters
	 */
	if ((intr_no < 0) || (intr_no >= SBBC_MAX_INTRS) ||
		(intr_handler == NULL) || (state == NULL) ||
		(lock == NULL))
		return (EINVAL);

	mutex_enter(&master_iosram->iosram_lock);

	if ((softsp = master_iosram->iosram_sbbc) == NULL) {
		mutex_exit(&master_iosram->iosram_lock);
		return (ENXIO);
	}

	mutex_enter(&softsp->sbbc_lock);

	intr = &master_iosram->intrs[intr_no];

	if (intr->sbbc_handler != (sbbc_intrfunc_t)NULL) {
		rc = EBUSY;
		goto reg_intr_exit;
	}

	intr->sbbc_handler  = intr_handler;
	intr->sbbc_arg = (void *)arg;
	intr->sbbc_intr_state = state;
	intr->sbbc_intr_lock = lock;
	intr->sbbc_intr_next = (sbbc_intrs_t *)NULL;

	/*
	 * we need to make sure that the mutex is for
	 * an ADAPTIVE lock, so call mutex_init() again with
	 * the sbbc iblock cookie
	 */
	mutex_init(lock, NULL, MUTEX_DRIVER,
		(void *)softsp->iblock);

	if (ddi_add_softintr(softsp->dip, DDI_SOFTINT_HIGH,
		&intr->sbbc_intr_id, NULL, NULL,
		intr_handler, (caddr_t)arg) != DDI_SUCCESS) {

		cmn_err(CE_WARN, "Can't add SBBC softint");
		rc = EAGAIN;
		goto reg_intr_exit;
	}

	/*
	 * Set the bit in the Interrupts Enabled Field for this
	 * interrupt
	 */
	if ((rc = iosram_read(SBBC_SC_INTR_ENABLED_KEY, 0,
		(caddr_t)&intr_enabled, sizeof (intr_enabled))) != 0) {

		goto reg_intr_exit;
	}

	intr_enabled |= intr_num;

	if ((rc = iosram_write(SBBC_SC_INTR_ENABLED_KEY, 0,
		(caddr_t)&intr_enabled, sizeof (intr_enabled))) != 0) {

		goto reg_intr_exit;
	}

reg_intr_exit:

	mutex_exit(&softsp->sbbc_lock);
	mutex_exit(&master_iosram->iosram_lock);

	return (rc);
}

/*
 * Remove an interrupt handler
 */
int
iosram_unreg_intr(uint32_t intr_num)
{
	sbbc_softstate_t	*softsp;
	int			rc = 0;
	sbbc_intrs_t		*intr;
	int			intr_no;
	uint32_t		intr_enabled;

	/*
	 * Verify that we have already set up the master sbbc
	 */
	if (master_iosram == NULL)
		return (ENXIO);

	/*
	 * determine which bit is this intr_num for ?
	 */
	for (intr_no = 0; intr_no < SBBC_MAX_INTRS; intr_no++) {
		if (intr_num == (1 << intr_no))
			break;
	}

	if ((intr_no < 0) || (intr_no >= SBBC_MAX_INTRS))
		return (EINVAL);

	mutex_enter(&master_iosram->iosram_lock);

	if ((softsp = master_iosram->iosram_sbbc) == NULL) {
		mutex_exit(&master_iosram->iosram_lock);
		return (ENXIO);
	}

	mutex_enter(&softsp->sbbc_lock);

	intr = &master_iosram->intrs[intr_no];

	/*
	 * No handler installed
	 */
	if (intr->sbbc_handler == (sbbc_intrfunc_t)NULL) {
		rc = EINVAL;
		goto unreg_intr_exit;
	}

	/*
	 * Unset the bit in the Interrupts Enabled Field for this
	 * interrupt
	 */
	if ((rc = iosram_read(SBBC_SC_INTR_ENABLED_KEY, 0,
		(caddr_t)&intr_enabled, sizeof (intr_enabled))) != 0) {

		goto unreg_intr_exit;
	}

	intr_enabled &= ~intr_num;

	if ((rc = iosram_write(SBBC_SC_INTR_ENABLED_KEY, 0,
		(caddr_t)&intr_enabled, sizeof (intr_enabled))) != 0) {

		goto unreg_intr_exit;
	}

	/*
	 * If handler is running, wait until it's done.
	 * It won't get triggered again because we disabled it above.
	 * When we wait, drop sbbc_lock so other interrupt handlers
	 * can still run.
	 */
	for (; ; ) {
		mutex_enter(intr->sbbc_intr_lock);
		if (*(intr->sbbc_intr_state) != SBBC_INTR_IDLE) {
			mutex_exit(intr->sbbc_intr_lock);
			mutex_exit(&softsp->sbbc_lock);
			delay(drv_usectohz(10000));
			mutex_enter(&softsp->sbbc_lock);
			mutex_enter(intr->sbbc_intr_lock);
		} else {
			break;
		}
		mutex_exit(intr->sbbc_intr_lock);
	}

	if (intr->sbbc_intr_id)
		ddi_remove_softintr(intr->sbbc_intr_id);

	intr->sbbc_handler  = (sbbc_intrfunc_t)NULL;
	intr->sbbc_arg = (void *)NULL;
	intr->sbbc_intr_id = 0;
	intr->sbbc_intr_state = NULL;
	intr->sbbc_intr_lock = (kmutex_t *)NULL;
	intr->sbbc_intr_next = (sbbc_intrs_t *)NULL;

unreg_intr_exit:

	mutex_exit(&softsp->sbbc_lock);
	mutex_exit(&master_iosram->iosram_lock);

	return (rc);
}

/*
 * sgsbbc_iosram_switchfrom(softsp)
 *      Switch master tunnel away from the specified instance.
 */
int
sgsbbc_iosram_switchfrom(struct sbbc_softstate *softsp)
{
	struct sbbc_softstate	*sp;
	int			rv = DDI_FAILURE;
	int			new_instance;

	/*
	 * Find the candidate target of tunnel from the linked list.
	 */
	mutex_enter(&chosen_lock);
	ASSERT(sgsbbc_instances);

	for (sp = sgsbbc_instances; sp != NULL; sp = sp->next) {
		if (softsp == sp)
			continue;

		if (sp->sbbc_state & SBBC_STATE_DETACH)
			continue;
		break;
	}
	if (sp == NULL) {
		/* at least one IOSRAM should be attached */
		rv = DDI_FAILURE;
	} else {
		/* Do the tunnel switch */
		new_instance = ddi_get_instance(sp->dip);
		rv = iosram_switch_tunnel(new_instance);
		if (rv == DDI_SUCCESS) {
			/* reset the chosen_iosram back ref */
			sp->iosram = master_iosram;
		}
	}
	mutex_exit(&chosen_lock);
	return (rv);
}


/*
 * Switch the tunnel to a different I/O board.
 * At the moment, we will say that this is
 * called with the instance of the SBBC to switch
 * to. This will probably change, but as long as we
 * can get a devinfo/softstate for the target SBBC it
 * doesn't matter what the parameter is.
 */
int
iosram_switch_tunnel(int instance)
{

	sbbc_softstate_t	*to_softsp, *from_softsp;
	dev_info_t		*pdip;	/* parent dip */
	tunnel_t		*new_tunnel; /* new tunnel */
	int			portid;
	uint_t			node;	/* node id to pass to OBP */
	uint_t			board;	/* board number to pass to OBP */
	int			rc = DDI_SUCCESS;
	static fn_t		f = "iosram_switch_tunnel";

	/* Check the firmware for tunnel switch support */
	if (prom_test("SUNW,switch-tunnel") != 0) {
		cmn_err(CE_WARN, "Firmware does not support tunnel switch");
		return (DDI_FAILURE);
	}

	if ((master_iosram == NULL) || (master_mbox == NULL))
		return (DDI_FAILURE);

	if (!(to_softsp = sbbc_get_soft_state(instance)))
		return (DDI_FAILURE);

	/*
	 * create the new tunnel
	 */
	if ((new_tunnel = kmem_zalloc(sizeof (tunnel_t), KM_NOSLEEP)) == NULL) {
		cmn_err(CE_WARN, "Can't allocate space for new tunnel");
		return (DDI_FAILURE);
	}

	pdip = ddi_get_parent(to_softsp->dip);
	if ((portid = ddi_getprop(DDI_DEV_T_ANY, pdip, DDI_PROP_DONTPASS,
		"portid", -1)) < 0) {

		SGSBBC_DBG_ALL("%s: couldn't get portid\n", f);
		return (DDI_FAILURE);
	}

	/*
	 * Compute node id and board number from port id
	 */
	node	= SG_PORTID_TO_NODEID(portid);
	board	= SG_IO_BD_PORTID_TO_BD_NUM(portid);

	/*
	 * lock the chosen IOSRAM
	 */
	mutex_enter(&master_iosram->iosram_lock);

	if (master_iosram->iosram_sbbc == NULL) {
		mutex_exit(&master_iosram->iosram_lock);
		return (DDI_FAILURE);
	}

	/*
	 * If the target SBBC has not mapped in its
	 * register address space, do it now
	 */
	mutex_enter(&to_softsp->sbbc_lock);
	if (to_softsp->sbbc_regs == NULL) {
		if (sbbc_map_regs(to_softsp) != DDI_SUCCESS) {
			mutex_exit(&to_softsp->sbbc_lock);
			mutex_exit(&master_iosram->iosram_lock);
			return (DDI_FAILURE);
		}
	}

	/*
	 * Get a pointer to the current sbbc
	 */
	from_softsp = master_iosram->iosram_sbbc;

	mutex_enter(&from_softsp->sbbc_lock);

	/*
	 * Disable interrupts from the SC now
	 */
	sbbc_disable_intr(from_softsp);

	/*
	 * move SC interrupts to the new tunnel
	 */
	if ((rc = sbbc_add_intr(to_softsp)) == DDI_FAILURE) {
		cmn_err(CE_WARN, "Failed to add new interrupt handler");
	} else if ((rc = tunnel_init(to_softsp, new_tunnel)) == DDI_FAILURE) {
		cmn_err(CE_WARN, "Failed to initialize new tunnel");
		ddi_remove_intr(to_softsp->dip, 0, to_softsp->iblock);
	} else {
		rw_enter(&master_iosram->tunnel_lock, RW_WRITER);

		/*
		 * If OBP switch is unsuccessful, abort the switch.
		 */
		if ((rc = prom_serengeti_tunnel_switch(node, board))
			!= DDI_SUCCESS) {

			/*
			 * Restart other CPUs.
			 */
			rw_exit(&master_iosram->tunnel_lock);

			cmn_err(CE_WARN, "OBP failed to switch tunnel");

			/*
			 * Remove interrupt
			 */
			ddi_remove_intr(to_softsp->dip, 0, to_softsp->iblock);

			/*
			 * Unmap new tunnel
			 */
			tunnel_fini(new_tunnel);
		} else {
			tunnel_t		*orig_tunnel;

			orig_tunnel = master_iosram->tunnel;
			tunnel_commit(to_softsp, new_tunnel);

			rw_exit(&master_iosram->tunnel_lock);

			/*
			 * Remove interrupt from original softsp
			 */
			ddi_remove_intr(from_softsp->dip, 0,
			    from_softsp->iblock);
			/*
			 * Unmap original tunnel
			 */
			tunnel_fini(orig_tunnel);
			kmem_free(orig_tunnel, sizeof (tunnel_t));

			/*
			 * Move the softintrs to the new dip.
			 */
			(void) iosram_switch_intr();
			(void) sbbc_mbox_switch(to_softsp);

			from_softsp->chosen = FALSE;

		}
	}

	/*
	 * Enable interrupt.
	 */
	sbbc_enable_intr(master_iosram->iosram_sbbc);

	/*
	 * Unlock and get out
	 */
	mutex_exit(&from_softsp->sbbc_lock);
	mutex_exit(&to_softsp->sbbc_lock);
	mutex_exit(&master_iosram->iosram_lock);

	/*
	 * Call the interrupt handler directly in case
	 * we have missed an interrupt
	 */
	(void) sbbc_intr_handler((caddr_t)master_iosram->iosram_sbbc);

	if (rc != DDI_SUCCESS) {
		/*
		 * Free up the new_tunnel
		 */
		kmem_free(new_tunnel, sizeof (tunnel_t));
		cmn_err(CE_WARN, "Tunnel switch failed");
	}

	return (rc);

}

/*
 * convert an alphanumeric OBP key to
 * our defined numeric keys
 */
static int
iosram_convert_key(char *toc_key)
{

	if (strcmp(toc_key, TOCKEY_DOMSTAT)  == 0)
		return (SBBC_DOMAIN_KEY);
	if (strcmp(toc_key, TOCKEY_KEYSWPO)  == 0)
		return (SBBC_KEYSWITCH_KEY);
	if (strcmp(toc_key, TOCKEY_TODDATA)  == 0)
		return (SBBC_TOD_KEY);
	if (strcmp(toc_key, TOCKEY_SOLCONS) == 0)
		return (SBBC_CONSOLE_KEY);
	if (strcmp(toc_key, TOCKEY_SOLMBOX)  == 0)
		return (SBBC_MAILBOX_KEY);
	if (strcmp(toc_key, TOCKEY_SOLSCIR)  == 0)
		return (SBBC_INTR_SC_KEY);
	if (strcmp(toc_key, TOCKEY_SCSOLIR)  == 0)
		return (SBBC_SC_INTR_KEY);
	if (strcmp(toc_key, TOCKEY_ENVINFO)  == 0)
		return (SBBC_ENVCTRL_KEY);
	if (strcmp(toc_key, TOCKEY_SOLSCIE)  == 0)
		return (SBBC_INTR_SC_ENABLED_KEY);
	if (strcmp(toc_key, TOCKEY_SCSOLIE)  == 0)
		return (SBBC_SC_INTR_ENABLED_KEY);
	if (strcmp(toc_key, TOCKEY_SIGBLCK)  == 0)
		return (SBBC_SIGBLCK_KEY);

	/* Unknown key */
	return (-1);
}

/*
 * Move the software interrupts from the old dip to the new dip
 * when doing tunnel switch.
 */
static int
iosram_switch_intr()
{
	sbbc_intrs_t	*intr;
	int		intr_no;
	int		rc = 0;

	ASSERT(MUTEX_HELD(&master_iosram->iosram_lock));

	for (intr_no = 0; intr_no < SBBC_MAX_INTRS; intr_no++) {
		intr = &master_iosram->intrs[intr_no];

		if (intr->sbbc_intr_id) {
			ddi_remove_softintr(intr->sbbc_intr_id);

			if (ddi_add_softintr(master_iosram->iosram_sbbc->dip,
				DDI_SOFTINT_HIGH,
				&intr->sbbc_intr_id, NULL, NULL,
				intr->sbbc_handler, intr->sbbc_arg)
				!= DDI_SUCCESS) {

				cmn_err(CE_WARN, "Can't add SBBC softint for "
					"interrupt %x", intr_no << 1);
				rc = EAGAIN;
			}
		}
	}

	return (rc);
}
