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
 * Driver to retire/unretire L2/L3 cachelines on panther
 */
#include <sys/types.h>
#include <sys/types32.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/param.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/cpuvar.h>
#include <sys/x_call.h>
#include <sys/cheetahregs.h>
#include <sys/mem_cache.h>
#include <sys/mem_cache_ioctl.h>

extern int	retire_l2(uint64_t, uint64_t);
extern int	retire_l2_alternate(uint64_t, uint64_t);
extern int	unretire_l2(uint64_t, uint64_t);
extern int	unretire_l2_alternate(uint64_t, uint64_t);
extern int	retire_l3(uint64_t, uint64_t);
extern int	retire_l3_alternate(uint64_t, uint64_t);
extern int	unretire_l3(uint64_t, uint64_t);
extern int	unretire_l3_alternate(uint64_t, uint64_t);

extern void	retire_l2_start(uint64_t, uint64_t);
extern void	retire_l2_end(uint64_t, uint64_t);
extern void	unretire_l2_start(uint64_t, uint64_t);
extern void	unretire_l2_end(uint64_t, uint64_t);
extern void	retire_l3_start(uint64_t, uint64_t);
extern void	retire_l3_end(uint64_t, uint64_t);
extern void	unretire_l3_start(uint64_t, uint64_t);
extern void	unretire_l3_end(uint64_t, uint64_t);

extern void	get_ecache_dtags_tl1(uint64_t, ch_cpu_logout_t *);
extern void	get_l2_tag_tl1(uint64_t, uint64_t);
extern void	get_l3_tag_tl1(uint64_t, uint64_t);
extern const int _ncpu;

/* Macro for putting 64-bit onto stack as two 32-bit ints */
#define	PRTF_64_TO_32(x)	(uint32_t)((x)>>32), (uint32_t)(x)


uint_t l2_flush_retries_done = 0;
int mem_cache_debug = 0x0;
uint64_t pattern = 0;
uint32_t retire_failures = 0;
#ifdef DEBUG
int	inject_anonymous_tag_error = 0;
int32_t last_error_injected_way = 0;
uint8_t last_error_injected_bit = 0;
int32_t last_l3tag_error_injected_way;
uint8_t last_l3tag_error_injected_bit;
int32_t last_l2tag_error_injected_way;
uint8_t last_l2tag_error_injected_bit;
#endif

/* dev_ops and cb_ops entry point function declarations */
static int	mem_cache_attach(dev_info_t *, ddi_attach_cmd_t);
static int	mem_cache_detach(dev_info_t *, ddi_detach_cmd_t);
static int	mem_cache_getinfo(dev_info_t *, ddi_info_cmd_t, void *,
				void **);
static int	mem_cache_open(dev_t *, int, int, cred_t *);
static int	mem_cache_close(dev_t, int, int, cred_t *);
static int	mem_cache_ioctl_ops(int, int, cache_info_t *);
static int	mem_cache_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

struct cb_ops mem_cache_cb_ops = {
	mem_cache_open,
	mem_cache_close,
	nodev,
	nodev,
	nodev,			/* dump */
	nodev,
	nodev,
	mem_cache_ioctl,
	nodev,			/* devmap */
	nodev,
	ddi_segmap,		/* segmap */
	nochpoll,
	ddi_prop_op,
	NULL,			/* for STREAMS drivers */
	D_NEW | D_MP		/* driver compatibility flag */
};

static struct dev_ops mem_cache_dev_ops = {
	DEVO_REV,		/* driver build version */
	0,			/* device reference count */
	mem_cache_getinfo,
	nulldev,
	nulldev,		/* probe */
	mem_cache_attach,
	mem_cache_detach,
	nulldev,		/* reset */
	&mem_cache_cb_ops,
	(struct bus_ops *)NULL,
	nulldev,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Soft state
 */
struct mem_cache_softc {
	dev_info_t	*dip;
	kmutex_t	mutex;
};
#define	getsoftc(inst)	((struct mem_cache_softc *)ddi_get_soft_state(statep,\
			(inst)))

/* module configuration stuff */
static void *statep;
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,
	"mem_cache_driver (08/01/30) ",
	&mem_cache_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	0
};

extern const int _ncpu; /* Pull the kernel's global _ncpu definition */

int
_init(void)
{
	int e;

	if (e = ddi_soft_state_init(&statep, sizeof (struct mem_cache_softc),
	    MAX_MEM_CACHE_INSTANCES)) {
		return (e);
	}

	if ((e = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&statep);

	return (e);
}

int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) != 0)
		return (e);

	ddi_soft_state_fini(&statep);

	return (DDI_SUCCESS);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
mem_cache_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int	inst;
	int	retval = DDI_SUCCESS;
	struct mem_cache_softc *softc;

	inst = getminor((dev_t)arg);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((softc = getsoftc(inst)) == NULL) {
			*result = (void *)NULL;
			retval = DDI_FAILURE;
		} else
			*result = (void *)softc->dip;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)((uintptr_t)inst);
		break;

	default:
		retval = DDI_FAILURE;
	}

	return (retval);
}

static int
mem_cache_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int inst;
	struct mem_cache_softc *softc = NULL;
	char name[80];

	switch (cmd) {
	case DDI_ATTACH:
		inst = ddi_get_instance(dip);
		if (inst >= MAX_MEM_CACHE_INSTANCES) {
			cmn_err(CE_WARN, "attach failed, too many instances\n");
			return (DDI_FAILURE);
		}
		(void) sprintf(name, MEM_CACHE_DRIVER_NAME"%d", inst);
		if (ddi_create_priv_minor_node(dip, name,
		    S_IFCHR,
		    inst,
		    DDI_PSEUDO,
		    0, NULL, "all", 0640) ==
		    DDI_FAILURE) {
			ddi_remove_minor_node(dip, NULL);
			return (DDI_FAILURE);
		}

		/* Allocate a soft state structure for this instance */
		if (ddi_soft_state_zalloc(statep, inst) != DDI_SUCCESS) {
			cmn_err(CE_WARN, " ddi_soft_state_zalloc() failed "
			    "for inst %d\n", inst);
			goto attach_failed;
		}

		/* Setup soft state */
		softc = getsoftc(inst);
		softc->dip = dip;
		mutex_init(&softc->mutex, NULL, MUTEX_DRIVER, NULL);

		/* Create main environmental node */
		ddi_report_dev(dip);

		return (DDI_SUCCESS);

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

attach_failed:

	/* Free soft state, if allocated. remove minor node if added earlier */
	if (softc)
		ddi_soft_state_free(statep, inst);

	ddi_remove_minor_node(dip, NULL);

	return (DDI_FAILURE);
}

static int
mem_cache_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int inst;
	struct mem_cache_softc *softc;

	switch (cmd) {
	case DDI_DETACH:
		inst = ddi_get_instance(dip);
		if ((softc = getsoftc(inst)) == NULL)
			return (ENXIO);

		/* Free the soft state and remove minor node added earlier */
		mutex_destroy(&softc->mutex);
		ddi_soft_state_free(statep, inst);
		ddi_remove_minor_node(dip, NULL);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
mem_cache_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int	inst = getminor(*devp);

	return (getsoftc(inst) == NULL ? ENXIO : 0);
}

/*ARGSUSED*/
static int
mem_cache_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int	inst = getminor(dev);

	return (getsoftc(inst) == NULL ? ENXIO : 0);
}

static char *tstate_to_desc[] = {
	"Invalid",			/* 0 */
	"Shared",			/* 1 */
	"Exclusive",			/* 2 */
	"Owner",			/* 3 */
	"Modified",			/* 4 */
	"NA",				/* 5 */
	"Owner/Shared",			/* 6 */
	"Reserved(7)",			/* 7 */
};

static char *
tag_state_to_desc(uint8_t tagstate)
{
	return (tstate_to_desc[tagstate & CH_ECSTATE_MASK]);
}

void
print_l2_tag(uint64_t tag_addr, uint64_t l2_tag)
{
	uint64_t l2_subaddr;
	uint8_t	l2_state;

	l2_subaddr = PN_L2TAG_TO_PA(l2_tag);
	l2_subaddr |= (tag_addr & PN_L2_INDEX_MASK);

	l2_state = (l2_tag & CH_ECSTATE_MASK);
	cmn_err(CE_CONT,
	    "PA=0x%08x.%08x E$tag 0x%08x.%08x E$state %s\n",
	    PRTF_64_TO_32(l2_subaddr),
	    PRTF_64_TO_32(l2_tag),
	    tag_state_to_desc(l2_state));
}

void
print_l2cache_line(ch_cpu_logout_t *clop)
{
	uint64_t l2_subaddr;
	int i, offset;
	uint8_t	way, l2_state;
	ch_ec_data_t *ecp;


	for (way = 0; way < PN_CACHE_NWAYS; way++) {
		ecp = &clop->clo_data.chd_l2_data[way];
		l2_subaddr = PN_L2TAG_TO_PA(ecp->ec_tag);
		l2_subaddr |= (ecp->ec_idx & PN_L2_INDEX_MASK);

		l2_state = (ecp->ec_tag & CH_ECSTATE_MASK);
		cmn_err(CE_CONT,
		    "\nWAY = %d index = 0x%08x PA=0x%08x.%08x\n"
		    "E$tag 0x%08x.%08x E$state %s",
		    way, (uint32_t)ecp->ec_idx, PRTF_64_TO_32(l2_subaddr),
		    PRTF_64_TO_32(ecp->ec_tag),
		    tag_state_to_desc(l2_state));
		/*
		 * Dump out Ecache subblock data captured.
		 * For Cheetah, we need to compute the ECC for each 16-byte
		 * chunk and compare it with the captured chunk ECC to figure
		 * out which chunk is bad.
		 */
		for (i = 0; i < (CH_ECACHE_SUBBLK_SIZE/16); i++) {
			ec_data_elm_t *ecdptr;
			uint64_t d_low, d_high;
			uint32_t ecc;
			int l2_data_idx = (i/2);

			offset = i * 16;
			ecdptr = &clop->clo_data.chd_l2_data[way].ec_data
			    [l2_data_idx];
			if ((i & 1) == 0) {
				ecc = (ecdptr->ec_eccd >> 9) & 0x1ff;
				d_high = ecdptr->ec_d8[0];
				d_low  = ecdptr->ec_d8[1];
			} else {
				ecc = ecdptr->ec_eccd & 0x1ff;
				d_high = ecdptr->ec_d8[2];
				d_low  = ecdptr->ec_d8[3];
			}

			cmn_err(CE_CONT,
			    "\nE$Data (0x%02x) 0x%08x.%08x 0x%08x.%08x"
			    " ECC 0x%03x",
			    offset, PRTF_64_TO_32(d_high),
			    PRTF_64_TO_32(d_low), ecc);
		}
	}	/* end of for way loop */
}

void
print_ecache_line(ch_cpu_logout_t *clop)
{
	uint64_t ec_subaddr;
	int i, offset;
	uint8_t	way, ec_state;
	ch_ec_data_t *ecp;


	for (way = 0; way < PN_CACHE_NWAYS; way++) {
		ecp = &clop->clo_data.chd_ec_data[way];
		ec_subaddr = PN_L3TAG_TO_PA(ecp->ec_tag);
		ec_subaddr |= (ecp->ec_idx & PN_L3_TAG_RD_MASK);

		ec_state = (ecp->ec_tag & CH_ECSTATE_MASK);
		cmn_err(CE_CONT,
		    "\nWAY = %d index = 0x%08x PA=0x%08x.%08x\n"
		    "E$tag 0x%08x.%08x E$state %s",
		    way, (uint32_t)ecp->ec_idx, PRTF_64_TO_32(ec_subaddr),
		    PRTF_64_TO_32(ecp->ec_tag),
		    tag_state_to_desc(ec_state));
		/*
		 * Dump out Ecache subblock data captured.
		 * For Cheetah, we need to compute the ECC for each 16-byte
		 * chunk and compare it with the captured chunk ECC to figure
		 * out which chunk is bad.
		 */
		for (i = 0; i < (CH_ECACHE_SUBBLK_SIZE/16); i++) {
			ec_data_elm_t *ecdptr;
			uint64_t d_low, d_high;
			uint32_t ecc;
			int ec_data_idx = (i/2);

			offset = i * 16;
			ecdptr =
			    &clop->clo_data.chd_ec_data[way].ec_data
			    [ec_data_idx];
			if ((i & 1) == 0) {
				ecc = (ecdptr->ec_eccd >> 9) & 0x1ff;
				d_high = ecdptr->ec_d8[0];
				d_low  = ecdptr->ec_d8[1];
			} else {
				ecc = ecdptr->ec_eccd & 0x1ff;
				d_high = ecdptr->ec_d8[2];
				d_low  = ecdptr->ec_d8[3];
			}

			cmn_err(CE_CONT,
			    "\nE$Data (0x%02x) 0x%08x.%08x 0x%08x.%08x"
			    " ECC 0x%03x",
			    offset, PRTF_64_TO_32(d_high),
			    PRTF_64_TO_32(d_low), ecc);
		}
	}
}

static boolean_t
tag_addr_collides(uint64_t tag_addr, cache_id_t type,
    retire_func_t start_of_func, retire_func_t end_of_func)
{
	uint64_t start_paddr, end_paddr;
	char *type_str;

	start_paddr = va_to_pa((void *)start_of_func);
	end_paddr = va_to_pa((void *)end_of_func);
	switch (type) {
		case L2_CACHE_TAG:
		case L2_CACHE_DATA:
			tag_addr &= PN_L2_INDEX_MASK;
			start_paddr &= PN_L2_INDEX_MASK;
			end_paddr &= PN_L2_INDEX_MASK;
			type_str = "L2:";
			break;
		case L3_CACHE_TAG:
		case L3_CACHE_DATA:
			tag_addr &= PN_L3_TAG_RD_MASK;
			start_paddr &= PN_L3_TAG_RD_MASK;
			end_paddr &= PN_L3_TAG_RD_MASK;
			type_str = "L3:";
			break;
		default:
			/*
			 * Should never reach here.
			 */
			ASSERT(0);
			return (B_FALSE);
	}
	if ((tag_addr > (start_paddr - 0x100)) &&
	    (tag_addr < (end_paddr + 0x100))) {
		if (mem_cache_debug & 0x1)
			cmn_err(CE_CONT,
			    "%s collision detected tag_addr = 0x%08x"
			    " start_paddr = 0x%08x end_paddr = 0x%08x\n",
			    type_str, (uint32_t)tag_addr, (uint32_t)start_paddr,
			    (uint32_t)end_paddr);
		return (B_TRUE);
	}
	else
		return (B_FALSE);
}

static uint64_t
get_tag_addr(cache_info_t *cache_info)
{
	uint64_t tag_addr, scratch;

	switch (cache_info->cache) {
		case L2_CACHE_TAG:
		case L2_CACHE_DATA:
			tag_addr = (uint64_t)(cache_info->index <<
			    PN_CACHE_LINE_SHIFT);
			scratch = (uint64_t)(cache_info->way <<
			    PN_L2_WAY_SHIFT);
			tag_addr |= scratch;
			tag_addr |= PN_L2_IDX_HW_ECC_EN;
			break;
		case L3_CACHE_TAG:
		case L3_CACHE_DATA:
			tag_addr = (uint64_t)(cache_info->index <<
			    PN_CACHE_LINE_SHIFT);
			scratch = (uint64_t)(cache_info->way <<
			    PN_L3_WAY_SHIFT);
			tag_addr |= scratch;
			tag_addr |= PN_L3_IDX_HW_ECC_EN;
			break;
		default:
			/*
			 * Should never reach here.
			 */
			ASSERT(0);
			return (uint64_t)(0);
	}
	return (tag_addr);
}

static int
mem_cache_ioctl_ops(int cmd, int mode, cache_info_t *cache_info)
{
	int	ret_val = 0;
	uint64_t afar, tag_addr;
	ch_cpu_logout_t clop;
	uint64_t Lxcache_tag_data[PN_CACHE_NWAYS];
	int	i, retire_retry_count;
	cpu_t	*cpu;
	uint64_t tag_data;
	uint8_t state;

	if (cache_info->way >= PN_CACHE_NWAYS)
		return (EINVAL);
	switch (cache_info->cache) {
		case L2_CACHE_TAG:
		case L2_CACHE_DATA:
			if (cache_info->index >=
			    (PN_L2_SET_SIZE/PN_L2_LINESIZE))
				return (EINVAL);
			break;
		case L3_CACHE_TAG:
		case L3_CACHE_DATA:
			if (cache_info->index >=
			    (PN_L3_SET_SIZE/PN_L3_LINESIZE))
				return (EINVAL);
			break;
		default:
			return (ENOTSUP);
	}
	/*
	 * Check if we have a valid cpu ID and that
	 * CPU is ONLINE.
	 */
	mutex_enter(&cpu_lock);
	cpu = cpu_get(cache_info->cpu_id);
	if ((cpu == NULL) || (!cpu_is_online(cpu))) {
		mutex_exit(&cpu_lock);
		return (EINVAL);
	}
	mutex_exit(&cpu_lock);
	pattern = 0;	/* default value of TAG PA when cacheline is retired. */
	switch (cmd) {
		case MEM_CACHE_RETIRE:
			tag_addr = get_tag_addr(cache_info);
			pattern |= PN_ECSTATE_NA;
			retire_retry_count = 0;
			affinity_set(cache_info->cpu_id);
			switch (cache_info->cache) {
				case L2_CACHE_DATA:
				case L2_CACHE_TAG:
					if ((cache_info->bit & MSB_BIT_MASK) ==
					    MSB_BIT_MASK)
						pattern |= PN_L2TAG_PA_MASK;
retry_l2_retire:
					if (tag_addr_collides(tag_addr,
					    cache_info->cache,
					    retire_l2_start, retire_l2_end))
						ret_val =
						    retire_l2_alternate(
						    tag_addr, pattern);
					else
						ret_val = retire_l2(tag_addr,
						    pattern);
					if (ret_val == 1) {
						/*
						 * cacheline was in retired
						 * STATE already.
						 * so return success.
						 */
						ret_val = 0;
					}
					if (ret_val < 0) {
						cmn_err(CE_WARN,
		"retire_l2() failed. index = 0x%x way %d. Retrying...\n",
						    cache_info->index,
						    cache_info->way);
						if (retire_retry_count >= 2) {
							retire_failures++;
							affinity_clear();
							return (EIO);
						}
						retire_retry_count++;
						goto retry_l2_retire;
					}
					if (ret_val == 2)
						l2_flush_retries_done++;
			/*
			 * We bind ourself to a CPU and send cross trap to
			 * ourself. On return from xt_one we can rely on the
			 * data in tag_data being filled in. Normally one would
			 * do a xt_sync to make sure that the CPU has completed
			 * the cross trap call xt_one.
			 */
					xt_one(cache_info->cpu_id,
					    (xcfunc_t *)(get_l2_tag_tl1),
					    tag_addr, (uint64_t)(&tag_data));
					state = tag_data & CH_ECSTATE_MASK;
					if (state != PN_ECSTATE_NA) {
						retire_failures++;
						print_l2_tag(tag_addr,
						    tag_data);
						cmn_err(CE_WARN,
		"L2 RETIRE:failed for index 0x%x way %d. Retrying...\n",
						    cache_info->index,
						    cache_info->way);
						if (retire_retry_count >= 2) {
							retire_failures++;
							affinity_clear();
							return (EIO);
						}
						retire_retry_count++;
						goto retry_l2_retire;
					}
					break;
				case L3_CACHE_TAG:
				case L3_CACHE_DATA:
					if ((cache_info->bit & MSB_BIT_MASK) ==
					    MSB_BIT_MASK)
						pattern |= PN_L3TAG_PA_MASK;
					if (tag_addr_collides(tag_addr,
					    cache_info->cache,
					    retire_l3_start, retire_l3_end))
						ret_val =
						    retire_l3_alternate(
						    tag_addr, pattern);
					else
						ret_val = retire_l3(tag_addr,
						    pattern);
					if (ret_val == 1) {
						/*
						 * cacheline was in retired
						 * STATE already.
						 * so return success.
						 */
						ret_val = 0;
					}
					if (ret_val < 0) {
						cmn_err(CE_WARN,
			"retire_l3() failed. ret_val = %d index = 0x%x\n",
						    ret_val,
						    cache_info->index);
						retire_failures++;
						affinity_clear();
						return (EIO);
					}
			/*
			 * We bind ourself to a CPU and send cross trap to
			 * ourself. On return from xt_one we can rely on the
			 * data in tag_data being filled in. Normally one would
			 * do a xt_sync to make sure that the CPU has completed
			 * the cross trap call xt_one.
			 */
					xt_one(cache_info->cpu_id,
					    (xcfunc_t *)(get_l3_tag_tl1),
					    tag_addr, (uint64_t)(&tag_data));
					state = tag_data & CH_ECSTATE_MASK;
					if (state != PN_ECSTATE_NA) {
						cmn_err(CE_WARN,
					"L3 RETIRE failed for index 0x%x\n",
						    cache_info->index);
						retire_failures++;
						affinity_clear();
						return (EIO);
					}

					break;
			}
			affinity_clear();
			break;
		case MEM_CACHE_UNRETIRE:
			tag_addr = get_tag_addr(cache_info);
			pattern = PN_ECSTATE_INV;
			affinity_set(cache_info->cpu_id);
			switch (cache_info->cache) {
				case L2_CACHE_DATA:
				case L2_CACHE_TAG:
			/*
			 * We bind ourself to a CPU and send cross trap to
			 * ourself. On return from xt_one we can rely on the
			 * data in tag_data being filled in. Normally one would
			 * do a xt_sync to make sure that the CPU has completed
			 * the cross trap call xt_one.
			 */
					xt_one(cache_info->cpu_id,
					    (xcfunc_t *)(get_l2_tag_tl1),
					    tag_addr, (uint64_t)(&tag_data));
					state = tag_data & CH_ECSTATE_MASK;
					if (state != PN_ECSTATE_NA) {
						affinity_clear();
						return (EINVAL);
					}
					if (tag_addr_collides(tag_addr,
					    cache_info->cache,
					    unretire_l2_start, unretire_l2_end))
						ret_val =
						    unretire_l2_alternate(
						    tag_addr, pattern);
					else
						ret_val =
						    unretire_l2(tag_addr,
						    pattern);
					if (ret_val != 0) {
						cmn_err(CE_WARN,
			"unretire_l2() failed. ret_val = %d index = 0x%x\n",
						    ret_val,
						    cache_info->index);
						retire_failures++;
						affinity_clear();
						return (EIO);
					}
					break;
				case L3_CACHE_TAG:
				case L3_CACHE_DATA:
			/*
			 * We bind ourself to a CPU and send cross trap to
			 * ourself. On return from xt_one we can rely on the
			 * data in tag_data being filled in. Normally one would
			 * do a xt_sync to make sure that the CPU has completed
			 * the cross trap call xt_one.
			 */
					xt_one(cache_info->cpu_id,
					    (xcfunc_t *)(get_l3_tag_tl1),
					    tag_addr, (uint64_t)(&tag_data));
					state = tag_data & CH_ECSTATE_MASK;
					if (state != PN_ECSTATE_NA) {
						affinity_clear();
						return (EINVAL);
					}
					if (tag_addr_collides(tag_addr,
					    cache_info->cache,
					    unretire_l3_start, unretire_l3_end))
						ret_val =
						    unretire_l3_alternate(
						    tag_addr, pattern);
					else
						ret_val =
						    unretire_l3(tag_addr,
						    pattern);
					if (ret_val != 0) {
						cmn_err(CE_WARN,
			"unretire_l3() failed. ret_val = %d index = 0x%x\n",
						    ret_val,
						    cache_info->index);
						affinity_clear();
						return (EIO);
					}
					break;
			}
			affinity_clear();
			break;
		case MEM_CACHE_ISRETIRED:
		case MEM_CACHE_STATE:
			return (ENOTSUP);
		case MEM_CACHE_READ_TAGS:
#ifdef DEBUG
		case MEM_CACHE_READ_ERROR_INJECTED_TAGS:
#endif
			/*
			 * Read tag and data for all the ways at a given afar
			 */
			afar = (uint64_t)(cache_info->index
			    << PN_CACHE_LINE_SHIFT);
			mutex_enter(&cpu_lock);
			affinity_set(cache_info->cpu_id);
			pause_cpus(NULL, NULL);
			mutex_exit(&cpu_lock);
			/*
			 * We bind ourself to a CPU and send cross trap to
			 * ourself. On return from xt_one we can rely on the
			 * data in clop being filled in. Normally one would
			 * do a xt_sync to make sure that the CPU has completed
			 * the cross trap call xt_one.
			 */
			xt_one(cache_info->cpu_id,
			    (xcfunc_t *)(get_ecache_dtags_tl1),
			    afar, (uint64_t)(&clop));
			mutex_enter(&cpu_lock);
			(void) start_cpus();
			mutex_exit(&cpu_lock);
			affinity_clear();
			switch (cache_info->cache) {
				case L2_CACHE_TAG:
					for (i = 0; i < PN_CACHE_NWAYS; i++) {
						Lxcache_tag_data[i] =
						    clop.clo_data.chd_l2_data
						    [i].ec_tag;
					}
#ifdef DEBUG
					last_error_injected_bit =
					    last_l2tag_error_injected_bit;
					last_error_injected_way =
					    last_l2tag_error_injected_way;
#endif
					break;
				case L3_CACHE_TAG:
					for (i = 0; i < PN_CACHE_NWAYS; i++) {
						Lxcache_tag_data[i] =
						    clop.clo_data.chd_ec_data
						    [i].ec_tag;
					}
#ifdef DEBUG
					last_error_injected_bit =
					    last_l3tag_error_injected_bit;
					last_error_injected_way =
					    last_l3tag_error_injected_way;
#endif
					break;
				default:
					return (ENOTSUP);
			}	/* end if switch(cache) */
#ifdef DEBUG
			if ((cmd == MEM_CACHE_READ_ERROR_INJECTED_TAGS) &&
			    (inject_anonymous_tag_error == 0) &&
			    (last_error_injected_way >= 0) &&
			    (last_error_injected_way <= 3)) {
				pattern = ((uint64_t)1 <<
				    last_error_injected_bit);
				/*
				 * If error bit is ECC we need to make sure
				 * ECC on all all WAYS are corrupted.
				 */
				if ((last_error_injected_bit >= 6) &&
				    (last_error_injected_bit <= 14)) {
					for (i = 0; i < PN_CACHE_NWAYS; i++)
						Lxcache_tag_data[i] ^=
						    pattern;
				} else
					Lxcache_tag_data
					    [last_error_injected_way] ^=
					    pattern;
			}
#endif
			if (ddi_copyout((caddr_t)Lxcache_tag_data,
			    (caddr_t)cache_info->datap,
			    sizeof (Lxcache_tag_data), mode)
			    != DDI_SUCCESS) {
				return (EFAULT);
			}
			break;	/* end of READ_TAGS */
		default:
			return (ENOTSUP);
	}	/* end if switch(cmd) */
	return (ret_val);
}

/*ARGSUSED*/
static int
mem_cache_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
		int *rvalp)
{
	int	inst;
	struct mem_cache_softc *softc;
	cache_info_t	cache_info;
	cache_info32_t	cache_info32;
	int	ret_val;
	int	is_panther;

	inst = getminor(dev);
	if ((softc = getsoftc(inst)) == NULL)
		return (ENXIO);

	mutex_enter(&softc->mutex);

#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		if (ddi_copyin((cache_info32_t *)arg, &cache_info32,
		    sizeof (cache_info32), mode) != DDI_SUCCESS) {
			mutex_exit(&softc->mutex);
			return (EFAULT);
		}
		cache_info.cache = cache_info32.cache;
		cache_info.index = cache_info32.index;
		cache_info.way = cache_info32.way;
		cache_info.cpu_id = cache_info32.cpu_id;
		cache_info.bit = cache_info32.bit;
		cache_info.datap = (void *)((uint64_t)cache_info32.datap);
	} else
#endif
	if (ddi_copyin((cache_info_t *)arg, &cache_info,
	    sizeof (cache_info), mode) != DDI_SUCCESS) {
		mutex_exit(&softc->mutex);
		return (EFAULT);
	}

	if ((cache_info.cpu_id < 0) || (cache_info.cpu_id >= _ncpu)) {
		mutex_exit(&softc->mutex);
		return (EINVAL);
	}
	is_panther = IS_PANTHER(cpunodes[cache_info.cpu_id].implementation);
	if (!is_panther) {
		mutex_exit(&softc->mutex);
		return (ENOTSUP);
	}
	switch (cmd) {
		case MEM_CACHE_RETIRE:
		case MEM_CACHE_UNRETIRE:
			if ((mode & FWRITE) == 0) {
				ret_val = EBADF;
				break;
			}
		/*FALLTHROUGH*/
		case MEM_CACHE_ISRETIRED:
		case MEM_CACHE_STATE:
		case MEM_CACHE_READ_TAGS:
#ifdef DEBUG
		case MEM_CACHE_READ_ERROR_INJECTED_TAGS:
#endif
			ret_val =  mem_cache_ioctl_ops(cmd, mode, &cache_info);
			break;
		default:
			ret_val = ENOTSUP;
			break;
	}
	mutex_exit(&softc->mutex);
	return (ret_val);
}
