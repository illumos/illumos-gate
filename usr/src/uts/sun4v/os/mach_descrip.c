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
 * Kernel Machine Description (MD)
 *
 * The Kernel maintains a global copy of the machine description for
 * the system. This is for use by all kernel subsystems and is exported
 * to user applications through the the 'mdesc' device driver. It is
 * initially copied in from the Hypervisor at boot time, but can be
 * updated dynamically on demand. The Kernel provides an interface
 * for consumers to obtain a handle to the global MD. Consumers of the
 * MD must use the specified interfaces. An update interface is provided
 * for platform services to intiate an MD update on notification by a
 * service entity.
 *
 * Locks
 * The current global MD is protected by the curr_mach_descrip_lock.
 * Each Machine description has a lock to synchornize its ref count.
 * The Obsolete MD list is protected by the obs_list_lock.
 */

#include <sys/machsystm.h>
#include <sys/vm.h>
#include <sys/cpu.h>
#include <sys/intreg.h>
#include <sys/machcpuvar.h>
#include <sys/machparam.h>
#include <vm/hat_sfmmu.h>
#include <vm/seg_kmem.h>
#include <sys/error.h>
#include <sys/hypervisor_api.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/mdesc.h>
#include <sys/mdesc_impl.h>
#include <sys/mach_descrip.h>
#include <sys/prom_plat.h>
#include <sys/promif.h>
#include <sys/ldoms.h>

static void *mach_descrip_strt_meta_alloc(size_t size);
static void mach_descrip_strt_meta_free(void *buf, size_t size);
static void *mach_descrip_strt_buf_alloc(size_t size, size_t align);
static void mach_descrip_strt_buf_free(void *buf, size_t size);
static void *mach_descrip_buf_alloc(size_t size, size_t align);
static void *mach_descrip_meta_alloc(size_t size);
static uint64_t mach_descrip_find_md_gen(caddr_t ptr);
static void init_md_params(void);
static void init_domaining_capabilities(md_t *mdp, mde_cookie_t *listp);

/*
 * Global ptr of the current generation Machine Description
 */
static machine_descrip_t *curr_mach_descrip;

/*
 * Initialized by machine_descrip_startup_init in startup.
 * machine_descript_init will reintialize the structure with
 * the vmem allocators once the vmem is available in the boot up
 * process.
 */
static machine_descrip_memops_t *curr_mach_descrip_memops = NULL;

static machine_descrip_memops_t startup_memops = {
	mach_descrip_strt_buf_alloc,
	mach_descrip_strt_buf_free,
	mach_descrip_strt_meta_alloc,
	mach_descrip_strt_meta_free,
};

static machine_descrip_memops_t mach_descrip_memops = {
	mach_descrip_buf_alloc,
	contig_mem_free,
	mach_descrip_meta_alloc,
	kmem_free,
};

static kmutex_t curr_mach_descrip_lock;
/*
 * List of obsolete Machine Descriptions
 * Machine descriptions that have users are put on this list
 * and freed after the last user has called md_fini_handle.
 */
static machine_descrip_t *obs_machine_descrip_list;

static kmutex_t obs_list_lock;

static const char alloc_fail_msg[] =
	"MD: cannot allocate MD buffer of size %ld bytes\n";

/*
 * Global flags that indicate what domaining features are
 * available, if any. The value is set at boot time based on
 * the value of the 'domaining-enabled' property in the MD
 * and the global override flag below. Updates to this
 * variable after boot are not supported.
 */
uint_t domaining_capabilities;

/*
 * Global override for the 'domaining_capailities' flags. If this
 * flag is set in /etc/system, domaining features are disabled,
 * ignoring the value of the 'domaining-enabled' property in
 * the MD.
 */
uint_t force_domaining_disabled;

#define	META_ALLOC_ALIGN	8
#define	HAS_GEN(x)	(x != MDESC_INVAL_GEN)

#ifdef DEBUG
static int mach_descrip_debug = 0;

#define	MDP(ARGS)	if (mach_descrip_debug) prom_printf ARGS
#define	PRINT_LIST() 	if (mach_descrip_debug) print_obs_list()

#ifdef	MACH_DESC_DEBUG
static void
dump_buf(uint8_t *bufp, int size)
{
	int i;
	for (i = 0; i < size; i += 16) {
		int j;
		prom_printf("0x%04x :", i);
		for (j = 0; j < 16 && (i+j) < size; j++)
			prom_printf(" %02x", bufp[i+j]);
		prom_printf("\n");
	}
}
#endif /* MACH_DESC_DEBUG */

static void
print_obs_list(void)
{
	machine_descrip_t *lmdescp;
	mutex_enter(&obs_list_lock);

	lmdescp	= obs_machine_descrip_list;
	prom_printf("MD_obs_list->");
	while (lmdescp != NULL) {
		prom_printf("g:%ld,r:%d", lmdescp->gen, lmdescp->refcnt);

		lmdescp = lmdescp->next;
		prom_printf("->");
	}
	prom_printf("NULL\n");
	mutex_exit(&obs_list_lock);
}

#else
#define	MDP(ARGS)
#define	PRINT_LIST()
#endif /* DEBUG */

/*
 * MD obsolete list managment functions
 */
static machine_descrip_t *
md_obs_list_look_up_by_gen(uint64_t gen)
{
	machine_descrip_t *mdescp;

	mutex_enter(&obs_list_lock);
	mdescp = obs_machine_descrip_list;

	while (mdescp != NULL) {
		if (mdescp->gen == gen) {
			mutex_exit(&obs_list_lock);
			return (mdescp);
		}
		mdescp = mdescp->next;
	}

	mutex_exit(&obs_list_lock);
	return (mdescp);
}

static void
md_obs_list_remove(machine_descrip_t *mdescp)
{
	machine_descrip_t *lmdescp;

	mutex_enter(&obs_list_lock);

	lmdescp	= obs_machine_descrip_list;

	if (obs_machine_descrip_list == mdescp) {
		obs_machine_descrip_list = mdescp->next;
	} else {
		while (lmdescp != NULL) {
			if (lmdescp->next == mdescp) {
				lmdescp->next = mdescp->next;
				mdescp->next = NULL;
				break;
			}
			lmdescp = lmdescp->next;
		}
	}
	mutex_exit(&obs_list_lock);
	PRINT_LIST();
}

static void
md_obs_list_add(machine_descrip_t *mdescp)
{
	mutex_enter(&obs_list_lock);

	mdescp->next = obs_machine_descrip_list;
	obs_machine_descrip_list = mdescp;

	mutex_exit(&obs_list_lock);
	PRINT_LIST();
}

/*
 * Allocate a machine_descrip meta structure and intitialize it.
 */
static machine_descrip_t *
new_mach_descrip(void)
{
	machine_descrip_t *mdescp;

	mdescp = (machine_descrip_t *)(*curr_mach_descrip_memops->meta_allocp)
	    (sizeof (machine_descrip_t));
	if (mdescp != NULL) {
		bzero(mdescp, sizeof (*mdescp));
		mdescp->memops = curr_mach_descrip_memops;
		mutex_init(&mdescp->lock, NULL, MUTEX_DRIVER, NULL);
	}

	return (mdescp);
}

/*
 * Free a machine_descrip meta structure and intitialize it.
 * Also free the MD buffer.
 */
static void
destroy_machine_descrip(machine_descrip_t *mdescp)
{
	machine_descrip_memops_t  *mdesc_memopsp;

	ASSERT((mdescp != NULL));

	mdesc_memopsp = mdescp->memops;
	if (mdescp->memops == NULL)
		panic("destroy_machine_descrip: memops NULL\n");

	(*mdesc_memopsp->buf_freep)(mdescp->va, mdescp->space);
	mutex_destroy(&mdescp->lock);
	(*mdesc_memopsp->meta_freep)(mdescp, sizeof (*mdescp));
}

/*
 * Call into the Hypervisor to retrieve the most recent copy of the
 * machine description. If references to the current MD are active
 * stow it in the obsolete MD list and update the current MD reference
 * with the new one.
 * The obsolete list contains one MD per generation. If the firmware
 * doesn't support MD generation fail the call.
 */
int
mach_descrip_update(void)
{
	uint64_t	md_size0, md_size;
	uint64_t	md_space = 0;
	uint64_t	hvret;
	caddr_t		tbuf = NULL;
	uint64_t	tbuf_pa;
	uint64_t	tgen;
	int		ret = 0;

	MDP(("MD: Requesting buffer size\n"));

	ASSERT((curr_mach_descrip != NULL));

	mutex_enter(&curr_mach_descrip_lock);

	/*
	 * If the required MD size changes between our first call
	 * to hv_mach_desc (to find the required buf size) and the
	 * second call (to get the actual MD) and our allocated
	 * memory is insufficient, loop until we have allocated
	 * sufficient space.
	 */
	do {
		if (tbuf != NULL)
			(*curr_mach_descrip_memops->buf_freep)(tbuf, md_space);

		md_size0 = 0LL;
		(void) hv_mach_desc((uint64_t)0, &md_size0);
		MDP(("MD: buffer size is %ld\n", md_size0));

		/*
		 * Align allocated space to nearest page.
		 * contig_mem_alloc_align() requires a power of 2 alignment.
		 */
		md_space = P2ROUNDUP(md_size0, PAGESIZE);
		MDP(("MD: allocated space is %ld\n", md_space));

		tbuf = (caddr_t)(*curr_mach_descrip_memops->buf_allocp)
		    (md_space, PAGESIZE);
		if (tbuf == NULL) {
			ret = -1;
			goto done;
		}

		tbuf_pa =  va_to_pa(tbuf);
		md_size = md_space;
		hvret = hv_mach_desc(tbuf_pa, &md_size);
		MDP(("MD: HV return code = %ld\n", hvret));

		/*
		 * We get H_EINVAL if our buffer size is too small. In
		 * that case stay in the loop, reallocate the buffer
		 * and try again.
		 */
		if (hvret != H_EOK && hvret != H_EINVAL) {
			MDP(("MD: Failed with code %ld from HV\n", hvret));
			ret = -1;
			goto done;
		}

	} while (md_space < md_size);

	tgen = mach_descrip_find_md_gen(tbuf);

#ifdef DEBUG
	if (!HAS_GEN(tgen)) {
		MDP(("MD: generation number not found\n"));
	} else
		MDP(("MD: generation number %ld\n", tgen));
#endif /* DEBUG */

	if (curr_mach_descrip->va != NULL) {

		/* check for the same generation number */
		if (HAS_GEN(tgen) && ((curr_mach_descrip->gen == tgen) &&
		    (curr_mach_descrip->size == md_size))) {
#ifdef DEBUG
			/*
			 * Pedantic Check for generation number. If the
			 * generation number is the same, make sure the
			 * MDs are really identical.
			 */
			if (bcmp(curr_mach_descrip->va, tbuf, md_size) != 0) {
				cmn_err(CE_WARN, "machine_descrip_update: MDs "
				    "with the same generation (%ld) are not "
				    "identical", tgen);
				ret = -1;
				goto done;
			}
#endif
			ret = 0;
			goto done;
		}

		/* check for generations moving backwards */
		if (HAS_GEN(tgen) && HAS_GEN(curr_mach_descrip->gen) &&
		    (curr_mach_descrip->gen > tgen)) {
			cmn_err(CE_WARN, "machine_descrip_update: new MD"
			    " older generation (%ld) than current MD (%ld)",
			    tgen, curr_mach_descrip->gen);
			ret = -1;
			goto done;
		}

		if (curr_mach_descrip->refcnt == 0) {

			MDP(("MD: freeing old md buffer gen %ld\n",
			    curr_mach_descrip->gen));

			/* Free old space */
			ASSERT(curr_mach_descrip->space > 0);

			(*curr_mach_descrip_memops->buf_freep)
			    (curr_mach_descrip->va, curr_mach_descrip->space);
		} else {
			if (!HAS_GEN(tgen)) {
				/*
				 * No update support if FW
				 * doesn't have MD generation id
				 * feature.
				 */
				prom_printf("WARNING: F/W does not support MD "
				    "generation count, MD update failed\n");
				ret = -1;
				goto done;
			}

			MDP(("MD: adding to obs list %ld\n",
			    curr_mach_descrip->gen));

			md_obs_list_add(curr_mach_descrip);

			curr_mach_descrip = new_mach_descrip();

			if (curr_mach_descrip == NULL) {
				panic("Allocation for machine description"
				    " failed\n");
			}
		}
	}

	curr_mach_descrip->va = tbuf;
	curr_mach_descrip->gen = tgen;
	curr_mach_descrip->size = md_size;
	curr_mach_descrip->space = md_space;

#ifdef MACH_DESC_DEBUG
	dump_buf((uint8_t *)curr_mach_descrip->va, md_size);
#endif /* MACH_DESC_DEBUG */

	mutex_exit(&curr_mach_descrip_lock);
	return (ret);

done:
	if (tbuf != NULL)
		(*curr_mach_descrip_memops->buf_freep)(tbuf, md_space);
	mutex_exit(&curr_mach_descrip_lock);
	return (ret);
}

static void *
mach_descrip_buf_alloc(size_t size, size_t align)
{
	void *p;

	if ((p = contig_mem_alloc_align(size, align)) == NULL)
		cmn_err(CE_WARN, alloc_fail_msg, size);

	return (p);
}

static void *
mach_descrip_strt_meta_alloc(size_t size)
{
	return (mach_descrip_strt_buf_alloc(size, META_ALLOC_ALIGN));
}

static void
mach_descrip_strt_meta_free(void *buf, size_t size)
{
	mach_descrip_strt_buf_free(buf, size);
}

static void *
mach_descrip_strt_buf_alloc(size_t size, size_t align)
{
	void *p = prom_alloc((caddr_t)0, size, align);

	if (p == NULL)
		prom_printf(alloc_fail_msg, size);

	return (p);
}

static void
mach_descrip_strt_buf_free(void *buf, size_t size)
{
	prom_free((caddr_t)buf, size);
}

static void *
mach_descrip_meta_alloc(size_t size)
{
	return (kmem_alloc(size, KM_SLEEP));
}

/*
 * Initialize the kernel's Machine Description(MD) framework
 * early on in startup during mlsetup() so consumers
 * can get to the MD before the VM system has been initialized.
 *
 * Also get the most recent version of the MD.
 */
void
mach_descrip_startup_init(void)
{

	mutex_init(&curr_mach_descrip_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&obs_list_lock, NULL, MUTEX_DRIVER, NULL);

	obs_machine_descrip_list = NULL;

	curr_mach_descrip_memops = &startup_memops;

	curr_mach_descrip = new_mach_descrip();
	if (curr_mach_descrip == NULL)
		panic("Allocation for machine description failed\n");

	if (mach_descrip_update())
		panic("Machine description initialization failed\n");

}

/*
 * Counterpart to the above init function.  Free up resources
 * allocated at startup by mach_descrip_startup_setup().
 * And reset machine description framework state.
 *
 * All consumers must have fini'ed their handles at this point.
 */
void
mach_descrip_startup_fini(void)
{

	ASSERT((curr_mach_descrip != NULL));
	ASSERT((curr_mach_descrip->refcnt == 0));
	ASSERT((obs_machine_descrip_list == NULL));

	destroy_machine_descrip(curr_mach_descrip);
	curr_mach_descrip = NULL;
	curr_mach_descrip_memops = NULL;
}

/*
 * Initialize the kernel's Machine Description(MD) framework
 * after the the VM system has been initialized.
 *
 * Also get the most recent version of the MD.
 * Assumes that the machine description frame work is in a clean
 * state and the machine description intialized during startup
 * has been cleaned up and resources deallocated.
 */
void
mach_descrip_init(void)
{
	ASSERT((curr_mach_descrip == NULL &&
	    curr_mach_descrip_memops == NULL));

	curr_mach_descrip_memops = &mach_descrip_memops;

	curr_mach_descrip = new_mach_descrip();
	if (curr_mach_descrip == NULL)
		panic("Allocation for machine description failed\n");

	if (mach_descrip_update())
		panic("Machine description intialization failed\n");

	/* read in global params */
	init_md_params();
}

/*
 * Client interface to get a handle to the current MD.
 * The md_fini_handle() interface should be used to
 * clean up the refernce to the MD returned by this function.
 */
md_t *
md_get_handle(void)
{
	md_t *mdp;

	mdp = NULL;

	mutex_enter(&curr_mach_descrip_lock);

	if (curr_mach_descrip != NULL) {

		mdp = md_init_intern(curr_mach_descrip->va,
		    curr_mach_descrip->memops->meta_allocp,
		    curr_mach_descrip->memops->meta_freep);

		if (mdp != NULL)
			curr_mach_descrip->refcnt++;
	}

	mutex_exit(&curr_mach_descrip_lock);

	return (mdp);
}

/*
 * Client interface to clean up the refernce to the MD returned
 * by md_get_handle().
 */
int
md_fini_handle(md_t *ptr)
{
	machine_descrip_t *mdescp;
	md_impl_t *mdp;


	mdp = (md_impl_t *)ptr;

	if (mdp == NULL)
		return (-1);
	/*
	 * Check if mdp is current MD gen
	 */
	mutex_enter(&curr_mach_descrip_lock);

	if (curr_mach_descrip->gen == mdp->gen) {
		curr_mach_descrip->refcnt--;
		mutex_exit(&curr_mach_descrip_lock);
		goto fini;
	}
	mutex_exit(&curr_mach_descrip_lock);

	/*
	 * MD is in the obsolete list
	 */
	mdescp = md_obs_list_look_up_by_gen(mdp->gen);
	if (mdescp == NULL)
		return (-1);

	mutex_enter(&mdescp->lock);
	mdescp->refcnt--;
	if (mdescp->refcnt == 0) {
		md_obs_list_remove(mdescp);
		mutex_exit(&mdescp->lock);
		destroy_machine_descrip(mdescp);
		goto fini;
	}
	mutex_exit(&mdescp->lock);

fini:
	return (md_fini(ptr));
}

/*
 * General purpose initialization function used to extract parameters
 * from the MD during the boot process. This is called immediately after
 * the in kernel copy of the MD has been initialized so that global
 * flags are available to various subsystems as they get initialized.
 */
static void
init_md_params(void)
{
	md_t		*mdp;
	int		num_nodes;
	mde_cookie_t	*listp;
	int		listsz;

	mdp = md_get_handle();
	ASSERT(mdp);
	num_nodes = md_node_count(mdp);
	ASSERT(num_nodes >= 0);

	listsz = num_nodes * sizeof (mde_cookie_t);
	listp = (mde_cookie_t *)
	    (*curr_mach_descrip_memops->meta_allocp)(listsz);

	/*
	 * Import various parameters from the MD. For now,
	 * the only parameter of interest is whether or not
	 * domaining features are supported.
	 */
	init_domaining_capabilities(mdp, listp);

	(*curr_mach_descrip_memops->meta_freep)(listp, listsz);
	(void) md_fini_handle(mdp);
}

static void
init_domaining_capabilities(md_t *mdp, mde_cookie_t *listp)
{
	mde_cookie_t	rootnode;
	int		num_nodes;
	uint64_t	val = 0;

	rootnode = md_root_node(mdp);
	ASSERT(rootnode != MDE_INVAL_ELEM_COOKIE);

	num_nodes = md_scan_dag(mdp, rootnode, md_find_name(mdp, "platform"),
	    md_find_name(mdp, "fwd"), listp);

	/* should only be one platform node */
	ASSERT(num_nodes == 1);

	if (md_get_prop_val(mdp, *listp, "domaining-enabled", &val) != 0) {
		/*
		 * The property is not present. This implies
		 * that the firmware does not support domaining
		 * features.
		 */
		MDP(("'domaining-enabled' property not present\n"));

		domaining_capabilities = 0;
		return;
	}

	domaining_capabilities = DOMAINING_SUPPORTED;

	if (val == 1) {
		if (force_domaining_disabled) {
			MDP(("domaining manually disabled\n"));
		} else {
			domaining_capabilities |= DOMAINING_ENABLED;
		}
	}

	MDP(("domaining_capabilities= 0x%x\n", domaining_capabilities));
}

/*
 * Client interface to get a pointer to the raw MD buffer
 * Private to kernel and mdesc driver.
 */
caddr_t
md_get_md_raw(md_t *ptr)
{
	md_impl_t *mdp;

	mdp = (md_impl_t *)ptr;
	if (mdp ==  NULL)
		return (NULL);
	return (mdp->caddr);
}

/*
 * This is called before an MD structure is intialized, so
 * it walks the raw MD looking for the generation property.
 */
static uint64_t
mach_descrip_find_md_gen(caddr_t ptr)
{
	md_header_t	*hdrp;
	md_element_t	*mdep;
	md_element_t	*rootnode = NULL;
	md_element_t	*elem = NULL;
	char		*namep;
	boolean_t	done;
	int		idx;

	hdrp = (md_header_t *)ptr;
	mdep = (md_element_t *)(ptr + MD_HEADER_SIZE);
	namep = (char *)(ptr + MD_HEADER_SIZE + hdrp->node_blk_sz);

	/*
	 * Very basic check for alignment to avoid
	 * bus error issues.
	 */
	if ((((uint64_t)ptr) & 7) != 0)
		return (MDESC_INVAL_GEN);

	if (mdtoh32(hdrp->transport_version) != MD_TRANSPORT_VERSION) {
		return (MDESC_INVAL_GEN);
	}

	/*
	 * Search for the root node. Perform the walk manually
	 * since the MD structure is not set up yet.
	 */
	for (idx = 0, done = B_FALSE; done == B_FALSE; ) {

		md_element_t *np = &(mdep[idx]);

		switch (MDE_TAG(np)) {
		case MDET_LIST_END:
			done = B_TRUE;
			break;

		case MDET_NODE:
			if (strcmp(namep + MDE_NAME(np), "root") == 0) {
				/* found root node */
				rootnode = np;
				done = B_TRUE;
				break;
			}
			idx = MDE_PROP_INDEX(np);
			break;

		default:
			/* ignore */
			idx++;
		}
	}

	if (rootnode == NULL) {
		/* root not found */
		return (MDESC_INVAL_GEN);
	}

	/* search the rootnode for the generation property */
	for (elem = (rootnode + 1); MDE_TAG(elem) != MDET_NODE_END; elem++) {

		char *prop_name;

		/* generation field is a prop_val */
		if (MDE_TAG(elem) != MDET_PROP_VAL)
			continue;

		prop_name = namep + MDE_NAME(elem);

		if (strcmp(prop_name, "md-generation#") == 0) {
			return (MDE_PROP_VALUE(elem));
		}
	}

	return (MDESC_INVAL_GEN);
}

/*
 * Failed to allocate the list : Return value -1
 * md_scan_dag API failed      : Return the result from md_scan_dag API
 */
int
md_alloc_scan_dag(md_t *ptr,
	mde_cookie_t startnode,
	char *node_name,
	char *dag,
	mde_cookie_t **list)
{
	int res;
	md_impl_t *mdp = (md_impl_t *)ptr;

	*list = (mde_cookie_t *)mdp->allocp(sizeof (mde_cookie_t) *
	    mdp->node_count);
	if (*list == NULL)
		return (-1);

	res = md_scan_dag(ptr, startnode,
	    md_find_name(ptr, node_name),
	    md_find_name(ptr, dag), *list);

	/*
	 * If md_scan_dag API returned 0 or -1 then free the buffer
	 * and return -1 to indicate the error from this API.
	 */
	if (res < 1) {
		md_free_scan_dag(ptr, list);
		*list = NULL;
	}

	return (res);
}

void
md_free_scan_dag(md_t *ptr,
	mde_cookie_t **list)
{
	md_impl_t *mdp = (md_impl_t *)ptr;

	mdp->freep(*list, sizeof (mde_cookie_t) * mdp->node_count);
}

/*
 * Return generation number of current machine descriptor. Can be used for
 * performance purposes to avoid requesting new md handle just to see if graph
 * was updated.
 */
uint64_t
md_get_current_gen(void)
{
	uint64_t gen = MDESC_INVAL_GEN;

	mutex_enter(&curr_mach_descrip_lock);

	if (curr_mach_descrip != NULL)
		gen = (curr_mach_descrip->gen);

	mutex_exit(&curr_mach_descrip_lock);

	return (gen);
}
