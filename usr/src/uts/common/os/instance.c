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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Instance number assignment code
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/kobj.h>
#include <sys/t_lock.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/autoconf.h>
#include <sys/systeminfo.h>
#include <sys/hwconf.h>
#include <sys/reboot.h>
#include <sys/ddi_impldefs.h>
#include <sys/instance.h>
#include <sys/debug.h>
#include <sys/sysevent.h>
#include <sys/modctl.h>
#include <sys/console.h>
#include <sys/cladm.h>
#include <sys/sysmacros.h>
#include <sys/crc32.h>


static void in_preassign_instance(void);
static void i_log_devfs_instance_mod(void);
static int in_get_infile(char *);
static void in_removenode(struct devnames *dnp, in_node_t *mp, in_node_t *ap);
static in_node_t *in_alloc_node(char *name, char *addr);
static int in_eqstr(char *a, char *b);
static char *in_name_addr(char **cpp, char **addrp);
static in_node_t *in_devwalk(dev_info_t *dip, in_node_t **ap, char *addr);
static void in_dealloc_node(in_node_t *np);
static in_node_t *in_make_path(char *path);
static void in_enlist(in_node_t *ap, in_node_t *np);
static int in_inuse(int instance, char *name);
static void in_hashdrv(in_drv_t *dp);
static in_drv_t *in_drvwalk(in_node_t *np, char *binding_name);
static in_drv_t *in_alloc_drv(char *bindingname);
static void in_endrv(in_node_t *np, in_drv_t *dp);
static void in_dq_drv(in_drv_t *np);
static void in_removedrv(struct devnames *dnp, in_drv_t *mp);
static int in_pathin(char *cp, int instance, char *bname, struct bind **args);
static int in_next_instance_block(major_t, int);
static int in_next_instance(major_t);

#pragma weak plat_ioaliases_init


/* external functions */
extern char *i_binding_to_drv_name(char *bname);
extern void plat_ioaliases_init(void);

/*
 * This plus devnames defines the entire software state of the instance world.
 */
typedef struct in_softstate {
	in_node_t	*ins_root;	/* the root of our instance tree */
	in_drv_t	*ins_no_major;	/* majorless drv entries */
	/*
	 * Used to serialize access to data structures
	 */
	void		*ins_thread;
	kmutex_t	ins_serial;
	kcondvar_t	ins_serial_cv;
	int		ins_busy;
	boolean_t	ins_dirty;	/* instance info needs flush */
} in_softstate_t;

static in_softstate_t e_ddi_inst_state;

/*
 * State transition information:
 * e_ddi_inst_state contains, among other things, the root of a tree of
 * device nodes used to track instance number assignments.
 * Each device node may contain multiple driver bindings, represented
 * by a linked list of in_drv_t nodes, each with an instance assignment
 * (except for root node). Each in_drv node can be in one of 3 states,
 * indicated by ind_state:
 *
 * IN_UNKNOWN:	Each node created in this state.  The instance number of
 *	this node is not known.  ind_instance is set to -1.
 * IN_PROVISIONAL:  When a node is assigned an instance number in
 *	e_ddi_assign_instance(), its state is set to IN_PROVISIONAL.
 *	Subsequently, the framework will always call either
 *	e_ddi_keep_instance() which makes the node IN_PERMANENT
 *	or e_ddi_free_instance(), which deletes the node.
 * IN_PERMANENT:
 *	If e_ddi_keep_instance() is called on an IN_PROVISIONAL node,
 *	its state is set to IN_PERMANENT.
 */

static char *instance_file = INSTANCE_FILE;
static char *instance_file_backup = INSTANCE_FILE INSTANCE_FILE_SUFFIX;

/*
 * Return values for in_get_infile().
 */
#define	PTI_FOUND	0
#define	PTI_NOT_FOUND	1
#define	PTI_REBUILD	2

int	instance_searchme = 0;	/* testing: use complex code path */

/*
 * Path to instance file magic string used for first time boot after
 * an install.  If this is the first string in the file we will
 * automatically rebuild the file.
 */
#define	PTI_MAGIC_STR		"#path_to_inst_bootstrap_1"
#define	PTI_MAGIC_STR_LEN	(sizeof (PTI_MAGIC_STR) - 1)

void
e_ddi_instance_init(void)
{
	char *file;
	int rebuild = 1;
	struct in_drv *dp;

	mutex_init(&e_ddi_inst_state.ins_serial, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&e_ddi_inst_state.ins_serial_cv, NULL, CV_DEFAULT, NULL);

	/*
	 * Only one thread is allowed to change the state of the instance
	 * number assignments on the system at any given time.
	 * Note that this is not really necessary, as we are single-threaded
	 * here, but it won't hurt, and it allows us to keep ASSERTS for
	 * our assumptions in the code.
	 */
	e_ddi_enter_instance();

	/*
	 * Init the ioaliases if the platform supports it
	 */
	if (&plat_ioaliases_init)
		plat_ioaliases_init();

	/*
	 * Create the root node, instance zallocs to 0.
	 * The name and address of this node never get examined, we always
	 * start searching with its first child.
	 */
	ASSERT(e_ddi_inst_state.ins_root == NULL);
	e_ddi_inst_state.ins_root = in_alloc_node(NULL, NULL);
	dp = in_alloc_drv("rootnex");
	in_endrv(e_ddi_inst_state.ins_root, dp);

	file = instance_file;
	switch (in_get_infile(file)) {
	default:
	case PTI_NOT_FOUND:
		/* make sure path_to_inst is recreated */
		boothowto |= RB_RECONFIG;

		/*
		 * Something is wrong. First try the backup file.
		 * If not found, rebuild path_to_inst. Emit a
		 * message about the problem.
		 */
		cmn_err(CE_WARN, "%s empty or not found", file);

		file = instance_file_backup;
		if (in_get_infile(file) != PTI_FOUND) {
			cmn_err(CE_NOTE, "rebuilding device instance data");
			break;
		}
		cmn_err(CE_NOTE, "using backup instance data in %s", file);
		/*FALLTHROUGH*/

	case PTI_FOUND:
		/*
		 * We've got a readable file
		 * parse the file into the instance tree
		 */
		(void) read_binding_file(file, NULL, in_pathin);
		rebuild = 0;
		break;

	case PTI_REBUILD:
		/*
		 * path_to_inst has magic str requesting a create
		 * Convert boot to reconfig boot to ensure /dev is
		 * in sync with new path_to_inst.
		 */
		boothowto |= RB_RECONFIG;
		cmn_err(CE_CONT,
		    "?Using default device instance data\n");
		break;
	}

	/*
	 * The OBP device tree has been copied to the kernel and
	 * bound to drivers at this point. We walk the per-driver
	 * list to preassign instances. Since the bus addr is
	 * unknown at this point, we cannot place the instance
	 * number in the instance tree. This will be done at
	 * a later time.
	 */
	if (rebuild)
		in_preassign_instance();

	e_ddi_exit_instance();
}

static void
in_preassign_instance()
{
	major_t		m;
	struct devnames	*dnp;
	dev_info_t	*dip;
	extern major_t	devcnt;

	for (m = 0; m < devcnt; m++) {
		dnp = &devnamesp[m];
		dip = dnp->dn_head;
		while (dip) {
			DEVI(dip)->devi_instance = dnp->dn_instance;
			dnp->dn_instance++;
			dip = ddi_get_next(dip);
		}

		/*
		 * The preassign instance numbers are not fully
		 * accounted for until e_ddi_assign_instance().
		 * We can't fully account for them now because we
		 * don't currently have a unit-address. Because of
		 * this, we need to remember the preassign boundary
		 * to avoid ordering issues related to
		 * e_ddi_assign_instance of a preassigned value .vs.
		 * re-assignment of the same value for a dynamic
		 * SID node created by bus_config.
		 */
		dnp->dn_pinstance = dnp->dn_instance;
		dnp->dn_instance = IN_SEARCHME;
	}
}

/*
 * Checks to see if the /etc/path_to_inst file exists and whether or not
 * it has the magic string in it.
 *
 * Returns one of the following:
 *
 *	PTI_FOUND	- We have found the /etc/path_to_inst file
 *	PTI_REBUILD	- We have found the /etc/path_to_inst file and the
 *			  first line was PTI_MAGIC_STR.
 *	PTI_NOT_FOUND	- We did not find the /etc/path_to_inst file
 *
 */
static int
in_get_infile(char *filename)
{
	struct _buf *file;
	int return_val;
	char buf[PTI_MAGIC_STR_LEN];

	/*
	 * Try to open the file.
	 */
	if ((file = kobj_open_file(filename)) == (struct _buf *)-1) {
		return (PTI_NOT_FOUND);
	}
	return_val = PTI_FOUND;

	/*
	 * Read the first PTI_MAGIC_STR_LEN bytes from the file to see if
	 * it contains the magic string.  If there aren't that many bytes
	 * in the file, then assume file is correct and no magic string
	 * and move on.
	 */
	switch (kobj_read_file(file, buf, PTI_MAGIC_STR_LEN, 0)) {

	case PTI_MAGIC_STR_LEN:
		/*
		 * If the first PTI_MAGIC_STR_LEN bytes are the magic string
		 * then return PTI_REBUILD.
		 */
		if (strncmp(PTI_MAGIC_STR, buf, PTI_MAGIC_STR_LEN) == 0)
			return_val = PTI_REBUILD;
		break;

	case 0:
		/*
		 * If the file is zero bytes in length, then consider the
		 * file to not be found
		 */
		return_val = PTI_NOT_FOUND;

	default: /* Do nothing we have a good file */
		break;
	}

	kobj_close_file(file);
	return (return_val);
}

int
is_pseudo_device(dev_info_t *dip)
{
	dev_info_t	*pdip;

	for (pdip = ddi_get_parent(dip); pdip && pdip != ddi_root_node();
	    pdip = ddi_get_parent(pdip)) {
		if (strcmp(ddi_get_name(pdip), DEVI_PSEUDO_NEXNAME) == 0)
			return (1);
	}
	return (0);
}


static void
in_set_instance(dev_info_t *dip, in_drv_t *dp, major_t major)
{
	/* use preassigned instance if available */
	if (DEVI(dip)->devi_instance != -1)
		dp->ind_instance = DEVI(dip)->devi_instance;
	else
		dp->ind_instance = in_next_instance(major);
}

/*
 * Return 1 if instance block was assigned for the path.
 *
 * For multi-port NIC cards, sequential instance assignment across all
 * ports on a card is highly desirable since the ppa is typically the
 * same as the instance number, and the ppa is used in the NIC's public
 * /dev name. This sequential assignment typically occurs as a result
 * of in_preassign_instance() after initial install, or by
 * i_ndi_init_hw_children() for NIC ports that share a common parent.
 *
 * Some NIC cards however use multi-function bridge chips, and to
 * support sequential instance assignment accross all ports, without
 * disabling multi-threaded attach, we have a (currently) undocumented
 * hack to allocate instance numbers in contiguous blocks based on
 * driver.conf properties.
 *
 *                       ^
 *           /----------   ------------\
 *        pci@0                      pci@0,1	MULTI-FUNCTION BRIDGE CHIP
 *       /     \                    /       \
 * FJSV,e4ta@4  FJSV,e4ta@4,1   FJSV,e4ta@6 FJSV,e4ta@6,1	NIC PORTS
 *      n            n+2             n+2         n+3		INSTANCE
 *
 * For the above example, the following driver.conf properties would be
 * used to guarantee sequential instance number assignment.
 *
 * ddi-instance-blocks ="ib-FJSVe4ca", "ib-FJSVe4ta", "ib-generic";
 * ib-FJSVe4ca =	"/pci@0/FJSV,e4ca@4", "/pci@0/FJSV,e4ca@4,1",
 *			"/pci@0,1/FJSV,e4ca@6", "/pci@0,1/FJSV,e4ca@6,1";
 * ib-FJSVe4ta =	"/pci@0/FJSV,e4ta@4", "/pci@0/FJSV,e4ta@4,1",
 *			"/pci@0,1/FJSV,e4ta@6", "/pci@0,1/FJSV,e4ta@6,1";
 * ib-generic =		"/pci@0/network@4", "/pci@0/network@4,1",
 *			"/pci@0,1/network@6", "/pci@0,1/network@6,1";
 *
 * The value of the 'ddi-instance-blocks' property references a series
 * of card specific properties, like 'ib-FJSV-e4ta', who's value
 * defines a single 'instance block'.  The 'instance block' describes
 * all the paths below a multi-function bridge, where each path is
 * called an 'instance path'.  The 'instance block' property value is a
 * series of 'instance paths'.  The number of 'instance paths' in an
 * 'instance block' defines the size of the instance block, and the
 * ordering of the 'instance paths' defines the instance number
 * assignment order for paths going through the 'instance block'.
 *
 * In the instance assignment code below, if a (path, driver) that
 * currently has no instance number has a path that goes through an
 * 'instance block', then block instance number allocation occurs.  The
 * block allocation code will find a sequential set of unused instance
 * numbers, and assign instance numbers for all the paths in the
 * 'instance block'.  Each path is assigned a persistent instance
 * number, even paths that don't exist in the device tree or fail
 * probe(9E).
 */
static int
in_assign_instance_block(dev_info_t *dip)
{
	char		**ibn;		/* instance block names */
	uint_t		nibn;		/* number of instance block names */
	uint_t		ibni;		/* ibn index */
	char		*driver;
	major_t		major;
	char		*path;
	char		*addr;
	int		plen;
	char		**ibp;		/* instance block paths */
	uint_t		nibp;		/* number of paths in instance block */
	uint_t		ibpi;		/* ibp index */
	int		ibplen;		/* length of instance block path */
	char		*ipath;
	int		instance_base;
	int		splice;
	int		i;

	/* check for fresh install case (in miniroot) */
	if (DEVI(dip)->devi_instance != -1)
		return (0);			/* already assigned */

	/*
	 * Check to see if we need to allocate a block of contiguous instance
	 * numbers by looking for the 'ddi-instance-blocks' property.
	 */
	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "ddi-instance-blocks", &ibn, &nibn) != DDI_SUCCESS)
		return (0);			/* no instance block needed */

	/*
	 * Get information out about node we are processing.
	 *
	 * NOTE: Since the node is not yet at DS_INITIALIZED, ddi_pathname()
	 * will not return the unit-address of the final path component even
	 * though the node has an established devi_addr unit-address - so we
	 * need to add the unit-address by hand.
	 */
	driver = (char *)ddi_driver_name(dip);
	major = ddi_driver_major(dip);
	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, path);
	if ((addr =  ddi_get_name_addr(dip)) != NULL) {
		(void) strcat(path, "@");
		(void) strcat(path, addr);
	}
	plen = strlen(path);

	/* loop through instance block names */
	for (ibni = 0; ibni < nibn; ibni++) {
		if (ibn[ibni] == NULL)
			continue;

		/* lookup instance block */
		if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, ibn[ibni],
		    &ibp, &nibp) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "no devinition for instance block '%s' in %s.conf",
			    ibn[ibni], driver);
			continue;
		}

		/* Does 'path' go through this instance block? */
		for (ibpi = 0; ibpi < nibp; ibpi++) {
			if (ibp[ibpi] == NULL)
				continue;
			ibplen = strlen(ibp[ibpi]);
			if ((ibplen <= plen) &&
			    (strcmp(ibp[ibpi], path + plen - ibplen) == 0))
				break;

		}
		if (ibpi >= nibp) {
			ddi_prop_free(ibp);
			continue;		/* no try next instance block */
		}

		/* yes, allocate and assign instances for all paths in block */

		/*
		 * determine where we splice in instance paths and verify
		 * that none of the paths are too long.
		 */
		splice = plen - ibplen;
		for (i = 0; i < nibp; i++) {
			if ((splice + strlen(ibp[i])+ 1) >= MAXPATHLEN) {
				cmn_err(CE_WARN,
				    "path %d through instance block '%s' from "
				    "%s.conf too long", i, ibn[ibni], driver);
				break;
			}
		}
		if (i < nibp) {
			ddi_prop_free(ibp);
			continue;		/* too long */
		}

		/* allocate the instance block - no more failures */
		instance_base = in_next_instance_block(major, nibp);

		ipath = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		for (ibpi = 0; ibpi < nibp; ibpi++) {
			if (ibp[ibpi] == NULL)
				continue;
			(void) strcpy(ipath, path);
			(void) strcpy(ipath + splice, ibp[ibpi]);
			(void) in_pathin(ipath,
			    instance_base + ibpi, driver, NULL);
		}

		/* free allocations */
		kmem_free(ipath, MAXPATHLEN);
		ddi_prop_free(ibp);
		kmem_free(path, MAXPATHLEN);
		ddi_prop_free(ibn);

		/* notify devfsadmd to sync of path_to_inst file */
		mutex_enter(&e_ddi_inst_state.ins_serial);
		i_log_devfs_instance_mod();
		e_ddi_inst_state.ins_dirty = B_TRUE;
		mutex_exit(&e_ddi_inst_state.ins_serial);
		return (1);
	}

	/* our path did not go through any of of the instance blocks */
	kmem_free(path, MAXPATHLEN);
	ddi_prop_free(ibn);
	return (0);
}

/*
 * Look up an instance number for a dev_info node, and assign one if it does
 * not have one (the dev_info node has devi_name and devi_addr already set).
 */
uint_t
e_ddi_assign_instance(dev_info_t *dip)
{
	char *name;
	in_node_t *ap, *np;
	in_drv_t *dp;
	major_t major;
	uint_t ret;
	char *bname;

	/*
	 * Allow implementation to override
	 */
	if ((ret = impl_assign_instance(dip)) != (uint_t)-1)
		return (ret);

	/*
	 * If this is a pseudo-device, use the instance number
	 * assigned by the pseudo nexus driver. The mutex is
	 * not needed since the instance tree is not used.
	 */
	if (is_pseudo_device(dip)) {
		return (ddi_get_instance(dip));
	}

	/*
	 * Only one thread is allowed to change the state of the instance
	 * number assignments on the system at any given time.
	 */
	e_ddi_enter_instance();

	/*
	 * Look for instance node, allocate one if not found
	 */
	np = in_devwalk(dip, &ap, NULL);
	if (np == NULL) {
		if (in_assign_instance_block(dip)) {
			np = in_devwalk(dip, &ap, NULL);
		} else {
			name = ddi_node_name(dip);
			np = in_alloc_node(name, ddi_get_name_addr(dip));
			ASSERT(np != NULL);
			in_enlist(ap, np);	/* insert into tree */
		}
	}
	ASSERT(np == in_devwalk(dip, &ap, NULL));

	/*
	 * Link the devinfo node and in_node_t
	 */
	if (DEVI(dip)->devi_in_node || np->in_devi) {
		ddi_err(DER_MODE, dip, "devinfo and  instance node (%p) "
		    "interlink fields are not NULL", (void *)np);
	}
	DEVI(dip)->devi_in_node = np;
	np->in_devi = dip;

	/*
	 * Look for driver entry, allocate one if not found
	 */
	bname = (char *)ddi_driver_name(dip);
	dp = in_drvwalk(np, bname);
	if (dp == NULL) {

		if (ddi_aliases_present == B_TRUE) {
			e_ddi_borrow_instance(dip, np);
		}

		if ((dp = in_drvwalk(np, bname)) == NULL) {
			dp = in_alloc_drv(bname);
			ASSERT(dp != NULL);
			major = ddi_driver_major(dip);
			ASSERT(major != DDI_MAJOR_T_NONE);
			in_endrv(np, dp);
			in_set_instance(dip, dp, major);
			dp->ind_state = IN_PROVISIONAL;
			in_hashdrv(dp);
		} else {
			dp->ind_state = IN_BORROWED;
		}
	}

	ret = dp->ind_instance;

	e_ddi_exit_instance();
	return (ret);
}

static int
mkpathname(char *path, in_node_t *np, int len)
{
	int len_needed;

	if (np == e_ddi_inst_state.ins_root)
		return (DDI_SUCCESS);

	if (mkpathname(path, np->in_parent, len) == DDI_FAILURE)
		return (DDI_FAILURE);

	len_needed = strlen(path);
	len_needed += strlen(np->in_node_name) + 1;	/* for '/' */
	if (np->in_unit_addr) {
		len_needed += strlen(np->in_unit_addr) + 1;  /* for '@' */
	}
	len_needed += 1; /* for '\0' */

	/*
	 * XX complain
	 */
	if (len_needed > len)
		return (DDI_FAILURE);

	if (np->in_unit_addr[0] == '\0')
		(void) sprintf(path+strlen(path), "/%s", np->in_node_name);
	else
		(void) sprintf(path+strlen(path), "/%s@%s", np->in_node_name,
		    np->in_unit_addr);

	return (DDI_SUCCESS);
}

/*
 * produce the path to the given instance of a major number.
 * path must hold MAXPATHLEN string
 */
int
e_ddi_instance_majorinstance_to_path(major_t major, uint_t inst, char *path)
{
	struct devnames	*dnp;
	in_drv_t	*dp;
	int		ret;

	e_ddi_enter_instance();

	/* look for the instance threaded off major */
	dnp = &devnamesp[major];
	for (dp = dnp->dn_inlist; dp != NULL; dp = dp->ind_next)
		if (dp->ind_instance == inst)
			break;

	/* produce path from the node that uses the instance */
	if (dp) {
		*path = 0;
		ret = mkpathname(path, dp->ind_node, MAXPATHLEN);
	} else
		ret = DDI_FAILURE;

	e_ddi_exit_instance();
	return (ret);
}

/*
 * Allocate a sequential block of instance numbers for the specified driver,
 * and return the base instance number of the block.  The implementation
 * depends on the list being sorted in ascending instance number sequence.
 * When there are no 'holes' in the allocation sequence, dn_instance is the
 * next available instance number. When dn_instance is IN_SEARCHME, hole(s)
 * exists and a slower code path executes which tries to fill holes.
 *
 * The block returned can't be in the preassigned range.
 */
static int
in_next_instance_block(major_t major, int block_size)
{
	int		prev;
	struct devnames	*dnp;
	in_drv_t	*dp;
	int		base;
	int		hole;

	dnp = &devnamesp[major];
	ASSERT(major != DDI_MAJOR_T_NONE);
	ASSERT(e_ddi_inst_state.ins_busy);
	ASSERT(block_size);

	/* check to see if we can do a quick allocation */
	if (!instance_searchme && (dnp->dn_instance != IN_SEARCHME)) {
		base = dnp->dn_instance;
		dnp->dn_instance += block_size;
		return (base);
	}

	/*
	 * Use more complex code path, start by skipping preassign entries.
	 */
	for (dp = dnp->dn_inlist; dp; dp = dp->ind_next)
		if (dp->ind_instance >= dnp->dn_pinstance)
			break;		/* beyond preassign */

	/* No non-preassign entries, allocate block at preassign base. */
	if (dp == NULL) {
		base = dnp->dn_pinstance;
		if (base == 0)
			dnp->dn_instance = block_size;
		return (base);
	}

	/* See if we fit in hole at beginning (after preassigns) */
	prev = dp->ind_instance;
	if ((prev - dnp->dn_pinstance) >= block_size)
		return (dnp->dn_pinstance);	/* we fit in beginning hole */

	/* search the list for a large enough hole */
	for (dp = dp->ind_next, hole = 0; dp; dp = dp->ind_next) {
		if (dp->ind_instance != (prev + 1))
			hole++;			/* we have a hole */
		if (dp->ind_instance >= (prev + block_size + 1))
			break;			/* we fit in hole */
		prev = dp->ind_instance;
	}

	/*
	 * If hole is zero then all holes are patched and we can resume
	 * quick allocations, but don't resume quick allocation if there is
	 * a preassign.
	 */
	if ((hole == 0) && (dnp->dn_pinstance == 0))
		dnp->dn_instance = prev + 1 + block_size;

	return (prev + 1);
}

/* assign instance block of size 1 */
static int
in_next_instance(major_t major)
{
	return (in_next_instance_block(major, 1));
}

/*
 * This call causes us to *forget* the instance number we've generated
 * for a given device if it was not permanent.
 */
void
e_ddi_free_instance(dev_info_t *dip, char *addr)
{
	char *name;
	in_node_t *np;
	in_node_t *ap;	/* ancestor node */
	major_t major;
	struct devnames *dnp;
	in_drv_t *dp;	/* in_drv entry */

	/*
	 * Allow implementation override
	 */
	if (impl_free_instance(dip) == DDI_SUCCESS)
		return;

	/*
	 * If this is a pseudo-device, no instance number
	 * was assigned.
	 */
	if (is_pseudo_device(dip)) {
		return;
	}

	name = (char *)ddi_driver_name(dip);
	major = ddi_driver_major(dip);
	ASSERT(major != DDI_MAJOR_T_NONE);
	dnp = &devnamesp[major];
	/*
	 * Only one thread is allowed to change the state of the instance
	 * number assignments on the system at any given time.
	 */
	e_ddi_enter_instance();
	np = in_devwalk(dip, &ap, addr);
	ASSERT(np);

	/*
	 * Break the interlink between dip and np
	 */
	if (DEVI(dip)->devi_in_node != np || np->in_devi != dip) {
		ddi_err(DER_MODE, dip, "devinfo node linked to "
		    "wrong instance node: %p", (void *)np);
	}
	DEVI(dip)->devi_in_node = NULL;
	np->in_devi = NULL;

	dp = in_drvwalk(np, name);
	ASSERT(dp);
	if (dp->ind_state == IN_PROVISIONAL) {
		in_removedrv(dnp, dp);
	} else if (dp->ind_state == IN_BORROWED) {
		dp->ind_state = IN_PERMANENT;
		e_ddi_return_instance(dip, addr, np);
	}
	if (np->in_drivers == NULL) {
		in_removenode(dnp, np, ap);
	}
	e_ddi_exit_instance();
}

/*
 * This makes our memory of an instance assignment permanent
 */
void
e_ddi_keep_instance(dev_info_t *dip)
{
	in_node_t *np, *ap;
	in_drv_t *dp;

	/* Don't make nulldriver instance assignments permanent */
	if (ddi_driver_major(dip) == nulldriver_major)
		return;

	/*
	 * Allow implementation override
	 */
	if (impl_keep_instance(dip) == DDI_SUCCESS)
		return;

	/*
	 * Nothing to do for pseudo devices.
	 */
	if (is_pseudo_device(dip))
		return;

	/*
	 * Only one thread is allowed to change the state of the instance
	 * number assignments on the system at any given time.
	 */
	e_ddi_enter_instance();
	np = in_devwalk(dip, &ap, NULL);
	ASSERT(np);
	dp = in_drvwalk(np, (char *)ddi_driver_name(dip));
	ASSERT(dp);

	mutex_enter(&e_ddi_inst_state.ins_serial);
	if (dp->ind_state == IN_PROVISIONAL || dp->ind_state == IN_BORROWED) {
		dp->ind_state = IN_PERMANENT;
		i_log_devfs_instance_mod();
		e_ddi_inst_state.ins_dirty = B_TRUE;
	}
	mutex_exit(&e_ddi_inst_state.ins_serial);
	e_ddi_exit_instance();
}

/*
 * A new major has been added to the system.  Run through the orphan list
 * and try to attach each one to a driver's list.
 */
void
e_ddi_unorphan_instance_nos()
{
	in_drv_t *dp, *ndp;

	/*
	 * disconnect the orphan list, and call in_hashdrv for each item
	 * on it
	 */

	/*
	 * Only one thread is allowed to change the state of the instance
	 * number assignments on the system at any given time.
	 */
	e_ddi_enter_instance();
	if (e_ddi_inst_state.ins_no_major == NULL) {
		e_ddi_exit_instance();
		return;
	}
	/*
	 * Hash instance list to devnames structure of major.
	 * Note that if there is not a valid major number for the
	 * node, in_hashdrv will put it back on the no_major list.
	 */
	dp = e_ddi_inst_state.ins_no_major;
	e_ddi_inst_state.ins_no_major = NULL;
	while (dp) {
		ndp = dp->ind_next;
		ASSERT(dp->ind_state != IN_UNKNOWN);
		dp->ind_next = NULL;
		in_hashdrv(dp);
		dp = ndp;
	}
	e_ddi_exit_instance();
}

static void
in_removenode(struct devnames *dnp, in_node_t *mp, in_node_t *ap)
{
	in_node_t *np;

	ASSERT(e_ddi_inst_state.ins_busy);

	/*
	 * Assertion: parents are always instantiated by the framework
	 * before their children, destroyed after them
	 */
	ASSERT(mp->in_child == NULL);
	/*
	 * Assertion: drv entries are always removed before their owning nodes
	 */
	ASSERT(mp->in_drivers == NULL);
	/*
	 * Take the node out of the tree
	 */
	if (ap->in_child == mp) {
		ap->in_child = mp->in_sibling;
		in_dealloc_node(mp);
		return;
	} else {
		for (np = ap->in_child; np; np = np->in_sibling) {
			if (np->in_sibling == mp) {
				np->in_sibling = mp->in_sibling;
				in_dealloc_node(mp);
				return;
			}
		}
	}
	panic("in_removenode dnp %p mp %p", (void *)dnp, (void *)mp);
}

/*
 * Recursive ascent
 *
 * This now only does half the job.  It finds the node, then the caller
 * has to search the node for the binding name
 */
static in_node_t *
in_devwalk(dev_info_t *dip, in_node_t **ap, char *addr)
{
	in_node_t *np;
	char *name;

	ASSERT(dip);
	ASSERT(e_ddi_inst_state.ins_busy);
	if (dip == ddi_root_node()) {
		*ap = NULL;
		return (e_ddi_inst_state.ins_root);
	}
	/*
	 * call up to find parent, then look through the list of kids
	 * for a match
	 */
	np = in_devwalk(ddi_get_parent(dip), ap, NULL);
	if (np == NULL)
		return (np);
	*ap = np;
	np = np->in_child;
	name = ddi_node_name(dip);
	if (addr == NULL)
		addr = ddi_get_name_addr(dip);

	while (np) {
		if (in_eqstr(np->in_node_name, name) &&
		    in_eqstr(np->in_unit_addr, addr)) {
			return (np);
		}
		np = np->in_sibling;
	}

	return (np);
}

/*
 * Create a node specified by cp and assign it the given instance no.
 */
static int
in_pathin(char *cp, int instance, char *bname, struct bind **args)
{
	in_node_t *np;
	in_drv_t *dp;
	char *name;

	ASSERT(e_ddi_inst_state.ins_busy);
	ASSERT(args == NULL);

	/*
	 * Give a warning to the console.
	 * return value ignored
	 */
	if (cp[0] != '/' || instance == -1 || bname == NULL) {
		cmn_err(CE_WARN,
		    "invalid instance file entry %s %d",
		    cp, instance);
		return (0);
	}

	if ((name  = i_binding_to_drv_name(bname)) != NULL)
		bname = name;

	np = in_make_path(cp);
	ASSERT(np);

	dp = in_drvwalk(np, bname);
	if (dp != NULL) {
		cmn_err(CE_WARN,
		    "multiple instance number assignments for "
		    "'%s' (driver %s), %d used",
		    cp, bname, dp->ind_instance);
		return (0);
	}

	if (in_inuse(instance, bname)) {
		cmn_err(CE_WARN,
		    "instance already in use: %s %d", cp, instance);
		return (0);
	}

	dp = in_alloc_drv(bname);
	in_endrv(np, dp);
	dp->ind_instance = instance;
	dp->ind_state = IN_PERMANENT;
	in_hashdrv(dp);

	return (0);
}

/*
 * Create (or find) the node named by path by recursively descending from the
 * root's first child (we ignore the root, which is never named)
 */
static in_node_t *
in_make_path(char *path)
{
	in_node_t *ap;		/* ancestor pointer */
	in_node_t *np;		/* working node pointer */
	in_node_t *rp;		/* return node pointer */
	char buf[MAXPATHLEN];	/* copy of string so we can change it */
	char *cp, *name, *addr;

	ASSERT(e_ddi_inst_state.ins_busy);

	if (path == NULL || path[0] != '/')
		return (NULL);

	(void) snprintf(buf, sizeof (buf), "%s", path);
	cp = buf + 1;	/* skip over initial '/' in path */
	name = in_name_addr(&cp, &addr);

	/*
	 * In S9 and earlier releases, the path_to_inst file
	 * SunCluster was prepended with "/node@#". This was
	 * removed in S10. We skip the prefix if the prefix
	 * still exists in /etc/path_to_inst. It is needed for
	 * various forms of Solaris upgrade to work properly
	 * in the SunCluster environment.
	 */
	if ((cluster_bootflags & CLUSTER_CONFIGURED) &&
	    (strcmp(name, "node") == 0))
		name = in_name_addr(&cp, &addr);

	ap = e_ddi_inst_state.ins_root;
	np = e_ddi_inst_state.ins_root->in_child;
	rp = np;
	while (name) {
		while (name && np) {
			if (in_eqstr(name, np->in_node_name) &&
			    in_eqstr(addr, np->in_unit_addr)) {
				name = in_name_addr(&cp, &addr);
				if (name == NULL)
					return (np);
				ap = np;
				np = np->in_child;
			} else {
				np = np->in_sibling;
			}
		}
		np = in_alloc_node(name, addr);
		in_enlist(ap, np);	/* insert into tree */
		rp = np;	/* value to return if we quit */
		ap = np;	/* new parent */
		np = NULL;	/* can have no children */
		name = in_name_addr(&cp, &addr);
	}

	return (rp);
}

/*
 * Insert node np into the tree as one of ap's children.
 */
static void
in_enlist(in_node_t *ap, in_node_t *np)
{
	in_node_t *mp;
	ASSERT(e_ddi_inst_state.ins_busy);
	/*
	 * Make this node some other node's child or child's sibling
	 */
	ASSERT(ap && np);
	if (ap->in_child == NULL) {
		ap->in_child = np;
	} else {
		for (mp = ap->in_child; mp; mp = mp->in_sibling)
			if (mp->in_sibling == NULL) {
				mp->in_sibling = np;
				break;
			}
	}
	np->in_parent = ap;
}

/*
 * Insert drv entry dp onto a node's driver list
 */
static void
in_endrv(in_node_t *np, in_drv_t *dp)
{
	in_drv_t *mp;
	ASSERT(e_ddi_inst_state.ins_busy);
	ASSERT(np && dp);
	mp = np->in_drivers;
	np->in_drivers = dp;
	dp->ind_next_drv = mp;
	dp->ind_node = np;
}

/*
 * Parse the next name out of the path, null terminate it and update cp.
 * caller has copied string so we can mess with it.
 * Upon return *cpp points to the next section to be parsed, *addrp points
 * to the current address substring (or NULL if none) and we return the
 * current name substring (or NULL if none).  name and address substrings
 * are null terminated in place.
 */

static char *
in_name_addr(char **cpp, char **addrp)
{
	char *namep;	/* return value holder */
	char *ap;	/* pointer to '@' in string */
	char *sp;	/* pointer to '/' in string */

	if (*cpp == NULL || **cpp == '\0') {
		*addrp = NULL;
		return (NULL);
	}
	namep = *cpp;
	sp = strchr(*cpp, '/');
	if (sp != NULL) {	/* more to follow */
		*sp = '\0';
		*cpp = sp + 1;
	} else {		/* this is last component. */
		*cpp = NULL;
	}
	ap = strchr(namep, '@');
	if (ap == NULL) {
		*addrp = NULL;
	} else {
		*ap = '\0';		/* terminate the name */
		*addrp = ap + 1;
	}
	return (namep);
}

/*
 * Allocate a node and storage for name and addr strings, and fill them in.
 */
static in_node_t *
in_alloc_node(char *name, char *addr)
{
	in_node_t *np;
	char *cp;
	size_t namelen;

	ASSERT(e_ddi_inst_state.ins_busy);
	/*
	 * Has name or will become root
	 */
	ASSERT(name || e_ddi_inst_state.ins_root == NULL);
	if (addr == NULL)
		addr = "";
	if (name == NULL)
		namelen = 0;
	else
		namelen = strlen(name) + 1;
	cp = kmem_zalloc(sizeof (in_node_t) + namelen + strlen(addr) + 1,
	    KM_SLEEP);
	np = (in_node_t *)cp;
	if (name) {
		np->in_node_name = cp + sizeof (in_node_t);
		(void) strcpy(np->in_node_name, name);
	}
	np->in_unit_addr = cp + sizeof (in_node_t) + namelen;
	(void) strcpy(np->in_unit_addr, addr);
	return (np);
}

/*
 * Allocate a drv entry and storage for binding name string, and fill it in.
 */
static in_drv_t *
in_alloc_drv(char *bindingname)
{
	in_drv_t *dp;
	char *cp;
	size_t namelen;

	ASSERT(e_ddi_inst_state.ins_busy);
	/*
	 * Has name or will become root
	 */
	ASSERT(bindingname || e_ddi_inst_state.ins_root == NULL);
	if (bindingname == NULL)
		namelen = 0;
	else
		namelen = strlen(bindingname) + 1;
	cp = kmem_zalloc(sizeof (in_drv_t) + namelen, KM_SLEEP);
	dp = (in_drv_t *)cp;
	if (bindingname) {
		dp->ind_driver_name = cp + sizeof (in_drv_t);
		(void) strcpy(dp->ind_driver_name, bindingname);
	}
	dp->ind_state = IN_UNKNOWN;
	dp->ind_instance = -1;
	return (dp);
}

static void
in_dealloc_node(in_node_t *np)
{
	/*
	 * The root node can never be de-allocated
	 */
	ASSERT(np->in_node_name && np->in_unit_addr);
	ASSERT(e_ddi_inst_state.ins_busy);
	kmem_free(np, sizeof (in_node_t) + strlen(np->in_node_name)
	    + strlen(np->in_unit_addr) + 2);
}

static void
in_dealloc_drv(in_drv_t *dp)
{
	ASSERT(dp->ind_driver_name);
	ASSERT(e_ddi_inst_state.ins_busy);
	kmem_free(dp, sizeof (in_drv_t) + strlen(dp->ind_driver_name)
	    + 1);
}

/*
 * Handle the various possible versions of "no address"
 */
static int
in_eqstr(char *a, char *b)
{
	if (a == b)	/* covers case where both are nulls */
		return (1);
	if (a == NULL && *b == 0)
		return (1);
	if (b == NULL && *a == 0)
		return (1);
	if (a == NULL || b == NULL)
		return (0);
	return (strcmp(a, b) == 0);
}

/*
 * Returns true if instance no. is already in use by named driver
 */
static int
in_inuse(int instance, char *name)
{
	major_t major;
	in_drv_t *dp;
	struct devnames *dnp;

	ASSERT(e_ddi_inst_state.ins_busy);
	/*
	 * For now, if we've never heard of this device we assume it is not
	 * in use, since we can't tell
	 * XXX could do the weaker search through the nomajor list checking
	 * XXX for the same name
	 */
	if ((major = ddi_name_to_major(name)) == DDI_MAJOR_T_NONE)
		return (0);
	dnp = &devnamesp[major];

	dp = dnp->dn_inlist;
	while (dp) {
		if (dp->ind_instance == instance)
			return (1);
		dp = dp->ind_next;
	}
	return (0);
}

static void
in_hashdrv(in_drv_t *dp)
{
	struct devnames *dnp;
	in_drv_t *mp, *pp;
	major_t major;

	/* hash to no major list */
	major = ddi_name_to_major(dp->ind_driver_name);
	if (major == DDI_MAJOR_T_NONE) {
		dp->ind_next = e_ddi_inst_state.ins_no_major;
		e_ddi_inst_state.ins_no_major = dp;
		return;
	}

	/*
	 * dnp->dn_inlist is sorted by instance number.
	 * Adding a new instance entry may introduce holes,
	 * set dn_instance to IN_SEARCHME so the next instance
	 * assignment may fill in holes.
	 */
	dnp = &devnamesp[major];
	pp = mp = dnp->dn_inlist;
	if (mp == NULL || dp->ind_instance < mp->ind_instance) {
		/* prepend as the first entry, turn on IN_SEARCHME */
		dnp->dn_instance = IN_SEARCHME;
		dp->ind_next = mp;
		dnp->dn_inlist = dp;
		return;
	}

	ASSERT(mp->ind_instance != dp->ind_instance);
	while (mp->ind_instance < dp->ind_instance && mp->ind_next) {
		pp = mp;
		mp = mp->ind_next;
		ASSERT(mp->ind_instance != dp->ind_instance);
	}

	if (mp->ind_instance < dp->ind_instance) { /* end of list */
		dp->ind_next = NULL;
		mp->ind_next = dp;
	} else {
		dp->ind_next = pp->ind_next;
		pp->ind_next = dp;
	}
}

/*
 * Remove a driver entry from the list, given a previous pointer
 */
static void
in_removedrv(struct devnames *dnp, in_drv_t *mp)
{
	in_drv_t *dp;
	in_drv_t *prevp;

	if (dnp->dn_inlist == mp) {	/* head of list */
		dnp->dn_inlist = mp->ind_next;
		dnp->dn_instance = IN_SEARCHME;
		in_dq_drv(mp);
		in_dealloc_drv(mp);
		return;
	}
	prevp = dnp->dn_inlist;
	for (dp = prevp->ind_next; dp; dp = dp->ind_next) {
		if (dp == mp) {		/* found it */
			break;
		}
		prevp = dp;
	}

	ASSERT(dp == mp);
	dnp->dn_instance = IN_SEARCHME;
	prevp->ind_next = mp->ind_next;
	in_dq_drv(mp);
	in_dealloc_drv(mp);
}

static void
in_dq_drv(in_drv_t *mp)
{
	struct in_node *node = mp->ind_node;
	in_drv_t *ptr, *prev;

	if (mp == node->in_drivers) {
		node->in_drivers = mp->ind_next_drv;
		return;
	}
	prev = node->in_drivers;
	for (ptr = prev->ind_next_drv; ptr != (struct in_drv *)NULL;
	    ptr = ptr->ind_next_drv) {
		if (ptr == mp) {
			prev->ind_next_drv = ptr->ind_next_drv;
			return;
		}
		prev = ptr;
	}
	panic("in_dq_drv: in_drv not found on node driver list");
}


in_drv_t *
in_drvwalk(in_node_t *np, char *binding_name)
{
	char *name;
	in_drv_t *dp = np->in_drivers;
	while (dp) {
		if ((name = i_binding_to_drv_name(dp->ind_driver_name))
		    == NULL) {
			name = dp->ind_driver_name;
		}
		if (strcmp(binding_name, name) == 0) {
			break;
		}
		dp = dp->ind_next_drv;
	}
	return (dp);
}



static void
i_log_devfs_instance_mod(void)
{
	sysevent_t	*ev;
	sysevent_id_t	eid;
	static int	sent_one = 0;

	/*
	 * Prevent unnecessary event generation.  Do not generate more than
	 * one event during boot.
	 */
	if (sent_one && !i_ddi_io_initialized())
		return;

	ev = sysevent_alloc(EC_DEVFS, ESC_DEVFS_INSTANCE_MOD, EP_DDI,
	    SE_NOSLEEP);
	if (ev == NULL) {
		return;
	}
	if (log_sysevent(ev, SE_NOSLEEP, &eid) != 0) {
		cmn_err(CE_WARN, "i_log_devfs_instance_mod: failed to post "
		    "event");
	} else {
		sent_one = 1;
	}
	sysevent_free(ev);
}

void
e_ddi_enter_instance(void)
{
	mutex_enter(&e_ddi_inst_state.ins_serial);
	if (e_ddi_inst_state.ins_thread == curthread)
		e_ddi_inst_state.ins_busy++;
	else {
		while (e_ddi_inst_state.ins_busy)
			cv_wait(&e_ddi_inst_state.ins_serial_cv,
			    &e_ddi_inst_state.ins_serial);
		e_ddi_inst_state.ins_thread = curthread;
		e_ddi_inst_state.ins_busy = 1;
	}
	mutex_exit(&e_ddi_inst_state.ins_serial);
}

void
e_ddi_exit_instance(void)
{
	mutex_enter(&e_ddi_inst_state.ins_serial);
	e_ddi_inst_state.ins_busy--;
	if (e_ddi_inst_state.ins_busy == 0) {
		cv_broadcast(&e_ddi_inst_state.ins_serial_cv);
		e_ddi_inst_state.ins_thread = NULL;
	}
	mutex_exit(&e_ddi_inst_state.ins_serial);
}

int
e_ddi_instance_is_clean(void)
{
	return (e_ddi_inst_state.ins_dirty == B_FALSE);
}

void
e_ddi_instance_set_clean(void)
{
	e_ddi_inst_state.ins_dirty = B_FALSE;
}

in_node_t *
e_ddi_instance_root(void)
{
	return (e_ddi_inst_state.ins_root);
}

/*
 * Visit a node in the instance tree
 */
static int
in_walk_instances(in_node_t *np, char *path, char *this,
    int (*f)(const char *, in_node_t *, in_drv_t *, void *), void *arg)
{
	in_drv_t *dp;
	int rval = INST_WALK_CONTINUE;
	char *next;

	while (np != NULL) {

		if (np->in_unit_addr[0] == 0)
			(void) sprintf(this, "/%s", np->in_node_name);
		else
			(void) sprintf(this, "/%s@%s", np->in_node_name,
			    np->in_unit_addr);
		next = this + strlen(this);

		for (dp = np->in_drivers; dp; dp = dp->ind_next_drv) {
			if (dp->ind_state == IN_PERMANENT) {
				rval = (*f)(path, np, dp, arg);
				if (rval == INST_WALK_TERMINATE)
					break;
			}
		}

		if (np->in_child) {
			rval = in_walk_instances(np->in_child,
			    path, next, f, arg);
			if (rval == INST_WALK_TERMINATE)
				break;
		}

		np = np->in_sibling;
	}

	return (rval);
}

/*
 * A general interface for walking the instance tree,
 * calling a user-supplied callback for each node.
 */
int
e_ddi_walk_instances(int (*f)(const char *,
	in_node_t *, in_drv_t *, void *), void *arg)
{
	in_node_t *root;
	int rval;
	char *path;

	path = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

	e_ddi_enter_instance();
	root = e_ddi_instance_root();
	rval = in_walk_instances(root->in_child, path, path, f, arg);

	e_ddi_exit_instance();

	kmem_free(path, MAXPATHLEN);
	return (rval);
}

in_node_t *
e_ddi_path_to_instance(char *path)
{
	in_node_t *np;

	np = in_make_path(path);
	if (np && np->in_drivers && np->in_drivers->ind_state == IN_PERMANENT) {
		return (np);
	}
	return (NULL);
}

void
e_ddi_borrow_instance(dev_info_t *cdip, in_node_t *cnp)
{
	char		*alias;
	in_node_t	*anp;
	char		*curr = kmem_alloc(MAXPATHLEN, KM_NOSLEEP);

	if (curr == NULL) {
		ddi_err(DER_PANIC, cdip, "curr alloc failed");
		/*NOTREACHED*/
	}

	(void) ddi_pathname(cdip, curr);

	if (cnp->in_drivers) {
		/* there can be multiple drivers bound */
		ddi_err(DER_LOG, cdip, "%s has previous binding: %s", curr,
		    cnp->in_drivers->ind_driver_name);
	}

	alias = ddi_curr_redirect(curr);

	/* bail here if the alias matches any other current path or itself */
	if (alias && ((strcmp(curr, alias) == 0) ||
	    (ddi_curr_redirect(alias) != 0))) {
		DDI_MP_DBG((CE_NOTE, "not borrowing current: %s alias: %s",
		    curr, alias));
		goto out;
	}

	if (alias && (anp = e_ddi_path_to_instance(alias)) != NULL) {
		/*
		 * Since pcieb nodes can split and merge, it is dangerous
		 * to borrow and instance for them. However since they do
		 * not expose their instance numbers it is safe to never
		 * borrow one.
		 */
		if (anp->in_drivers->ind_driver_name &&
		    (strcmp(anp->in_drivers->ind_driver_name, "pcieb") == 0)) {
			DDI_MP_DBG((CE_NOTE, "not borrowing pcieb: "
			    "%s alias: %s", curr, alias));
			goto out;
		}
		DDI_MP_DBG((CE_NOTE, "borrowing current: %s alias: %s",
		    curr, alias));
		cnp->in_drivers = anp->in_drivers;
		anp->in_drivers = NULL;
	}
out:
	kmem_free(curr, MAXPATHLEN);
}

void
e_ddi_return_instance(dev_info_t *cdip, char *addr, in_node_t *cnp)
{
	in_node_t	*anp;
	char 		*alias;
	char		*curr = kmem_alloc(MAXPATHLEN, KM_NOSLEEP);

	if (curr == NULL) {
		ddi_err(DER_PANIC, cdip, "alloc of curr failed");
		/*NOTREACHED*/
	}

	(void) ddi_pathname(cdip, curr);
	if (addr) {
		(void) strlcat(curr, "@", MAXPATHLEN);
		(void) strlcat(curr, addr, MAXPATHLEN);

	}
	if (cnp->in_drivers == NULL) {
		ddi_err(DER_PANIC, cdip, "cnp has no inst: %p", cnp);
		/*NOTREACHED*/
	}

	alias = ddi_curr_redirect(curr);
	kmem_free(curr, MAXPATHLEN);

	if (alias && (anp = e_ddi_path_to_instance(alias)) != NULL) {
		ASSERT(anp->in_drivers == NULL);
		anp->in_drivers = cnp->in_drivers;
		cnp->in_drivers = NULL;
	}
}
