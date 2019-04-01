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
 *
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * This plugin creates memory configuration nodes and properties in the
 * PICL tree for Cheetah platforms.
 *
 * Subtree of memory-controller in the physical aspect.
 * memory-controller --- memory-module-group --- memory-module
 *
 * Subtree of memory in the logical aspect.
 * memory --- memory-segment --- memory-bank
 * Add property _memory-module-group_ at memory-segment referring to the
 * memory-module-group if InterleaveFactor is one, or at memory-bank
 * if InterleaveFactor is greater than one.
 *
 * Undo strategy:
 * Create all nodes and properties, or none if it fails in physical and
 * logical memory tree respectively. It keeps on creating logic
 * memory tree although it falis on physical logic tree, but no link to
 * memory module group.
 *
 * NOTE:
 * It depends on PICL devtree plugin and currently
 * there is no refresh routine for DR.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>
#include <syslog.h>
#include <string.h>
#include <libintl.h>
#include <picl.h>
#include <picltree.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <mc.h>
#include <libnvpair.h>
#include <limits.h>
#include "piclmemcfg.h"

/*
 * Plugin registration entry points
 */
static	void	piclmemcfg_register(void);
static	void	piclmemcfg_init(void);
static	void	piclmemcfg_fini(void);

/*
 * PICL event handler
 */
static void  piclmemcfg_evhandler(const char *ename, const void *earg,
		size_t size, void *cookie);

#pragma	init(piclmemcfg_register)

static picld_plugin_reg_t  my_reg_info = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_NON_CRITICAL,
	"SUNW_piclmemcfg",
	piclmemcfg_init,
	piclmemcfg_fini
};

/*
 * Log message texts
 */
#define	EM_INIT_FAILED		gettext("SUNW_piclmemcfg init failed!\n")
#define	EM_PHYSIC_MEM_TREE_FAILED	\
	gettext("SUNW_piclmemcfg physical memory tree failed!\n")
#define	EM_LOGIC_MEM_TREE_FAILED		\
	gettext("SUNW_piclmemcfg logical memory tree failed!\n")

#define	EM_INIT_MC_FAILED	\
	gettext("SUNW_piclmemcfg init mc failed!\n")

/*
 * Global variables for Memory Controllers
 */
#define	MC_DIR	"/dev/mc/"

static int	nsegments;	/* The number of memory segments */
static int	nbanks;		/* The max. number of banks per segment */
static int	ndevgrps;	/* The max. number of device groups per mc */
static int	ndevs;		/* The max. number of devices per dev group */
static int	transfersize;

static picl_nodehdl_t	*msegh_info;

/*
 * Memory-module-group node handle list, a singal linking list, where
 * memory module group id is the key to match.
 *
 * It is allocated and added to the head of list, and freed as well.
 * The mmgh field is cleared if failure is encountered in the physical
 * memory tree.
 *
 * This list is accessed in the logical memory tree, and allocated memory
 * is released at the end of plugin.
 */
typedef struct memmodgrp_info {
	int			mmgid;
	struct memmodgrp_info	*next;
	picl_nodehdl_t		mmgh;
	picl_nodehdl_t		mch;
} mmodgrp_info_t;

static	mmodgrp_info_t		*head2mmodgrp;

/*
 * Release the allocated memory of mmodgrp_info
 */
static void
free_allocated_mem(void)
{
	mmodgrp_info_t		*mmghdl, *currmmghdl;

	mmghdl = head2mmodgrp;

	while (mmghdl) {
		currmmghdl = mmghdl;
		mmghdl = mmghdl->next;
		free(currmmghdl);
	}

	head2mmodgrp = NULL;
}

/*
 * Delete nodes whose MC is gone at mmodgrp_info
 */
static void
del_plugout_mmodgrp(picl_nodehdl_t mch)
{
	mmodgrp_info_t		*mmghdl, *prevmmghdl, *nextmmghdl;

	for (mmghdl = head2mmodgrp, prevmmghdl = NULL; mmghdl != NULL;
	    mmghdl = nextmmghdl) {
		nextmmghdl = mmghdl->next;
		if (mmghdl->mch == mch) {
			if (prevmmghdl == NULL)
				/* we are at the head */
				head2mmodgrp = nextmmghdl;
			else
				prevmmghdl->next = nextmmghdl;
			free(mmghdl);
		} else
			prevmmghdl = mmghdl;
	}
}

/*
 * Search the memory module group node in the mmodgrp_info by global id.
 * The matched memory-module-group node handle will be assigned to
 * the second parameter.
 */
static int
find_mem_mod_grp_hdl(int id, picl_nodehdl_t *mmodgrph)
{
	mmodgrp_info_t		*mmghdl;
	int			err = PICL_FAILURE;

	mmghdl = head2mmodgrp;

	while (mmghdl) {
		if ((mmghdl->mmgh) && (mmghdl->mmgid == id)) {
			*mmodgrph = mmghdl->mmgh;
			err = PICL_SUCCESS;
			break;
		}
		mmghdl = mmghdl->next;
	}

	return (err);
}

/*
 * Delete nodes and properties created in the physical memory tree.
 */
static void
undo_phymem_tree(void)
{
	mmodgrp_info_t		*mmghdl;

	mmghdl = head2mmodgrp;

	while (mmghdl) {
		/*
		 * Delete nodes and properties of memory-module-group(s)
		 */
		if (mmghdl->mmgh == NULL)
			continue;

		(void) ptree_delete_node(mmghdl->mmgh);
		(void) ptree_destroy_node(mmghdl->mmgh);

		/*
		 * Clear out the saved node handle of memory module group
		 * so that logic memory tree won't link to it.
		 */
		mmghdl->mch = mmghdl->mmgh = NULL;
		mmghdl = mmghdl->next;
	}
}

/*
 * Create all memory-banks under the given memory-segment.
 */
static int
add_mem_banks(picl_nodehdl_t msegh, int fd, struct mc_segment *mcseg)
{
	int			i;
	int			err = PICL_SUCCESS;
	static picl_nodehdl_t	mmodgrph;
	picl_prophdl_t		bankh;
	ptree_propinfo_t	propinfo;
	struct mc_bank		mcbank;
	char			propname[PICL_CLASSNAMELEN_MAX];

	/*
	 * Get all bank information via ioctl
	 */
	for (i = 0; i < mcseg->nbanks; i++) {
		mcbank.id = mcseg->bankids[i].globalid;
		if (ioctl(fd, MCIOC_BANK, &mcbank) == -1)
			return (PICL_FAILURE);

		/*
		 * Create memory-bank node under memory-segment node
		 */
		err = ptree_create_and_add_node(msegh, PICL_NAME_MEMORY_BANK,
		    PICL_CLASS_MEMORY_BANK, &bankh);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Add property, Size to memory-bank node
		 */
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_UNSIGNED_INT, PICL_READ, sizeof (mcbank.size),
		    PICL_PROP_SIZE, NULL, NULL);
		if (err != PICL_SUCCESS)
			break;

		err = ptree_create_and_add_prop(bankh, &propinfo, &mcbank.size,
		    NULL);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Add property, AddressMask to memory-bank node
		 */
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_UNSIGNED_INT, PICL_READ, sizeof (mcbank.mask),
		    PICL_PROP_ADDRESSMASK, NULL, NULL);
		if (err != PICL_SUCCESS)
			break;

		err = ptree_create_and_add_prop(bankh, &propinfo, &mcbank.mask,
		    NULL);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Add property, AddressMatch to memory-bank node
		 */
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_UNSIGNED_INT, PICL_READ, sizeof (mcbank.match),
		    PICL_PROP_ADDRESSMATCH, NULL, NULL);
		if (err != PICL_SUCCESS)
			break;

		err = ptree_create_and_add_prop(bankh, &propinfo,
		    &mcbank.match, NULL);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Add global id of bank to property, ID memory-bank node
		 */
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_INT, PICL_READ, sizeof (mcbank.id), PICL_PROP_ID,
		    NULL, NULL);
		if (err != PICL_SUCCESS)
			break;

		err = ptree_create_and_add_prop(bankh, &propinfo, &mcbank.id,
		    NULL);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Add property, _memory-module-group_ to memory-bank node
		 */
		if ((find_mem_mod_grp_hdl(mcbank.devgrpid.globalid,
		    &mmodgrph)) != PICL_SUCCESS)
			continue;

		/*
		 * The number of memory modules > 1 means there needs
		 * memory module group, and then refers to it. Otherwise,
		 * it refers to memory module node handle instead.
		 */
		(void) strlcpy(propname, (ndevs > 1 ?
		    PICL_REFPROP_MEMORY_MODULE_GROUP :
		    PICL_REFPROP_MEMORY_MODULE), PICL_CLASSNAMELEN_MAX);

		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_REFERENCE, PICL_READ, sizeof (picl_nodehdl_t),
		    propname, NULL, NULL);
		if (err != PICL_SUCCESS)
			break;

		err = ptree_create_and_add_prop(bankh, &propinfo, &mmodgrph,
		    NULL);
		if (err != PICL_SUCCESS)
			break;
	}
	return (PICL_SUCCESS);
}

static void
undo_logical_tree(int nsegments)
{
	int	i;
	/*
	 * Undo in the logical memory tree
	 */
	for (i = 0; i < nsegments; i++) {
		(void) ptree_delete_node(msegh_info[i]);
		(void) ptree_destroy_node(msegh_info[i]);
	}
}

/*
 * Create logical memory tree
 * memory --- memory-segment --- memory-bank
 * Get information via ioctl of memory control driver
 */
static int
create_logical_tree(picl_nodehdl_t memh, int fd)
{
	int			i;
	int			err = PICL_SUCCESS;
	picl_nodehdl_t		msegh;
	ptree_propinfo_t	propinfo;
	struct mc_memory	*mcmem;
	struct mc_segment	*mcseg;
	picl_prophdl_t		proph;
	uint64_t		memsize = 0;

	/*
	 * allocate memory for mc_memory where nsegmentids are various
	 */
	if ((mcmem = alloca((nsegments - 1) * sizeof (mcmem->segmentids[0]) +
	    sizeof (*mcmem))) == NULL)
		return (PICL_FAILURE);

	mcmem->nsegments = nsegments;

	/*
	 * Get logical memory information
	 */
	if (ioctl(fd, MCIOC_MEM, mcmem) == -1)
		return (PICL_FAILURE);

	/*
	 * allocate memory for mc_segment where nbanks are various
	 */
	if ((mcseg = alloca((nbanks - 1) * sizeof (mcseg->bankids[0]) +
	    sizeof (*mcseg))) == NULL)
		return (PICL_FAILURE);

	/*
	 * Get all segments to create memory-segment nodes and
	 * add properties.
	 */
	for (i = 0; i < nsegments; i++) {
		mcseg->id = mcmem->segmentids[i].globalid;
		mcseg->nbanks = nbanks;

		if (ioctl(fd, MCIOC_SEG, mcseg) == -1)
			break;

		/*
		 * Create memory-segment node under memory node
		 */
		err = ptree_create_and_add_node(memh, PICL_NAME_MEMORY_SEGMENT,
		    PICL_CLASS_MEMORY_SEGMENT, &msegh);
		if (err != PICL_SUCCESS)
			break;

		msegh_info[i] = msegh;

		/*
		 * Add property, Size to memory-segment node
		 */
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_UNSIGNED_INT, PICL_READ, sizeof (mcseg->size),
		    PICL_PROP_SIZE, NULL, NULL);
		if (err != PICL_SUCCESS)
			break;

		memsize += mcseg->size;
		err = ptree_create_and_add_prop(msegh, &propinfo, &mcseg->size,
		    NULL);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Add property, BaseAddress to memory-segment node
		 */
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_UNSIGNED_INT, PICL_READ, sizeof (mcseg->base),
		    PICL_PROP_BASEADDRESS, NULL, NULL);
		if (err != PICL_SUCCESS)
			break;

		err = ptree_create_and_add_prop(msegh, &propinfo, &mcseg->base,
		    NULL);
		if (err != PICL_SUCCESS)
			break;

		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_UNSIGNED_INT, PICL_READ, sizeof (mcseg->ifactor),
		    PICL_PROP_INTERLEAVE_FACTOR, NULL, NULL);
		if (err != PICL_SUCCESS)
			break;

		err = ptree_create_and_add_prop(msegh, &propinfo,
		    &mcseg->ifactor, NULL);
		if (err != PICL_SUCCESS)
			break;

		err = add_mem_banks(msegh, fd, mcseg);
		if (err != PICL_SUCCESS)
			break;
	}

	if (err != PICL_SUCCESS) {
		undo_logical_tree(nsegments);
		return (err);
	}

	err = ptree_get_prop_by_name(memh, PICL_PROP_SIZE, &proph);
	if (err == PICL_SUCCESS) {	/* update the value */
		err = ptree_update_propval(proph, &memsize, sizeof (memsize));
		return (err);
	}

	/*
	 * Add the size property
	 */
	(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_UNSIGNED_INT, PICL_READ, sizeof (memsize),
	    PICL_PROP_SIZE, NULL, NULL);
	err = ptree_create_and_add_prop(memh, &propinfo, &memsize, NULL);

	return (err);
}

/*
 * Add memory-module nodes and properties at each enabled memory-module-group.
 * The formula of unique id is (id of the given memory module group *
 * max number of memory modules per memory module group) + index
 * of memory modules in this memory module group
 */
static int
add_mem_modules(picl_nodehdl_t mmodgrph, struct mc_devgrp *mcdevgrp)
{
	uint64_t		size;
	picl_nodehdl_t		dimmh;
	ptree_propinfo_t	propinfo;
	int			i;
	int			err = PICL_SUCCESS;

	size = mcdevgrp->size / mcdevgrp->ndevices;

	/*
	 * Get all memory-modules of the given memory-module-group
	 */
	for (i = 0; i < mcdevgrp->ndevices; i++) {
		/*
		 * Create memory-module node under memory-module-group
		 */
		err = ptree_create_and_add_node(mmodgrph,
		    PICL_NAME_MEMORY_MODULE, PICL_CLASS_MEMORY_MODULE, &dimmh);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Add property, Size to memory-module-group node
		 */
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_UNSIGNED_INT, PICL_READ, sizeof (size),
		    PICL_PROP_SIZE, NULL, NULL);
		if (err != PICL_SUCCESS)
			break;

		err = ptree_create_and_add_prop(dimmh, &propinfo, &size, NULL);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Add property, ID to memory-module-group node
		 */
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_INT, PICL_READ, sizeof (i), PICL_PROP_ID,
		    NULL, NULL);
		if (err != PICL_SUCCESS)
			break;

		err = ptree_create_and_add_prop(dimmh, &propinfo, &i,
		    NULL);
		if (err != PICL_SUCCESS)
			break;
	}
	return (err);
}

/*
 * Create the subtree at every enabled Memory Controller where size of
 * memory module group is greater than zero.
 * Get information via ioctl of memory control driver
 */
static int
create_physical_tree(picl_nodehdl_t mch, void *args)
{
	int			i, portid;
	int			err = PICL_SUCCESS;
	mmodgrp_info_t		*mmghdl;
	picl_nodehdl_t		mmodgrph;
	ptree_propinfo_t	propinfo;
	struct mc_control 	*mccontrol;
	struct mc_devgrp 	mcdevgrp;
	int			fd;

	fd = (int)args;
	/*
	 * Get portid of memory-controller as the key to get its
	 * configuration via ioctl.
	 */
	err = ptree_get_propval_by_name(mch, OBP_PROP_PORTID, &portid,
	    sizeof (portid));
	if (err != PICL_SUCCESS)
		return (err);

	if ((mccontrol = alloca((ndevgrps - 1) *
	    sizeof (mccontrol->devgrpids[0]) + sizeof (*mccontrol))) == NULL)
		return (PICL_FAILURE);

	mccontrol->id = portid;
	mccontrol->ndevgrps = ndevgrps;

	if (ioctl(fd, MCIOC_CONTROL, mccontrol) == -1) {
		if (errno == EINVAL)
			return (PICL_WALK_CONTINUE);
		else
			return (PICL_FAILURE);
	}

	/*
	 * If returned ndevgrps is zero, Memory Controller is disable, and
	 * skip it.
	 */
	if (mccontrol->ndevgrps == 0)
		return (PICL_WALK_CONTINUE);

	/*
	 * Get all memory module groups of the given memory controller.
	 */
	for (i = 0; i < mccontrol->ndevgrps; i++) {
		int	mmglocalid = mccontrol->devgrpids[i].localid;

		mcdevgrp.id = mccontrol->devgrpids[i].globalid;

		if (ioctl(fd, MCIOC_DEVGRP, &mcdevgrp) == -1)
			return (PICL_FAILURE);

		/*
		 * Node doesn't need to be created if size is 0, i.e.
		 * there is no memory dimm at slot.
		 */
		if (mcdevgrp.size == 0)
			continue;

		/*
		 * Create memory-module-group node under memory-controller
		 */
		err = ptree_create_and_add_node(mch, PICL_NAME_MEM_MOD_GROUP,
		    PICL_CLASS_MEMORY_MODULE_GROUP, &mmodgrph);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Allocate space for mmodgrp_info to save the information
		 * so that it is easier to do the undo and setup of the
		 * reference property in logical memory tree.
		 */
		if ((mmghdl = malloc(sizeof (*mmghdl))) == NULL)
			return (PICL_FAILURE);

		/*
		 * Save the information and add it to the beginnong of list.
		 */
		mmghdl->mmgid = mcdevgrp.id;
		mmghdl->mmgh = mmodgrph;
		mmghdl->mch = mch;
		mmghdl->next = head2mmodgrp;

		head2mmodgrp = mmghdl;

		/*
		 * Add property, Size to memory-module-group node
		 */
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_UNSIGNED_INT, PICL_READ, sizeof (mcdevgrp.size),
		    PICL_PROP_SIZE, NULL, NULL);
		if (err != PICL_SUCCESS)
			break;

		err = ptree_create_and_add_prop(mmodgrph, &propinfo,
		    &mcdevgrp.size, NULL);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Add property, ID to memory-module-group node
		 */
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_INT, PICL_READ, sizeof (mmglocalid),
		    PICL_PROP_ID, NULL, NULL);
		if (err != PICL_SUCCESS)
			break;

		err = ptree_create_and_add_prop(mmodgrph, &propinfo,
		    &mmglocalid, NULL);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Create all memory-module nodes and properties.
		 */
		err = add_mem_modules(mmodgrph, &mcdevgrp);
		if (err != PICL_SUCCESS)
			break;
	}

	if (err == PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);
	return (err);
}

/*
 * Create physical memory tree
 * memory-controller --- memory-module-group --- memory-module
 *
 * It searches all memory-controller nodes in the whole devtree.
 * It returns failure if encountering error in physical tree.
 */
static int
find_mc_create_tree(picl_nodehdl_t rooth, int fd)
{
	int		err;

	err = ptree_walk_tree_by_class(rooth, PICL_CLASS_MEMORY_CONTROLLER,
	    (void *)fd, create_physical_tree);
	return (err);
}

static int
init_mc(void)
{
	struct mc_memconf	mcmemconf;
	int			fd;
	DIR			*dirp;
	struct dirent		*retp;
	char			path[PATH_MAX];
	int 			found = 0;
	int			valid_entry = 0;

	/* open the directory */
	if ((dirp = opendir(MC_DIR)) == NULL) {
		/*
		 * As not all platforms have mc drivers that create the
		 * /dev/mc directory, print a message only if there is
		 * an entry found on which the open failed.
		 */
		if (errno != ENOENT)
			syslog(LOG_ERR, EM_INIT_MC_FAILED);
		return (-1);
	}

	/* start searching this directory */
	while ((retp = readdir(dirp)) != NULL) {
		/* skip . .. etc... */
		if (strcmp(retp->d_name, ".") == 0 ||
		    strcmp(retp->d_name, "..") == 0)
			continue;

		(void) strcpy(path, MC_DIR);
		(void) strcat(path, retp->d_name);
		/* open the memory controller driver */
		if ((fd = open(path, O_RDONLY, 0)) != -1) {
			found = 1;
			break;
		}
		if (errno != ENOENT)
			valid_entry = 1;
	}
	(void) closedir(dirp);

	if (!found) {
		if (valid_entry)
			syslog(LOG_ERR, EM_INIT_MC_FAILED);
		return (-1);
	}

	/*
	 * Initialize some global variables via ioctl
	 */
	if (ioctl(fd, MCIOC_MEMCONF, &mcmemconf) == -1) {
		(void) close(fd);
		return (-1);
	}

	nsegments = mcmemconf.nsegments;
	nbanks = mcmemconf.nbanks;
	ndevgrps = mcmemconf.ndevgrps;
	ndevs = mcmemconf.ndevs;
	transfersize = mcmemconf.xfer_size;

	return (fd);
}

/*
 * executed as part of .init when the plugin is dlopen()ed
 */
void
piclmemcfg_register(void)
{
	(void) picld_plugin_register(&my_reg_info);
}

/*
 * init entry point of the plugin
 * Creates the PICL nodes and properties in the physical and logical aspects.
 */
void
piclmemcfg_init(void)
{
	picl_nodehdl_t		plfh;
	picl_nodehdl_t		memh;
	ptree_propinfo_t	propinfo;
	int			fd, err;

	/*
	 * Initialize the header pointer of mmodgrp_info list
	 */
	head2mmodgrp = NULL;
	msegh_info = NULL;

	if ((fd = init_mc()) < 0)
		return;

	/*
	 * allocate memory to save memory-segment node handles. Thus,
	 * it is easier to delete them if it fails.
	 */
	if ((msegh_info = malloc(nsegments * sizeof (picl_nodehdl_t))) ==
	    NULL) {
		syslog(LOG_ERR, EM_INIT_FAILED);
		(void) close(fd);
		return;
	}

	/*
	 * find platform node
	 */
	if ((ptree_get_node_by_path(PLATFORM_PATH, &plfh)) != PICL_SUCCESS) {
		syslog(LOG_ERR, EM_INIT_FAILED);
		(void) close(fd);
		return;
	}

	/*
	 * Find the memory node
	 */
	if ((ptree_get_node_by_path(MEMORY_PATH, &memh)) != PICL_SUCCESS) {
		syslog(LOG_ERR, EM_INIT_FAILED);
		(void) close(fd);
		return;
	}

	/*
	 * Create subtree of memory-controller in the physical aspect.
	 * memory-controller --- memory-module-group --- memory-module
	 */
	err = find_mc_create_tree(plfh, fd);

	if (err != PICL_SUCCESS) {
		undo_phymem_tree();
		syslog(LOG_ERR, EM_PHYSIC_MEM_TREE_FAILED);
	}

	/*
	 * Add property, TransferSize to memory node
	 */
	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_UNSIGNED_INT, PICL_READ, sizeof (transfersize),
	    PICL_PROP_TRANSFER_SIZE, NULL, NULL);
	if (err != PICL_SUCCESS) {
		(void) close(fd);
		return;
	}

	err = ptree_create_and_add_prop(memh, &propinfo,
	    &transfersize, NULL);
	if (err != PICL_SUCCESS) {
		(void) close(fd);
		return;
	}

	/*
	 * Create subtree of memory in the logical aspect.
	 * memory --- memory-segment --- memory-bank
	 */
	if ((create_logical_tree(memh, fd)) != PICL_SUCCESS) {
		syslog(LOG_ERR, EM_LOGIC_MEM_TREE_FAILED);
		undo_logical_tree(nsegments);
	}

	(void) close(fd);
	(void) ptree_register_handler(PICLEVENT_MC_ADDED,
	    piclmemcfg_evhandler, NULL);
	(void) ptree_register_handler(PICLEVENT_MC_REMOVED,
	    piclmemcfg_evhandler, NULL);
}

/*
 * fini entry point of the plugin
 */
void
piclmemcfg_fini(void)
{
	(void) ptree_unregister_handler(PICLEVENT_MC_ADDED,
	    piclmemcfg_evhandler, NULL);
	(void) ptree_unregister_handler(PICLEVENT_MC_REMOVED,
	    piclmemcfg_evhandler, NULL);
	/*
	 * Release all the allocated memory for global structures
	 */
	free_allocated_mem();
	if (msegh_info)
		free(msegh_info);
}

/*
 * Event handler of this plug-in
 */
/*ARGSUSED*/
static void
piclmemcfg_evhandler(const char *ename, const void *earg, size_t size,
    void *cookie)
{
	int		err;
	int		fd;
	picl_nodehdl_t	memh;
	picl_nodehdl_t	nodeh;
	int		old_nsegs;
	nvlist_t	*nvlp;

	memh = NULL;
	if (nvlist_unpack((char *)earg, size, &nvlp, NULL))
		return;

	if (nvlist_lookup_uint64(nvlp, PICLEVENTARG_NODEHANDLE, &nodeh)) {
		nvlist_free(nvlp);
		return;
	}
	nvlist_free(nvlp);

	/*
	 * get the memory node
	 */
	err = ptree_get_node_by_path(MEMORY_PATH, &memh);
	if (err != PICL_SUCCESS)
		return;

	/*
	 * nsegments won't be overwritten until init_mc succeeds
	 */
	old_nsegs = nsegments;
	if ((fd = init_mc()) < 0)
		return;

	if (strcmp(ename, PICLEVENT_MC_ADDED) == 0)
		(void) create_physical_tree(nodeh, (void *)fd);
	else if (strcmp(ename, PICLEVENT_MC_REMOVED) == 0)
		/*
		 * Delete the entry at the list only since class at PICL is
		 * deleted in devtree plugin.
		 */
		(void) del_plugout_mmodgrp(nodeh);

	(void) undo_logical_tree(old_nsegs);
	free(msegh_info);

	/*
	 * allocate memory to save memory-segment node handles. Thus,
	 * it is easier to delete them if it fails.
	 */
	if ((msegh_info = malloc(nsegments * sizeof (picl_nodehdl_t))) ==
	    NULL) {
		(void) close(fd);
		return;
	}

	(void) create_logical_tree(memh, fd);

	(void) close(fd);
}
