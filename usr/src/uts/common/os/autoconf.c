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
 * This file contains ddi functions needed during boot and DR.
 * Many functions in swapgeneric.c can be moved here.
 *
 * The object file is currently linked into unix.
 */

#include <sys/bootconf.h>
#include <sys/conf.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_implfuncs.h>
#include <sys/hwconf.h>
#include <sys/instance.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/promif.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/systeminfo.h>
#include <sys/hwconf.h>
#include <sys/sysevent_impl.h>
#include <sys/sunldi_impl.h>
#include <sys/disp.h>
#include <sys/bootconf.h>
#include <sys/fm/util.h>
#include <sys/ddifm_impl.h>

extern dev_info_t *top_devinfo;
extern dev_info_t *scsi_vhci_dip;
extern struct hwc_class *hcl_head;
static char *rootname;		/* node name of top_devinfo */

/*
 * This lock must be held while updating devi_sibling pointers of
 * rootnex immediate children
 */
kmutex_t global_vhci_lock;

major_t mm_major;
major_t	nulldriver_major;

/*
 * Forward declarations
 */
static void impl_create_root_class(void);
static void create_devinfo_tree(void);

#if defined(__x86)
char *bootpath_prop = NULL;
char *fstype_prop = NULL;
#endif

/*
 * Setup the DDI but don't necessarily init the DDI.  This will happen
 * later once /boot is released.
 */
void
setup_ddi(void)
{
	impl_ddi_init_nodeid();
	impl_create_root_class();
	create_devinfo_tree();
	e_ddi_instance_init();
	impl_ddi_callback_init();
	log_event_init();
	fm_init();
	ndi_fm_init();
	irm_init();

	(void) i_ddi_load_drvconf(DDI_MAJOR_T_NONE);

	ldi_init();

	i_ddi_devices_init();
	i_ddi_read_devices_files();
}

/*
 * Perform setup actions post startup (i_ddi_io_initialized)
 */
void
setup_ddi_poststartup(void)
{
	extern void i_ddi_start_flush_daemon(void);
	extern void i_ddi_irm_poststartup(void);
	extern void i_ddi_intr_redist_all_cpus(void);

	i_ddi_start_flush_daemon();

	/* Startup Interrupt Resource Management (IRM) */
	i_ddi_irm_poststartup();

	/*
	 * For platforms that support INTR_WEIGHTED_DIST, we perform a
	 * redistribution at this point (after NICs configured) so that
	 * "isolation" relative to "ddi-intr-weight" occurs.
	 */
	i_ddi_intr_redist_all_cpus();
}

/*
 * Create classes and major number bindings for the name of my root.
 * Called immediately before 'loadrootmodules'
 */
static void
impl_create_root_class(void)
{
	major_t major;
	size_t size;
	char *cp;

	/*
	 * The name for the root nexus is exactly as the manufacturer
	 * placed it in the prom name property.  No translation.
	 */
	if ((major = ddi_name_to_major("rootnex")) == DDI_MAJOR_T_NONE)
		panic("Couldn't find major number for 'rootnex'");

	/*
	 * C OBP (Serengeti) does not include the NULL when returning
	 * the length of the name property, while this violates 1275,
	 * Solaris needs to work around this by allocating space for
	 * an extra character.
	 */
	size = (size_t)BOP_GETPROPLEN(bootops, "mfg-name") + 1;
	rootname = kmem_zalloc(size, KM_SLEEP);
	(void) BOP_GETPROP(bootops, "mfg-name", rootname);

	/*
	 * Fix conflict between OBP names and filesystem names.
	 * Substitute '_' for '/' in the name.  Ick.  This is only
	 * needed for the root node since '/' is not a legal name
	 * character in an OBP device name.
	 */
	for (cp = rootname; *cp; cp++)
		if (*cp == '/')
			*cp = '_';

	/*
	 * Bind rootname to rootnex driver
	 */
	if (make_mbind(rootname, major, NULL, mb_hashtab) != 0) {
		cmn_err(CE_WARN, "A driver or driver alias has already "
		    "registered the name \"%s\".  The root nexus needs to "
		    "use this name, and will override the existing entry. "
		    "Please correct /etc/name_to_major and/or "
		    "/etc/driver_aliases and reboot.", rootname);

		/*
		 * Resort to the emergency measure of blowing away the
		 * existing hash entry and replacing it with rootname's.
		 */
		delete_mbind(rootname, mb_hashtab);
		if (make_mbind(rootname, major, NULL, mb_hashtab) != 0)
			panic("mb_hashtab: inconsistent state.");
	}

	/*
	 * The `platform' or `implementation architecture' name has been
	 * translated by boot to be proper for file system use.  It is
	 * the `name' of the platform actually booted.  Note the assumption
	 * is that the name will `fit' in the buffer platform (which is
	 * of size SYS_NMLN, which is far bigger than will actually ever
	 * be needed).
	 */
	(void) BOP_GETPROP(bootops, "impl-arch-name", platform);

#if defined(__x86)
	/*
	 * Retrieve and honor the bootpath and optional fstype properties
	 */
	size = (size_t)BOP_GETPROPLEN(bootops, "bootpath");
	if (size != -1) {
		bootpath_prop = kmem_zalloc(size, KM_SLEEP);
		(void) BOP_GETPROP(bootops, "bootpath", bootpath_prop);
		setbootpath(bootpath_prop);
	}

	size = (size_t)BOP_GETPROPLEN(bootops, "fstype");
	if (size != -1) {
		fstype_prop = kmem_zalloc(size, KM_SLEEP);
		(void) BOP_GETPROP(bootops, "fstype", fstype_prop);
		setbootfstype(fstype_prop);
	}
#endif
}

/*
 * Note that this routine does not take into account the endianness
 * of the host or the device (or PROM) when retrieving properties.
 */
static int
getlongprop_buf(int id, char *name, char *buf, int maxlen)
{
	int size;

	size = prom_getproplen((pnode_t)id, name);
	if (size <= 0 || (size > maxlen - 1))
		return (-1);

	if (-1 == prom_getprop((pnode_t)id, name, buf))
		return (-1);

	/*
	 * Workaround for bugid 1085575 - OBP may return a "name" property
	 * without null terminating the string with '\0'.  When this occurs,
	 * append a '\0' and return (size + 1).
	 */
	if (strcmp("name", name) == 0) {
		if (buf[size - 1] != '\0') {
			buf[size] = '\0';
			size += 1;
		}
	}

	return (size);
}

/*ARGSUSED1*/
static int
get_neighbors(dev_info_t *di, int flag)
{
	register int nid, snid, cnid;
	dev_info_t *parent;
	char buf[OBP_MAXPROPNAME];

	if (di == NULL)
		return (DDI_WALK_CONTINUE);

	nid = ddi_get_nodeid(di);

	snid = cnid = 0;
	switch (flag) {
		case DDI_WALK_PRUNESIB:
			cnid = (int)prom_childnode((pnode_t)nid);
			break;
		case DDI_WALK_PRUNECHILD:
			snid = (int)prom_nextnode((pnode_t)nid);
			break;
		case 0:
			snid = (int)prom_nextnode((pnode_t)nid);
			cnid = (int)prom_childnode((pnode_t)nid);
			break;
		default:
			return (DDI_WALK_TERMINATE);
	}


	if (snid && (snid != -1) && ((parent = ddi_get_parent(di)) != NULL)) {
		/*
		 * add the first sibling that passes check_status()
		 */
		for (; snid && (snid != -1);
		    snid = (int)prom_nextnode((pnode_t)snid)) {
			if (getlongprop_buf(snid, OBP_NAME, buf,
			    sizeof (buf)) > 0) {
				if (check_status(snid, buf, parent) ==
				    DDI_SUCCESS) {
					(void) ddi_add_child(parent, buf,
					    snid, -1);
					break;
				}
			}
		}
	}

	if (cnid && (cnid != -1)) {
		/*
		 * add the first child that passes check_status()
		 */
		if (getlongprop_buf(cnid, OBP_NAME, buf, sizeof (buf)) > 0) {
			if (check_status(cnid, buf, di) == DDI_SUCCESS) {
				(void) ddi_add_child(di, buf, cnid, -1);
			} else {
				for (cnid = (int)prom_nextnode((pnode_t)cnid);
				    cnid && (cnid != -1);
				    cnid = (int)prom_nextnode((pnode_t)cnid)) {
					if (getlongprop_buf(cnid, OBP_NAME,
					    buf, sizeof (buf)) > 0) {
						if (check_status(cnid, buf, di)
						    == DDI_SUCCESS) {
							(void) ddi_add_child(
							    di, buf, cnid, -1);
							break;
						}
					}
				}
			}
		}
	}

	return (DDI_WALK_CONTINUE);
}

static void
di_dfs(dev_info_t *devi, int (*f)(dev_info_t *, int), caddr_t arg)
{
	(void) (*f)(devi, 0);
	if (devi) {
		di_dfs((dev_info_t *)DEVI(devi)->devi_child, f, arg);
		di_dfs((dev_info_t *)DEVI(devi)->devi_sibling, f, arg);
	}
}

dev_info_t *
i_ddi_create_branch(dev_info_t *pdip, int nid)
{
	char *buf;
	dev_info_t *dip = NULL;

	if (pdip == NULL || nid == OBP_NONODE || nid == OBP_BADNODE)
		return (NULL);

	buf = kmem_alloc(OBP_MAXPROPNAME, KM_SLEEP);

	if (getlongprop_buf(nid, OBP_NAME, buf, OBP_MAXPROPNAME) > 0) {
		if (check_status(nid, buf, pdip) == DDI_SUCCESS)
			dip = ddi_add_child(pdip, buf, nid, -1);
	}

	kmem_free(buf, OBP_MAXPROPNAME);

	if (dip == NULL)
		return (NULL);

	/*
	 * Don't create any siblings of the branch root, just
	 * children.
	 */
	(void) get_neighbors(dip, DDI_WALK_PRUNESIB);

	di_dfs(ddi_get_child(dip), get_neighbors, 0);

	return (dip);
}

static void
create_devinfo_tree(void)
{
	major_t major;
	pnode_t nodeid;

	i_ddi_node_cache_init();
#if defined(__sparc)
	nodeid = prom_nextnode(0);
#else /* x86 */
	nodeid = DEVI_SID_NODEID;
#endif
	top_devinfo = i_ddi_alloc_node(NULL, rootname,
	    nodeid, -1, NULL, KM_SLEEP);
	ndi_hold_devi(top_devinfo);	/* never release the root */

	i_ddi_add_devimap(top_devinfo);

	/*
	 * Bind root node.
	 * This code is special because root node has no parent
	 */
	major = ddi_name_to_major("rootnex");
	ASSERT(major != DDI_MAJOR_T_NONE);
	DEVI(top_devinfo)->devi_major = major;
	devnamesp[major].dn_head = top_devinfo;
	i_ddi_set_binding_name(top_devinfo, rootname);
	i_ddi_set_node_state(top_devinfo, DS_BOUND);

	/*
	 * Record that devinfos have been made for "rootnex."
	 * di_dfs() is used to read the prom because it doesn't get the
	 * next sibling until the function returns, unlike ddi_walk_devs().
	 */
	di_dfs(ddi_root_node(), get_neighbors, 0);

#if !defined(__sparc)
	/*
	 * On x86, there is no prom. Create device tree by
	 * probing pci config space
	 */
	{
		extern void impl_setup_ddi(void);
		impl_setup_ddi();
	}
#endif /* x86 */
}

/*
 * Init and attach the root node. root node is the first one to be
 * attached, so the process is somewhat "handcrafted".
 */
void
i_ddi_init_root()
{
#ifdef  DDI_PROP_DEBUG
	(void) ddi_prop_debug(1);	/* Enable property debugging */
#endif  /* DDI_PROP_DEBUG */

	/*
	 * Initialize root node
	 */
	if (impl_ddi_sunbus_initchild(top_devinfo) != DDI_SUCCESS)
		panic("Could not initialize root nexus");

	/*
	 * Attach root node (no need to probe)
	 * Hold both devinfo and rootnex driver so they can't go away.
	 */
	DEVI(top_devinfo)->devi_ops = ndi_hold_driver(top_devinfo);
	ASSERT(DEV_OPS_HELD(DEVI(top_devinfo)->devi_ops));
	DEVI(top_devinfo)->devi_instance = e_ddi_assign_instance(top_devinfo);

	(void) i_ddi_load_drvconf(DEVI(top_devinfo)->devi_major);

	mutex_enter(&(DEVI(top_devinfo)->devi_lock));
	DEVI_SET_ATTACHING(top_devinfo);
	mutex_exit(&(DEVI(top_devinfo)->devi_lock));

	if (devi_attach(top_devinfo, DDI_ATTACH) != DDI_SUCCESS)
		panic("Could not attach root nexus");

	mutex_enter(&(DEVI(top_devinfo)->devi_lock));
	DEVI_CLR_ATTACHING(top_devinfo);
	mutex_exit(&(DEVI(top_devinfo)->devi_lock));

	mutex_init(&global_vhci_lock, NULL, MUTEX_DEFAULT, NULL);

	ndi_hold_devi(top_devinfo);	/* hold it forever */
	i_ddi_set_node_state(top_devinfo, DS_READY);

	/*
	 * Now, expand .conf children of root
	 */
	(void) i_ndi_make_spec_children(top_devinfo, 0);

	/*
	 * Must be set up before attaching root or pseudo drivers
	 */
	pm_init_locks();

	/*
	 * Attach options dip
	 */
	options_dip = i_ddi_attach_pseudo_node("options");

	/*
	 * Attach pseudo nexus and enumerate its children
	 */
	pseudo_dip = i_ddi_attach_pseudo_node(DEVI_PSEUDO_NEXNAME);
	(void) i_ndi_make_spec_children(pseudo_dip, 0);

	/*
	 * Attach and hold clone dip
	 */
	clone_dip = i_ddi_attach_pseudo_node("clone");
	clone_major = ddi_driver_major(clone_dip);
	mm_major = ddi_name_to_major("mm");
	nulldriver_major = ddi_name_to_major("nulldriver");

	/*
	 * Attach scsi_vhci for MPXIO, this registers scsi vhci class
	 * with the MPXIO framework.
	 */
	scsi_vhci_dip = i_ddi_attach_pseudo_node("scsi_vhci");
}
