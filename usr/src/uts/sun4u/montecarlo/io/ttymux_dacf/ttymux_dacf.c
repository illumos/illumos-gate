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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This is a dacf module based upon the Extensions to Device Autoconfiguration
 * project.  See PSARC/1998/212 for more details.
 *
 * This module provides the dacf functions
 * to be called after a driver has attached and before it detaches.
 * The post attach functionality is used to autoconfigure a serial console
 * multiplexer if the OBP console is a multiplexer.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/klwp.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>

#include <sys/consdev.h>
#include <sys/kbio.h>
#include <sys/debug.h>
#include <sys/reboot.h>
#include <sys/termios.h>
#include <sys/clock.h>

#include <sys/kstr.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>

#include <sys/errno.h>
#include <sys/devops.h>
#include <sys/note.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/dacf.h>
#include <sys/promif.h>

#include "ttymux_dacf.h"

#pragma weak	find_platform_consoles
extern char *find_platform_consoles(sm_mux_state_t *_m, dev_info_t *_di,
    dev_t _d, uint_t _f);

#define	platform_consoles(_m, _di, _d, _f)		\
	(find_platform_consoles != NULL		\
	? find_platform_consoles(_m, _di, _d, _f)	\
	: (nulldev(_m, _di, _d, _f), (char *)0))

/*
 * External functions
 */
extern uintptr_t space_fetch(char *key);
extern int space_store(char *key, uintptr_t ptr);
extern void ttymux_dprintf(int l, const char *fmt, ...);
extern int prom_ihandle_to_path(ihandle_t, char *, uint_t);
extern void prom_interpret(char *, uintptr_t, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t);
extern ihandle_t prom_stdin_ihandle();
extern ihandle_t prom_stdout_ihandle();

extern vnode_t *rconsvp;	/* redirection device */

/*
 * Dacf entry points
 */
static int ttymux_config(dacf_infohdl_t, dacf_arghdl_t, int);

/*
 * Internal functions
 */
static dacf_op_t ttymuxconfig_op[] = {
	{ DACF_OPID_POSTATTACH, ttymux_config },
	{ DACF_OPID_END,	NULL },
};

static dacf_opset_t opsets[] = {
	{ "ttymux_config",	ttymuxconfig_op },
	{ NULL,		NULL }
};

struct dacfsw dacfsw = {
	DACF_MODREV_1,
	opsets,
};

struct modldacf modldacf = {
	&mod_dacfops,   /* Type of module */
	"ttymux DACF %I%",
	&dacfsw
};

struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldacf, NULL
};

/*LINTLIBRARY*/

/*
 * The following minor nodes can be linked underneath the serial
 * console multiplexer.
 * These are the only ones currently tested.
 * (NOTE: Devices of device_type serial are also allowed to be used as
 * additional consoles).
 * Disallow plumbing of untested node types.
 */
static const char * const supported_types[] = {
	DDI_NT_SERIAL, (char *const)NULL
};

#define	OFLAGS	FREAD|FWRITE|FNOCTTY|FNONBLOCK

#define	INPUT_ALIAS	"multiplexer-input-devices"
#define	OUTPUT_ALIAS	"multiplexer-output-devices"
#define	OBPDEV		0x100
#define	FORTH_STRINGLEN	1024
#define	MUXDEVTYPE	"SUNW,serial-multiplexer"

static char fth_fmt[] =
"\" get-device-list\" "	/* ( method-str method-len ) */
"h# %p "		/* ( method-str method-len ihandle ) */
"$call-method "		/* ( ihandle_n-1 ... ihandle n ) */
"dup "			/* ( ihandle_n-1 ... ihandle n n ) */
"h# %p "		/* ( ihandle_n-1 ... ihandle n n numfound ) */
"l! "			/* ( ihandle_n-1 ... ihandle n ) */
"0 "			/* ( ihandle_n-1 ... ihandle n 0 ) */
"do "			/* ( ihandle_n-1 ... ihandle_i+1 ihandle_i ) */
"  i "			/* ( ihandle_n-1 ... ihandle_i+1 ihandle_i index ) */
"  h# %x "		/* ( ihandle_n-1 ... ihandle_i+1 ihandle_i index max) */
"  < if "		/* ( ihandle_n-1 ... ihandle_i+1 ihandle_i ) */
"    h# %p "		/* ( ihandle_n-1 ... ihandle_i+1 ihandle_i buf ) */
"    i "		/* ( ihandle_n-1 ... ihandle_i+1 ihandle_i buf index) */
"    4 * + "		/* ( ihandle_n-1 ... ihandle_i+1 ihandle_i buf' ) */
"    l! "		/* ( ihandle_n-1 ... ihandle_i+1 ) */
"  else "		/* */
"    drop "		/* ( ihandle_n-1 ... ihandle_i+1 ) */
"  then "		/* */
"loop ";		/* ( ihandle_n-1 ... ihandle_i+1 ) */

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
ioctl_cmd(vnode_t *avp, int cmd, void *data, int datasize, int *bytecnt)
{
	struct strioctl ios;
	int		rval;

	ios.ic_timout = 0;
	ios.ic_cmd = cmd;
	ios.ic_dp = (char *)data;
	ios.ic_len = datasize;

	rval = kstr_ioctl(avp, I_STR, (intptr_t)&ios);
	if (bytecnt)
		*bytecnt = ios.ic_len;
	return (rval);
}

/*
 * How many consoles are actually linked underneath the Solaris console
 * multiplexer.
 */
static int
usable_consoles(sm_mux_state_t *sp, uint_t *iconsoles, uint_t *oconsoles)
{
	uint_t  j, cnt, icnt = 0u, ocnt = 0u;

	mutex_enter(&sp->sm_cons_mutex);
	for (j = 0, cnt = 0; j < sp->sm_cons_cnt; j++)
		if (sp->sm_cons_links[j].sm_muxid != 0) {
			sm_console_t *cn = &sp->sm_cons_links[j];
			if (cn->sm_mode & FORINPUT)
				icnt += 1;
			if (cn->sm_mode & FOROUTPUT)
				ocnt += 1;
			if (cn->sm_mode == FORIO)
				cnt += 1;
		}
	mutex_exit(&sp->sm_cons_mutex);
	*iconsoles = icnt;
	*oconsoles = ocnt;
	return (cnt);
}

/*
 * Before linking a device underneath a serial multiplexer check that
 * its minor node type is supported.
 */
static boolean_t
compatible_console(dev_t dev)
{
	int			circ;
	boolean_t		compatible;
	char *const		*nodetype;
	struct ddi_minor_data	*dmdp;
	dev_info_t		*dip;
	char			devtype[32];
	int			len;

	/*
	 * Find the node nodetype to verify that the current version of
	 * the code supports its use as a console
	 * Supported types are listed in the array supported_types
	 */
	if ((dip = e_ddi_hold_devi_by_dev(dev, 0)) == NULL) {
		ttymux_dprintf(DPRINT_L2, "No dip for %d:%d\n",
		    getmajor(dev), getminor(dev));
		return (B_FALSE);
	}

	compatible = B_FALSE;
	len = sizeof (devtype);

	ndi_devi_enter(dip, &circ);
	for (dmdp = DEVI(dip)->devi_minor; dmdp != NULL; dmdp = dmdp->next) {
		struct ddi_minor_data   *mdp = dmdp;

		if (mdp->ddm_dev == dev) {

			ttymux_dprintf(DPRINT_L0, "compat: matched dev\n");
			/*
			 * check the OBP device_type property first
			 * its a good bet that it will be compatible
			 * if it has the value serial.
			 */
			if (ddi_prop_op(DDI_DEV_T_ANY, dip,
			    PROP_LEN_AND_VAL_BUF, 0, "device_type",
			    (caddr_t)devtype, &len) == DDI_PROP_SUCCESS &&
			    strcmp(devtype, "serial") == 0) {
				compatible = B_TRUE;
			} else {
				for (nodetype =
				    (char *const *)&supported_types[0];
				    *nodetype != (char *const)NULL;
				    nodetype++) {
					if (strcmp(*nodetype,
					    mdp->ddm_node_type) == 0) {
						compatible = B_TRUE;
						break;
					}
				}
			}
			break;
		}
	}
	ndi_devi_exit(dip, circ);
	ddi_release_devi(dip);

	/*
	 * The current version of the implementation has only been tested
	 * with a serial multiplexer.
	 */

	ttymux_dprintf(DPRINT_L0, "%d:%d is %s\n", getmajor(dev),
	    getminor(dev), (compatible) ? "compatible" : "incompatible");

	return (compatible);
}

/*
 * get-device-list ( -- [ihandle n-1, ... ihandle], n )
 * Call the "get-device-list" method of an OBP device.
 * ihdl		- ihandle of the OBP device whose method is to be called
 * ihdls	- array of ihandles returned to the caller
 * maxi		- length of the ihdls array
 */
static int
get_device_list(ihandle_t ihdl, ihandle_t *ihdls, size_t maxi)
{
	int	numfound = -1;
	char	fstr[FORTH_STRINGLEN];

	if (snprintf(fstr, FORTH_STRINGLEN, fth_fmt, (caddr32_t)ihdl,
	    &numfound, maxi, ihdls) > FORTH_STRINGLEN) {
		ttymux_dprintf(DPRINT_L3,
		    "WARNING: forth buffer size is too small.\n");
		return (0);
	}

	prom_interpret(fstr, 0, 0, 0, 0, 0);

	ttymux_dprintf(DPRINT_L0, "ihdl 0x%p cnt %d\n",
	    (caddr32_t)ihdl, numfound);

	return (numfound);
}

/*
 * Read an OBP property and return the result in propval.
 * The caller is responsible for freeing the memory.
 */
static int
read_prop(pnode_t node, char *propname, char **propval)
{
	int	proplen = -1;

	if (node == OBP_BADNODE ||
	    (proplen = prom_getproplen(node, propname)) <= 0)
		return (proplen);

	*propval = kmem_zalloc(proplen + 1, KM_SLEEP);
	(void) prom_getprop(node, propname, *propval);

	return (proplen);
}

/*
 * Parse a white space separated list of tokens and call
 * the input action with each parsed token.
 */
static void
parse(sm_mux_state_t *ms, char *p,
    void (*action)(sm_mux_state_t *, char *, void *), void *arg)
{
	char    *e, *tok = NULL;

	if (p == 0 || *p == 0)
		return;

	e = p + strlen(p);

	do {
		switch (*p) {
		case ' ':
		case '\t':
			if (tok != NULL) {
				*p = 0;
				action(ms, tok, arg);
				tok = NULL;
				*p = ' ';
			}
			break;
		default:
			if (tok == NULL) {
				tok = p;
			}
			break;
		}
	} while (++p < e);

	if (tok != NULL)
		action(ms, tok, arg);
}

/*
 * Search for a console structure matching a device path.
 * Return a new initialized structure if one does not exist.
 */
sm_console_t *
get_aconsole(sm_mux_state_t *ms, char *path)
{
	sm_console_t	*cn;
	int		j;

	for (cn = ms->sm_cons_links, j = 0;
	    j < ms->sm_cons_cnt; cn++, j++) {
		if (cn->sm_path && strcmp(cn->sm_path, path) == 0)
			break;
	}
	if (j == ms->sm_cons_cnt) {
		if (j + 1 == TTYMUX_MAX_LINKS) {
			cn = NULL;
		} else {
			bzero((caddr_t)cn, sizeof (*cn));
			ms->sm_cons_cnt += 1;
		}
	}
	return (cn);
}

/*
 * Create a new console structure representing the device
 * identified by path. The void * argument indicates which I/O
 * mode the device will support.
 */
static void
add_aconsole(sm_mux_state_t *ms, char *path, void *arg)
{
	sm_console_t	*cn;
	char		*cpath;

	if (*path == '/') {
		cpath = kmem_alloc(strlen(path) + 1, KM_SLEEP);
		(void) strcpy(cpath, path);
	} else if (read_prop(prom_alias_node(), path, &cpath) <= 0) {
			return;
	}

	/*
	 * Device paths should have a minor name - if its missing assume
	 * it should be :a!
	 */
	if (strrchr(cpath, ':') == NULL) {
		char	*p;
		size_t	len = strlen(cpath) + 1;

		p = kmem_zalloc(len + 2, KM_SLEEP);
		(void) strcpy(p, cpath);
		(void) strcat(p, ":a");	/* assume :a ! */
		kmem_free(cpath, len);
		cpath = p;
	}
	if ((cn = get_aconsole(ms, cpath)) != NULL) {
		cn->sm_obp_con = ((uint_t)(uintptr_t)arg & OBPDEV) ?
		    B_TRUE : B_FALSE;
		cn->sm_mode |= (io_mode_t)((uint_t)(uintptr_t)arg & FORIO);
		if (cn->sm_path != NULL)
			kmem_free(cn->sm_path, strlen(cn->sm_path) + 1);
		cn->sm_path = cpath;
	} else {
		ttymux_dprintf(DPRINT_L3, "Too many "
		    " consoles - ignoring %s\n", cpath);
		kmem_free(cpath, strlen(cpath) + 1);
	}
}

/*
 * Discover which consoles OBP is using.
 */
static int
find_obp_consoles(sm_mux_state_t *ms, io_mode_t mode)
{
	sm_console_t	*cn;
	int		i, cnt;
	char		*devpath;
	ihandle_t	ihdls[TTYMUX_MAX_LINKS];
	ihandle_t	stdihdl;

	if (mode == FORINPUT)
		stdihdl = ms->sm_cons_stdin.sm_i_ihdl;
	else if (mode == FOROUTPUT)
		stdihdl = ms->sm_cons_stdout.sm_o_ihdl;
	else
		return (EINVAL);
	devpath = kmem_alloc(MAXPATHLEN+2, KM_SLEEP);

	cnt = get_device_list(stdihdl, ihdls, TTYMUX_MAX_LINKS);

	for (i = 0; i < cnt; i++) {

		if (prom_ihandle_to_path(ihdls[i], devpath, MAXPATHLEN) == 0)
			continue;
		/*
		 * If the minor name is not part of the path and there is
		 * more than one minor node then ddi_pathname_to_dev_t
		 * can fail to resolve the path correctly (it's an OBP
		 * problem)!!! If there's no minor name then assume the default
		 * minor name (:a).
		 */
		if (strrchr(devpath, ':') == NULL)
			(void) strcat(devpath, ":a");	/* assume :a ! */

		if ((cn = get_aconsole(ms, devpath)) == 0) {
			ttymux_dprintf(DPRINT_L3, "Too many "
			    " consoles - ignoring %s\n", devpath);
			continue;
		}

		cn->sm_mode |= mode;
		cn->sm_obp_con = B_TRUE;
		if (mode == FORINPUT)
			cn->sm_i_ihdl = ihdls[i];
		else
			cn->sm_o_ihdl = ihdls[i];
		if (cn->sm_path == NULL) {
			cn->sm_path = kmem_alloc(strlen(devpath) + 1, KM_SLEEP);
			(void) strcpy(cn->sm_path, devpath);
		}

	}
	kmem_free(devpath, MAXPATHLEN + 2);

	return (0);
}

/*
 * Convert a file system path into a dev_t
 */
static dev_t
fs_devtype(char *fspath)
{
	vnode_t	*vp = NULL;
	dev_t	dev;

	if (fspath == 0 ||
	    vn_open(fspath, UIO_SYSSPACE, FREAD, 0, &vp, 0, 0) != 0) {
		return (NODEV);
	} else {
		dev = vp->v_rdev;
		VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(vp);
		return (dev);
	}
}

/*
 * Convert a device tree path into a dev_t
 */
static dev_t
di_devtype(char *path)
{
	dev_t   dev;

	if (path == 0 || *path == 0)
		return (NODEV);

	ttymux_dprintf(DPRINT_L0, "loading device %s\n", path);
	dev = ddi_pathname_to_dev_t(path);

	return (dev);
}


static int
open_stream(vnode_t **vp, int *fd, dev_t dev)
{
	file_t	*fp;
	int	rv;

	/* create a vnode for the device and open it */
	*vp = makespecvp(dev, VCHR);
	if ((rv = VOP_OPEN(vp, FREAD+FWRITE+FNOCTTY, CRED(), NULL)) != 0) {
		goto out2;
	}
	/* Associate a file pointer with the vnode */
	if ((rv = falloc(*vp, FREAD+FWRITE+FNOCTTY, &fp, NULL)) != 0) {
		goto out1;
	}
	mutex_exit(&fp->f_tlock);	/* must be called single threaded */
	/* Allocate a file descriptor (any non-negative integer will suffice) */
	if ((*fd = ufalloc(0)) == -1) {
		rv = EMFILE;
		goto out1;
	}
	/* associate the file pointer with the fd */
	setf(*fd, fp);
	return (0);

out1:
	VOP_CLOSE(*vp, FREAD+FWRITE+FNOCTTY, 1, (offset_t)0, CRED(), NULL);
out2:
	VN_RELE(*vp);
	return (rv);
}

/*
 * Plumb a device specified by the sm_console_t argument underneath the
 * serial multiplexer indicated by the vnode_t argument.
 */
static int
link_aconsole(vnode_t *mux_avp, sm_console_t *cn)
{
	vnode_t		*lvp;
	int		lfd;
	int		rv, rval;
	ttymux_assoc_t	assoc;
	struct termios	tc;

	ASSERT(cn->sm_path);

	/* get an open vnode for the device */
	if ((rv = open_stream(&lvp, &lfd, cn->sm_dev)) != 0)
		return (rv);

	/*
	 * Enable the receiver on the lower device since it will
	 * be used by OBP.
	 */
	if ((rv = ioctl_cmd(lvp, TCGETS, &tc, sizeof (tc), 0)) == 0) {
		tc.c_cflag |= CREAD;
		rv = ioctl_cmd(lvp, TCSETS, &tc, sizeof (tc), 0);
	}
	if (rv != 0)
		ttymux_dprintf(DPRINT_L3,
		    "DACF: Failed to enable console receiver [error %d]\n", rv);

	/*
	 * Pop all the modules off the stream prior to linking it.
	 */
	do {
		rv = strioctl(lvp, I_POP, 0, 0, K_TO_K, CRED(), &rval);
	} while (rv == 0);

	if (rv != EINVAL) {
		ttymux_dprintf(DPRINT_L3,
		    "Failed to pop all modules: error %d", rv);
		goto out;
	}

	if ((rv = strioctl(mux_avp, I_PLINK, (intptr_t)lfd,
	    FREAD+FWRITE+FNOCTTY, K_TO_K, CRED(), &(cn->sm_muxid))) != 0) {

		ttymux_dprintf(DPRINT_L3,
		    "Failed to link device: error %d", rv);
		goto out;
	}
	/* close the linked device */
	(void) closeandsetf(lfd, NULL);
	/*
	 * Now tell the mux to associate the new stream
	 */
	assoc.ttymux_udev = mux_avp->v_rdev;
	assoc.ttymux_ldev = cn->sm_dev;
	assoc.ttymux_linkid = cn->sm_muxid;
	assoc.ttymux_tag = 0;
	assoc.ttymux_ioflag = cn->sm_mode;
	if ((rv = ioctl_cmd(mux_avp, TTYMUX_ASSOC,
	    (void *)&assoc, sizeof (assoc), 0)) != 0) {
		ttymux_dprintf(DPRINT_L3,
		    "Failed to associate %d:%d with the console\n",
		    getmajor(cn->sm_dev), getminor(cn->sm_dev));

		if (strioctl(mux_avp, I_PUNLINK, (intptr_t)cn->sm_muxid, 0,
		    K_TO_K, CRED(), &rval) != 0)
			ttymux_dprintf(DPRINT_L3,
			    "Can't unlink %d:%d - Closing vnode\n",
			    getmajor(cn->sm_dev), getminor(cn->sm_dev));

	}
	return (rv);

out:
	VOP_CLOSE(lvp, FREAD+FWRITE+FNOCTTY, 1, (offset_t)0, CRED(), NULL);
	VN_RELE(lvp);
	return (rv);
}

static int
enable_aconsole(sm_mux_state_t *ms, sm_console_t *cn, vnode_t *muxvp)
{
	ttymux_assoc_t	assoc;

	ASSERT(cn && cn->sm_dev != NODEV);

	assoc.ttymux_ldev = cn->sm_dev;

	cn->sm_muxid = (ioctl_cmd(muxvp, TTYMUX_GETLINK,
	    (void *)&assoc, sizeof (assoc), 0) == 0) ? assoc.ttymux_linkid : 0;

	if (cn->sm_muxid != 0)
		return (0);	/* already linked */
	else
		return (link_aconsole(muxvp, cn));
}

/*
 * Enable all discovered consoles such that they can provide real I/O.
 * The discovered list is stored in the sm_mux_state_t pointer.
 */
static int
enable_all_consoles(sm_mux_state_t *ms, vnode_t *muxvp)
{
	sm_console_t	*cn;
	uint_t		j;

	ttymux_dprintf(DPRINT_L0, "Enable %d devices\n", ms->sm_cons_cnt);
	for (cn = ms->sm_cons_links, j = 0;
	    j < ms->sm_cons_cnt; cn++, j++) {

		if (cn->sm_path == NULL)
			continue;

		if ((strstr(cn->sm_path, "/dev") == cn->sm_path &&
		    (cn->sm_dev = fs_devtype(cn->sm_path)) == NODEV) ||
		    (cn->sm_dev = di_devtype(cn->sm_path)) == NODEV) {

			ttymux_dprintf(DPRINT_L0,
			    "Cannot find a driver for device: %s\n",
			    cn->sm_path ? cn->sm_path : "");
			continue;
		}
		ttymux_dprintf(DPRINT_L0, "Enabling %d:%d\n",
		    getmajor(cn->sm_dev), getminor(cn->sm_dev));

		/*
		 * Refuse requests to use devices as consoles which have an
		 * unsupported minor node type.
		 */
		if (compatible_console(cn->sm_dev) == B_FALSE)
			continue;

		/*
		 * Enable a console device by linking the target console
		 * underneath the ttymux minor node that has been specified
		 * in a DACF reservation (see /etc/dacf.conf).
		 */
		(void) enable_aconsole(ms, cn, muxvp);
	}
	return (0);
}

static int
find_consoles(sm_mux_state_t *ms, dev_info_t *dip, dev_t dev)
{
	int	len;
	char	*propval;
	char	devtype[32];
	pnode_t	node;
	uint_t	flags;

	/*
	 * Look for target consoles based on options node properties
	 */
	node = prom_optionsnode();
	if ((len = read_prop(node, INPUT_ALIAS, &propval)) > 0) {
		parse(ms, propval, add_aconsole, (void *)FORINPUT);
		kmem_free(propval, len + 1);
	}
	if ((len = read_prop(node, OUTPUT_ALIAS, &propval)) > 0) {
		parse(ms, propval, add_aconsole, (void *)FOROUTPUT);
		kmem_free(propval, len + 1);
	}

	/*
	 * Look for platform specific target consoles.
	 * Assume that they are OBP consoles and used for both input and output.
	 */
	flags = (uint_t)FORIO | OBPDEV;
	if ((propval = platform_consoles(ms, dip, dev, flags)) != NULL) {
		parse(ms, propval, add_aconsole, (void *)(uintptr_t)flags);
		kmem_free(propval, strlen(propval) + 1);
	}

	/*
	 * Discover which consoles OBP is actually using according to
	 * interfaces proposed by case number FWARC/262.
	 */
	len = sizeof (devtype);
	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF, 0,
	    "device_type", (caddr_t)devtype, &len) == DDI_PROP_SUCCESS &&
	    strcmp(devtype, "serial") == 0 &&
	    ddi_prop_exists(DDI_DEV_T_ANY, dip, 0, MUXDEVTYPE) == 1) {

		(void) find_obp_consoles(ms, FORINPUT);
		(void) find_obp_consoles(ms, FOROUTPUT);

	}
	ttymux_dprintf(DPRINT_L0, "%d consoles configured\n",
	    ms->sm_cons_cnt);
	return (ms->sm_cons_cnt);
}

static int
validate_reservation(dacf_infohdl_t di, dev_info_t **dip, dev_t *dev,
    io_mode_t *mode)
{
	char	*dname, *nname, *ipath, *opath;

	if ((dname = (char *)dacf_driver_name(di)) == NULL)
		return (EINVAL);

	if ((*dip = dacf_devinfo_node(di)) == NULL)
		return (EINVAL);

	*dev = makedevice(ddi_driver_major(*dip), dacf_minor_number(di));

	if (*dev == NODEV || *dip == NULL || strcmp(dname, TTYMUX_DRVNAME) != 0)
		return (EINVAL);
	else if (getminor(*dev) != (minor_t)0)
		return (EINVAL);	/* minor 0 is special */
	else if (rconsvp != NULL || space_fetch(TTYMUXPTR) != NULL)
		return (EAGAIN);	/* already configured */

	opath = prom_stdoutpath();
	ipath = prom_stdinpath();
	nname = ddi_node_name(*dip);
	*mode = 0;

	if (ipath != NULL && strstr(ipath, nname) != 0)
		*mode = FORINPUT;
	if (opath != NULL && strstr(opath, nname) != 0)
		*mode |= FOROUTPUT;
	if ((*mode & FORIO) == 0)
		return (EINVAL);
	if ((*mode & FOROUTPUT) == 0) {
		ttymux_dprintf(DPRINT_L3,
		    "Warning: multiplexer is not the output device\n");
	}
	if ((*mode & FORINPUT) == 0) {
		ttymux_dprintf(DPRINT_L3,
		    "Warning: multiplexer is not the input device\n");
	}
	return (0);
}

/*
 * This operation set is for configuring the ttymux driver for use as
 * the system console.
 * It must run before consconfig configures the Solaris console.
 */
/*ARGSUSED*/
static int
ttymux_config(dacf_infohdl_t info_hdl, dacf_arghdl_t arg_hdl, int flags)
{
	sm_mux_state_t	*ms;
	io_mode_t	mode;
	dev_t		dev;
	dev_info_t	*dip;
	uint_t		i, icnt = 0, ocnt = 0;
	int		rv;
	vnode_t		*muxvp;

	ttymux_dprintf(DPRINT_L0, "\n");

	if ((rv = validate_reservation(info_hdl, &dip, &dev, &mode)) != 0) {
		ttymux_dprintf(DPRINT_L0, "reservation ignored (%d)\n", rv);
		return (DACF_SUCCESS);
	}

	ms = kmem_zalloc(sizeof (*ms), KM_SLEEP);

	mutex_init(&ms->sm_cons_mutex, NULL, MUTEX_DRIVER, NULL);

	for (i = 0; i < TTYMUX_MAX_LINKS; i++)
		ms->sm_cons_links[i].sm_dev = NODEV;

	ms->sm_cons_stdin.sm_dev = ms->sm_cons_stdout.sm_dev = NODEV;
	if (mode & FORINPUT)
		ms->sm_cons_stdin.sm_dev = dev;
	if (mode & FOROUTPUT)
		ms->sm_cons_stdout.sm_dev = dev;
	ms->sm_cons_stdin.sm_i_ihdl = prom_stdin_ihandle();
	ms->sm_cons_stdout.sm_o_ihdl = prom_stdout_ihandle();

	if (prom_is_openprom()) {
		pnode_t	node = prom_optionsnode();

		if (prom_getproplen(node, INPUT_ALIAS) > 0) {
			ms->sm_ialias = kmem_alloc(
			    strlen(INPUT_ALIAS) + 1, KM_SLEEP);
			(void) strcpy(ms->sm_ialias, INPUT_ALIAS);
		}
		if (prom_getproplen(node, OUTPUT_ALIAS) > 0) {
			ms->sm_oalias = kmem_alloc(
			    strlen(OUTPUT_ALIAS) + 1, KM_SLEEP);
			(void) strcpy(ms->sm_oalias, OUTPUT_ALIAS);
		}
	}

	(void) find_consoles(ms, dip, dev);
	/* Store the console list for use by the ttymux driver */
	if (space_store(TTYMUXPTR, (uintptr_t)ms) != 0) {
		ttymux_dprintf(DPRINT_L3, "Named pointer error\n");
		if (ms->sm_ialias)
			kmem_free(ms->sm_ialias, strlen(ms->sm_ialias) + 1);
		if (ms->sm_oalias)
			kmem_free(ms->sm_oalias, strlen(ms->sm_oalias) + 1);
		for (i = 0; i < ms->sm_cons_cnt; i++) {
			sm_console_t *cn = &ms->sm_cons_links[i];
			if (cn->sm_path)
				kmem_free(cn->sm_path, strlen(cn->sm_path) + 1);
		}
		kmem_free(ms, sizeof (*ms));
		return (DACF_FAILURE);
	}

	muxvp = dacf_makevp(info_hdl);

	if ((rv = VOP_OPEN(&muxvp, OFLAGS, CRED(), NULL)) == 0) {

		(void) enable_all_consoles(ms, muxvp);
		(void) usable_consoles(ms, &icnt, &ocnt);

		VOP_CLOSE(muxvp, OFLAGS, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(muxvp);
	} else {
		ttymux_dprintf(DPRINT_L3,
		    "Error %d opening the console device\n", rv);
		VN_RELE(muxvp);
		return (DACF_FAILURE);
	}

	if (icnt == 0 && (mode & FORINPUT))
		ttymux_dprintf(DPRINT_L3, "No input consoles configured.\n");
	if (ocnt == 0 && (mode & FOROUTPUT))
		ttymux_dprintf(DPRINT_L3, "No output consoles configured.\n");

	ttymux_dprintf(DPRINT_L0, "mux config complete\n");

	return (DACF_SUCCESS);
}
