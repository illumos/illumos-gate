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


#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/ksynch.h>
#include <sys/modctl.h>
#include <sys/stat.h>			/* needed for S_IFBLK and S_IFCHR */
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/cred.h>
#include <sys/promif.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cyclic.h>
#include <sys/note.h>
#include <sys/mach_descrip.h>
#include <sys/mdeg.h>
#include <sys/ldc.h>
#include <sys/vldc_impl.h>

/*
 * Function prototypes.
 */

/* DDI entrypoints */
static int vldc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int vldc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int vldc_open(dev_t *devp, int flag, int otyp, cred_t *cred);
static int vldc_close(dev_t dev, int flag, int otyp, cred_t *cred);
static int vldc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp);
static int vldc_read(dev_t dev, struct uio *uiop, cred_t *credp);
static int vldc_write(dev_t dev, struct uio *uiop, cred_t *credp);
static int vldc_chpoll(dev_t dev, short events, int anyyet,
    short *reventsp, struct pollhead **phpp);

/* Internal functions */
static uint_t i_vldc_cb(uint64_t event, caddr_t arg);
static int i_vldc_mdeg_cb(void *cb_argp, mdeg_result_t *resp);
static int i_vldc_mdeg_register(vldc_t *vldcp);
static int i_vldc_mdeg_unregister(vldc_t *vldcp);
static int i_vldc_add_port(vldc_t *vldcp, md_t *mdp, mde_cookie_t node);
static int i_vldc_remove_port(vldc_t *vldcp, uint_t portno);
static int i_vldc_close_port(vldc_t *vldcp, uint_t portno);

/* soft state structure */
static void *vldc_ssp;

/*
 * Matching criteria passed to the MDEG to register interest
 * in changes to 'virtual-device-port' nodes identified by their
 * 'id' property.
 */
static md_prop_match_t vport_prop_match[] = {
	{ MDET_PROP_VAL,    "id"   },
	{ MDET_LIST_END,    NULL    }
};

static mdeg_node_match_t vport_match = { "virtual-device-port",
					vport_prop_match };

/*
 * Specification of an MD node passed to the MDEG to filter any
 * 'virtual-device-port' nodes that do not belong to the specified
 * node. This template is copied for each vldc instance and filled
 * in with the appropriate 'name' and 'cfg-handle' values before
 * being passed to the MDEG.
 */
static mdeg_prop_spec_t vldc_prop_template[] = {
	{ MDET_PROP_STR,    "name",		NULL	},
	{ MDET_PROP_VAL,    "cfg-handle",	NULL    },
	{ MDET_LIST_END,    NULL,		NULL    }
};

#define	VLDC_MDEG_PROP_NAME(specp)		((specp)[0].ps_str)
#define	VLDC_SET_MDEG_PROP_NAME(specp, name)	((specp)[0].ps_str = (name))
#define	VLDC_SET_MDEG_PROP_INST(specp, inst)	((specp)[1].ps_val = (inst))


static struct cb_ops vldc_cb_ops = {
	vldc_open,	/* open */
	vldc_close,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	vldc_read,	/* read */
	vldc_write,	/* write */
	vldc_ioctl,	/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	ddi_segmap,	/* segmap */
	vldc_chpoll,	/* chpoll */
	ddi_prop_op,	/* prop_op */
	NULL,		/* stream */
	D_NEW | D_MP	/* flag */
};

static struct dev_ops vldc_ops = {
	DEVO_REV,		/* rev */
	0,			/* ref count */
	ddi_getinfo_1to1,	/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	vldc_attach,		/* attach */
	vldc_detach,		/* detach */
	nodev,			/* reset */
	&vldc_cb_ops,		/* cb_ops */
	(struct bus_ops *)NULL,	/* bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv md = {
	&mod_driverops, 			/* Type - it is a driver */
	"sun4v Virtual LDC Driver",		/* Name of the module */
	&vldc_ops,				/* driver specific ops */
};

static struct modlinkage ml = {
	MODREV_1,
	&md,
	NULL
};

/* maximum MTU and cookie size tunables */
uint32_t vldc_max_mtu = VLDC_MAX_MTU;
uint64_t vldc_max_cookie = VLDC_MAX_COOKIE;

/*
 * when ldc_close() returns EAGAIN, it is retried with a wait
 * of 'vldc_close_delay' between each retry.
 */
static clock_t	vldc_close_delay = VLDC_CLOSE_DELAY;

#ifdef DEBUG

/*
 * Print debug messages
 *
 * set vldcdbg to 0x7 to enable all messages
 *
 * 0x4 - Warnings
 * 0x2 - All debug messages (most verbose)
 * 0x1 - Minimal debug messages
 */

int vldcdbg = 0x0;

static void
vldcdebug(const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	cmn_err(CE_CONT, "?%s", buf);
}

#define	D1	if (vldcdbg & 0x01) vldcdebug
#define	D2	if (vldcdbg & 0x02) vldcdebug
#define	DWARN	if (vldcdbg & 0x04) vldcdebug

#else /* not DEBUG */

#define	D1	if (0) printf
#define	D2	if (0) printf
#define	DWARN	if (0) printf

#endif /* not DEBUG */


/* _init(9E): initialize the loadable module */
int
_init(void)
{
	int error;

	/* init the soft state structure */
	error = ddi_soft_state_init(&vldc_ssp, sizeof (vldc_t), 1);
	if (error != 0) {
		return (error);
	}

	/* Link the driver into the system */
	error = mod_install(&ml);

	return (error);
}

/* _info(9E): return information about the loadable module */
int
_info(struct modinfo *modinfop)
{
	/* Report status of the dynamically loadable driver module */
	return (mod_info(&ml, modinfop));
}

/* _fini(9E): prepare the module for unloading. */
int
_fini(void)
{
	int error;

	/* Unlink the driver module from the system */
	if ((error = mod_remove(&ml)) == 0) {
		/*
		 * We have successfully "removed" the driver.
		 * destroy soft state
		 */
		ddi_soft_state_fini(&vldc_ssp);
	}

	return (error);
}

/* ldc callback */
static uint_t
i_vldc_cb(uint64_t event, caddr_t arg)
{
	int 		rv;
	vldc_port_t	*vport = (vldc_port_t *)arg;
	ldc_status_t	old_status;
	short		pollevents = 0;

	ASSERT(vport != NULL);
	ASSERT(vport->minorp != NULL);

	D1("i_vldc_cb: vldc@%d:%d callback invoked, channel=0x%lx, "
	    "event=0x%lx\n", vport->inst, vport->number, vport->ldc_id, event);

	/* ensure the port can't be destroyed while we are handling the cb */
	mutex_enter(&vport->minorp->lock);

	if (vport->status == VLDC_PORT_CLOSED) {
		return (LDC_SUCCESS);
	}

	old_status = vport->ldc_status;
	rv = ldc_status(vport->ldc_handle, &vport->ldc_status);
	if (rv != 0) {
		DWARN("i_vldc_cb: vldc@%d:%d could not get ldc status, "
		    "rv=%d\n", vport->inst, vport->number, rv);
		mutex_exit(&vport->minorp->lock);
		return (LDC_SUCCESS);
	}

	if (event & LDC_EVT_UP) {
		pollevents |= POLLOUT;
		vport->hanged_up = B_FALSE;

	} else if (event & LDC_EVT_RESET) {
		/*
		 * Mark the port in reset, if it is not CLOSED and
		 * the channel was previously in LDC_UP state. This
		 * implies that the port cannot be used until it has
		 * been closed and reopened.
		 */
		if (old_status == LDC_UP) {
			vport->status = VLDC_PORT_RESET;
			vport->hanged_up = B_TRUE;
			pollevents = POLLHUP;
		} else {
			rv = ldc_up(vport->ldc_handle);
			if (rv) {
				DWARN("i_vldc_cb: vldc@%d:%d cannot bring "
				    "channel UP rv=%d\n", vport->inst,
				    vport->number, rv);
				mutex_exit(&vport->minorp->lock);
				return (LDC_SUCCESS);
			}
			rv = ldc_status(vport->ldc_handle, &vport->ldc_status);
			if (rv != 0) {
				DWARN("i_vldc_cb: vldc@%d:%d could not get "
				    "ldc status, rv=%d\n", vport->inst,
				    vport->number, rv);
				mutex_exit(&vport->minorp->lock);
				return (LDC_SUCCESS);
			}
			if (vport->ldc_status == LDC_UP) {
				pollevents |= POLLOUT;
				vport->hanged_up = B_FALSE;
			}
		}

	} else if (event & LDC_EVT_DOWN) {
		/*
		 * The other side went away - mark port in RESET state
		 */
		vport->status = VLDC_PORT_RESET;
		vport->hanged_up = B_TRUE;
		pollevents = POLLHUP;
	}

	if (event & LDC_EVT_READ)
		pollevents |= POLLIN;

	mutex_exit(&vport->minorp->lock);

	if (pollevents != 0) {
		D1("i_vldc_cb: port@%d pollwakeup=0x%x\n",
		    vport->number, pollevents);
		pollwakeup(&vport->poll, pollevents);
	}

	return (LDC_SUCCESS);
}

/* mdeg callback */
static int
i_vldc_mdeg_cb(void *cb_argp, mdeg_result_t *resp)
{
	vldc_t		*vldcp;
	int		idx;
	uint64_t	portno;
	int		rv;
	md_t		*mdp;
	mde_cookie_t	node;

	if (resp == NULL) {
		D1("i_vldc_mdeg_cb: no result returned\n");
		return (MDEG_FAILURE);
	}

	vldcp = (vldc_t *)cb_argp;

	mutex_enter(&vldcp->lock);
	if (vldcp->detaching == B_TRUE) {
		D1("i_vldc_mdeg_cb: detach in progress\n");
		mutex_exit(&vldcp->lock);
		return (MDEG_FAILURE);
	}

	D1("i_vldc_mdeg_cb: added=%d, removed=%d, matched=%d\n",
	    resp->added.nelem, resp->removed.nelem, resp->match_prev.nelem);

	/* process added ports */
	for (idx = 0; idx < resp->added.nelem; idx++) {
		mdp = resp->added.mdp;
		node = resp->added.mdep[idx];

		D1("i_vldc_mdeg_cb: processing added node 0x%lx\n", node);

		/* attempt to add a port */
		if ((rv = i_vldc_add_port(vldcp, mdp, node)) != MDEG_SUCCESS) {
			cmn_err(CE_NOTE, "?i_vldc_mdeg_cb: unable to add port, "
			    "err = %d", rv);
		}
	}

	/* process removed ports */
	for (idx = 0; idx < resp->removed.nelem; idx++) {
		mdp = resp->removed.mdp;
		node = resp->removed.mdep[idx];

		D1("i_vldc_mdeg_cb: processing removed node 0x%lx\n", node);

		/* read in the port's id property */
		if (md_get_prop_val(mdp, node, "id", &portno)) {
			cmn_err(CE_NOTE, "?i_vldc_mdeg_cb: node 0x%lx of "
			    "removed list has no 'id' property", node);
			continue;
		}

		/* attempt to remove a port */
		if ((rv = i_vldc_remove_port(vldcp, portno)) != 0) {
			cmn_err(CE_NOTE, "?i_vldc_mdeg_cb: unable to remove "
			    "port %lu, err %d", portno, rv);
		}
	}

	/*
	 * Currently no support for updating already active ports. So, ignore
	 * the match_curr and match_prev arrays for now.
	 */

	mutex_exit(&vldcp->lock);

	return (MDEG_SUCCESS);
}

/* register callback to mdeg */
static int
i_vldc_mdeg_register(vldc_t *vldcp)
{
	mdeg_prop_spec_t *pspecp;
	mdeg_node_spec_t *inst_specp;
	mdeg_handle_t	mdeg_hdl;
	size_t		templatesz;
	int		inst;
	char		*name;
	size_t		namesz;
	char		*nameprop;
	int		rv;

	/* get the unique vldc instance assigned by the LDom manager */
	inst = ddi_prop_get_int(DDI_DEV_T_ANY, vldcp->dip,
	    DDI_PROP_DONTPASS, "reg", -1);
	if (inst == -1) {
		cmn_err(CE_NOTE, "?vldc%d has no 'reg' property",
		    ddi_get_instance(vldcp->dip));
		return (DDI_FAILURE);
	}

	/* get the name of the vldc instance */
	rv = ddi_prop_lookup_string(DDI_DEV_T_ANY, vldcp->dip,
	    DDI_PROP_DONTPASS, "name", &nameprop);
	if (rv != DDI_PROP_SUCCESS) {
		cmn_err(CE_NOTE, "?vldc%d has no 'name' property",
		    ddi_get_instance(vldcp->dip));
		return (DDI_FAILURE);
	}

	D1("i_vldc_mdeg_register: name=%s, instance=%d\n", nameprop, inst);

	/*
	 * Allocate and initialize a per-instance copy
	 * of the global property spec array that will
	 * uniquely identify this vldc instance.
	 */
	templatesz = sizeof (vldc_prop_template);
	pspecp = kmem_alloc(templatesz, KM_SLEEP);

	bcopy(vldc_prop_template, pspecp, templatesz);

	/* copy in the name property */
	namesz = strlen(nameprop) + 1;
	name = kmem_alloc(namesz, KM_SLEEP);

	bcopy(nameprop, name, namesz);
	VLDC_SET_MDEG_PROP_NAME(pspecp, name);
	ddi_prop_free(nameprop);

	/* copy in the instance property */
	VLDC_SET_MDEG_PROP_INST(pspecp, inst);

	/* initialize the complete prop spec structure */
	inst_specp = kmem_alloc(sizeof (mdeg_node_spec_t), KM_SLEEP);
	inst_specp->namep = "virtual-device";
	inst_specp->specp = pspecp;

	/* perform the registration */
	rv = mdeg_register(inst_specp, &vport_match, i_vldc_mdeg_cb,
	    vldcp, &mdeg_hdl);

	if (rv != MDEG_SUCCESS) {
		cmn_err(CE_NOTE, "?i_vldc_mdeg_register: mdeg_register "
		    "failed, err = %d", rv);
		kmem_free(name, namesz);
		kmem_free(pspecp, templatesz);
		kmem_free(inst_specp, sizeof (mdeg_node_spec_t));
		return (DDI_FAILURE);
	}

	/* save off data that will be needed later */
	vldcp->inst_spec = inst_specp;
	vldcp->mdeg_hdl = mdeg_hdl;

	return (DDI_SUCCESS);
}

/* unregister callback from mdeg */
static int
i_vldc_mdeg_unregister(vldc_t *vldcp)
{
	char	*name;
	int	rv;

	D1("i_vldc_mdeg_unregister: hdl=0x%lx\n", vldcp->mdeg_hdl);

	rv = mdeg_unregister(vldcp->mdeg_hdl);
	if (rv != MDEG_SUCCESS) {
		return (rv);
	}

	/*
	 * Clean up cached MDEG data
	 */
	name = VLDC_MDEG_PROP_NAME(vldcp->inst_spec->specp);
	if (name != NULL) {
		kmem_free(name, strlen(name) + 1);
	}
	kmem_free(vldcp->inst_spec->specp, sizeof (vldc_prop_template));
	vldcp->inst_spec->specp = NULL;

	kmem_free(vldcp->inst_spec, sizeof (mdeg_node_spec_t));
	vldcp->inst_spec = NULL;

	return (MDEG_SUCCESS);
}

static int
i_vldc_get_port_channel(md_t *mdp, mde_cookie_t node, uint64_t *ldc_id)
{
	int num_nodes, nchan;
	size_t listsz;
	mde_cookie_t *listp;

	/*
	 * Find the channel-endpoint node(s) (which should be under this
	 * port node) which contain the channel id(s).
	 */
	if ((num_nodes = md_node_count(mdp)) <= 0) {
		cmn_err(CE_NOTE, "?i_vldc_get_port_channel: invalid number of "
		    "channel-endpoint nodes found (%d)", num_nodes);
		return (-1);
	}

	/* allocate space for node list */
	listsz = num_nodes * sizeof (mde_cookie_t);
	listp = kmem_alloc(listsz, KM_SLEEP);

	nchan = md_scan_dag(mdp, node, md_find_name(mdp, "channel-endpoint"),
	    md_find_name(mdp, "fwd"), listp);

	if (nchan <= 0) {
		cmn_err(CE_NOTE, "?i_vldc_get_port_channel: no channel-endpoint"
		    " nodes found");
		kmem_free(listp, listsz);
		return (-1);
	}

	D2("i_vldc_get_port_channel: %d channel-endpoint nodes found", nchan);

	/* use property from first node found */
	if (md_get_prop_val(mdp, listp[0], "id", ldc_id)) {
		cmn_err(CE_NOTE, "?i_vldc_get_port_channel: channel-endpoint "
		    "has no 'id' property");
		kmem_free(listp, listsz);
		return (-1);
	}

	kmem_free(listp, listsz);

	return (0);
}

/* add a vldc port */
static int
i_vldc_add_port(vldc_t *vldcp, md_t *mdp, mde_cookie_t node)
{
	vldc_port_t	*vport;
	char		*sname;
	uint64_t	portno;
	int		vldc_inst;
	minor_t		minor;
	int		minor_idx;
	boolean_t	new_minor;
	int		rv;

	ASSERT(MUTEX_HELD(&vldcp->lock));

	/* read in the port's id property */
	if (md_get_prop_val(mdp, node, "id", &portno)) {
		cmn_err(CE_NOTE, "?i_vldc_add_port: node 0x%lx of added "
		    "list has no 'id' property", node);
		return (MDEG_FAILURE);
	}

	if (portno >= VLDC_MAX_PORTS) {
		cmn_err(CE_NOTE, "?i_vldc_add_port: found port number (%lu) "
		    "larger than maximum supported number of ports", portno);
		return (MDEG_FAILURE);
	}

	vport = &(vldcp->port[portno]);

	if (vport->minorp != NULL) {
		cmn_err(CE_NOTE, "?i_vldc_add_port: trying to add a port (%lu)"
		    " which is already bound", portno);
		return (MDEG_FAILURE);
	}

	vport->number = portno;

	/* get all channels for this device (currently only one) */
	if (i_vldc_get_port_channel(mdp, node, &vport->ldc_id) == -1) {
		return (MDEG_FAILURE);
	}

	/* set the default MTU */
	vport->mtu = VLDC_DEFAULT_MTU;

	/* get the service being exported by this port */
	if (md_get_prop_str(mdp, node, "vldc-svc-name", &sname)) {
		cmn_err(CE_NOTE, "?i_vldc_add_port: vdevice has no "
		    "'vldc-svc-name' property");
		return (MDEG_FAILURE);
	}

	/* minor number look up */
	for (minor_idx = 0; minor_idx < vldcp->minors_assigned;
	    minor_idx++) {
		if (strcmp(vldcp->minor_tbl[minor_idx].sname, sname) == 0) {
			/* found previously assigned minor number */
			break;
		}
	}

	new_minor = B_FALSE;
	if (minor_idx == vldcp->minors_assigned) {
		/* end of lookup - assign new minor number */
		if (vldcp->minors_assigned == VLDC_MAX_MINORS) {
			cmn_err(CE_NOTE, "?i_vldc_add_port: too many minor "
			    "nodes (%d)", minor_idx);
			return (MDEG_FAILURE);
		}

		(void) strlcpy(vldcp->minor_tbl[minor_idx].sname,
		    sname, MAXPATHLEN);

		vldcp->minors_assigned++;
		new_minor = B_TRUE;
	}

	if (vldcp->minor_tbl[minor_idx].portno != VLDC_INVALID_PORTNO) {
		cmn_err(CE_NOTE, "?i_vldc_add_port: trying to add a port (%lu)"
		    " which has a minor number in use by port (%u)",
		    portno, vldcp->minor_tbl[minor_idx].portno);
		return (MDEG_FAILURE);
	}

	vldc_inst = ddi_get_instance(vldcp->dip);

	vport->inst = vldc_inst;
	vport->minorp = &vldcp->minor_tbl[minor_idx];
	vldcp->minor_tbl[minor_idx].portno = portno;
	vldcp->minor_tbl[minor_idx].in_use = 0;

	D1("i_vldc_add_port: vldc@%d:%d  mtu=%d, ldc=%ld, service=%s\n",
	    vport->inst, vport->number, vport->mtu, vport->ldc_id, sname);

	/*
	 * Create a minor node. The minor number is
	 * (vldc_inst << VLDC_INST_SHIFT) | minor_idx
	 */
	minor = (vldc_inst << VLDC_INST_SHIFT) | (minor_idx);

	rv = ddi_create_minor_node(vldcp->dip, sname, S_IFCHR,
	    minor, DDI_NT_SERIAL, 0);

	if (rv != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "?i_vldc_add_port: failed to create minor"
		    "node (%u), err = %d", minor, rv);
		vldcp->minor_tbl[minor_idx].portno = VLDC_INVALID_PORTNO;
		if (new_minor) {
			vldcp->minors_assigned--;
		}
		return (MDEG_FAILURE);
	}

	/*
	 * The port is now bound to a minor node and is initially in the
	 * closed state.
	 */
	vport->status = VLDC_PORT_CLOSED;

	D1("i_vldc_add_port: port %lu initialized\n", portno);

	return (MDEG_SUCCESS);
}

/* remove a vldc port */
static int
i_vldc_remove_port(vldc_t *vldcp, uint_t portno)
{
	vldc_port_t *vport;
	vldc_minor_t *vminor;

	ASSERT(vldcp != NULL);
	ASSERT(MUTEX_HELD(&vldcp->lock));

	vport = &(vldcp->port[portno]);
	vminor = vport->minorp;
	if (vminor == NULL) {
		cmn_err(CE_NOTE, "?i_vldc_remove_port: trying to remove a "
		    "port (%u) which is not bound", portno);
		return (MDEG_FAILURE);
	}

	/*
	 * Make sure that all new attempts to open or use the minor node
	 * associated with the port will fail.
	 */
	mutex_enter(&vminor->lock);
	vminor->portno = VLDC_INVALID_PORTNO;
	mutex_exit(&vminor->lock);

	/* send hangup to anyone polling */
	pollwakeup(&vport->poll, POLLHUP);

	/* Now wait for all current users of the minor node to finish. */
	mutex_enter(&vminor->lock);
	while (vminor->in_use > 0) {
		cv_wait(&vminor->cv, &vminor->lock);
	}

	if (vport->status != VLDC_PORT_CLOSED) {
		/* close the port before it is torn down */
		(void) i_vldc_close_port(vldcp, portno);
	}

	/* remove minor node */
	ddi_remove_minor_node(vldcp->dip, vport->minorp->sname);
	vport->minorp = NULL;

	mutex_exit(&vminor->lock);

	D1("i_vldc_remove_port: removed vldc port %u\n", portno);

	return (MDEG_SUCCESS);
}

/*
 * Close and destroy the ldc channel associated with the port 'vport'
 *
 * NOTE It may not be possible close and destroy the channel if resources
 *	are still in use so the fucntion may exit before all the teardown
 *	operations are completed and would have to be called again by the
 *	vldc framework.
 *
 *	This function needs to be able to handle the case where it is called
 *	more than once and has to pick up from where it left off.
 */
static int
i_vldc_ldc_close(vldc_port_t *vport)
{
	int err = 0;

	ASSERT(MUTEX_HELD(&vport->minorp->lock));

	/*
	 * If ldc_close() succeeded or if the channel was already closed[*]
	 * (possibly by a previously unsuccessful call to this function)
	 * we keep going and try to teardown the rest of the LDC state,
	 * otherwise we bail out.
	 *
	 * [*] indicated by ldc_close() returning a value of EFAULT
	 */
	err = ldc_close(vport->ldc_handle);
	if ((err != 0) && (err != EFAULT))
		return (err);

	err = ldc_unreg_callback(vport->ldc_handle);
	if (err != 0)
		return (err);

	err = ldc_fini(vport->ldc_handle);
	if (err != 0)
		return (err);

	vport->status = VLDC_PORT_OPEN;

	return (0);
}

/* close a vldc port */
static int
i_vldc_close_port(vldc_t *vldcp, uint_t portno)
{
	vldc_port_t	*vport;
	vldc_minor_t	*vminor;
	int		rv = DDI_SUCCESS;

	vport = &(vldcp->port[portno]);

	ASSERT(MUTEX_HELD(&vport->minorp->lock));

	D1("i_vldc_close_port: vldc@%d:%d: closing port\n",
	    vport->inst, vport->minorp->portno);

	vminor = vport->minorp;

	switch (vport->status) {
	case VLDC_PORT_CLOSED:
		/* nothing to do */
		DWARN("i_vldc_close_port: port %d in an unexpected "
		    "state (%d)\n", portno, vport->status);
		return (DDI_SUCCESS);

	case VLDC_PORT_READY:
	case VLDC_PORT_RESET:
		do {
			rv = i_vldc_ldc_close(vport);
			if (rv != EAGAIN)
				break;

			/*
			 * EAGAIN indicates that ldc_close() failed because
			 * ldc callback thread is active for the channel.
			 * cv_timedwait() is used to release vminor->lock and
			 * allow ldc callback thread to complete.
			 * after waking up, check if the port has been closed
			 * by another thread in the meantime.
			 */
			(void) cv_timedwait(&vminor->cv, &vminor->lock,
			    ddi_get_lbolt() + drv_usectohz(vldc_close_delay));
			rv = 0;
		} while (vport->status != VLDC_PORT_CLOSED);

		if ((rv != 0) || (vport->status == VLDC_PORT_CLOSED))
			return (rv);

		break;

	case VLDC_PORT_OPEN:
		break;

	default:
		DWARN("i_vldc_close_port: port %d in an unexpected "
		    "state (%d)\n", portno, vport->status);
		ASSERT(0);	/* fail quickly to help diagnosis */
		return (EINVAL);
	}

	ASSERT(vport->status == VLDC_PORT_OPEN);

	/* free memory */
	kmem_free(vport->send_buf, vport->mtu);
	kmem_free(vport->recv_buf, vport->mtu);

	if (strcmp(vminor->sname, VLDC_HVCTL_SVCNAME) == 0)
		kmem_free(vport->cookie_buf, vldc_max_cookie);

	vport->status = VLDC_PORT_CLOSED;

	return (rv);
}

/*
 * attach(9E): attach a device to the system.
 * called once for each instance of the device on the system.
 */
static int
vldc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int 	i, instance;
	vldc_t	*vldcp;

	switch (cmd) {

	case DDI_ATTACH:

		instance = ddi_get_instance(dip);

		if (ddi_soft_state_zalloc(vldc_ssp, instance) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		vldcp = ddi_get_soft_state(vldc_ssp, instance);
		if (vldcp == NULL) {
			ddi_soft_state_free(vldc_ssp, instance);
			return (ENXIO);
		}

		D1("vldc_attach: DDI_ATTACH instance=%d\n", instance);

		mutex_init(&vldcp->lock, NULL, MUTEX_DRIVER, NULL);
		vldcp->dip = dip;
		vldcp->detaching = B_FALSE;

		for (i = 0; i < VLDC_MAX_PORTS; i++) {
			/* No minor node association to start with */
			vldcp->port[i].minorp = NULL;
		}

		for (i = 0; i < VLDC_MAX_MINORS; i++) {
			mutex_init(&(vldcp->minor_tbl[i].lock), NULL,
			    MUTEX_DRIVER, NULL);
			cv_init(&(vldcp->minor_tbl[i].cv), NULL,
			    CV_DRIVER, NULL);
			/* No port association to start with */
			vldcp->minor_tbl[i].portno = VLDC_INVALID_PORTNO;
		}

		/* Register for MD update notification */
		if (i_vldc_mdeg_register(vldcp) != DDI_SUCCESS) {
			ddi_soft_state_free(vldc_ssp, instance);
			return (DDI_FAILURE);
		}

		return (DDI_SUCCESS);

	case DDI_RESUME:

		return (DDI_SUCCESS);

	default:

		return (DDI_FAILURE);
	}
}

/*
 * detach(9E): detach a device from the system.
 */
static int
vldc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int 		i, instance;
	vldc_t		*vldcp;

	switch (cmd) {

	case DDI_DETACH:

		instance = ddi_get_instance(dip);

		vldcp = ddi_get_soft_state(vldc_ssp, instance);
		if (vldcp == NULL) {
			return (DDI_FAILURE);
		}

		D1("vldc_detach: DDI_DETACH instance=%d\n", instance);

		mutex_enter(&vldcp->lock);

		/* Fail the detach if all ports have not been removed. */
		for (i = 0; i < VLDC_MAX_MINORS; i++) {
			if (vldcp->minor_tbl[i].portno != VLDC_INVALID_PORTNO) {
				D1("vldc_detach: vldc@%d:%d is bound, "
				    "detach failed\n",
				    instance, vldcp->minor_tbl[i].portno);
				mutex_exit(&vldcp->lock);
				return (DDI_FAILURE);
			}
		}

		/*
		 * Prevent MDEG from adding new ports before the callback can
		 * be unregistered. The lock can't be held accross the
		 * unregistration call because a callback may be in progress
		 * and blocked on the lock.
		 */
		vldcp->detaching = B_TRUE;

		mutex_exit(&vldcp->lock);

		if (i_vldc_mdeg_unregister(vldcp) != MDEG_SUCCESS) {
			vldcp->detaching = B_FALSE;
			return (DDI_FAILURE);
		}

		/* Tear down all bound ports and free resources. */
		for (i = 0; i < VLDC_MAX_MINORS; i++) {
			if (vldcp->minor_tbl[i].portno != VLDC_INVALID_PORTNO) {
				(void) i_vldc_remove_port(vldcp, i);
			}
			mutex_destroy(&(vldcp->minor_tbl[i].lock));
			cv_destroy(&(vldcp->minor_tbl[i].cv));
		}

		mutex_destroy(&vldcp->lock);
		ddi_soft_state_free(vldc_ssp, instance);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:

		return (DDI_SUCCESS);

	default:

		return (DDI_FAILURE);
	}
}

/* cb_open */
static int
vldc_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
	_NOTE(ARGUNUSED(flag, otyp, cred))

	int instance;
	minor_t minor;
	uint64_t portno;
	vldc_t *vldcp;
	vldc_port_t *vport;
	vldc_minor_t *vminor;

	minor = getminor(*devp);
	instance = VLDCINST(minor);
	vldcp = ddi_get_soft_state(vldc_ssp, instance);
	if (vldcp == NULL)
		return (ENXIO);

	vminor = VLDCMINOR(vldcp, minor);
	mutex_enter(&vminor->lock);
	portno = vminor->portno;
	if (portno == VLDC_INVALID_PORTNO) {
		mutex_exit(&vminor->lock);
		return (ENXIO);
	}

	vport = &(vldcp->port[portno]);

	D1("vldc_open: opening vldc@%d:%lu\n", instance, portno);

	if (vport->status != VLDC_PORT_CLOSED) {
		mutex_exit(&vminor->lock);
		return (EBUSY);
	}

	vport->recv_buf = kmem_alloc(vport->mtu, KM_SLEEP);
	vport->send_buf = kmem_alloc(vport->mtu, KM_SLEEP);

	if (strcmp(vport->minorp->sname, VLDC_HVCTL_SVCNAME) == 0)
		vport->cookie_buf = kmem_alloc(vldc_max_cookie, KM_SLEEP);

	vport->is_stream = B_FALSE;	/* assume not a stream */
	vport->hanged_up = B_FALSE;

	vport->status = VLDC_PORT_OPEN;

	mutex_exit(&vminor->lock);

	return (DDI_SUCCESS);
}

/* cb_close */
static int
vldc_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	_NOTE(ARGUNUSED(flag, otyp, cred))

	int instance;
	minor_t minor;
	uint64_t portno;
	vldc_t *vldcp;
	vldc_minor_t *vminor;
	int rv;

	minor = getminor(dev);
	instance = VLDCINST(minor);
	vldcp = ddi_get_soft_state(vldc_ssp, instance);
	if (vldcp == NULL) {
		return (ENXIO);
	}

	vminor = VLDCMINOR(vldcp, minor);
	mutex_enter(&vminor->lock);
	portno = vminor->portno;
	if (portno == VLDC_INVALID_PORTNO) {
		mutex_exit(&vminor->lock);
		return (ENOLINK);
	}

	D1("vldc_close: closing vldc@%d:%lu\n", instance, portno);

	rv = i_vldc_close_port(vldcp, portno);

	mutex_exit(&vminor->lock);

	return (rv);
}

static int
vldc_set_ldc_mode(vldc_port_t *vport, vldc_t *vldcp, int channel_mode)
{
	ldc_attr_t attr;
	int rv;

	ASSERT(MUTEX_HELD(&vport->minorp->lock));

	/* validate mode */
	switch (channel_mode) {
	case LDC_MODE_RELIABLE:
		vport->is_stream = B_TRUE;
		break;
	case LDC_MODE_RAW:
	case LDC_MODE_UNRELIABLE:
		vport->is_stream = B_FALSE;
		break;
	default:
		return (EINVAL);
	}

	if (vport->status == VLDC_PORT_READY) {
		rv = i_vldc_ldc_close(vport);
		if (rv != 0) {
			DWARN("vldc_set_ldc_mode: i_vldc_ldc_close "
			    "failed, rv=%d\n", rv);
			return (rv);
		}
	}

	D1("vldc_set_ldc_mode: vport status %d, mode %d\n",
	    vport->status, channel_mode);

	vport->ldc_mode = channel_mode;

	/* initialize the channel */
	attr.devclass = LDC_DEV_SERIAL;
	attr.instance = ddi_get_instance(vldcp->dip);
	attr.mtu = vport->mtu;
	attr.mode = vport->ldc_mode;

	if ((rv = ldc_init(vport->ldc_id, &attr,
	    &vport->ldc_handle)) != 0) {
		DWARN("vldc_ioctl_opt_op: ldc_init failed, rv=%d\n", rv);
		goto error_init;
	}

	/* register it */
	if ((rv = ldc_reg_callback(vport->ldc_handle,
	    i_vldc_cb, (caddr_t)vport)) != 0) {
		DWARN("vldc_ioctl_opt_op: ldc_reg_callback failed, rv=%d\n",
		    rv);
		goto error_reg;
	}

	/* open the channel */
	if ((rv = ldc_open(vport->ldc_handle)) != 0) {
		DWARN("vldc_ioctl_opt_op: ldc_open failed, rv=%d\n", rv);
		goto error_open;
	}

	vport->status = VLDC_PORT_READY;

	/*
	 * Attempt to bring the channel up, but do not
	 * fail if the other end is not up yet.
	 */
	rv = ldc_up(vport->ldc_handle);
	if (rv == ECONNREFUSED) {
		D1("vldc_ioctl_opt_op: remote endpoint not up yet\n");
	} else if (rv != 0) {
		DWARN("vldc_ioctl_opt_op: ldc_up failed, rv=%d\n", rv);
		goto error_up;
	}

	rv = ldc_status(vport->ldc_handle, &vport->ldc_status);
	if (rv != 0) {
		DWARN("vldc_ioctl_opt_op: vldc@%d:%d could not get ldc "
		    "status, rv=%d\n", vport->inst, vport->number, rv);
		goto error_up;
	}

	D1("vldc_ioctl_opt_op: ldc %ld initialized successfully\n",
	    vport->ldc_id);

	return (0);

error_up:
	vport->status = VLDC_PORT_OPEN;
	(void) ldc_close(vport->ldc_handle);
error_open:
	(void) ldc_unreg_callback(vport->ldc_handle);
error_reg:
	(void) ldc_fini(vport->ldc_handle);
error_init:
	return (rv);
}

/* ioctl to read cookie */
static int
i_vldc_ioctl_read_cookie(vldc_port_t *vport, int vldc_instance, void *arg,
    int mode)
{
	vldc_data_t copy_info;
	uint64_t len, balance, copy_size;
	caddr_t src_addr, dst_addr;
	int rv;

	if (ddi_copyin(arg, &copy_info, sizeof (copy_info), mode) == -1) {
		return (EFAULT);
	}

	len = balance = copy_info.length;
	src_addr = (caddr_t)copy_info.src_addr;
	dst_addr = (caddr_t)copy_info.dst_addr;
	while (balance > 0) {

		/* get the max amount to the copied */
		copy_size = MIN(balance, vldc_max_cookie);

		mutex_enter(&vport->minorp->lock);

		D2("i_vldc_ioctl_read_cookie: vldc@%d:%d reading from 0x%p "
		    "size 0x%lx to 0x%p\n", vldc_instance, vport->number,
		    dst_addr, copy_size, src_addr);

		/* read from the HV into the temporary buffer */
		rv = ldc_mem_rdwr_cookie(vport->ldc_handle, vport->cookie_buf,
		    &copy_size, dst_addr, LDC_COPY_IN);
		if (rv != 0) {
			DWARN("i_vldc_ioctl_read_cookie: vldc@%d:%d cannot "
			    "read address 0x%p, rv=%d\n",
			    vldc_instance, vport->number, dst_addr, rv);
			mutex_exit(&vport->minorp->lock);
			return (EFAULT);
		}

		D2("i_vldc_ioctl_read_cookie: vldc@%d:%d read succeeded\n",
		    vldc_instance, vport->number);

		mutex_exit(&vport->minorp->lock);

		/*
		 * copy data from temporary buffer out to the
		 * caller and free buffer
		 */
		rv = ddi_copyout(vport->cookie_buf, src_addr, copy_size, mode);
		if (rv != 0) {
			return (EFAULT);
		}

		/* adjust len, source and dest */
		balance -= copy_size;
		src_addr += copy_size;
		dst_addr += copy_size;
	}

	/* set the structure to reflect outcome */
	copy_info.length = len;
	if (ddi_copyout(&copy_info, arg, sizeof (copy_info), mode) != 0) {
		return (EFAULT);
	}

	return (0);
}

/* ioctl to write cookie */
static int
i_vldc_ioctl_write_cookie(vldc_port_t *vport, int vldc_instance, void *arg,
    int mode)
{
	vldc_data_t copy_info;
	uint64_t len, balance, copy_size;
	caddr_t src_addr, dst_addr;
	int rv;

	if (ddi_copyin(arg, &copy_info, sizeof (copy_info), mode) != 0) {
		return (EFAULT);
	}

	D2("i_vldc_ioctl_write_cookie: vldc@%d:%d writing 0x%lx size 0x%lx "
	    "to 0x%lx\n", vldc_instance, vport->number, copy_info.src_addr,
	    copy_info.length, copy_info.dst_addr);

	len = balance = copy_info.length;
	src_addr = (caddr_t)copy_info.src_addr;
	dst_addr = (caddr_t)copy_info.dst_addr;
	while (balance > 0) {

		/* get the max amount to the copied */
		copy_size = MIN(balance, vldc_max_cookie);

		/*
		 * copy into the temporary buffer the data
		 * to be written to the HV
		 */
		if (ddi_copyin((caddr_t)src_addr, vport->cookie_buf,
		    copy_size, mode) != 0) {
			return (EFAULT);
		}

		mutex_enter(&vport->minorp->lock);

		/* write the data from the temporary buffer to the HV */
		rv = ldc_mem_rdwr_cookie(vport->ldc_handle, vport->cookie_buf,
		    &copy_size, dst_addr, LDC_COPY_OUT);
		if (rv != 0) {
			DWARN("i_vldc_ioctl_write_cookie: vldc@%d:%d "
			    "failed to write at address 0x%p\n, rv=%d",
			    vldc_instance, vport->number, dst_addr, rv);
			mutex_exit(&vport->minorp->lock);
			return (EFAULT);
		}

		D2("i_vldc_ioctl_write_cookie: vldc@%d:%d write succeeded\n",
		    vldc_instance, vport->number);

		mutex_exit(&vport->minorp->lock);

		/* adjust len, source and dest */
		balance -= copy_size;
		src_addr += copy_size;
		dst_addr += copy_size;
	}

	/* set the structure to reflect outcome */
	copy_info.length = len;
	if (ddi_copyout(&copy_info, (caddr_t)arg,
	    sizeof (copy_info), mode) != 0) {
		return (EFAULT);
	}

	return (0);
}

/* vldc specific ioctl option commands */
static int
i_vldc_ioctl_opt_op(vldc_port_t *vport, vldc_t *vldcp, void *arg, int mode)
{
	vldc_opt_op_t 	vldc_cmd;
	uint32_t	new_mtu;
	int		rv = 0;

	if (ddi_copyin(arg, &vldc_cmd, sizeof (vldc_cmd), mode) != 0) {
		return (EFAULT);
	}

	D1("vldc_ioctl_opt_op: op %d\n", vldc_cmd.opt_sel);

	switch (vldc_cmd.opt_sel) {

	case VLDC_OPT_MTU_SZ:

		if (vldc_cmd.op_sel == VLDC_OP_GET) {
			vldc_cmd.opt_val = vport->mtu;
			if (ddi_copyout(&vldc_cmd, arg,
			    sizeof (vldc_cmd), mode) == -1) {
				return (EFAULT);
			}
		} else {
			new_mtu = vldc_cmd.opt_val;

			if ((new_mtu < LDC_PACKET_SIZE) ||
			    (new_mtu > vldc_max_mtu)) {
				return (EINVAL);
			}

			mutex_enter(&vport->minorp->lock);

			if ((vport->status != VLDC_PORT_CLOSED) &&
			    (new_mtu != vport->mtu)) {
				/*
				 * The port has buffers allocated since it is
				 * not closed plus the MTU size has changed.
				 * Reallocate the buffers to the new MTU size.
				 */
				kmem_free(vport->recv_buf, vport->mtu);
				vport->recv_buf = kmem_alloc(new_mtu, KM_SLEEP);

				kmem_free(vport->send_buf, vport->mtu);
				vport->send_buf = kmem_alloc(new_mtu, KM_SLEEP);

				vport->mtu = new_mtu;
			}

			mutex_exit(&vport->minorp->lock);
		}

		break;

	case VLDC_OPT_STATUS:

		if (vldc_cmd.op_sel == VLDC_OP_GET) {
			vldc_cmd.opt_val = vport->status;
			if (ddi_copyout(&vldc_cmd, arg,
			    sizeof (vldc_cmd), mode) == -1) {
				return (EFAULT);
			}
		} else {
			return (ENOTSUP);
		}

		break;

	case VLDC_OPT_MODE:

		if (vldc_cmd.op_sel == VLDC_OP_GET) {
			vldc_cmd.opt_val = vport->ldc_mode;
			if (ddi_copyout(&vldc_cmd, arg,
			    sizeof (vldc_cmd), mode) == -1) {
				return (EFAULT);
			}
		} else {
			mutex_enter(&vport->minorp->lock);
			rv = vldc_set_ldc_mode(vport, vldcp, vldc_cmd.opt_val);
			mutex_exit(&vport->minorp->lock);
		}

		break;

	default:

		D1("vldc_ioctl_opt_op: unsupported op %d\n", vldc_cmd.opt_sel);
		return (ENOTSUP);
	}

	return (rv);
}

/* cb_ioctl */
static int
vldc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	_NOTE(ARGUNUSED(credp, rvalp))

	int rv = EINVAL;
	int instance;
	minor_t minor;
	uint64_t portno;
	vldc_t *vldcp;
	vldc_port_t *vport;
	vldc_minor_t *vminor;

	minor = getminor(dev);
	instance = VLDCINST(minor);
	vldcp = ddi_get_soft_state(vldc_ssp, instance);
	if (vldcp == NULL) {
		return (ENXIO);
	}

	vminor = VLDCMINOR(vldcp, minor);
	mutex_enter(&vminor->lock);
	portno = vminor->portno;
	if (portno == VLDC_INVALID_PORTNO) {
		mutex_exit(&vminor->lock);
		return (ENOLINK);
	}
	vminor->in_use += 1;
	mutex_exit(&vminor->lock);

	vport = &(vldcp->port[portno]);

	D1("vldc_ioctl: vldc@%d:%lu cmd=0x%x\n", instance, portno, cmd);

	switch (cmd) {

	case VLDC_IOCTL_OPT_OP:
		rv = i_vldc_ioctl_opt_op(vport, vldcp, (void *)arg,  mode);
		break;

	case VLDC_IOCTL_READ_COOKIE:
		if (strcmp(vport->minorp->sname, VLDC_HVCTL_SVCNAME)) {
			rv = EINVAL;
			break;
		}
		rv = i_vldc_ioctl_read_cookie(vport, instance,
		    (void *)arg, mode);
		break;

	case VLDC_IOCTL_WRITE_COOKIE:
		if (strcmp(vport->minorp->sname, VLDC_HVCTL_SVCNAME)) {
			rv = EINVAL;
			break;
		}
		rv = i_vldc_ioctl_write_cookie(vport, instance,
		    (void *)arg, mode);
		break;

	default:
		DWARN("vldc_ioctl: vldc@%d:%lu unknown cmd=0x%x\n",
		    instance, portno, cmd);
		rv = EINVAL;
		break;
	}

	mutex_enter(&vminor->lock);
	vminor->in_use -= 1;
	if (vminor->in_use == 0) {
		cv_signal(&vminor->cv);
	}
	mutex_exit(&vminor->lock);

	D1("vldc_ioctl: rv=%d\n", rv);

	return (rv);
}

/* cb_read */
static int
vldc_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp))

	int instance;
	minor_t minor;
	size_t size = 0;
	uint64_t portno;
	vldc_t *vldcp;
	vldc_port_t *vport;
	vldc_minor_t *vminor;
	int rv = 0;

	minor = getminor(dev);
	instance = VLDCINST(minor);
	vldcp = ddi_get_soft_state(vldc_ssp, instance);
	if (vldcp == NULL) {
		return (ENXIO);
	}

	vminor = VLDCMINOR(vldcp, minor);
	mutex_enter(&vminor->lock);
	portno = vminor->portno;
	if (portno == VLDC_INVALID_PORTNO) {
		mutex_exit(&vminor->lock);
		return (ENOLINK);
	}

	D2("vldc_read: vldc@%d:%lu reading data\n", instance, portno);

	vport = &(vldcp->port[portno]);

	/* check the port status */
	if (vport->status != VLDC_PORT_READY) {
		DWARN("vldc_read: vldc@%d:%lu not in the ready state\n",
		    instance, portno);
		mutex_exit(&vminor->lock);
		return (ENOTACTIVE);
	}

	/* read data */
	size = MIN(vport->mtu, uiop->uio_resid);
	rv = ldc_read(vport->ldc_handle, vport->recv_buf, &size);

	D2("vldc_read: vldc@%d:%lu ldc_read size=%ld, rv=%d\n",
	    instance, portno, size, rv);

	if (rv == 0) {
		if (size != 0) {
			rv = uiomove(vport->recv_buf, size, UIO_READ, uiop);
		} else {
			rv = EWOULDBLOCK;
		}
	} else {
		switch (rv) {
		case ENOBUFS:
			break;
		case ETIMEDOUT:
		case EWOULDBLOCK:
			rv = EWOULDBLOCK;
			break;
		default:
			rv = ECONNRESET;
			break;
		}
	}

	mutex_exit(&vminor->lock);

	return (rv);
}

/* cb_write */
static int
vldc_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp))

	int instance;
	minor_t minor;
	size_t size;
	size_t orig_size;
	uint64_t portno;
	vldc_t *vldcp;
	vldc_port_t *vport;
	vldc_minor_t *vminor;
	int rv = EINVAL;

	minor = getminor(dev);
	instance = VLDCINST(minor);
	vldcp = ddi_get_soft_state(vldc_ssp, instance);
	if (vldcp == NULL) {
		return (ENXIO);
	}

	vminor = VLDCMINOR(vldcp, minor);
	mutex_enter(&vminor->lock);
	portno = vminor->portno;
	if (portno == VLDC_INVALID_PORTNO) {
		mutex_exit(&vminor->lock);
		return (ENOLINK);
	}

	vport = &(vldcp->port[portno]);

	/* check the port status */
	if (vport->status != VLDC_PORT_READY) {
		DWARN("vldc_write: vldc@%d:%lu not in the ready state\n",
		    instance, portno);
		mutex_exit(&vminor->lock);
		return (ENOTACTIVE);
	}

	orig_size = uiop->uio_resid;
	size = orig_size;

	if (size > vport->mtu) {
		if (vport->is_stream) {
			/* can only send MTU size at a time */
			size = vport->mtu;
		} else {
			mutex_exit(&vminor->lock);
			return (EMSGSIZE);
		}
	}

	D2("vldc_write: vldc@%d:%lu writing %lu bytes\n", instance, portno,
	    size);

	rv = uiomove(vport->send_buf, size, UIO_WRITE, uiop);
	if (rv == 0) {
		rv = ldc_write(vport->ldc_handle, (caddr_t)vport->send_buf,
		    &size);
		if (rv != 0) {
			DWARN("vldc_write: vldc@%d:%lu failed writing %lu "
			    "bytes rv=%d\n", instance, portno, size, rv);
		}
	} else {
		size = 0;
	}

	mutex_exit(&vminor->lock);

	/* resid is total number of bytes *not* sent */
	uiop->uio_resid = orig_size - size;

	return (rv);
}

/* cb_chpoll */
static int
vldc_chpoll(dev_t dev, short events, int anyyet,  short *reventsp,
    struct pollhead **phpp)
{
	int instance;
	minor_t minor;
	uint64_t portno;
	vldc_t *vldcp;
	vldc_port_t *vport;
	vldc_minor_t *vminor;
	boolean_t haspkts;

	minor = getminor(dev);
	instance = VLDCINST(minor);
	vldcp = ddi_get_soft_state(vldc_ssp, instance);
	if (vldcp == NULL) {
		return (ENXIO);
	}

	vminor = VLDCMINOR(vldcp, minor);
	mutex_enter(&vminor->lock);
	portno = vminor->portno;
	if (portno == VLDC_INVALID_PORTNO) {
		mutex_exit(&vminor->lock);
		return (ENOLINK);
	}

	vport = &(vldcp->port[portno]);

	/* check the port status */
	if (vport->status != VLDC_PORT_READY) {
		mutex_exit(&vminor->lock);
		return (ENOTACTIVE);
	}

	D2("vldc_chpoll: vldc@%d:%lu polling events 0x%x\n",
	    instance, portno, events);

	*reventsp = 0;

	if (vport->ldc_status == LDC_UP) {
		/*
		 * Check if the receive queue is empty and if not, signal that
		 * there is data ready to read.
		 */
		if (events & POLLIN) {
			if ((ldc_chkq(vport->ldc_handle, &haspkts) == 0) &&
			    haspkts) {
				*reventsp |= POLLIN;
			}
		}

		if (events & POLLOUT)
			*reventsp |= POLLOUT;

	} else if (vport->hanged_up) {
		*reventsp |= POLLHUP;
		vport->hanged_up = B_FALSE;
	}

	mutex_exit(&vminor->lock);

	if (((*reventsp) == 0) && (!anyyet)) {
		*phpp = &vport->poll;
	}

	D2("vldc_chpoll: vldc@%d:%lu ev=0x%x, rev=0x%x\n",
	    instance, portno, events, *reventsp);

	return (0);
}
