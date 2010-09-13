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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/sunddi.h>
#include <sys/mac_provider.h>
#include <sys/dls_impl.h>
#include <inet/ipnet.h>

extern	int	bpfopen(dev_t *devp, int flag, int otyp, cred_t *cred);
extern	int	bpfclose(dev_t dev, int flag, int otyp, cred_t *cred);
extern	int	bpfread(dev_t dev, struct uio *uio_p, cred_t *cred_p);
extern	int	bpfwrite(dev_t dev, struct uio *uio, cred_t *cred);
extern	int	bpfchpoll(dev_t, short, int, short *, struct pollhead **);
extern	int	bpfioctl(dev_t, int, intptr_t, int, cred_t *, int *);
extern	int	bpfilterattach(void);
extern	int	bpfilterdetach(void);

extern	bpf_provider_t	bpf_mac;
extern	bpf_provider_t	bpf_ipnet;

static	int	bpf_attach(dev_info_t *, ddi_attach_cmd_t);
static	void	*bpf_create_inst(const netid_t);
static	void	bpf_destroy_inst(const netid_t, void *);
static	int	bpf_detach(dev_info_t *, ddi_detach_cmd_t);
static	int	bpf_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static	int	bpf_provider_add(bpf_provider_t *);
static	int	bpf_provider_remove(bpf_provider_t *);
static	void	bpf_shutdown_inst(const netid_t, void *);

extern	void	bpfdetach(uintptr_t);
extern	int	bpf_bufsize;
extern	int	bpf_maxbufsize;

bpf_provider_head_t bpf_providers;

static struct cb_ops bpf_cb_ops = {
	bpfopen,
	bpfclose,
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	bpfread,
	bpfwrite,	/* write */
	bpfioctl,	/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	bpfchpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_MTSAFE,
	CB_REV,
	nodev,		/* aread */
	nodev,		/* awrite */
};

static struct dev_ops bpf_ops = {
	DEVO_REV,
	0,
	bpf_getinfo,
	nulldev,
	nulldev,
	bpf_attach,
	bpf_detach,
	nodev,		/* reset */
	&bpf_cb_ops,
	(struct bus_ops *)0
};

extern struct mod_ops mod_driverops;
static struct modldrv bpfmod = {
	&mod_driverops, "Berkely Packet Filter", &bpf_ops
};
static struct modlinkage modlink1 = { MODREV_1, &bpfmod, NULL };

static dev_info_t *bpf_dev_info = NULL;
static net_instance_t *bpf_inst = NULL;

int
_init()
{
	int bpfinst;

	bpfinst = mod_install(&modlink1);
	return (bpfinst);
}

int
_fini(void)
{
	int bpfinst;

	bpfinst = mod_remove(&modlink1);
	return (bpfinst);
}

int
_info(struct modinfo *modinfop)
{
	int bpfinst;

	bpfinst = mod_info(&modlink1, modinfop);
	return (bpfinst);
}

static int
bpf_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{

	switch (cmd) {
	case DDI_ATTACH:
		/*
		 * Default buffer size from bpf's driver.conf file
		 */
		bpf_bufsize = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
		    "buf_size", 32 * 1024);
		/*
		 * Maximum buffer size from bpf's driver.conf file
		 */
		bpf_maxbufsize = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
		    "max_buf_size", 16 * 1024 * 1024);

		if (ddi_create_minor_node(dip, "bpf", S_IFCHR, 0,
		    DDI_PSEUDO, 0) == DDI_FAILURE) {
			ddi_remove_minor_node(dip, NULL);
			goto attach_failed;
		}
		bpf_dev_info = dip;
		ddi_report_dev(dip);

		LIST_INIT(&bpf_providers);

		if (bpfilterattach() != 0)
			goto attach_failed;

		ipnet_set_itap(bpf_itap);
		VERIFY(bpf_provider_add(&bpf_ipnet) == 0);
		VERIFY(bpf_provider_add(&bpf_mac) == 0);

		/*
		 * Set up to be notified about zones coming and going
		 * so that proper interaction with ipnet is possible.
		 */
		bpf_inst = net_instance_alloc(NETINFO_VERSION);
		if (bpf_inst == NULL)
			goto attach_failed;
		bpf_inst->nin_name = "bpf";
		bpf_inst->nin_create = bpf_create_inst;
		bpf_inst->nin_destroy = bpf_destroy_inst;
		bpf_inst->nin_shutdown = bpf_shutdown_inst;
		if (net_instance_register(bpf_inst) != 0) {
			net_instance_free(bpf_inst);
			goto attach_failed;
		}

		return (DDI_SUCCESS);
		/* NOTREACHED */
	case DDI_RESUME:
		return (DDI_SUCCESS);
		/* NOTREACHED */
	default:
		break;
	}

attach_failed:

	/*
	 * Use our own detach routine to toss
	 * away any stuff we allocated above.
	 */
	(void) bpfilterdetach();
	(void) bpf_detach(dip, DDI_DETACH);
	return (DDI_FAILURE);
}

static int
bpf_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int error;

	switch (cmd) {
	case DDI_DETACH:
		if (net_instance_unregister(bpf_inst) != 0)
			return (DDI_FAILURE);
		net_instance_free(bpf_inst);

		ipnet_set_itap(NULL);
		error = bpfilterdetach();
		if (error != 0)
			return (DDI_FAILURE);
		VERIFY(bpf_provider_remove(&bpf_ipnet) == 0);
		VERIFY(bpf_provider_remove(&bpf_mac) == 0);

		ASSERT(LIST_EMPTY(&bpf_providers));

		ddi_prop_remove_all(dip);

		return (DDI_SUCCESS);
		/* NOTREACHED */
	case DDI_SUSPEND:
	case DDI_PM_SUSPEND:
		return (DDI_SUCCESS);
		/* NOTREACHED */
	default:
		break;
	}
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
bpf_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = bpf_dev_info;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		break;
	}
	return (error);
}

/*
 * The two functions below work with and manage a list of providers that
 * supply BPF with packets. Their addition and removal is only happens
 * when the bpf module is attaching/detaching, thus there is no race
 * condition to guard against with using locks as the kernel module system
 * takes care of this for us. Similarly, bpf_provider_tickle() is called
 * from bpf_setif, which implies an open file descriptor that would get
 * in the way of detach being active.
 */
static int
bpf_provider_add(bpf_provider_t *provider)
{
	bpf_provider_list_t *bp;

	LIST_FOREACH(bp, &bpf_providers, bpl_next) {
		if (bp->bpl_what == provider)
			return (EEXIST);
	}


	bp = kmem_alloc(sizeof (*bp), KM_SLEEP);
	bp->bpl_what = provider;
	LIST_INSERT_HEAD(&bpf_providers, bp, bpl_next);

	return (0);
}

static int
bpf_provider_remove(bpf_provider_t *provider)
{
	bpf_provider_list_t *bp;

	LIST_FOREACH(bp, &bpf_providers, bpl_next) {
		if (bp->bpl_what == provider)
			break;
	}

	if (bp == NULL)
		return (ESRCH);

	LIST_REMOVE(bp, bpl_next);

	kmem_free(bp, sizeof (*bp));

	return (0);
}

/*
 * return a pointer to the structure that holds all of the functions
 * available to be used to support a particular packet provider.
 */
bpf_provider_t *
bpf_find_provider_by_id(int who)
{
	bpf_provider_list_t *b;

	LIST_FOREACH(b, &bpf_providers, bpl_next) {
		if (b->bpl_what->bpr_unit == who)
			return (b->bpl_what);
	}

	return (NULL);
}

/*
 * This function is used by bpf_setif() to force an open() to be called on
 * a given device name. If a device has been unloaded by the kernel, but it
 * is still recognised, then calling this function will hopefully cause it
 * to be loaded back into the kernel. When this function is called, it is
 * not known which packet provider the name belongs to so all are tried.
 */
int
bpf_provider_tickle(char *name, zoneid_t zone)
{
	bpf_provider_list_t *bp;
	uintptr_t handle;
	int tickled = 0;

	LIST_FOREACH(bp, &bpf_providers, bpl_next) {
		handle = 0;
		if (bp->bpl_what->bpr_open(name, &handle, zone) == 0) {
			bp->bpl_what->bpr_close(handle);
			tickled++;
		} else if (bp->bpl_what->bpr_unit == BPR_MAC) {
			/*
			 * For mac devices, sometimes the open/close is not
			 * enough. In that case, further provocation is
			 * attempted by fetching the linkid and trying to
			 * use that as the key for open, rather than the
			 * name.
			 */
			datalink_id_t id;

			if (bp->bpl_what->bpr_getlinkid(name, &id,
			    zone) == 0) {
				if (bp->bpl_what->bpr_open(name, &handle,
				    zone) == 0) {
					bp->bpl_what->bpr_close(handle);
					tickled++;
				} else {
					mac_handle_t mh;

					if (mac_open_by_linkid(id, &mh) == 0) {
						mac_close(mh);
						tickled++;
					}
				}
			}
		}

	}

	if (tickled != 0)
		return (EWOULDBLOCK);

	return (ENXIO);
}

/*
 * The following three functions provide the necessary callbacks into
 * the netinfo API. This API is primarily used to trigger awareness of
 * when a zone is being torn down, allowing BPF to drive IPNET to
 * tell it which interfaces need to go away.
 */
/*ARGSUSED*/
static void *
bpf_create_inst(const netid_t netid)
{
	/*
	 * BPF does not keep any per-instance state, its list of
	 * interfaces is global, as is its device hash table.
	 */
	return ((void *)bpf_itap);
}

/*ARGSUSED*/
static void
bpf_shutdown_inst(const netid_t netid, void *arg)
{
}

/*ARGSUSED*/
static void
bpf_destroy_inst(const netid_t netid, void *arg)
{
}
