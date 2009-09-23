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
 * IP Tunneling Driver
 *
 * As viewed from the top, this module is a GLDv3 driver that consumes the
 * mac driver interfaces.  It implements the logic for various forms of IP
 * (IPv4 or IPv6) encapsulation within IP (IPv4 or IPv6).
 */

#include <sys/file.h>
#include <sys/list.h>
#include "iptun_impl.h"

#define	IPTUN_LINKINFO		"IP tunneling driver"
#define	IPTUN_HASHSZ		67

dev_info_t	*iptun_dip;
ldi_ident_t	iptun_ldi_ident;

static int	iptun_attach(dev_info_t *, ddi_attach_cmd_t);
static int	iptun_detach(dev_info_t *, ddi_detach_cmd_t);
static int	iptun_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	iptun_constructor(void *, void *, int);
static void	iptun_destructor(void *, void *);

DDI_DEFINE_STREAM_OPS(iptun_dev_ops, nulldev, nulldev, iptun_attach,
    iptun_detach, nodev, iptun_getinfo, D_MP, NULL, ddi_quiesce_not_supported);

static struct modldrv iptun_modldrv = {
	&mod_driverops,
	IPTUN_LINKINFO,
	&iptun_dev_ops
};

static struct modlinkage iptun_modlinkage = {
	MODREV_1,
	&iptun_modldrv,
	NULL
};

/*
 * Initialize the tunnel stack instance.
 */
/* ARGSUSED */
static void *
iptun_stack_init(netstackid_t stackid, netstack_t *ns)
{
	iptun_stack_t	*iptuns;

	iptuns = kmem_zalloc(sizeof (*iptuns), KM_SLEEP);
	iptuns->iptuns_netstack = ns;
	mutex_init(&iptuns->iptuns_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&iptuns->iptuns_iptunlist, sizeof (iptun_t),
	    offsetof(iptun_t, iptun_link));

	return (iptuns);
}

/* ARGSUSED */
static void
iptun_stack_shutdown(netstackid_t stackid, void *arg)
{
	iptun_stack_t	*iptuns = arg;
	iptun_t		*iptun;
	datalink_id_t	linkid;

	/* note that iptun_delete() removes iptun from the list */
	while ((iptun = list_head(&iptuns->iptuns_iptunlist)) != NULL) {
		linkid = iptun->iptun_linkid;
		(void) iptun_delete(linkid, iptun->iptun_cred);
		(void) dls_mgmt_destroy(linkid, B_FALSE);
	}
	if (iptuns->iptuns_g_q != NULL)
		(void) ldi_close(iptuns->iptuns_g_q_lh, FWRITE|FREAD, CRED());
}

/*
 * Free the tunnel stack instance.
 */
/* ARGSUSED */
static void
iptun_stack_fini(netstackid_t stackid, void *arg)
{
	iptun_stack_t *iptuns = arg;

	list_destroy(&iptuns->iptuns_iptunlist);
	mutex_destroy(&iptuns->iptuns_lock);
	kmem_free(iptuns, sizeof (*iptuns));
}

static void
iptun_fini(void)
{
	ddi_taskq_destroy(iptun_taskq);
	mac_fini_ops(&iptun_dev_ops);
	ldi_ident_release(iptun_ldi_ident);
	mod_hash_destroy_idhash(iptun_hash);
	kmem_cache_destroy(iptun_cache);
}

int
_init(void)
{
	int rc;

	rc = ldi_ident_from_mod(&iptun_modlinkage, &iptun_ldi_ident);
	if (rc != 0)
		return (rc);

	iptun_cache = kmem_cache_create("iptun_cache", sizeof (iptun_t), 0,
	    iptun_constructor, iptun_destructor, NULL, NULL, NULL, 0);
	if (iptun_cache == NULL) {
		ldi_ident_release(iptun_ldi_ident);
		return (ENOMEM);
	}

	iptun_taskq = ddi_taskq_create(NULL, "iptun_taskq", 1,
	    TASKQ_DEFAULTPRI, 0);
	if (iptun_taskq == NULL) {
		ldi_ident_release(iptun_ldi_ident);
		kmem_cache_destroy(iptun_cache);
		return (ENOMEM);
	}

	iptun_hash = mod_hash_create_idhash("iptun_hash", IPTUN_HASHSZ,
	    mod_hash_null_valdtor);

	mac_init_ops(&iptun_dev_ops, IPTUN_DRIVER_NAME);

	if ((rc = mod_install(&iptun_modlinkage)) != 0)
		iptun_fini();
	return (rc);
}

int
_fini(void)
{
	int rc;

	if ((rc = mod_remove(&iptun_modlinkage)) == 0)
		iptun_fini();
	return (rc);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&iptun_modlinkage, modinfop));
}

static int
iptun_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		if (ddi_get_instance(dip) != 0 || iptun_ioc_init() != 0)
			return (DDI_FAILURE);
		iptun_dip = dip;
		netstack_register(NS_IPTUN, iptun_stack_init,
		    iptun_stack_shutdown, iptun_stack_fini);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/* ARGSUSED */
static int
iptun_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		/*
		 * We prevent the pseudo device from detaching (and thus the
		 * driver from unloading) when there are tunnels configured by
		 * consulting iptun_count().  We don't need to hold a lock
		 * here because the tunnel count is only changed when a tunnel
		 * is created or deleted, which can't happen while the detach
		 * routine is running (the ioctl path calls
		 * ddi_hold_devi_by_instance() in dld's drv_ioctl(), and the
		 * /dev/net implicit path has the device open).
		 */
		if (iptun_count() > 0)
			return (DDI_FAILURE);
		netstack_unregister(NS_IPTUN);
		iptun_dip = NULL;
		iptun_ioc_fini();
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/* ARGSUSED */
static int
iptun_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = iptun_dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = NULL;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

/* ARGSUSED */
static int
iptun_constructor(void *buf, void *cdrarg, int kmflags)
{
	iptun_t	*iptun = buf;

	bzero(iptun, sizeof (*iptun));
	mutex_init(&iptun->iptun_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&iptun->iptun_upcall_cv, NULL, CV_DRIVER, NULL);
	cv_init(&iptun->iptun_enter_cv, NULL, CV_DRIVER, NULL);

	return (0);
}

/* ARGSUSED */
static void
iptun_destructor(void *buf, void *cdrarg)
{
	iptun_t *iptun = buf;

	/* This iptun_t must not still be in use. */
	ASSERT(!(iptun->iptun_flags & (IPTUN_BOUND|IPTUN_MAC_REGISTERED|
	    IPTUN_MAC_STARTED|IPTUN_HASH_INSERTED|IPTUN_UPCALL_PENDING)));

	mutex_destroy(&iptun->iptun_lock);
	cv_destroy(&iptun->iptun_upcall_cv);
}
