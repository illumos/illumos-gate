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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/strsubr.h>
#include <sys/socketvar.h>
#include <sys/rds.h>

#include <sys/ib/ibtl/ibti.h>
#include <sys/ib/clients/rdsv3/rdsv3.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

extern int rdsv3_init(void);
extern void rdsv3_exit(void);
extern void rdsv3_cong_init(void);
extern void rdsv3_cong_exit(void);
extern void rdsv3_trans_init(void);
extern void rdsv3_trans_exit(void);
extern int rdsv3_sock_init(void);
extern void rdsv3_sock_exit(void);

/* global */
dev_info_t	*rdsv3_dev_info = NULL;
kmem_cache_t	*rdsv3_alloc_cache = NULL;

extern kmutex_t rdsv3_rdma_listen_id_lock;
extern struct rdma_cm_id *rdsv3_rdma_listen_id;

extern kmutex_t rdsv3_sock_lock;
extern list_t rdsv3_sock_list;

extern void rdsv3_bind_tree_init();
extern void rdsv3_bind_tree_exit();

int
rdsv3_sock_init()
{
	RDSV3_DPRINTF4("rdsv3_sock_init", "Enter");

	rdsv3_alloc_cache = kmem_cache_create("rdsv3_alloc_cache",
	    sizeof (struct rsock) + sizeof (struct rdsv3_sock), 0, NULL,
	    NULL, NULL, NULL, NULL, 0);
	if (rdsv3_alloc_cache == NULL) {
		RDSV3_DPRINTF2("rdsv3_alloc_cache",
		    "kmem_cache_create(rdsv3_alloc_cache) failed");
		return (-1);
	}
	rdsv3_bind_tree_init();

	mutex_init(&rdsv3_sock_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&rdsv3_sock_list, sizeof (struct rdsv3_sock),
	    offsetof(struct rdsv3_sock, rs_item));

	RDSV3_DPRINTF4("rdsv3_sock_init", "Return");

	return (0);
}

void
rdsv3_sock_exit()
{
	RDSV3_DPRINTF2("rdsv3_sock_exit", "Enter");

	rdsv3_bind_tree_exit();

	kmem_cache_destroy(rdsv3_alloc_cache);

	list_destroy(&rdsv3_sock_list);
	mutex_destroy(&rdsv3_sock_lock);

	RDSV3_DPRINTF2("rdsv3_sock_exit", "Return");
}

static int
rdsv3_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int	ret;

	RDSV3_DPRINTF2("rdsv3_attach", "Enter (dip: %p)", dip);

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (rdsv3_dev_info != NULL) {
		RDSV3_DPRINTF2("rdsv3_attach", "Multiple RDS instances are"
		    " not supported (rdsv3_dev_info: 0x%p)", rdsv3_dev_info);
		return (DDI_FAILURE);
	}
	rdsv3_dev_info = dip;

	mutex_init(&rdsv3_rdma_listen_id_lock, NULL, MUTEX_DRIVER, NULL);
	rdsv3_rdma_listen_id = NULL;

	rdsv3_trans_init();
	ret = rdsv3_init();
	if (ret) {
		RDSV3_DPRINTF2("rdsv3_attach", "rdsv3_init failed: %d", ret);
		rdsv3_trans_exit();
		mutex_destroy(&rdsv3_rdma_listen_id_lock);
		rdsv3_dev_info = NULL;
		return (DDI_FAILURE);
	}

	ret = rdsv3_sock_init();
	if (ret) {
		rdsv3_exit();
		rdsv3_trans_exit();
		mutex_destroy(&rdsv3_rdma_listen_id_lock);
		rdsv3_dev_info = NULL;
		return (DDI_FAILURE);
	}

	ret = ddi_create_minor_node(dip, "rdsv3", S_IFCHR, 0, DDI_PSEUDO, 0);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_CONT, "ddi_create_minor_node failed: %d", ret);
		rdsv3_sock_exit();
		rdsv3_exit();
		rdsv3_trans_exit();
		mutex_destroy(&rdsv3_rdma_listen_id_lock);
		rdsv3_dev_info = NULL;
		return (DDI_FAILURE);
	}

	RDSV3_DPRINTF2("rdsv3_attach", "Return");

	return (DDI_SUCCESS);
}

static int
rdsv3_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	RDSV3_DPRINTF2("rdsv3_detach", "Enter (dip: %p)", dip);

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	rdsv3_sock_exit();
	rdsv3_exit();
	rdsv3_trans_exit();
	ddi_remove_minor_node(dip, "rdsv3");
	rdsv3_dev_info = NULL;

	RDSV3_DPRINTF2("rdsv3_detach", "Return");

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
rdsv3_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int ret = DDI_FAILURE;

	RDSV3_DPRINTF2("rdsv3_info", "Enter (dip: %p, cmd: %d)", dip, cmd);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (rdsv3_dev_info != NULL) {
			*result = (void *)rdsv3_dev_info;
			ret = DDI_SUCCESS;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = NULL;
		ret = DDI_SUCCESS;
		break;

	default:
		break;
	}

	RDSV3_DPRINTF4("rdsv3_info", "Return");

	return (ret);
}

/* Driver entry points */
static struct cb_ops	rdsv3_cb_ops = {
	nulldev,		/* open */
	nulldev,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* stream */
	D_MP,			/* cb_flag */
	CB_REV,			/* rev */
	nodev,			/* int (*cb_aread)() */
	nodev,			/* int (*cb_awrite)() */
};

/* Device options */
static struct dev_ops rdsv3_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	rdsv3_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	rdsv3_attach,		/* attach */
	rdsv3_detach,		/* detach */
	nodev,			/* reset */
	&rdsv3_cb_ops,		/* driver ops - devctl interfaces */
	NULL,			/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed	/* quiesce */
};

/*
 * Module linkage information.
 */
#define	RDSV3_DEVDESC	"RDSv3 IB transport driver"
static struct modldrv rdsv3_modldrv = {
	&mod_driverops,		/* Driver module */
	RDSV3_DEVDESC,		/* Driver name and version */
	&rdsv3_ops,		/* Driver ops */
};

static struct modlinkage rdsv3_modlinkage = {
	MODREV_1,
	(void *)&rdsv3_modldrv,
	NULL
};

int
_init(void)
{
	int	ret;

	if (ibt_hw_is_present() == 0) {
		return (ENODEV);
	}

	/* Initialize logging */
	rdsv3_logging_initialization();

	ret = mod_install(&rdsv3_modlinkage);
	if (ret != 0) {
		/*
		 * Could not load module
		 */
		rdsv3_logging_destroy();
		return (ret);
	}

	return (0);
}

int
_fini()
{
	int	ret;

	/*
	 * Remove module
	 */
	if ((ret = mod_remove(&rdsv3_modlinkage)) != 0) {
		return (ret);
	}

	/* Stop logging */
	rdsv3_logging_destroy();

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&rdsv3_modlinkage, modinfop));
}
