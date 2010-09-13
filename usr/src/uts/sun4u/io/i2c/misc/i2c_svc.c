/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/open.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/modctl.h>
#include <sys/i2c/misc/i2c_svc.h>
#include <sys/i2c/misc/i2c_svc_impl.h>

kmutex_t i2c_svc_mutex;

static struct modldrv i2c_modldrv = {
	&mod_miscops,		/* type of module - misc */
	"I2C module",
	NULL,
};

static struct modlinkage i2c_modlinkage = {
	MODREV_1,
	&i2c_modldrv,
	0
};

i2c_nexus_reg_list_t *nexus_reg_list_head = NULL;

int i2csvcdebug = 0;

int
_init(void)
{
	int error;

	if ((error = mod_install(&i2c_modlinkage)) == 0) {
		mutex_init(&i2c_svc_mutex, NULL, MUTEX_DRIVER, NULL);
	}

	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&i2c_modlinkage)) == 0) {
		mutex_destroy(&i2c_svc_mutex);
	}

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&i2c_modlinkage, modinfop));
}

/*
 * i2c_client_register is called by I2C client drivers,
 * typically in attach, but before starting any bus transfers.
 *
 * dip	   - the client device's dip.
 * i2c_hdl - pointer to a handle returned on success.
 *
 */
int
i2c_client_register(dev_info_t *dip, i2c_client_hdl_t *i2c_hdl)
{
	dev_info_t *pdip;
	i2c_client_hdl_t hdl;
	i2c_nexus_reg_list_t *reg_list;

	pdip = ddi_get_parent(dip);

	mutex_enter(&i2c_svc_mutex);

	reg_list = nexus_reg_list_head;
	/*
	 * search parent reg list to find dip's parent.
	 */
	for (; reg_list != NULL; reg_list = reg_list->next) {
		if (reg_list->dip == pdip) {
			break;
		}
	}

	mutex_exit(&i2c_svc_mutex);

	if (reg_list == NULL) {

		return (I2C_FAILURE);
	}

	hdl = kmem_alloc(sizeof (struct i2c_client_hdl_impl), KM_SLEEP);

	CHDL(hdl)->chdl_dip = dip;
	CHDL(hdl)->chdl_nexus_reg = &reg_list->nexus_reg;
	*i2c_hdl = hdl;

	return (I2C_SUCCESS);
}

/*
 * i2c_client_unregister() is called by the I2C client driver
 * when it no longer wishes to transmit on the I2C bus, typically
 * during its detach routine.
 *
 * hdl - handle previously returned by i2c_client_register().
 *
 */
void
i2c_client_unregister(i2c_client_hdl_t hdl)
{
	kmem_free(hdl, sizeof (struct i2c_client_hdl_impl));
}

/*
 * i2c_transfer() is called by client drivers to handle
 * I2C data transfers.  It performs some basic sanity checking of
 * flags vs. i2c_len and i2c_wlen values, and then calls the
 * parent's i2c_transfer() function to handle the actual transfer.
 */
int
i2c_transfer(i2c_client_hdl_t hdl, i2c_transfer_t *i2c_tran)
{
	switch (i2c_tran->i2c_flags) {
	case I2C_WR:
		if (i2c_tran->i2c_wlen == 0) {

			return (EINVAL);
		}
		break;
	case I2C_RD:
		if (i2c_tran->i2c_rlen == 0) {

			return (EINVAL);
		}
		break;
	case I2C_WR_RD:
		if (i2c_tran->i2c_wlen == 0 || i2c_tran->i2c_rlen == 0) {

			return (EINVAL);
		}
		break;
	default:

		return (EINVAL);
	}

	if (CHDL(hdl)->chdl_nexus_reg->i2c_nexus_transfer != NULL) {
		(*CHDL(hdl)->chdl_nexus_reg->i2c_nexus_transfer)
				(CHDL(hdl)->chdl_dip, i2c_tran);

		return (i2c_tran->i2c_result);
	} else {

		return (ENOTSUP);
	}
}

/*
 * i2c_transfer_alloc() allocates a i2c_transfer structure along
 * with read and write buffers of size rlen and wlen respectively.
 *
 * i2c_hdl - handle returned previously by i2c_client_register()
 * i2c - address of pointer to allocated buffer returned on success.
 * wlen - write size buffer to allocate.  May be 0.
 * rlen - read size buffer to allocate.  May be 0.
 * flags - I2C_SLEEP or I2C_NOSLEEP
 */
/*ARGSUSED*/
int
i2c_transfer_alloc(i2c_client_hdl_t hdl,
			i2c_transfer_t **i2c,
			ushort_t wlen,
			ushort_t rlen,
			uint_t flags)
{
	i2c_transfer_alloc_t *i2cw;
	int sleep;
	int size;

	/*
	 * set i2c to NULL in case the caller just checks i2c
	 * to determine failures.
	 */
	*i2c = NULL;

	if (flags & I2C_SLEEP) {
		sleep = KM_SLEEP;
	} else if (flags & I2C_NOSLEEP) {
		sleep = KM_NOSLEEP;
	} else {
		sleep = KM_NOSLEEP;
	}

	size = sizeof (i2c_transfer_alloc_t) + rlen + wlen;

	if ((i2cw = kmem_zalloc(size, sleep)) == NULL) {

		return (I2C_FAILURE);
	}

	i2cw->i2cw_size = size;
	i2cw->i2cw_i2ct.i2c_wlen = wlen;
	i2cw->i2cw_i2ct.i2c_rlen = rlen;
	if (wlen != 0) {
		i2cw->i2cw_i2ct.i2c_wbuf = (uchar_t *)i2cw +
			sizeof (i2c_transfer_alloc_t);
	}
	if (rlen != 0) {
		i2cw->i2cw_i2ct.i2c_rbuf = (uchar_t *)i2cw +
			sizeof (i2c_transfer_alloc_t) + wlen;
	}
	*i2c = (i2c_transfer_t *)i2cw;

	return (I2C_SUCCESS);
}

/*
 * i2c_transfer_free() is called to free a buffer previously
 * allocated by i2c_transfer_allocate().
 *
 * i2c_hdl - handle returned previously by i2c_client_register()
 * i2c - buffer previously allocated by i2c_transfer_allocate()
 */
/*ARGSUSED*/
void
i2c_transfer_free(i2c_client_hdl_t hdl, i2c_transfer_t *i2c_tran)
{
	i2c_transfer_alloc_t *i2cw = (i2c_transfer_alloc_t *)i2c_tran;

	kmem_free(i2cw, i2cw->i2cw_size);
}

/*
 * i2c_nexus_register() is called by the nexus driver to inform
 * I2C services that it is ready to accept transactions, and
 * give the I2C services a vector of functions.
 *
 * dip - dip of the bus controller
 * nexus_reg - pointer to reg structure of vector functions
 */
void
i2c_nexus_register(dev_info_t *dip, i2c_nexus_reg_t *nexus_reg)
{
	i2c_nexus_reg_list_t *nexus_reglist;

	nexus_reglist = kmem_alloc(sizeof (struct i2c_nexus_reg_list),
		KM_SLEEP);

	mutex_enter(&i2c_svc_mutex);
	nexus_reglist->next = nexus_reg_list_head;
	nexus_reg_list_head = nexus_reglist;
	mutex_exit(&i2c_svc_mutex);

	nexus_reglist->nexus_reg = *nexus_reg;
	nexus_reglist->dip = dip;
}

/*
 * i2c_nexus_unregister() is called by the nexus driver when
 * it is no longer able to accept transactions for its I2C
 * children.
 *
 * dip - dev_info pointer passed to i2c_nexus_register().
 */
void
i2c_nexus_unregister(dev_info_t *dip)
{
	i2c_nexus_reg_list_t **reg_list;
	i2c_nexus_reg_list_t *save = NULL;

	mutex_enter(&i2c_svc_mutex);

	reg_list = &nexus_reg_list_head;

	/*
	 * reg_list is the address of the pointer to an element on
	 * the reg list.  It starts out being the address of the
	 * list head, but then is changed to the address of the
	 * next pointer in a list element.  Once the element to
	 * delete is found, then we change the pointer to the
	 * address found in the next pointer of the element to
	 * be deleted.
	 */
	for (; *reg_list != NULL; reg_list = &(*reg_list)->next) {
		if ((*reg_list)->dip == dip) {
			save = *reg_list;
			/* prev next pointer adjusted to point */
			*reg_list = (*reg_list)->next;
			break;
		}
	}
	mutex_exit(&i2c_svc_mutex);
	if (save != NULL) {
		kmem_free(save, sizeof (i2c_nexus_reg_list_t));
	} else {
		cmn_err(CE_WARN, "could not find nexus reg to free");
	}
}
