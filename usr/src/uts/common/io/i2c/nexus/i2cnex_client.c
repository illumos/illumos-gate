/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2025 Oxide Computer Company
 */

/*
 * I2C logic for client device drivers.
 *
 * This file contains all of the logic around I2C client functions that device
 * drivers use to access an I2C bus. Today, access to an address is based on
 * either the reg[] handle or allowing a device to access an address at the same
 * spot in the tree as their device to handle muxing. Let's talk about the
 * various abstractions that exist.
 *
 * ------------
 * i2c_client_t
 * ------------
 *
 * This i2c_client_t represents the information to talk to a given device at a
 * specified address. It is assumed that an instance of a driver will create one
 * of these per thing it needs to talk to and it will use it across multiple
 * threads. In general, we want to keep the simple case simple for I2C drivers
 * where by they don't have to think too much about locking of the client or
 * related unless they need to perform different transactions coherently or they
 * have something special going on where there are global side effects like the
 * ee1004 driver where everyone is listening for the same address to determine
 * which page is active.
 *
 * Because the i2c_client_t can be used by multiple threads in the driver in
 * parallel, we generally treat access to the data that we cache in the
 * i2c_client_t as being protected by and requiring the caller to hold the
 * active i2c transaction represented by the i2c_txn_t. We do not require
 * callers to have one before coming into here. We will get one on their
 * behalf.
 *
 * An important aspect here is that everything is subordinate to holding the
 * active transaction. This ensures that we honor lock ordering and avoid
 * deadlock situations. Only once that is owned can one use the request
 * structures embedded in the i2c_client_t. They are here to minimize run-time
 * allocations.
 *
 * ----------------
 * i2c_reg_handle_t
 * ----------------
 *
 * The i2c_reg_handle_t is used as a convenient way to access data on an i2c
 * device as many devices are ultimately phrased in terms of registers. The goal
 * was to provide something that is similar to ddi_regs_map_setup(), but is
 * phrased in terms of fallible I/O. Trying to squeeze this in and have drivers
 * check results did not seem very practical where as for many other buses those
 * transactions take the form of posted I/O and so are more reasonably phrased
 * that way.
 *
 * The register handle is tied to the client and mostly contains metadata along
 * with buffers that are used to make requests. In a similar fashion to the
 * i2c_client_t, one is required to have an active transaction before accessing
 * those. This means that the i2c_reg_handle_t is mostly the same as the
 * i2c_client_t with respect to locking and access.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/bitext.h>
#include <sys/thread.h>
#include <sys/stddef.h>

#include "i2cnex.h"

/*
 * This includes all possible i2c_errno_t translations. We'd rather just
 * translate everything and give folks something potentially useful than get it
 * wrong.
 */
const char *
i2c_client_errtostr(i2c_client_t *client, i2c_errno_t errno)
{
	switch (errno) {
	case I2C_CORE_E_OK:
		return ("I2C_CORE_E_OK");
	case I2C_CORE_E_CONTROLLER:
		return ("I2C_CORE_E_CONTROLLER");
	case I2C_CORE_E_BAD_ADDR_TYPE:
		return ("I2C_CORE_E_BAD_ADDR_TYPE");
	case I2C_CORE_E_BAD_ADDR:
		return ("I2C_CORE_E_BAD_ADDR");
	case I2C_CORE_E_UNSUP_ADDR_TYPE:
		return ("I2C_CORE_E_UNSUP_ADDR_TYPE");
	case I2C_CORE_E_ADDR_RSVD:
		return ("I2C_CORE_E_ADDR_RSVD");
	case I2C_CORE_E_ADDR_IN_USE:
		return ("I2C_CORE_E_ADDR_IN_USE");
	case I2C_CORE_E_ADDR_REFCNT:
		return ("I2C_CORE_E_ADDR_REFCNT");
	case I2C_CORE_E_UNKNOWN_ADDR:
		return ("I2C_CORE_E_UNKNOWN_ADDR");
	case I2C_CORE_E_CANT_XLATE_REQ:
		return ("I2C_CORE_E_CANT_XLATE_REQ");
	case I2C_CORE_E_NEED_READ_OR_WRITE:
		return ("I2C_CORE_E_NEED_READ_OR_WRITE");
	case I2C_CORE_E_BAD_I2C_REQ_FLAGS:
		return ("I2C_CORE_E_BAD_I2C_REQ_FLAGS");
	case I2C_CORE_E_BAD_I2C_REQ_READ_LEN:
		return ("I2C_CORE_E_BAD_I2C_REQ_READ_LEN");
	case I2C_CORE_E_BAD_I2C_REQ_WRITE_LEN:
		return ("I2C_CORE_E_BAD_I2C_REQ_WRITE_LEN");
	case I2C_CORE_E_BAD_SMBUS_REQ_FLAGS:
		return ("I2C_CORE_E_BAD_SMBUS_REQ_FLAGS");
	case I2C_CORE_E_BAD_SMBUS_READ_LEN:
		return ("I2C_CORE_E_BAD_SMBUS_READ_LEN");
	case I2C_CORE_E_BAD_SMBUS_WRITE_LEN:
		return ("I2C_CORE_E_BAD_SMBUS_WRITE_LEN");
	case I2C_CORE_E_BAD_SMBUS_OP:
		return ("I2C_CORE_E_BAD_SMBUS_OP");
	case I2C_CORE_E_UNSUP_SMBUS_OP:
		return ("I2C_CORE_E_UNSUP_SMBUS_OP");
	case I2C_CORE_E_LOCK_WOULD_BLOCK:
		return ("I2C_CORE_E_LOCK_WOULD_BLOCK");
	case I2C_CORE_E_LOCK_WAIT_SIGNAL:
		return ("I2C_CORE_E_LOCK_WAIT_SIGNAL");
	case I2C_IOCTL_E_NVL_TOO_BIG:
		return ("I2C_IOCTL_E_NVL_TOO_BIG");
	case I2C_IOCTL_E_NVL_INVALID:
		return ("I2C_IOCTL_E_NVL_INVALID");
	case I2C_IOCTL_E_NVL_KEY_MISSING:
		return ("I2C_IOCTL_E_NVL_KEY_MISSING");
	case I2C_IOCTL_E_NVL_KEY_UNKNOWN:
		return ("I2C_IOCTL_E_NVL_KEY_UNKNOWN");
	case I2C_IOCTL_E_NVL_KEY_BAD_TYPE:
		return ("I2C_IOCTL_E_NVL_KEY_BAD_TYPE");
	case I2C_IOCTL_E_BAD_USER_DATA:
		return ("I2C_IOCTL_E_BAD_USER_DATA");
	case I2C_IOCTL_E_NO_KERN_MEM:
		return ("I2C_IOCTL_E_NO_KERN_MEM");
	case I2C_IOCTL_E_BAD_DEV_NAME:
		return ("I2C_IOCTL_E_BAD_DEV_NAME");
	case I2C_IOCTL_E_COMPAT_LEN_RANGE:
		return ("I2C_IOCTL_E_COMPAT_LEN_RANGE");
	case I2C_IOCTL_E_NEXUS:
		return ("I2C_IOCTL_E_NEXUS");
	case I2C_IOCTL_E_NO_BUS_LOCK_NEXUS:
		return ("I2C_IOCTL_E_NO_BUS_LOCK_NEXUS");
	case I2C_IOCTL_E_IN_PROGRESS:
		return ("I2C_IOCTL_E_IN_PROGRESS");
	case I2C_CLIENT_E_BAD_DIP:
		return ("I2C_CLIENT_E_BAD_DIP");
	case I2C_CLIENT_E_BAD_REG_IDX:
		return ("I2C_CLIENT_E_BAD_REG_IDX");
	case I2C_CLIENT_E_BAD_CLAIM_FLAGS:
		return ("I2C_CLIENT_E_BAD_CLAIM_FLAGS");
	case I2C_CLIENT_E_BAD_IO_FLAGS:
		return ("I2C_CLIENT_E_BAD_IO_FLAGS");
	case I2C_CLIENT_E_BAD_LOCK_FLAGS:
		return ("I2C_CLIENT_E_BAD_LOCK_FLAGS");
	case I2C_CLIENT_E_SIGNAL:
		return ("I2C_CLIENT_E_SIGNAL");
	case I2C_CLIENT_E_BAD_REG_ATTR_VERS:
		return ("I2C_CLIENT_E_BAD_REG_ATTR_VERS");
	case I2C_CLIENT_E_BAD_REG_ATTR_FLAGS:
		return ("I2C_CLIENT_E_BAD_REG_ATTR_FLAGS");
	case I2C_CLIENT_E_BAD_REG_ATTR_RLEN:
		return ("I2C_CLIENT_E_BAD_REG_ATTR_RLEN");
	case I2C_CLIENT_E_BAD_REG_ATTR_ALEN:
		return ("I2C_CLIENT_E_BAD_REG_ATTR_ALEN");
	case I2C_CLIENT_E_BAD_REG_ATTR_ENDIAN:
		return ("I2C_CLIENT_E_BAD_REG_ATTR_ENDIAN");
	case I2C_CLIENT_E_BAD_REG_ATTR_MAX:
		return ("I2C_CLIENT_E_BAD_REG_ATTR_MAX");
	case I2C_CLIENT_E_REG_ALEN_UNSUP_BY_CTRL:
		return ("I2C_CLIENT_E_REG_ALEN_UNSUP_BY_CTRL");
	case I2C_CLIENT_E_BAD_REG_ADDR:
		return ("I2C_CLIENT_E_BAD_REG_ADDR");
	case I2C_CLIENT_E_BAD_REG_COUNT:
		return ("I2C_CLIENT_E_BAD_REG_COUNT");
	case I2C_CLIENT_E_REG_ADDR_OVERFLOW:
		return ("I2C_CLIENT_E_REG_ADDR_OVERFLOW");
	case I2C_CLIENT_E_REG_IO_TOO_LARGE:
		return ("I2C_CLIENT_E_REG_IO_TOO_LARGE");
	case I2C_CLIENT_E_PARTIAL_REG:
		return ("I2C_CLIENT_E_PARTIAL_REG");
	case I2C_CLIENT_E_CLAIM_OWNED_ADDR:
		return ("I2C_CLIENT_E_CLAIM_OWNED_ADDR");
	case I2C_PROP_E_UNSUP:
		return ("I2C_PROP_E_UNSUP");
	case I2C_PROP_E_UNKNOWN:
		return ("I2C_PROP_E_UNKNOWN");
	case I2C_PROP_E_READ_ONLY:
		return ("I2C_PROP_E_READ_ONLY");
	case I2C_PROP_E_SMALL_BUF:
		return ("I2C_PROP_E_SMALL_BUF");
	case I2C_PROP_E_TOO_BIG_BUF:
		return ("I2C_PROP_E_TOO_BIG_BUF");
	case I2C_PROP_E_BAD_VAL:
		return ("I2C_PROP_E_BAD_VAL");
	case I2C_PROP_E_SET_UNSUP:
		return ("I2C_PROP_E_SET_UNSUP");
	case I2C_MUX_E_BAD_FLAG:
		return ("I2C_MUX_E_BAD_FLAG");
	default:
		return ("unknown error");
	}
}

const char *
i2c_client_ctrl_errtostr(i2c_client_t *client, i2c_ctrl_error_t errno)
{
	switch (errno) {
	case I2C_CTRL_E_OK:
		return ("I2C_CTRL_E_OK");
	case I2C_CTRL_E_INTERNAL:
		return ("I2C_CTRL_E_INTERNAL");
	case I2C_CTRL_E_DRIVER:
		return ("I2C_CTRL_E_DRIVER");
	case I2C_CTRL_E_UNSUP_CMD:
		return ("I2C_CTRL_E_UNSUP_CMD");
	case I2C_CTRL_E_BUS_BUSY:
		return ("I2C_CTRL_E_BUS_BUSY");
	case I2C_CTRL_E_ADDR_NACK:
		return ("I2C_CTRL_E_ADDR_NACK");
	case I2C_CTRL_E_DATA_NACK:
		return ("I2C_CTRL_E_DATA_NACK");
	case I2C_CTRL_E_NACK:
		return ("I2C_CTRL_E_NACK");
	case I2C_CTRL_E_ARB_LOST:
		return ("I2C_CTRL_E_ARB_LOST");
	case I2C_CTRL_E_BAD_ACK:
		return ("I2C_CTRL_E_BAD_ACK");
	case I2C_CTRL_E_REQ_TO:
		return ("I2C_CTRL_E_REQ_TO");
	case I2C_CTRL_E_BAD_SMBUS_RLEN:
		return ("I2C_CTRL_E_BAD_SMBUS_RLEN");
	case I2C_CTRL_E_SMBUS_CLOCK_LOW:
		return ("I2C_CTRL_E_SMBUS_CLOCK_LOW");
	default:
		return ("unknown error");
	}
}

static i2c_errno_t
i2c_client_bus_lock(i2c_ctrl_t *ctrl, i2c_txn_tag_t tag, const void *arg,
    bool block, i2c_txn_t **txnp)
{
	i2c_txn_t *txn;
	i2c_errno_t err;

	txn = i2c_txn_alloc(ctrl, tag, arg);
	err = i2c_txn_ctrl_lock(txn, block);
	if (err != I2C_CORE_E_OK) {
		i2c_txn_free(txn);
		return (err);
	}

	*txnp = txn;
	return (I2C_CORE_E_OK);

}

void
i2c_client_destroy(i2c_client_t *client)
{
	i2c_txn_t *txn;

	if (client == NULL)
		return;

	VERIFY3P(client->icli_txn, ==, NULL);
	VERIFY3U(client->icli_curthread, ==, 0);

	VERIFY3U(i2c_bus_lock(client, 0, &txn), ==, I2C_CORE_E_OK);
	list_remove(&client->icli_dev->id_clients, client);

	if ((client->icli_flags & I2C_CLIENT_F_CLAIM_ADDR) != 0) {
		i2c_nexus_t *nex = client->icli_dev->id_nex;
		i2c_port_t *port = nex->in_pnex->in_data.in_port;
		if ((client->icli_flags & I2C_CLIENT_F_SHARED_ADDR) != 0) {
			i2c_addr_free_shared(port, &client->icli_addr,
			    ddi_driver_major(client->icli_dip));
			client->icli_flags &= ~I2C_CLIENT_F_SHARED_ADDR;
		} else {
			i2c_addr_free(port, &client->icli_addr);
		}
		client->icli_flags &= ~I2C_CLIENT_F_CLAIM_ADDR;
	}
	i2c_bus_unlock(txn);

	VERIFY3U(list_is_empty(&client->icli_regs), !=, 0);

	list_destroy(&client->icli_regs);
	mutex_destroy(&client->icli_mutex);
	kmem_free(client, sizeof (i2c_client_t));
}

static i2c_client_t *
i2c_client_alloc(i2c_txn_t *txn, i2c_dev_t *dev, dev_info_t *dip,
    const i2c_addr_t *addr)
{
	i2c_client_t *client;

	VERIFY(i2c_txn_held(txn));

	client = kmem_zalloc(sizeof (i2c_client_t), KM_SLEEP);
	client->icli_dip = dip;
	client->icli_addr = *addr;
	client->icli_dev = dev;
	client->icli_ctrl = dev->id_nex->in_ctrl;
	VERIFY3P(dev->id_nex->in_pnex->in_type, ==, I2C_NEXUS_T_PORT);
	client->icli_io_port = dev->id_nex->in_pnex->in_data.in_port;
	mutex_init(&client->icli_mutex, NULL, MUTEX_DRIVER, NULL);
	list_create(&client->icli_regs, sizeof (i2c_reg_hdl_t),
	    offsetof(i2c_reg_hdl_t, reg_link));
	list_insert_tail(&dev->id_clients, client);

	return (client);
}

i2c_errno_t
i2c_client_init(dev_info_t *dip, uint32_t regno, i2c_client_t **clientp)
{
	int *reg;
	uint_t nreg;
	i2c_addr_t addr;
	i2c_error_t err;
	i2c_txn_t *txn;

	if (!i2c_dip_is_dev(dip)) {
		return (I2C_CLIENT_E_BAD_DIP);
	}

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", &reg, &nreg) != DDI_PROP_SUCCESS) {
		return (I2C_CLIENT_E_BAD_DIP);
	}

	if (regno >= nreg / 2) {
		ddi_prop_free(reg);
		return (I2C_CLIENT_E_BAD_REG_IDX);
	}

	addr.ia_type = reg[regno * 2];
	addr.ia_addr = reg[regno * 2 + 1];
	ddi_prop_free(reg);

	if (!i2c_addr_validate(&addr, &err)) {
		return (err.i2c_error);
	}

	i2c_nexus_t *nex = i2c_dev_to_nexus(dip);
	i2c_ctrl_t *ctrl = nex->in_ctrl;

	err.i2c_error = i2c_client_bus_lock(ctrl, I2C_LOCK_TAG_CLIENT_ALLOC,
	    nex, true, &txn);
	if (err.i2c_error != I2C_CORE_E_OK) {
		return (err.i2c_error);
	}
	*clientp = i2c_client_alloc(txn, nex->in_data.in_dev, dip, &addr);
	i2c_bus_unlock(txn);

	return (I2C_CORE_E_OK);
}

i2c_errno_t
i2c_client_claim_addr(dev_info_t *dip, const i2c_addr_t *addr,
    i2c_claim_flags_t flags, i2c_client_t **clientp)
{
	int *reg;
	uint_t nreg;
	i2c_error_t err;
	i2c_txn_t *txn;

	if ((flags & ~I2C_CLAIM_F_SHARED) != 0) {
		return (I2C_CLIENT_E_BAD_CLAIM_FLAGS);
	}

	if (!i2c_addr_validate(addr, &err)) {
		return (err.i2c_error);
	}

	if (!i2c_dip_is_dev(dip)) {
		return (I2C_CLIENT_E_BAD_DIP);
	}

	major_t major = ddi_driver_major(dip);
	if (major == DDI_MAJOR_T_NONE || major == DDI_MAJOR_T_UNKNOWN) {
		return (I2C_CLIENT_E_BAD_DIP);
	}

	/*
	 * Before we do anything else, see if this address is in reg[]. If it
	 * is, then as long as we weren't requesting a shared address, we can
	 * just do a normal i2c_client_init(). By definition the driver already
	 * owns it. Howerver, if the request was for a shared address the device
	 * owns, that's an error.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", &reg, &nreg) != DDI_PROP_SUCCESS) {
		return (I2C_CLIENT_E_BAD_DIP);
	}
	for (uint_t i = 0; i < nreg / 2; i++) {
		if (reg[i * 2] == addr->ia_type && reg[i * 2 + 1] ==
		    addr->ia_addr) {
			if ((flags & I2C_CLAIM_F_SHARED) != 0) {
				return (I2C_CLIENT_E_CLAIM_OWNED_ADDR);
			}

			return (i2c_client_init(dip, i, clientp));
		}
	}
	ddi_prop_free(reg);


	/*
	 * To allocate an address, we need to own the controller. Obtain the
	 * controller lock and use this. The fact that we've claimed this shared
	 * address is recorded on the client and stored on the device so it can
	 * be released when the client is freed.
	 */
	i2c_nexus_t *nex = i2c_dev_to_nexus(dip);
	i2c_ctrl_t *ctrl = nex->in_ctrl;
	VERIFY3U(nex->in_pnex->in_type, ==, I2C_NEXUS_T_PORT);
	i2c_port_t *port = nex->in_pnex->in_data.in_port;

	err.i2c_error = i2c_client_bus_lock(ctrl, I2C_LOCK_TAG_CLIENT_ALLOC,
	    nex, true, &txn);
	if (err.i2c_error != I2C_CORE_E_OK) {
		return (err.i2c_error);
	}

	bool ret;
	if ((flags & I2C_CLAIM_F_SHARED) != 0) {
		ret = i2c_addr_alloc_shared(port, addr, major, &err);
	} else {
		ret = i2c_addr_alloc(port, addr, &err);
	}

	if (!ret) {
		i2c_bus_unlock(txn);
		return (err.i2c_error);
	}

	*clientp = i2c_client_alloc(txn, nex->in_data.in_dev, dip, addr);
	(*clientp)->icli_flags |= I2C_CLIENT_F_CLAIM_ADDR;
	if ((flags & I2C_CLAIM_F_SHARED) != 0) {
		(*clientp)->icli_flags |= I2C_CLIENT_F_SHARED_ADDR;
	}
	i2c_bus_unlock(txn);

	return (I2C_CORE_E_OK);
}

const i2c_addr_t *
i2c_client_addr(i2c_client_t *client)
{
	return (&client->icli_addr);
}

void
i2c_bus_unlock(i2c_txn_t *txn)
{
	i2c_txn_ctrl_unlock(txn);
	i2c_txn_free(txn);
}

i2c_errno_t
i2c_bus_lock(i2c_client_t *client, i2c_bus_lock_flags_t flags, i2c_txn_t **txnp)
{
	bool block;
	i2c_ctrl_t *ctrl = client->icli_ctrl;

	if ((flags & ~I2C_BUS_LOCK_F_NONBLOCK) != 0) {
		return (I2C_CLIENT_E_BAD_LOCK_FLAGS);
	}

	block = (flags & I2C_BUS_LOCK_F_NONBLOCK) == 0;
	return (i2c_client_bus_lock(ctrl, I2C_LOCK_TAG_CLIENT_LOCK, client,
	    block, txnp));
}

/*
 * We serialize an I2C client such only one I/O can be issued by a client at a
 * time. If multiple kernel threads try to do so, they will block. Note, that
 * this is still not great and means that the caller could clobber their error
 * information. This mostly is designed as a belt and suspenders bit and to
 * allow a bit of observability to the fact that this might be happening.
 */
static void
i2c_client_io_release(i2c_client_t *client)
{
	bool free;
	i2c_txn_t *txn;

	mutex_enter(&client->icli_mutex);
	VERIFY3U(client->icli_curthread, ==, curthread);
	client->icli_curthread = 0;
	free = (client->icli_flags & I2C_CLIENT_F_ALLOC_TXN) != 0;
	client->icli_flags &= ~I2C_CLIENT_F_ALLOC_TXN;
	txn = client->icli_txn;
	client->icli_txn = NULL;
	mutex_exit(&client->icli_mutex);

	if (free) {
		i2c_bus_unlock(txn);
	}
}

static bool
i2c_client_io_acquire(i2c_txn_t *txn, i2c_client_t *client, i2c_error_t *errp)
{
	bool alloc = false;

	if (txn == NULL) {
		i2c_errno_t err = i2c_bus_lock(client, 0, &txn);
		if (err != I2C_CORE_E_OK) {
			return (i2c_error(errp, err, 0));
		}
		alloc = true;
	}

	mutex_enter(&client->icli_mutex);
	VERIFY3P(client->icli_txn, ==, NULL);
	client->icli_txn = txn;
	if (alloc) {
		client->icli_flags |= I2C_CLIENT_F_ALLOC_TXN;
	}
	client->icli_curthread = (uintptr_t)curthread;
	mutex_exit(&client->icli_mutex);

	return (true);
}

/*
 * Take care of everything that's required to submit an I/O request. Muxes that
 * need to be activated are taken care of by the controller logic.
 */
static bool
i2c_client_submit(i2c_client_t *client, bool smbus)
{
	i2c_ctrl_t *ctrl = client->icli_ctrl;
	i2c_txn_t *txn = client->icli_txn;
	bool ret;

	VERIFY3P(txn, !=, NULL);
	VERIFY(i2c_txn_held(txn));

	if (smbus) {
		ret = i2c_ctrl_io_smbus(txn, ctrl, client->icli_io_port,
		    &client->icli_reqs.req_smbus);
	} else {
		ret = i2c_ctrl_io_i2c(txn, ctrl, client->icli_io_port,
		    &client->icli_reqs.req_i2c);
	}

	return (ret);
}

bool
smbus_client_send_byte(i2c_txn_t *txn, i2c_client_t *client, uint8_t data,
    i2c_error_t *errp)
{
	smbus_req_t *req = &client->icli_reqs.req_smbus;
	i2c_error_t err;

	if (errp == NULL)
		errp = &err;

	if (!i2c_client_io_acquire(txn, client, errp)) {
		return (false);
	}

	bzero(req, sizeof (smbus_req_t));
	req->smbr_addr = client->icli_addr;
	req->smbr_op = SMBUS_OP_SEND_BYTE;
	req->smbr_wlen = sizeof (data);
	req->smbr_wdata[0] = data;

	bool ret = i2c_client_submit(client, true);
	*errp = req->smbr_error;
	i2c_client_io_release(client);
	return (ret);
}

bool
smbus_client_write_u8(i2c_txn_t *txn, i2c_client_t *client, uint8_t cmd,
    uint8_t data, i2c_error_t *errp)
{
	smbus_req_t *req = &client->icli_reqs.req_smbus;
	i2c_error_t err;

	if (errp == NULL)
		errp = &err;

	if (!i2c_client_io_acquire(txn, client, errp)) {
		return (false);
	}

	bzero(req, sizeof (smbus_req_t));
	req->smbr_addr = client->icli_addr;
	req->smbr_op = SMBUS_OP_WRITE_BYTE;
	req->smbr_wlen = sizeof (data);
	req->smbr_cmd = cmd;
	req->smbr_wdata[0] = data;

	bool ret = i2c_client_submit(client, true);
	*errp = req->smbr_error;
	i2c_client_io_release(client);
	return (ret);
}

bool
smbus_client_write_u16(i2c_txn_t *txn, i2c_client_t *client, uint8_t cmd,
    uint16_t data, i2c_error_t *errp)
{
	smbus_req_t *req = &client->icli_reqs.req_smbus;
	i2c_error_t err;

	if (errp == NULL)
		errp = &err;

	if (!i2c_client_io_acquire(txn, client, errp)) {
		return (false);
	}

	bzero(req, sizeof (smbus_req_t));
	req->smbr_addr = client->icli_addr;
	req->smbr_op = SMBUS_OP_WRITE_BYTE;
	req->smbr_wlen = sizeof (data);
	req->smbr_cmd = cmd;
	req->smbr_wdata[0] = bitx16(data, 7, 0);
	req->smbr_wdata[1] = bitx16(data, 15, 8);

	bool ret = i2c_client_submit(client, true);
	*errp = req->smbr_error;
	i2c_client_io_release(client);
	return (ret);
}

bool
smbus_client_recv_byte(i2c_txn_t *txn, i2c_client_t *client, uint8_t *data,
    i2c_error_t *errp)
{
	smbus_req_t *req = &client->icli_reqs.req_smbus;
	i2c_error_t err;

	if (errp == NULL)
		errp = &err;

	if (!i2c_client_io_acquire(txn, client, errp)) {
		return (false);
	}

	bzero(req, sizeof (smbus_req_t));
	req->smbr_addr = client->icli_addr;
	req->smbr_op = SMBUS_OP_RECV_BYTE;

	bool ret = i2c_client_submit(client, true);
	*errp = req->smbr_error;
	if (ret) {
		*data = req->smbr_rdata[0];
	}
	i2c_client_io_release(client);
	return (ret);
}

bool
smbus_client_read_u8(i2c_txn_t *txn, i2c_client_t *client, uint8_t cmd,
    uint8_t *data, i2c_error_t *errp)
{
	smbus_req_t *req = &client->icli_reqs.req_smbus;
	i2c_error_t err;

	if (errp == NULL)
		errp = &err;

	if (!i2c_client_io_acquire(txn, client, errp)) {
		return (false);
	}

	bzero(req, sizeof (smbus_req_t));
	req->smbr_addr = client->icli_addr;
	req->smbr_op = SMBUS_OP_READ_BYTE;
	req->smbr_cmd = cmd;

	bool ret = i2c_client_submit(client, true);
	*errp = req->smbr_error;
	if (ret) {
		*data = req->smbr_rdata[0];
	}
	i2c_client_io_release(client);
	return (ret);
}

bool
smbus_client_read_u16(i2c_txn_t *txn, i2c_client_t *client, uint8_t cmd,
    uint16_t *data, i2c_error_t *errp)
{
	smbus_req_t *req = &client->icli_reqs.req_smbus;
	i2c_error_t err;

	if (errp == NULL)
		errp = &err;

	if (!i2c_client_io_acquire(txn, client, errp)) {
		return (false);
	}

	bzero(req, sizeof (smbus_req_t));
	req->smbr_addr = client->icli_addr;
	req->smbr_op = SMBUS_OP_READ_BYTE;
	req->smbr_cmd = cmd;

	bool ret = i2c_client_submit(client, true);
	*errp = req->smbr_error;
	if (ret) {
		*data = bitset16(0, req->smbr_rdata[0], 7, 0);
		*data = bitset16(*data, req->smbr_rdata[1], 15, 8);
	}
	i2c_client_io_release(client);
	return (ret);
}

void
i2c_reg_handle_destroy(i2c_reg_hdl_t *reg_hdl)
{
	if (reg_hdl == NULL) {
		return;
	}

	mutex_enter(&reg_hdl->reg_client->icli_mutex);
	list_remove(&reg_hdl->reg_client->icli_regs, reg_hdl);
	mutex_exit(&reg_hdl->reg_client->icli_mutex);
	kmem_free(reg_hdl, sizeof (i2c_reg_hdl_t));
}

i2c_errno_t
i2c_reg_handle_init(i2c_client_t *client, const i2c_reg_acc_attr_t *attrp,
    i2c_reg_hdl_t **outp)
{
	i2c_ctrl_t *ctrl = client->icli_ctrl;
	const bool i2c = ctrl->ic_ops->i2c_io_i2c_f != NULL;

	if (attrp->i2cacc_version != I2C_REG_ACC_ATTR_V0) {
		return (I2C_CLIENT_E_BAD_REG_ATTR_VERS);
	}

	if (attrp->i2cacc_flags != 0) {
		return (I2C_CLIENT_E_BAD_REG_ATTR_FLAGS);
	}

	/*
	 * Currently we only support 1 and 2 byte address and register widths.
	 */
	if (attrp->i2cacc_reg_len != 1 &&
	    attrp->i2cacc_reg_len != 2) {
		return (I2C_CLIENT_E_BAD_REG_ATTR_RLEN);
	}

	switch (attrp->i2cacc_addr_len) {
	case 1:
		if (attrp->i2cacc_addr_max > UINT8_MAX) {
			return (I2C_CLIENT_E_BAD_REG_ATTR_MAX);
		}
		break;
	case 2:
		if (attrp->i2cacc_addr_max > UINT16_MAX) {
			return (I2C_CLIENT_E_BAD_REG_ATTR_MAX);
		}

		if (!i2c) {
			return (I2C_CLIENT_E_REG_ALEN_UNSUP_BY_CTRL);
		}
		break;
	default:
		return (I2C_CLIENT_E_BAD_REG_ATTR_ALEN);
	}

	switch (attrp->i2cacc_addr_endian) {
	case DDI_NEVERSWAP_ACC:
		if (attrp->i2cacc_addr_len > 1) {
			return (I2C_CLIENT_E_BAD_REG_ATTR_ENDIAN);
		}
		break;
	case DDI_STRUCTURE_BE_ACC:
	case DDI_STRUCTURE_LE_ACC:
		break;
	default:
		return (I2C_CLIENT_E_BAD_REG_ATTR_ENDIAN);
	}

	switch (attrp->i2cacc_reg_endian) {
	case DDI_NEVERSWAP_ACC:
		if (attrp->i2cacc_reg_len > 1) {
			return (I2C_CLIENT_E_BAD_REG_ATTR_ENDIAN);
		}
		break;
	case DDI_STRUCTURE_BE_ACC:
	case DDI_STRUCTURE_LE_ACC:
		break;
	default:
		return (I2C_CLIENT_E_BAD_REG_ATTR_ENDIAN);
	}

	i2c_reg_hdl_t *reg_hdl = kmem_zalloc(sizeof (i2c_reg_hdl_t), KM_SLEEP);
	reg_hdl->reg_client = client;
	reg_hdl->reg_attr = *attrp;

	/*
	 * Calculate the number of registers we can take from a read or write
	 * request. If we're issuing a write, we need to take the address length
	 * into account. If we're issuing a read, we don't. If the device
	 * supports I2C, we use the I2C maximums. If the device supports the I2C
	 * block emulation, we can use that as the limit. Otherwise, we are
	 * limited to a single register as that's what an SMBus get operation
	 * can do.
	 *
	 * When we have a two byte address, we need to take that into account
	 * for the length that we're requesting.
	 */
	if (ctrl->ic_limit.lim_i2c_read != 0) {
		reg_hdl->reg_max_nread = ctrl->ic_limit.lim_i2c_read /
		    reg_hdl->reg_attr.i2cacc_reg_len;
	} else {
		reg_hdl->reg_max_nread = 1;
	}

	if (ctrl->ic_limit.lim_i2c_write != 0) {
		uint32_t max = ctrl->ic_limit.lim_i2c_read;
		if (i2c) {
			max -= reg_hdl->reg_attr.i2cacc_addr_len;
		}
		reg_hdl->reg_max_nwrite = max /
		    reg_hdl->reg_attr.i2cacc_reg_len;
	} else {
		reg_hdl->reg_max_nwrite = 1;
	}

	mutex_enter(&client->icli_mutex);
	list_insert_tail(&client->icli_regs, reg_hdl);
	mutex_exit(&client->icli_mutex);

	*outp = reg_hdl;
	return (I2C_CORE_E_OK);
}

/*
 * Check several aspects of the request before we proceed with it:
 *
 *  - That the requested number of bytes is an integral number of registers.
 *  - That the requested address range does not exceed the maximum (inclusive)
 *    address
 *  - That the total number of bytes requested fits within our maximum.
 */
static bool
i2c_reg_check(i2c_reg_hdl_t *hdl, uint64_t addr, uint32_t nbytes, bool get,
    i2c_error_t *errp)
{
	const i2c_reg_acc_attr_t *attr = &hdl->reg_attr;
	size_t reg_max = get ? hdl->reg_max_nread : hdl->reg_max_nwrite;

	if ((nbytes % attr->i2cacc_reg_len) != 0) {
		return (i2c_error(errp, I2C_CLIENT_E_PARTIAL_REG, 0));
	}

	uint32_t nregs = nbytes / attr->i2cacc_reg_len;
	if (nregs > reg_max) {
		return (i2c_error(errp, I2C_CLIENT_E_REG_IO_TOO_LARGE, 0));
	}

	if (addr > attr->i2cacc_addr_max) {
		return (i2c_error(errp, I2C_CLIENT_E_BAD_REG_ADDR, 0));
	}

	if (nregs == 0 || nregs > attr->i2cacc_addr_max) {
		return (i2c_error(errp, I2C_CLIENT_E_BAD_REG_COUNT, 0));
	}

	if (addr > attr->i2cacc_addr_max + 1 - nregs) {
		return (i2c_error(errp, I2C_CLIENT_E_REG_ADDR_OVERFLOW, 0));
	}

	return (true);
}

static void
i2c_reg_setup_addr(const i2c_reg_hdl_t *hdl, uint64_t addr, i2c_req_t *req)
{
	if (hdl->reg_attr.i2cacc_addr_len == 1) {
		req->ir_wdata[0] = addr % UINT8_MAX;
		req->ir_wlen = 1;
		return;
	}

	uint16_t val = addr % UINT16_MAX;
	switch (hdl->reg_attr.i2cacc_addr_endian) {
	case DDI_STRUCTURE_BE_ACC:
		val = BE_16(val);
		break;
	case DDI_STRUCTURE_LE_ACC:
		val = LE_16(val);
		break;
	default:
		break;
	}

	bcopy(&val, req->ir_wdata, sizeof (val));
	req->ir_wlen = 2;
}

bool
i2c_reg_get(i2c_txn_t *txn, i2c_reg_hdl_t *hdl, uint64_t addr, void *buf,
    uint32_t nbytes, i2c_error_t *errp)
{
	i2c_req_t *req;
	i2c_error_t err;

	if (errp == NULL)
		errp = &err;

	if (!i2c_reg_check(hdl, addr, nbytes, true, errp)) {
		return (false);
	}

	if (!i2c_client_io_acquire(txn, hdl->reg_client, errp)) {
		return (false);
	}

	req = &hdl->reg_client->icli_reqs.req_i2c;
	bzero(req, sizeof (i2c_req_t));
	req->ir_addr = hdl->reg_client->icli_addr;

	i2c_reg_setup_addr(hdl, addr, req);
	req->ir_rlen = nbytes;
	VERIFY3U(req->ir_rlen, <=, sizeof (req->ir_rdata));
	bool ret = i2c_client_submit(hdl->reg_client, false);
	*errp = req->ir_error;
	if (!ret) {
		i2c_client_io_release(hdl->reg_client);
		return (false);
	}

	/*
	 * For 1 byte values, we can just copy them into place. For larger
	 * values, we need to manually walk and perform byte swaps.
	 */
	if (hdl->reg_attr.i2cacc_reg_len == 1) {
		bcopy(req->ir_rdata, buf, req->ir_rlen);
	} else {
		VERIFY3U(hdl->reg_attr.i2cacc_reg_len, ==, sizeof (uint16_t));
		for (uint32_t i = 0; i < nbytes; i += sizeof (uint16_t)) {
			uint16_t v;

			bcopy(req->ir_rdata + i, &v, sizeof (v));
			switch (hdl->reg_attr.i2cacc_reg_endian) {
			case DDI_STRUCTURE_BE_ACC:
				v = BE_16(v);
				break;
			case DDI_STRUCTURE_LE_ACC:
				v = LE_16(v);
				break;
			default:
				break;
			}

			bcopy(&v, buf + i, sizeof (v));
		}
	}

	i2c_client_io_release(hdl->reg_client);
	return (true);
}

bool
i2c_reg_put(i2c_txn_t *txn, i2c_reg_hdl_t *hdl, uint64_t addr, const void *buf,
    uint32_t nbytes, i2c_error_t *errp)
{
	i2c_req_t *req;
	i2c_error_t err;

	if (errp == NULL)
		errp = &err;

	if (!i2c_reg_check(hdl, addr, nbytes, false, errp)) {
		return (false);
	}

	if (!i2c_client_io_acquire(txn, hdl->reg_client, errp)) {
		return (false);
	}

	req = &hdl->reg_client->icli_reqs.req_i2c;
	bzero(req, sizeof (i2c_req_t));
	req->ir_addr = hdl->reg_client->icli_addr;

	i2c_reg_setup_addr(hdl, addr, req);

	if (hdl->reg_attr.i2cacc_reg_len == 1) {
		bcopy(buf, req->ir_wdata + req->ir_wlen, nbytes);
	} else {
		for (uint32_t i = 0; i < nbytes; i += sizeof (uint16_t)) {
			uint16_t v;

			bcopy(buf + i, &v, sizeof (v));
			switch (hdl->reg_attr.i2cacc_reg_endian) {
			case DDI_STRUCTURE_BE_ACC:
				v = BE_16(v);
				break;
			case DDI_STRUCTURE_LE_ACC:
				v = LE_16(v);
				break;
			default:
				break;
			}

			bcopy(&v, req->ir_wdata + req->ir_wlen + i, sizeof (v));
		}
	}

	req->ir_wlen += nbytes;
	VERIFY3P(req->ir_wlen, <=, sizeof (req->ir_wdata));

	bool ret = i2c_client_submit(hdl->reg_client, false);
	*errp = req->ir_error;
	i2c_client_io_release(hdl->reg_client);
	return (ret);
}

uint32_t
i2c_reg_max_read(i2c_reg_hdl_t *hdl)
{
	return (hdl->reg_max_nread);
}

uint32_t
i2c_reg_max_write(i2c_reg_hdl_t *hdl)
{
	return (hdl->reg_max_nwrite);
}

/*
 * We need a relatively unique name for an I2C class sensor. For now we use the
 * driver name and instance, along with the address for this particular client.
 * Something that looks more like a tree perhaps be better. As we figure out how
 * to relate things in topo, we should feel free to revisit this.
 */
int
i2c_client_ksensor_create_scalar(i2c_client_t *client, uint64_t kind,
    const ksensor_ops_t *ops, void *arg, const char *name, id_t *idp)
{
	dev_info_t *dip = client->icli_dip;
	const char *class;
	char *i2c_name;

	switch (kind) {
	case SENSOR_KIND_TEMPERATURE:
		class = "ddi_sensor:temperature:i2c";
		break;
	case SENSOR_KIND_VOLTAGE:
		class = "ddi_sensor:voltage:i2c";
		break;
	case SENSOR_KIND_CURRENT:
		class = "ddi_sensor:current:i2c";
		break;
	default:
		return (ENOTSUP);
	}

	i2c_name = kmem_asprintf("%s%d.%x:%s", ddi_driver_name(dip),
	    ddi_get_instance(dip), client->icli_addr.ia_addr, name);
	int ret = ksensor_create(dip, ops, arg, i2c_name, class, idp);
	strfree(i2c_name);
	return (ret);
}
