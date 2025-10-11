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
 * This file generally contains routines and operations that interface with
 * userland I/O.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/policy.h>
#include <sys/sysmacros.h>
#include <sys/ctype.h>

#include "i2cnex.h"

static void
i2c_user_free(i2c_user_t *user)
{
	VERIFY3P(user->iu_txn, ==, NULL);
	VERIFY3U(user->iu_thread, ==, 0);
	VERIFY0(user->iu_flags);

	if (user->iu_minor > 0) {
		ASSERT3S(user->iu_minor, >=, I2C_USER_MINOR_MIN);
		id_free(i2cnex_minors.im_user_ids, user->iu_minor);
		user->iu_minor = 0;
	}

	mutex_destroy(&user->iu_mutex);
	kmem_free(user, sizeof (i2c_user_t));
}

static i2c_user_t *
i2c_user_find_by_minor(minor_t m)
{
	const i2c_user_t u = {
		.iu_minor = m
	};
	i2c_user_t *ret;

	mutex_enter(&i2cnex_minors.im_mutex);
	ret = avl_find(&i2cnex_minors.im_users, &u, NULL);
	mutex_exit(&i2cnex_minors.im_mutex);

	return (ret);
}

static void
i2c_user_release(i2c_user_t *user)
{
	i2c_txn_t *txn = NULL;

	VERIFY3U(user->iu_thread, ==, curthread);

	mutex_enter(&user->iu_mutex);
	if ((user->iu_flags & I2C_USER_F_LOCK) != 0) {
		VERIFY3P(user->iu_txn, !=, NULL);
		VERIFY(i2c_txn_held(user->iu_txn));
		txn = user->iu_txn;
		user->iu_txn = NULL;
		i2c_txn_ctrl_unlock(txn);
		user->iu_flags &= ~I2C_USER_F_LOCK;
	}

	user->iu_flags &= ~I2C_USER_F_ACTIVE;
	user->iu_thread = 0;
	mutex_exit(&user->iu_mutex);

	if (txn != NULL) {
		i2c_txn_free(txn);
	}
}

/*
 * Acquire exclusive access to both the i2c_user_t and begin an I2C transaction
 * for performing I/O. This occurs in two steps. First we must acquire the
 * i2c_user_t from any other threads. Then we must acquire the bus, where we
 * might be competing against other user I/Os or drivers.
 */
static bool
i2c_user_acquire(i2c_user_t *user, i2c_txn_tag_t tag, bool block, bool nexus,
    i2c_error_t *err)
{
	mutex_enter(&user->iu_mutex);
	if ((user->iu_flags & I2C_USER_F_ACTIVE) != 0) {
		VERIFY3P(user->iu_txn, !=, NULL);
		return (i2c_error(err, I2C_IOCTL_E_IN_PROGRESS, 0));
	}

	user->iu_flags |= I2C_USER_F_ACTIVE;
	user->iu_thread = (uintptr_t)curthread;

	/*
	 * Check to see if we already have have a txn. This is intended for when
	 * we add the ability for a user process to hold a transaction across
	 * multiple ioctl calls.
	 */
	if (user->iu_txn != NULL) {
		if (nexus) {
			return (i2c_error(err, I2C_IOCTL_E_NO_BUS_LOCK_NEXUS,
			    0));
		}

		VERIFY3U(user->iu_flags & I2C_USER_F_CTRL_LOCK, !=, 0);
		VERIFY(i2c_txn_held(user->iu_txn));
		mutex_exit(&user->iu_mutex);
		return (true);
	}

	/*
	 * We don't have this. Drop the user lock and attempt to get an
	 * i2c_txn_t and lock things.
	 */
	mutex_exit(&user->iu_mutex);
	i2c_ctrl_t *ctrl = user->iu_nexus->in_ctrl;
	i2c_txn_t *txn = i2c_txn_alloc(ctrl, tag, user);

	err->i2c_error = i2c_txn_ctrl_lock(txn, block);
	if (err->i2c_error != I2C_CORE_E_OK) {
		i2c_txn_free(txn);
		i2c_user_release(user);
		return (false);
	}

	mutex_enter(&user->iu_mutex);
	user->iu_txn = txn;
	user->iu_flags |= I2C_USER_F_LOCK;
	mutex_exit(&user->iu_mutex);

	return (true);
}

int
i2c_nex_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	i2c_nexus_t *nex;
	i2c_user_t *user;

	if (drv_priv(credp) != 0)
		return (EPERM);

	if (otyp != OTYP_CHR)
		return (ENOTSUP);

	/*
	 * Right now we deny FEXCL because we don't have ioctls to take and
	 * release the controller lock across operations. We'd prefer to also
	 * use semantic ioctls where possible for that.
	 */
	if ((flag & (FNDELAY | FNONBLOCK | FEXCL)) != 0)
		return (EINVAL);

	if ((flag & FREAD) != FREAD)
		return (EINVAL);

	/*
	 * This is an open that refers to a given minor which could be a device
	 */
	nex = i2c_nex_find_by_minor(getminor(*devp));
	if (nex == NULL) {
		return (ENXIO);
	}

	user = kmem_zalloc(sizeof (i2c_user_t), KM_NOSLEEP_LAZY);
	if (user == NULL) {
		return (ENOMEM);
	}
	user->iu_nexus = nex;
	mutex_init(&user->iu_mutex, NULL, MUTEX_DRIVER, NULL);
	user->iu_minor = id_alloc_nosleep(i2cnex_minors.im_user_ids);
	if (user->iu_minor == -1) {
		i2c_user_free(user);
		return (ENOSPC);
	}

	mutex_enter(&i2cnex_minors.im_mutex);
	avl_add(&i2cnex_minors.im_users, user);
	mutex_exit(&i2cnex_minors.im_mutex);

	*devp = makedevice(getmajor(*devp), user->iu_minor);

	return (0);
}

/*
 * Enforce stricter checks for adding or removing a device given that this is
 * changing system configuration.
 */
static bool
i2c_nex_ioctl_port_device_manip(cred_t *credp)
{
	if (crgetzoneid(credp) != GLOBAL_ZONEID ||
	    drv_priv(credp) != 0 ||
	    secpolicy_sys_config(credp, B_FALSE) != 0) {
		return (false);
	}

	return (true);
}

static int
i2c_nex_ioctl_ctrl_props(i2c_user_t *user, intptr_t arg, int mode,
    cred_t *credp)
{
	ui2c_ctrl_nprops_t props;

	if ((mode & FREAD) == 0) {
		return (EBADF);
	}

	bzero(&props, sizeof (props));
	props.ucp_nstd = i2c_prop_nstd();
	props.ucp_npriv = 0;

	if (ddi_copyout(&props, (void *)arg, sizeof (ui2c_ctrl_nprops_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
i2c_nex_ioctl_ctrl_prop_info(i2c_user_t *user, intptr_t arg, int mode,
    cred_t *credp)
{
	ui2c_prop_info_t info;
	i2c_nexus_t *nex = user->iu_nexus;
	i2c_ctrl_t *ctrl = nex->in_ctrl;

	if ((mode & FREAD) == 0) {
		return (EBADF);
	}

	if (ddi_copyin((void *)arg, &info, sizeof (ui2c_prop_info_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (i2c_prop_info(ctrl, &info)) {
		i2c_success(&info.upi_error);
	}

	if (ddi_copyout(&info, (void *)arg, sizeof (ui2c_prop_info_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
i2c_nex_ioctl_ctrl_prop_get(i2c_user_t *user, intptr_t arg, int mode,
    cred_t *credp)
{
	ui2c_prop_t prop;
	i2c_nexus_t *nex = user->iu_nexus;
	i2c_ctrl_t *ctrl = nex->in_ctrl;

	if ((mode & FREAD) == 0) {
		return (EBADF);
	}

	if (ddi_copyin((void *)arg, &prop, sizeof (ui2c_prop_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	prop.up_size = sizeof (prop.up_value);
	if (i2c_prop_get(ctrl, prop.up_prop, prop.up_value, &prop.up_size,
	    &prop.up_error)) {
		i2c_success(&prop.up_error);
	}

	if (ddi_copyout(&prop, (void *)arg, sizeof (ui2c_prop_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
i2c_nex_ioctl_ctrl_prop_set(i2c_user_t *user, intptr_t arg, int mode,
    cred_t *credp)
{
	ui2c_prop_t prop;
	i2c_nexus_t *nex = user->iu_nexus;
	i2c_ctrl_t *ctrl = nex->in_ctrl;

	if (!i2c_nex_ioctl_port_device_manip(credp)) {
		return (EPERM);
	}

	if ((mode & FWRITE) == 0) {
		return (EBADF);
	}

	if (ddi_copyin((void *)arg, &prop, sizeof (ui2c_prop_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (!i2c_user_acquire(user, I2C_LOCK_TAG_USER_PROP_SET, true, false,
	    &prop.up_error)) {
		goto copyout;
	}

	if (i2c_prop_set(user->iu_txn, ctrl, prop.up_prop, prop.up_value,
	    prop.up_size, &prop.up_error)) {
		i2c_success(&prop.up_error);
	}
	i2c_user_release(user);

copyout:
	if (ddi_copyout(&prop, (void *)arg, sizeof (ui2c_prop_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
i2c_nex_ioctl_dev_info(i2c_user_t *user, intptr_t arg, int mode,
    cred_t *credp)
{
	int *reg;
	uint_t nreg;
	ui2c_dev_info_t info;
	i2c_nexus_t *nex = user->iu_nexus;
	i2c_dev_t *dev = nex->in_data.in_dev;

	if ((mode & FREAD) == 0) {
		return (EBADF);
	}

	bzero(&info, sizeof (info));

	if (!i2c_user_acquire(user, I2C_LOCK_TAG_USER_DEV_INFO, true, false,
	    &info.udi_error)) {
		goto copyout;
	}

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, nex->in_dip,
	    DDI_PROP_DONTPASS, "reg", &reg, &nreg) != DDI_PROP_SUCCESS) {
		(void) i2c_error(&info.udi_error, I2C_IOCTL_E_NEXUS, 0);
		goto copyout;
	}

	if (nreg % 2 != 0) {
		ddi_prop_free(reg);
		(void) i2c_error(&info.udi_error, I2C_IOCTL_E_NEXUS, 0);
		goto copyout;
	}

	for (uint_t i = 0; i < nreg; i += 2) {
		i2c_addr_t addr = { reg[i], reg[i + 1] };
		if (!i2c_addr_validate(&addr, &info.udi_error)) {
			ddi_prop_free(reg);
			(void) i2c_error(&info.udi_error, I2C_IOCTL_E_NEXUS, 0);
			goto copyout;
		}

		if (addr.ia_type != I2C_ADDR_7BIT)
			continue;

		info.udi_7b[addr.ia_addr] = I2C_ADDR_SOURCE_REG;
		if (i == 0) {
			info.udi_primary.ia_type = I2C_ADDR_7BIT;
			info.udi_primary.ia_addr = addr.ia_addr;
		}
	}
	ddi_prop_free(reg);

	if (dev->id_mux != NULL) {
		info.udi_flags |= UI2C_DEV_F_MUX;
	}

	for (i2c_client_t *client = list_head(&dev->id_clients); client != NULL;
	    client = list_next(&dev->id_clients, client)) {
		i2c_addr_source_t type;

		VERIFY3U(client->icli_addr.ia_type, ==, I2C_ADDR_7BIT);

		/*
		 * This indicates it's an address from a reg[]. This is already
		 * handled.
		 */
		if ((client->icli_flags & I2C_CLIENT_F_CLAIM_ADDR) == 0)
			continue;

		if ((client->icli_flags & I2C_CLIENT_F_SHARED_ADDR) != 0) {
			type = I2C_ADDR_SOURCE_SHARED;
		} else {
			type = I2C_ADDR_SOURCE_CLAIMED;
		}

		info.udi_7b[client->icli_addr.ia_addr] = (uint8_t)type;
	}
	i2c_user_release(user);

copyout:
	if (ddi_copyout(&info, (void *)arg, sizeof (ui2c_dev_info_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
i2c_nex_ioctl_mux_info(i2c_user_t *user, intptr_t arg, int mode,
    cred_t *credp)
{
	ui2c_mux_info_t info;
	i2c_nexus_t *nex = user->iu_nexus;
	i2c_mux_t *mux = nex->in_data.in_mux;

	if ((mode & FREAD) == 0) {
		return (EBADF);
	}

	bzero(&info, sizeof (info));
	info.umi_nports = mux->im_nports;

	if (ddi_copyout(&info, (void *)arg, sizeof (ui2c_mux_info_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
i2c_nex_ioctl_port_info(i2c_user_t *user, intptr_t arg, int mode,
    cred_t *credp)
{
	ui2c_port_info_t info;
	i2c_nexus_t *nex = user->iu_nexus;
	i2c_port_t *port = nex->in_data.in_port;

	if ((mode & FREAD) == 0) {
		return (EBADF);
	}

	bzero(&info, sizeof (info));

	if (!i2c_user_acquire(user, I2C_LOCK_TAG_USER_PROP_INFO, true, false,
	    &info.upo_error)) {
		goto copyout;
	}

	info.upo_portno = port->ip_portno;
	info.upo_ndevs = avl_numnodes(&port->ip_devices);
	info.upo_ndevs_ds = port->ip_ndevs_ds;
	i2c_addr_info_7b(port, &info);
	i2c_user_release(user);

copyout:
	if (ddi_copyout(&info, (void *)arg, sizeof (ui2c_port_info_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

/*
 * While we have made sure to consider 10-bit address support, we only support
 * 7-bit addresses.
 */
bool
i2c_addr_validate(const i2c_addr_t *addr, i2c_error_t *err)
{
	switch (addr->ia_type) {
	case I2C_ADDR_7BIT:
		break;
	case I2C_ADDR_10BIT:
		if (addr->ia_addr >= (1 << 10)) {
			return (i2c_error(err, I2C_CORE_E_BAD_ADDR, 0));
		}
		return (i2c_error(err, I2C_CORE_E_UNSUP_ADDR_TYPE, 0));
	default:
		return (i2c_error(err, I2C_CORE_E_BAD_ADDR_TYPE, 0));
	}

	/*
	 * We specifically refuse to address reserved addresses in this list at
	 * this time. These are all noted as reserved in I2C. While SMBus has
	 * more addresses with specific semantic meanings, we don't need to
	 * guard against them, though one could reasonably ask about things like
	 * PMBus Zone and other PMBus broadcast commands.
	 */
	switch (addr->ia_addr) {
	case I2C_RSVD_ADDR_GEN_CALL:
	case I2C_RSVD_ADDR_C_BUS:
	case I2C_RSVD_ADDR_DIFF_BUS:
	case I2C_RSVD_ADDR_FUTURE:
	case I2C_RSVD_ADDR_HS_0:
	case I2C_RSVD_ADDR_HS_1:
	case I2C_RSVD_ADDR_HS_2:
	case I2C_RSVD_ADDR_HS_3:
	case I2C_RSVD_ADDR_10B_0:
	case I2C_RSVD_ADDR_10B_1:
	case I2C_RSVD_ADDR_10B_2:
	case I2C_RSVD_ADDR_10B_3:
	case I2C_RSVD_ADDR_DID_0:
	case I2C_RSVD_ADDR_DID_1:
	case I2C_RSVD_ADDR_DID_2:
	case I2C_RSVD_ADDR_DID_3:
		return (i2c_error(err, I2C_CORE_E_ADDR_RSVD, 0));
	default:
		if (addr->ia_addr >= (1 << 7)) {
			return (i2c_error(err, I2C_CORE_E_BAD_ADDR, 0));
		}
	}

	return (true);
}

static bool
i2c_req_validate(i2c_req_t *req)
{
	if (!i2c_addr_validate(&req->ir_addr, &req->ir_error)) {
		return (false);
	}

	if (req->ir_flags != 0) {
		return (i2c_error(&req->ir_error, I2C_CORE_E_BAD_I2C_REQ_FLAGS,
		    0));
	}

	if (req->ir_wlen > sizeof (req->ir_wdata)) {
		return (i2c_error(&req->ir_error,
		    I2C_CORE_E_BAD_I2C_REQ_WRITE_LEN, 0));
	}

	if (req->ir_rlen > sizeof (req->ir_rdata)) {
		return (i2c_error(&req->ir_error,
		    I2C_CORE_E_BAD_I2C_REQ_READ_LEN, 0));
	}

	if (req->ir_rlen == 0 && req->ir_wlen == 0) {
		return (i2c_error(&req->ir_error, I2C_CORE_E_NEED_READ_OR_WRITE,
		    0));
	}

	return (true);
}

/*
 * Validate aspects of the actual request itself. There is no way to validate
 * the command field nor the actual data fields.
 */
static bool
smbus_req_validate(smbus_req_t *req)
{
	if (!i2c_addr_validate(&req->smbr_addr, &req->smbr_error)) {
		return (false);
	}

	if ((req->smbr_flags & ~I2C_IO_REQ_F_QUICK_WRITE) != 0) {
		return (i2c_error(&req->smbr_error,
		    I2C_CORE_E_BAD_SMBUS_REQ_FLAGS, 0));
	} else if ((req->smbr_flags & I2C_IO_REQ_F_QUICK_WRITE) != 0 &&
	    req->smbr_op != SMBUS_OP_QUICK_COMMAND) {
		return (i2c_error(&req->smbr_error,
		    I2C_CORE_E_BAD_SMBUS_REQ_FLAGS, 0));
	}

	switch (req->smbr_op) {
	case SMBUS_OP_QUICK_COMMAND:
	case SMBUS_OP_SEND_BYTE:
	case SMBUS_OP_WRITE_BYTE:
	case SMBUS_OP_WRITE_WORD:
	case SMBUS_OP_WRITE_U32:
	case SMBUS_OP_WRITE_U64:
	case SMBUS_OP_RECV_BYTE:
	case SMBUS_OP_READ_BYTE:
	case SMBUS_OP_READ_WORD:
	case SMBUS_OP_READ_U32:
	case SMBUS_OP_READ_U64:
	case SMBUS_OP_PROCESS_CALL:
		/*
		 * These commands have a fixed read/write size, therefore we do
		 * not allow one to be specified.
		 */
		if (req->smbr_rlen != 0) {
			return (i2c_error(&req->smbr_error,
			    I2C_CORE_E_BAD_SMBUS_READ_LEN, 0));
		}

		if (req->smbr_wlen != 0) {
			return (i2c_error(&req->smbr_error,
			    I2C_CORE_E_BAD_SMBUS_WRITE_LEN, 0));
		}
		break;
	case SMBUS_OP_WRITE_BLOCK:
	case SMBUS_OP_I2C_WRITE_BLOCK:
		if (req->smbr_rlen != 0) {
			return (i2c_error(&req->smbr_error,
			    I2C_CORE_E_BAD_SMBUS_READ_LEN, 0));
		}

		if (req->smbr_wlen == 0 || req->smbr_wlen > I2C_REQ_MAX) {
			return (i2c_error(&req->smbr_error,
			    I2C_CORE_E_BAD_SMBUS_WRITE_LEN, 0));
		}
		break;
	case SMBUS_OP_I2C_READ_BLOCK:
		if (req->smbr_rlen == 0 || req->smbr_rlen > I2C_REQ_MAX) {
			return (i2c_error(&req->smbr_error,
			    I2C_CORE_E_BAD_SMBUS_READ_LEN, 0));
		}

		if (req->smbr_wlen != 0) {
			return (i2c_error(&req->smbr_error,
			    I2C_CORE_E_BAD_SMBUS_WRITE_LEN, 0));
		}
		break;
	case SMBUS_OP_READ_BLOCK:
	case SMBUS_OP_BLOCK_PROCESS_CALL:
	case SMBUS_OP_HOST_NOTIFY:

		/*
		 * These operations are unsupported right now. The block
		 * portions require us to handle variable I/O. The notification
		 * doesn't make sense for a controller interface today. If we
		 * end up supporting a target mode then we should consider it.
		 */
		return (i2c_error(&req->smbr_error, I2C_CORE_E_UNSUP_SMBUS_OP,
		    0));
	default:
		return (i2c_error(&req->smbr_error, I2C_CORE_E_BAD_SMBUS_OP,
		    0));
	}

	return (true);
}

/*
 * This is one of two functions for a user to perform I/O targeting any device
 * on a port. I/O targeting a port is slightly different from I/O targeting a
 * device when it comes to mux activation. In this case, only the muxes that are
 * required to reach this port will be activated before issuing the I/O. For a
 * device based target, we will activate all the muxes required to get there.
 *
 * The call to i2c_user_lock() will make sure that only one thread is
 * actively performing I/O on this fd at a time. That is part of our contract
 * with userland. It will also take care of ensuring or leveraging any existing
 * controller locks. i2c_ctrl_io_i2c() will actually take care of dealing with
 * muxes and translating the request to an SMBus request if the underlying
 * controller is an SMBus device.
 */
static int
i2c_nex_ioctl_port_i2c_req(i2c_user_t *user, intptr_t arg, int mode,
    cred_t *credp)
{
	i2c_req_t req;
	i2c_nexus_t *nex = user->iu_nexus;
	i2c_ctrl_t *ctrl = nex->in_ctrl;

	if (!i2c_nex_ioctl_port_device_manip(credp)) {
		return (EPERM);
	}

	if ((mode & (FREAD | FWRITE)) != (FREAD | FWRITE)) {
		return (EBADF);
	}

	if (ddi_copyin((void *)arg, &req, sizeof (i2c_req_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (!i2c_req_validate(&req)) {
		goto copyout;
	}

	if (!i2c_user_acquire(user, I2C_LOCK_TAG_USER_IO, true, false,
	    &req.ir_error)) {
		goto copyout;
	}

	(void) i2c_ctrl_io_i2c(user->iu_txn, ctrl, nex->in_data.in_port, &req);
	i2c_user_release(user);

copyout:
	if (ddi_copyout(&req, (void *)arg, sizeof (i2c_req_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
i2c_nex_ioctl_port_smbus_req(i2c_user_t *user, intptr_t arg, int mode,
    cred_t *credp)
{
	smbus_req_t req;
	i2c_nexus_t *nex = user->iu_nexus;
	i2c_ctrl_t *ctrl = nex->in_ctrl;

	if (!i2c_nex_ioctl_port_device_manip(credp)) {
		return (EPERM);
	}

	if ((mode & (FREAD | FWRITE)) != (FREAD | FWRITE)) {
		return (EBADF);
	}

	if (ddi_copyin((void *)arg, &req, sizeof (smbus_req_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (!smbus_req_validate(&req)) {
		goto copyout;
	}

	if (!i2c_user_acquire(user, I2C_LOCK_TAG_USER_IO, true, false,
	    &req.smbr_error)) {
		goto copyout;
	}

	(void) i2c_ctrl_io_smbus(user->iu_txn, ctrl, nex->in_data.in_port,
	    &req);
	i2c_user_release(user);

copyout:
	if (ddi_copyout(&req, (void *)arg, sizeof (i2c_req_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

typedef struct {
	i2c_addr_t da_addr;
	char *da_name;
	char **da_compat;
	uint_t da_ncompat;
	bool da_have_type;
	bool da_have_addr;
} i2c_dev_add_t;

typedef struct {
	const char *dan_key;
	bool (*dan_proc)(nvpair_t *, i2c_error_t *, i2c_dev_add_t *);
} i2c_dev_add_nvl_proc_t;

static bool
i2c_nex_dev_add_parse_addr(nvpair_t *pair, i2c_error_t *err, i2c_dev_add_t *add)
{
	if (nvpair_value_uint16(pair, &add->da_addr.ia_addr) != 0) {
		return (i2c_error(err, I2C_IOCTL_E_NVL_KEY_BAD_TYPE, 0));
	}

	add->da_have_addr = true;
	return (true);
}

static bool
i2c_nex_dev_add_parse_type(nvpair_t *pair, i2c_error_t *err, i2c_dev_add_t *add)
{
	if (nvpair_value_uint16(pair, &add->da_addr.ia_type) != 0) {
		return (i2c_error(err, I2C_IOCTL_E_NVL_KEY_BAD_TYPE, 0));
	}

	add->da_have_type = true;
	return (true);
}

static bool
i2c_nex_dev_add_name_valid(const char *name, i2c_error_t *err)
{
	size_t len = strnlen(name, I2C_NAME_MAX);
	if (len >= I2C_NAME_MAX || len == 0) {
		return (i2c_error(err, I2C_IOCTL_E_BAD_DEV_NAME, 0));
	}

	if (!ISALPHA(name[0])) {
		return (i2c_error(err, I2C_IOCTL_E_BAD_DEV_NAME, 0));
	}

	for (size_t i = 1; i < len; i++) {
		if (ISALPHA(name[i]) || ISDIGIT(name[i])) {
			continue;
		}

		if (name[i] == ',' || name[i] == '.' || name[i] == '+' ||
		    name[i] == '-' || name[i] == '_') {
			continue;
		}

		return (i2c_error(err, I2C_IOCTL_E_BAD_DEV_NAME, 0));
	}

	return (true);
}

static bool
i2c_nex_dev_add_parse_name(nvpair_t *pair, i2c_error_t *err, i2c_dev_add_t *add)
{
	if (nvpair_value_string(pair, &add->da_name) != 0) {
		return (i2c_error(err, I2C_IOCTL_E_NVL_KEY_BAD_TYPE, 0));
	}

	return (i2c_nex_dev_add_name_valid(add->da_name, err));
}

static bool
i2c_nex_dev_add_parse_compat(nvpair_t *pair, i2c_error_t *err,
    i2c_dev_add_t *add)
{
	if (nvpair_value_string_array(pair, &add->da_compat,
	    &add->da_ncompat) != 0) {
		return (i2c_error(err, I2C_IOCTL_E_NVL_KEY_BAD_TYPE, 0));
	}

	if (add->da_ncompat > UI2C_IOCTL_NVL_NCOMPAT_MAX) {
		return (i2c_error(err, I2C_IOCTL_E_COMPAT_LEN_RANGE, 0));
	}

	for (size_t i = 0; i < add->da_ncompat; i++) {
		if (!i2c_nex_dev_add_name_valid(add->da_compat[i], err)) {
			return (false);
		}
	}

	return (true);
}

static const i2c_dev_add_nvl_proc_t dev_add_nvl[] = {
	{ UI2C_IOCTL_NVL_ADDR, i2c_nex_dev_add_parse_addr },
	{ UI2C_IOCTL_NVL_TYPE, i2c_nex_dev_add_parse_type },
	{ UI2C_IOCTL_NVL_NAME, i2c_nex_dev_add_parse_name },
	{ UI2C_IOCTL_NVL_COMPAT, i2c_nex_dev_add_parse_compat }
};

static bool
i2c_nex_dev_add_nvl_parse(nvlist_t *nvl, i2c_error_t *err, i2c_dev_add_t *add)
{
	bzero(add, sizeof (i2c_dev_add_t));

	for (nvpair_t *nvpair = nvlist_next_nvpair(nvl, NULL); nvpair != NULL;
	    nvpair = nvlist_next_nvpair(nvl, nvpair)) {
		const char *name = nvpair_name(nvpair);
		bool match = false;

		for (size_t i = 0; i < ARRAY_SIZE(dev_add_nvl); i++) {
			if (strcmp(name, dev_add_nvl[i].dan_key) != 0)
				continue;

			match = true;
			if (!dev_add_nvl[i].dan_proc(nvpair, err, add)) {
				return (false);
			}
			break;
		}

		if (!match) {
			return (i2c_error(err, I2C_IOCTL_E_NVL_KEY_UNKNOWN, 0));
		}
	}

	if (!add->da_have_type || !add->da_have_addr || add->da_name == NULL) {
		return (i2c_error(err, I2C_IOCTL_E_NVL_KEY_MISSING, 0));
	}

	/*
	 * We can't validate the address without knowing which type it is.
	 * Now that we've parsed each key, check whether the address fits or is
	 * a reserved address.
	 */
	return (i2c_addr_validate(&add->da_addr, err));
}

static int
i2c_nex_ioctl_port_device_add(i2c_user_t *user, intptr_t arg, int mode,
    cred_t *credp)
{
	ui2c_dev_add_t dev;
	i2c_dev_add_t add;
	char *nvl_data = NULL;
	nvlist_t *nvl = NULL;
#ifdef	_MULTI_DATAMODEL
	ui2c_dev_add32_t dev32;
#endif

	if (!i2c_nex_ioctl_port_device_manip(credp)) {
		return (EPERM);
	}

	if ((mode & FWRITE) == 0) {
		return (EBADF);
	}

	uint_t model = ddi_model_convert_from(mode);
	switch (model) {
#ifdef	_MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		bzero(&dev, sizeof (dev));
		if (ddi_copyin((void *)arg, &dev32, sizeof (dev32),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		dev.uda_nvl = dev32.uda_nvl;
		dev.uda_nvl_len = dev32.uda_nvl_len;
		break;
#endif	/* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)arg, &dev, sizeof (dev),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		break;
	default:
		return (ENOTSUP);
	}

	if (dev.uda_nvl_len > UI2C_IOCTL_NVL_MAX_SIZE) {
		(void) i2c_error(&dev.uda_error, I2C_IOCTL_E_NVL_TOO_BIG, 0);
		goto copyout;
	}

	nvl_data = kmem_alloc(UI2C_IOCTL_NVL_MAX_SIZE, KM_NOSLEEP_LAZY);
	if (nvl_data == NULL) {
		(void) i2c_error(&dev.uda_error, I2C_IOCTL_E_NO_KERN_MEM, 0);
		goto copyout;
	}

	if (ddi_copyin((void *)dev.uda_nvl, nvl_data, dev.uda_nvl_len,
	    mode & FKIOCTL) != 0) {
		(void) i2c_error(&dev.uda_error, I2C_IOCTL_E_BAD_USER_DATA, 0);
		goto copyout;
	}

	if (nvlist_unpack(nvl_data, dev.uda_nvl_len, &nvl, 0) != 0) {
		(void) i2c_error(&dev.uda_error, I2C_IOCTL_E_NVL_INVALID, 0);
		goto copyout;
	}

	if (!i2c_nex_dev_add_nvl_parse(nvl, &dev.uda_error, &add)) {
		goto copyout;
	}

	/*
	 * We've gotten to the point where we know that the request contains
	 * something that looks reasonable. We first need to see if this address
	 * is free. If so, we claim the address and then deal with the NDI dance
	 * required to actually create the node. Note, all ndi holds have to be
	 * done ahead of taking the controller lock, hence why that comes first
	 * and may seem a bit early.
	 */
	i2c_nexus_t *nex = user->iu_nexus;
	i2c_port_t *port = nex->in_data.in_port;

	/*
	 * We're required to enter the NDI node for this before we take the
	 * controller lock. This ensures that a BUS_CONFIG_ALL request can't
	 * come in between us adding the device and then going through and
	 * trying to construct this. Because we're required to take the NDI
	 * here, we cannot actually operate across a request to have locke the
	 * bus via an ioctl. That is for I/O only.
	 */
	ndi_devi_enter(nex->in_dip);
	if (!i2c_user_acquire(user, I2C_LOCK_TAG_USER_DEV_ADD, true, true,
	    &dev.uda_error)) {
		ndi_devi_exit(nex->in_dip);
		goto copyout;
	}

	i2c_dev_t *device = i2c_device_init(user->iu_txn, port, &add.da_addr,
	    add.da_name, add.da_compat, add.da_ncompat, &dev.uda_error);
	if (device == NULL) {
		i2c_user_release(user);
		ndi_devi_exit(nex->in_dip);
		goto copyout;
	}

	/*
	 * We need to drop the controller lock while we attempt to process this
	 * operation. Because we have the NDI hold, no one can come in and
	 * remove the device we just added (because they'd need this). While in
	 * an ideal world we might want to hold the controller lock across our
	 * device configuration, this can recursively configure across a large
	 * number of threads. For example, if this device adds a mux, it'll then
	 * attempt to recursively configure and not just across this one. This
	 * isn't ideal, but it is how it is.
	 */
	i2c_user_release(user);

	/*
	 * We want to make sure that a BUS_CONFIG_ALL request that comes in
	 * while we're getting this ready can't find us while we're between this
	 * point and doing the ndi_devi_config_one() call. As such we need to
	 * enter the dev_info node here.
	 */
	if (!i2c_device_config(port, device)) {
		if (!i2c_user_acquire(user, I2C_LOCK_TAG_USER_DEV_ADD, true,
		    true, &dev.uda_error)) {
			ndi_devi_exit(nex->in_dip);
			goto copyout;
		}
		i2c_device_fini(user->iu_txn, port, device);
		i2c_user_release(user);
		(void) i2c_error(&dev.uda_error, I2C_IOCTL_E_NEXUS, 0);
	} else {
		i2c_success(&dev.uda_error);
	}

	ndi_devi_exit(nex->in_dip);

copyout:
	if (nvl_data != NULL) {
		kmem_free(nvl_data, UI2C_IOCTL_NVL_MAX_SIZE);
	}

	if (nvl != NULL) {
		nvlist_free(nvl);
	}

	switch (model) {
#ifdef	_MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		dev32.uda_error = dev.uda_error;

		if (ddi_copyout(&dev32, (void *)arg, sizeof (dev32),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		break;
#endif	/* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
		if (ddi_copyout(&dev, (void *)arg, sizeof (dev),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		break;
	default:
		return (ENOTSUP);
	}


	return (0);
}

static int
i2c_nex_ioctl_port_device_rem(i2c_user_t *user, intptr_t arg, int mode,
    cred_t *credp)
{
	ui2c_dev_rem_t rem;

	/*
	 * Enforce stricter checks for removing a device given that this is
	 * changing system configuration.
	 */
	if (!i2c_nex_ioctl_port_device_manip(credp)) {
		return (EPERM);
	}

	if ((mode & FWRITE) == 0) {
		return (EBADF);
	}

	if (ddi_copyin((void *)arg, &rem, sizeof (rem), mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (!i2c_addr_validate(&rem.udr_addr, &rem.udr_error))
		goto copyout;

	/*
	 * At this point we're going to enter both the ndi lock for this port
	 * and then the controller lock. This makes sure we have a consistent
	 * view of the world as we go to manipulate it and check it. We first
	 * check to see if the device exists. Then we have to drop the
	 * controller lock and ask the NDI to remove this recursively. This may
	 * fail because the device is in use. If it succeeds, then we go through
	 * and grab the controller and remove all the remaining metadata there.
	 */
	i2c_nexus_t *nex = user->iu_nexus;
	i2c_port_t *port = nex->in_data.in_port;

	ndi_devi_enter(nex->in_dip);
	if (!i2c_user_acquire(user, I2C_LOCK_TAG_USER_DEV_RM, true, true,
	    &rem.udr_error)) {
		ndi_devi_exit(nex->in_dip);
		goto copyout;
	}

	i2c_dev_t *dev = i2c_device_find_by_addr(user->iu_txn, port,
	    &rem.udr_addr);
	if (dev == NULL) {
		i2c_user_release(user);
		ndi_devi_exit(nex->in_dip);
		(void) i2c_error(&rem.udr_error, I2C_CORE_E_UNKNOWN_ADDR, 0);
		goto copyout;
	}

	/*
	 * We've found this, drop the txn, nothing else can remove this from
	 * here because we have the NDI node. Do this, then go back and actually
	 * finish freeing the device.
	 */
	i2c_user_release(user);

	if (!i2c_device_unconfig(port, dev)) {
		ndi_devi_exit(nex->in_dip);
		(void) i2c_error(&rem.udr_error, I2C_IOCTL_E_NEXUS, 0);
		goto copyout;
	}

	if (!i2c_user_acquire(user, I2C_LOCK_TAG_USER_DEV_RM, true, true,
	    &rem.udr_error)) {
		ndi_devi_exit(nex->in_dip);
		goto copyout;
	}

	/*
	 * We must proceed to clean up the metadata related to this device while
	 * we have our hold to ensure that no one else can come in and do
	 * something like a BUS_CONFIG_ALL while we're operating.
	 */
	VERIFY3P(dev->id_nex->in_dip, ==, NULL);
	i2c_device_fini(user->iu_txn, port, dev);
	dev = NULL;
	i2c_user_release(user);
	ndi_devi_exit(nex->in_dip);

	i2c_success(&rem.udr_error);

copyout:
	if (ddi_copyout(&rem, (void *)arg, sizeof (rem), mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

int
i2c_nex_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int ret;
	i2c_user_t *user;

	user = i2c_user_find_by_minor(getminor(dev));
	if (user == NULL) {
		return (ENXIO);
	}

	switch (user->iu_nexus->in_type) {
	case I2C_NEXUS_T_CTRL:
		switch (cmd) {
		case UI2C_IOCTL_CTRL_NPROPS:
			ret = i2c_nex_ioctl_ctrl_props(user, arg, mode, credp);
			break;
		case UI2C_IOCTL_CTRL_PROP_INFO:
			ret = i2c_nex_ioctl_ctrl_prop_info(user, arg, mode,
			    credp);
			break;
		case UI2C_IOCTL_CTRL_PROP_GET:
			ret = i2c_nex_ioctl_ctrl_prop_get(user, arg, mode,
			    credp);
			break;
		case UI2C_IOCTL_CTRL_PROP_SET:
			ret = i2c_nex_ioctl_ctrl_prop_set(user, arg, mode,
			    credp);
			break;
		default:
			ret = ENOTTY;
			break;
		}
		break;
	case I2C_NEXUS_T_DEV:
		switch (cmd) {
		case UI2C_IOCTL_DEV_INFO:
			ret = i2c_nex_ioctl_dev_info(user, arg, mode, credp);
			break;
		default:
			ret = ENOTTY;
			break;
		}
		break;
	case I2C_NEXUS_T_MUX:
		switch (cmd) {
		case UI2C_IOCTL_MUX_INFO:
			ret = i2c_nex_ioctl_mux_info(user, arg, mode, credp);
			break;
		default:
			ret = ENOTTY;
			break;
		}
		break;
	case I2C_NEXUS_T_PORT:
		switch (cmd) {
		case UI2C_IOCTL_PORT_INFO:
			ret = i2c_nex_ioctl_port_info(user, arg, mode, credp);
			break;
		case UI2C_IOCTL_I2C_REQ:
			ret = i2c_nex_ioctl_port_i2c_req(user, arg, mode,
			    credp);
			break;
		case UI2C_IOCTL_SMBUS_REQ:
			ret = i2c_nex_ioctl_port_smbus_req(user, arg, mode,
			    credp);
			break;
		case UI2C_IOCTL_DEVICE_ADD:
			ret = i2c_nex_ioctl_port_device_add(user, arg, mode,
			    credp);
			break;
		case UI2C_IOCTL_DEVICE_REMOVE:
			ret = i2c_nex_ioctl_port_device_rem(user, arg, mode,
			    credp);
			break;
		default:
			ret = ENOTTY;
			break;
		}
		break;
	default:
		panic("unknown I2C nexus type: 0x%x", user->iu_nexus->in_type);
	}

	return (ret);
}

int
i2c_nex_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	i2c_user_t *user;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	user = i2c_user_find_by_minor(getminor(dev));
	if (user == NULL) {
		return (ENXIO);
	}

	mutex_enter(&i2cnex_minors.im_mutex);
	avl_remove(&i2cnex_minors.im_users, user);
	mutex_exit(&i2cnex_minors.im_mutex);

	i2c_user_free(user);

	return (0);
}
