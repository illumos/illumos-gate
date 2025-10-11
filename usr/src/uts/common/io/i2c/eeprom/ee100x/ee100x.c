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
 * DDR4 EEPROM Driver
 *
 * -------------
 * Device Design
 * -------------
 *
 * The EE1004 device is found in DDR4 devices and is specified by JC-42.4.
 * These EEPROMs are 512-byte devices that are split into two 256-byte pages and
 * have the ability to lock data in 128-byte regions. As was the style of the
 * time and likely a side effect of device operation, the page select and data
 * read/write operations are split across two different I2C addresses.
 *
 * The JEDEC spec splits the 7-bit address into a 4-bit device class and a
 * 3-bit device ID. The device ID is used to identify a single DIMM, whose id is
 * usally set based on pins on the DDR4 socket. So to read from DIMM 0 we would
 * target address 0x50. From DIMM4, 0x54. From DIMM7, 0x57.
 *
 * While these devices have separate addresses for the SPD reads and writes
 * (along with the temperature sensor) all other addresses are shared between
 * devices. In particular this includes the page address and the write
 * protection features. In other words, if you change the active page, it's
 * going to change it for all devices at that spot in the tree. Similarly if you
 * issue a write protect command it's for everything that can be reached.
 *
 * Now of course, there are only up to 8 device IDs on a bus; however, DDR4
 * server platforms often supported up to 16 DIMMs, which means muxes are in
 * play. This means that on a common DDR4 server platform you often have
 * something that looks like:
 *
 *                          +------------+
 *                          |    I2C     |
 *                          | controller |
 *                          +------------+
 *                                |
 *                                |
 *                                v
 *                            +-------+
 *             +--------------|  mux  |--------------+
 *             |              +-------+              |
 *             |                                     |
 *    +-----+--+--+-----+                   +-----+--+--+-----+
 *    |     |     |     |                   |     |     |     |
 *    v     v     v     v                   v     v     v     v
 *  +---+ +---+ +---+ +---+               +---+ +---+ +---+ +---+
 *  | D | | D | | D | | D |               | D | | D | | D | | D |
 *  | I | | I | | I | | I |               | I | | I | | I | | I |
 *  | M | | M | | M | | M |               | M | | M | | M | | M |
 *  | M | | M | | M | | M |               | M | | M | | M | | M |
 *  |   | |   | |   | |   |               |   | |   | |   | |   |
 *  | 0 | | 1 | | 2 | | 3 |               | 8 | | 9 | | a | | b |
 *  +---+ +---+ +---+ +---+               +---+ +---+ +---+ +---+
 *
 * So while we said earlier that all devices will change at the same time or be
 * impacted by I/O to a common address, that isn't quite true. It's technically
 * all devices that are on the same mux segment.
 *
 * -------------------------
 * Driver Address Management
 * -------------------------
 *
 *
 * To keep the driver simple, we don't try to ask the question of whether
 * or not a device is in the same spot of the tree. Similarly, we also don't
 * actually try to remember what page was last set. We do this because we don't
 * want to track what device was last active and then this allows someone else
 * using the bus behind our backs to have made changes. In other words, we will
 * always set the page for every I/O. While this wastes a bit of bus transaction
 * time, it's not the end of world. Notably asking what page is set costs the
 * same as just setting it.
 *
 * Each instance of the device ends up with three different I2C clients today:
 *
 *  1. A client (and reg handle) for the EEPROM itself.
 *  2. A client for selecting page 0 (0x36).
 *  3. A client for selecting page 1 (0x37).
 *
 * The client for (1) comes from the device reg[] array. The other two are
 * shared addresses that we claim at run time. Due to having to change the page,
 * we end up serializing I/O across all instances of the device with a shared
 * mutex: ee100x_spa_mutex. Our lock ordering requires that one hold this mutex
 * prior to beginning any bus transactions. A bus transaction must be made
 * explicitly and passed from call to call to ensure that we don't have anyone
 * else interrupt us for a single I/O and potentially change the page semantics
 * on us.
 *
 * While there are are writable portions of the SPD, today the driver does not
 * support that wanting to ensure that we don't actually damage the device and
 * make it impossible for the CPU to use the DRAM in question.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/bitext.h>

#include <sys/i2c/client.h>
#include <eedev.h>

/*
 * These are the I2C addresses that are used to change and query pages per
 * EE1004. The way that the device indicates what page it's on is by issuing an
 * ack (page 0) or a nack (page 1) to a request.
 */
#define	EE1004_GET_PAGE_ADDR	0x36
#define	EE1004_SET_PAGE0_ADDR	0x36
#define	EE1004_SET_PAGE1_ADDR	0x37

/*
 * Organization of an EEPROM1004 device. The device is required to always be a
 * 512 byte device organized in two banks of 256 bytes.
 */
#define	EE1004_LEN	512
#define	EE1004_SEG	256

typedef struct ee100x {
	dev_info_t *ee_dip;
	i2c_client_t *ee_mem;
	i2c_reg_hdl_t *ee_mem_hdl;
	i2c_client_t *ee_spa0;
	i2c_client_t *ee_spa1;
	eedev_hdl_t *ee_devhdl;
	uint8_t ee_buf[I2C_REQ_MAX];
} ee100x_t;

/*
 * Device soft state
 */
static void *ee100x_state;

/*
 * This is a driver-wide mutex that we use to serialize all operations related
 * to page switching and I/O. Effectively the driver can only support a single
 * I/O outstanding across the system. See the theory statement for more
 * information.
 */
static kmutex_t ee100x_spa_mutex;

static int
ee100x_read(void *arg, struct uio *uio, uint32_t page, uint32_t pageoff,
    uint32_t nbytes)
{
	int ret = 0;
	ee100x_t *ee = arg;
	i2c_client_t *client;
	i2c_txn_t *txn;
	i2c_error_t err;

	if (page == 0) {
		client = ee->ee_spa0;
	} else {
		client = ee->ee_spa1;
	}

	mutex_enter(&ee100x_spa_mutex);
	if (i2c_bus_lock(client, 0, &txn) != I2C_CORE_E_OK) {
		mutex_exit(&ee100x_spa_mutex);
		return (EINTR);
	}

	if (!smbus_client_write_u8(txn, client, 0, 0, &err)) {
		dev_err(ee->ee_dip, CE_WARN, "!failed to select page %u: "
		    "0x%x/0x%x", page, err.i2c_error, err.i2c_ctrl);
		ret = EIO;
		goto done;
	}

	if (i2c_reg_get(txn, ee->ee_mem_hdl, pageoff, ee->ee_buf, nbytes,
	    &err)) {
		ret = uiomove(ee->ee_buf, nbytes, UIO_READ, uio);
	} else {
		dev_err(ee->ee_dip, CE_WARN, "!failed to read %u bytes of NVM "
		    "at 0x%x on page %u: 0x%x/0x%x", nbytes, pageoff, page,
		    err.i2c_error, err.i2c_ctrl);
		ret = EIO;
	}

done:
	i2c_bus_unlock(txn);
	mutex_exit(&ee100x_spa_mutex);

	return (ret);
}

static const eedev_ops_t ee100x_eedev_ops = {
	.eo_read = ee100x_read
};

static bool
ee100x_eedev_init(ee100x_t *ee)
{
	int ret;
	eedev_reg_t reg;

	bzero(&reg, sizeof (reg));
	reg.ereg_vers = EEDEV_REG_VERS;
	reg.ereg_size = EE1004_LEN;
	reg.ereg_seg = EE1004_SEG;
	reg.ereg_read_gran = 1;
	reg.ereg_ro = true;
	reg.ereg_dip = ee->ee_dip;
	reg.ereg_driver = ee;
	reg.ereg_name = NULL;
	reg.ereg_ops = &ee100x_eedev_ops;
	reg.ereg_max_read = MIN(i2c_reg_max_read(ee->ee_mem_hdl),
	    I2C_REQ_MAX / 2);

	if ((ret = eedev_create(&reg, &ee->ee_devhdl)) != 0) {
		dev_err(ee->ee_dip, CE_WARN, "failed to create eedev device: "
		    "%d", ret);
		return (false);
	}

	return (true);
}

static void
ee100x_cleanup(ee100x_t *ee)
{
	eedev_fini(ee->ee_devhdl);
	i2c_client_destroy(ee->ee_spa1);
	i2c_client_destroy(ee->ee_spa0);
	i2c_reg_handle_destroy(ee->ee_mem_hdl);
	i2c_client_destroy(ee->ee_mem);
	ddi_soft_state_free(ee100x_state, ddi_get_instance(ee->ee_dip));
}

static int
ee100x_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	i2c_errno_t ret;
	i2c_addr_t addr;
	i2c_reg_acc_attr_t attr;
	ee100x_t *ee;

	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(ee100x_state, ddi_get_instance(dip)) !=
	    DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to alocate soft state");
		return (DDI_FAILURE);
	}

	ee = ddi_get_soft_state(ee100x_state, ddi_get_instance(dip));
	if (ee == NULL) {
		dev_err(dip, CE_WARN, "failed to obtain soft state after "
		    "alloc");
		return (DDI_FAILURE);
	}
	ee->ee_dip = dip;

	if ((ret = i2c_client_init(ee->ee_dip, 0, &ee->ee_mem)) !=
	    I2C_CORE_E_OK) {
		dev_err(dip, CE_WARN, "failed to initialize memory i2c "
		    "client: 0x%x", ret);
		goto err;
	}

	bzero(&attr, sizeof (attr));
	attr.i2cacc_version = I2C_REG_ACC_ATTR_V0;
	attr.i2cacc_addr_len = 1;
	attr.i2cacc_reg_len = 1;
	attr.i2cacc_addr_max = UINT8_MAX;

	if ((ret = i2c_reg_handle_init(ee->ee_mem, &attr, &ee->ee_mem_hdl)) !=
	    I2C_CORE_E_OK) {
		dev_err(dip, CE_WARN, "failed to initialize client handle: "
		    "0x%x", ret);
		goto err;
	}

	addr.ia_type = I2C_ADDR_7BIT;
	addr.ia_addr = EE1004_SET_PAGE0_ADDR;
	if ((ret = i2c_client_claim_addr(ee->ee_dip, &addr, I2C_CLAIM_F_SHARED,
	    &ee->ee_spa0)) != I2C_CORE_E_OK) {
		dev_err(dip, CE_WARN, "failed to claim address 0x%x: 0x%x",
		    addr.ia_addr, ret);
		goto err;
	}

	addr.ia_type = I2C_ADDR_7BIT;
	addr.ia_addr = EE1004_SET_PAGE1_ADDR;
	if ((ret = i2c_client_claim_addr(ee->ee_dip, &addr, I2C_CLAIM_F_SHARED,
	    &ee->ee_spa1)) != I2C_CORE_E_OK) {
		dev_err(dip, CE_WARN, "failed to claim address 0x%x: 0x%x",
		    addr.ia_addr, ret);
		goto err;
	}

	if (!ee100x_eedev_init(ee))
		goto err;

	return (DDI_SUCCESS);

err:
	ee100x_cleanup(ee);
	return (DDI_FAILURE);
}

static int
ee100x_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **outp)
{
	ee100x_t *ee;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		ee = ddi_get_soft_state(ee100x_state, getminor((dev_t)arg));
		if (ee == NULL) {
			return (DDI_FAILURE);
		}
		*outp = ee->ee_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		ee = ddi_get_soft_state(ee100x_state, getminor((dev_t)arg));
		if (ee == NULL) {
			return (DDI_FAILURE);
		}

		*outp = (void *)(uintptr_t)ddi_get_instance(ee->ee_dip);
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
ee100x_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ee100x_t *ee;

	if (cmd == DDI_SUSPEND) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	ee = ddi_get_soft_state(ee100x_state, ddi_get_instance(dip));
	if (ee == NULL) {
		dev_err(dip, CE_WARN, "cannot detach: failed to obtain soft "
		    "state");
		return (DDI_FAILURE);
	}

	ee100x_cleanup(ee);
	return (DDI_SUCCESS);
}

static struct dev_ops ee100x_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = ee100x_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = ee100x_attach,
	.devo_detach = ee100x_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed
};

static struct modldrv ee100x_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "EE1004 Driver",
	.drv_dev_ops = &ee100x_dev_ops
};

static struct modlinkage ee100x_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &ee100x_modldrv, NULL }
};

static void
ee100x_globals_fini(void)
{
	ddi_soft_state_fini(&ee100x_state);
	mutex_destroy(&ee100x_spa_mutex);
}

static int
ee100x_globals_init(void)
{
	int ret;

	if ((ret = ddi_soft_state_init(&ee100x_state, sizeof (ee100x_t), 0)) !=
	    0) {
		return (ret);
	}
	mutex_init(&ee100x_spa_mutex, NULL, MUTEX_DRIVER, NULL);

	return (0);
}

int
_init(void)
{
	int ret;

	if ((ret = ee100x_globals_init()) != 0) {
		return (ret);
	}

	if ((ret = mod_install(&ee100x_modlinkage)) != 0) {
		ee100x_globals_fini();
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ee100x_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&ee100x_modlinkage)) == 0) {
		ee100x_globals_fini();
	}

	return (ret);
}
