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
 * Test various aspects of creating and removing devices. This operates on the
 * smbussim1/0 port where there are no devices by default. In particular we
 * want to verify a few different properties:
 *
 *  - Invalid nvlists and missing nvlist fields are caught
 *  - The device name and compatible array are correctly populated
 *  - Address allocation across ports is sensible, meaning that something on the
 *    top-level port stops allocations on downstream ports and vice-versa
 *
 * Unlike the i2cadm tests, we care about the specific kernel ioctl return
 * values.
 */

#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <sys/debug.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/nvpair.h>
#include <sys/sysmacros.h>
#include <libdevinfo.h>

#include <sys/i2c/ioctl.h>
#include "i2c_ioctl_util.h"

static const char *bad_names[] = {
	"",
	"thisisalongstringthatshouldbetoolongbuthasvalidchars",
	"0nonum",
	"42",
	"help#",
	"!at24c32",
	"at24%c32",
	"at@24xc32",
	"three rings",
	"elven(kings)",
	"ゼルダの伝説"
};

static bool
test_add(int fd, const void *arg, size_t len, i2c_errno_t err, const char *desc)
{
	bool ret = true;
	ui2c_dev_add_t add = {
		.uda_error = {
			/*
			 * We use token values here to make sure that they're
			 * always set by the target.
			 */
			INT32_MIN,
			INT32_MIN
		},
		.uda_nvl = (uintptr_t)arg,
		.uda_nvl_len = len
	};

	if (ioctl(fd, UI2C_IOCTL_DEVICE_ADD, &add) != 0) {
		warnx("TEST FAILED: %s: add ioctl failed unexpectedly with "
		    "errno %s", desc, strerrorname_np(errno));
		return (false);
	}

	if (add.uda_error.i2c_error != err) {
		warnx("TEST FAILED: %s: ioctl failed with I2C error 0x%x, "
		    "expected 0x%x", desc, add.uda_error.i2c_error, err);
		ret = false;
	}

	if (add.uda_error.i2c_ctrl != I2C_CTRL_E_OK) {
		warnx("TEST FAILED: %s: ioctl has unexpected controller "
		    "error 0x%x", desc, add.uda_error.i2c_ctrl);
		ret = false;
	}

	if (ret) {
		if (err == I2C_CORE_E_OK) {
			(void) printf("TEST PASSED: %s correctly created "
			    "device\n", desc);
		} else {
			(void) printf("TEST PASSED: %s correctly failed with "
			    "0x%x\n", desc, err);
		}
	}

	return (ret);
}

static bool
test_add_nvlist(int fd, nvlist_t *nvl, i2c_errno_t err, const char *desc)
{
	size_t len;
	char *data = fnvlist_pack(nvl, &len);
	bool ret = test_add(fd, data, len, err, desc);
	fnvlist_pack_free(data, len);
	return (ret);
}

static bool
test_bad_nvlists(int fd)
{
	bool ret = true;
	const char *str = "I promise I'm an nvlist_t";

	if (!test_add(fd, NULL, 4 * 1024 * 1024, I2C_IOCTL_E_NVL_TOO_BIG,
	    "nvlist_t too large to copy in")) {
		ret = false;
	}

	size_t pgsz = (size_t)sysconf(_SC_PAGESIZE);
	void *addr = mmap(NULL, pgsz, PROT_NONE, MAP_PRIVATE | MAP_ANON,
	    -1, 0);
	VERIFY3P(addr, !=, NULL);
	if (!test_add(fd, addr, pgsz, I2C_IOCTL_E_BAD_USER_DATA, "unreadable "
	    "user data")) {
		ret = false;
	}
	VERIFY0(munmap(addr, pgsz));

	if (!test_add(fd, str, strlen(str) + 1, I2C_IOCTL_E_NVL_INVALID,
	    "unparseable nvlist_t")) {
		ret = false;
	}

	/*
	 * Go through and test all of the missing keys cases.
	 */
	nvlist_t *nvl = fnvlist_alloc();
	if (!test_add_nvlist(fd, nvl, I2C_IOCTL_E_NVL_KEY_MISSING, "missing "
	    "keys (all)")) {
		ret = false;
	}

	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_ADDR, 0x00);
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_TYPE, I2C_ADDR_7BIT);
	if (!test_add_nvlist(fd, nvl, I2C_IOCTL_E_NVL_KEY_MISSING, "missing "
	    "keys (name)")) {
		ret = false;
	}
	nvlist_free(nvl);

	nvl = fnvlist_alloc();
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_ADDR, 0x00);
	fnvlist_add_string(nvl, UI2C_IOCTL_NVL_NAME, "foobar");
	if (!test_add_nvlist(fd, nvl, I2C_IOCTL_E_NVL_KEY_MISSING, "missing "
	    "keys (type)")) {
		ret = false;
	}
	nvlist_free(nvl);

	nvl = fnvlist_alloc();
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_TYPE, I2C_ADDR_7BIT);
	fnvlist_add_string(nvl, UI2C_IOCTL_NVL_NAME, "foobar");
	if (!test_add_nvlist(fd, nvl, I2C_IOCTL_E_NVL_KEY_MISSING, "missing "
	    "keys (type)")) {
		ret = false;
	}
	nvlist_free(nvl);

	nvl = fnvlist_alloc();
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_ADDR, 0x00);
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_TYPE, I2C_ADDR_7BIT);
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_NAME, 0x42);
	if (!test_add_nvlist(fd, nvl, I2C_IOCTL_E_NVL_KEY_BAD_TYPE, "bad key "
	    "type (name)")) {
		ret = false;
	}
	nvlist_free(nvl);

	nvl = fnvlist_alloc();
	fnvlist_add_uint32(nvl, UI2C_IOCTL_NVL_ADDR, 0x00);
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_TYPE, I2C_ADDR_7BIT);
	fnvlist_add_string(nvl, UI2C_IOCTL_NVL_NAME, "foobar");
	if (!test_add_nvlist(fd, nvl, I2C_IOCTL_E_NVL_KEY_BAD_TYPE, "bad key "
	    "type (addr)")) {
		ret = false;
	}
	nvlist_free(nvl);

	nvl = fnvlist_alloc();
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_ADDR, 0x00);
	fnvlist_add_int64(nvl, UI2C_IOCTL_NVL_TYPE, I2C_ADDR_7BIT);
	fnvlist_add_string(nvl, UI2C_IOCTL_NVL_NAME, "foobar");
	if (!test_add_nvlist(fd, nvl, I2C_IOCTL_E_NVL_KEY_BAD_TYPE, "bad key "
	    "type (type)")) {
		ret = false;
	}
	nvlist_free(nvl);

	nvl = fnvlist_alloc();
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_ADDR, 0x00);
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_TYPE, I2C_ADDR_7BIT);
	fnvlist_add_string(nvl, UI2C_IOCTL_NVL_NAME, "foobar");
	fnvlist_add_byte_array(nvl, UI2C_IOCTL_NVL_COMPAT, (uchar_t *)str,
	    strlen(str));
	if (!test_add_nvlist(fd, nvl, I2C_IOCTL_E_NVL_KEY_BAD_TYPE, "bad key "
	    "type (compat)")) {
		ret = false;
	}
	nvlist_free(nvl);

	for (size_t i = 0; i < nbad_addrs; i++) {
		char desc[128];

		(void) snprintf(desc, sizeof (desc), "bad address %zu "
		    "(0x%x,0x%x)", i, bad_addrs[i].ba_type,
		    bad_addrs[i].ba_addr);
		nvl = fnvlist_alloc();
		fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_TYPE,
		    bad_addrs[i].ba_type);
		fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_ADDR,
		    bad_addrs[i].ba_addr);
		fnvlist_add_string(nvl, UI2C_IOCTL_NVL_NAME, "foobar");
		if (!test_add_nvlist(fd, nvl, bad_addrs[i].ba_error, desc)) {
			ret = false;
		}
		fnvlist_free(nvl);
	}

	for (size_t i = 0; i < ARRAY_SIZE(bad_names); i++) {
		char desc[128];

		(void) snprintf(desc, sizeof (desc), "bad names %zu", i);
		nvl = fnvlist_alloc();
		fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_TYPE, I2C_ADDR_7BIT);
		fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_ADDR, 0x42);
		fnvlist_add_string(nvl, UI2C_IOCTL_NVL_NAME, bad_names[i]);
		if (!test_add_nvlist(fd, nvl, I2C_IOCTL_E_BAD_DEV_NAME, desc)) {
			ret = false;
		}
		fnvlist_free(nvl);
	}

	for (size_t i = 0; i < ARRAY_SIZE(bad_names); i++) {
		char desc[128];

		(void) snprintf(desc, sizeof (desc), "bad compat %zu", i);
		nvl = fnvlist_alloc();
		fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_TYPE, I2C_ADDR_7BIT);
		fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_ADDR, 0x42);
		fnvlist_add_string(nvl, UI2C_IOCTL_NVL_NAME, "foobar");
		fnvlist_add_string_array(nvl, UI2C_IOCTL_NVL_COMPAT,
		    (char * const *)&bad_names[i], 1);
		if (!test_add_nvlist(fd, nvl, I2C_IOCTL_E_BAD_DEV_NAME, desc)) {
			ret = false;
		}
		fnvlist_free(nvl);
	}

	char *compat[42];
	for (size_t i = 0; i < ARRAY_SIZE(compat); i++) {
		compat[i] = "at24c32";
	}

	nvl = fnvlist_alloc();
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_TYPE, I2C_ADDR_7BIT);
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_ADDR, 0x42);
	fnvlist_add_string(nvl, UI2C_IOCTL_NVL_NAME, "foobar");
	fnvlist_add_string_array(nvl, UI2C_IOCTL_NVL_COMPAT, compat,
	    ARRAY_SIZE(compat));
	if (!test_add_nvlist(fd, nvl, I2C_IOCTL_E_COMPAT_LEN_RANGE,
	    "compat[] too long")) {
		ret = false;
	}
	fnvlist_free(nvl);

	nvl = fnvlist_alloc();
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_TYPE, I2C_ADDR_7BIT);
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_ADDR, 0x42);
	fnvlist_add_string(nvl, UI2C_IOCTL_NVL_NAME, "foobar");
	fnvlist_add_string(nvl, "magicite", "materia");

	if (!test_add_nvlist(fd, nvl, I2C_IOCTL_E_NVL_KEY_UNKNOWN,
	    "extra keys")) {
		ret = false;
	}
	fnvlist_free(nvl);

	return (ret);
}

static bool
test_add_device(int fd, const char *name, uint8_t addr, i2c_errno_t err,
    const char *desc)
{
	nvlist_t *nvl = fnvlist_alloc();
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_TYPE, I2C_ADDR_7BIT);
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_ADDR, addr);
	fnvlist_add_string(nvl, UI2C_IOCTL_NVL_NAME, name);
	bool ret = test_add_nvlist(fd, nvl, err, desc);
	fnvlist_free(nvl);
	return (ret);
}

static bool
test_address_conflicts(int fd)
{
	bool ret = true;

	if (!test_add_device(fd, "pca9548", 0x70, I2C_CORE_E_OK, "create "
	    "pca9548")) {
		ret = false;
	}

	if (!test_add_device(fd, "fake-device", 0x70, I2C_CORE_E_ADDR_IN_USE,
	    "address in use fails (0x70)")) {
		ret = false;
	}

	int pfd0 = i2c_ioctl_test_get_fd(I2C_D_PORT, "smbussim1/0/0x70/mux/0",
	    O_RDWR);
	int pfd4 = i2c_ioctl_test_get_fd(I2C_D_PORT, "smbussim1/0/0x70/mux/4",
	    O_RDWR);

	/*
	 * Verify that an address used downstream on the mux cannot be used
	 * upstream of it.
	 */
	if (!test_add_device(pfd0, "fake-device", 0x42, I2C_CORE_E_OK, "create "
	    "fake device (ox42) on mux port 0")) {
		ret = false;
	}

	if (!test_add_device(pfd4, "fake-device", 0x42, I2C_CORE_E_OK, "create "
	    "fake device (ox42) on mux port 4")) {
		ret = false;
	}

	if (!test_add_device(fd, "fake-device", 0x42, I2C_CORE_E_ADDR_IN_USE,
	    "cannot create device on upstream port used on downstream ports")) {
		ret = false;
	}

	/*
	 * Verify that an address used on the top-level port cannot be used
	 * downstream of it.
	 */
	if (test_add_device(fd, "fake-device", 0x23, I2C_CORE_E_OK, "create "
	    "fake device (0x23)")) {
		if (!test_add_device(pfd0, "fake-device", 0x23,
		    I2C_CORE_E_ADDR_IN_USE, "cannot allocate address on "
		    "downstream port when used upstream (1)")) {
			ret = false;
		}

		if (!test_add_device(pfd4, "fake-device", 0x23,
		    I2C_CORE_E_ADDR_IN_USE, "cannot allocate address on "
		    "downstream port when used upstream (2)")) {
			ret = false;
		}
	} else {
		ret = false;
	}

	VERIFY0(close(pfd4));
	VERIFY0(close(pfd0));
	return (ret);
}

typedef struct {
	bool tcc_ret;
	bool tcc_compat0;
	bool tcc_compat1;
	char **tcc_compat;
} test_compat_cb_t;

static int
test_compat_walk_cb(di_node_t di, void *arg)
{
	test_compat_cb_t *cb = arg;
	const char *name = di_node_name(di);
	int exp;

	if (strcmp(name, "fake-compat-0") == 0) {
		cb->tcc_compat0 = true;
		exp = 1;
	} else if (strcmp(name, "fake-compat-1") == 0) {
		cb->tcc_compat1 = true;
		exp = 32;
	} else {
		return (DI_WALK_CONTINUE);
	}

	char *compat;
	int nents = di_prop_lookup_strings(DDI_DEV_T_ANY, di, "compatible",
	    &compat);
	if (nents == exp) {
		bool valid = true;
		for (int i = 0; i < exp; i++) {
			if (strcmp(compat, cb->tcc_compat[i]) != 0) {
				valid = false;
				warnx("TEST FAILED: %s has incorrect "
				    "compatible[%d] entry: expected %s, found "
				    "%s", name, i, compat, cb->tcc_compat[i]);
			}

			compat += strlen(compat) + 1;
		}

		if (valid) {
			(void) printf("TEST PASSED: devi %s has correct "
			    "comaptible[%d]\n", name, nents);
		}
	} else {
		warnx("TEST FAILED: node %s has wrong compatible[] count: "
		    "found %d, expected %d", name, nents, exp);
		cb->tcc_ret = false;
	}

	return (DI_WALK_PRUNECHILD);
}

static bool
test_compat(int fd)
{
	bool ret = true;
	char *compat[32];

	for (size_t i = 0; i < ARRAY_SIZE(compat); i++) {
		if (asprintf(&compat[i], "bad,compat%zu", i) < 0) {
			err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to "
			    "construct compat entry %zu", i);
		}
	}

	nvlist_t *nvl = fnvlist_alloc();
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_TYPE, I2C_ADDR_7BIT);
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_ADDR, 0x30);
	fnvlist_add_string(nvl, UI2C_IOCTL_NVL_NAME, "fake-compat-0");
	fnvlist_add_string_array(nvl, UI2C_IOCTL_NVL_COMPAT, compat,
	    1);
	if (!test_add_nvlist(fd, nvl, I2C_CORE_E_OK, "1-entry compat[]")) {
		ret = false;
	}
	fnvlist_free(nvl);

	nvl = fnvlist_alloc();
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_TYPE, I2C_ADDR_7BIT);
	fnvlist_add_uint16(nvl, UI2C_IOCTL_NVL_ADDR, 0x31);
	fnvlist_add_string(nvl, UI2C_IOCTL_NVL_NAME, "fake-compat-1");
	fnvlist_add_string_array(nvl, UI2C_IOCTL_NVL_COMPAT, compat,
	    ARRAY_SIZE(compat));
	if (!test_add_nvlist(fd, nvl, I2C_CORE_E_OK, "32-entry compat[]")) {
		ret = false;
	}
	fnvlist_free(nvl);

	test_compat_cb_t cb = {
		.tcc_ret = true,
		.tcc_compat0 = false,
		.tcc_compat1 = false,
		.tcc_compat = compat
	};

	di_node_t root = di_init(i2c_sim_dipath, DINFOCPYALL);
	(void) di_walk_node(root, DI_WALK_CLDFIRST, &cb, test_compat_walk_cb);
	di_fini(root);

	if (!cb.tcc_ret) {
		ret = false;
	}

	if (!cb.tcc_compat0) {
		warnx("TEST FAILED: failed to find devi fake-compat-0");
		ret = false;
	}

	if (!cb.tcc_compat1) {
		warnx("TEST FAILED: failed to find devi fake-compat-1");
		ret = false;
	}

	for (size_t i = 0; i < ARRAY_SIZE(compat); i++) {
		free(compat[i]);
	}

	return (ret);
}

static bool
test_rm(int fd, uint16_t family, uint16_t addr, i2c_errno_t err,
    const char *desc)
{
	bool ret = true;
	ui2c_dev_rem_t rm = {
		.udr_error = {
			/* Token errors to ensure this is set by copyout. */
			INT32_MAX,
			INT32_MAX
		},
		.udr_addr = { family, addr }
	};

	if (ioctl(fd, UI2C_IOCTL_DEVICE_REMOVE, &rm) != 0) {
		warnx("TEST FAILED: %s: removal ioctl failed unexpectedly with "
		    "errno %s", desc, strerrorname_np(errno));
		return (false);
	}

	if (rm.udr_error.i2c_error != err) {
		warnx("TEST FAILED: %s: ioctl failed with I2C error 0x%x, "
		    "expected 0x%x", desc, rm.udr_error.i2c_error, err);
		ret = false;
	}

	if (rm.udr_error.i2c_ctrl != I2C_CTRL_E_OK) {
		warnx("TEST FAILED: %s: ioctl has unexpected controller "
		    "error 0x%x", desc, rm.udr_error.i2c_ctrl);
		ret = false;
	}

	if (ret) {
		if (err == I2C_CORE_E_OK) {
			(void) printf("TEST PASSED: %s correctly removed "
			    "device\n", desc);
		} else {
			(void) printf("TEST PASSED: %s correctly failed with "
			    "0x%x\n", desc, err);
		}
	}

	return (ret);
}

static bool
test_teardown(int fd)
{
	bool ret = true;

	for (size_t i = 0; i < nbad_addrs; i++) {
		char desc[128];

		(void) snprintf(desc, sizeof (desc), "remove bad address %zu",
		    i);
		if (!test_rm(fd, bad_addrs[i].ba_type, bad_addrs[i].ba_addr,
		    bad_addrs[i].ba_error, desc)) {
			ret = false;
		}
	}

	if (!test_rm(fd, I2C_ADDR_7BIT, 0x70, I2C_IOCTL_E_NEXUS,
	    "cannot tear down mux with devices under it")) {
		ret = false;
	}

	if (!test_rm(fd, I2C_ADDR_7BIT, 0x30, I2C_CORE_E_OK, "tear down device "
	    "unrelated to mux (0x30)")) {
		ret = false;
	}

	if (!test_rm(fd, I2C_ADDR_7BIT, 0x31, I2C_CORE_E_OK, "tear down device "
	    "unrelated to mux (0x31)")) {
		ret = false;
	}

	int pfd0 = i2c_ioctl_test_get_fd(I2C_D_PORT, "smbussim1/0/0x70/mux/0",
	    O_RDWR);
	if (!test_rm(pfd0, I2C_ADDR_7BIT, 0x42, I2C_CORE_E_OK, "tear down "
	    "device under mux (0/0x42)")) {
		ret = false;
	}

	if (!test_rm(pfd0, I2C_ADDR_7BIT, 0x42, I2C_CORE_E_UNKNOWN_ADDR,
	    "cannot remove 0/0x42 a second time on same port")) {
		ret = false;
	}
	VERIFY0(close(pfd0));

	int pfd2 = i2c_ioctl_test_get_fd(I2C_D_PORT, "smbussim1/0/0x70/mux/2",
	    O_RDWR);
	if (!test_rm(pfd2, I2C_ADDR_7BIT, 0x42, I2C_CORE_E_UNKNOWN_ADDR,
	    "cannot remove non-existent 2/0x42")) {
		ret = false;
	}
	VERIFY0(close(pfd2));

	int pdf4 = i2c_ioctl_test_get_fd(I2C_D_PORT, "smbussim1/0/0x70/mux/4",
	    O_RDWR);
	if (!test_rm(pdf4, I2C_ADDR_7BIT, 0x42, I2C_CORE_E_OK, "tear down "
	    "device under mux (4/0x42)")) {
		ret = false;
	}

	if (!test_rm(pdf4, I2C_ADDR_7BIT, 0x42, I2C_CORE_E_UNKNOWN_ADDR,
	    "cannot remove 4/0x42 a second time on same port")) {
		ret = false;
	}
	VERIFY0(close(pdf4));

	if (!test_rm(fd, I2C_ADDR_7BIT, 0x70, I2C_CORE_E_OK, "tear down empty "
	    "mux")) {
		ret = false;
	}

	if (!test_rm(fd, I2C_ADDR_7BIT, 0x23, I2C_CORE_E_OK, "tear down device "
	    "(0x23)")) {
		ret = false;
	}
	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	int fd = i2c_ioctl_test_get_fd(I2C_D_PORT, "smbussim1/0", O_RDWR);

	if (!test_bad_nvlists(fd)) {
		ret = EXIT_FAILURE;
	}

	if (!test_address_conflicts(fd)) {
		ret = EXIT_FAILURE;
	}

	if (!test_compat(fd)) {
		ret = EXIT_FAILURE;
	}

	if (!test_teardown(fd)) {
		ret = EXIT_FAILURE;
	}

	VERIFY0(close(fd));
	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}
	return (ret);
}
