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
 * Copyright 2022 Oxide Computer Company
 */

/*
 * This test focuses on trying to manipulate GPIO attributes at the kernel ioctl
 * level and verifying that the various failure modes we expect are generated.
 * We opt not to use libxpio here because libxpio purposefully does not support
 * generating various error cases.
 *
 * This test always operates against the gpio_sim2 controller.
 */

#include <err.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <libnvpair.h>
#include <stdbool.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <errno.h>
#include <sys/debug.h>

#include <sys/gpio/kgpio.h>
#include <sys/gpio/gpio_sim.h>

/*
 * For now we hardcode the path to our controller rather than discovering it
 * through libdevinfo or libxpio.
 */
static const char *gpio_ctrl_path = "/devices/pseudo/kgpio@0:gpio_sim2";
static int gpio_attr_fail = EXIT_SUCCESS;

typedef struct {
	/*
	 * Should the update succeed or fail.
	 */
	bool gat_pass;
	/*
	 * Description of the test case for humans.
	 */
	const char *gat_desc;
	/*
	 * GPIO to actually perform the update on.
	 */
	uint32_t gat_pin;
	/*
	 * Function to create the update nvlist.
	 */
	nvlist_t *(*gat_create)(void);
	/*
	 * Function to check the error nvlist. Not required if gat_pass is true.
	 */
	bool	(*gat_check)(nvlist_t *);
} gpio_attr_test_t;

static uint32_t
gpio_nvpair_count(nvlist_t *nvl)
{
	uint32_t ret = 0;

	for (nvpair_t *head = nvlist_next_nvpair(nvl, NULL); head != NULL;
	    head = nvlist_next_nvpair(nvl, head)) {
		ret++;
	}

	return (ret);
}

static bool
gpio_err_key(nvlist_t *nvl, const char *key, kgpio_attr_err_t err)
{
	int ret;
	uint32_t val;

	if ((ret = nvlist_lookup_uint32(nvl, key, &val)) != 0) {
		warnx("failed to lookup %s: %s", key, strerror(ret));
		return (false);
	}

	if (val != err) {
		warnx("error for %s is wrong: found 0x%x, expected 0x%x",
		    key, val, err);
		return (false);
	}

	return (true);
}

static nvlist_t *
gpio_mkrdonly(void)
{
	nvlist_t *nvl = fnvlist_alloc();

	fnvlist_add_string(nvl, KGPIO_ATTR_NAME, "foobar");
	fnvlist_add_uint32(nvl, GPIO_SIM_ATTR_INPUT, GPIO_SIM_INPUT_LOW);
	fnvlist_add_uint32(nvl, GPIO_SIM_ATTR_VOLTAGE, GPIO_SIM_VOLTAGE_54P5);
	return (nvl);
}

static bool
gpio_chkrdonly(nvlist_t *nvl)
{
	uint32_t count;
	bool ret = true;

	count = gpio_nvpair_count(nvl);
	if (count != 3) {
		warnx("encountered incorrect number of keys: %u, expected %u",
		    count, 3);
		ret = false;
	}

	if (!gpio_err_key(nvl, KGPIO_ATTR_NAME, KGPIO_ATTR_ERR_ATTR_RO) ||
	    !gpio_err_key(nvl, GPIO_SIM_ATTR_INPUT, KGPIO_ATTR_ERR_ATTR_RO) ||
	    !gpio_err_key(nvl, GPIO_SIM_ATTR_VOLTAGE, KGPIO_ATTR_ERR_ATTR_RO)) {
		ret = false;
	}

	return (ret);
}

static nvlist_t *
gpio_mkunknown(void)
{
	nvlist_t *nvl = fnvlist_alloc();

	fnvlist_add_uint32(nvl, "calvinball", 0x23);
	return (nvl);
}

static nvlist_t *
gpio_mkunknown_valid(void)
{
	nvlist_t *nvl = fnvlist_alloc();

	fnvlist_add_uint32(nvl, "calvinball", 0x23);
	fnvlist_add_uint32(nvl, GPIO_SIM_ATTR_SPEED, GPIO_SIM_SPEED_MEDIUM);
	return (nvl);
}

static bool
gpio_chkunknown(nvlist_t *nvl)
{
	uint32_t count;
	bool ret = true;

	count = gpio_nvpair_count(nvl);
	if (count != 1) {
		warnx("encountered incorrect number of keys: %u, expected %u",
		    count, 1);
		ret = false;
	}

	if (!gpio_err_key(nvl, "calvinball", KGPIO_ATTR_ERR_UNKNOWN_ATTR)) {
		ret = false;
	}

	return (ret);
}

static nvlist_t *
gpio_mkbadtype_string(void)
{
	nvlist_t *nvl = fnvlist_alloc();

	fnvlist_add_string(nvl, GPIO_SIM_ATTR_PULL, "link!");
	fnvlist_add_string(nvl, GPIO_SIM_ATTR_OUTPUT, "zelda!");
	return (nvl);
}

static nvlist_t *
gpio_mkbadtype_nvl(void)
{
	nvlist_t *nvl = fnvlist_alloc();
	nvlist_t *nested = fnvlist_alloc();

	fnvlist_add_uint32(nested, GPIO_SIM_ATTR_PULL, 1);
	fnvlist_add_uint32(nested, GPIO_SIM_ATTR_OUTPUT, 2);
	fnvlist_add_nvlist(nvl, GPIO_SIM_ATTR_PULL, nested);
	fnvlist_add_nvlist(nvl, GPIO_SIM_ATTR_OUTPUT, nested);
	nvlist_free(nested);

	return (nvl);
}

static nvlist_t *
gpio_mkbadtype_array(void)
{
	uint32_t vals[] = { 0x23, 0x42, 0x169 };
	nvlist_t *nvl = fnvlist_alloc();

	fnvlist_add_uint32_array(nvl, GPIO_SIM_ATTR_PULL, vals,
	    ARRAY_SIZE(vals));
	fnvlist_add_uint32_array(nvl, GPIO_SIM_ATTR_OUTPUT, vals,
	    ARRAY_SIZE(vals));
	return (nvl);
}

static nvlist_t *
gpio_mkbadtype_s8(void)
{
	nvlist_t *nvl = fnvlist_alloc();

	fnvlist_add_int8(nvl, GPIO_SIM_ATTR_PULL, 2);
	fnvlist_add_int8(nvl, GPIO_SIM_ATTR_OUTPUT, 1);
	return (nvl);
}

static bool
gpio_chkbadattr(nvlist_t *nvl)
{
	uint32_t count;
	bool ret = true;

	count = gpio_nvpair_count(nvl);
	if (count != 2) {
		warnx("encountered incorrect number of keys: %u, expected %u",
		    count, 2);
		ret = false;
	}

	if (!gpio_err_key(nvl, GPIO_SIM_ATTR_PULL, KGPIO_ATTR_ERR_BAD_TYPE) ||
	    !gpio_err_key(nvl, GPIO_SIM_ATTR_OUTPUT, KGPIO_ATTR_ERR_BAD_TYPE)) {
		ret = false;
	}

	return (ret);
}

static nvlist_t *
gpio_mkbadval(void)
{
	nvlist_t *nvl = fnvlist_alloc();

	fnvlist_add_uint32(nvl, GPIO_SIM_ATTR_OUTPUT, 0x42);
	fnvlist_add_uint32(nvl, GPIO_SIM_ATTR_PULL, UINT32_MAX);
	fnvlist_add_uint32(nvl, GPIO_SIM_ATTR_SPEED,
	    GPIO_SIM_SPEED_VERY_HIGH * 10);
	return (nvl);
}

static bool
gpio_chkbadval(nvlist_t *nvl)
{
	uint32_t count;
	bool ret = true;

	count = gpio_nvpair_count(nvl);
	if (count != 3) {
		warnx("encountered incorrect number of keys: %u, expected %u",
		    count, 3);
		ret = false;
	}

	if (!gpio_err_key(nvl, GPIO_SIM_ATTR_PULL,
	    KGPIO_ATTR_ERR_UNKNOWN_VAL) ||
	    !gpio_err_key(nvl, GPIO_SIM_ATTR_OUTPUT,
	    KGPIO_ATTR_ERR_UNKNOWN_VAL) ||
	    !gpio_err_key(nvl, GPIO_SIM_ATTR_SPEED,
	    KGPIO_ATTR_ERR_UNKNOWN_VAL)) {
		ret = false;
	}

	return (ret);
}

static nvlist_t *
gpio_mkcantapply(void)
{
	nvlist_t *nvl = fnvlist_alloc();

	fnvlist_add_uint32(nvl, GPIO_SIM_ATTR_OUTPUT, GPIO_SIM_OUTPUT_HIGH);
	fnvlist_add_uint32(nvl, GPIO_SIM_ATTR_PULL, GPIO_SIM_PULL_UP_5K);
	return (nvl);
}

static bool
gpio_chkcantapply(nvlist_t *nvl)
{
	uint32_t count;
	bool ret = true;

	count = gpio_nvpair_count(nvl);
	if (count != 2) {
		warnx("encountered incorrect number of keys: %u, expected %u",
		    count, 2);
		ret = false;
	}

	if (!gpio_err_key(nvl, GPIO_SIM_ATTR_PULL,
	    KGPIO_ATTR_ERR_CANT_APPLY_VAL) ||
	    !gpio_err_key(nvl, GPIO_SIM_ATTR_OUTPUT,
	    KGPIO_ATTR_ERR_CANT_APPLY_VAL)) {
		ret = false;
	}

	return (ret);
}

static nvlist_t *
gpio_mkmulti(void)
{
	nvlist_t *nvl = fnvlist_alloc();

	fnvlist_add_uint32(nvl, GPIO_SIM_ATTR_OUTPUT, GPIO_SIM_OUTPUT_HIGH);
	fnvlist_add_uint32(nvl, GPIO_SIM_ATTR_VOLTAGE, GPIO_SIM_VOLTAGE_54P5);
	fnvlist_add_uint32(nvl, "triforce", 0x23);
	fnvlist_add_string(nvl, GPIO_SIM_ATTR_PULL, "magecite");
	fnvlist_add_uint32(nvl, GPIO_SIM_ATTR_SPEED, 0xbadcafe);

	return (nvl);
}

static bool
gpio_chkmulti(nvlist_t *nvl)
{
	uint32_t count;
	bool ret = true;

	count = gpio_nvpair_count(nvl);
	if (count != 5) {
		warnx("encountered incorrect number of keys: %u, expected %u",
		    count, 5);
		ret = false;
	}

	if (!gpio_err_key(nvl, GPIO_SIM_ATTR_VOLTAGE, KGPIO_ATTR_ERR_ATTR_RO) ||
	    !gpio_err_key(nvl, GPIO_SIM_ATTR_OUTPUT,
	    KGPIO_ATTR_ERR_CANT_APPLY_VAL) ||
	    !gpio_err_key(nvl, "triforce", KGPIO_ATTR_ERR_UNKNOWN_ATTR) ||
	    !gpio_err_key(nvl, GPIO_SIM_ATTR_PULL, KGPIO_ATTR_ERR_BAD_TYPE) ||
	    !gpio_err_key(nvl, GPIO_SIM_ATTR_SPEED,
	    KGPIO_ATTR_ERR_UNKNOWN_VAL)) {
		ret = false;
	}

	return (ret);
}

static const gpio_attr_test_t gpio_attr_tests[] = {
	{ false, "update read-only value fails", 2, gpio_mkrdonly,
	    gpio_chkrdonly },
	{ false, "unknown attribute fails", 2, gpio_mkunknown,
	    gpio_chkunknown },
	{ false, "unknown/valid attribute fails", 2, gpio_mkunknown_valid,
	    gpio_chkunknown },
	{ false, "bad attribute type 0 (string)", 0, gpio_mkbadtype_string,
	    gpio_chkbadattr },
	{ false, "bad attribute type 1 (nvlist)", 0, gpio_mkbadtype_nvl,
	    gpio_chkbadattr },
	{ false, "bad attribute type 2 (uint32 array)", 0, gpio_mkbadtype_array,
	    gpio_chkbadattr },
	{ false, "bad attribute type 3 (int8)", 0, gpio_mkbadtype_s8,
	    gpio_chkbadattr },
	{ false, "bad values", 1, gpio_mkbadval, gpio_chkbadval },
	{ false, "can't apply value", 5, gpio_mkcantapply, gpio_chkcantapply },
	{ false, "disjoint errors", 5, gpio_mkmulti, gpio_chkmulti },
};

static void
gpio_attr_run_one(int ctrl_fd, const gpio_attr_test_t *test)
{
	int ret;
	char err_buf[16 * 1024];
	char *buf = NULL;
	size_t buflen = 0;
	kgpio_update_t update;
	nvlist_t *nvl;

	nvl = test->gat_create();
	if (nvl == NULL) {
		gpio_attr_fail = EXIT_FAILURE;
		(void) fprintf(stderr, "TEST FAILED: %s: failed to make "
		    "nvlist\n", test->gat_desc);
		return;
	}

	ret = nvlist_pack(nvl, &buf, &buflen, NV_ENCODE_NATIVE, 0);
	if (ret != 0) {
		gpio_attr_fail = EXIT_FAILURE;
		(void) fprintf(stderr, "TEST FAILED: %s: failed to pack "
		    "nvlist: %s\n", test->gat_desc, strerror(ret));
		nvlist_free(nvl);
		return;
	}

	nvlist_free(nvl);

	(void) memset(&update, 0, sizeof (update));
	update.kgu_id = test->gat_pin;
	update.kgu_attr = (uintptr_t)buf;
	update.kgu_attr_len = buflen;
	update.kgu_err = (uintptr_t)err_buf;
	update.kgu_err_len = sizeof (err_buf);

	if (ioctl(ctrl_fd, KGPIO_IOC_GPIO_UPDATE, &update) != 0) {
		gpio_attr_fail = EXIT_FAILURE;
		(void) fprintf(stderr, "TEST FAILED: %s: update ioctl had a "
		    "hard failure: %s\n", test->gat_desc, strerror(errno));
		free(buf);
		return;
	}

	free(buf);
	bool pass = (update.kgu_flags & KGPIO_UPDATE_ERROR) == 0;

	if (test->gat_pass && pass) {
		(void) printf("TEST PASSED: %s\n", test->gat_desc);
	} else if (test->gat_pass && !pass) {
		gpio_attr_fail = EXIT_FAILURE;
		(void) fprintf(stderr, "TEST FAILED: %s: expected update to "
		    "succeed, but failed\n", test->gat_desc);
	} else if (pass) {
		gpio_attr_fail = EXIT_FAILURE;
		(void) fprintf(stderr, "TEST FAILED: %s: expected update to "
		    "fail, but succeeded\n", test->gat_desc);
	} else {
		nvlist_t *err_nvl;

		if ((update.kgu_flags & KGPIO_UPDATE_ERR_NVL_VALID) == 0) {
			gpio_attr_fail = EXIT_FAILURE;
			(void) fprintf(stderr, "TEST FAILED: %s: kernel failed "
			    "to give us valid error data\n");
			return;
		}

		ret = nvlist_unpack(err_buf, update.kgu_err_len, &err_nvl, 0);
		if (ret != 0) {
			gpio_attr_fail = EXIT_FAILURE;
			(void) fprintf(stderr, "TEST FAILED: %s: failed to "
			    "unpack error nvlist: %s\n", test->gat_desc,
			    strerror(ret));
			return;
		}

		if (!test->gat_check(err_nvl)) {
			gpio_attr_fail = EXIT_FAILURE;
			(void) fprintf(stderr, "TEST FAILED: %s: error nvlist "
			    "incorrect\n", test->gat_desc);
		} else {
			(void) printf("TEST PASSED: %s\n", test->gat_desc);
		}

		nvlist_free(err_nvl);
	}
}

int
main(void)
{
	int ctrl_fd;

	ctrl_fd = open(gpio_ctrl_path, O_RDWR);
	if (ctrl_fd < 0) {
		err(EXIT_FAILURE, "failed to open controller %s",
		    gpio_ctrl_path);
	}

	for (uint32_t i = 0; i < ARRAY_SIZE(gpio_attr_tests); i++) {
		gpio_attr_run_one(ctrl_fd, &gpio_attr_tests[i]);
	}

	(void) close(ctrl_fd);

	if (gpio_attr_fail == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully!\n");
	}
	return (gpio_attr_fail);
}
