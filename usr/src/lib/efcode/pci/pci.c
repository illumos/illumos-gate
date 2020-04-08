/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2000-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <fcode/private.h>
#include <fcode/log.h>

#include <fcdriver/fcdriver.h>

static fstack_t
mem_map_in(fcode_env_t *env, fstack_t hi, fstack_t mid, fstack_t lo,
    fstack_t requested_len)
{
	private_data_t	*cdp = DEVICE_PRIVATE(env);
	int error;
	fc_cell_t requested_virt, adjusted_virt;
	char *service = "map-in";
	fstack_t mcookie = 0;
	int pa_offset = 0, va_offset = 0;
	fstack_t adjusted_len = 0;

	pa_offset = lo & PAGEOFFSET;
	lo &= PAGEMASK;

	/* adjust the requested_len to a multiple of a pagesize */
	requested_len = (requested_len + pa_offset + PAGEOFFSET) & PAGEMASK;

	error = fc_run_priv(cdp->common, service, 4, 1,
	    fc_size2cell(requested_len), fc_uint32_t2cell(hi),
	    fc_uint32_t2cell(mid), fc_uint32_t2cell(lo), &requested_virt);

	if (error)
		throw_from_fclib(env, 1, "pci:%s: failed\n", service);

	/*
	 * Check the requested_virt address and ensure that
	 * it starts at a page boundary.
	 */

	va_offset = requested_virt & PAGEOFFSET;

	if (va_offset != 0) {

		/*
		 * Align the virtual address to a page boundary
		 * before mapping it to a mcookie. Recalcuate the
		 * length and round it up to the next multiple of a pagesize.
		 */

		adjusted_virt = requested_virt & PAGEMASK;
		adjusted_len = (requested_len + va_offset + PAGEOFFSET)
		    & PAGEMASK;
	}

	mcookie = mapping_to_mcookie(requested_virt, requested_len,
	    adjusted_virt, adjusted_len);

	if (mcookie == 0)
		throw_from_fclib(env, 1, "pci-mapin-> pci:%s:"
		    " mapping_to_mcookie failed\n", service);
	/*
	 * Recalculate the address of the mcookie.
	 */

	mcookie += va_offset + pa_offset;

	debug_msg(DEBUG_REG_ACCESS, "pci:map-in: %llx -> %x\n",
	    (uint64_t)requested_virt, (uint32_t)mcookie);

	return (mcookie);
}

static void
mem_map_out(fcode_env_t *env, fstack_t mcookie, fstack_t requested_len)
{
	private_data_t *cdp = DEVICE_PRIVATE(env);
	char *service = "map-out";
	fc_cell_t requested_virt;
	int error;

	if (!is_mcookie(mcookie)) {
		log_message(MSG_ERROR, "pci:%s: %x not mcookie!\n", service,
		    (uint32_t)mcookie);
		requested_virt = mcookie;
	} else {
		requested_virt = mcookie_to_rvirt(mcookie);
		requested_len = mcookie_to_rlen(mcookie);
		delete_mapping(mcookie);
		debug_msg(DEBUG_REG_ACCESS, "pci:%s: %x -> %llx\n", service,
		    (uint32_t)mcookie, (uint64_t)requested_virt);
	}

	error = fc_run_priv(cdp->common, service, 2, 0,
	    fc_size2cell(requested_len), requested_virt);

	if (error)
		log_message(MSG_ERROR, "pci:%s: failed\n", service);
}

static void
pci_config_fetch(fcode_env_t *env, char *service)
{
	uint32_t cfgadd;
	fc_cell_t value;
	private_data_t	*h = DEVICE_PRIVATE(env);
	int error;

	ASSERT(h);
	CHECK_DEPTH(env, 1, service);
	cfgadd = POP(DS);
	error = fc_run_priv(h->common, service, 1, 1, fc_uint32_t2cell(cfgadd),
	    &value);

	if (error)
		throw_from_fclib(env, 1, "pci:%s ( %x ) FAIL\n", service,
		    cfgadd);

	PUSH(DS, value);
}

static void
pci_config_store(fcode_env_t *env, char *service)
{
	uint32_t cfgadd;
	fc_cell_t value;
	private_data_t	*h = DEVICE_PRIVATE(env);
	int error;

	ASSERT(h);
	CHECK_DEPTH(env, 2, service);
	cfgadd = POP(DS);
	value = POP(DS);
	error = fc_run_priv(h->common, service, 2, 0, fc_uint32_t2cell(cfgadd),
	    fc_uint32_t2cell(value));

	if (error)
		throw_from_fclib(env, 1, "pci:%s ( %x %x ) FAIL\n", service,
		    cfgadd, value);
}

static void
config_lfetch(fcode_env_t *env)
{
	pci_config_fetch(env, "config-l@");
}

static void
config_lstore(fcode_env_t *env)
{
	pci_config_store(env, "config-l!");
}

static void
config_wfetch(fcode_env_t *env)
{
	pci_config_fetch(env, "config-w@");
}

static void
config_wstore(fcode_env_t *env)
{
	pci_config_store(env, "config-w!");
}

static void
config_bfetch(fcode_env_t *env)
{
	pci_config_fetch(env, "config-b@");
}

static void
config_bstore(fcode_env_t *env)
{
	pci_config_store(env, "config-b!");
}

static void
do_map_in(fcode_env_t *env)
{
	fstack_t phi, pmid, plo, len, addr;

	CHECK_DEPTH(env, 4, "pci:map-in");
	len = POP(DS);
	phi = POP(DS);
	pmid = POP(DS);
	plo = POP(DS);
	addr = mem_map_in(env, phi, pmid, plo, len);
	PUSH(DS, addr);
}

static void
do_map_out(fcode_env_t *env)
{
	fstack_t addr, len;

	CHECK_DEPTH(env, 2, "pci:map-out");
	len = POP(DS);
	addr = POP(DS);
	mem_map_out(env, addr, len);
}

static void
do_encode_unit(fcode_env_t *env)
{
	char enc_buf[64];
	uint32_t hi;
	int dev, fn;

	CHECK_DEPTH(env, 3, "pci:encode-unit");
	hi = POP(DS);
	(void) POP(DS);
	(void) POP(DS);

	fn  = ((hi >> 8) & 0x7);
	dev = ((hi >> 11) & 0x1f);

	if (fn) {
		sprintf(enc_buf, "%x,%x", dev, fn);
	} else {
		sprintf(enc_buf, "%x", dev);
	}
	debug_msg(DEBUG_REG_ACCESS, "pci:encode-unit ( %x ) -> %s\n",
	    hi, enc_buf);
	push_a_string(env, STRDUP(enc_buf));
}

static void
do_decode_unit(fcode_env_t *env)
{
	int lo, hi, unit;
	char *buf;

	CHECK_DEPTH(env, 2, "pci:decode-unit");
	buf = pop_a_string(env, NULL);
	if (sscanf(buf, "%x,%x", &hi, &lo) != 2) {
		throw_from_fclib(env, 1, "pci:decode-unit: '%s'", buf);
	}
	unit = ((hi & 0x1f) << 11);
	unit |= ((lo & 0x7) << 8);
	debug_msg(DEBUG_REG_ACCESS, "pci:decode-unit ( '%s' ) -> 0 0 %x\n",
	    buf, unit);
	PUSH(DS, 0);
	PUSH(DS, 0);
	PUSH(DS, unit);
}

static void
do_device_id(fcode_env_t *env)
{
	uint32_t cfgadd;
	uint16_t ven_id, dev_id;
	char buf[40];

	CHECK_DEPTH(env, 3, "pci:device-id");
	cfgadd = POP(DS);
	(void) POP(DS);
	(void) POP(DS);
	PUSH(DS, cfgadd + PCI_CONF_VENID);
	config_wfetch(env);
	ven_id = POP(DS);
	PUSH(DS, cfgadd + PCI_CONF_DEVID);
	config_wfetch(env);
	dev_id = POP(DS);
	sprintf(buf, "pci%x,%x", ven_id, dev_id);
	push_a_string(env, STRDUP(buf));
}

static void
do_class_id(fcode_env_t *env)
{
	uint32_t cfgadd;
	uint8_t basclass, subclass, progclass;
	char buf[40];

	CHECK_DEPTH(env, 3, "pci:class-id");
	cfgadd = POP(DS);
	(void) POP(DS);
	(void) POP(DS);
	PUSH(DS, cfgadd + PCI_CONF_BASCLASS);
	config_bfetch(env);
	basclass = POP(DS);
	PUSH(DS, cfgadd + PCI_CONF_SUBCLASS);
	config_bfetch(env);
	subclass = POP(DS);
	PUSH(DS, cfgadd + PCI_CONF_PROGCLASS);
	config_bfetch(env);
	progclass = POP(DS);
	sprintf(buf, "pciclass%02x%02x%02x", basclass, subclass, progclass);
	push_a_string(env, STRDUP(buf));
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	ASSERT(env->current_device);
	NOTICE;

	FORTH(0,	"config-l@",		config_lfetch);
	FORTH(0,	"config-l!",		config_lstore);
	FORTH(0,	"config-w@",		config_wfetch);
	FORTH(0,	"config-w!",		config_wstore);
	FORTH(0,	"config-b@",		config_bfetch);
	FORTH(0,	"config-b!",		config_bstore);
	FORTH(0,	"map-in",		do_map_in);
	FORTH(0,	"map-out",		do_map_out);
	FORTH(0,	"decode-unit",		do_decode_unit);
	FORTH(0,	"encode-unit",		do_encode_unit);
	FORTH(0,	"device-id",		do_device_id);
	FORTH(0,	"class-id",		do_class_id);

	install_dma_methods(env);
}
