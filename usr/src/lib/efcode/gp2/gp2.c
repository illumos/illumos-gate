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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <fcode/private.h>
#include <fcode/log.h>

#include <fcdriver/fcdriver.h>

fstack_t
mem_map_in(fcode_env_t *env, fstack_t hi, fstack_t lo, fstack_t len)
{
	private_data_t *pdp = DEVICE_PRIVATE(env);
	fc_cell_t virt;
	fstack_t mcookie = 0;
	char *service = "map-in";
	int error;
	int offset = 0;

	/*
	 * The calculation of the offset, lo and len are left here
	 * due to historical precedence.
	 */

	offset = lo & PAGEOFFSET;
	lo &= PAGEMASK;
	len = (len + offset + PAGEOFFSET) & PAGEMASK;

	error = fc_run_priv(pdp->common, service, 3, 1, fc_size2cell(len),
	    fc_uint32_t2cell(hi), fc_uint32_t2cell(lo), &virt);

	if (error)
		throw_from_fclib(env, 1, "gp2:%s: failed\n", service);

	mcookie = mapping_to_mcookie(virt, len, 0, 0);

	if (mcookie == 0)
		throw_from_fclib(env, 1, "gp2:%s: mapping_to_mcookie failed\n",
		    service);

	mcookie += offset;

	debug_msg(DEBUG_REG_ACCESS, "gp2:%s: %llx -> %x\n", service,
	    (uint64_t)virt, (uint32_t)mcookie);

	return (mcookie);
}

static void
mem_map_out(fcode_env_t *env, fstack_t mcookie, fstack_t len)
{
	private_data_t *pdp = DEVICE_PRIVATE(env);
	fc_cell_t virt;
	char *service = "map-out";
	int error;
	int offset;

	/*
	 * The calculation of the offset, lo and len are left here
	 * due to historical precedence.
	 */

	offset = mcookie & PAGEOFFSET;
	mcookie &= PAGEMASK;
	len = (len + offset + PAGEOFFSET) & PAGEMASK;

	if (!is_mcookie(mcookie)) {
		log_message(MSG_ERROR, "gp2:%s: %x not an mcookie!\n",
		    service, (int)mcookie);
		virt = mcookie;
	} else {
		virt = mcookie_to_addr(mcookie);
		debug_msg(DEBUG_REG_ACCESS, "gp2:%s: %x -> %llx\n", service,
		    (int)mcookie, (uint64_t)virt);
		delete_mapping(mcookie);
	}

	error = fc_run_priv(pdp->common, service, 2, 0, fc_size2cell(len),
	    virt);
	if (error)
		log_message(MSG_ERROR, "gp2:%s: failed\n", service);
}

static void
do_get_portid(fcode_env_t *env)
{
	fstack_t	phi, plo, portid;
	private_data_t *pdp = DEVICE_PRIVATE(env);

	CHECK_DEPTH(env, 2, "gp2:get-portid");
	phi = POP(DS);
	plo = POP(DS);

	portid = ((plo & 0xff800000) >> 23) | ((phi & 1) << 9);
	debug_msg(DEBUG_REG_ACCESS, "gp2:get-portid ( %x %x ) -> %x\n",
	    (int)phi, (int)plo, (int)portid);
	PUSH(DS, portid);
}

static void
do_map_in(fcode_env_t *env)
{
	fstack_t phi, pmid, plo, len, addr;

	CHECK_DEPTH(env, 3, "gp2:map-in");
	len = POP(DS);
	phi = POP(DS);
	plo = POP(DS);
	addr = mem_map_in(env, phi, plo, len);
	PUSH(DS, addr);
}

static void
do_map_out(fcode_env_t *env)
{
	fstack_t addr, len;

	CHECK_DEPTH(env, 2, "gp2:map-out");
	len = POP(DS);
	addr = POP(DS);
	mem_map_out(env, addr, len);
}

static void
do_encode_unit(fcode_env_t *env)
{
	char enc_buf[64];
	fstack_t hi, mid, lo;
	int id, off;

	CHECK_DEPTH(env, 2, "gp2:encode-unit");
	hi = POP(DS);
	lo = POP(DS);

	hi  = (hi & 0x00000001);	/* get high order agent id bit */
	id = (hi << 9) | (lo >> 23);	/* build extended agent id */
	off = lo & 0x7fffff;		/* build config offset */

	if (off) {
		sprintf(enc_buf, "%x,%x", id, off);
	} else {
		sprintf(enc_buf, "%x", id);
	}
	debug_msg(DEBUG_REG_ACCESS, "gp2:encode_unit ( %x %x ) -> '%s'\n",
	    (int)hi, (int)lo, enc_buf);
	push_a_string(env, STRDUP(enc_buf));
}

static void
do_decode_unit(fcode_env_t *env)
{
	uint32_t lo, hi;
	int agent, offset;
	char *buf;

	CHECK_DEPTH(env, 2, "gp2:decode-unit");
	buf = pop_a_string(env, NULL);
	if (sscanf(buf, "%x,%x", &agent, &offset) != 2) {
		if (sscanf(buf, "%x", &agent) != 1) {
			throw_from_fclib(env, 1, "gp2:decode_unit:%s", buf);
		}
		offset = 0;
	}
	lo = offset | (agent << 23);
	hi = (agent >> 9) | 0x400;
	debug_msg(DEBUG_REG_ACCESS, "gp2:decode_unit ( '%s' ) -> %x %x\n", buf,
	    hi, lo);
	PUSH(DS, lo);
	PUSH(DS, hi);
}

static void
do_claim_addr(fcode_env_t *env)
{
	fstack_t portid, bar, align, type, size_hi, size_lo;
	fc_cell_t lo, hi;
	private_data_t *pdp = DEVICE_PRIVATE(env);
	char *service = "claim-address";
	int error;

	CHECK_DEPTH(env, 6, "gp2:claim-address");
	portid = POP(DS);
	bar = POP(DS);
	align = POP(DS);
	type = POP(DS);
	size_hi = POP(DS);
	size_lo = POP(DS);

	error = fc_run_priv(pdp->common, service, 6, 2,
	    fc_int2cell(portid), fc_int2cell(bar), fc_int2cell(align),
	    fc_int2cell(type), fc_int2cell(size_hi), fc_int2cell(size_lo),
	    &lo, &hi);

	if (error)
		throw_from_fclib(env, 1, "gp2:%s: failed\n", service);

	debug_msg(DEBUG_REG_ACCESS,
	    "gp2:%s ( %x %x %x %x %x %x ) -> %x %x\n", service, (int)portid,
	    (int)bar, (int)align, (int)type, (int)size_hi, (int)size_lo,
	    (uint32_t)hi, (uint32_t)lo);

	PUSH(DS, (uint32_t)lo);
	PUSH(DS, (uint32_t)hi);
}

static void
do_master_interrupt(fcode_env_t *env)
{
	int portid;
	token_t xt;

	CHECK_DEPTH(env, 2, "gp2:master-interrput");
	portid = POP(DS);
	xt = POP(DS);
	PUSH(DS, FALSE);
	debug_msg(DEBUG_REG_ACCESS, "gp2:master-interrupt ( %x %x ) -> %x\n",
	    portid, xt, (int)FALSE);
}

static void
do_register_vectory_entry(fcode_env_t *env)
{
	int ign, ino, level;

	CHECK_DEPTH(env, 3, "gp2:register-vector-entry");
	ign = POP(DS);
	ino = POP(DS);
	level = POP(DS);
	PUSH(DS, FALSE);
	debug_msg(DEBUG_REG_ACCESS, "gp2:register-vector-entry ( %x %x %x ) ->"
	    " %x\n", ign, ino, level, (int)FALSE);
}

static void
do_get_interrupt_target(fcode_env_t *env)
{
	int mid = 0;

	PUSH(DS, mid);
	debug_msg(DEBUG_REG_ACCESS, "gp2:get-interrupt-target ( ) -> %x\n",
	    mid);
}

static void
do_device_id(fcode_env_t *env)
{
	fstack_t	phi, plo, addr;
	fc_cell_t	virtaddr;
	private_data_t *pdp = DEVICE_PRIVATE(env);
	uint64_t	wci_id_reg;
	int		rc, parid;

	CHECK_DEPTH(env, 2, "gp2:device-id");
	phi = POP(DS);
	plo = POP(DS);

	PUSH(DS, plo);
	PUSH(DS, phi);
	PUSH(DS, 0x100);

	do_map_in(env);

	addr = POP(DS);

	virtaddr = mcookie_to_addr(addr);

	/* Try to read the wci_id register */
	rc = fc_run_priv(pdp->common, "rx@", 1, 1, virtaddr + 0xe0,
	    &wci_id_reg);

	mem_map_out(env, addr, 0x100);

	/*
	 * Get the part id from the jtag ID register
	 */
	parid = ((wci_id_reg >> 12) & 0xffff);

	if (!rc && parid == 0x4478) {
		debug_msg(DEBUG_FIND_FCODE, "gp2: do_device_id: gp2-wci\n");
		push_a_string(env, "SUNW,wci");
	} else {
		debug_msg(DEBUG_FIND_FCODE, "gp2: do_device_id: gp2-pci\n");
		push_a_string(env, "gp2-pci");
	}
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	ASSERT(env->current_device);
	NOTICE;

	create_int_prop(env, "#address-cells", 2);

	FORTH(0,	"map-in",		do_map_in);
	FORTH(0,	"get-portid",		do_get_portid);
	FORTH(0,	"map-out",		do_map_out);
	FORTH(0,	"decode-unit",		do_decode_unit);
	FORTH(0,	"encode-unit",		do_encode_unit);
	FORTH(0,	"claim-address",	do_claim_addr);
	FORTH(0,	"master-interrupt",	do_master_interrupt);
	FORTH(0,	"register-vector-entry", do_register_vectory_entry);
	FORTH(0,	"get-interrupt-target",	do_get_interrupt_target);
	FORTH(0,	"device-id",		do_device_id);

	install_dma_methods(env);

}
