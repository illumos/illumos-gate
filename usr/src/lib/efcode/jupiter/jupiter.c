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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <fcode/private.h>
#include <fcode/log.h>

#include <fcdriver/fcdriver.h>

#include <sys/opl_cfg.h>

/* VA for HardWare Descriptor */
static	hwd_cmu_chan_t	hwd_va_cmu;
static	hwd_leaf_t	hwd_va_pci;

/* Macro to get I/O portid */
#define	DO_GET_IO_PORTID(env, lo, hi, portid)	\
	PUSH(DS, lo);				\
	PUSH(DS, hi);				\
	do_get_io_portid(env);			\
	portid = (uint32_t)POP(DS)

fstack_t
mem_map_in(fcode_env_t *env, fstack_t hi, fstack_t lo, fstack_t len)
{
	private_data_t	*pdp = DEVICE_PRIVATE(env);
	fc_cell_t	virt;
	fstack_t	mcookie = 0;
	char		*service = "map-in";
	int		error;
	int		offset = 0;

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
		throw_from_fclib(env, 1, "jupiter:%s: failed\n", service);

	mcookie = mapping_to_mcookie(virt, len, 0, 0);

	if (mcookie == 0)
		throw_from_fclib(env, 1,
		    "jupiter:%s: mapping_to_mcookie failed\n", service);

	mcookie += offset;

	debug_msg(DEBUG_REG_ACCESS, "jupiter:%s: %llx -> %x\n", service,
	    (long long)virt, (uint32_t)mcookie);

	return (mcookie);
}

static void
mem_map_out(fcode_env_t *env, fstack_t mcookie, fstack_t len)
{
	private_data_t	*pdp = DEVICE_PRIVATE(env);
	fc_cell_t	virt;
	char		*service = "map-out";
	int		error;
	int		offset;

	/*
	 * The calculation of the offset, lo and len are left here
	 * due to historical precedence.
	 */

	offset = mcookie & PAGEOFFSET;
	mcookie &= PAGEMASK;
	len = (len + offset + PAGEOFFSET) & PAGEMASK;

	if (!is_mcookie(mcookie)) {
		log_message(MSG_ERROR, "jupiter:%s: %x not an mcookie!\n",
		    service, (int)mcookie);
		virt = mcookie;
	} else {
		virt = mcookie_to_addr(mcookie);
		debug_msg(DEBUG_REG_ACCESS, "jupiter:%s: %x -> %llx\n",
		    service, (int)mcookie, (long long)virt);
		delete_mapping(mcookie);
	}

	error = fc_run_priv(pdp->common, service, 2, 0,
	    fc_size2cell(len), virt);
	if (error)
		log_message(MSG_ERROR, "jupiter:%s: failed\n", service);
}

static void
do_map_in(fcode_env_t *env)
{
	fstack_t	phi, plo, len, addr;

	CHECK_DEPTH(env, 3, "jupiter:map-in");
	len = POP(DS);
	phi = POP(DS);
	plo = POP(DS);
	addr = mem_map_in(env, phi, plo, len);
	PUSH(DS, addr);
}

static void
do_map_out(fcode_env_t *env)
{
	fstack_t	addr, len;

	CHECK_DEPTH(env, 2, "jupiter:map-out");
	len = POP(DS);
	addr = POP(DS);
	mem_map_out(env, addr, len);
}

static void
do_get_io_portid(fcode_env_t *env)
{
	fstack_t	phi, plo;
	unsigned int	portid, lsb, ch, leaf;

	CHECK_DEPTH(env, 2, "jupiter:get-portid");

	phi = POP(DS);
	plo = POP(DS);

	lsb  = OPL_ADDR_TO_LSB(phi);
	ch   = OPL_ADDR_TO_CHANNEL(phi);
	leaf = OPL_ADDR_TO_LEAF(phi, plo);

	portid = OPL_IO_PORTID(lsb, ch, leaf);

	debug_msg(DEBUG_REG_ACCESS, "jupiter:get-portid ( %x %x ) -> %x\n",
	    (int)phi, (int)plo, (int)portid);
	PUSH(DS, portid);
}

static void
do_encode_unit(fcode_env_t *env)
{
	char		enc_buf[64];
	fstack_t	hi, lo;
	uint32_t	id;
	long long	off;

	CHECK_DEPTH(env, 2, "jupiter:encode-unit");

	hi = POP(DS);
	lo = POP(DS);
	off = (long long)(((hi & 0x1F) << 32) | lo);

	/* Convert physical address to portid */
	DO_GET_IO_PORTID(env, lo, hi, id);

	if (off) {
		(void) sprintf(enc_buf, "%x,%llx", id, off);
	} else {
		(void) sprintf(enc_buf, "%x", id);
	}

	debug_msg(DEBUG_REG_ACCESS, "jupiter:encode_unit ( %x %x ) -> '%s'\n",
	    (uint32_t)hi, (uint32_t)lo, enc_buf);

	push_a_string(env, STRDUP(enc_buf));
}

static void
do_decode_unit(fcode_env_t *env)
{
	uint32_t	hi;
	long long	lo;
	unsigned int	portid, lsb, ch;
	char		*buf;

	CHECK_DEPTH(env, 2, "jupiter:decode-unit");

	buf = pop_a_string(env, NULL);
	if (sscanf(buf, "%x,%llx", &portid, &lo) != 2) {
		if (sscanf(buf, "%x", &portid) != 1) {
			throw_from_fclib(env, 1, "jupiter:decode_unit:%s",
			    buf);
		}
		lo = 0;
	}

	lsb = OPL_IO_PORTID_TO_LSB(portid);
	ch  = OPL_PORTID_TO_CHANNEL(portid);
	hi  = OPL_ADDR_HI(lsb, ch);

	debug_msg(DEBUG_REG_ACCESS,
	    "jupiter:decode_unit ( '%s' ) -> %x %llx\n", buf, hi, lo);

	PUSH(DS, (fstack_t)lo);
	PUSH(DS, (fstack_t)hi);
}

static void
do_device_id(fcode_env_t *env)
{
	common_data_t	*cdp = COMMON_PRIVATE(env);
	char		*buf = NULL;
	uint32_t	hi;
	long long	lo;
	uint32_t	portid, ch, leaf;

	CHECK_DEPTH(env, 2, "jupiter:device-id");

	hi = POP(DS);
	lo = POP(DS);

	portid = 0;
	if (cdp && cdp->fc.unit_address &&
	    ((buf = strdup(cdp->fc.unit_address)) != NULL)) {
		/*
		 * Get portid number from unit_address
		 * Because of no leaf information in physical address
		 */
		if (sscanf(buf, "%x,%llx", &portid, &lo) != 2) {
			if (sscanf(buf, "%x", &portid) != 1) {
				throw_from_fclib(env, 1,
				    "jupiter:do_device_id: invalid %s", buf);
			}
		}
	} else {
		/*
		 * Non existence unit_address case.
		 * Convert physical address to portid.
		 */
		throw_from_fclib(env, 1,
		    "jupiter:do_device_id: failed unit address");
		DO_GET_IO_PORTID(env, lo, hi, portid);
	}

	debug_msg(DEBUG_FIND_FCODE,
	    "jupiter:do_device_id:(%x,%llx)\n", portid, lo);

	/* Pick up each ID from portid */
	ch   = OPL_PORTID_TO_CHANNEL(portid);
	leaf = OPL_PORTID_TO_LEAF(portid);

	if (ch == OPL_CMU_CHANNEL) {
		/*
		 * CMU-CH: PCICMU CHANNEL
		 */
		debug_msg(DEBUG_FIND_FCODE,
		    "jupiter:do_device_id:cmu-ch\n");
		push_a_string(env, "cmu-ch");
	} else if (OPL_OBERON_CHANNEL(ch) && OPL_VALID_LEAF(leaf)) {
		/*
		 * PCI-CH: Oberon Leaves CHANNEL
		 */
		if (leaf) {
			/* Leaf B */
			debug_msg(DEBUG_FIND_FCODE,
			    "jupiter:do_device_id:jup-oberon-pci1\n");
			push_a_string(env, "jup-oberon-pci1");
		} else {
			/* Leaf A */
			debug_msg(DEBUG_FIND_FCODE,
			    "jupiter:do_device_id:jup-oberon-pci0\n");
			push_a_string(env, "jup-oberon-pci0");
		}
	} else {
		/* Not matched to any channels */
		throw_from_fclib(env, 1,
		    "jupiter:do_device_id: invalid portid %x", portid);
		push_a_string(env, "");
	}

	/* Free the duplicated buf */
	if (buf != NULL)
		free(buf);
}

static void
do_get_hwd_va(fcode_env_t *env)
{
	private_data_t	*pdp = DEVICE_PRIVATE(env);
	char		*service = "get-hwd-va";
	char		*buf;
	uint32_t	portid = 0;
	int		ch;
	int		error;
	fc_cell_t	status;
	void		*hwd_va;

	CHECK_DEPTH(env, 2, "jupiter:get-hwd-va");

	/* Get a portid with string format */
	buf = pop_a_string(env, NULL);

	/* Convert to the integer from the string */
	if (sscanf(buf, "%x", &portid) != 1) {
		throw_from_fclib(env, 1, "jupiter:%s: invalid portid",
		    service);
	}

	ch = OPL_PORTID_TO_CHANNEL(portid);
	if (!OPL_VALID_CHANNEL(ch)) {
		throw_from_fclib(env, 1, "jupiter:%s: invalid poritd",
		    service);
		hwd_va = 0;
		goto out;
	}

	if (ch == OPL_CMU_CHANNEL) {
		hwd_va = (void *)&hwd_va_cmu;
	} else {
		hwd_va = (void *)&hwd_va_pci;
	}

	/*
	 * Get the virtual address of hwd specified with portid.
	 */
	error = fc_run_priv(pdp->common, service, 2, 1,
	    fc_uint32_t2cell(portid), fc_ptr2cell(hwd_va), &status);

	if (error || !status)
		throw_from_fclib(env, 1, "jupiter:%s: failed\n", service);

out:
	PUSH(DS, (fstack_t)hwd_va);
}

static void
do_get_intrp_name(fcode_env_t *env)
{
	/*
	 * Just pass the "eFCode" string.
	 */

	debug_msg(DEBUG_FIND_FCODE,
	    "jupiter: do_get_intrp_name: eFCode\n");

	push_a_string(env, "eFCode");
}

static void
do_master_interrupt(fcode_env_t *env)
{
	private_data_t	*pdp = DEVICE_PRIVATE(env);
	char		*service = "master-interrupt";
	int		portid;
	token_t		xt;
	int		error;
	fc_cell_t	status;

	CHECK_DEPTH(env, 2, "jupiter:master-interrupt");
	portid	= POP(DS);
	xt	= POP(DS);

	/*
	 * Install the master interrupt handler for this port id.
	 */
	error = fc_run_priv(pdp->common, service, 2, 1,
	    fc_uint32_t2cell(portid), fc_uint32_t2cell(xt), &status);

	if (error || !status)
		throw_from_fclib(env, 1, "jupiter:%s: failed\n", service);

	PUSH(DS, FALSE);

	debug_msg(DEBUG_REG_ACCESS,
	    "jupiter:master-interrupt ( %x %x ) -> %x\n",
	    portid, xt, (int)FALSE);
}

static void
do_register_vector_entry(fcode_env_t *env)
{
	int	ign, ino, level;

	CHECK_DEPTH(env, 3, "jupiter:register-vector-entry");
	ign   = POP(DS);
	ino   = POP(DS);
	level = POP(DS);

	PUSH(DS, FALSE);
	debug_msg(DEBUG_REG_ACCESS,
	    "jupiter:register-vector-entry ( %x %x %x ) -> %x\n",
	    ign, ino, level, (int)FALSE);
}

static void
do_get_interrupt_target(fcode_env_t *env)
{
	int	mid = -1;

	PUSH(DS, mid);
	debug_msg(DEBUG_REG_ACCESS,
	    "jupiter:get-interrupt-target ( ) -> %x\n", mid);
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
	FORTH(0,	"map-out",		do_map_out);
	FORTH(0,	"get-portid",		do_get_io_portid);
	FORTH(0,	"decode-unit",		do_decode_unit);
	FORTH(0,	"encode-unit",		do_encode_unit);
	FORTH(0,	"device-id",		do_device_id);
	FORTH(0,	"get-hwd-va",		do_get_hwd_va);
	FORTH(0,	"get-fcinterp-name",	do_get_intrp_name);
	FORTH(0,	"master-interrupt",	do_master_interrupt);
	FORTH(0,	"register-vector-entry", do_register_vector_entry);
	FORTH(0,	"get-interrupt-target",	do_get_interrupt_target);
}
