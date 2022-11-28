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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<libelf.h>
#include	<sys/regset.h>
#include	<rtld_db.h>
#include	<_rtld_db.h>
#include	<msg.h>
#include	<stdio.h>


typedef	struct {
    rd_agent_t	*rlid_rap;
    psaddr_t	rlid_pltaddr;
    psaddr_t	rlid_gotaddr;
    rd_err_e	rlid_ret;
} Rli_data;

/*
 * Iterator function for rd_loadobj_iter - we are scaning
 * each object loaded to try and find the object defining
 * the current PLT being traversed - when found we return
 * the GOT pointer for that object.
 */
static int
rli_func(const rd_loadobj_t *rl, void *data)
{
	Ehdr	    ehdr;
	Phdr	    phdr;
	Rli_data    *rli_data;
	ulong_t	    off;
	psaddr_t    baseaddr;
	psaddr_t    pltaddr;
	uint_t	    i;
	uint_t	    found_obj = 0;
	psaddr_t    dynbase = 0;
	rd_agent_t  *rap;
	rd_err_e    rc;

	rli_data = (Rli_data *)data;
	pltaddr = rli_data->rlid_pltaddr;
	rap = rli_data->rlid_rap;

	if (ps_pread(rap->rd_psp, rl->rl_base, (char *)&ehdr,
	    sizeof (Ehdr)) != PS_OK) {
		rli_data->rlid_ret = RD_ERR;
		LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_X86_1),
		    EC_ADDR(rl->rl_base)));
		return (0);
	}
	if (ehdr.e_type == ET_EXEC)
		baseaddr = 0;
	else
		baseaddr = rl->rl_base;

	off = rl->rl_base + ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		if (ps_pread(rap->rd_psp, off, (char *)&phdr,
		    sizeof (Phdr)) != PS_OK) {
			rli_data->rlid_ret = RD_ERR;
			LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_X86_1),
			    EC_ADDR(rl->rl_base)));
			return (0);
		}
		if (phdr.p_type == PT_LOAD) {
			if ((pltaddr >= (phdr.p_vaddr + baseaddr)) &&
			    (pltaddr < (phdr.p_vaddr + baseaddr +
			    phdr.p_memsz))) {
				found_obj = 1;
			}
		} else if (phdr.p_type == PT_DYNAMIC)  {
			dynbase = phdr.p_vaddr + baseaddr;
		}
		off += ehdr.e_phentsize;

		if (found_obj & dynbase)
			break;
	}

	if (found_obj) {
		Dyn dynent;

		if (dynbase == 0) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_NODYN_X86)));
			rli_data->rlid_ret = RD_ERR;
			return (0);
		}
		if ((rc = find_dynamic_ent32(rap, dynbase, DT_PLTGOT,
		    &dynent)) != RD_OK) {
			rli_data->rlid_ret = rc;
			return (0);
		}
		/*
		 * We've found our gotpntr. Return (0) to stop
		 * the 'iteration'.
		 */
		rli_data->rlid_gotaddr = dynent.d_un.d_val + baseaddr;
		return (0);
	}

	return (1);
}


/*
 * On x86, basically, a PLT entry looks like this:
 *	8048738:  ff 25 c8 45 05 08   jmp    *0x80545c8	 < OFFSET_INTO_GOT>
 *	804873e:  68 20 00 00 00      pushl  $0x20
 *	8048743:  e9 70 ff ff ff      jmp    0xffffff70 <80486b8> < &.plt >
 *
 *  The first time around OFFSET_INTO_GOT contains address of pushl; this forces
 *	first time resolution to go thru PLT's first entry (which is a call)
 *  The nth time around, the OFFSET_INTO_GOT actually contains the resolved
 *	address of the symbol(name), so the jmp is direct  [VT]
 *  The only complication is when going from a .so to an executable or to
 *      another .so, we must resolve where the GOT table is for the given
 *      object.
 */
/* ARGSUSED 3 */
rd_err_e
plt32_resolution(rd_agent_t *rap, psaddr_t pc, lwpid_t lwpid,
    psaddr_t pltbase, rd_plt_info_t *rpi)
{
	unsigned	addr;
	unsigned	ebx;
	psaddr_t	pltoff, pltaddr;


	if (rtld_db_version >= RD_VERSION3) {
		rpi->pi_flags = 0;
		rpi->pi_baddr = 0;
	}

	pltoff = pc - pltbase;
	pltaddr = pltbase +
	    ((pltoff / M_PLT_ENTSIZE) * M_PLT_ENTSIZE);
	/*
	 * This is the target of the jmp instruction
	 */
	if (ps_pread(rap->rd_psp, pltaddr + 2, (char *)&addr,
	    sizeof (unsigned)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_2), EC_ADDR(pltaddr + 2)));
		return (RD_ERR);
	}

	/*
	 * Is this branch %ebx relative
	 */
	if (ps_pread(rap->rd_psp, pltaddr + 1, (char *)&ebx,
	    sizeof (unsigned)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_2), EC_ADDR(pltaddr + 1)));
		return (RD_ERR);
	}

	/*
	 * If this .plt call is made via a GOT table (pic code), then
	 * in order to resolve the PLT we must determine where the
	 * GOT table is for the object making the call.
	 *
	 * We do this by using the rd_loadobj_iter() logic to scan
	 * all of the objects currently loaded into memory, when we
	 * find one which contains the .PLT table in question - we
	 * find the GOT address for that object.
	 */
	if ((ebx & 0xff) == 0xa3) {
		rd_err_e    rderr;
		Rli_data    rli_data;

		rli_data.rlid_ret = RD_OK;
		rli_data.rlid_pltaddr = pltaddr;
		rli_data.rlid_rap = rap;
		rli_data.rlid_gotaddr = 0;
		if ((rderr = _rd_loadobj_iter32(rap, rli_func, &rli_data))
		    != RD_OK) {
			return (rderr);
		}

		if (rli_data.rlid_ret != RD_OK) {
			return (rli_data.rlid_ret);
		}

		if (rli_data.rlid_gotaddr == 0) {
			LOG(ps_plog(MSG_ORIG(MSG_DB_NOGOT_X86)));
			return (RD_ERR);
		}
		addr += rli_data.rlid_gotaddr;
	}

	/*
	 * Find out what's pointed to by @OFFSET_INTO_GOT
	 */
	if (ps_pread(rap->rd_psp, addr, (char *)&addr,
	    sizeof (unsigned)) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_READFAIL_2), EC_ADDR(addr)));
		return (RD_ERR);
	}
	if (addr == (pltaddr + 6)) {
		rd_err_e	rerr;
		/*
		 * If GOT[ind] points to PLT+6 then this is the first
		 * time through this PLT.
		 */
		if ((rerr = rd_binder_exit_addr(rap, MSG_ORIG(MSG_SYM_RTBIND),
		    &(rpi->pi_target))) != RD_OK) {
			return (rerr);
		}
		rpi->pi_skip_method = RD_RESOLVE_TARGET_STEP;
		rpi->pi_nstep = 1;
	} else {
		/*
		 * This is the n'th time through and GOT[ind] points
		 * to the final destination.
		 */
		rpi->pi_skip_method = RD_RESOLVE_STEP;
		rpi->pi_nstep = 1;
		rpi->pi_target = 0;
		if (rtld_db_version >= RD_VERSION3) {
			rpi->pi_flags |= RD_FLG_PI_PLTBOUND;
			rpi->pi_baddr = addr;
		}
	}

	return (RD_OK);
}
