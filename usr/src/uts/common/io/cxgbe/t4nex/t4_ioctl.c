/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2011-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/queue.h>

#include "t4nex.h"
#include "common/common.h"
#include "common/t4_regs.h"

/* helpers */
static int pci_rw(struct adapter *sc, void *data, int flags, int write);
static int reg_rw(struct adapter *sc, void *data, int flags, int write);
static void reg_block_dump(struct adapter *sc, uint8_t *buf, unsigned int start,
    unsigned int end);
static int regdump(struct adapter *sc, void *data, int flags);
static int get_sge_context(struct adapter *sc, void *data, int flags);
static int get_devlog(struct adapter *sc, void *data, int flags);
static int read_card_mem(struct adapter *sc, void *data, int flags);
static int read_tid_tab(struct adapter *sc, void *data, int flags);
static int read_mbox(struct adapter *sc, void *data, int flags);
static int read_cim_la(struct adapter *sc, void *data, int flags);
static int read_cim_qcfg(struct adapter *sc, void *data, int flags);
static int read_cim_ibq(struct adapter *sc, void *data, int flags);
static int read_edc(struct adapter *sc, void *data, int flags);

int
t4_ioctl(struct adapter *sc, int cmd, void *data, int mode)
{
	int rc = ENOTSUP;

	switch (cmd) {
	case T4_IOCTL_PCIGET32:
	case T4_IOCTL_PCIPUT32:
		rc = pci_rw(sc, data, mode, cmd == T4_IOCTL_PCIPUT32);
		break;
	case T4_IOCTL_GET32:
	case T4_IOCTL_PUT32:
		rc = reg_rw(sc, data, mode, cmd == T4_IOCTL_PUT32);
		break;
	case T4_IOCTL_REGDUMP:
		rc = regdump(sc, data, mode);
		break;
	case T4_IOCTL_SGE_CONTEXT:
		rc = get_sge_context(sc, data, mode);
		break;
	case T4_IOCTL_DEVLOG:
		rc = get_devlog(sc, data, mode);
		break;
	case T4_IOCTL_GET_MEM:
		rc = read_card_mem(sc, data, mode);
		break;
	case T4_IOCTL_GET_TID_TAB:
		rc = read_tid_tab(sc, data, mode);
		break;
	case T4_IOCTL_GET_MBOX:
		rc = read_mbox(sc, data, mode);
		break;
	case T4_IOCTL_GET_CIM_LA:
		rc = read_cim_la(sc, data, mode);
		break;
	case T4_IOCTL_GET_CIM_QCFG:
		rc = read_cim_qcfg(sc, data, mode);
		break;
	case T4_IOCTL_GET_CIM_IBQ:
		rc = read_cim_ibq(sc, data, mode);
		break;
	case T4_IOCTL_GET_EDC:
		rc = read_edc(sc, data, mode);
		break;
	default:
		return (EINVAL);
	}

	return (rc);
}

static int
pci_rw(struct adapter *sc, void *data, int flags, int write)
{
	struct t4_reg32_cmd r;

	if (ddi_copyin(data, &r, sizeof (r), flags) < 0)
		return (EFAULT);

	/* address must be 32 bit aligned */
	r.reg &= ~0x3;

	if (write != 0)
		t4_os_pci_write_cfg4(sc, r.reg, r.value);
	else {
		t4_os_pci_read_cfg4(sc, r.reg, &r.value);
		if (ddi_copyout(&r, data, sizeof (r), flags) < 0)
			return (EFAULT);
	}

	return (0);
}

static int
reg_rw(struct adapter *sc, void *data, int flags, int write)
{
	struct t4_reg32_cmd r;

	if (ddi_copyin(data, &r, sizeof (r), flags) < 0)
		return (EFAULT);

	/* Register address must be 32 bit aligned */
	r.reg &= ~0x3;

	if (write != 0)
		t4_write_reg(sc, r.reg, r.value);
	else {
		r.value = t4_read_reg(sc, r.reg);
		if (ddi_copyout(&r, data, sizeof (r), flags) < 0)
			return (EFAULT);
	}

	return (0);
}

static void
reg_block_dump(struct adapter *sc, uint8_t *buf, unsigned int start,
    unsigned int end)
{
	/* LINTED: E_BAD_PTR_CAST_ALIGN */
	uint32_t *p = (uint32_t *)(buf + start);

	for (/* */; start <= end; start += sizeof (uint32_t))
		*p++ = t4_read_reg(sc, start);
}

static int
regdump(struct adapter *sc, void *data, int flags)
{
	struct t4_regdump r;
	uint8_t *buf;
	int rc = 0, i;
	static const unsigned int reg_ranges[] = {
		0x1008, 0x1108,
		0x1180, 0x11b4,
		0x11fc, 0x123c,
		0x1300, 0x173c,
		0x1800, 0x18fc,
		0x3000, 0x30d8,
		0x30e0, 0x5924,
		0x5960, 0x59d4,
		0x5a00, 0x5af8,
		0x6000, 0x6098,
		0x6100, 0x6150,
		0x6200, 0x6208,
		0x6240, 0x6248,
		0x6280, 0x6338,
		0x6370, 0x638c,
		0x6400, 0x643c,
		0x6500, 0x6524,
		0x6a00, 0x6a38,
		0x6a60, 0x6a78,
		0x6b00, 0x6b84,
		0x6bf0, 0x6c84,
		0x6cf0, 0x6d84,
		0x6df0, 0x6e84,
		0x6ef0, 0x6f84,
		0x6ff0, 0x7084,
		0x70f0, 0x7184,
		0x71f0, 0x7284,
		0x72f0, 0x7384,
		0x73f0, 0x7450,
		0x7500, 0x7530,
		0x7600, 0x761c,
		0x7680, 0x76cc,
		0x7700, 0x7798,
		0x77c0, 0x77fc,
		0x7900, 0x79fc,
		0x7b00, 0x7c38,
		0x7d00, 0x7efc,
		0x8dc0, 0x8e1c,
		0x8e30, 0x8e78,
		0x8ea0, 0x8f6c,
		0x8fc0, 0x9074,
		0x90fc, 0x90fc,
		0x9400, 0x9458,
		0x9600, 0x96bc,
		0x9800, 0x9808,
		0x9820, 0x983c,
		0x9850, 0x9864,
		0x9c00, 0x9c6c,
		0x9c80, 0x9cec,
		0x9d00, 0x9d6c,
		0x9d80, 0x9dec,
		0x9e00, 0x9e6c,
		0x9e80, 0x9eec,
		0x9f00, 0x9f6c,
		0x9f80, 0x9fec,
		0xd004, 0xd03c,
		0xdfc0, 0xdfe0,
		0xe000, 0xea7c,
		0xf000, 0x11190,
		0x19040, 0x19124,
		0x19150, 0x191b0,
		0x191d0, 0x191e8,
		0x19238, 0x1924c,
		0x193f8, 0x19474,
		0x19490, 0x194f8,
		0x19800, 0x19f30,
		0x1a000, 0x1a06c,
		0x1a0b0, 0x1a120,
		0x1a128, 0x1a138,
		0x1a190, 0x1a1c4,
		0x1a1fc, 0x1a1fc,
		0x1e040, 0x1e04c,
		0x1e240, 0x1e28c,
		0x1e2c0, 0x1e2c0,
		0x1e2e0, 0x1e2e0,
		0x1e300, 0x1e384,
		0x1e3c0, 0x1e3c8,
		0x1e440, 0x1e44c,
		0x1e640, 0x1e68c,
		0x1e6c0, 0x1e6c0,
		0x1e6e0, 0x1e6e0,
		0x1e700, 0x1e784,
		0x1e7c0, 0x1e7c8,
		0x1e840, 0x1e84c,
		0x1ea40, 0x1ea8c,
		0x1eac0, 0x1eac0,
		0x1eae0, 0x1eae0,
		0x1eb00, 0x1eb84,
		0x1ebc0, 0x1ebc8,
		0x1ec40, 0x1ec4c,
		0x1ee40, 0x1ee8c,
		0x1eec0, 0x1eec0,
		0x1eee0, 0x1eee0,
		0x1ef00, 0x1ef84,
		0x1efc0, 0x1efc8,
		0x1f040, 0x1f04c,
		0x1f240, 0x1f28c,
		0x1f2c0, 0x1f2c0,
		0x1f2e0, 0x1f2e0,
		0x1f300, 0x1f384,
		0x1f3c0, 0x1f3c8,
		0x1f440, 0x1f44c,
		0x1f640, 0x1f68c,
		0x1f6c0, 0x1f6c0,
		0x1f6e0, 0x1f6e0,
		0x1f700, 0x1f784,
		0x1f7c0, 0x1f7c8,
		0x1f840, 0x1f84c,
		0x1fa40, 0x1fa8c,
		0x1fac0, 0x1fac0,
		0x1fae0, 0x1fae0,
		0x1fb00, 0x1fb84,
		0x1fbc0, 0x1fbc8,
		0x1fc40, 0x1fc4c,
		0x1fe40, 0x1fe8c,
		0x1fec0, 0x1fec0,
		0x1fee0, 0x1fee0,
		0x1ff00, 0x1ff84,
		0x1ffc0, 0x1ffc8,
		0x20000, 0x2002c,
		0x20100, 0x2013c,
		0x20190, 0x201c8,
		0x20200, 0x20318,
		0x20400, 0x20528,
		0x20540, 0x20614,
		0x21000, 0x21040,
		0x2104c, 0x21060,
		0x210c0, 0x210ec,
		0x21200, 0x21268,
		0x21270, 0x21284,
		0x212fc, 0x21388,
		0x21400, 0x21404,
		0x21500, 0x21518,
		0x2152c, 0x2153c,
		0x21550, 0x21554,
		0x21600, 0x21600,
		0x21608, 0x21628,
		0x21630, 0x2163c,
		0x21700, 0x2171c,
		0x21780, 0x2178c,
		0x21800, 0x21c38,
		0x21c80, 0x21d7c,
		0x21e00, 0x21e04,
		0x22000, 0x2202c,
		0x22100, 0x2213c,
		0x22190, 0x221c8,
		0x22200, 0x22318,
		0x22400, 0x22528,
		0x22540, 0x22614,
		0x23000, 0x23040,
		0x2304c, 0x23060,
		0x230c0, 0x230ec,
		0x23200, 0x23268,
		0x23270, 0x23284,
		0x232fc, 0x23388,
		0x23400, 0x23404,
		0x23500, 0x23518,
		0x2352c, 0x2353c,
		0x23550, 0x23554,
		0x23600, 0x23600,
		0x23608, 0x23628,
		0x23630, 0x2363c,
		0x23700, 0x2371c,
		0x23780, 0x2378c,
		0x23800, 0x23c38,
		0x23c80, 0x23d7c,
		0x23e00, 0x23e04,
		0x24000, 0x2402c,
		0x24100, 0x2413c,
		0x24190, 0x241c8,
		0x24200, 0x24318,
		0x24400, 0x24528,
		0x24540, 0x24614,
		0x25000, 0x25040,
		0x2504c, 0x25060,
		0x250c0, 0x250ec,
		0x25200, 0x25268,
		0x25270, 0x25284,
		0x252fc, 0x25388,
		0x25400, 0x25404,
		0x25500, 0x25518,
		0x2552c, 0x2553c,
		0x25550, 0x25554,
		0x25600, 0x25600,
		0x25608, 0x25628,
		0x25630, 0x2563c,
		0x25700, 0x2571c,
		0x25780, 0x2578c,
		0x25800, 0x25c38,
		0x25c80, 0x25d7c,
		0x25e00, 0x25e04,
		0x26000, 0x2602c,
		0x26100, 0x2613c,
		0x26190, 0x261c8,
		0x26200, 0x26318,
		0x26400, 0x26528,
		0x26540, 0x26614,
		0x27000, 0x27040,
		0x2704c, 0x27060,
		0x270c0, 0x270ec,
		0x27200, 0x27268,
		0x27270, 0x27284,
		0x272fc, 0x27388,
		0x27400, 0x27404,
		0x27500, 0x27518,
		0x2752c, 0x2753c,
		0x27550, 0x27554,
		0x27600, 0x27600,
		0x27608, 0x27628,
		0x27630, 0x2763c,
		0x27700, 0x2771c,
		0x27780, 0x2778c,
		0x27800, 0x27c38,
		0x27c80, 0x27d7c,
		0x27e00, 0x27e04
	};

	if (ddi_copyin(data, &r, sizeof (r), flags) < 0)
		return (EFAULT);

	if (r.len > T4_REGDUMP_SIZE)
		r.len = T4_REGDUMP_SIZE;
	else if (r.len < T4_REGDUMP_SIZE)
		return (E2BIG);

	buf = kmem_zalloc(T4_REGDUMP_SIZE, KM_SLEEP);

	r.version = 4 | (sc->params.rev << 10);
	for (i = 0; i < ARRAY_SIZE(reg_ranges); i += 2)
		reg_block_dump(sc, buf, reg_ranges[i], reg_ranges[i + 1]);

	if (ddi_copyout(buf, r.data, r.len, flags) < 0)
		rc = EFAULT;

	if (rc == 0 && ddi_copyout(&r, data, sizeof (r), flags) < 0)
		rc = EFAULT;

	kmem_free(buf, T4_REGDUMP_SIZE);

	return (rc);
}

static int
get_sge_context(struct adapter *sc, void *data, int flags)
{
	struct t4_sge_context sgec;
	uint32_t buff[SGE_CTXT_SIZE / 4];
	int rc = 0;

	if (ddi_copyin(data, &sgec, sizeof (sgec), flags) < 0) {
		rc = EFAULT;
		goto _exit;
	}

	if (sgec.len < SGE_CTXT_SIZE || sgec.addr > M_CTXTQID) {
		rc = EINVAL;
		goto _exit;
	}

	if ((sgec.mem_id != T4_CTXT_EGRESS) && (sgec.mem_id != T4_CTXT_FLM) &&
	    (sgec.mem_id != T4_CTXT_INGRESS)) {
		rc = EINVAL;
		goto _exit;
	}

	rc = (sc->flags & FW_OK) ?
	    -t4_sge_ctxt_rd(sc, sc->mbox, sgec.addr, sgec.mem_id, buff) :
	    -t4_sge_ctxt_rd_bd(sc, sgec.addr, sgec.mem_id, buff);
	if (rc != 0)
		goto _exit;

	sgec.version = 4 | (sc->params.rev << 10);

	/* copyout data and then t4_sge_context */
	rc = ddi_copyout(buff, sgec.data, sgec.len, flags);
	if (rc == 0)
		rc = ddi_copyout(&sgec, data, sizeof (sgec), flags);
	/* if ddi_copyout fails, return EFAULT - for either of the two */
	if (rc != 0)
		rc = EFAULT;

_exit:
	return (rc);
}

static int
read_tid_tab(struct adapter *sc, void *data, int flags)
{
	struct t4_tid_info t4tid;
	uint32_t *buf, *b;
	struct tid_info *t = &sc->tids;
	int rc = 0;

	if (ddi_copyin(data, &t4tid, sizeof (t4tid), flags) < 0) {
		rc = EFAULT;
		goto _exit;
	}

	buf = b = kmem_zalloc(t4tid.len, KM_NOSLEEP);
	if (buf == NULL) {
		rc = ENOMEM;
		goto _exit;
	}

	*b++ = t->tids_in_use;
	*b++ = t->atids_in_use;
	*b = t->stids_in_use;

	if (ddi_copyout(buf, t4tid.data, t4tid.len, flags) < 0)
		rc = EFAULT;

	kmem_free(buf, t4tid.len);

_exit:
	return (rc);
}

static int
read_card_mem(struct adapter *sc, void *data, int flags)
{
	struct t4_mem_range mr;
	uint32_t base, size, lo, hi, win, off, remaining, i, n;
	uint32_t *buf, *b;
	int rc = 0;

	if (ddi_copyin(data, &mr, sizeof (mr), flags) < 0) {
		rc = EFAULT;
		goto _exit;
	}

	/* reads are in multiples of 32 bits */
	if (mr.addr & 3 || mr.len & 3 || mr.len == 0) {
		rc = EINVAL;
		goto _exit;
	}

	/*
	 * We don't want to deal with potential holes so we mandate that the
	 * requested region must lie entirely within one of the 3 memories.
	 */
	lo = t4_read_reg(sc, A_MA_TARGET_MEM_ENABLE);
	if (lo & F_EDRAM0_ENABLE) {
		hi = t4_read_reg(sc, A_MA_EDRAM0_BAR);
		base = G_EDRAM0_BASE(hi) << 20;
		size = G_EDRAM0_SIZE(hi) << 20;
		if (size > 0 &&
		    mr.addr >= base && mr.addr < base + size &&
		    mr.addr + mr.len <= base + size)
			goto proceed;
	}
	if (lo & F_EDRAM1_ENABLE) {
		hi = t4_read_reg(sc, A_MA_EDRAM1_BAR);
		base = G_EDRAM1_BASE(hi) << 20;
		size = G_EDRAM1_SIZE(hi) << 20;
		if (size > 0 &&
		    mr.addr >= base && mr.addr < base + size &&
		    mr.addr + mr.len <= base + size)
			goto proceed;
	}
	if (lo & F_EXT_MEM_ENABLE) {
		hi = t4_read_reg(sc, A_MA_EXT_MEMORY_BAR);
		base = G_EXT_MEM_BASE(hi) << 20;
		size = G_EXT_MEM_SIZE(hi) << 20;
		if (size > 0 &&
		    mr.addr >= base && mr.addr < base + size &&
		    mr.addr + mr.len <= base + size)
			goto proceed;
	}
	return (ENXIO);

proceed:
	buf = b = kmem_zalloc(mr.len, KM_NOSLEEP);
	if (buf == NULL) {
		rc = ENOMEM;
		goto _exit;
	}

	/*
	 * Position the PCIe window (we use memwin2) to the 16B aligned area
	 * just at/before the requested region.
	 */
	win = mr.addr & ~0xf;
	off = mr.addr - win;  /* offset of the requested region in the win */
	remaining = mr.len;

	while (remaining) {
		t4_write_reg(sc,
		    PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_OFFSET, 2), win);
		(void) t4_read_reg(sc,
		    PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_OFFSET, 2));

		/* number of bytes that we'll copy in the inner loop */
		n = min(remaining, MEMWIN2_APERTURE - off);

		for (i = 0; i < n; i += 4, remaining -= 4)
			*b++ = t4_read_reg(sc, MEMWIN2_BASE + off + i);

		win += MEMWIN2_APERTURE;
		off = 0;
	}

	if (ddi_copyout(buf, mr.data, mr.len, flags) < 0)
		rc = EFAULT;

	kmem_free(buf, mr.len);

_exit:
	return (rc);
}

static int
get_devlog(struct adapter *sc, void *data, int flags)
{
	struct devlog_params *dparams = &sc->params.devlog;
	struct fw_devlog_e *buf;
	struct t4_devlog dl;
	int rc = 0;

	if (ddi_copyin(data, &dl, sizeof (dl), flags) < 0) {
		rc = EFAULT;
		goto done;
	}

	if (dparams->start == 0) {
		rc = ENXIO;
		goto done;
	}

	if (dl.len < dparams->size) {
		dl.len = dparams->size;
		rc = ddi_copyout(&dl, data, sizeof (dl), flags);
		/*
		 * rc = 0 indicates copyout was successful, then return ENOBUFS
		 * to indicate that the buffer size was not enough. Return of
		 * EFAULT indicates that the copyout was not successful.
		 */
		rc = (rc == 0) ? ENOBUFS : EFAULT;
		goto done;
	}

	buf = kmem_zalloc(dparams->size, KM_NOSLEEP);
	if (buf == NULL) {
		rc = ENOMEM;
		goto done;
	}

	rc = -t4_mem_read(sc, dparams->memtype, dparams->start, dparams->size,
	    (void *)buf);
	if (rc != 0)
		goto done1;

	/* Copyout device log buffer and then carrier buffer */
	if (ddi_copyout(buf, dl.data, dl.len, flags) < 0)
		rc = EFAULT;
	else if (ddi_copyout(&dl, data, sizeof (dl), flags) < 0)
		rc = EFAULT;

done1:
	kmem_free(buf, dparams->size);

done:
	return (rc);
}

static int
read_cim_qcfg(struct adapter *sc, void *data, int flags)
{
	struct t4_cim_qcfg t4cimqcfg;
	int rc = 0;

	if (ddi_copyin(data, &t4cimqcfg, sizeof (t4cimqcfg), flags) < 0) {
		rc = EFAULT;
		goto _exit;
	}

	rc = t4_cim_read(sc, A_UP_IBQ_0_RDADDR, ARRAY_SIZE(t4cimqcfg.stat),
	    t4cimqcfg.stat);

	if (rc != 0)
		return (rc);

	t4_read_cimq_cfg(sc, t4cimqcfg.base, t4cimqcfg.size, t4cimqcfg.thres);

	if (ddi_copyout(&t4cimqcfg, data, sizeof (t4cimqcfg), flags) < 0)
		rc = EFAULT;

_exit:
	return (rc);
}

static int
read_edc(struct adapter *sc, void *data, int flags)
{
	struct t4_edc t4edc;
	int rc = 0;
	u32 count, pos = 0;
	u32 memoffset;
	__be32 *edc = NULL;

	if (ddi_copyin(data, &t4edc, sizeof (t4edc), flags) < 0) {
		rc = EFAULT;
		goto _exit;
	}

	if (t4edc.mem > 2)
		goto _exit;

	edc = kmem_zalloc(t4edc.len, KM_NOSLEEP);
	if (edc == NULL) {
		rc = ENOMEM;
		goto _exit;
	}
	/*
	 * Offset into the region of memory which is being accessed
	 * MEM_EDC0 = 0
	 * MEM_EDC1 = 1
	 * MEM_MC   = 2
	 */
	memoffset = (t4edc.mem * (5 * 1024 * 1024));
	count = t4edc.len;
	pos = t4edc.pos;

	while (count) {
		u32 len;

		rc = t4_mem_win_read(sc, (pos + memoffset), edc);
		if (rc != 0) {
			kmem_free(edc, t4edc.len);
			goto _exit;
		}

		len = MEMWIN0_APERTURE;
		pos += len;
		count -= len;
	}

	if (ddi_copyout(edc, t4edc.data, t4edc.len, flags) < 0)
		rc = EFAULT;

	kmem_free(edc, t4edc.len);
_exit:
	return (rc);
}

static int
read_cim_ibq(struct adapter *sc, void *data, int flags)
{
	struct t4_ibq t4ibq;
	int rc = 0;
	__be64 *buf;

	if (ddi_copyin(data, &t4ibq, sizeof (t4ibq), flags) < 0) {
		rc = EFAULT;
		goto _exit;
	}

	buf = kmem_zalloc(t4ibq.len, KM_NOSLEEP);
	if (buf == NULL) {
		rc = ENOMEM;
		goto _exit;
	}

	rc = t4_read_cim_ibq(sc, 3, (u32 *)buf, CIM_IBQ_SIZE * 4);
	if (rc < 0) {
		kmem_free(buf, t4ibq.len);
		return (rc);
	} else
		rc = 0;

	if (ddi_copyout(buf, t4ibq.data, t4ibq.len, flags) < 0)
		rc = EFAULT;

	kmem_free(buf, t4ibq.len);

_exit:
	return (rc);
}

static int
read_cim_la(struct adapter *sc, void *data, int flags)
{
	struct t4_cim_la t4cimla;
	int rc = 0;
	unsigned int cfg;
	__be64 *buf;

	rc = t4_cim_read(sc, A_UP_UP_DBG_LA_CFG, 1, &cfg);
	if (rc != 0)
		return (rc);

	if (ddi_copyin(data, &t4cimla, sizeof (t4cimla), flags) < 0) {
		rc = EFAULT;
		goto _exit;
	}

	buf = kmem_zalloc(t4cimla.len, KM_NOSLEEP);
	if (buf == NULL) {
		rc = ENOMEM;
		goto _exit;
	}

	rc = t4_cim_read_la(sc, (u32 *)buf, NULL);
	if (rc != 0) {
		kmem_free(buf, t4cimla.len);
		return (rc);
	}

	if (ddi_copyout(buf, t4cimla.data, t4cimla.len, flags) < 0)
		rc = EFAULT;

	kmem_free(buf, t4cimla.len);

_exit:
	return (rc);
}

static int
read_mbox(struct adapter *sc, void *data, int flags)
{
	struct t4_mbox t4mbox;
	int rc = 0, i;
	__be64 *p, *buf;

	u32 data_reg = PF_REG(4, A_CIM_PF_MAILBOX_DATA);

	if (ddi_copyin(data, &t4mbox, sizeof (t4mbox), flags) < 0) {
		rc = EFAULT;
		goto _exit;
	}

	buf = p = kmem_zalloc(t4mbox.len, KM_NOSLEEP);
	if (buf == NULL) {
		rc = ENOMEM;
		goto _exit;
	}

	for (i = 0; i < t4mbox.len; i += 8, p++)
		*p =  t4_read_reg64(sc, data_reg + i);

	if (ddi_copyout(buf, t4mbox.data, t4mbox.len, flags) < 0)
		rc = EFAULT;

	kmem_free(buf, t4mbox.len);

_exit:
	return (rc);
}
