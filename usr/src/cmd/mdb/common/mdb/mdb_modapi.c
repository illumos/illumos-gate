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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_module.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_callb.h>
#include <mdb/mdb_dump.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_io.h>
#include <mdb/mdb_lex.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb.h>

/*
 * Private callback structure for implementing mdb_walk_dcmd, below.
 */
typedef struct {
	mdb_idcmd_t *dw_dcmd;
	mdb_argvec_t dw_argv;
	uint_t dw_flags;
} dcmd_walk_arg_t;

/*
 * Global properties which modules are allowed to look at.  These are
 * re-initialized by the target activation callbacks.
 */
int mdb_prop_postmortem = FALSE;	/* Are we examining a dump? */
int mdb_prop_kernel = FALSE;		/* Are we examining a kernel? */
int mdb_prop_datamodel = 0;		/* Data model (see mdb_target_impl.h) */

ssize_t
mdb_vread(void *buf, size_t nbytes, uintptr_t addr)
{
	ssize_t rbytes = mdb_tgt_vread(mdb.m_target, buf, nbytes, addr);

	if (rbytes > 0 && rbytes < nbytes)
		return (set_errbytes(rbytes, nbytes));

	return (rbytes);
}

ssize_t
mdb_vwrite(const void *buf, size_t nbytes, uintptr_t addr)
{
	return (mdb_tgt_vwrite(mdb.m_target, buf, nbytes, addr));
}

ssize_t
mdb_aread(void *buf, size_t nbytes, uintptr_t addr, void *as)
{
	ssize_t rbytes = mdb_tgt_aread(mdb.m_target, as, buf, nbytes, addr);

	if (rbytes > 0 && rbytes < nbytes)
		return (set_errbytes(rbytes, nbytes));

	return (rbytes);
}

ssize_t
mdb_awrite(const void *buf, size_t nbytes, uintptr_t addr, void *as)
{
	return (mdb_tgt_awrite(mdb.m_target, as, buf, nbytes, addr));
}

ssize_t
mdb_fread(void *buf, size_t nbytes, uintptr_t addr)
{
	ssize_t rbytes = mdb_tgt_fread(mdb.m_target, buf, nbytes, addr);

	if (rbytes > 0 && rbytes < nbytes)
		return (set_errbytes(rbytes, nbytes));

	return (rbytes);
}

ssize_t
mdb_fwrite(const void *buf, size_t nbytes, uintptr_t addr)
{
	return (mdb_tgt_fwrite(mdb.m_target, buf, nbytes, addr));
}

ssize_t
mdb_pread(void *buf, size_t nbytes, physaddr_t addr)
{
	ssize_t rbytes = mdb_tgt_pread(mdb.m_target, buf, nbytes, addr);

	if (rbytes > 0 && rbytes < nbytes)
		return (set_errbytes(rbytes, nbytes));

	return (rbytes);
}

ssize_t
mdb_pwrite(const void *buf, size_t nbytes, physaddr_t addr)
{
	return (mdb_tgt_pwrite(mdb.m_target, buf, nbytes, addr));
}

ssize_t
mdb_readstr(char *buf, size_t nbytes, uintptr_t addr)
{
	return (mdb_tgt_readstr(mdb.m_target, MDB_TGT_AS_VIRT,
	    buf, nbytes, addr));
}

ssize_t
mdb_writestr(const char *buf, uintptr_t addr)
{
	return (mdb_tgt_writestr(mdb.m_target, MDB_TGT_AS_VIRT, buf, addr));
}

ssize_t
mdb_readsym(void *buf, size_t nbytes, const char *name)
{
	ssize_t rbytes = mdb_tgt_readsym(mdb.m_target, MDB_TGT_AS_VIRT,
	    buf, nbytes, MDB_TGT_OBJ_EVERY, name);

	if (rbytes > 0 && rbytes < nbytes)
		return (set_errbytes(rbytes, nbytes));

	return (rbytes);
}

ssize_t
mdb_writesym(const void *buf, size_t nbytes, const char *name)
{
	return (mdb_tgt_writesym(mdb.m_target, MDB_TGT_AS_VIRT,
	    buf, nbytes, MDB_TGT_OBJ_EVERY, name));
}

ssize_t
mdb_readvar(void *buf, const char *name)
{
	GElf_Sym sym;

	if (mdb_tgt_lookup_by_name(mdb.m_target, MDB_TGT_OBJ_EVERY,
	    name, &sym, NULL))
		return (-1);

	if (mdb_tgt_vread(mdb.m_target, buf, sym.st_size,
	    (uintptr_t)sym.st_value) == sym.st_size)
		return ((ssize_t)sym.st_size);

	return (-1);
}

ssize_t
mdb_writevar(const void *buf, const char *name)
{
	GElf_Sym sym;

	if (mdb_tgt_lookup_by_name(mdb.m_target, MDB_TGT_OBJ_EVERY,
	    name, &sym, NULL))
		return (-1);

	if (mdb_tgt_vwrite(mdb.m_target, buf, sym.st_size,
	    (uintptr_t)sym.st_value) == sym.st_size)
		return ((ssize_t)sym.st_size);

	return (-1);
}

int
mdb_lookup_by_name(const char *name, GElf_Sym *sym)
{
	return (mdb_lookup_by_obj(MDB_TGT_OBJ_EVERY, name, sym));
}

int
mdb_lookup_by_obj(const char *obj, const char *name, GElf_Sym *sym)
{
	return (mdb_tgt_lookup_by_name(mdb.m_target, obj, name, sym, NULL));
}

int
mdb_lookup_by_addr(uintptr_t addr, uint_t flags, char *buf,
	size_t nbytes, GElf_Sym *sym)
{
	return (mdb_tgt_lookup_by_addr(mdb.m_target, addr, flags,
	    buf, nbytes, sym, NULL));
}

int
mdb_getareg(mdb_tid_t tid, const char *rname, mdb_reg_t *rp)
{
	return (mdb_tgt_getareg(mdb.m_target, tid, rname, rp));
}

u_longlong_t
mdb_strtoull(const char *s)
{
	int radix = mdb.m_radix;

	if (s[0] == '0') {
		switch (s[1]) {
		case 'I':
		case 'i':
			radix = 2;
			s += 2;
			break;
		case 'O':
		case 'o':
			radix = 8;
			s += 2;
			break;
		case 'T':
		case 't':
			radix = 10;
			s += 2;
			break;
		case 'X':
		case 'x':
			radix = 16;
			s += 2;
			break;
		}
	}

	return (strtonum(s, radix));
}

size_t
mdb_snprintf(char *buf, size_t nbytes, const char *format, ...)
{
	va_list alist;

	va_start(alist, format);
	nbytes = mdb_iob_vsnprintf(buf, nbytes, format, alist);
	va_end(alist);

	return (nbytes);
}

void
mdb_printf(const char *format, ...)
{
	va_list alist;

	va_start(alist, format);
	mdb_iob_vprintf(mdb.m_out, format, alist);
	va_end(alist);
}

void
mdb_warn(const char *format, ...)
{
	va_list alist;

	va_start(alist, format);
	vwarn(format, alist);
	va_end(alist);
}

void
mdb_flush(void)
{
	mdb_iob_flush(mdb.m_out);
}

/*
 * Convert an object of len bytes pointed to by srcraw between
 * network-order and host-order and store in dstraw.  The length len must
 * be the actual length of the objects pointed to by srcraw and dstraw (or
 * zero) or the results are undefined.  srcraw and dstraw may be the same,
 * in which case the object is converted in-place.  Note that this routine
 * will convert from host-order to network-order or network-order to
 * host-order, since the conversion is the same in either case.
 */
/* ARGSUSED */
void
mdb_nhconvert(void *dstraw, const void *srcraw, size_t len)
{
#ifdef	_LITTLE_ENDIAN
	uint8_t	b1, b2;
	uint8_t *dst, *src;
	size_t i;

	dst = (uint8_t *)dstraw;
	src = (uint8_t *)srcraw;
	for (i = 0; i < len / 2; i++) {
		b1 = src[i];
		b2 = src[len - i - 1];
		dst[i] = b2;
		dst[len - i - 1] = b1;
	}
#else
	if (dstraw != srcraw)
		bcopy(srcraw, dstraw, len);
#endif
}


/*
 * Bit formatting functions: Note the interesting use of UM_GC here to
 * allocate a buffer for the caller which will be automatically freed
 * when the dcmd completes or is forcibly aborted.
 */

#define	NBNB			(NBBY / 2)	/* number of bits per nibble */
#define	SETBIT(buf, j, c) { \
	if (((j) + 1) % (NBNB + 1) == 0) \
		(buf)[(j)++] = ' '; \
	(buf)[(j)++] = (c); \
}

const char *
mdb_one_bit(int width, int bit, int on)
{
	int i, j = 0;
	char *buf;

	buf = mdb_zalloc(width + (width / NBNB) + 2, UM_GC | UM_SLEEP);

	for (i = --width; i > bit; i--)
		SETBIT(buf, j, '.');

	SETBIT(buf, j, on ? '1' : '0');

	for (i = bit - 1; i >= 0; i--)
		SETBIT(buf, j, '.');

	return (buf);
}

const char *
mdb_inval_bits(int width, int start, int stop)
{
	int i, j = 0;
	char *buf;

	buf = mdb_zalloc(width + (width / NBNB) + 2, UM_GC | UM_SLEEP);

	for (i = --width; i > stop; i--)
		SETBIT(buf, j, '.');

	for (i = stop; i >= start; i--)
		SETBIT(buf, j, 'x');

	for (; i >= 0; i--)
		SETBIT(buf, j, '.');

	return (buf);
}

ulong_t
mdb_inc_indent(ulong_t i)
{
	if (mdb_iob_getflags(mdb.m_out) & MDB_IOB_INDENT) {
		ulong_t margin = mdb_iob_getmargin(mdb.m_out);
		mdb_iob_margin(mdb.m_out, margin + i);
		return (margin);
	}

	mdb_iob_margin(mdb.m_out, i);
	mdb_iob_setflags(mdb.m_out, MDB_IOB_INDENT);
	return (0);
}

ulong_t
mdb_dec_indent(ulong_t i)
{
	if (mdb_iob_getflags(mdb.m_out) & MDB_IOB_INDENT) {
		ulong_t margin = mdb_iob_getmargin(mdb.m_out);

		if (margin < i || margin - i == 0) {
			mdb_iob_clrflags(mdb.m_out, MDB_IOB_INDENT);
			mdb_iob_margin(mdb.m_out, MDB_IOB_DEFMARGIN);
		} else
			mdb_iob_margin(mdb.m_out, margin - i);

		return (margin);
	}

	return (0);
}

int
mdb_eval(const char *s)
{
	mdb_frame_t *ofp = mdb.m_fmark;
	mdb_frame_t *fp = mdb.m_frame;
	int err;

	if (s == NULL)
		return (set_errno(EINVAL));

	/*
	 * Push m_in down onto the input stack, then set m_in to point to the
	 * i/o buffer for our command string, and reset the frame marker.
	 * The mdb_run() function returns when the new m_in iob reaches EOF.
	 */
	mdb_iob_stack_push(&fp->f_istk, mdb.m_in, yylineno);
	mdb.m_in = mdb_iob_create(mdb_strio_create(s), MDB_IOB_RDONLY);

	mdb.m_fmark = NULL;
	err = mdb_run();
	mdb.m_fmark = ofp;

	/*
	 * Now pop the old standard input stream and restore mdb.m_in and
	 * the parser's saved current line number.
	 */
	mdb.m_in = mdb_iob_stack_pop(&fp->f_istk);
	yylineno = mdb_iob_lineno(mdb.m_in);

	/*
	 * If mdb_run() returned an error, propagate this backward
	 * up the stack of debugger environment frames.
	 */
	if (MDB_ERR_IS_FATAL(err))
		longjmp(fp->f_pcb, err);

	if (err == MDB_ERR_PAGER || err == MDB_ERR_SIGINT)
		return (set_errno(EMDB_CANCEL));

	if (err != 0)
		return (set_errno(EMDB_EVAL));

	return (0);
}

void
mdb_set_dot(uintmax_t addr)
{
	mdb_nv_set_value(mdb.m_dot, addr);
	mdb.m_incr = 0;
}

uintmax_t
mdb_get_dot(void)
{
	return (mdb_nv_get_value(mdb.m_dot));
}

static int
walk_step(mdb_wcb_t *wcb)
{
	mdb_wcb_t *nwcb = wcb->w_lyr_head;
	int status;

	/*
	 * If the control block has no layers, we just invoke the walker's
	 * step function and return status indicating whether to continue
	 * or stop.  If the control block has layers, we need to invoke
	 * ourself recursively for the next layer, until eventually we
	 * percolate down to an unlayered walk.
	 */
	if (nwcb == NULL)
		return (wcb->w_walker->iwlk_step(&wcb->w_state));

	if ((status = walk_step(nwcb)) != WALK_NEXT) {
		wcb->w_lyr_head = nwcb->w_lyr_link;
		nwcb->w_lyr_link = NULL;
		mdb_wcb_destroy(nwcb);
	}

	if (status == WALK_DONE && wcb->w_lyr_head != NULL)
		return (WALK_NEXT);

	return (status);
}

static int
walk_common(mdb_wcb_t *wcb)
{
	int status, rval = 0;
	mdb_frame_t *pfp;

	/*
	 * Enter the control block in the active list so that mdb can clean
	 * up after it in case we abort out of the current command.
	 */
	if ((pfp = mdb_list_prev(mdb.m_frame)) != NULL && pfp->f_pcmd != NULL)
		mdb_wcb_insert(wcb, pfp);
	else
		mdb_wcb_insert(wcb, mdb.m_frame);

	/*
	 * The per-walk constructor performs private buffer initialization
	 * and locates whatever symbols are necessary.
	 */
	if ((status = wcb->w_walker->iwlk_init(&wcb->w_state)) != WALK_NEXT) {
		if (status != WALK_DONE)
			rval = set_errno(EMDB_WALKINIT);
		goto done;
	}

	/*
	 * Mark wcb to indicate that walk_init has been called (which means
	 * we can call walk_fini if the walk is aborted at this point).
	 */
	wcb->w_inited = TRUE;

	while (walk_step(wcb) == WALK_NEXT)
		continue;
done:
	if ((pfp = mdb_list_prev(mdb.m_frame)) != NULL && pfp->f_pcmd != NULL)
		mdb_wcb_delete(wcb, pfp);
	else
		mdb_wcb_delete(wcb, mdb.m_frame);

	mdb_wcb_destroy(wcb);
	return (rval);
}

typedef struct pwalk_step {
	mdb_walk_cb_t ps_cb;
	void *ps_private;
} pwalk_step_t;

static int
pwalk_step(uintptr_t addr, const void *data, void *private)
{
	pwalk_step_t *psp = private;
	int ret;

	mdb.m_frame->f_cbactive = B_TRUE;
	ret = psp->ps_cb(addr, data, psp->ps_private);
	mdb.m_frame->f_cbactive = B_FALSE;

	return (ret);
}

int
mdb_pwalk(const char *name, mdb_walk_cb_t func, void *private, uintptr_t addr)
{
	mdb_iwalker_t *iwp = mdb_walker_lookup(name);
	pwalk_step_t p;

	if (func == NULL)
		return (set_errno(EINVAL));

	p.ps_cb = func;
	p.ps_private = private;

	if (iwp != NULL) {
		int ret;
		int cbactive = mdb.m_frame->f_cbactive;
		mdb.m_frame->f_cbactive = B_FALSE;
		ret = walk_common(mdb_wcb_create(iwp, pwalk_step, &p, addr));
		mdb.m_frame->f_cbactive = cbactive;
		return (ret);
	}

	return (-1); /* errno is set for us */
}

int
mdb_walk(const char *name, mdb_walk_cb_t func, void *data)
{
	return (mdb_pwalk(name, func, data, NULL));
}

/*ARGSUSED*/
static int
walk_dcmd(uintptr_t addr, const void *ignored, dcmd_walk_arg_t *dwp)
{
	int status;

	mdb.m_frame->f_cbactive = B_TRUE;
	status = mdb_call_idcmd(dwp->dw_dcmd, addr, 1, dwp->dw_flags,
	    &dwp->dw_argv, NULL, NULL);
	mdb.m_frame->f_cbactive = B_FALSE;

	if (status == DCMD_USAGE || status == DCMD_ABORT)
		return (WALK_ERR);

	dwp->dw_flags &= ~DCMD_LOOPFIRST;
	return (WALK_NEXT);
}

int
mdb_pwalk_dcmd(const char *wname, const char *dcname,
    int argc, const mdb_arg_t *argv, uintptr_t addr)
{
	mdb_argvec_t args;
	dcmd_walk_arg_t dw;
	mdb_iwalker_t *iwp;
	mdb_wcb_t *wcb;
	int status;

	if (wname == NULL || dcname == NULL)
		return (set_errno(EINVAL));

	if ((dw.dw_dcmd = mdb_dcmd_lookup(dcname)) == NULL)
		return (-1); /* errno is set for us */

	if ((iwp = mdb_walker_lookup(wname)) == NULL)
		return (-1); /* errno is set for us */

	args.a_data = (mdb_arg_t *)argv;
	args.a_nelems = args.a_size = argc;

	mdb_argvec_create(&dw.dw_argv);
	mdb_argvec_copy(&dw.dw_argv, &args);
	dw.dw_flags = DCMD_LOOP | DCMD_LOOPFIRST | DCMD_ADDRSPEC;

	wcb = mdb_wcb_create(iwp, (mdb_walk_cb_t)walk_dcmd, &dw, addr);
	status = walk_common(wcb);

	mdb_argvec_zero(&dw.dw_argv);
	mdb_argvec_destroy(&dw.dw_argv);

	return (status);
}

int
mdb_walk_dcmd(const char *wname, const char *dcname,
    int argc, const mdb_arg_t *argv)
{
	return (mdb_pwalk_dcmd(wname, dcname, argc, argv, NULL));
}

/*ARGSUSED*/
static int
layered_walk_step(uintptr_t addr, const void *data, mdb_wcb_t *wcb)
{
	/*
	 * Prior to calling the top-level walker's step function, reset its
	 * mdb_walk_state_t walk_addr and walk_layer members to refer to the
	 * target virtual address and data buffer of the underlying object.
	 */
	wcb->w_state.walk_addr = addr;
	wcb->w_state.walk_layer = data;

	return (wcb->w_walker->iwlk_step(&wcb->w_state));
}

int
mdb_layered_walk(const char *wname, mdb_walk_state_t *wsp)
{
	mdb_wcb_t *cwcb, *wcb;
	mdb_iwalker_t *iwp;

	if (wname == NULL || wsp == NULL)
		return (set_errno(EINVAL));

	if ((iwp = mdb_walker_lookup(wname)) == NULL)
		return (-1); /* errno is set for us */

	if ((cwcb = mdb_wcb_from_state(wsp)) == NULL)
		return (set_errno(EMDB_BADWCB));

	if (cwcb->w_walker == iwp)
		return (set_errno(EMDB_WALKLOOP));

	wcb = mdb_wcb_create(iwp, (mdb_walk_cb_t)layered_walk_step,
	    cwcb, wsp->walk_addr);

	if (iwp->iwlk_init(&wcb->w_state) != WALK_NEXT) {
		mdb_wcb_destroy(wcb);
		return (set_errno(EMDB_WALKINIT));
	}

	wcb->w_inited = TRUE;

	mdb_dprintf(MDB_DBG_WALK, "added %s`%s as %s`%s layer\n",
	    iwp->iwlk_modp->mod_name, iwp->iwlk_name,
	    cwcb->w_walker->iwlk_modp->mod_name, cwcb->w_walker->iwlk_name);

	if (cwcb->w_lyr_head != NULL) {
		for (cwcb = cwcb->w_lyr_head; cwcb->w_lyr_link != NULL; )
			cwcb = cwcb->w_lyr_link;
		cwcb->w_lyr_link = wcb;
	} else
		cwcb->w_lyr_head = wcb;

	return (0);
}

int
mdb_call_dcmd(const char *name, uintptr_t dot, uint_t flags,
    int argc, const mdb_arg_t *argv)
{
	mdb_idcmd_t *idcp;
	mdb_argvec_t args;
	int status;

	if (name == NULL || argc < 0)
		return (set_errno(EINVAL));

	if ((idcp = mdb_dcmd_lookup(name)) == NULL)
		return (-1); /* errno is set for us */

	args.a_data = (mdb_arg_t *)argv;
	args.a_nelems = args.a_size = argc;
	status = mdb_call_idcmd(idcp, dot, 1, flags, &args, NULL, NULL);

	if (status == DCMD_ERR || status == DCMD_ABORT)
		return (set_errno(EMDB_DCFAIL));

	if (status == DCMD_USAGE)
		return (set_errno(EMDB_DCUSAGE));

	return (0);
}

int
mdb_add_walker(const mdb_walker_t *wp)
{
	mdb_module_t *mp;

	if (mdb.m_lmod == NULL) {
		mdb_cmd_t *cp = mdb.m_frame->f_cp;
		mp = cp->c_dcmd->idc_modp;
	} else
		mp = mdb.m_lmod;

	return (mdb_module_add_walker(mp, wp, 0));
}

int
mdb_remove_walker(const char *name)
{
	mdb_module_t *mp;

	if (mdb.m_lmod == NULL) {
		mdb_cmd_t *cp = mdb.m_frame->f_cp;
		mp = cp->c_dcmd->idc_modp;
	} else
		mp = mdb.m_lmod;

	return (mdb_module_remove_walker(mp, name));
}

void
mdb_get_pipe(mdb_pipe_t *p)
{
	mdb_cmd_t *cp = mdb.m_frame->f_cp;
	mdb_addrvec_t *adp = &cp->c_addrv;

	if (p == NULL) {
		warn("dcmd failure: mdb_get_pipe invoked with NULL pointer\n");
		longjmp(mdb.m_frame->f_pcb, MDB_ERR_API);
	}

	if (adp->ad_nelems != 0) {
		ASSERT(adp->ad_ndx != 0);
		p->pipe_data = &adp->ad_data[adp->ad_ndx - 1];
		p->pipe_len = adp->ad_nelems - adp->ad_ndx + 1;
		adp->ad_ndx = adp->ad_nelems;
	} else {
		p->pipe_data = NULL;
		p->pipe_len = 0;
	}
}

void
mdb_set_pipe(const mdb_pipe_t *p)
{
	mdb_cmd_t *cp = mdb.m_frame->f_pcmd;

	if (p == NULL) {
		warn("dcmd failure: mdb_set_pipe invoked with NULL pointer\n");
		longjmp(mdb.m_frame->f_pcb, MDB_ERR_API);
	}

	if (cp != NULL) {
		size_t nbytes = sizeof (uintptr_t) * p->pipe_len;

		mdb_cmd_reset(cp);
		cp->c_addrv.ad_data = mdb_alloc(nbytes, UM_SLEEP);
		bcopy(p->pipe_data, cp->c_addrv.ad_data, nbytes);
		cp->c_addrv.ad_nelems = p->pipe_len;
		cp->c_addrv.ad_size = p->pipe_len;
	}
}

ssize_t
mdb_get_xdata(const char *name, void *buf, size_t nbytes)
{
	return (mdb_tgt_getxdata(mdb.m_target, name, buf, nbytes));
}

/*
 * Private callback structure for implementing mdb_object_iter, below.
 */
typedef struct {
	mdb_object_cb_t oi_cb;
	void *oi_arg;
	int oi_rval;
} object_iter_arg_t;

/*ARGSUSED*/
static int
mdb_object_cb(void *data, const mdb_map_t *map, const char *fullname)
{
	object_iter_arg_t *arg = data;
	mdb_object_t obj;

	if (arg->oi_rval != 0)
		return (0);

	bzero(&obj, sizeof (obj));
	obj.obj_base = map->map_base;
	obj.obj_name = strbasename(map->map_name);
	obj.obj_size = map->map_size;
	obj.obj_fullname = fullname;

	arg->oi_rval = arg->oi_cb(&obj, arg->oi_arg);

	return (0);
}

int
mdb_object_iter(mdb_object_cb_t cb, void *data)
{
	object_iter_arg_t arg;

	arg.oi_cb = cb;
	arg.oi_arg = data;
	arg.oi_rval = 0;

	if (mdb_tgt_object_iter(mdb.m_target, mdb_object_cb, &arg) != 0)
		return (-1);

	return (arg.oi_rval);
}

/*
 * Private callback structure for implementing mdb_symbol_iter, below.
 */
typedef struct {
	mdb_symbol_cb_t si_cb;
	void *si_arg;
	int si_rval;
} symbol_iter_arg_t;

/*ARGSUSED*/
static int
mdb_symbol_cb(void *data, const GElf_Sym *gsym, const char *name,
    const mdb_syminfo_t *sip, const char *obj)
{
	symbol_iter_arg_t *arg = data;
	mdb_symbol_t sym;

	if (arg->si_rval != 0)
		return (0);

	bzero(&sym, sizeof (sym));
	sym.sym_name = name;
	sym.sym_object = obj;
	sym.sym_sym = gsym;
	sym.sym_table = sip->sym_table;
	sym.sym_id = sip->sym_id;

	arg->si_rval = arg->si_cb(&sym, arg->si_arg);

	return (0);
}

int
mdb_symbol_iter(const char *obj, uint_t which, uint_t type,
    mdb_symbol_cb_t cb, void *data)
{
	symbol_iter_arg_t arg;

	arg.si_cb = cb;
	arg.si_arg = data;
	arg.si_rval = 0;

	if (mdb_tgt_symbol_iter(mdb.m_target, obj, which, type,
	    mdb_symbol_cb, &arg) != 0)
		return (-1);

	return (arg.si_rval);
}

/*
 * Private structure and function for implementing mdb_dumpptr on top
 * of mdb_dump_internal
 */
typedef struct dptrdat {
	mdb_dumpptr_cb_t func;
	void *arg;
} dptrdat_t;

static ssize_t
mdb_dump_aux_ptr(void *buf, size_t nbyte, uint64_t offset, void *arg)
{
	dptrdat_t *dat = arg;

	return (dat->func(buf, nbyte, offset, dat->arg));
}

/*
 * Private structure and function for handling callbacks which return
 * EMDB_PARTIAL
 */
typedef struct d64dat {
	mdb_dump64_cb_t func;
	void *arg;
} d64dat_t;

static ssize_t
mdb_dump_aux_partial(void *buf, size_t nbyte, uint64_t offset, void *arg)
{
	d64dat_t *dat = arg;
	int result;
	int count;

	result = dat->func(buf, nbyte, offset, dat->arg);
	if (result == -1 && errno == EMDB_PARTIAL) {
		count = 0;
		do {
			result = dat->func((char *)buf + count, 1,
			    offset + count, dat->arg);
			if (result == 1)
				count++;
		} while (count < nbyte && result == 1);
		if (count)
			result = count;
	}

	return (result);
}

int
mdb_dumpptr(uintptr_t addr, size_t len, uint_t flags, mdb_dumpptr_cb_t fp,
    void *arg)
{
	dptrdat_t dat;
	d64dat_t dat64;

	dat.func = fp;
	dat.arg = arg;
	dat64.func = mdb_dump_aux_ptr;
	dat64.arg = &dat;
	return (mdb_dump_internal(addr, len, flags, mdb_dump_aux_partial,
	    &dat64, sizeof (uintptr_t)));
}

int
mdb_dump64(uint64_t addr, uint64_t len, uint_t flags, mdb_dump64_cb_t fp,
    void *arg)
{
	d64dat_t dat64;

	dat64.func = fp;
	dat64.arg = arg;
	return (mdb_dump_internal(addr, len, flags, mdb_dump_aux_partial,
	    &dat64, sizeof (uint64_t)));
}

int
mdb_get_state(void)
{
	mdb_tgt_status_t ts;

	(void) mdb_tgt_status(mdb.m_target, &ts);

	return (ts.st_state);
}

void *
mdb_callback_add(int class, mdb_callback_f fp, void *arg)
{
	mdb_module_t *m;

	if (class != MDB_CALLBACK_STCHG && class != MDB_CALLBACK_PROMPT) {
		(void) set_errno(EINVAL);
		return (NULL);
	}

	if (mdb.m_lmod != NULL)
		m = mdb.m_lmod;
	else
		m = mdb.m_frame->f_cp->c_dcmd->idc_modp;

	return (mdb_callb_add(m, class, fp, arg));
}

void
mdb_callback_remove(void *hdl)
{
	mdb_callb_remove(hdl);
}
