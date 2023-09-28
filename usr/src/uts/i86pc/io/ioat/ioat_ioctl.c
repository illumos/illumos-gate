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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/modctl.h>
#include <sys/ddi_impldefs.h>
#include <sys/sysmacros.h>

#include <vm/hat.h>
#include <vm/as.h>

#include <sys/ioat.h>


extern void *ioat_statep;
#define	ptob64(x)	(((uint64_t)(x)) << PAGESHIFT)

static int ioat_ioctl_rdreg(ioat_state_t *state, void *arg, int mode);
#ifdef	DEBUG
static int ioat_ioctl_wrreg(ioat_state_t *state, void *arg, int mode);
static int ioat_ioctl_test(ioat_state_t *state, void *arg, int mode);
#endif

/*
 * ioat_ioctl()
 */
/*ARGSUSED*/
int
ioat_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred, int *rval)
{
	ioat_state_t *state;
	int instance;
	int e;


	e = drv_priv(cred);
	if (e != 0) {
		return (EPERM);
	}
	instance = getminor(dev);
	if (instance == -1) {
		return (EBADF);
	}
	state = ddi_get_soft_state(ioat_statep, instance);
	if (state == NULL) {
		return (EBADF);
	}

	switch (cmd) {
	case IOAT_IOCTL_READ_REG:
		e = ioat_ioctl_rdreg(state, (void *)arg, mode);
		break;
#ifdef	DEBUG
	case IOAT_IOCTL_WRITE_REG:
		e = ioat_ioctl_wrreg(state, (void *)arg, mode);
		break;
	case IOAT_IOCTL_TEST:
		e = ioat_ioctl_test(state, (void *)arg, mode);
		break;
#endif

	default:
		e = ENXIO;
	}

	return (e);
}


/*
 * ioat_ioctl_rdreg()
 */
static int
ioat_ioctl_rdreg(ioat_state_t *state, void *arg, int mode)
{
	ioat_ioctl_rdreg_t rdreg;
	int e;


	e = ddi_copyin(arg, &rdreg, sizeof (ioat_ioctl_rdreg_t), mode);
	if (e != 0) {
		return (EFAULT);
	}

	/*
	 * read a device register, where size is read size in bits, addr is
	 * the offset into MMIO registers.
	 */
	switch (rdreg.size) {
	case 8:
		rdreg.data = (uint64_t)ddi_get8(state->is_reg_handle,
		    (uint8_t *)&state->is_genregs[rdreg.addr]);
		break;
	case 16:
		rdreg.data = (uint64_t)ddi_get16(state->is_reg_handle,
		    (uint16_t *)&state->is_genregs[rdreg.addr]);
		break;
	case 32:
		rdreg.data = (uint64_t)ddi_get32(state->is_reg_handle,
		    (uint32_t *)&state->is_genregs[rdreg.addr]);
		break;
	case 64:
		rdreg.data = (uint64_t)ddi_get64(state->is_reg_handle,
		    (uint64_t *)&state->is_genregs[rdreg.addr]);
		break;
	default:
		return (EFAULT);
	}

	e = ddi_copyout(&rdreg, arg, sizeof (ioat_ioctl_rdreg_t), mode);
	if (e != 0) {
		return (EFAULT);
	}

	return (0);
}


#ifdef	DEBUG
/*
 * ioat_ioctl_wrreg()
 */
static int
ioat_ioctl_wrreg(ioat_state_t *state, void *arg, int mode)
{
	ioat_ioctl_wrreg_t wrreg;
	int e;


	e = ddi_copyin(arg, &wrreg, sizeof (ioat_ioctl_wrreg_t), mode);
	if (e != 0) {
		return (EFAULT);
	}

	/*
	 * write a device register, where size is write size in bits, addr is
	 * the offset into MMIO registers.
	 */
	switch (wrreg.size) {
	case 8:
		ddi_put8(state->is_reg_handle,
		    (uint8_t *)&state->is_genregs[wrreg.addr],
		    (uint8_t)wrreg.data);
		break;
	case 16:
		ddi_put16(state->is_reg_handle,
		    (uint16_t *)&state->is_genregs[wrreg.addr],
		    (uint16_t)wrreg.data);
		break;
	case 32:
		ddi_put32(state->is_reg_handle,
		    (uint32_t *)&state->is_genregs[wrreg.addr],
		    (uint32_t)wrreg.data);
		break;
	case 64:
		ddi_put64(state->is_reg_handle,
		    (uint64_t *)&state->is_genregs[wrreg.addr],
		    (uint64_t)wrreg.data);
		break;
	default:
		return (EFAULT);
	}

	return (0);
}


/*
 * ioat_ioctl_test()
 */
/*ARGSUSED*/
static int
ioat_ioctl_test(ioat_state_t *state, void *arg, int mode)
{
	dcopy_handle_t channel;
	dcopy_cmd_t cmd;
	uint8_t *source;
	uint_t buf_size;
	uint_t poll_cnt;
	uint8_t *dest;
	uint8_t *buf;
	int flags;
	int i;
	int e;


	/* allocate 2 paged aligned 4k pages */
	buf_size = 0x1000;
	buf = kmem_zalloc((buf_size * 2) + 0x1000, KM_SLEEP);
	source = (uint8_t *)(((uintptr_t)buf + PAGEOFFSET) & PAGEMASK);
	dest = source + buf_size;

	/* Init source buffer */
	for (i = 0; i < buf_size; i++) {
		source[i] = (uint8_t)(i & 0xFF);
	}

	/* allocate a DMA channel */
	e = dcopy_alloc(DCOPY_SLEEP, &channel);
	if (e != DCOPY_SUCCESS) {
		cmn_err(CE_CONT, "dcopy_alloc() failed\n");
		goto testfail_alloc;
	}

	/*
	 * post 32 DMA copy's from dest to dest.  These will complete in order
	 * so they won't stomp on each other. We don't care about the data
	 * right now which is why we go dest to dest.
	 */
	flags = DCOPY_SLEEP;
	for (i = 0; i < 32; i++) {
		/*
		 * if this is the second command, link the commands from here
		 * on out. We only want to keep track of the last command. We
		 * will poll on the last command completing (which infers that
		 * the other commands completed). If any of the previous
		 * commands fail, so will the last one. Linking the commands
		 * also allows us to only call free for the last command. free
		 * will free up the entire chain of commands.
		 */
		if (i == 1) {
			flags |= DCOPY_ALLOC_LINK;
		}
		e = dcopy_cmd_alloc(channel, flags, &cmd);
		if (e != DCOPY_SUCCESS) {
			cmn_err(CE_CONT, "dcopy_cmd_alloc() failed\n");
			goto testfail_alloc;
		}

		ASSERT(cmd->dp_version == DCOPY_CMD_V0);
		cmd->dp_cmd = DCOPY_CMD_COPY;
		cmd->dp_flags = DCOPY_CMD_NOFLAGS;

		/* do a bunch of dest to dest DMA's */
		cmd->dp.copy.cc_source = ptob64(hat_getpfnum(kas.a_hat,
		    (caddr_t)source)) + ((uintptr_t)dest & PAGEOFFSET);
		cmd->dp.copy.cc_dest = ptob64(hat_getpfnum(kas.a_hat,
		    (caddr_t)dest)) + ((uintptr_t)dest & PAGEOFFSET);
		cmd->dp.copy.cc_size = PAGESIZE;

		e = dcopy_cmd_post(cmd);
		if (e != DCOPY_SUCCESS) {
			cmn_err(CE_CONT, "dcopy_post() failed\n");
			goto testfail_post;
		}
	}

	e = dcopy_cmd_alloc(channel, flags, &cmd);
	if (e != DCOPY_SUCCESS) {
		cmn_err(CE_CONT, "dcopy_cmd_alloc() failed\n");
		goto testfail_alloc;
	}

	/* now queue up the DMA we are going to check status and data for  */
	cmd->dp_cmd = DCOPY_CMD_COPY;
	cmd->dp_flags = DCOPY_CMD_INTR;
	cmd->dp.copy.cc_source = ptob64(hat_getpfnum(kas.a_hat,
	    (caddr_t)source)) + ((uintptr_t)source & PAGEOFFSET);
	cmd->dp.copy.cc_dest = ptob64(hat_getpfnum(kas.a_hat,
	    (caddr_t)dest)) + ((uintptr_t)dest & PAGEOFFSET);
	cmd->dp.copy.cc_size = PAGESIZE;
	e = dcopy_cmd_post(cmd);
	if (e != DCOPY_SUCCESS) {
		cmn_err(CE_CONT, "dcopy_post() failed\n");
		goto testfail_post;
	}

	/* check the status of the last command */
	poll_cnt = 0;
	flags = DCOPY_POLL_NOFLAGS;
	while ((e = dcopy_cmd_poll(cmd, flags)) == DCOPY_PENDING) {
		poll_cnt++;
		if (poll_cnt >= 16) {
			flags |= DCOPY_POLL_BLOCK;
		}
	}
	if (e != DCOPY_COMPLETED) {
		cmn_err(CE_CONT, "dcopy_poll() failed\n");
		goto testfail_poll;
	}

	/* since the cmd's are linked we only need to pass in the last cmd */
	dcopy_cmd_free(&cmd);
	dcopy_free(&channel);

	/* verify the data */
	for (i = 0; i < PAGESIZE; i++) {
		if (dest[i] != (uint8_t)(i & 0xFF)) {
			cmn_err(CE_CONT,
			    "dcopy_data_compare() failed, %p[%d]: %x, %x\n",
			    (void *)dest, i, dest[i], i & 0xFF);
			return (-1);
		}
	}

	kmem_free(buf, (buf_size * 2) + 0x1000);

	return (0);

testfail_poll:
testfail_post:
	dcopy_cmd_free(&cmd);
	dcopy_free(&channel);
testfail_alloc:
	kmem_free(buf, (buf_size * 2) + 0x1000);

	return (-1);
}
#endif
