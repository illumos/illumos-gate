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

/*
 * SD card common framework.  This module provides most of the common
 * functionality so that SecureDigital host adapters and client devices
 * (such as the sdcard driver) can share common code.
 *
 * NB that this file contains a fair bit of non-DDI compliant code.
 * But writing a nexus driver would be impossible to do with only DDI
 * compliant interfaces.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sdcard/sda_impl.h>

/*
 * Types and Structures.
 */

typedef struct sda_cmd_impl {
	struct sda_cmd	c_public;

	/*
	 * Implementation private stuff.
	 */
	sda_slot_t	*c_slot;
	kmutex_t	c_lock;
	kcondvar_t	c_cv;
	list_node_t	c_list;
	sda_err_t	c_errno;

	sda_index_t	c_acmd;		/* saved acmd */
	sda_rtype_t	c_artype;	/* saved rtype */
	uint32_t	c_aarg;		/* saved argument */

	void		(*c_done)(struct sda_cmd *);
	void		*c_private;
} sda_cmd_impl_t;

#define	c_index		c_public.sc_index
#define	c_argument	c_public.sc_argument
#define	c_rtype		c_public.sc_rtype
#define	c_response	c_public.sc_response
#define	c_blksz		c_public.sc_blksz
#define	c_nblks		c_public.sc_nblks
#define	c_resid		c_public.sc_resid
#define	c_flags		c_public.sc_flags
#define	c_ndmac		c_public.sc_ndmac
#define	c_dmacs		c_public.sc_dmacs
#define	c_kvaddr	c_public.sc_kvaddr

/*
 * Local Prototypes.
 */

static void sda_cmd_wait(sda_cmd_t *);
static int sda_cmd_ctor(void *, void *, int);
static void sda_cmd_dtor(void *, void *);

/*
 * Static Variables.
 */

static kmem_cache_t *sda_cmd_cache;

/*
 * Macros.
 */

#define	CIP(cmdp)	((sda_cmd_impl_t *)(void *)cmdp)

/*
 * Implementation.
 */

void
sda_cmd_init(void)
{
	sda_cmd_cache = kmem_cache_create("sda_cmd_cache",
	    sizeof (struct sda_cmd_impl), 0, sda_cmd_ctor, sda_cmd_dtor,
	    NULL, NULL, NULL, 0);
}

void
sda_cmd_fini(void)
{
	kmem_cache_destroy(sda_cmd_cache);
}

void
sda_cmd_list_init(list_t *list)
{
	list_create(list, sizeof (struct sda_cmd_impl),
	    offsetof(struct sda_cmd_impl, c_list));
}

void
sda_cmd_list_fini(list_t *list)
{
	list_destroy(list);
}

/*ARGSUSED1*/
int
sda_cmd_ctor(void *cbuf, void *arg, int kmflags)
{
	sda_cmd_impl_t	*c = cbuf;

	mutex_init(&c->c_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&c->c_cv, NULL, CV_DRIVER, NULL);
	return (0);
}

/*ARGSUSED1*/
void
sda_cmd_dtor(void *cbuf, void *arg)
{
	sda_cmd_impl_t	*c = cbuf;

	cv_destroy(&c->c_cv);
	mutex_destroy(&c->c_lock);
}

void *
sda_cmd_data(sda_cmd_t *cmdp)
{
	return (CIP(cmdp)->c_private);
}

sda_err_t
sda_cmd_errno(sda_cmd_t *cmdp)
{
	return (CIP(cmdp)->c_errno);
}

void
sda_cmd_notify(sda_cmd_t *cmdp, uint16_t flags, sda_err_t errno)
{
	sda_cmd_impl_t	*c = CIP(cmdp);

	/*
	 * Now we need to make sure that we wake anyone waiting on this
	 * command to complete, if it is complete.
	 */
	mutex_enter(&c->c_lock);
	c->c_flags &= ~(flags);
	/*
	 * Don't overwrite an earlier error.
	 */
	if (c->c_errno == SDA_EOK) {
		c->c_errno = errno;
	}
	if ((c->c_flags & (SDA_CMDF_BUSY | SDA_CMDF_DAT)) == 0) {

		if (c->c_done != NULL) {
			mutex_exit(&c->c_lock);
			c->c_done(cmdp);
		} else {
			cv_broadcast(&c->c_cv);
			mutex_exit(&c->c_lock);
		}
	} else {
		mutex_exit(&c->c_lock);
	}
}

void
sda_cmd_wait(sda_cmd_t *cmdp)
{
	sda_cmd_impl_t	*c = CIP(cmdp);

	mutex_enter(&c->c_lock);
	while ((c->c_flags & (SDA_CMDF_BUSY | SDA_CMDF_DAT)) != 0)
		cv_wait(&c->c_cv, &c->c_lock);
	mutex_exit(&c->c_lock);
}

void
sda_cmd_submit(sda_slot_t *slot, sda_cmd_t *cmdp, void (*done)(sda_cmd_t *))
{
	sda_cmd_impl_t	*c = CIP(cmdp);
	sda_err_t	errno = 0;

	mutex_enter(&c->c_lock);
	c->c_done = done;
	c->c_flags |= SDA_CMDF_BUSY;
	mutex_exit(&c->c_lock);

	sda_slot_enter(slot);

	/* checks for cases where the slot can't accept the command */
	if (slot->s_failed) {
		errno = SDA_EFAULT;
	}
	if (!slot->s_inserted) {
		errno = SDA_ENODEV;
	}
	if (errno != SDA_EOK) {
		sda_slot_exit(slot);
		/* fail it synchronously */
		sda_cmd_notify(cmdp, SDA_CMDF_DAT | SDA_CMDF_BUSY, errno);
		return;
	}

	list_insert_tail(&slot->s_cmdlist, c);
	sda_slot_exit(slot);

	sda_slot_wakeup(slot);
}

void
sda_cmd_resubmit_acmd(sda_slot_t *slot, sda_cmd_t *cmdp)
{
	sda_cmd_impl_t	*c = CIP(cmdp);

	ASSERT(sda_slot_owned(slot));

	c->c_index = c->c_acmd;
	c->c_argument = c->c_aarg;
	c->c_rtype = c->c_artype;
	c->c_acmd = 0;

	list_insert_head(&slot->s_cmdlist, c);
}

sda_cmd_t *
sda_cmd_alloc(sda_slot_t *slot, sda_index_t index, uint32_t argument,
    sda_rtype_t rtype, void *data, int kmflag)
{
	sda_cmd_impl_t	*c;

	c = kmem_cache_alloc(sda_cmd_cache, kmflag);
	if (c == NULL) {
		return (NULL);
	}
	c->c_index = index;
	c->c_rtype = rtype;
	c->c_argument = argument;
	c->c_resid = 0;
	c->c_nblks = 0;
	c->c_blksz = 0;

	c->c_kvaddr = 0;
	c->c_ndmac = 0;
	c->c_dmacs = NULL;
	c->c_flags = 0;

	c->c_slot = slot;
	c->c_errno = SDA_EOK;
	c->c_done = NULL;
	c->c_private = data;
	c->c_acmd = 0;

	return (&(c->c_public));
}

sda_cmd_t *
sda_cmd_alloc_acmd(sda_slot_t *slot, sda_index_t index, uint32_t argument,
    sda_rtype_t rtype, void *data, int kmflag)
{
	sda_cmd_impl_t	*c;

	c = kmem_cache_alloc(sda_cmd_cache, kmflag);
	if (c == NULL) {
		return (NULL);
	}
	c->c_index = CMD_APP_CMD;
	c->c_argument = index == ACMD_SD_SEND_OCR ? 0 : slot->s_rca << 16;
	c->c_rtype = R1;
	c->c_acmd = index;
	c->c_artype = rtype;
	c->c_aarg = argument;
	c->c_resid = 0;
	c->c_nblks = 0;
	c->c_blksz = 0;

	c->c_kvaddr = 0;
	c->c_ndmac = 0;
	c->c_dmacs = NULL;
	c->c_flags = 0;

	c->c_slot = slot;
	c->c_errno = SDA_EOK;
	c->c_done = NULL;
	c->c_private = data;

	return (&(c->c_public));
}

void
sda_cmd_free(sda_cmd_t *cmdp)
{
	kmem_cache_free(sda_cmd_cache, cmdp);
}

sda_err_t
sda_cmd_exec(sda_slot_t *slot, sda_cmd_t *cmdp, uint32_t *resp)
{
	int		errno;

	if ((cmdp->sc_rtype & Rb) || (cmdp->sc_nblks != 0)) {
		cmdp->sc_flags |= SDA_CMDF_DAT;
	}
	sda_cmd_submit(slot, cmdp,  NULL);

	sda_cmd_wait(cmdp);

	if (resp != NULL) {
		switch (cmdp->sc_rtype) {
		case R0:
			break;
		case R2:
			resp[0] = cmdp->sc_response[0];
			resp[1] = cmdp->sc_response[1];
			resp[2] = cmdp->sc_response[2];
			resp[3] = cmdp->sc_response[3];
			break;
		default:
			resp[0] = cmdp->sc_response[0];
			break;
		}
	}

	errno = CIP(cmdp)->c_errno;

	return (errno);
}
