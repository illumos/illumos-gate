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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<sys/param.h>
#include	<sys/types.h>
#include	<sys/user.h>
#include	<sys/vfs.h>
#include	<sys/vnode.h>
#include	<sys/file.h>
#include	<sys/stream.h>
#include	<sys/stropts.h>
#include	<sys/strsubr.h>
#include	<sys/dlpi.h>
#include	<sys/vnode.h>
#include	<sys/socket.h>
#include	<sys/sockio.h>
#include	<sys/cmn_err.h>
#include	<net/if.h>
#include	<sys/sad.h>
#include	<sys/kstr.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/sunldi.h>

#include	<sys/cred.h>
#include	<sys/sysmacros.h>

#include	<sys/modctl.h>

/*
 * Routines to allow strplumb() legitimate access
 * to the kernel.
 */
int
kstr_open(major_t maj, minor_t min, vnode_t **vpp, int *fd)
{
	vnode_t		*vp;
	int		error;

	vp = makespecvp(makedevice(maj, min), VCHR);

	/*
	 * Fix for 4170365: only allocate file descriptor entry
	 * if file descriptor is to be returned; otherwise VOP_OPEN.
	 */
	if (fd != NULL)
		error = fassign(&vp, FREAD|FWRITE, fd);
	else
		error = VOP_OPEN(&vp, FREAD|FWRITE, CRED(), NULL);

	/*
	 * Must set vpp after calling fassign()/VOP_OPEN()
	 * since `vp' might change if it's a clone driver.
	 */
	if (vpp != NULL)
		*vpp = vp;

	return (error);
}

int
kstr_plink(vnode_t *vp, int fd, int *mux_id)
{
	int	id;
	int	error;

	if (error = strioctl(vp, I_PLINK, (intptr_t)fd, 0, K_TO_K, CRED(), &id))
		return (error);
	if (mux_id)
		*mux_id = id;
	return (0);
}

int
kstr_unplink(vnode_t *vp, int mux_id)
{
	int	rval;

	return (strioctl(vp, I_PUNLINK, (intptr_t)mux_id, 0,
	    K_TO_K, CRED(), &rval));
}

int
kstr_push(vnode_t *vp, char *mod)
{
	int	rval;

	return (strioctl(vp, I_PUSH, (intptr_t)mod, 0, K_TO_K, CRED(), &rval));
}

int
kstr_pop(vnode_t *vp)
{
	int	rval;

	return (strioctl(vp, I_POP, 0, 0, K_TO_K, CRED(), &rval));
}

int
kstr_close(vnode_t *vp, int fd)
{
	int ret;

	if (vp == (vnode_t *)NULL && fd == -1)
		return (EINVAL);

	if (fd != -1) {
		if (closeandsetf(fd, NULL) == 0) {
			return (0);
		} else {
			return (EINVAL);
		}
	} else {
		ret = VOP_CLOSE(vp, FREAD|FWRITE, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(vp);
		return (ret);
	}
}

int
kstr_ioctl(struct vnode *vp, int cmd, intptr_t arg)
{
	int	rval;

	return (strioctl(vp, cmd, arg, 0, K_TO_K, CRED(), &rval));
}

/*
 * Optionally send data (if smp set) and optionally receive data (if rmp is
 * set). If timeo is NULL the reception will sleep until a message is
 * received; otherwise the sleep is limited to the specified amount of time.
 */
int
kstr_msg(vnode_t *vp, mblk_t *smp, mblk_t **rmp, timestruc_t *timeo)
{
	int			error;
	clock_t			timout;	/* milliseconds */
	uchar_t 		pri;
	int 			pflag;
	rval_t			rval;

	if (rmp == NULL && timeo != NULL &&
	    (timeo->tv_sec != 0 || timeo->tv_nsec != 0))
		return (EINVAL);

	if (smp == NULL && rmp == NULL)
		return (EINVAL);

	if (smp != NULL) {
		/* Send message while honoring flow control */
		(void) kstrputmsg(vp, smp, NULL, 0, 0,
		    MSG_BAND | MSG_HOLDSIG | MSG_IGNERROR, 0);
	}

	if (rmp == NULL) {
		/* No reply wanted by caller */
		return (0);
	}

	/*
	 * Convert from nanoseconds to milliseconds.
	 */
	if (timeo != NULL) {
		timout = timeo->tv_sec * 1000 + timeo->tv_nsec / 1000000;
		if (timout > INT_MAX)
			return (EINVAL);
	} else
		timout = -1;

	/* Wait for timeout millseconds for a message */
	pflag = MSG_ANY;
	pri = 0;
	*rmp = NULL;
	error = kstrgetmsg(vp, rmp, NULL, &pri, &pflag, timout, &rval);
	/* Callers use *rmp == NULL to determine that there was a timeout */
	if (error == ETIME)
		error = 0;
	return (error);
}

#define	SAD_ADM	"/devices/pseudo/sad@0:admin"
#define	SAD_USR	"/devices/pseudo/sad@0:user"

/*
 * It is the callers responsibility to make sure that "mods"
 * conforms to what is required. We do not check it here.
 *
 * "maj", "min", and "lastmin" are value-result parameters.
 * for SET_AUTOPUSH, "anchor" should be set to the place in the stream
 *	to put the anchor, or NULL if no anchor needs to be set.
 * for GET_AUTOPUSH, "anchor" should point to a uint_t to store the
 *	position of the anchor at, or NULL if the caller is not interested.
 */
int
kstr_autopush(int op, major_t *maj, minor_t *min, minor_t *lastmin,
    uint_t *anchor, char *mods[])
{
	ldi_handle_t	lh;
	ldi_ident_t	li;
	struct strapush	push;
	int		i, error, rval;

	li = ldi_ident_from_anon();
	if (op == SET_AUTOPUSH || op == CLR_AUTOPUSH) {
		error = ldi_open_by_name(SAD_ADM, FREAD|FWRITE,
		    kcred, &lh, li);
		if (error) {
			printf("kstr_autopush: open failed error %d\n", error);
			ldi_ident_release(li);
			return (error);
		}
	} else	{
		error = ldi_open_by_name(SAD_USR, FREAD|FWRITE,
		    kcred, &lh, li);
		if (error) {
			printf("kstr_autopush: open failed error %d\n", error);
			ldi_ident_release(li);
			return (error);
		}
	}
	ldi_ident_release(li);

	switch (op) {
	case GET_AUTOPUSH:
		/* Get autopush information */

		push.sap_major = *maj;
		push.sap_minor = *min;

		error = ldi_ioctl(lh, SAD_GAP, (intptr_t)&push,
		    FKIOCTL, kcred, &rval);
		if (error) {
			printf("kstr_autopush: "
			    "ioctl(GET_AUTOPUSH) failed, error %d\n", error);
			(void) ldi_close(lh, FREAD|FWRITE, kcred);
			return (error);
		}
		switch (push.sap_cmd) {
		case SAP_ONE:
			*maj = push.sap_major;
			*min = push.sap_minor;
			*lastmin = 0;
			break;

		case SAP_RANGE:
			*maj = push.sap_major;
			*min = push.sap_minor;
			*lastmin = push.sap_lastminor;
			break;

		case SAP_ALL:
			*maj = push.sap_major;
			*min = (minor_t)-1;
			break;
		}

		if (anchor != NULL)
			*anchor = push.sap_anchor;

		if (push.sap_npush > 1) {
			for (i = 0; i < push.sap_npush &&
			    mods[i] != NULL; i++)
				(void) strcpy(mods[i], push.sap_list[i]);
			mods[i] = NULL;
		}
		(void) ldi_close(lh, FREAD|FWRITE, kcred);
		return (0);

	case CLR_AUTOPUSH:
		/* Remove autopush information */

		push.sap_cmd = SAP_CLEAR;
		push.sap_minor = *min;
		push.sap_major = *maj;

		error = ldi_ioctl(lh, SAD_SAP, (intptr_t)&push,
		    FKIOCTL, kcred, &rval);
		if (error) {
			printf("kstr_autopush: "
			    "ioctl(CLR_AUTOPUSH) failed, error %d\n", error);
		}
		(void) ldi_close(lh, FREAD|FWRITE, kcred);
		return (error);

	case SET_AUTOPUSH:
		/* Set autopush information */

		if (*min == (minor_t)-1) {
			push.sap_cmd = SAP_ALL;
		} else if (*lastmin == 0) {
			push.sap_cmd = SAP_ONE;
		} else	{
			push.sap_cmd = SAP_RANGE;
		}

		if (anchor != NULL)
			push.sap_anchor = *anchor;
		else
			push.sap_anchor = 0;

		push.sap_minor = *min;
		push.sap_major = *maj;
		if (lastmin)
			push.sap_lastminor = *lastmin;
		else
			push.sap_lastminor = 0;

		/* pain */
		for (i = 0; i < MAXAPUSH && mods[i] != (char *)NULL; i++) {
			(void) strcpy(push.sap_list[i], mods[i]);
		}
		push.sap_npush = i;
		push.sap_list[i][0] = '\0';

		error = ldi_ioctl(lh, SAD_SAP, (intptr_t)&push,
		    FKIOCTL, kcred, &rval);
		if (error) {
			printf("kstr_autopush: "
			    "ioctl(SET_AUTOPUSH) failed, error %d\n", error);
		}
		(void) ldi_close(lh, FREAD|FWRITE, kcred);
		return (error);

	default:
		(void) ldi_close(lh, FREAD|FWRITE, kcred);
		return (EINVAL);
	}
}
