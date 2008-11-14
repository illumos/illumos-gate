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
 * functions to handle legacy ndd  ioctls
 */
#include <sys/types.h>
#include <sys/mac.h>
#include <sys/mac_impl.h>
#include <inet/nd.h>
#include <sys/mac_ether.h>
#include <sys/policy.h>
#include <sys/strsun.h>

static int mac_ndd_set_ioctl(mac_impl_t *, mblk_t *, int, int *);
static int mac_ndd_get_ioctl(mac_impl_t *, mblk_t *, int, int *);
static int mac_ndd_get_names(mac_impl_t *, mblk_t *);
static boolean_t mac_add_name(mblk_t *, char *, int);

/*
 * add "<name> (<rwtag>) " into the mblk, allocating more memory if needed.
 */
static boolean_t
mac_add_name(mblk_t *mp, char *name, int ndd_flags)
{
	char *cp, *rwtag;
	int len, flags;

	flags = (ndd_flags & (MAC_PROP_PERM_WRITE|MAC_PROP_PERM_READ));
	switch (flags) {
	case 0:
		rwtag = "no read or write";
		break;
	case MAC_PROP_PERM_WRITE:
		rwtag = "write only";
		break;
	case MAC_PROP_PERM_READ:
		rwtag = "read only";
		break;
	default:
		rwtag = "read and write";
		break;
	}

	while (mp->b_cont != NULL)
		mp = mp->b_cont;
	/*
	 * allocate space for name, <space>, '(', rwtag, ')', and
	 * two terminating null chars.
	 */
	len = strlen(name) + strlen(rwtag) + 6;
	if (mp->b_wptr + len >= mp->b_datap->db_lim) {
		mp->b_cont = allocb(len, BPRI_HI);
		mp = mp->b_cont;
		if (mp != NULL)
			return (B_FALSE);
	}
	cp = (char *)mp->b_wptr;
	(void) snprintf(cp, len, "%s (%s)", name, rwtag);
	mp->b_wptr += strnlen(cp, len);
	mp->b_wptr++; /* skip past the terminating \0 */
	return (B_TRUE);
}


/*
 * handle a query for "ndd -get \?". The result is put into mp, and
 * more memory is allocated if needed. The resulting size of the data
 * is returned.
 */
static int
mac_ndd_get_names(mac_impl_t *mip, mblk_t *mp)
{
	int size_out, i;
	mblk_t *tmp;
	mac_priv_prop_t *mpriv;
	uint_t permflags;
	int status;
	uint64_t value;

	if (!mac_add_name(mp, "?", MAC_PROP_PERM_READ))
		return (-1);

	/* first the known ndd mappings */
	for (i = 0; i < mip->mi_type->mt_mappingcount; i++) {
		permflags = MAC_PROP_PERM_RW;
		if ((mip->mi_type->mt_mapping[i].mp_flags & MAC_PROP_MAP_KSTAT)
		    != 0)
			permflags = MAC_PROP_PERM_READ;
		else {
			status = mip->mi_callbacks->mc_getprop(mip->mi_driver,
			    mip->mi_type->mt_mapping[i].mp_name,
			    mip->mi_type->mt_mapping[i].mp_prop_id,
			    0, mip->mi_type->mt_mapping[i].mp_valsize,
			    &value, &permflags);
			if (status != 0)
				return (-1);
		}
		if (!mac_add_name(mp, mip->mi_type->mt_mapping[i].mp_name,
		    permflags))
			return (-1);
	}

	/* now the driver's ndd variables */
	for (i = 0; i < mip->mi_priv_prop_count; i++) {

		mpriv = &mip->mi_priv_prop[i];

		/* skip over the "_" */
		if (!mac_add_name(mp, &mpriv->mpp_name[1], mpriv->mpp_flags))
			return (-1);
	}

	tmp = mp;
	while (tmp->b_cont != NULL)
		tmp = tmp->b_cont;
	*tmp->b_wptr++ = '\0';
	size_out = msgdsize(mp);
	return (size_out);
}


/*
 * Handle legacy ndd ioctls for ND_GET and ND_SET.
 */
void
mac_ndd_ioctl(mac_impl_t *mip, queue_t *wq, mblk_t *mp)
{
	IOCP    iocp;
	int	cmd, err, rval;

	iocp = (IOCP)mp->b_rptr;
	if (iocp->ioc_count == 0 || mp->b_cont == NULL) {
		err = EINVAL;
		goto done;
	}

	cmd = iocp->ioc_cmd;

	if (cmd == ND_SET) {
		err = mac_ndd_set_ioctl(mip, mp, iocp->ioc_count, &rval);
	} else if (cmd == ND_GET) {
		err = mac_ndd_get_ioctl(mip, mp, iocp->ioc_count, &rval);
	}
done:
	if (err == 0)
		miocack(wq, mp, msgdsize(mp->b_cont), rval);
	else
		miocnak(wq, mp, 0, err);
}

static int
mac_ndd_get_ioctl(mac_impl_t *mip, mblk_t *mp, int avail, int *rval)
{
	mblk_t		*mp1;
	char		*valp;
	uchar_t 	*value;
	uint32_t	new_value;
	int		size_out, i;
	int		status = EINVAL;
	char		*name, priv_name[MAXLINKPROPNAME];
	uint8_t		u8;
	uint16_t	u16;
	uint32_t	u32;
	uint64_t	u64;
	uint_t		perm;

	if (mp->b_cont == NULL || avail < 2)
		return (EINVAL);
	valp = (char *)mp->b_cont->b_rptr;
	mp1 = allocb(avail, BPRI_HI); /* the returned buffer */
	if (mp1 == NULL)
		return (ENOMEM);

	if (strcmp(valp, "?") == 0) {
		/*
		 * handle "ndd -get <..> \?" queries.
		 */
		size_out = mac_ndd_get_names(mip, mp1);
		if (size_out < 0) {
			status = ENOMEM;
			goto get_done;
		}
		if (size_out > avail) {
			int excess;
			char *cp;
			/*
			 * need more user buffer space. Return as many
			 * mblks as will fit and return the needed
			 * buffer size in ioc_rval.
			 */
			excess = size_out - avail;
			*rval = size_out; /* what's needed */
			size_out -= excess;
			(void) adjmsg(mp1, -(excess + 1));
			cp = (char *)mp1->b_wptr;
			*cp = '\0';
		}
		status = 0;
		goto get_done;
	}

	ASSERT(mip->mi_callbacks->mc_callbacks & MC_GETPROP);
	name = valp;
	valp = (char *)mp1->b_rptr;
	mp1->b_wptr = mp1->b_rptr;

	/* first lookup ndd <-> public property mapping */
	for (i = 0; i < mip->mi_type->mt_mappingcount; i++) {
		if (strcmp(name, mip->mi_type->mt_mapping[i].mp_name) != 0)
			continue;

		switch (mip->mi_type->mt_mapping[i].mp_valsize) {
		case 1:
			value = (uchar_t *)&u8;
			break;
		case 2:
			value = (uchar_t *)&u16;
			break;
		case 4:
			value = (uchar_t *)&u32;
			break;
		default:
			value = (uchar_t *)&u64;
			break;
		}

		if ((mip->mi_type->mt_mapping[i].mp_flags & MAC_PROP_MAP_KSTAT)
		    != 0) {
			u64 = mac_stat_get((mac_handle_t)mip,
			    mip->mi_type->mt_mapping[i].mp_kstat);
			status = 0;
			/*
			 * ether_stats are all always KSTAT_DATA_UINT32
			 */
			new_value = u32 = (long)u64;
		} else {
			status = mip->mi_callbacks->mc_getprop(mip->mi_driver,
			    name, mip->mi_type->mt_mapping[i].mp_prop_id, 0,
			    mip->mi_type->mt_mapping[i].mp_valsize, value,
			    &perm);
			switch (mip->mi_type->mt_mapping[i].mp_valsize) {
			case 1:
				new_value = u8;
				break;
			case 2:
				new_value = u16;
				break;
			case 4:
				new_value = u32;
				break;
			case 8:
				/*
				 * The only uint64_t is for speed, which is
				 * converted to Mbps in ndd reports.
				 */
				new_value = (u64/1000000);
				break;
			}
		}

		if (status != 0)
			goto get_done;

		(void) snprintf(valp, avail, "%d", new_value);
		goto update_reply;
	}

	/*
	 * could not find a public property. try the private prop route
	 * where all string processing will be done by the driver.
	 */
	(void) snprintf(priv_name, sizeof (priv_name), "_%s", name);
	status = mip->mi_callbacks->mc_getprop(mip->mi_driver, priv_name,
	    MAC_PROP_PRIVATE, 0, avail - 2, mp1->b_rptr, &perm);
	if (status != 0)
		goto get_done;

update_reply:
	size_out += strnlen((const char *)mp1->b_rptr, avail);
	valp += size_out;
	*valp++ = '\0'; /* need \0\0 */
	*valp++ = '\0';
	mp1->b_wptr = (uchar_t *)valp;
	*rval = 0;

get_done:
	freemsg(mp->b_cont);
	if (status == 0)
		mp->b_cont = mp1;
	else {
		freemsg(mp1);
		mp->b_cont = NULL;
	}
	return (status);
}

static int
mac_ndd_set_ioctl(mac_impl_t *mip, mblk_t *mp, int avail, int *rval)
{
	mblk_t  	*mp1;
	char		*valp, *name, *new_valuep;
	uchar_t 	*vp;
	long		new_value;
	int		status, i;
	uint8_t		u8;
	uint16_t	u16;
	uint32_t	u32;
	IOCP		iocp;
	char		priv_name[MAXLINKPROPNAME];

	if (avail == 0 || !(mp1 = mp->b_cont))
		return (EINVAL);

	if (mp1->b_cont) {
		freemsg(mp1->b_cont);
		mp1->b_cont = NULL;
	}
	mp1->b_datap->db_lim[-1] = '\0';
	valp = (char *)mp1->b_rptr;
	name = valp;
	*rval = 0;
	while (*valp++)
		;
	if (valp >= (char *)mp1->b_wptr)
		valp = NULL;

	new_valuep = valp;
	if (ddi_strtol(valp, NULL, 0, &new_value) != 0)
		goto priv_prop;

	iocp = (IOCP)mp->b_rptr;
	if (valp != NULL &&
	    ((iocp->ioc_cr == NULL) ||
	    ((status = secpolicy_net_config(iocp->ioc_cr, B_FALSE)) != 0)))
		return (status);

	status = EINVAL;

	/* first lookup ndd <-> public property mapping */
	for (i = 0; i < mip->mi_type->mt_mappingcount; i++) {
		if (strcmp(name, mip->mi_type->mt_mapping[i].mp_name) != 0)
			continue;

		if (mip->mi_type->mt_mapping[i].mp_flags & MAC_PROP_MAP_KSTAT)
			return (EINVAL);

		if (new_value > mip->mi_type->mt_mapping[i].mp_maxval ||
		    new_value < mip->mi_type->mt_mapping[i].mp_minval ||
		    (mip->mi_type->mt_mapping[i].mp_flags & MAC_PROP_PERM_WRITE)
		    == 0)
			return (EINVAL);
		switch (mip->mi_type->mt_mapping[i].mp_valsize) {
		case 1:
			u8 = (uint8_t)new_value;
			vp = (uchar_t *)&u8;
			break;
		case 2:
			u16 = (uint16_t)new_value;
			vp = (uchar_t *)&u16;
			break;
		case 4:
			u32 = (uint32_t)new_value;
			vp = (uchar_t *)&u32;
			break;
		case 8:
			vp = (uchar_t *)&new_value;
			break;
		default:
			return (ENOTSUP);
		}

		status = mip->mi_callbacks->mc_setprop(mip->mi_driver,
		    name, mip->mi_type->mt_mapping[i].mp_prop_id,
		    mip->mi_type->mt_mapping[i].mp_valsize, (const void *)vp);
		goto done;
	}

priv_prop:
	(void) snprintf(priv_name, sizeof (priv_name), "_%s", name);
	status = mip->mi_callbacks->mc_setprop(mip->mi_driver, priv_name,
	    MAC_PROP_PRIVATE, strlen(new_valuep), new_valuep);
done:
	freemsg(mp1);
	mp->b_cont = NULL;
	return (status);
}
