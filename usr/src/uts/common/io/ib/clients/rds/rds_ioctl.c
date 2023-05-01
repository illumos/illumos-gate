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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/sockio.h>
#include <sys/stream.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/strsun.h>
#include <inet/common.h>
#include <net/if.h>
#include <net/if_types.h>
#include <inet/mi.h>
#include <sys/t_kuser.h>
#include <sys/stropts.h>
#include <sys/pathname.h>
#include <sys/kstr.h>
#include <sys/timod.h>
#include <sys/sunddi.h>
#include <sys/ib/clients/rds/rds.h>
#include <sys/ib/clients/rds/rds_transport.h>

/*
 * Just pass the ioctl to IP and the result to the caller.
 */
int
rds_do_ip_ioctl(int cmd, int len, void *arg)
{
	vnode_t	*kkvp, *vp;
	TIUSER	*tiptr;
	struct	strioctl iocb;
	k_sigset_t smask;
	int	err = 0;

	if (lookupname("/dev/udp", UIO_SYSSPACE, FOLLOW, NULLVPP, &kkvp) == 0) {
		if (t_kopen((file_t *)NULL, kkvp->v_rdev, FREAD|FWRITE,
		    &tiptr, CRED()) == 0) {
			vp = tiptr->fp->f_vnode;
		} else {
			VN_RELE(kkvp);
			return (EPROTO);
		}
	} else {
		return (EPROTO);
	}

	iocb.ic_cmd = cmd;
	iocb.ic_timout = 0;
	iocb.ic_len = len;
	iocb.ic_dp = (caddr_t)arg;
	sigintr(&smask, 0);
	err = kstr_ioctl(vp, I_STR, (intptr_t)&iocb);
	sigunintr(&smask);
	(void) t_kclose(tiptr, 0);
	VN_RELE(kkvp);
	return (err);
}

/*
 * Check if the IP interface named by `lifrp' is RDS-capable.
 */
static boolean_t
rds_capable_interface(struct lifreq *lifrp)
{
	char	ifname[LIFNAMSIZ];
	char	drv[MAXLINKNAMELEN];
	uint_t	ppa;
	char	*cp;

	if (lifrp->lifr_type == IFT_IB)
		return (B_TRUE);

	/*
	 * Strip off the logical interface portion before getting
	 * intimate with the name.
	 */
	(void) strlcpy(ifname, lifrp->lifr_name, LIFNAMSIZ);
	if ((cp = strchr(ifname, ':')) != NULL)
		*cp = '\0';

	if (strcmp("lo0", ifname) == 0) {
		/*
		 * loopback is considered RDS-capable
		 */
		return (B_TRUE);
	}

	return (
	    ddi_parse_dlen(ifname, drv, MAXLINKNAMELEN, &ppa) == DDI_SUCCESS &&
	    rds_transport_ops->rds_transport_if_lookup_by_name(drv));
}

/*
 * Issue an SIOCGLIFCONF down to IP and return the result in `lifcp'.
 * lifcp->lifc_buf is dynamically allocated to be *bufsizep bytes.
 */
static int
rds_do_lifconf(struct lifconf *lifcp, uint_t *bufsizep)
{
	int err;
	int nifs;

	if ((err = rds_do_ip_ioctl(SIOCGIFNUM, sizeof (int), &nifs)) != 0)
		return (err);

	/*
	 * Pad the interface count to account for additional interfaces that
	 * may have been configured between the SIOCGLIFNUM and SIOCGLIFCONF.
	 */
	nifs += 4;

	bzero(lifcp, sizeof (struct lifconf));
	lifcp->lifc_family = AF_INET;
	lifcp->lifc_len = *bufsizep = (nifs * sizeof (struct lifreq));
	lifcp->lifc_buf = kmem_zalloc(*bufsizep, KM_NOSLEEP);
	if (lifcp->lifc_buf == NULL)
		return (ENOMEM);

	err = rds_do_ip_ioctl(SIOCGLIFCONF, sizeof (struct lifconf), lifcp);
	if (err != 0) {
		kmem_free(lifcp->lifc_buf, *bufsizep);
		return (err);
	}
	return (0);
}

void
rds_ioctl_copyin_done(queue_t *q, mblk_t *mp)
{
	void	*addr;
	mblk_t	*mp1;
	int	err = 0;
	struct	iocblk *iocp = (void *)mp->b_rptr;

	if (!(mp1 = mp->b_cont) || !(mp1 = mp1->b_cont)) {
		err = EPROTO;
		goto done;
	}

	addr = mp1->b_rptr;

	switch (iocp->ioc_cmd) {
	case SIOCGIFNUM: {
		uint_t bufsize;
		struct lifconf lifc;
		struct lifreq *lifrp;
		int i, nifs, retval = 0;

		if ((err = rds_do_lifconf(&lifc, &bufsize)) != 0)
			break;

		nifs = lifc.lifc_len / sizeof (struct lifreq);
		for (lifrp = lifc.lifc_req, i = 0; i < nifs; i++, lifrp++) {
			if (strlen(lifrp->lifr_name) <= IFNAMSIZ &&
			    rds_capable_interface(lifrp)) {
				retval++;
			}
		}
		*((int *)addr) = retval;
		kmem_free(lifc.lifc_buf, bufsize);
		break;
	}

	case O_SIOCGIFCONF:
	case SIOCGIFCONF: {
		STRUCT_HANDLE(ifconf, ifc);
		caddr_t ubuf_addr;
		int	ubuf_size;
		uint_t	bufsize;
		int	i, nifs;
		struct lifconf lifc;
		struct lifreq *lifrp;
		struct ifreq *ifrp;

		STRUCT_SET_HANDLE(ifc, iocp->ioc_flag, (struct ifconf *)addr);
		ubuf_size = STRUCT_FGET(ifc, ifc_len);
		ubuf_addr = STRUCT_FGETP(ifc, ifc_buf);

		if ((err = rds_do_lifconf(&lifc, &bufsize)) != 0)
			break;

		mp1 = mi_copyout_alloc(q, mp, ubuf_addr, ubuf_size, B_FALSE);
		if (mp1 == NULL) {
			err = ENOMEM;
			kmem_free(lifc.lifc_buf, bufsize);
			break;
		}

		ifrp = (void *)mp1->b_rptr;
		nifs = lifc.lifc_len / sizeof (struct lifreq);
		for (lifrp = lifc.lifc_req, i = 0; i < nifs &&
		    MBLKTAIL(mp1) >= sizeof (struct ifreq); i++, lifrp++) {
			/*
			 * Skip entries that are impossible to return with
			 * SIOCGIFCONF, or not RDS-capable.
			 */
			if (strlen(lifrp->lifr_name) > IFNAMSIZ ||
			    !rds_capable_interface(lifrp)) {
				continue;
			}

			ifrp->ifr_addr = *(struct sockaddr *)&lifrp->lifr_addr;
			ifrp->ifr_addr.sa_family = AF_INET_OFFLOAD;
			(void) strlcpy(ifrp->ifr_name, lifrp->lifr_name,
			    IFNAMSIZ);
			ifrp++;
			mp1->b_wptr += sizeof (struct ifreq);
		}

		STRUCT_FSET(ifc, ifc_len, MBLKL(mp1));
		kmem_free(lifc.lifc_buf, bufsize);
		break;
	}
	case SIOCGIFMTU:
	case SIOCGIFFLAGS:
		err = rds_do_ip_ioctl(iocp->ioc_cmd, sizeof (struct ifreq),
		    addr);
		break;

	case TI_GETMYNAME: {
		rds_t *rds;
		STRUCT_HANDLE(strbuf, sb);
		ipaddr_t	v4addr;
		uint16_t port;
		int addrlen;
		sin_t *sin;

		STRUCT_SET_HANDLE(sb,
		    ((struct iocblk *)(uintptr_t)mp->b_rptr)->ioc_flag, addr);
		rds = (rds_t *)q->q_ptr;
		ASSERT(rds->rds_family == AF_INET_OFFLOAD);
		addrlen = sizeof (sin_t);
		v4addr = rds->rds_src;
		port = rds->rds_port;
		mp1 = mi_copyout_alloc(q, mp, STRUCT_FGETP(sb, buf), addrlen,
		    B_TRUE);
		if (mp1 == NULL)
			return;
		STRUCT_FSET(sb, len, (int)sizeof (sin_t));
		sin = (sin_t *)(uintptr_t)mp1->b_rptr;
		mp1->b_wptr = (uchar_t *)&sin[1];
		*sin = sin_null;
		sin->sin_family = AF_INET_OFFLOAD;
		sin->sin_addr.s_addr = v4addr;
		sin->sin_port = port;

	}
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	if (err == 0) {
		mi_copyout(q, mp);
		return;
	}
done:
	mi_copy_done(q, mp, err);
}

void
rds_ioctl_copyin_setup(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp = (struct iocblk *)(uintptr_t)mp->b_rptr;
	int	copyin_size;

	if (mp->b_cont == NULL) {
		iocp->ioc_error = EINVAL;
		mp->b_datap->db_type = M_IOCNAK;
		iocp->ioc_count = 0;
		qreply(q, mp);
		return;
	}

	switch (iocp->ioc_cmd) {
	case O_SIOCGIFCONF:
	case SIOCGIFCONF:
		if (iocp->ioc_count == TRANSPARENT)
			copyin_size = SIZEOF_STRUCT(ifconf, iocp->ioc_flag);
		else
			copyin_size = iocp->ioc_count;
		break;

	case SIOCGIFNUM:
		copyin_size = sizeof (int);
		break;
	case SIOCGIFFLAGS:
	case SIOCGIFMTU:
		copyin_size = sizeof (struct ifreq);
		break;
	case TI_GETMYNAME:
		copyin_size = SIZEOF_STRUCT(strbuf, iocp->ioc_flag);
		break;
	}
	mi_copyin(q, mp, NULL, copyin_size);
}

void
rds_ioctl(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp = (struct iocblk *)(uintptr_t)mp->b_rptr;


	switch (iocp->ioc_cmd) {
		case O_SIOCGIFCONF:
		case SIOCGIFCONF:
		case SIOCGIFNUM:
		case SIOCGIFMTU:
		case SIOCGIFFLAGS:
		case TI_GETMYNAME:
			rds_ioctl_copyin_setup(q, mp);
			break;
		default:
			cmn_err(CE_CONT, "rds_wput unsupported IOCTL \n");
			miocnak(q, mp, 0, ENOTSUP);
			break;
	}
}

boolean_t
rds_verify_bind_address(ipaddr_t addr)
{
	int i, nifs;
	uint_t bufsize;
	struct lifconf lifc;
	struct lifreq *lifrp;
	struct sockaddr_in *sinp;
	boolean_t retval = B_FALSE;

	if (rds_do_lifconf(&lifc, &bufsize) != 0)
		return (B_FALSE);

	nifs = lifc.lifc_len / sizeof (struct lifreq);
	for (lifrp = lifc.lifc_req, i = 0; i < nifs; i++, lifrp++) {
		sinp = (struct sockaddr_in *)&lifrp->lifr_addr;
		if (rds_capable_interface(lifrp) &&
		    sinp->sin_addr.s_addr == addr) {
			retval = B_TRUE;
			break;
		}
	}

	kmem_free(lifc.lifc_buf, bufsize);
	return (retval);
}
