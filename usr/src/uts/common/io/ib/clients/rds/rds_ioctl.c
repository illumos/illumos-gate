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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	AF_INET_OFFLOAD	30

#include <sys/sockio.h>
#include <sys/stream.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/strsun.h>
#include <inet/common.h>
#include <net/if.h>
#include <inet/mi.h>
#include <sys/t_kuser.h>
#include <sys/stropts.h>
#include <sys/pathname.h>
#include <sys/kstr.h>
#include <sys/timod.h>
#include <sys/ib/clients/rds/rds.h>
#include <sys/ib/clients/rds/rds_transport.h>

static	sin_t	sin_null;	/* Zero address for quick clears */

#define	isdigit(ch)	((ch) >= '0' && (ch) <= '9')

#define	isalpha(ch)	(((ch) >= 'a' && (ch) <= 'z') || \
			((ch) >= 'A' && (ch) <= 'Z'))

/*
 * Just pass the ioctl to IP and the result to the caller.
 */
int
rds_do_ip_ioctl(int cmd, int len, caddr_t arg)
{
	vnode_t	*kvp, *vp;
	TIUSER	*tiptr;
	struct	strioctl iocb;
	k_sigset_t smask;
	int	err = 0;

	if (lookupname("/dev/udp", UIO_SYSSPACE, FOLLOW, NULLVPP,
	    &kvp) == 0) {
		if (t_kopen((file_t *)NULL, kvp->v_rdev, FREAD|FWRITE,
		    &tiptr, CRED()) == 0) {
			vp = tiptr->fp->f_vnode;
		} else {
			VN_RELE(kvp);
			return (EPROTO);
		}
	} else {
			return (EPROTO);
	}

	iocb.ic_cmd = cmd;
	iocb.ic_timout = 0;
	iocb.ic_len = len;
	iocb.ic_dp = arg;
	sigintr(&smask, 0);
	err = kstr_ioctl(vp, I_STR, (intptr_t)&iocb);
	sigunintr(&smask);
	(void) t_kclose(tiptr, 0);
	VN_RELE(kvp);
	return (err);
}

/*
 * Return 0 if the interface is IB.
 * Return error (>0) if any error is encountered during processing.
 * Return -1 if the interface is not IB and no error.
 */
static int
rds_is_ib_interface(char *name)
{

	char		dev_path[MAXPATHLEN];
	char		devname[MAXNAMELEN];
	ldi_handle_t	lh;
	dl_info_ack_t	info;
	int		ret = 0;
	int		i;
	k_sigset_t	smask;

	/*
	 * ibd devices are only style 2 devices
	 * so we will open only style 2 devices
	 * by ignoring the ppa
	 */
	i = strlen(name) - 1;
	while ((i >= 0) && (!isalpha(name[i]))) i--;
	if (i < 0) {
		/* Invalid interface name, no alphabet */
		return (-1);
	}
	(void) strncpy(devname, name, i + 1);
	devname[i + 1] = '\0';

	if (strcmp("lo", devname) == 0) {
		/*
		 * loopback interface is considered RDS capable
		 */
		return (0);
	}

	(void) strncpy(dev_path, "/dev/", MAXPATHLEN);
	if (strlcat(dev_path, devname, MAXPATHLEN) >= MAXPATHLEN) {
		/* string overflow */
		return (-1);
	}

	ret = ldi_open_by_name(dev_path, FREAD|FWRITE, kcred, &lh, rds_li);
	if (ret != 0) {
		return (ret);
	}

	sigintr(&smask, 0);
	ret = dl_info(lh, &info, NULL, NULL, NULL);
	sigunintr(&smask);
	(void) ldi_close(lh, FREAD|FWRITE, kcred);
	if (ret != 0) {
		return (ret);
	}

	if (info.dl_mac_type != DL_IB &&
	    !rds_transport_ops->rds_transport_if_lookup_by_name(devname)) {
		return (-1);
	}

	return (0);
}

void
rds_ioctl_copyin_done(queue_t *q, mblk_t *mp)
{
	char	*addr;
	mblk_t	*mp1;
	int	err = 0;
	struct	iocblk *iocp = (struct iocblk *)(uintptr_t)mp->b_rptr;

	if (!(mp1 = mp->b_cont) || !(mp1 = mp1->b_cont)) {
		err = EPROTO;
		goto done;
	}

	addr = (char *)mp1->b_rptr;

	switch (iocp->ioc_cmd) {

	case SIOCGIFNUM: {
		/* Get number of interfaces. */
		struct ifconf   kifc;
		struct ifreq *ifr;
		int num_ifs;
		int n;

		err = rds_do_ip_ioctl(iocp->ioc_cmd, sizeof (int),
		    (char *)&num_ifs);
		if (err != 0) {
			break;
		}

		kifc.ifc_len = num_ifs * sizeof (struct ifreq);
		kifc.ifc_buf = kmem_zalloc(kifc.ifc_len, KM_SLEEP);
		err = rds_do_ip_ioctl(SIOCGIFCONF,
		    sizeof (struct ifconf), (caddr_t)&kifc);
		if (err != 0) {
			kmem_free(kifc.ifc_buf, kifc.ifc_len);
			break;
		}
		ifr = kifc.ifc_req;
		n = num_ifs;
		for (num_ifs = 0; n > 0; ifr++) {
			err = rds_is_ib_interface(ifr->ifr_name);
			if (err == 0) {
				num_ifs++;
			} else if (err > 0) {
				num_ifs = 0;
				break;
			} else {
				err = 0;
			}
			n--;
		}
		*((int *)(uintptr_t)addr) = num_ifs;
		kmem_free(kifc.ifc_buf, kifc.ifc_len);
	}
		break;

	case O_SIOCGIFCONF:
	case SIOCGIFCONF: {
		STRUCT_HANDLE(ifconf, ifc);
		caddr_t ubuf_addr;
		int	ubuf_size;
		struct ifconf   kifc;
		struct ifreq *ifr, *ptr;
		int num_ifs;

		STRUCT_SET_HANDLE(ifc, iocp->ioc_flag,
		    (struct ifconf *)(uintptr_t)addr);

		ubuf_size = STRUCT_FGET(ifc, ifc_len);
		ubuf_addr = STRUCT_FGETP(ifc, ifc_buf);

		err = rds_do_ip_ioctl(SIOCGIFNUM, sizeof (int),
		    (char *)&num_ifs);
		if (err != 0) {
			break;
		}

		kifc.ifc_len = num_ifs * sizeof (struct ifreq);
		kifc.ifc_buf = kmem_zalloc(kifc.ifc_len, KM_SLEEP);
		err = rds_do_ip_ioctl(iocp->ioc_cmd,
		    sizeof (struct ifconf), (caddr_t)&kifc);
		if (err != 0) {
			kmem_free(kifc.ifc_buf, kifc.ifc_len);
			break;
		}
		mp1 = mi_copyout_alloc(q, mp, ubuf_addr, ubuf_size, B_FALSE);
		if (mp1 == NULL) {
			err = ENOMEM;
			kmem_free(kifc.ifc_buf, ubuf_size);
			break;
		}

		ifr = kifc.ifc_req;
		ptr = (struct ifreq *)(uintptr_t)mp1->b_rptr;
		for (; num_ifs > 0 &&
		    (int)((uintptr_t)mp1->b_wptr - (uintptr_t)mp1->b_rptr) <
		    ubuf_size; num_ifs--, ifr++) {
			err = rds_is_ib_interface(ifr->ifr_name);
			if (err == 0) {
				ifr->ifr_addr.sa_family = AF_INET_OFFLOAD;
				bcopy((caddr_t)ifr, ptr, sizeof (struct ifreq));
				ptr++;
				mp1->b_wptr = (uchar_t *)ptr;
			} else if (err > 0) {
				break;
			} else {
				err = 0;
			}
		}

		STRUCT_FSET(ifc, ifc_len, (int)((uintptr_t)mp1->b_wptr -
		    (uintptr_t)mp1->b_rptr));
		kmem_free(kifc.ifc_buf, kifc.ifc_len);
	}
		break;
	case SIOCGIFMTU:
		err = rds_do_ip_ioctl(iocp->ioc_cmd,
		    sizeof (struct ifreq), addr);
		break;

	case SIOCGIFFLAGS:
		err = rds_do_ip_ioctl(iocp->ioc_cmd,
		    sizeof (struct ifreq), addr);
		break;
	case TI_GETMYNAME: {

		rds_t *rds;
		STRUCT_HANDLE(strbuf, sb);
		ipaddr_t	v4addr;
		uint16_t port;
		int addrlen;
		sin_t *sin;

		STRUCT_SET_HANDLE(sb,
		    ((struct iocblk *)(uintptr_t)mp->b_rptr)->ioc_flag,
		    (void *)(uintptr_t)addr);
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
	int	numifs;
	struct ifconf   kifc;
	struct ifreq *ifr;
	boolean_t ret = B_FALSE;


	if (rds_do_ip_ioctl(SIOCGIFNUM, sizeof (int), (caddr_t)&numifs)) {
		return (ret);
	}

	kifc.ifc_len = numifs * sizeof (struct ifreq);
	kifc.ifc_buf = kmem_zalloc(kifc.ifc_len, KM_SLEEP);

	if (rds_do_ip_ioctl(SIOCGIFCONF, sizeof (struct ifconf),
	    (caddr_t)&kifc)) {
		goto done;
	}

	ifr = kifc.ifc_req;
	for (numifs = kifc.ifc_len / sizeof (struct ifreq);
	    numifs > 0; numifs--, ifr++) {
		struct	sockaddr_in	*sin;

		sin = (struct sockaddr_in *)(uintptr_t)&ifr->ifr_addr;
		if ((sin->sin_addr.s_addr == addr) &&
		    (rds_is_ib_interface(ifr->ifr_name) == 0)) {
				ret = B_TRUE;
				break;
		}
	}

done:
	kmem_free(kifc.ifc_buf, kifc.ifc_len);
	return (ret);
}
