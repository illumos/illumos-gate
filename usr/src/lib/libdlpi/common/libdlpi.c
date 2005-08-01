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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Data-Link Provider Interface (Version 2)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <stropts.h>
#include <sys/dlpi.h>
#include <errno.h>
#include <sys/sysmacros.h>
#include <ctype.h>
#include <libdlpi.h>
#include <libdladm.h>

typedef enum dlpi_multi_op {
	DLPI_MULTI_DISABLE = 0,
	DLPI_MULTI_ENABLE
} dlpi_multi_op_t;

typedef enum dlpi_promisc_op {
	DLPI_PROMISC_OFF = 0,
	DLPI_PROMISC_ON
} dlpi_promisc_op_t;

const char	*i_dlpi_mac_type[] = {
	"CSMA/CD",		/* 0x00 */
	"Token Bus",		/* 0x01 */
	"Token Ring",		/* 0x02 */
	"Metro Net",		/* 0x03 */
	"Ethernet",		/* 0x04 */
	"HDLC",			/* 0x05 */
	"Sync Character",	/* 0x06 */
	"CTCA",			/* 0x07 */
	"FDDI",			/* 0x08 */
	"unknown"		/* 0x09 */
	"Frame Relay (LAPF)",	/* 0x0a */
	"MP Frame Relay",	/* 0x0b */
	"Async Character",	/* 0x0c */
	"X.25 (Classic IP)",	/* 0x0d */
	"Software Loopback",	/* 0x0e */
	"undefined",		/* 0x0f */
	"Fiber Channel",	/* 0x10 */
	"ATM",			/* 0x11 */
	"ATM (Classic IP)",	/* 0x12 */
	"X.25 (LAPB)",		/* 0x13 */
	"ISDN",			/* 0x14 */
	"HIPPI",		/* 0x15 */
	"100BaseVG Ethernet",	/* 0x16 */
	"100BaseVG Token Ring",	/* 0x17 */
	"Ethernet/IEEE 802.3",	/* 0x18 */
	"100BaseT",		/* 0x19 */
	"Infiniband"		/* 0x1a */
};

static int i_dlpi_ifrm_num(char *, unsigned int *);

const char *
dlpi_mac_type(uint_t type)
{
	if (type >= sizeof (i_dlpi_mac_type) / sizeof (i_dlpi_mac_type[0]))
		return ("ERROR");

	return (i_dlpi_mac_type[type]);
}

static int
strputmsg(int fd, uint8_t *ctl_buf, size_t ctl_len, int flags)
{
	struct strbuf	ctl;

	ctl.buf = (char *)ctl_buf;
	ctl.len = ctl_len;

	return (putmsg(fd, &ctl, NULL, flags));
}

static int
strgetmsg(int fd, int timeout, char *ctl_buf,
    size_t *ctl_lenp, char *data_buf, size_t *data_lenp)
{
	struct strbuf	ctl;
	struct strbuf	data;
	int		res;
	struct pollfd	pfd;
	int		flags = 0;

	pfd.fd = fd;
	pfd.events = POLLIN | POLLPRI;

	switch (poll(&pfd, 1, timeout)) {
	default:
		ctl.buf = ctl_buf;
		ctl.len = 0;
		ctl.maxlen = (ctl_lenp != NULL) ? *ctl_lenp : 0;

		data.buf = data_buf;
		data.len = 0;
		data.maxlen = (data_lenp != NULL) ? *data_lenp : 0;

		if ((res = getmsg(fd, &ctl, &data, &flags)) < 0)
			goto failed;

		if (ctl_buf != NULL) {
			if (res & MORECTL) {
				errno = E2BIG;
				goto failed;
			}

			*ctl_lenp = ctl.len;
		}

		if (data_buf != NULL) {
			if (res & MOREDATA) {
				errno = E2BIG;
				goto failed;
			}

			*data_lenp = data.len;
		}

		break;
	case 0:
		errno = ETIME;
		/*FALLTHRU*/
	case -1:
		goto failed;
	}

	return (0);
failed:
	return (-1);
}

int
dlpi_open(const char *provider)
{
	char		devname[MAXPATHLEN];
	char		path[MAXPATHLEN];
	int		fd;
	struct stat	st;

	(void) snprintf(devname, MAXPATHLEN, "/dev/%s", provider);

	if ((fd = open(devname, O_RDWR)) != -1)
		return (fd);

	(void) snprintf(path, MAXPATHLEN, "/devices/pseudo/clone@0:%s",
	    provider);

	if (stat(path, &st) == 0) {
		(void) strlcpy(devname, path, sizeof (devname));
		if ((fd = open(devname, O_RDWR)) != -1)
			return (fd);
	}

	return (-1);
}

int
dlpi_close(int fd)
{
	return (close(fd));
}

int
dlpi_info(int fd, int timeout, dl_info_ack_t *ackp,
    union DL_qos_types *selp, union DL_qos_types *rangep,
    uint8_t *addrp, size_t *addrlenp, uint8_t *brdcst_addrp,
    size_t *brdcst_addrlenp)
{
	int			rc = -1;
	size_t			size;
	dl_info_ack_t		*buf;
	dl_info_req_t		dlir;
	dl_info_ack_t		*dliap;
	union DL_qos_types	*uqtp;

	size = sizeof (dl_info_ack_t);		/* DL_INFO_ACK */
	size += sizeof (union DL_qos_types);	/* QoS selections */
	size += sizeof (union DL_qos_types);	/* QoS ranges */
	size += MAXADDRLEN + MAXSAPLEN;		/* DLSAP Address */
	size += MAXADDRLEN;			/* Broadcast Address */

	if ((buf = malloc(size)) == NULL)
		return (-1);

	dlir.dl_primitive = DL_INFO_REQ;

	if (strputmsg(fd, (uint8_t *)&dlir, DL_INFO_REQ_SIZE, RS_HIPRI) == -1)
		goto done;

	if (strgetmsg(fd, timeout, (char *)buf, &size, NULL, NULL) == -1)
		goto done;

	if (size < DL_INFO_ACK_SIZE) {
		errno = EBADMSG;
		goto done;
	}

	dliap = (dl_info_ack_t *)buf;
	if (dliap->dl_primitive != DL_INFO_ACK ||
	    dliap->dl_version != DL_VERSION_2) {
		errno = EPROTO;
		goto done;
	}

	(void) memcpy(ackp, buf, DL_INFO_ACK_SIZE);

	if (dliap->dl_qos_offset != 0) {
		if (dliap->dl_qos_length < sizeof (t_uscalar_t)) {
			errno = EPROTO;
			goto done;
		}

		uqtp = (union DL_qos_types *)
		    ((uintptr_t)buf + dliap->dl_qos_offset);
		if (uqtp->dl_qos_type != DL_QOS_CO_SEL1 &&
		    uqtp->dl_qos_type != DL_QOS_CL_SEL1) {
			errno = EPROTO;
			goto done;
		}

		if (selp != NULL)
			(void) memcpy(selp, (char *)buf + dliap->dl_qos_offset,
			    dliap->dl_qos_length);
	}

	if (dliap->dl_qos_range_offset != 0) {
		if (dliap->dl_qos_range_length < sizeof (t_uscalar_t)) {
			errno = EPROTO;
			goto done;
		}

		uqtp = (union DL_qos_types *)
		    ((uintptr_t)buf + dliap->dl_qos_range_offset);
		if (uqtp->dl_qos_type != DL_QOS_CO_RANGE1 &&
		    uqtp->dl_qos_type != DL_QOS_CL_RANGE1) {
			errno = EPROTO;
			goto done;
		}

		if (rangep != NULL)
			(void) memcpy(rangep,
			    (char *)buf + dliap->dl_qos_range_offset,
			    dliap->dl_qos_range_length);
	}

	if (dliap->dl_addr_offset != 0) {
		if (dliap->dl_addr_length == 0) {
			errno = EPROTO;
			goto done;
		}

		if (addrlenp != NULL)
			*addrlenp = dliap->dl_addr_length;
		if (addrp != NULL)
			(void) memcpy(addrp,
			    (char *)buf + dliap->dl_addr_offset,
			    dliap->dl_addr_length);
	}

	if (dliap->dl_brdcst_addr_offset != 0) {
		if (dliap->dl_brdcst_addr_length == 0) {
			errno = EPROTO;
			goto done;
		}

		if (brdcst_addrlenp != NULL)
			*brdcst_addrlenp = dliap->dl_brdcst_addr_length;
		if (brdcst_addrp != NULL)
			(void) memcpy(brdcst_addrp,
			    (char *)buf + dliap->dl_brdcst_addr_offset,
			    dliap->dl_brdcst_addr_length);
	}

	rc = 0;	/* success */
done:
	free(buf);
	return (rc);
}

int
dlpi_attach(int fd, int timeout, uint_t ppa)
{
	int			rc = -1;
	size_t			size;
	dl_attach_req_t		dlar;
	dl_error_ack_t		*dleap;
	union DL_primitives	*buf;
	union DL_primitives	*udlp;

	size = 0;
	size = MAX(sizeof (dl_ok_ack_t), size);
	size = MAX(sizeof (dl_error_ack_t), size);

	if ((buf = malloc(size)) == NULL)
		return (-1);

	dlar.dl_primitive = DL_ATTACH_REQ;
	dlar.dl_ppa = ppa;

	if (strputmsg(fd, (uint8_t *)&dlar, DL_ATTACH_REQ_SIZE, 0) == -1)
		goto done;

	if (strgetmsg(fd, timeout, (char *)buf, &size, NULL, NULL) == -1)
		goto done;

	if (size < sizeof (t_uscalar_t)) {
		errno = EBADMSG;
		goto done;
	}

	udlp = (union DL_primitives *)buf;
	switch (udlp->dl_primitive) {
	case DL_OK_ACK:
		if (size < DL_OK_ACK_SIZE) {
			errno = EBADMSG;
			goto done;
		}
		break;

	case DL_ERROR_ACK:
		if (size < DL_ERROR_ACK_SIZE) {
			errno = EBADMSG;
			goto done;
		}

		dleap = (dl_error_ack_t *)buf;
		switch (dleap->dl_errno) {
		case DL_BADPPA:
			errno = EINVAL;
			break;

		case DL_ACCESS:
			errno = EPERM;
			break;

		case DL_SYSERR:
			errno = dleap->dl_unix_errno;
			break;

		default:
			errno = EPROTO;
			break;
		}

		goto done;

	default:
		errno = EBADMSG;
		goto done;
	}

	rc = 0;	/* success */
done:
	free(buf);
	return (rc);
}

int
dlpi_detach(int fd, int timeout)
{
	int			rc = -1;
	size_t			size;
	dl_detach_req_t		dldr;
	dl_error_ack_t		*dleap;
	union DL_primitives	*buf;
	union DL_primitives	*udlp;

	size = 0;
	size = MAX(sizeof (dl_ok_ack_t), size);
	size = MAX(sizeof (dl_error_ack_t), size);

	if ((buf = malloc(size)) == NULL)
		return (-1);

	dldr.dl_primitive = DL_DETACH_REQ;

	if (strputmsg(fd, (uint8_t *)&dldr, DL_DETACH_REQ_SIZE, 0) == -1)
		goto done;

	if (strgetmsg(fd, timeout, (char *)buf, &size, NULL, NULL) == -1)
		goto done;

	if (size < sizeof (t_uscalar_t)) {
		errno = EBADMSG;
		goto done;
	}

	udlp = (union DL_primitives *)buf;
	switch (udlp->dl_primitive) {
	case DL_OK_ACK:
		if (size < DL_OK_ACK_SIZE) {
			errno = EBADMSG;
			goto done;
		}
		break;

	case DL_ERROR_ACK:
		if (size < DL_ERROR_ACK_SIZE) {
			errno = EBADMSG;
			goto done;
		}

		dleap = (dl_error_ack_t *)buf;
		switch (dleap->dl_errno) {
		case DL_SYSERR:
			errno = dleap->dl_unix_errno;
			break;

		default:
			errno = EPROTO;
			break;
		}
		goto done;

	default:
		errno = EBADMSG;
		goto done;
	}

	rc = 0;	/* success */
done:
	free(buf);
	return (rc);
}

int
dlpi_bind(int fd, int timeout, uint_t sap, uint16_t mode,
    boolean_t conn_mgmt, uint32_t *max_conn_ind,
    uint32_t *xid_test, uint8_t *addrp, size_t *addrlenp)
{
	int			rc = -1;
	size_t			size;
	dl_bind_req_t		dlbr;
	dl_bind_ack_t		*dlbap;
	dl_error_ack_t		*dleap;
	union DL_primitives	*buf;
	union DL_primitives	*udlp;

	size = 0;
	size = MAX(sizeof (dl_bind_ack_t) + MAXADDRLEN + MAXSAPLEN, size);
	size = MAX(sizeof (dl_error_ack_t), size);

	if ((buf = malloc(size)) == NULL)
		return (-1);

	dlbr.dl_primitive = DL_BIND_REQ;
	dlbr.dl_sap = sap;
	dlbr.dl_service_mode = mode;
	dlbr.dl_conn_mgmt = (conn_mgmt) ? 1 : 0;
	dlbr.dl_max_conind = (max_conn_ind != NULL) ? *max_conn_ind : 0;
	dlbr.dl_xidtest_flg = (xid_test != NULL) ? *xid_test : 0;

	if (strputmsg(fd, (uint8_t *)&dlbr, DL_BIND_REQ_SIZE, 0) == -1)
		goto done;

	if (strgetmsg(fd, timeout, (char *)buf, &size, NULL, NULL) == -1)
		goto done;

	if (size < sizeof (t_uscalar_t)) {
		errno = EBADMSG;
		goto done;
	}

	udlp = (union DL_primitives *)buf;
	switch (udlp->dl_primitive) {
	case DL_BIND_ACK:
		if (size < DL_BIND_ACK_SIZE) {
			errno = EBADMSG;
			goto done;
		}

		dlbap = (dl_bind_ack_t *)buf;
		if (max_conn_ind != NULL)
			*max_conn_ind = dlbap->dl_max_conind;
		if (xid_test != NULL)
			*xid_test = dlbap->dl_xidtest_flg;

		if (dlbap->dl_addr_offset != 0) {
			if (dlbap->dl_addr_length == 0) {
				errno = EPROTO;
				goto done;
			}

			if (addrlenp != NULL)
				*addrlenp = dlbap->dl_addr_length;
			if (addrp != NULL)
				(void) memcpy(addrp,
				    (char *)buf + dlbap->dl_addr_offset,
				    dlbap->dl_addr_length);
		}

		break;

	case DL_ERROR_ACK:
		if (size < DL_ERROR_ACK_SIZE) {
			errno = EBADMSG;
			goto done;
		}

		dleap = (dl_error_ack_t *)buf;
		switch (dleap->dl_errno) {
		case DL_BADADDR:
			errno = EINVAL;
			break;

		case DL_INITFAILED:
		case DL_NOTINIT:
			errno = EIO;
			break;

		case DL_ACCESS:
			errno = EACCES;
			break;

		case DL_NOADDR:
			errno = EFAULT;
			break;

		case DL_UNSUPPORTED:
		case DL_NOAUTO:
		case DL_NOXIDAUTO:
		case DL_NOTESTAUTO:
			errno = ENOTSUP;
			break;

		case DL_SYSERR:
			errno = dleap->dl_unix_errno;
			break;

		default:
			errno = EPROTO;
			break;
		}
		goto done;

	default:
		errno = EBADMSG;
		goto done;
	}

	rc = 0;	/* success */
done:
	free(buf);
	return (rc);
}

int
dlpi_unbind(int fd, int timeout)
{
	int			rc = -1;
	size_t			size;
	dl_unbind_req_t		dlubr;
	dl_error_ack_t		*dleap;
	union DL_primitives	*buf;
	union DL_primitives	*udlp;

	size = 0;
	size = MAX(sizeof (dl_ok_ack_t), size);
	size = MAX(sizeof (dl_error_ack_t), size);

	if ((buf = malloc(size)) == NULL)
		return (-1);

	dlubr.dl_primitive = DL_UNBIND_REQ;

	if (strputmsg(fd, (uint8_t *)&dlubr, DL_UNBIND_REQ_SIZE, 0) == -1)
		goto done;

	if (strgetmsg(fd, timeout, (char *)buf, &size, NULL, NULL) == -1)
		goto done;

	if (size < sizeof (t_uscalar_t)) {
		errno = EBADMSG;
		goto done;
	}

	udlp = (union DL_primitives *)buf;
	switch (udlp->dl_primitive) {
	case DL_OK_ACK:
		if (size < DL_OK_ACK_SIZE) {
			errno = EBADMSG;
			goto done;
		}
		break;

	case DL_ERROR_ACK:
		if (size < DL_ERROR_ACK_SIZE) {
			errno = EBADMSG;
			goto done;
		}

		dleap = (dl_error_ack_t *)buf;
		switch (dleap->dl_errno) {
		case DL_SYSERR:
			errno = dleap->dl_unix_errno;
			break;

		default:
			errno = EPROTO;
			break;
		}
		goto done;

	default:
		errno = EBADMSG;
		goto done;
	}

	rc = 0;	/* success */
done:
	free(buf);
	return (rc);
}

static int
i_dlpi_multi(int fd, int timeout, dlpi_multi_op_t op,
    uint8_t *addrp, size_t addr_length)
{
	int			rc = -1;
	size_t			opsize;
	size_t			size;
	dl_enabmulti_req_t	*dlemrp;
	dl_disabmulti_req_t	*dldmrp;
	dl_error_ack_t		*dleap;
	union DL_primitives	*buf;
	union DL_primitives	*udlp;

	opsize = (op == DLPI_MULTI_ENABLE) ? sizeof (dl_enabmulti_req_t) :
	    sizeof (dl_disabmulti_req_t);
	opsize += addr_length;

	size = 0;
	size = MAX(opsize, size);
	size = MAX(sizeof (dl_ok_ack_t), size);
	size = MAX(sizeof (dl_error_ack_t), size);

	if ((buf = malloc(size)) == NULL)
		return (-1);

	if (op == DLPI_MULTI_ENABLE) {
		dlemrp = (dl_enabmulti_req_t *)buf;
		dlemrp->dl_primitive = DL_ENABMULTI_REQ;
		dlemrp->dl_addr_length = addr_length;
		dlemrp->dl_addr_offset = sizeof (dl_enabmulti_req_t);
		(void) memcpy(&dlemrp[1], addrp, addr_length);
	} else {
		dldmrp = (dl_disabmulti_req_t *)buf;
		dldmrp->dl_primitive = DL_DISABMULTI_REQ;
		dldmrp->dl_addr_length = addr_length;
		dldmrp->dl_addr_offset = sizeof (dl_disabmulti_req_t);
		(void) memcpy(&dldmrp[1], addrp, addr_length);
	}

	if (strputmsg(fd, (uint8_t *)buf, opsize, 0) == -1)
		goto done;

	if (strgetmsg(fd, timeout, (char *)buf, &size, NULL, NULL) == -1)
		goto done;

	if (size < sizeof (t_uscalar_t)) {
		errno = EBADMSG;
		goto done;
	}

	udlp = (union DL_primitives *)buf;
	switch (udlp->dl_primitive) {
	case DL_OK_ACK:
		if (size < DL_OK_ACK_SIZE) {
			errno = EBADMSG;
			goto done;
		}
		break;

	case DL_ERROR_ACK:
		if (size < DL_ERROR_ACK_SIZE) {
			errno = EBADMSG;
			goto done;
		}

		dleap = (dl_error_ack_t *)buf;
		switch (dleap->dl_errno) {
		case DL_BADADDR:
			errno = EINVAL;
			break;

		case DL_TOOMANY:
			errno = ENOSPC;
			break;

		case DL_NOTSUPPORTED:
			errno = ENOTSUP;
			break;

		case DL_NOTENAB:
			errno = EINVAL;
			break;

		case DL_SYSERR:
			errno = dleap->dl_unix_errno;
			break;

		default:
			errno = EPROTO;
			break;
		}
		goto done;

	default:
		errno = EBADMSG;
		goto done;
	}

	rc = 0;	/* success */
done:
	free(buf);
	return (rc);
}

int
dlpi_enabmulti(int fd, int timeout, uint8_t *addrp,
    size_t addr_length)
{
	return (i_dlpi_multi(fd, timeout, DLPI_MULTI_ENABLE, addrp,
	    addr_length));
}

int
dlpi_disabmulti(int fd, int timeout, uint8_t *addrp,
    size_t addr_length)
{
	return (i_dlpi_multi(fd, timeout, DLPI_MULTI_DISABLE, addrp,
	    addr_length));
}

static int
i_dlpi_promisc(int fd, int timeout, dlpi_promisc_op_t op,
    uint_t level)
{
	int			rc = -1;
	size_t			opsize;
	size_t			size;
	dl_promiscon_req_t	*dlpnrp;
	dl_promiscoff_req_t	*dlpfrp;
	dl_error_ack_t		*dleap;
	union DL_primitives	*buf;
	union DL_primitives	*udlp;

	opsize = (op == DLPI_PROMISC_ON) ? sizeof (dl_promiscon_req_t) :
	    sizeof (dl_promiscoff_req_t);

	size = 0;
	size = MAX(opsize, size);
	size = MAX(sizeof (dl_ok_ack_t), size);
	size = MAX(sizeof (dl_error_ack_t), size);

	if ((buf = malloc(size)) == NULL)
		return (-1);

	if (op == DLPI_PROMISC_ON) {
		dlpnrp = (dl_promiscon_req_t *)buf;
		dlpnrp->dl_primitive = DL_PROMISCON_REQ;
		dlpnrp->dl_level = level;

		if (strputmsg(fd, (uint8_t *)dlpnrp, opsize, 0) == -1)
			goto done;
	} else {
		dlpfrp = (dl_promiscoff_req_t *)buf;
		dlpfrp->dl_primitive = DL_PROMISCOFF_REQ;
		dlpfrp->dl_level = level;

		if (strputmsg(fd, (uint8_t *)dlpfrp, opsize, 0) == -1)
			goto done;
	}

	if (strgetmsg(fd, timeout, (char *)buf, &size, NULL, NULL) == -1)
		goto done;

	if (size < sizeof (t_uscalar_t)) {
		errno = EBADMSG;
		goto done;
	}

	udlp = (union DL_primitives *)buf;
	switch (udlp->dl_primitive) {
	case DL_OK_ACK:
		if (size < DL_OK_ACK_SIZE) {
			errno = EBADMSG;
			goto done;
		}
		break;

	case DL_ERROR_ACK:
		if (size < DL_ERROR_ACK_SIZE) {
			errno = EBADMSG;
			goto done;
		}

		dleap = (dl_error_ack_t *)buf;
		switch (dleap->dl_errno) {
		case DL_NOTSUPPORTED:
		case DL_UNSUPPORTED:
			errno = ENOTSUP;
			break;

		case DL_NOTENAB:
			errno = EINVAL;
			break;

		case DL_SYSERR:
			errno = dleap->dl_unix_errno;
			break;

		default:
			errno = EPROTO;
			break;
		}
		goto done;

	default:
		errno = EBADMSG;
		goto done;
	}

	rc = 0;	/* success */
done:
	free(buf);
	return (rc);
}

int
dlpi_promiscon(int fd, int timeout, uint_t level)
{
	return (i_dlpi_promisc(fd, timeout, DLPI_PROMISC_ON, level));
}

int
dlpi_promiscoff(int fd, int timeout, uint_t level)
{
	return (i_dlpi_promisc(fd, timeout, DLPI_PROMISC_OFF, level));
}

int
dlpi_phys_addr(int fd, int timeout, uint_t type, uint8_t *addrp,
    size_t *addrlenp)
{
	int			rc = -1;
	size_t			size;
	dl_phys_addr_req_t	dlpar;
	dl_phys_addr_ack_t	*dlpaap;
	dl_error_ack_t		*dleap;
	union DL_primitives	*buf;
	union DL_primitives	*udlp;

	size = 0;
	size = MAX(sizeof (dl_phys_addr_ack_t) + MAXADDRLEN, size);
	size = MAX(sizeof (dl_error_ack_t), size);

	if ((buf = malloc(size)) == NULL)
		return (-1);

	dlpar.dl_primitive = DL_PHYS_ADDR_REQ;
	dlpar.dl_addr_type = type;

	if (strputmsg(fd, (uint8_t *)&dlpar, DL_PHYS_ADDR_REQ_SIZE, 0) == -1)
		goto done;

	if (strgetmsg(fd, timeout, (char *)buf, &size, NULL, NULL) == -1)
		goto done;

	if (size < sizeof (t_uscalar_t)) {
		errno = EBADMSG;
		goto done;
	}

	udlp = (union DL_primitives *)buf;
	switch (udlp->dl_primitive) {
	case DL_PHYS_ADDR_ACK:
		if (size < DL_PHYS_ADDR_ACK_SIZE) {
			errno = EBADMSG;
			goto done;
		}

		dlpaap = (dl_phys_addr_ack_t *)buf;
		if (dlpaap->dl_addr_offset != 0) {
			if (dlpaap->dl_addr_length == 0) {
				errno = EPROTO;
				goto done;
			}

			if (addrlenp != NULL)
				*addrlenp = dlpaap->dl_addr_length;

			if (addrp != NULL)
				(void) memcpy(addrp,
				    (char *)buf + dlpaap->dl_addr_offset,
				    dlpaap->dl_addr_length);
		}
		break;

	case DL_ERROR_ACK:
		if (size < DL_ERROR_ACK_SIZE) {
			errno = EBADMSG;
			goto done;
		}

		dleap = (dl_error_ack_t *)buf;
		switch (dleap->dl_errno) {
		case DL_SYSERR:
			errno = dleap->dl_unix_errno;
			break;

		default:
			errno = EPROTO;
			break;
		}
		goto done;

	default:
		errno = EBADMSG;
		goto done;
	}

	rc = 0;	/* success */
done:
	free(buf);
	return (rc);
}

int
dlpi_set_phys_addr(int fd, int timeout, uint8_t *addrp,
    size_t addr_length)
{
	int			rc = -1;
	size_t			opsize;
	size_t			size;
	dl_set_phys_addr_req_t	*dlspap;
	dl_error_ack_t		*dleap;
	union DL_primitives	*buf;
	union DL_primitives	*udlp;

	opsize = sizeof (dl_set_phys_addr_req_t) + addr_length;

	size = 0;
	size = MAX(opsize, size);
	size = MAX(sizeof (dl_ok_ack_t), size);
	size = MAX(sizeof (dl_error_ack_t), size);

	if ((buf = malloc(size)) == NULL)
		return (-1);

	dlspap = (dl_set_phys_addr_req_t *)buf;
	dlspap->dl_primitive = DL_SET_PHYS_ADDR_REQ;
	dlspap->dl_addr_length = addr_length;
	dlspap->dl_addr_offset = sizeof (dl_set_phys_addr_req_t);
	(void) memcpy(&dlspap[1], addrp, addr_length);

	if (strputmsg(fd, (uint8_t *)dlspap, opsize, 0) == -1)
		goto done;

	if (strgetmsg(fd, timeout, (char *)buf, &size, NULL, NULL) == -1)
		goto done;

	if (size < sizeof (t_uscalar_t)) {
		errno = EBADMSG;
		goto done;
	}

	udlp = (union DL_primitives *)buf;
	switch (udlp->dl_primitive) {
	case DL_OK_ACK:
		if (size < DL_OK_ACK_SIZE) {
			errno = EBADMSG;
			goto done;
		}
		break;

	case DL_ERROR_ACK:
		if (size < DL_ERROR_ACK_SIZE) {
			errno = EBADMSG;
			goto done;
		}

		dleap = (dl_error_ack_t *)buf;
		switch (dleap->dl_errno) {
		case DL_BADADDR:
			errno = EINVAL;
			break;

		case DL_NOTSUPPORTED:
			errno = ENOTSUP;
			break;

		case DL_SYSERR:
			errno = dleap->dl_unix_errno;
			break;

		default:
			errno = EPROTO;
			break;
		}
		goto done;

	default:
		errno = EBADMSG;
		goto done;
	}

	rc = 0;	/* success */
done:
	free(buf);
	return (rc);
}

void
dlpi_passive(int fd, int timeout)
{
	size_t			size;
	dl_passive_req_t	dlpr;
	union DL_primitives	*buf;

	size = MAX(sizeof (dl_ok_ack_t), sizeof (dl_error_ack_t));

	if ((buf = malloc(size)) == NULL)
		return;

	dlpr.dl_primitive = DL_PASSIVE_REQ;

	/*
	 * We don't care about the outcome of this operation.  We at least
	 * don't want to return until the operation completes or the
	 * timeout expires.
	 */
	if (strputmsg(fd, (uint8_t *)&dlpr, DL_PASSIVE_REQ_SIZE, 0) == 0)
		(void) strgetmsg(fd, timeout, (char *)buf, &size, NULL, NULL);
	free(buf);
}

static int
i_dlpi_style1_open(dlpi_if_attr_t *diap)
{
	int		fd;
	int		cnt;
	dl_info_ack_t	dlia;

	/* Open device */
	if ((fd = dlpi_open(diap->devname)) == -1) {
		diap->style1_failed = B_TRUE;
		diap->mod_pushed = 0;
		return (-1);
	} else {
		diap->style1_fd = fd;
	}

	/*
	 * Try to push modules (if any) onto the device stream
	 */
	for (cnt = 0; cnt < diap->mod_cnt; cnt++) {
		if (ioctl(fd, I_PUSH, diap->modlist[cnt]) == -1) {
			diap->mod_pushed = cnt+1;
			return (-1);
		}
	}

	if (dlpi_info(fd, -1, &dlia, NULL, NULL, NULL, NULL, NULL, NULL) == -1)
		goto failed;

	if (dlia.dl_provider_style != DL_STYLE1)
		goto failed;

	diap->style = DL_STYLE1;

	return (fd);
failed:
	(void) dlpi_close(fd);
	return (-1);
}

static int
i_dlpi_style2_open(dlpi_if_attr_t *diap)
{
	int	fd;
	uint_t	ppa;
	dl_info_ack_t	dlia;

	/*
	 * If style 1 open failed, we need to determine how far it got and
	 * finish up the open() call as a style 2 open
	 *
	 * If no modules were pushed (mod_pushed == 0), then we need to
	 * strip off the ppa off the device name and open it as a style 2
	 * device
	 *
	 * If the pushing of the last module failed, we need to strip off the
	 * ppa from that module and try pushing it as a style 2 module
	 *
	 * Otherwise we failed during the push of an intermediate module and
	 * must fail out and close the device.
	 *
	 * And if style1 did not fail (i.e. we called style2 open directly),
	 * just open the device
	 */
	if (diap->style1_failed) {
		if (!diap->mod_pushed) {
			if (i_dlpi_ifrm_num(diap->devname, &ppa) < 0)
				return (-1);
			if ((fd = dlpi_open(diap->devname)) == -1)
				return (-1);
		} else if (diap->mod_pushed == diap->mod_cnt) {
			if (i_dlpi_ifrm_num(
				    diap->modlist[diap->mod_cnt - 1], &ppa) < 0)
				return (-1);
			diap->mod_pushed--;
			fd = diap->style1_fd;
		} else {
			return (-1);
		}
	} else {
		if ((fd = dlpi_open(diap->devname)) == -1)
			return (-1);
	}

	/*
	 * Try and push modules (if any) onto the device stream
	 */
	for (; diap->mod_pushed < diap->mod_cnt; diap->mod_pushed++) {
		if (ioctl(fd, I_PUSH,
		    diap->modlist[diap->mod_pushed]) == -1)
			goto failed;
	}

	if (dlpi_info(fd, -1, &dlia, NULL, NULL, NULL, NULL, NULL,
	    NULL) == -1)
		goto failed;

	if (dlia.dl_provider_style != DL_STYLE2)
		goto failed;

	diap->style = DL_STYLE2;

	if (dlpi_attach(fd, -1, diap->ppa) < 0)
		goto failed;

	return (fd);
failed:
	(void) dlpi_close(fd);
	return (-1);
}

static int
i_dlpi_ifname_parse(const char *ifname, dlpi_if_attr_t *diap)
{
	char		*modlist = NULL; /* list of modules to push */
	int		cnt = 0; /* number of modules to push */
	char		modbuf[LIFNAMSIZ + 32];
	char		*nxtmod;
	char		*p;
	int		len;

	/* if lun is specified fail (backwards compat) */
	if (strchr(ifname, ':') != NULL)
		return (-1);

	/* save copy of original device name */
	if (strlcpy(diap->ifname, ifname, sizeof (diap->ifname)) >=
	    sizeof (diap->ifname))
		return (-1);

	/* initialize ppa */
	diap->ppa = -1;

	/* get provider name and ppa from ifname */
	len = strlen(ifname);
	for (p = (char *)ifname + len; --p != ifname; len--) {
		if (!isdigit(*p)) {
			(void) strlcpy(diap->provider, ifname, len + 1);
			diap->ppa = atoi(p + 1);
			break;
		}
	}

	if (strlcpy(modbuf, diap->ifname, sizeof (modbuf)) >=
	    sizeof (modbuf))
		return (-1);

	/* parse '.' delimited module list */
	modlist = strchr(modbuf, '.');
	if (modlist != NULL) {
		/* null-terminate interface name (device) */
		*modlist = '\0';
		modlist++;
		while (modlist && cnt < MAX_MODS) {
			if (*modlist == '\0')
				return (-1);

			nxtmod = strchr(modlist, '.');
			if (nxtmod) {
				*nxtmod = '\0';
				nxtmod++;
			}
			if (strlcpy(diap->modlist[cnt], modlist,
			    sizeof (diap->modlist[cnt])) >=
			    sizeof (diap->modlist[cnt]))
				return (-1);
			cnt++;
			modlist = nxtmod;
		}
	}
	diap->mod_cnt = cnt;

	if (strlcpy(diap->devname, modbuf, sizeof (diap->devname)) >=
	    sizeof (diap->devname))
		return (-1);

	return (0);
}

int
dlpi_if_open(const char *ifname, dlpi_if_attr_t *diap,
    boolean_t force_style2)
{
	int	fd;

	if (i_dlpi_ifname_parse(ifname, diap) == -1) {
		errno = EINVAL;
		return (-1);
	}

	if (!force_style2) {
		if ((fd = i_dlpi_style1_open(diap)) != -1)
			return (fd);
	}

	if ((fd = i_dlpi_style2_open(diap)) == -1)
		return (-1);

	return (fd);
}

int
dlpi_if_parse(const char *ifname, char *provider, int *ppap)
{
	dlpi_if_attr_t	diap;

	if (i_dlpi_ifname_parse(ifname, &diap) == -1) {
		errno = EINVAL;
		return (-1);
	}

	if (strlcpy(provider, diap.provider, LIFNAMSIZ) > LIFNAMSIZ)
		return (-1);

	if (ppap != NULL)
		*ppap = diap.ppa;

	return (0);
}

/*
 * attempt to remove ppa from end of file name
 * return -1 if none found
 * return ppa if found and remove the ppa from the filename
 */
static int
i_dlpi_ifrm_num(char *fname, unsigned int *ppa)
{
	int	i;
	uint_t	p = 0;
	unsigned int	m = 1;

	i = strlen(fname) - 1;

	while (i >= 0 && isdigit(fname[i])) {
		p += (fname[i] - '0')*m;
		m *= 10;
		i--;
	}

	if (m == 1) {
		return (-1);
	}

	fname[i + 1] = '\0';
	*ppa = p;
	return (0);
}
