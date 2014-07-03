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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <strings.h>
#include <dirent.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/dld.h>
#include <sys/dld_ioc.h>
#include <libdladm_impl.h>
#include <libintl.h>
#include <libdlpi.h>
#include <libdllink.h>

static char	dladm_rootdir[MAXPATHLEN] = "/";

typedef struct media_type_desc {
	uint32_t	media_type;
#define	MAX_MEDIA_TYPE_STRING	32
	const char	media_type_str[MAX_MEDIA_TYPE_STRING];
} media_type_t;

static media_type_t media_type_table[] =  {
	{ DL_ETHER,	"Ethernet" },
	{ DL_WIFI,	"WiFi" },
	{ DL_IB,	"Infiniband" },
	{ DL_IPV4,	"IPv4Tunnel" },
	{ DL_IPV6,	"IPv6Tunnel" },
	{ DL_6TO4,	"6to4Tunnel" },
	{ DL_CSMACD,	"CSMA/CD" },
	{ DL_TPB,	"TokenBus" },
	{ DL_TPR,	"TokenRing" },
	{ DL_METRO,	"MetroNet" },
	{ DL_HDLC,	"HDLC" },
	{ DL_CHAR,	"SyncCharacter" },
	{ DL_CTCA,	"CTCA" },
	{ DL_FDDI, 	"FDDI" },
	{ DL_FC, 	"FiberChannel" },
	{ DL_ATM, 	"ATM" },
	{ DL_IPATM, 	"ATM(ClassicIP)" },
	{ DL_X25, 	"X.25" },
	{ DL_IPX25, 	"X.25(ClassicIP)" },
	{ DL_ISDN, 	"ISDN" },
	{ DL_HIPPI, 	"HIPPI" },
	{ DL_100VG, 	"100BaseVGEthernet" },
	{ DL_100VGTPR, 	"100BaseVGTokenRing" },
	{ DL_ETH_CSMA, 	"IEEE802.3" },
	{ DL_100BT, 	"100BaseT" },
	{ DL_FRAME, 	"FrameRelay" },
	{ DL_MPFRAME, 	"MPFrameRelay" },
	{ DL_ASYNC, 	"AsyncCharacter" },
	{ DL_IPNET, 	"IPNET" },
	{ DL_OTHER, 	"Other" }
};
#define	MEDIATYPECOUNT	(sizeof (media_type_table) / sizeof (media_type_t))

typedef struct {
	uint32_t	lp_type;
	char		*lp_name;
} link_protect_t;

static link_protect_t link_protect_types[] = {
	{ MPT_MACNOSPOOF, "mac-nospoof" },
	{ MPT_RESTRICTED, "restricted" },
	{ MPT_IPNOSPOOF, "ip-nospoof" },
	{ MPT_DHCPNOSPOOF, "dhcp-nospoof" }
};
#define	LPTYPES	(sizeof (link_protect_types) / sizeof (link_protect_t))

dladm_status_t
dladm_open(dladm_handle_t *handle)
{
	int dld_fd;

	if (handle == NULL)
		return (DLADM_STATUS_BADARG);

	if ((dld_fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
		return (dladm_errno2status(errno));

	/*
	 * Don't open DLMGMT_DOOR now.  dlmgmtd(1M) is not able to
	 * open the door when the dladm handle is opened because the
	 * door hasn't been created yet at that time.  Thus, we must
	 * open it on-demand in dladm_door_fd().  Move the open()
	 * to dladm_door_fd() for all cases.
	 */

	if ((*handle = malloc(sizeof (struct dladm_handle))) == NULL) {
		(void) close(dld_fd);
		return (DLADM_STATUS_NOMEM);
	}

	(*handle)->dld_fd = dld_fd;
	(*handle)->door_fd = -1;

	return (DLADM_STATUS_OK);
}

void
dladm_close(dladm_handle_t handle)
{
	if (handle != NULL) {
		(void) close(handle->dld_fd);
		if (handle->door_fd != -1)
			(void) close(handle->door_fd);
		free(handle);
	}
}

int
dladm_dld_fd(dladm_handle_t handle)
{
	return (handle->dld_fd);
}

/*
 * If DLMGMT_DOOR hasn't been opened in the handle yet, open it.
 */
dladm_status_t
dladm_door_fd(dladm_handle_t handle, int *door_fd)
{
	int fd;

	if (handle->door_fd == -1) {
		if ((fd = open(DLMGMT_DOOR, O_RDONLY)) < 0)
			return (dladm_errno2status(errno));
		handle->door_fd = fd;
	}
	*door_fd = handle->door_fd;

	return (DLADM_STATUS_OK);
}

const char *
dladm_status2str(dladm_status_t status, char *buf)
{
	const char	*s;

	switch (status) {
	case DLADM_STATUS_OK:
		s = "ok";
		break;
	case DLADM_STATUS_BADARG:
		s = "invalid argument";
		break;
	case DLADM_STATUS_FAILED:
		s = "operation failed";
		break;
	case DLADM_STATUS_TOOSMALL:
		s = "buffer size too small";
		break;
	case DLADM_STATUS_NOTSUP:
		s = "operation not supported";
		break;
	case DLADM_STATUS_NOTFOUND:
		s = "object not found";
		break;
	case DLADM_STATUS_BADVAL:
		s = "invalid value";
		break;
	case DLADM_STATUS_NOMEM:
		s = "insufficient memory";
		break;
	case DLADM_STATUS_EXIST:
		s = "object already exists";
		break;
	case DLADM_STATUS_LINKINVAL:
		s = "invalid link";
		break;
	case DLADM_STATUS_PROPRDONLY:
		s = "read-only property";
		break;
	case DLADM_STATUS_BADVALCNT:
		s = "invalid number of values";
		break;
	case DLADM_STATUS_DBNOTFOUND:
		s = "database not found";
		break;
	case DLADM_STATUS_DENIED:
		s = "permission denied";
		break;
	case DLADM_STATUS_IOERR:
		s = "I/O error";
		break;
	case DLADM_STATUS_TEMPONLY:
		s = "change cannot be persistent";
		break;
	case DLADM_STATUS_TIMEDOUT:
		s = "operation timed out";
		break;
	case DLADM_STATUS_ISCONN:
		s = "already connected";
		break;
	case DLADM_STATUS_NOTCONN:
		s = "not connected";
		break;
	case DLADM_STATUS_REPOSITORYINVAL:
		s = "invalid configuration repository";
		break;
	case DLADM_STATUS_MACADDRINVAL:
		s = "invalid MAC address";
		break;
	case DLADM_STATUS_KEYINVAL:
		s = "invalid key";
		break;
	case DLADM_STATUS_INVALIDMACADDRLEN:
		s = "invalid MAC address length";
		break;
	case DLADM_STATUS_INVALIDMACADDRTYPE:
		s = "invalid MAC address type";
		break;
	case DLADM_STATUS_LINKBUSY:
		s = "link busy";
		break;
	case DLADM_STATUS_VIDINVAL:
		s = "invalid VLAN identifier";
		break;
	case DLADM_STATUS_TRYAGAIN:
		s = "try again later";
		break;
	case DLADM_STATUS_NONOTIF:
		s = "link notification is not supported";
		break;
	case DLADM_STATUS_BADTIMEVAL:
		s = "invalid time range";
		break;
	case DLADM_STATUS_INVALIDMACADDR:
		s = "invalid MAC address value";
		break;
	case DLADM_STATUS_INVALIDMACADDRNIC:
		s = "MAC address reserved for use by underlying data-link";
		break;
	case DLADM_STATUS_INVALIDMACADDRINUSE:
		s = "MAC address is already in use";
		break;
	case DLADM_STATUS_MACFACTORYSLOTINVALID:
		s = "invalid factory MAC address slot";
		break;
	case DLADM_STATUS_MACFACTORYSLOTUSED:
		s = "factory MAC address slot already used";
		break;
	case DLADM_STATUS_MACFACTORYSLOTALLUSED:
		s = "all factory MAC address slots are in use";
		break;
	case DLADM_STATUS_MACFACTORYNOTSUP:
		s = "factory MAC address slots not supported";
		break;
	case DLADM_STATUS_INVALIDMACPREFIX:
		s = "Invalid MAC address prefix value";
		break;
	case DLADM_STATUS_INVALIDMACPREFIXLEN:
		s = "Invalid MAC address prefix length";
		break;
	case DLADM_STATUS_BADCPUID:
		s = "non-existent processor ID";
		break;
	case DLADM_STATUS_CPUERR:
		s = "could not determine processor status";
		break;
	case DLADM_STATUS_CPUNOTONLINE:
		s = "processor not online";
		break;
	case DLADM_STATUS_TOOMANYELEMENTS:
		s = "too many elements specified";
		break;
	case DLADM_STATUS_BADRANGE:
		s = "invalid range";
		break;
	case DLADM_STATUS_DB_NOTFOUND:
		s = "database not found";
		break;
	case DLADM_STATUS_DB_PARSE_ERR:
		s = "database parse error";
		break;
	case DLADM_STATUS_PROP_PARSE_ERR:
		s = "property parse error";
		break;
	case DLADM_STATUS_ATTR_PARSE_ERR:
		s = "attribute parse error";
		break;
	case DLADM_STATUS_FLOW_DB_ERR:
		s = "flow database error";
		break;
	case DLADM_STATUS_FLOW_DB_OPEN_ERR:
		s = "flow database open error";
		break;
	case DLADM_STATUS_FLOW_DB_PARSE_ERR:
		s = "flow database parse error";
		break;
	case DLADM_STATUS_FLOWPROP_DB_PARSE_ERR:
		s = "flow property database parse error";
		break;
	case DLADM_STATUS_FLOW_ADD_ERR:
		s = "flow add error";
		break;
	case DLADM_STATUS_FLOW_WALK_ERR:
		s = "flow walk error";
		break;
	case DLADM_STATUS_FLOW_IDENTICAL:
		s = "a flow with identical attributes exists";
		break;
	case DLADM_STATUS_FLOW_INCOMPATIBLE:
		s = "flow(s) with incompatible attributes exists";
		break;
	case DLADM_STATUS_FLOW_EXISTS:
		s = "link still has flows";
		break;
	case DLADM_STATUS_PERSIST_FLOW_EXISTS:
		s = "persistent flow with the same name exists";
		break;
	case DLADM_STATUS_INVALID_IP:
		s = "invalid IP address";
		break;
	case DLADM_STATUS_INVALID_PREFIXLEN:
		s = "invalid IP prefix length";
		break;
	case DLADM_STATUS_INVALID_PROTOCOL:
		s = "invalid IP protocol";
		break;
	case DLADM_STATUS_INVALID_PORT:
		s = "invalid port number";
		break;
	case DLADM_STATUS_INVALID_DSF:
		s = "invalid dsfield";
		break;
	case DLADM_STATUS_INVALID_DSFMASK:
		s = "invalid dsfield mask";
		break;
	case DLADM_STATUS_INVALID_MACMARGIN:
		s = "MTU check failed, use lower MTU or -f option";
		break;
	case DLADM_STATUS_BADPROP:
		s = "invalid property";
		break;
	case DLADM_STATUS_MINMAXBW:
		s = "minimum value for maxbw is 1200K";
		break;
	case DLADM_STATUS_NO_HWRINGS:
		s = "request hw rings failed";
		break;
	case DLADM_STATUS_PERMONLY:
		s = "change must be persistent";
		break;
	case DLADM_STATUS_OPTMISSING:
		s = "optional software not installed";
		break;
	case DLADM_STATUS_IPTUNTYPE:
		s = "invalid IP tunnel type";
		break;
	case DLADM_STATUS_IPTUNTYPEREQD:
		s = "IP tunnel type required";
		break;
	case DLADM_STATUS_BADIPTUNLADDR:
		s = "invalid local IP tunnel address";
		break;
	case DLADM_STATUS_BADIPTUNRADDR:
		s = "invalid remote IP tunnel address";
		break;
	case DLADM_STATUS_ADDRINUSE:
		s = "address already in use";
		break;
	case DLADM_STATUS_POOLCPU:
		s = "pool and cpus property are mutually exclusive";
		break;
	case DLADM_STATUS_INVALID_PORT_INSTANCE:
		s = "invalid IB phys link";
		break;
	case DLADM_STATUS_PORT_IS_DOWN:
		s = "port is down";
		break;
	case DLADM_STATUS_PARTITION_EXISTS:
		s = "partition already exists";
		break;
	case DLADM_STATUS_PKEY_NOT_PRESENT:
		s = "PKEY is not present on the port";
		break;
	case DLADM_STATUS_INVALID_PKEY:
		s = "invalid PKEY";
		break;
	case DLADM_STATUS_NO_IB_HW_RESOURCE:
		s = "IB internal resource not available";
		break;
	case DLADM_STATUS_INVALID_PKEY_TBL_SIZE:
		s = "invalid PKEY table size";
		break;
	case DLADM_STATUS_PORT_NOPROTO:
		s = "local or remote port requires transport";
		break;
	case DLADM_STATUS_INVALID_MTU:
		s = "MTU check failed, MTU outside of device's supported range";
		break;
	default:
		s = "<unknown error>";
		break;
	}
	(void) snprintf(buf, DLADM_STRSIZE, "%s", dgettext(TEXT_DOMAIN, s));
	return (buf);
}

/*
 * Convert a unix errno to a dladm_status_t.
 * We only convert errnos that are likely to be encountered. All others
 * are mapped to DLADM_STATUS_FAILED.
 */
dladm_status_t
dladm_errno2status(int err)
{
	switch (err) {
	case 0:
		return (DLADM_STATUS_OK);
	case EINVAL:
		return (DLADM_STATUS_BADARG);
	case EEXIST:
		return (DLADM_STATUS_EXIST);
	case ENOENT:
		return (DLADM_STATUS_NOTFOUND);
	case ENOSPC:
		return (DLADM_STATUS_TOOSMALL);
	case ENOMEM:
		return (DLADM_STATUS_NOMEM);
	case ENOTSUP:
		return (DLADM_STATUS_NOTSUP);
	case ENETDOWN:
		return (DLADM_STATUS_NONOTIF);
	case EACCES:
	case EPERM:
		return (DLADM_STATUS_DENIED);
	case EIO:
		return (DLADM_STATUS_IOERR);
	case EBUSY:
		return (DLADM_STATUS_LINKBUSY);
	case EAGAIN:
		return (DLADM_STATUS_TRYAGAIN);
	case ENOTEMPTY:
		return (DLADM_STATUS_FLOW_EXISTS);
	case EOPNOTSUPP:
		return (DLADM_STATUS_FLOW_INCOMPATIBLE);
	case EALREADY:
		return (DLADM_STATUS_FLOW_IDENTICAL);
	case EADDRINUSE:
		return (DLADM_STATUS_ADDRINUSE);
	default:
		return (DLADM_STATUS_FAILED);
	}
}

boolean_t
dladm_str2interval(char *oarg, uint32_t *interval)
{
	int		val;
	char		*endp = NULL;

	errno = 0;
	val = strtol(oarg, &endp, 10);
	if (errno != 0 || val <= 0 || *endp != '\0')
		return (B_FALSE);

	*interval = val;

	return (B_TRUE);
}

dladm_status_t
dladm_str2bw(char *oarg, uint64_t *bw)
{
	char		*endp = NULL;
	int64_t		n;
	int		mult = 1;

	n = strtoull(oarg, &endp, 10);

	if ((errno != 0) || (strlen(endp) > 1))
		return (DLADM_STATUS_BADARG);

	if (n < 0)
		return (DLADM_STATUS_BADVAL);

	switch (*endp) {
	case 'k':
	case 'K':
		mult = 1000;
		break;
	case 'm':
	case 'M':
	case '\0':
		mult = 1000000;
		break;
	case 'g':
	case 'G':
		mult = 1000000000;
		break;
	case '%':
		/*
		 * percentages not supported for now,
		 * see RFE 6540675
		 */
		return (DLADM_STATUS_NOTSUP);
	default:
		return (DLADM_STATUS_BADVAL);
	}

	*bw = n * mult;

	/* check for overflow */
	if (*bw / mult != n)
		return (DLADM_STATUS_BADARG);

	return (DLADM_STATUS_OK);
}

/*
 * Convert bandwidth in bps to a string in Mbps.  For values greater
 * than 1Mbps or 1000000, print a whole Mbps value.  For values that
 * have fractional Mbps in whole Kbps, print the bandwidth in a manner
 * similar to a floating point format.
 *
 *        bps       string
 *          0            0
 *        100            0
 *       2000        0.002
 *     431000        0.431
 *    1000000            1
 *    1030000        1.030
 *  100000000          100
 */
const char *
dladm_bw2str(int64_t bw, char *buf)
{
	int kbps, mbps;

	kbps = (bw%1000000)/1000;
	mbps = bw/1000000;
	if (kbps != 0) {
		if (mbps == 0)
			(void) snprintf(buf, DLADM_STRSIZE, "0.%03u", kbps);
		else
			(void) snprintf(buf, DLADM_STRSIZE, "%5u.%03u", mbps,
			    kbps);
	} else {
		(void) snprintf(buf, DLADM_STRSIZE, "%5u", mbps);
	}

	return (buf);
}

#define	LOCK_DB_PERMS	S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH

static int
i_dladm_lock_db(const char *lock_file, short type)
{
	int	lock_fd;
	struct	flock lock;

	if ((lock_fd = open(lock_file, O_RDWR | O_CREAT | O_TRUNC,
	    LOCK_DB_PERMS)) < 0)
		return (-1);

	lock.l_type = type;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(lock_fd, F_SETLKW, &lock) < 0) {
		int err = errno;

		(void) close(lock_fd);
		(void) unlink(lock_file);
		errno = err;
		return (-1);
	}
	return (lock_fd);
}

static void
i_dladm_unlock_db(const char *lock_file, int fd)
{
	struct flock lock;

	if (fd < 0)
		return;

	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	(void) fcntl(fd, F_SETLKW, &lock);
	(void) close(fd);
	(void) unlink(lock_file);
}

/*
 * Given a link class, returns its class string.
 */
const char *
dladm_class2str(datalink_class_t class, char *buf)
{
	const char *s;

	switch (class) {
	case DATALINK_CLASS_PHYS:
		s = "phys";
		break;
	case DATALINK_CLASS_VLAN:
		s = "vlan";
		break;
	case DATALINK_CLASS_AGGR:
		s = "aggr";
		break;
	case DATALINK_CLASS_VNIC:
		s = "vnic";
		break;
	case DATALINK_CLASS_ETHERSTUB:
		s = "etherstub";
		break;
	case DATALINK_CLASS_IPTUN:
		s = "iptun";
		break;
	case DATALINK_CLASS_SIMNET:
		s = "simnet";
		break;
	case DATALINK_CLASS_BRIDGE:
		s = "bridge";
		break;
	case DATALINK_CLASS_PART:
		s = "part";
		break;
	default:
		s = "unknown";
		break;
	}

	(void) snprintf(buf, DLADM_STRSIZE, "%s", s);
	return (buf);
}

/*
 * Given a physical link media type, returns its media type string.
 */
const char *
dladm_media2str(uint32_t media, char *buf)
{
	const char *s = "--";
	media_type_t *mt;
	int idx;

	for (idx = 0; idx < MEDIATYPECOUNT; idx++) {
		mt = media_type_table + idx;
		if (mt->media_type == media) {
			s = mt->media_type_str;
			break;
		}
	}

	(void) snprintf(buf, DLADM_STRSIZE, "%s", s);
	return (buf);
}

/*
 * Given a physical link media type string, returns its media type constant.
 */
uint32_t
dladm_str2media(const char *buf)
{
	media_type_t *mt;
	int idx;

	for (idx = 0; idx < MEDIATYPECOUNT; idx++) {
		mt = media_type_table + idx;
		if (strcasecmp(buf, mt->media_type_str) == 0)
			return (mt->media_type);
	}

	return (DL_OTHER);
}

dladm_status_t
i_dladm_rw_db(dladm_handle_t handle, const char *db_file, mode_t db_perms,
    dladm_status_t (*process_db)(dladm_handle_t, void *, FILE *, FILE *),
    void *arg, boolean_t writeop)
{
	dladm_status_t	status = DLADM_STATUS_OK;
	FILE		*fp, *nfp = NULL;
	char		lock[MAXPATHLEN];
	char		file[MAXPATHLEN];
	char		newfile[MAXPATHLEN];
	char		*db_basename;
	int		nfd, lock_fd;

	/*
	 * If we are called from a boot script such as net-physical,
	 * it's quite likely that the root fs is still not writable.
	 * For this case, it's ok for the lock creation to fail since
	 * no one else could be accessing our configuration file.
	 */
	db_basename = strrchr(db_file, '/');
	if (db_basename == NULL || db_basename[1] == '\0')
		return (dladm_errno2status(EINVAL));
	db_basename++;
	(void) snprintf(lock, MAXPATHLEN, "/tmp/%s.lock", db_basename);
	if ((lock_fd = i_dladm_lock_db
	    (lock, (writeop ? F_WRLCK : F_RDLCK))) < 0 && errno != EROFS)
		return (dladm_errno2status(errno));

	(void) snprintf(file, MAXPATHLEN, "%s/%s", dladm_rootdir, db_file);
	if ((fp = fopen(file, (writeop ? "r+" : "r"))) == NULL) {
		int	err = errno;

		i_dladm_unlock_db(lock, lock_fd);
		if (err == ENOENT)
			return (DLADM_STATUS_DBNOTFOUND);

		return (dladm_errno2status(err));
	}

	if (writeop) {
		(void) snprintf(newfile, MAXPATHLEN, "%s/%s.new",
		    dladm_rootdir, db_file);
		if ((nfd = open(newfile, O_WRONLY | O_CREAT | O_TRUNC,
		    db_perms)) < 0) {
			(void) fclose(fp);
			i_dladm_unlock_db(lock, lock_fd);
			return (dladm_errno2status(errno));
		}

		if ((nfp = fdopen(nfd, "w")) == NULL) {
			(void) close(nfd);
			(void) fclose(fp);
			(void) unlink(newfile);
			i_dladm_unlock_db(lock, lock_fd);
			return (dladm_errno2status(errno));
		}
	}
	status = (*process_db)(handle, arg, fp, nfp);
	if (!writeop || status != DLADM_STATUS_OK)
		goto done;

	/* Set permissions on file to db_perms */
	if (fchmod(nfd, db_perms) < 0) {
		status = dladm_errno2status(errno);
		goto done;
	}

	/*
	 * Configuration files need to be owned by the 'dladm' user and
	 * 'netadm' group.
	 */
	if (fchown(nfd, UID_DLADM, GID_NETADM) < 0) {
		status = dladm_errno2status(errno);
		goto done;
	}

	if (fflush(nfp) == EOF) {
		status = dladm_errno2status(errno);
		goto done;
	}
	(void) fclose(fp);
	(void) fclose(nfp);

	if (rename(newfile, file) < 0) {
		(void) unlink(newfile);
		i_dladm_unlock_db(lock, lock_fd);
		return (dladm_errno2status(errno));
	}

	i_dladm_unlock_db(lock, lock_fd);
	return (DLADM_STATUS_OK);

done:
	if (nfp != NULL) {
		(void) fclose(nfp);
		if (status != DLADM_STATUS_OK)
			(void) unlink(newfile);
	}
	(void) fclose(fp);
	i_dladm_unlock_db(lock, lock_fd);
	return (status);
}

dladm_status_t
dladm_set_rootdir(const char *rootdir)
{
	DIR	*dp;

	if (rootdir == NULL || *rootdir != '/' ||
	    (dp = opendir(rootdir)) == NULL)
		return (DLADM_STATUS_BADARG);

	(void) strncpy(dladm_rootdir, rootdir, MAXPATHLEN);
	(void) closedir(dp);
	return (DLADM_STATUS_OK);
}

boolean_t
dladm_valid_linkname(const char *link)
{
	size_t		len = strlen(link);
	const char	*cp;

	if (len >= MAXLINKNAMELEN)
		return (B_FALSE);

	/*
	 * The link name cannot start with a digit and must end with a digit.
	 */
	if ((isdigit(link[0]) != 0) || (isdigit(link[len - 1]) == 0))
		return (B_FALSE);

	/*
	 * The legal characters in a link name are:
	 * alphanumeric (a-z,  A-Z,  0-9), underscore ('_'), and '.'.
	 */
	for (cp = link; *cp != '\0'; cp++) {
		if ((isalnum(*cp) == 0) && (*cp != '_') && (*cp != '.'))
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Convert priority string to a value.
 */
dladm_status_t
dladm_str2pri(char *token, mac_priority_level_t *pri)
{
	if (strlen(token) == strlen("low") &&
	    strncasecmp(token, "low", strlen("low")) == 0) {
		*pri = MPL_LOW;
	} else if (strlen(token) == strlen("medium") &&
	    strncasecmp(token, "medium", strlen("medium")) == 0) {
		*pri = MPL_MEDIUM;
	} else if (strlen(token) == strlen("high") &&
	    strncasecmp(token, "high", strlen("high")) == 0) {
		*pri = MPL_HIGH;
	} else {
		return (DLADM_STATUS_BADVAL);
	}
	return (DLADM_STATUS_OK);
}

/*
 * Convert priority value to a string.
 */
const char *
dladm_pri2str(mac_priority_level_t pri, char *buf)
{
	const char	*s;

	switch (pri) {
	case MPL_LOW:
		s = "low";
		break;
	case MPL_MEDIUM:
		s = "medium";
		break;
	case MPL_HIGH:
		s = "high";
		break;
	default:
		s = "--";
		break;
	}
	(void) snprintf(buf, DLADM_STRSIZE, "%s", dgettext(TEXT_DOMAIN, s));
	return (buf);
}

/*
 * Convert protect string to a value.
 */
dladm_status_t
dladm_str2protect(char *token, uint32_t *ptype)
{
	link_protect_t	*lp;
	int		i;

	for (i = 0; i < LPTYPES; i++) {
		lp = &link_protect_types[i];
		if (strcmp(token, lp->lp_name) == 0) {
			*ptype = lp->lp_type;
			return (DLADM_STATUS_OK);
		}
	}
	return (DLADM_STATUS_BADVAL);
}

/*
 * Convert protect value to a string.
 */
const char *
dladm_protect2str(uint32_t ptype, char *buf)
{
	const char	*s = "--";
	link_protect_t	*lp;
	int		i;

	for (i = 0; i < LPTYPES; i++) {
		lp = &link_protect_types[i];
		if (lp->lp_type == ptype) {
			s = lp->lp_name;
			break;
		}
	}
	(void) snprintf(buf, DLADM_STRSIZE, "%s", dgettext(TEXT_DOMAIN, s));
	return (buf);
}

/*
 * Convert an IPv4 address to/from a string.
 */
const char *
dladm_ipv4addr2str(void *addr, char *buf)
{
	if (inet_ntop(AF_INET, addr, buf, INET_ADDRSTRLEN) == NULL)
		buf[0] = '\0';

	return (buf);
}

dladm_status_t
dladm_str2ipv4addr(char *token, void *addr)
{
	return (inet_pton(AF_INET, token, addr) == 1 ?
	    DLADM_STATUS_OK : DLADM_STATUS_INVALID_IP);
}

const char *
dladm_ipv6addr2str(void *addr, char *buf)
{
	if (inet_ntop(AF_INET6, addr, buf, INET6_ADDRSTRLEN) == NULL)
		buf[0] = '\0';

	return (buf);
}

dladm_status_t
dladm_str2ipv6addr(char *token, void *addr)
{
	return (inet_pton(AF_INET6, token, addr) == 1 ?
	    DLADM_STATUS_OK : DLADM_STATUS_INVALID_IP);
}

/*
 * Find the set bits in a mask.
 * This is used for expanding a bitmask into individual sub-masks
 * which can be used for further processing.
 */
void
dladm_find_setbits32(uint32_t mask, uint32_t *list, uint32_t *cnt)
{
	int	i, c = 0;

	for (i = 0; i < 32; i++) {
		if (((1 << i) & mask) != 0)
			list[c++] = 1 << i;
	}
	*cnt = c;
}

void
dladm_free_args(dladm_arg_list_t *list)
{
	if (list != NULL) {
		free(list->al_buf);
		free(list);
	}
}

dladm_status_t
dladm_parse_args(char *str, dladm_arg_list_t **listp, boolean_t novalues)
{
	dladm_arg_list_t	*list;
	dladm_arg_info_t	*aip;
	char			*buf, *curr;
	int			len, i;

	if (str == NULL)
		return (DLADM_STATUS_BADVAL);

	if (str[0] == '\0')
		return (DLADM_STATUS_OK);

	list = malloc(sizeof (dladm_arg_list_t));
	if (list == NULL)
		return (dladm_errno2status(errno));

	list->al_count = 0;
	list->al_buf = buf = strdup(str);
	if (buf == NULL)
		return (dladm_errno2status(errno));

	curr = buf;
	len = strlen(buf);
	aip = NULL;
	for (i = 0; i < len; i++) {
		char		c = buf[i];
		boolean_t	match = (c == '=' || c == ',');

		if (!match && i != len - 1)
			continue;

		if (match) {
			buf[i] = '\0';
			if (*curr == '\0')
				goto fail;
		}

		if (aip != NULL && c != '=') {
			if (aip->ai_count > DLADM_MAX_ARG_VALS)
				goto fail;

			if (novalues)
				goto fail;

			aip->ai_val[aip->ai_count] = curr;
			aip->ai_count++;
		} else {
			if (list->al_count > DLADM_MAX_ARG_VALS)
				goto fail;

			aip = &list->al_info[list->al_count];
			aip->ai_name = curr;
			aip->ai_count = 0;
			list->al_count++;
			if (c == ',')
				aip = NULL;
		}
		curr = buf + i + 1;
	}

	*listp = list;
	return (DLADM_STATUS_OK);

fail:
	dladm_free_args(list);
	return (DLADM_STATUS_FAILED);
}

/*
 * mac_propval_range_t functions.  Currently implemented for only
 * ranges of uint32_t elements, but can be expanded as required.
 */
/*
 * Convert an array of strings (which can be ranges or individual
 * elements) into a single mac_propval_range_t structure which
 * is allocated here but should be freed by the caller.
 */
dladm_status_t
dladm_strs2range(char **prop_val, uint_t val_cnt,
	mac_propval_type_t type, mac_propval_range_t **range)
{
	int			i;
	char			*endp;
	mac_propval_range_t	*rangep;
	dladm_status_t		status = DLADM_STATUS_OK;

	switch (type) {
	case MAC_PROPVAL_UINT32: {
		mac_propval_uint32_range_t	*ur;

		/* Allocate range structure */
		rangep = malloc(sizeof (mac_propval_range_t) +
		    (val_cnt-1)*(sizeof (mac_propval_uint32_range_t)));
		if (rangep == NULL)
			return (DLADM_STATUS_NOMEM);

		rangep->mpr_count = 0;
		ur = &rangep->mpr_range_uint32[0];
		for (i = 0; i < val_cnt; i++, ur++) {
			errno = 0;
			if (strchr(prop_val[i], '-') == NULL) {
				/* single element */
				ur->mpur_min = ur->mpur_max =
				    strtol(prop_val[i], &endp, 10);
				if ((endp != NULL) && (*endp != '\0')) {
					return (DLADM_STATUS_BADRANGE);
				}
			} else {
				/* range of elements */
				ur->mpur_min = strtol(prop_val[i], &endp, 10);
				if (*endp++ != '-')
					return (DLADM_STATUS_BADRANGE);
				ur->mpur_max = strtol(endp, &endp, 10);
				if (endp != NULL && *endp != '\0' ||
				    ur->mpur_max < ur->mpur_min)
					return (DLADM_STATUS_BADRANGE);
			}
			rangep->mpr_count++;
		}
		break;
	}
	default:
		return (DLADM_STATUS_BADVAL);
	}

	rangep->mpr_type = type;
	*range = rangep;

	return (status);
}

/*
 * Convert a mac_propval_range_t structure into an array of elements.
 */
dladm_status_t
dladm_range2list(mac_propval_range_t *rangep, void *elem, uint_t *nelem)
{
	int		i, j, k;
	dladm_status_t	status = DLADM_STATUS_OK;

	switch (rangep->mpr_type) {
	case MAC_PROPVAL_UINT32: {
		mac_propval_uint32_range_t	*ur;
		uint32_t			*elem32 = elem;

		k = 0;
		ur = &rangep->mpr_range_uint32[0];
		for (i = 0; i < rangep->mpr_count; i++, ur++) {
			for (j = 0; j <= ur->mpur_max - ur->mpur_min; j++) {
				elem32[k++] = ur->mpur_min + j;
				if (k > *nelem) {
					status = DLADM_STATUS_TOOMANYELEMENTS;
					break;
				}
			}
		}
		*nelem = k;
		break;
	}
	default:
		status = DLADM_STATUS_BADVAL;
		break;
	}
	return (status);
}

/*
 * Convert a mac_propval_range_t structure into an array of strings
 * of single elements or ranges.
 */
int
dladm_range2strs(mac_propval_range_t *rangep, char **prop_val)
{
	int	i;

	switch (rangep->mpr_type) {
	case MAC_PROPVAL_UINT32: {
		mac_propval_uint32_range_t	*ur;

		/* Write ranges and individual elements */
		ur = &rangep->mpr_range_uint32[0];
		for (i = 0; i < rangep->mpr_count; i++, ur++) {
			if (ur->mpur_min == ur->mpur_max) {
				/* single element */
				(void) snprintf(prop_val[i], DLADM_PROP_VAL_MAX,
				    "%u", ur->mpur_min);
			} else {
				/* range of elements */
				(void) snprintf(prop_val[i], DLADM_PROP_VAL_MAX,
				    "%u-%u", ur->mpur_min, ur->mpur_max);
			}
		}
		return (0);
	}
	default:
		break;
	}
	return (EINVAL);
}

static int
uint32cmp(const void *a, const void *b)
{
	return (*(uint32_t *)a - *(uint32_t *)b);
}

/*
 * Sort and convert an array of elements into a single
 * mac_propval_range_t structure which is allocated here but
 * should be freed by the caller.
 */
dladm_status_t
dladm_list2range(void *elem, uint_t nelem, mac_propval_type_t type,
    mac_propval_range_t **range)
{
	int			i;
	uint_t			nr = 0;
	mac_propval_range_t	*rangep;
	dladm_status_t		status = DLADM_STATUS_OK;

	switch (type) {
	case MAC_PROPVAL_UINT32: {
		mac_propval_uint32_range_t	*ur;
		uint32_t			*elem32 = elem;
		uint32_t			*sort32;

		/* Allocate range structure */
		rangep = malloc(sizeof (mac_propval_range_t) +
		    (nelem-1)*(sizeof (mac_propval_uint32_range_t)));
		if (rangep == NULL)
			return (DLADM_STATUS_NOMEM);

		/* Allocate array for sorting */
		sort32 = malloc(nelem * sizeof (uint32_t));
		if (sort32 == NULL) {
			free(rangep);
			return (DLADM_STATUS_NOMEM);
		}

		/* Copy and sort list */
		for (i = 0; i < nelem; i++)
			sort32[i] =  elem32[i];
		if (nelem > 1)
			qsort(sort32, nelem, sizeof (uint32_t), uint32cmp);

		/* Convert list to ranges */
		ur = &rangep->mpr_range_uint32[0];
		ur->mpur_min = ur->mpur_max = sort32[0];
		for (i = 1; i < nelem; i++) {
			if (sort32[i]-sort32[i-1] == 1) {
				/* part of current range */
				ur->mpur_max = sort32[i];
			} else {
				/* start a new range */
				nr++; ur++;
				ur->mpur_min = ur->mpur_max = sort32[i];
			}
		}
		free(sort32);
		break;
	}
	default:
		return (DLADM_STATUS_BADRANGE);
	}

	rangep->mpr_type = type;
	rangep->mpr_count = nr + 1;
	*range = rangep;

	return (status);
}
