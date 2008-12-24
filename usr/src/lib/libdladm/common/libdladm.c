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

#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <strings.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/dld.h>
#include <libdladm_impl.h>
#include <libintl.h>
#include <libdlpi.h>

static char	dladm_rootdir[MAXPATHLEN] = "/";

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
	case DLADM_STATUS_CPUMAX:
		s = "non-existent processor ID";
		break;
	case DLADM_STATUS_CPUERR:
		s = "could not determine processor status";
		break;
	case DLADM_STATUS_CPUNOTONLINE:
		s = "processor not online";
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
		s = "minimum value for maxbw is 1.2M";
		break;
	case DLADM_STATUS_NO_HWRINGS:
		s = "request hw rings failed";
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
	default:
		return (DLADM_STATUS_FAILED);
	}
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
 * Convert bandwidth in bps to a string in mpbs.  For values greater
 * than 1mbps or 1000000, print a whole mbps value.  For values that
 * have fractional Mbps in whole Kbps , print the bandwidth in a manner
 * simlilar to a floating point format.
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
	const char *s;

	switch (media) {
	case DL_ETHER:
		s = "Ethernet";
		break;
	case DL_WIFI:
		s = "WiFi";
		break;
	case DL_IB:
		s = "Infiniband";
		break;
	case DL_IPV4:
		s = "IPv4Tunnel";
		break;
	case DL_IPV6:
		s = "IPv6Tunnel";
		break;
	case DL_CSMACD:
		s = "CSMA/CD";
		break;
	case DL_TPB:
		s = "TokenBus";
		break;
	case DL_TPR:
		s = "TokenRing";
		break;
	case DL_METRO:
		s = "MetroNet";
		break;
	case DL_HDLC:
		s = "HDLC";
		break;
	case DL_CHAR:
		s = "SyncCharacter";
		break;
	case DL_CTCA:
		s = "CTCA";
		break;
	case DL_FDDI:
		s = "FDDI";
		break;
	case DL_FC:
		s = "FiberChannel";
		break;
	case DL_ATM:
		s = "ATM";
		break;
	case DL_IPATM:
		s = "ATM(ClassicIP)";
		break;
	case DL_X25:
		s = "X.25";
		break;
	case DL_IPX25:
		s = "X.25(ClassicIP)";
		break;
	case DL_ISDN:
		s = "ISDN";
		break;
	case DL_HIPPI:
		s = "HIPPI";
		break;
	case DL_100VG:
		s = "100BaseVGEthernet";
		break;
	case DL_100VGTPR:
		s = "100BaseVGTokenRing";
		break;
	case DL_ETH_CSMA:
		s = "IEEE802.3";
		break;
	case DL_100BT:
		s = "100BaseT";
		break;
	case DL_FRAME:
		s = "FrameRelay";
		break;
	case DL_MPFRAME:
		s = "MPFrameRelay";
		break;
	case DL_ASYNC:
		s = "AsyncCharacter";
		break;
	case DL_IPNET:
		s = "IPNET";
		break;
	default:
		s = "--";
		break;
	}

	(void) snprintf(buf, DLADM_STRSIZE, "%s", s);
	return (buf);
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

	/*
	 * Configuration files need to be owned by the 'dladm' user.
	 * If we are invoked by root, the file ownership needs to be fixed.
	 */
	if (getuid() == 0 || geteuid() == 0) {
		if (fchown(nfd, UID_DLADM, GID_SYS) < 0) {
			status = dladm_errno2status(errno);
			goto done;
		}
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

	if (len + 1 >= MAXLINKNAMELEN)
		return (B_FALSE);

	/*
	 * The link name cannot start with a digit and must end with a digit.
	 */
	if ((isdigit(link[0]) != 0) || (isdigit(link[len - 1]) == 0))
		return (B_FALSE);

	/*
	 * The legal characters in a link name are:
	 * alphanumeric (a-z,  A-Z,  0-9), and the underscore ('_').
	 */
	for (cp = link; *cp != '\0'; cp++) {
		if ((isalnum(*cp) == 0) && (*cp != '_'))
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
