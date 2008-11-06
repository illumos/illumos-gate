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
#include <sys/param.h>
#include <sys/stat.h>
#include <libdladm_impl.h>
#include <libintl.h>
#include <libdlpi.h>

static char		dladm_rootdir[MAXPATHLEN] = "/";

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
		s = "change cannot be persistent, specify -t please";
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
	default:
		return (DLADM_STATUS_FAILED);
	}
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
i_dladm_rw_db(const char *db_file, mode_t db_perms,
    dladm_status_t (*process_db)(void *, FILE *, FILE *),
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
	status = (*process_db)(arg, fp, nfp);
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
