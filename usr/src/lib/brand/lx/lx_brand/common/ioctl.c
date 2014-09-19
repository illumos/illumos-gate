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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <assert.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stropts.h>
#include <strings.h>
#include <thread.h>
#include <errno.h>
#include <libintl.h>
#include <sys/bitmap.h>
#include <sys/lx_autofs.h>
#include <sys/lx_syscall.h>
#include <sys/modctl.h>
#include <sys/filio.h>
#include <sys/termios.h>
#include <sys/termio.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ptms.h>
#include <sys/ldlinux.h>
#include <sys/lx_ptm.h>
#include <sys/lx_socket.h>
#include <sys/syscall.h>
#include <sys/brand.h>
#include <sys/lx_audio.h>
#include <sys/lx_ioctl.h>
#include <sys/lx_misc.h>
#include <sys/lx_debug.h>
#include <sys/ptyvar.h>
#include <sys/audio.h>
#include <sys/mixer.h>

/* Define _KERNEL to get the devt manipulation macros. */
#define	_KERNEL
#include <sys/sysmacros.h>
#undef	_KERNEL

/* Maximum number of modules on a stream that we can handle. */
#define	MAX_STRMODS	10

/* Maximum buffer size for debugging messages. */
#define	MSGBUF		1024

/* Structure used to define an ioctl translator. */
typedef struct ioc_cmd_translator {
	int	ict_lx_cmd;
	char	*ict_lx_cmd_str;
	int	ict_cmd;
	char	*ict_cmd_str;
	int	(*ict_func)(int fd, struct stat *stat,
	    int cmd, char *cmd_str, intptr_t arg);
} ioc_cmd_translator_t;

/*
 * Structures used to associate a group of ioctl translators with
 * a specific device.
 */
typedef struct ioc_dev_translator {
	char			*idt_driver;
	major_t			idt_major;

	/* Array of command translators. */
	ioc_cmd_translator_t	*idt_cmds;
} ioc_dev_translator_t;

/*
 * Structures used to associate a group of ioctl translators with
 * a specific filesystem.
 */
typedef struct ioc_fs_translator {
	char			*ift_filesystem;

	/* Array of command translators. */
	ioc_cmd_translator_t	*ift_cmds;
} ioc_fs_translator_t;

/* Structure used to define a unsupported ioctl error codes. */
typedef struct ioc_errno_translator {
	int	iet_lx_cmd;
	char	*iet_lx_cmd_str;
	int	iet_errno;
} ioc_errno_translator_t;

/* Structure used to convert oss format flags into Solaris options. */
typedef struct oss_fmt_translator {
	int	oft_oss_fmt;
	int	oft_encoding;
	int	oft_precision;
} oss_fmt_translator_t;

/* Translator forward declerations. */
static oss_fmt_translator_t oft_table[];
static ioc_cmd_translator_t ioc_translators_file[];
static ioc_cmd_translator_t ioc_translators_fifo[];
static ioc_cmd_translator_t ioc_translators_sock[];
static ioc_dev_translator_t ioc_translator_ptm;
static ioc_dev_translator_t *ioc_translators_dev[];
static ioc_fs_translator_t *ioc_translators_fs[];
static ioc_errno_translator_t ioc_translators_errno[];

/*
 * Interface name table.
 */
typedef struct ifname_map {
	char	im_linux[IFNAMSIZ];
	char	im_solaris[IFNAMSIZ];
	struct ifname_map *im_next;
} ifname_map_t;

static ifname_map_t *ifname_map;
static mutex_t ifname_mtx;

/*
 * Macros and structures to help convert integers to string
 * values that they represent (for displaying in debug output).
 */
#define	I2S_ENTRY(x)	{ x, #x },
#define	I2S_END		{ 0, NULL }

typedef struct int2str {
	int	i2s_int;
	char	*i2s_str;
} int2str_t;

static int2str_t st_mode_strings[] = {
	I2S_ENTRY(S_IFIFO)
	I2S_ENTRY(S_IFCHR)
	I2S_ENTRY(S_IFDIR)
	I2S_ENTRY(S_IFBLK)
	I2S_ENTRY(S_IFREG)
	I2S_ENTRY(S_IFLNK)
	I2S_ENTRY(S_IFSOCK)
	I2S_ENTRY(S_IFDOOR)
	I2S_ENTRY(S_IFPORT)
	I2S_END
};

static int2str_t oss_fmt_str[] = {
	I2S_ENTRY(LX_OSS_AFMT_QUERY)
	I2S_ENTRY(LX_OSS_AFMT_MU_LAW)
	I2S_ENTRY(LX_OSS_AFMT_A_LAW)
	I2S_ENTRY(LX_OSS_AFMT_IMA_ADPCM)
	I2S_ENTRY(LX_OSS_AFMT_U8)
	I2S_ENTRY(LX_OSS_AFMT_S16_LE)
	I2S_ENTRY(LX_OSS_AFMT_S16_BE)
	I2S_ENTRY(LX_OSS_AFMT_S8)
	I2S_ENTRY(LX_OSS_AFMT_U16_LE)
	I2S_ENTRY(LX_OSS_AFMT_U16_BE)
	I2S_ENTRY(LX_OSS_AFMT_MPEG)
	I2S_END
};

static void
lx_ioctl_msg(int fd, int cmd, char *lx_cmd_str, struct stat *stat, char *msg)
{
	int	errno_backup = errno;
	char	*path, path_buf[MAXPATHLEN];

	assert(msg != NULL);

	if (lx_debug_enabled == 0)
		return;

	path = lx_fd_to_path(fd, path_buf, sizeof (path_buf));
	if (path == NULL)
		path = "?";

	if (lx_cmd_str == NULL)
		lx_cmd_str = "?";

	/* Display the initial error message and extended ioctl information. */
	lx_debug("\t%s", msg);
	lx_debug("\tlx_ioctl(): cmd = 0x%x - %s, fd = %d - %s",
	    cmd, lx_cmd_str, fd, path);

	/* Display information about the target file, if it's available. */
	if (stat != NULL) {
		major_t	fd_major = getmajor(stat->st_rdev);
		minor_t	fd_minor = getminor(stat->st_rdev);
		int	fd_mode = stat->st_mode & S_IFMT;
		char	*fd_mode_str = "unknown";
		char	buf[LX_MSG_MAXLEN];
		int	i;

		/* Translate the file type bits into a string. */
		for (i = 0; st_mode_strings[i].i2s_str != NULL; i++) {
			if (fd_mode != st_mode_strings[i].i2s_int)
				continue;
			fd_mode_str = st_mode_strings[i].i2s_str;
			break;
		}

		(void) snprintf(buf, sizeof (buf),
		    "\tlx_ioctl(): mode = %s", fd_mode_str);

		if ((fd_mode == S_IFCHR) || (fd_mode == S_IFBLK)) {
			char	*fd_driver[MODMAXNAMELEN + 1];
			int	i;

			/* This is a device so display the devt. */
			i = strlen(buf);
			(void) snprintf(buf + i, sizeof (buf) - i,
			    "; rdev = [%d, %d]", fd_major, fd_minor);

			/* Try to display the drivers name. */
			if (modctl(MODGETNAME,
			    fd_driver, sizeof (fd_driver), &fd_major) == 0) {
				i = strlen(buf);
				(void) snprintf(buf + i, sizeof (buf) - i,
				    "; driver = %s", fd_driver);
			}
		}
		lx_debug(buf);
	}

	/* Restore errno. */
	errno = errno_backup;
}

static int
ldlinux_check(int fd)
{
	struct str_mlist	mlist[MAX_STRMODS];
	struct str_list		strlist;
	int			i;

	/* Get the number of modules on the stream. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, I_LIST, "I_LIST");
	if ((i = ioctl(fd, I_LIST, (struct str_list *)NULL)) < 0) {
		lx_debug("\tldlinux_check(): unable to count stream modules");
		return (-errno);
	}

	/* Sanity check the number of modules on the stream. */
	assert(i <= MAX_STRMODS);

	/* Get the list of modules on the stream. */
	strlist.sl_nmods = i;
	strlist.sl_modlist = mlist;
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, I_LIST, "I_LIST");
	if (ioctl(fd, I_LIST, &strlist) < 0) {
		lx_debug("\tldlinux_check(): unable to list stream modules");
		return (-errno);
	}

	for (i = 0; i < strlist.sl_nmods; i++)
		if (strcmp(strlist.sl_modlist[i].l_name, LDLINUX_MOD) == 0)
			return (1);

	return (0);
}

static int
ioctl_istr(int fd, int cmd, char *cmd_str, void *arg, int arg_len)
{
	struct strioctl istr;

	istr.ic_cmd = cmd;
	istr.ic_len = arg_len;
	istr.ic_timout = 0;
	istr.ic_dp = arg;

	lx_debug("\tioctl_istr(%d, 0x%x - %s, ...)", fd, cmd, cmd_str);
	if (ioctl(fd, I_STR, &istr) < 0)
		return (-1);
	return (0);
}

/*
 * Add an interface name mapping if it doesn't already exist.
 *
 * Interfaces with IFF_LOOPBACK flag get renamed to loXXX.
 * Interfaces with IFF_BROADCAST flag get renamed to ethXXX.
 *
 * Caller locks the name table.
 */
static int
ifname_add(char *if_name, int if_flags)
{
	static int eth_index = 0;
	static int lo_index = 0;
	ifname_map_t **im_pp;

	for (im_pp = &ifname_map; *im_pp; im_pp = &(*im_pp)->im_next)
		if (strncmp((*im_pp)->im_solaris, if_name, IFNAMSIZ) == 0)
			return (0);

	*im_pp = calloc(1, sizeof (ifname_map_t));
	if (*im_pp == NULL)
		return (-1);

	(void) strlcpy((*im_pp)->im_solaris, if_name, IFNAMSIZ);
	if (if_flags & IFF_LOOPBACK) {
		/* Loopback */
		if (lo_index == 0)
			(void) strlcpy((*im_pp)->im_linux, "lo", IFNAMSIZ);
		else
			(void) snprintf((*im_pp)->im_linux, IFNAMSIZ,
			    "lo:%d", lo_index);
		lo_index++;
	} else if (if_flags & IFF_BROADCAST) {
		/* Assume ether if it has a broadcast address */
		(void) snprintf((*im_pp)->im_linux, IFNAMSIZ,
		    "eth%d", eth_index);
		eth_index++;
	} else {
		/* Do not translate unknown interfaces */
		(void) strlcpy((*im_pp)->im_linux, if_name, IFNAMSIZ);
	}

	lx_debug("map interface %s -> %s", if_name, (*im_pp)->im_linux);

	return (0);
}

static int
ifname_cmp(const void *p1, const void *p2)
{
	struct ifreq *rp1 = (struct ifreq *)p1;
	struct ifreq *rp2 = (struct ifreq *)p2;

	return (strncmp(rp1->ifr_name, rp2->ifr_name, IFNAMSIZ));
}

/*
 * (Re-)scan all interfaces and add them to the name table.
 * Caller locks the name table.
 */
static int
ifname_scan(void)
{
	struct ifconf conf;
	int i, fd, ifcount;

	conf.ifc_buf = NULL;

	if ((fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
		goto fail;
	lx_debug("\tioctl(%d, 0x%x - %s, ...)", fd, SIOCGIFNUM, "SIOCGIFNUM");
	if (ioctl(fd, SIOCGIFNUM, &ifcount) < 0) {
		lx_debug("\tifname_scan(): unable to get number of interfaces");
		goto fail;
	}

	conf.ifc_len = ifcount * sizeof (struct ifreq);
	if ((conf.ifc_buf = calloc(ifcount, sizeof (struct ifreq))) == NULL)
		goto fail;
	lx_debug("\tioctl(%d, 0x%x - %s, ...)", fd, SIOCGIFCONF, "SIOCGIFCONF");
	if (ioctl(fd, SIOCGIFCONF, &conf) < 0) {
		lx_debug("\tifname_scan(): unable to get interfaces");
		goto fail;
	}

	/* Get the interface flags */
	for (i = 0; i < ifcount; i++) {
		lx_debug("\tioctl(%d, 0x%x - %s, ...)",
		    fd, SIOCGIFFLAGS, "SIOCGIFFLAGS");
		if (ioctl(fd, SIOCGIFFLAGS, &conf.ifc_req[i]) < 0) {
			conf.ifc_req[i].ifr_flags = 0;
			lx_debug("\tifname_scan(): unable to get flags for %s",
			    conf.ifc_req[i].ifr_name);
		}
	}

	/*
	 * Sort the interfaces by name to preserve the order
	 * across reboots of this zone.  Note that the order of
	 * interface names won't be consistent across network
	 * configuration changes.  ie.  If network interfaces
	 * are added or removed from a zone (either dynamically
	 * or statically) the network interfaces names to physical
	 * network interface mappings that linux apps see may
	 * change.
	 */
	qsort(conf.ifc_req, ifcount, sizeof (struct ifreq), ifname_cmp);

	/* Add to the name table */
	for (i = 0; i < ifcount; i++)
		if (ifname_add(conf.ifc_req[i].ifr_name,
		    conf.ifc_req[i].ifr_flags) != 0)
			goto fail;

	(void) close(fd);
	free(conf.ifc_buf);

	return (0);

fail:
	if (fd >= 0)
		(void) close(fd);
	if (conf.ifc_buf != NULL)
		free(conf.ifc_buf);

	return (-1);
}

static int
ifname_from_linux(char *name)
{
	int pass;
	ifname_map_t *im_p;

	(void) mutex_lock(&ifname_mtx);

	for (pass = 0; pass < 2; pass++) {
		for (im_p = ifname_map; im_p; im_p = im_p->im_next)
			if (strncmp(im_p->im_linux, name, IFNAMSIZ) == 0)
				break;
		if (im_p != NULL || (pass == 0 && ifname_scan() != 0))
			break;
	}

	(void) mutex_unlock(&ifname_mtx);

	if (im_p) {
		(void) strlcpy(name, im_p->im_solaris, IFNAMSIZ);
		return (0);
	}

	return (-1);
}

static int
ifname_from_solaris(char *name)
{
	int pass;
	ifname_map_t *im_p;

	(void) mutex_lock(&ifname_mtx);

	for (pass = 0; pass < 2; pass++) {
		for (im_p = ifname_map; im_p; im_p = im_p->im_next)
			if (strncmp(im_p->im_solaris, name, IFNAMSIZ) == 0)
				break;
		if (im_p != NULL || (pass == 0 && ifname_scan() != 0))
			break;
	}

	(void) mutex_unlock(&ifname_mtx);

	if (im_p) {
		(void) strlcpy(name, im_p->im_linux, IFNAMSIZ);
		return (0);
	}

	return (-1);
}

/*
 * Called to initialize the ioctl translation subsystem.
 */
int
lx_ioctl_init()
{
	int i, ret;

	/* Figure out the major numbers for our devices translators. */
	for (i = 0; ioc_translators_dev[i] != NULL; i++) {
		ioc_dev_translator_t *idt = ioc_translators_dev[i];

		ret = modctl(MODGETMAJBIND,
		    idt->idt_driver, strlen(idt->idt_driver) + 1,
		    &idt->idt_major);

		if (ret != 0) {
			lx_err("lx_ioctl_init(): modctl(MODGETMAJBIND, %s) "
			    "failed: %s\n", idt->idt_driver, strerror(errno));
			lx_err("lx_ioctl_init(): ioctl translator disabled "
			    "for: %s\n", idt->idt_driver);
			idt->idt_major = (major_t)-1;
		}
	}

	/* Create the interface name table */
	if (ifname_scan() != 0)
		lx_err("lx_ioctl_init(): ifname_scan() failed\n");

	return (0);
}

static ioc_cmd_translator_t *
lx_ioctl_find_ict_cmd(ioc_cmd_translator_t *ict, int cmd)
{
	assert(ict != NULL);
	while ((ict != NULL) && (ict->ict_func != NULL)) {
		if (cmd == ict->ict_lx_cmd)
			return (ict);
		ict++;
	}
	return (NULL);
}

/*
 * Main entry point for the ioctl translater.
 */
long
lx_ioctl(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int			fd = (int)p1;
	int			cmd = (int)p2;
	intptr_t		arg = (uintptr_t)p3;
	struct stat		stat;
	ioc_cmd_translator_t	*ict = NULL;
	ioc_errno_translator_t	*iet = NULL;
	major_t			fd_major;
	int			i, ret;

	if (fstat(fd, &stat) != 0) {
		lx_ioctl_msg(fd, cmd, NULL, NULL,
		    "lx_ioctl(): fstat() failed");

		/*
		 * Linux ioctl(2) is only documented to return EBADF, EFAULT,
		 * EINVAL or ENOTTY.
		 *
		 * EINVAL is documented to be "Request or argp is not valid",
		 * so it's reasonable to force any errno that's not EBADF,
		 * EFAULT or ENOTTY to be EINVAL.
		 */
		if ((errno != EBADF) && (errno != EFAULT) && (errno != ENOTTY))
			errno = EINVAL;

		return (-errno);	/* errno already set. */
	}

	/* Generic handling for FIOCLEX and FIONCLEX */
	if (cmd == LX_FIOCLEX) {
		if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)
			return (-errno);
		return (0);
	} else if (cmd == LX_FIONCLEX) {
		if (fcntl(fd, F_SETFD, 0) == -1)
			return (-errno);
		return (0);
	}

	switch (stat.st_mode & S_IFMT) {
	default:
		break;
	case S_IFREG:
		/* Use file translators. */
		ict = ioc_translators_file;
		break;

	case S_IFSOCK:
		/* Use socket translators. */
		ict = ioc_translators_sock;
		break;

	case S_IFIFO:
		/* Use fifo translators. */
		ict = ioc_translators_fifo;
		break;

	case S_IFCHR:
		fd_major = getmajor(stat.st_rdev);

		/*
		 * Look through all the device translators to see if there
		 * is one for this device.
		 */
		for (i = 0; ioc_translators_dev[i] != NULL; i++) {
			if (fd_major != ioc_translators_dev[i]->idt_major)
				continue;

			/* We found a translator for this device. */
			ict = ioc_translators_dev[i]->idt_cmds;
			break;
		}

		/*
		 * If we didn't find a device translator, fall back on the
		 * file translators.
		 */
		if (ict == NULL)
			ict = ioc_translators_file;

		break;
	}

	/*
	 * Search the selected translator group to see if we have a
	 * translator for this specific command.
	 */
	if ((ict != NULL) &&
	    ((ict = lx_ioctl_find_ict_cmd(ict, cmd)) != NULL)) {
		/* We found a translator for this command, invoke it. */
		lx_ioctl_msg(fd, cmd, ict->ict_lx_cmd_str, &stat,
		    "lx_ioctl(): emulating ioctl");

		ret = ict->ict_func(fd, &stat, ict->ict_cmd, ict->ict_cmd_str,
		    arg);

		if ((ret < 0) && (ret != -EBADF) && (ret != -EFAULT) &&
		    (ret != -ENOTTY))
			ret = -EINVAL;

		return (ret);
	}

	/*
	 * If we didn't find a file or device translator for this
	 * command then try to find a filesystem translator for
	 * this command.
	 */
	for (i = 0; ioc_translators_fs[i] != NULL; i++) {
		if (strcmp(stat.st_fstype,
		    ioc_translators_fs[i]->ift_filesystem) != 0)
			continue;

		/* We found a translator for this filesystem. */
		ict = ioc_translators_fs[i]->ift_cmds;
		break;
	}

	/*
	 * Search the selected translator group to see if we have a
	 * translator for this specific command.
	 */
	if ((ict != NULL) &&
	    ((ict = lx_ioctl_find_ict_cmd(ict, cmd)) != NULL)) {
		/* We found a translator for this command, invoke it. */
		lx_ioctl_msg(fd, cmd, ict->ict_lx_cmd_str, &stat,
		    "lx_ioctl(): emulating ioctl");
		ret = ict->ict_func(fd, &stat, ict->ict_cmd, ict->ict_cmd_str,
		    arg);

		if ((ret < 0) && (ret != -EBADF) && (ret != -EFAULT) &&
		    (ret != -ENOTTY))
			ret = -EINVAL;

		return (ret);
	}

	/*
	 * No translator for this ioctl was found.
	 * Check if there is an errno translator.
	 */
	for (iet = ioc_translators_errno; iet->iet_lx_cmd_str != NULL; iet++) {
		if (cmd != iet->iet_lx_cmd)
			continue;

		/* We found a an errno translator for this ioctl. */
		lx_ioctl_msg(fd, cmd, iet->iet_lx_cmd_str, &stat,
		    "lx_ioctl(): emulating errno");

		ret = -iet->iet_errno;

		if ((ret < 0) && (ret != -EBADF) && (ret != -EFAULT) &&
		    (ret != -ENOTTY))
			ret = -EINVAL;

		return (ret);
	}

	/*
	 * errno tweaking which some test cases expect because kernel
	 * version 2.6.39 changed the returned errno from EINVAL to
	 * ENOTTY (see LTP sockioctl01 test cases).
	 */
	if (cmd == LX_SIOCATMARK && (stat.st_mode & S_IFMT) != S_IFSOCK)
		return (-ENOTTY);

	lx_ioctl_msg(fd, cmd, NULL, &stat,
	    "lx_ioctl(): unsupported linux ioctl");
	lx_unsupported("unsupported linux ioctl 0x%x", cmd);
	return (-EINVAL);
}


/*
 * Ioctl translator functions.
 */
/*
 * Used by translators that want to explicitly return EINVAL for an
 * ioctl(2) instead of having the translation framework do it implicitly.
 * This allows us to indicate which unsupported ioctl(2)s should not
 * trigger a SIGSYS when running in LX_STRICT mode.
 */
/* ARGSUSED */
static int
ict_einval(int fd, struct stat *stat, int cmd, char *cmd_str, intptr_t arg)
{
	return (-EINVAL);
}

static int
/*ARGSUSED*/
ict_pass(int fd, struct stat *stat, int cmd, char *cmd_str, intptr_t arg)
{
	int ret;

	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, cmd, cmd_str);
	ret = ioctl(fd, cmd, arg);
	return (ret < 0 ? -errno : ret);
}

static int
/*ARGSUSED*/
ict_tcsbrkp(int fd, struct stat *stat, int cmd, char *cmd_str, intptr_t arg)
{
	int ret, dur = 0;

	assert(cmd == LX_TCSBRKP);
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, TCSBRK, "TCSBRK");
	ret = ioctl(fd, TCSBRK, (intptr_t)&dur);
	return (ret < 0 ? -errno : ret);
}

static int
/*ARGSUSED*/
ict_sioifoob(int fd, struct stat *stat, int cmd, char *cmd_str, intptr_t arg)
{
	int req, *reqp = (int *)arg;
	int len, val;

	assert(cmd == SIOCATMARK);

	if (uucopy(reqp, &req, sizeof (req)) != 0)
		return (-errno);

	len = sizeof (val);

	/*
	 * Linux expects a SIOCATMARK of a UDP socket to return ENOTTY, while
	 * Illumos allows it. Linux prior to 2.6.39 returned EINVAL for this.
	 */
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &val, &len) < 0) {
		lx_debug("ict_siofmark: getsockopt failed, errno %d", errno);
		return (-EINVAL);
	}

	if ((len != sizeof (val)) || (val != SOCK_STREAM))
		return (-ENOTTY);

	if (ioctl(fd, cmd, &req) < 0)
		return (-errno);

	if (uucopy(&req, reqp, sizeof (req)) != 0)
		return (-errno);

	return (0);
}

static int
/*ARGSUSED*/
ict_sioifreq(int fd, struct stat *stat, int cmd, char *cmd_str, intptr_t arg)
{
	struct ifreq req, *reqp = (struct ifreq *)arg;

	assert(cmd == SIOCGIFFLAGS || cmd == SIOCSIFFLAGS ||
	    cmd == SIOCGIFADDR || cmd == SIOCSIFADDR ||
	    cmd == SIOCGIFDSTADDR || cmd == SIOCSIFDSTADDR ||
	    cmd == SIOCGIFBRDADDR || cmd == SIOCSIFBRDADDR ||
	    cmd == SIOCGIFNETMASK || cmd == SIOCSIFNETMASK ||
	    cmd == SIOCGIFMETRIC || cmd == SIOCSIFMETRIC ||
	    cmd == SIOCGIFMTU || cmd == SIOCSIFMTU);

	/* Copy in the data */
	if (uucopy(reqp, &req, sizeof (struct ifreq)) != 0)
		return (-errno);

	if (ifname_from_linux(req.ifr_name) < 0)
		return (-EINVAL);

	lx_debug("\tioctl(%d, 0x%x - %s, %.14s",
	    fd, cmd, cmd_str, req.ifr_name);

	if (ioctl(fd, cmd, &req) < 0)
		return (-errno);

	if (ifname_from_solaris(req.ifr_name) < 0)
		return (-EINVAL);

	/* Copy out the data */
	if (uucopy(&req, reqp, sizeof (struct ifreq)) != 0)
		return (-errno);

	return (0);
}

static int
/*ARGSUSED*/
ict_siocgifconf(int fd, struct stat *stat, int cmd, char *cmd_str, intptr_t arg)
{
	struct ifconf	conf, *confp = (struct ifconf *)arg;
	int		i, ifcount, ret;

	assert(cmd == LX_SIOCGIFCONF);

	/* Copy in the data. */
	if (uucopy(confp, &conf, sizeof (conf)) != 0)
		return (-errno);

	if (conf.ifc_len == 0) {
		/* They want to know how many interfaces there are. */
		lx_debug("\tioctl(%d, 0x%x - %s, ...)",
		    fd, SIOCGIFNUM, "SIOCGIFNUM");
		if (ioctl(fd, SIOCGIFNUM, (intptr_t)&ifcount) < 0)
			return (-errno);
		conf.ifc_len = ifcount * sizeof (struct ifreq);

		/* Check if we're done. */
		if (conf.ifc_buf == NULL) {
			/* Copy out the data. */
			if (uucopy(&conf, confp, sizeof (conf)) != 0)
				return (-errno);
			return (0);
		}
	}

	/* Get interface configuration list. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)", fd, SIOCGIFCONF, "SIOCGIFCONF");
	ret = ioctl(fd, SIOCGIFCONF, &conf);
	if (ret < 0)
		return (-errno);

	/* Rename interfaces to linux */
	for (i = 0; i < conf.ifc_len / sizeof (struct ifreq); i++)
		if (ifname_from_solaris(conf.ifc_req[i].ifr_name) < 0)
			return (-EINVAL);

	/* Copy out the data */
	if (uucopy(&conf, confp, sizeof (conf)) != 0)
		return (-errno);

	return (0);
}

static int
/*ARGSUSED*/
ict_siocifhwaddr(int fd, struct stat *stat, int cmd, char *cmd_str,
    intptr_t arg)
{
	struct ifreq req, *reqp = (struct ifreq *)arg;
	struct arpreq arpreq;

	assert(cmd == LX_SIOCGIFHWADDR || cmd == LX_SIOCSIFHWADDR);

	/* Copy in the data */
	if (uucopy(reqp, &req, sizeof (struct ifreq)) != 0)
		return (-errno);

	lx_debug("\tioctl(%d, 0x%x - %s, lx %.14s)",
	    fd, cmd,
	    (cmd == LX_SIOCGIFHWADDR) ? "SIOCGIFHWADDR" : "SIOCSIFHWADDR",
	    req.ifr_name);

	/*
	 * We're not going to support SIOCSIFHWADDR, but we need to be able to
	 * check the result of the uucopy first to see if the command
	 * should have returned EFAULT.
	 */
	if (cmd == LX_SIOCSIFHWADDR) {
		lx_unsupported("unsupported linux ioctl: SIOCSIFHWADDR");
		return (-EINVAL);
	}

	if (strcmp(req.ifr_name, "lo") == 0 ||
	    strncmp(req.ifr_name, "lo:", 3) == 0) {
		/* Abuse ifr_addr for linux ifr_hwaddr */
		bzero(&req.ifr_addr, sizeof (struct sockaddr));
		req.ifr_addr.sa_family = LX_ARPHRD_LOOPBACK;

		/* Copy out the data */
		if (uucopy(&req, reqp, sizeof (struct ifreq)) != 0)
			return (-errno);

		return (0);
	}

	if (ifname_from_linux(req.ifr_name) < 0)
		return (-EINVAL);

	lx_debug("\tioctl(%d, 0x%x - %s, %.14s)",
	    fd, SIOCGIFADDR, "SIOCGIFADDR", req.ifr_name);

	if (ioctl(fd, SIOCGIFADDR, &req) < 0)
		return (-errno);

	bcopy(&req.ifr_addr, &arpreq.arp_pa, sizeof (struct sockaddr));

	lx_debug("\tioctl(%d, 0x%x - %s, ...)", fd, SIOCGARP, "SIOCGARP");

	if (ioctl(fd, SIOCGARP, &arpreq) < 0)
		return (-errno);

	if (ifname_from_solaris(req.ifr_name) < 0)
		return (-EINVAL);

	/* Abuse ifr_addr for linux ifr_hwaddr */
	bcopy(&arpreq.arp_ha, &req.ifr_addr, sizeof (struct sockaddr));
	if (strncmp(req.ifr_name, "eth", 3) == 0)
		req.ifr_addr.sa_family = LX_ARPHRD_ETHER;
	else
		req.ifr_addr.sa_family = LX_ARPHRD_VOID;

	/* Copy out the data */
	if (uucopy(&req, reqp, sizeof (struct ifreq)) != 0)
		return (-errno);

	return (0);
}

static void
l2s_termios(struct lx_termios *l_tios, struct termios *s_tios)
{
	assert((l_tios != NULL) && (s_tios != NULL));

	bzero(s_tios, sizeof (*s_tios));

	s_tios->c_iflag = l_tios->c_iflag;
	s_tios->c_oflag = l_tios->c_oflag;
	s_tios->c_cflag = l_tios->c_cflag;

	s_tios->c_lflag = l_tios->c_lflag;
	if (s_tios->c_lflag & ICANON) {
		s_tios->c_cc[VEOF] = l_tios->c_cc[LX_VEOF];
		s_tios->c_cc[VEOL] = l_tios->c_cc[LX_VEOL];
	} else {
		s_tios->c_cc[VMIN] = l_tios->c_cc[LX_VMIN];
		s_tios->c_cc[VTIME] = l_tios->c_cc[LX_VTIME];
	}

	s_tios->c_cc[VEOL2] = l_tios->c_cc[LX_VEOL2];
	s_tios->c_cc[VERASE] = l_tios->c_cc[LX_VERASE];
	s_tios->c_cc[VKILL] = l_tios->c_cc[LX_VKILL];
	s_tios->c_cc[VREPRINT] = l_tios->c_cc[LX_VREPRINT];
	s_tios->c_cc[VLNEXT] = l_tios->c_cc[LX_VLNEXT];
	s_tios->c_cc[VWERASE] = l_tios->c_cc[LX_VWERASE];
	s_tios->c_cc[VINTR] = l_tios->c_cc[LX_VINTR];
	s_tios->c_cc[VQUIT] = l_tios->c_cc[LX_VQUIT];
	s_tios->c_cc[VSWTCH] = l_tios->c_cc[LX_VSWTC];
	s_tios->c_cc[VSTART] = l_tios->c_cc[LX_VSTART];
	s_tios->c_cc[VSTOP] = l_tios->c_cc[LX_VSTOP];
	s_tios->c_cc[VSUSP] = l_tios->c_cc[LX_VSUSP];
	s_tios->c_cc[VDISCARD] = l_tios->c_cc[LX_VDISCARD];
}

static void
l2s_termio(struct lx_termio *l_tio, struct termio *s_tio)
{
	assert((l_tio != NULL) && (s_tio != NULL));

	bzero(s_tio, sizeof (*s_tio));

	s_tio->c_iflag = l_tio->c_iflag;
	s_tio->c_oflag = l_tio->c_oflag;
	s_tio->c_cflag = l_tio->c_cflag;

	s_tio->c_lflag = l_tio->c_lflag;
	if (s_tio->c_lflag & ICANON) {
		s_tio->c_cc[VEOF] = l_tio->c_cc[LX_VEOF];
	} else {
		s_tio->c_cc[VMIN] = l_tio->c_cc[LX_VMIN];
		s_tio->c_cc[VTIME] = l_tio->c_cc[LX_VTIME];
	}

	s_tio->c_cc[VINTR] = l_tio->c_cc[LX_VINTR];
	s_tio->c_cc[VQUIT] = l_tio->c_cc[LX_VQUIT];
	s_tio->c_cc[VERASE] = l_tio->c_cc[LX_VERASE];
	s_tio->c_cc[VKILL] = l_tio->c_cc[LX_VKILL];
	s_tio->c_cc[VSWTCH] = l_tio->c_cc[LX_VSWTC];
}

static void
termios2lx_cc(struct lx_termios *l_tios, struct lx_cc *lio)
{
	assert((l_tios != NULL) && (lio != NULL));

	bzero(lio, sizeof (*lio));

	lio->veof = l_tios->c_cc[LX_VEOF];
	lio->veol = l_tios->c_cc[LX_VEOL];
	lio->vmin = l_tios->c_cc[LX_VMIN];
	lio->vtime = l_tios->c_cc[LX_VTIME];
}

static void
termio2lx_cc(struct lx_termio *l_tio, struct lx_cc *lio)
{
	assert((l_tio != NULL) && (lio != NULL));

	bzero(lio, sizeof (*lio));

	lio->veof = l_tio->c_cc[LX_VEOF];
	lio->veol = 0;
	lio->vmin = l_tio->c_cc[LX_VMIN];
	lio->vtime = l_tio->c_cc[LX_VTIME];
}

static void
s2l_termios(struct termios *s_tios, struct lx_termios *l_tios)
{
	assert((s_tios != NULL) && (l_tios != NULL));

	bzero(l_tios, sizeof (*l_tios));

	l_tios->c_iflag = s_tios->c_iflag;
	l_tios->c_oflag = s_tios->c_oflag;
	l_tios->c_cflag = s_tios->c_cflag;
	l_tios->c_lflag = s_tios->c_lflag;

	if (s_tios->c_lflag & ICANON) {
		l_tios->c_cc[LX_VEOF] = s_tios->c_cc[VEOF];
		l_tios->c_cc[LX_VEOL] = s_tios->c_cc[VEOL];
	} else {
		l_tios->c_cc[LX_VMIN] = s_tios->c_cc[VMIN];
		l_tios->c_cc[LX_VTIME] = s_tios->c_cc[VTIME];
	}

	l_tios->c_cc[LX_VEOL2] = s_tios->c_cc[VEOL2];
	l_tios->c_cc[LX_VERASE] = s_tios->c_cc[VERASE];
	l_tios->c_cc[LX_VKILL] = s_tios->c_cc[VKILL];
	l_tios->c_cc[LX_VREPRINT] = s_tios->c_cc[VREPRINT];
	l_tios->c_cc[LX_VLNEXT] = s_tios->c_cc[VLNEXT];
	l_tios->c_cc[LX_VWERASE] = s_tios->c_cc[VWERASE];
	l_tios->c_cc[LX_VINTR] = s_tios->c_cc[VINTR];
	l_tios->c_cc[LX_VQUIT] = s_tios->c_cc[VQUIT];
	l_tios->c_cc[LX_VSWTC] = s_tios->c_cc[VSWTCH];
	l_tios->c_cc[LX_VSTART] = s_tios->c_cc[VSTART];
	l_tios->c_cc[LX_VSTOP] = s_tios->c_cc[VSTOP];
	l_tios->c_cc[LX_VSUSP] = s_tios->c_cc[VSUSP];
	l_tios->c_cc[LX_VDISCARD] = s_tios->c_cc[VDISCARD];
}

static void
s2l_termio(struct termio *s_tio, struct lx_termio *l_tio)
{
	assert((s_tio != NULL) && (l_tio != NULL));

	bzero(l_tio, sizeof (*l_tio));

	l_tio->c_iflag = s_tio->c_iflag;
	l_tio->c_oflag = s_tio->c_oflag;
	l_tio->c_cflag = s_tio->c_cflag;
	l_tio->c_lflag = s_tio->c_lflag;

	if (s_tio->c_lflag & ICANON) {
		l_tio->c_cc[LX_VEOF] = s_tio->c_cc[VEOF];
	} else {
		l_tio->c_cc[LX_VMIN] = s_tio->c_cc[VMIN];
		l_tio->c_cc[LX_VTIME] = s_tio->c_cc[VTIME];
	}

	l_tio->c_cc[LX_VINTR] = s_tio->c_cc[VINTR];
	l_tio->c_cc[LX_VQUIT] = s_tio->c_cc[VQUIT];
	l_tio->c_cc[LX_VERASE] = s_tio->c_cc[VERASE];
	l_tio->c_cc[LX_VKILL] = s_tio->c_cc[VKILL];
	l_tio->c_cc[LX_VSWTC] = s_tio->c_cc[VSWTCH];
}

static int
/*ARGSUSED*/
ict_tcsets(int fd, struct stat *stat, int cmd, char *cmd_str, intptr_t arg)
{
	struct lx_termios	l_tios, *l_tiosp = (struct lx_termios *)arg;
	struct termios		s_tios;
	struct lx_cc		lio;
	int			ldlinux, ret;

	assert(cmd == TCSETS || cmd == TCSETSW || cmd == TCSETSF);

	/* Copy in the data. */
	if (uucopy(l_tiosp, &l_tios, sizeof (l_tios)) != 0)
		return (-errno);

	/*
	 * The TIOCSETLD/TIOCGETLD ioctls are only supported by the
	 * ldlinux strmod.  So make sure the module exists on the
	 * target stream before we invoke the ioctl.
	 */
	if ((ldlinux = ldlinux_check(fd)) < 0)
		return (ldlinux);

	if (ldlinux == 1) {
		termios2lx_cc(&l_tios, &lio);
		if (ioctl_istr(fd, TIOCSETLD, "TIOCSETLD",
		    &lio, sizeof (lio)) < 0)
			return (-errno);
	}

	l2s_termios(&l_tios, &s_tios);
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, cmd, cmd_str);
	ret = ioctl(fd, cmd, (intptr_t)&s_tios);
	return ((ret < 0) ? -errno : ret);
}

static int
/*ARGSUSED*/
ict_tcseta(int fd, struct stat *stat, int cmd, char *cmd_str, intptr_t arg)
{
	struct lx_termio	l_tio, *l_tiop = (struct lx_termio *)arg;
	struct termio		s_tio;
	struct lx_cc		lio;
	int			ldlinux, ret;

	assert(cmd == TCSETA || cmd == TCSETAW || cmd == TCSETAF);

	/* Copy in the data. */
	if (uucopy(l_tiop, &l_tio, sizeof (l_tio)) != 0)
		return (-errno);

	/*
	 * The TIOCSETLD/TIOCGETLD ioctls are only supported by the
	 * ldlinux strmod.  So make sure the module exists on the
	 * target stream before we invoke the ioctl.
	 */
	if ((ldlinux = ldlinux_check(fd)) < 0)
		return (ldlinux);

	if (ldlinux == 1) {
		termio2lx_cc(&l_tio, &lio);
		if (ioctl_istr(fd, TIOCSETLD, "TIOCSETLD",
		    &lio, sizeof (lio)) < 0)
			return (-errno);
	}

	l2s_termio(&l_tio, &s_tio);
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, cmd, cmd_str);
	ret = ioctl(fd, cmd, (intptr_t)&s_tio);
	return ((ret < 0) ? -errno : ret);
}

/*
 * The Solaris TIOCGPGRP ioctl does not have exactly the same semantics as
 * the Linux one. To mimic Linux semantics we have to do some extra work
 * normally done by the Solaris version of tcgetpgrp().
 */
static int
/*ARGSUSED*/
ict_tiocgpgrp(int fd, struct stat *stat, int cmd, char *cmd_str, intptr_t arg)
{
	pid_t	ttysid, mysid;
	int	ret;

	assert(cmd == LX_TIOCGPGRP);

	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, TIOCGSID, "TIOCGSID");
	if (ioctl(fd, TIOCGSID, (intptr_t)&ttysid) < 0)
		return (-errno);
	if ((mysid = getsid(0)) < 0)
		return (-errno);
	if (mysid != ttysid)
		return (-ENOTTY);

	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, TIOCGPGRP, "TIOCGPGRP");
	ret = ioctl(fd, TIOCGPGRP, arg);
	return ((ret < 0) ? -errno : ret);
}

static int
/*ARGSUSED*/
ict_sptlock(int fd, struct stat *stat, int cmd, char *cmd_str, intptr_t arg)
{
	assert(cmd == LX_TIOCSPTLCK);

	/*
	 * The success/fail return values are different between Linux
	 * and Solaris.   Linux expects 0 or -1.  Solaris can return
	 * positive number on success.
	 */
	if (ioctl_istr(fd, UNLKPT, "UNLKPT", NULL, 0) < 0)
		return (-errno);
	return (0);
}

static int
/*ARGSUSED*/
ict_gptn(int fd, struct stat *stat, int cmd, char *cmd_str, intptr_t arg)
{
	int		ptyno, *ptynop = (int *)arg;
	pt_own_t	pto;

	assert(cmd == LX_TIOCGPTN);
	assert(getmajor(stat->st_rdev) == ioc_translator_ptm.idt_major);

	/* This operation is only valid for the lx_ptm device. */
	ptyno = LX_PTM_DEV_TO_PTS(stat->st_rdev);

	/*
	 * We'd like to just use grantpt() directly, but we can't since
	 * it assumes the fd node that's passed to it is a ptm node,
	 * and in our case it's an lx_ptm node.  It also relies on
	 * naming services to get the current process group name.
	 * Hence we have to invoke the OWNERPT ioctl directly here.
	 */
	pto.pto_ruid = getuid();
	pto.pto_rgid = getgid();
	if (ioctl_istr(fd, OWNERPT, "OWNERPT", &pto, sizeof (pto)) != 0)
		return (-EACCES);

	/* Copy out the data. */
	if (uucopy(&ptyno, ptynop, sizeof (ptyno)) != 0)
		return (-errno);

	return (0);
}

static int
/*ARGSUSED*/
ict_tiocgwinsz(int fd, struct stat *stat, int cmd, char *cmd_str, intptr_t arg)
{
	struct winsize	winsize, *winsizep = (struct winsize *)arg;

	assert(cmd == LX_TIOCGWINSZ);

	lx_debug("\tioctl(%d, 0x%x - %s, ...)", fd, TIOCGWINSZ, "TIOCGWINSZ");
	if (ioctl(fd, TIOCGWINSZ, arg) >= 0)
		return (0);
	if (errno != EINVAL)
		return (-errno);

	bzero(&winsize, sizeof (winsize));
	if (uucopy(&winsize, winsizep, sizeof (winsize)) != 0)
		return (-errno);

	return (0);
}

static int
/*ARGSUSED*/
ict_tcgets_emulate(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	struct lx_termios	l_tios, *l_tiosp = (struct lx_termios *)arg;
	struct termios		s_tios;

	assert(cmd == LX_TCGETS);

	if (syscall(SYS_brand, B_TTYMODES, &s_tios) < 0)
		return (-errno);

	/* Now munge the data to how Linux wants it. */
	s2l_termios(&s_tios, &l_tios);
	if (uucopy(&l_tios, l_tiosp, sizeof (l_tios)) != 0)
		return (-errno);

	return (0);
}

static int
/*ARGSUSED*/
ict_tcgets_native(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	struct lx_termios	l_tios, *l_tiosp = (struct lx_termios *)arg;
	struct termios		s_tios;
	struct lx_cc		lio;
	int			ldlinux;

	assert(cmd == LX_TCGETS);

	if ((ldlinux = ldlinux_check(fd)) < 0)
		return (ldlinux);

	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, TCGETS, "TCGETS");
	if (ioctl(fd, TCGETS, (intptr_t)&s_tios) < 0)
		return (-errno);

	/* Now munge the data to how Linux wants it. */
	s2l_termios(&s_tios, &l_tios);

	/*
	 * The TIOCSETLD/TIOCGETLD ioctls are only supported by the
	 * ldlinux strmod.  So make sure the module exists on the
	 * target stream before we invoke the ioctl.
	 */
	if (ldlinux != 0) {
		if (ioctl_istr(fd, TIOCGETLD, "TIOCGETLD",
		    &lio, sizeof (lio)) < 0)
			return (-errno);

		l_tios.c_cc[LX_VEOF] = lio.veof;
		l_tios.c_cc[LX_VEOL] = lio.veol;
		l_tios.c_cc[LX_VMIN] = lio.vmin;
		l_tios.c_cc[LX_VTIME] = lio.vtime;
	}

	/* Copy out the data. */
	if (uucopy(&l_tios, l_tiosp, sizeof (l_tios)) != 0)
		return (-errno);

	return (0);
}

static int
/*ARGSUSED*/
ict_tcgeta(int fd, struct stat *stat, int cmd, char *cmd_str, intptr_t arg)
{
	struct lx_termio	l_tio, *l_tiop = (struct lx_termio *)arg;
	struct termio		s_tio;
	struct lx_cc		lio;
	int			ldlinux;

	assert(cmd == LX_TCGETA);

	if ((ldlinux = ldlinux_check(fd)) < 0)
		return (ldlinux);

	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, TCGETA, "TCGETA");
	if (ioctl(fd, TCGETA, (intptr_t)&s_tio) < 0)
		return (-errno);

	/* Now munge the data to how Linux wants it. */
	s2l_termio(&s_tio, &l_tio);

	/*
	 * The TIOCSETLD/TIOCGETLD ioctls are only supported by the
	 * ldlinux strmod.  So make sure the module exists on the
	 * target stream before we invoke the ioctl.
	 */
	if (ldlinux != 0) {
		if (ioctl_istr(fd, TIOCGETLD, "TIOCGETLD",
		    &lio, sizeof (lio)) < 0)
			return (-errno);

		l_tio.c_cc[LX_VEOF] = lio.veof;
		l_tio.c_cc[LX_VMIN] = lio.vmin;
		l_tio.c_cc[LX_VTIME] = lio.vtime;
	}

	/* Copy out the data. */
	if (uucopy(&l_tio, l_tiop, sizeof (l_tio)) != 0)
		return (-errno);

	return (0);
}

static int
/*ARGSUSED*/
ict_tiocsctty(int fd, struct stat *stat, int cmd, char *cmd_str, intptr_t arg)
{
	pid_t	mysid, ttysid;

	if ((mysid = getsid(0)) < 0)
		return (-errno);

	/* Check if this fd is already our ctty. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, TIOCGSID, "TIOCGSID");
	if (ioctl(fd, TIOCGSID, (intptr_t)&ttysid) >= 0)
		if (mysid == ttysid)
			return (0);

	/*
	 * Need to make sure we're a session leader, otherwise the
	 * TIOCSCTTY ioctl will fail.
	 */
	if (mysid != getpid())
		(void) setpgrp();

	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, TIOCSCTTY, "TIOCSCTTY");
	if (ioctl(fd, TIOCSCTTY, 0) < 0)
		return (-errno);
	return (0);
}

/*
 * /dev/dsp ioctl translators and support
 */
static int
i_is_dsp_dev(int fd)
{
	int minor;

	/*
	 * This is a cloning device so we have to ask the driver
	 * what kind of minor node this is.
	 */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, LXA_IOC_GETMINORNUM, "LXA_IOC_GETMINORNUM");
	if (ioctl(fd, LXA_IOC_GETMINORNUM, &minor) < 0)
		return (-EINVAL);
	if (minor != LXA_MINORNUM_DSP)
		return (-EINVAL);
	return (0);
}

static int
/*ARGSUSED*/
ict_oss_sndctl_dsp_reset(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	int err;

	/* Ioctl is only supported on dsp audio devices. */
	if ((err = i_is_dsp_dev(fd)) != 0)
		return (err);

	/* Nothing to really do on Solaris. */
	return (0);
}

static void
i_oss_fmt_str(char *buf, int buf_size, uint_t mask)
{
	int i, first = 1;

	assert(buf != NULL);

	buf[0] = '\0';
	for (i = 0; oss_fmt_str[i].i2s_str != NULL; i++) {
		if ((oss_fmt_str[i].i2s_int != mask) &&
		    ((oss_fmt_str[i].i2s_int & mask) == 0))
			continue;
		if (first)
			first = 0;
		else
			(void) strlcat(buf, " | ", buf_size);
		(void) strlcat(buf, oss_fmt_str[i].i2s_str, buf_size);
	}
}

static int
/*ARGSUSED*/
ict_oss_sndctl_dsp_getfmts(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	audio_info_t	sa_info;
	char		buf[MSGBUF];
	uint_t		*maskp = (uint_t *)arg;
	uint_t		mask = 0;
	int		i, amode, err;

	assert(cmd == LX_OSS_SNDCTL_DSP_GETFMTS);

	/* Ioctl is only supported on dsp audio devices. */
	if ((err = i_is_dsp_dev(fd)) != 0)
		return (err);

	/* We need to know the access mode for the file. */
	if ((amode = fcntl(fd, F_GETFL)) < 0)
		return (-EINVAL);
	amode &= O_ACCMODE;
	assert((amode == O_RDONLY) || (amode == O_WRONLY) || (amode == O_RDWR));

	/* Test to see what Linux oss formats the target device supports. */
	for (i = 0; oft_table[i].oft_oss_fmt != 0; i++) {

		/* Initialize the mode request. */
		AUDIO_INITINFO(&sa_info);

		/* Translate a Linux oss format into Solaris settings. */
		if ((amode == O_RDONLY) || (amode == O_RDWR)) {
			sa_info.record.encoding = oft_table[i].oft_encoding;
			sa_info.record.precision = oft_table[i].oft_precision;
		}
		if ((amode == O_WRONLY) || (amode == O_RDWR)) {
			sa_info.play.encoding = oft_table[i].oft_encoding;
			sa_info.play.precision = oft_table[i].oft_precision;
		}

		/* Send the request. */
		lx_debug("\tioctl(%d, 0x%x - %s, ...)",
		    fd, AUDIO_SETINFO, "AUDIO_SETINFO");
		if (ioctl(fd, AUDIO_SETINFO, &sa_info) < 0)
			continue;

		/* This Linux oss format is supported. */
		mask |= oft_table[i].oft_oss_fmt;
	}

	if (lx_debug_enabled != 0) {
		i_oss_fmt_str(buf, sizeof (buf), mask);
		lx_debug("\toss formats supported = 0x%x (%s)", mask, buf);
	}
	if (uucopy(&mask, maskp, sizeof (mask)) != 0)
		return (-errno);
	return (0);
}

static int
/*ARGSUSED*/
ict_oss_sndctl_dsp_setfmts(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	audio_info_t	sa_info;
	char		buf[MSGBUF];
	uint_t		*maskp = (uint_t *)arg;
	uint_t		mask;
	int		i, amode, err;

	assert(cmd == LX_OSS_SNDCTL_DSP_SETFMTS);

	/* Ioctl is only supported on dsp audio devices. */
	if ((err = i_is_dsp_dev(fd)) != 0)
		return (err);

	if (uucopy(maskp, &mask, sizeof (mask)) != 0)
		return (-errno);

	if (lx_debug_enabled != 0) {
		i_oss_fmt_str(buf, sizeof (buf), mask);
		lx_debug("\toss formats request = 0x%x (%s)", mask, buf);
	}

	if ((mask == (uint_t)-1) || (mask == 0)) {
		lx_debug("\tXXX: possible oss formats query?");
		return (-EINVAL);
	}

	/* Check if multiple format bits were specified. */
	if (!BIT_ONLYONESET(mask))
		return (-EINVAL);

	/* Decode the oss format request into a native format. */
	for (i = 0; oft_table[i].oft_oss_fmt != 0; i++) {
		if (oft_table[i].oft_oss_fmt == mask)
			break;
	}
	if (oft_table[i].oft_oss_fmt == 0)
		return (-EINVAL);

	/* We need to know the access mode for the file. */
	if ((amode = fcntl(fd, F_GETFL)) < 0)
		return (-EINVAL);
	amode &= O_ACCMODE;
	assert((amode == O_RDONLY) || (amode == O_WRONLY) || (amode == O_RDWR));

	/* Initialize the mode request. */
	AUDIO_INITINFO(&sa_info);

	/* Translate the Linux oss request into a Solaris request. */
	if ((amode == O_RDONLY) || (amode == O_RDWR)) {
		sa_info.record.encoding = oft_table[i].oft_encoding;
		sa_info.record.precision = oft_table[i].oft_precision;
	}
	if ((amode == O_WRONLY) || (amode == O_RDWR)) {
		sa_info.play.encoding = oft_table[i].oft_encoding;
		sa_info.play.precision = oft_table[i].oft_precision;
	}

	/* Send the request. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, AUDIO_SETINFO, "AUDIO_SETINFO");
	return ((ioctl(fd, AUDIO_SETINFO, &sa_info) < 0) ? -errno : 0);
}

static int
/*ARGSUSED*/
ict_oss_sndctl_dsp_channels(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	audio_info_t	sa_info;
	uint_t		*channelsp = (uint_t *)arg;
	uint_t		channels;
	int		amode, err;

	assert((cmd == LX_OSS_SNDCTL_DSP_CHANNELS) ||
	    (cmd == LX_OSS_SNDCTL_DSP_STEREO));

	/* Ioctl is only supported on dsp audio devices. */
	if ((err = i_is_dsp_dev(fd)) != 0)
		return (err);

	if (uucopy(channelsp, &channels, sizeof (channels)) != 0)
		return (-errno);

	lx_debug("\toss %s request = 0x%x (%u)",
	    (cmd == LX_OSS_SNDCTL_DSP_CHANNELS) ? "channel" : "stereo",
	    channels, channels);

	if (channels == (uint_t)-1) {
		lx_debug("\tXXX: possible channel/stereo query?");
		return (-EINVAL);
	}

	if (cmd == LX_OSS_SNDCTL_DSP_STEREO) {
		/*
		 * There doesn't seem to be any documentation for
		 * SNDCTL_DSP_STEREO.  Looking at source that uses or
		 * used this ioctl seems to indicate that the
		 * functionality provided by this ioctl has been
		 * subsumed by the SNDCTL_DSP_CHANNELS ioctl.  It
		 * seems that the only arguments ever passed to
		 * the SNDCTL_DSP_STEREO.  Ioctl are boolean values
		 * of '0' or '1'.  Hence we'll start out strict and
		 * only support those values.
		 *
		 * Some online forum discussions about this ioctl
		 * seemed to indicate that in case of success it
		 * returns the "stereo" setting (ie, either
		 * '0' for mono or '1' for stereo).
		 */
		if ((channels != 0) && (channels != 1)) {
			lx_debug("\tinvalid stereo request");
			return (-EINVAL);
		}
		channels += 1;
	} else {
		/* Limit the system to one or two channels. */
		if ((channels != 1) && (channels != 2)) {
			lx_debug("\tinvalid channel request");
			return (-EINVAL);
		}
	}

	/* We need to know the access mode for the file. */
	if ((amode = fcntl(fd, F_GETFL)) < 0)
		return (-EINVAL);
	amode &= O_ACCMODE;
	assert((amode == O_RDONLY) || (amode == O_WRONLY) || (amode == O_RDWR));

	/* Initialize the channel request. */
	AUDIO_INITINFO(&sa_info);

	/* Translate the Linux oss request into a Solaris request. */
	if ((amode == O_RDONLY) || (amode == O_RDWR))
		sa_info.record.channels = channels;
	if ((amode == O_WRONLY) || (amode == O_RDWR))
		sa_info.play.channels = channels;

	/* Send the request. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, AUDIO_SETINFO, "AUDIO_SETINFO");
	if (ioctl(fd, AUDIO_SETINFO, &sa_info) < 0)
		return (-errno);

	if (cmd == LX_OSS_SNDCTL_DSP_STEREO)
		return (channels - 1);
	return (0);
}

static int
/*ARGSUSED*/
ict_oss_sndctl_dsp_speed(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	audio_info_t	sa_info;
	uint_t		*speedp = (uint_t *)arg;
	uint_t		speed;
	int		amode, err;

	assert(cmd == LX_OSS_SNDCTL_DSP_SPEED);

	/* Ioctl is only supported on dsp audio devices. */
	if ((err = i_is_dsp_dev(fd)) != 0)
		return (err);

	if (uucopy(speedp, &speed, sizeof (speed)) != 0)
		return (-errno);

	lx_debug("\toss speed request = 0x%x (%u)", speed, speed);

	if (speed == (uint_t)-1) {
		lx_debug("\tXXX: possible oss speed query?");
		return (-EINVAL);
	}

	/* We need to know the access mode for the file. */
	if ((amode = fcntl(fd, F_GETFL)) < 0)
		return (-EINVAL);
	amode &= O_ACCMODE;
	assert((amode == O_RDONLY) || (amode == O_WRONLY) || (amode == O_RDWR));

	/* Initialize the speed request. */
	AUDIO_INITINFO(&sa_info);

	/* Translate the Linux oss request into a Solaris request. */
	if ((amode == O_RDONLY) || (amode == O_RDWR))
		sa_info.record.sample_rate = speed;
	if ((amode == O_WRONLY) || (amode == O_RDWR))
		sa_info.play.sample_rate = speed;

	/* Send the request. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, AUDIO_SETINFO, "AUDIO_SETINFO");
	return ((ioctl(fd, AUDIO_SETINFO, &sa_info) < 0) ? -errno : 0);
}

static int
/*ARGSUSED*/
ict_oss_sndctl_dsp_getblksize(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	lxa_frag_info_t	fi;
	uint_t		*blksizep = (uint_t *)arg;
	uint_t		blksize;
	int		err;

	assert(cmd == LX_OSS_SNDCTL_DSP_GETBLKSIZE);

	/* Ioctl is only supported on dsp audio devices. */
	if ((err = i_is_dsp_dev(fd)) != 0)
		return (err);

	/* Query the current fragment count and size. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, LXA_IOC_GET_FRAG_INFO, "LXA_IOC_GET_FRAG_INFO");
	if (ioctl(fd, LXA_IOC_GET_FRAG_INFO, &fi) < 0)
		return (-errno);

	blksize = fi.lxa_fi_size;

	if (uucopy(&blksize, blksizep, sizeof (blksize)) != 0)
		return (-errno);
	return (0);
}

static int
/*ARGSUSED*/
ict_oss_sndctl_dsp_getspace(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	lx_oss_audio_buf_info_t	*spacep = (lx_oss_audio_buf_info_t *)arg;
	lx_oss_audio_buf_info_t	space;
	lxa_frag_info_t		fi;
	int			err;

	assert((cmd == LX_OSS_SNDCTL_DSP_GETOSPACE) ||
	    (cmd == LX_OSS_SNDCTL_DSP_GETISPACE));

	/* Ioctl is only supported on dsp audio devices. */
	if ((err = i_is_dsp_dev(fd)) != 0)
		return (err);

	/* Query the current fragment count and size. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, LXA_IOC_GET_FRAG_INFO, "LXA_IOC_GET_FRAG_INFO");
	if (ioctl(fd, LXA_IOC_GET_FRAG_INFO, &fi) < 0)
		return (-errno);

	/* Return the current fragment count and size. */
	space.fragstotal = fi.lxa_fi_cnt;
	space.fragsize = fi.lxa_fi_size;

	/*
	 * We'll lie and tell applications that they can always write
	 * out at least one fragment without blocking.
	 */
	space.fragments = 1;
	space.bytes = space.fragsize;

	if (cmd == LX_OSS_SNDCTL_DSP_GETOSPACE)
		lx_debug("\toss get output space result = ");
	if (cmd == LX_OSS_SNDCTL_DSP_GETISPACE)
		lx_debug("\toss get input space result = ");

	lx_debug("\t\tbytes = 0x%x (%u), fragments = 0x%x (%u)",
	    space.bytes, space.bytes, space.fragments, space.fragments);
	lx_debug("\t\tfragtotal = 0x%x (%u), fragsize = 0x%x (%u)",
	    space.fragstotal, space.fragstotal,
	    space.fragsize, space.fragsize);

	if (uucopy(&space, spacep, sizeof (space)) != 0)
		return (-errno);
	return (0);
}

static int
/*ARGSUSED*/
ict_oss_sndctl_dsp_setfragment(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	lxa_frag_info_t	fi;
	uint_t		*fraginfop = (uint_t *)arg;
	uint_t		fraginfo, frag_size, frag_cnt;
	int		err;

	assert(cmd == LX_OSS_SNDCTL_DSP_SETFRAGMENT);

	/* Ioctl is only supported on dsp audio devices. */
	if ((err = i_is_dsp_dev(fd)) != 0)
		return (err);

	if (uucopy(fraginfop, &fraginfo, sizeof (fraginfo)) != 0)
		return (-errno);

	/*
	 * The argument to this ioctl is a 32-bit integer of the
	 * format 0x MMMM SSSS where:
	 * 	SSSS - requests a fragment size of 2^SSSS
	 * 	MMMM - requests a maximum fragment count of 2^MMMM
	 * if MMMM is 0x7fff then the application is requesting
	 * no limits on the number of fragments.
	 */

	frag_size = fraginfo & 0xffff;
	frag_cnt = fraginfo >> 16;

	lx_debug("\toss fragment request: "
	    "power size = 0x%x (%u), power cnt = 0x%x (%u)",
	    frag_size, frag_size, frag_cnt, frag_cnt);

	/* Limit the supported fragment size from 2^4 to 2^31. */
	if ((frag_size < 4) || (frag_size > 31))
		return (-EINVAL);

	/* Limit the number of fragments from 2^1 to 2^32. */
	if (((frag_cnt < 1) || (frag_cnt > 32)) && (frag_cnt != 0x7fff))
		return (-EINVAL);

	/* Expand the fragment values. */
	frag_size = 1 << frag_size;
	if ((frag_cnt == 32) || (frag_cnt == 0x7fff)) {
		frag_cnt = UINT_MAX;
	} else {
		frag_cnt = 1 << frag_cnt;
	}

	lx_debug("\toss fragment request: "
	    "translated size = 0x%x (%u), translated cnt = 0x%x (%u)",
	    frag_size, frag_size, frag_cnt, frag_cnt);

	fi.lxa_fi_size = frag_size;
	fi.lxa_fi_cnt = frag_cnt;

	/* Set the current fragment count and size. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, LXA_IOC_SET_FRAG_INFO, "LXA_IOC_SET_FRAG_INFO");
	return ((ioctl(fd, LXA_IOC_SET_FRAG_INFO, &fi) < 0) ? -errno : 0);
}

static int
/*ARGSUSED*/
ict_oss_sndctl_dsp_getcaps(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	uint_t	*capsp = (uint_t *)arg;
	uint_t	caps;
	int	err;

	assert(cmd == LX_OSS_SNDCTL_DSP_GETCAPS);

	/* Ioctl is only supported on dsp audio devices. */
	if ((err = i_is_dsp_dev(fd)) != 0)
		return (err);

	/*
	 * Report that we support mmap access
	 * this is where things start to get fun.
	 */
	caps = LX_OSS_DSP_CAP_MMAP | LX_OSS_DSP_CAP_TRIGGER;

	if (uucopy(&caps, capsp, sizeof (caps)) != 0)
		return (-errno);
	return (0);
}

static int
/*ARGSUSED*/
ict_oss_sndctl_dsp_settrigger(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	uint_t		*triggerp = (uint_t *)arg;
	uint_t		trigger;
	int		err;

	assert(cmd == LX_OSS_SNDCTL_DSP_SETTRIGGER);

	/* Ioctl is only supported on dsp audio devices. */
	if ((err = i_is_dsp_dev(fd)) != 0)
		return (err);

	if (uucopy(triggerp, &trigger, sizeof (trigger)) != 0)
		return (-errno);

	lx_debug("\toss set trigger request = 0x%x (%u)",
	    trigger, trigger);

	/* We only support two types of trigger requests. */
	if ((trigger != LX_OSS_PCM_DISABLE_OUTPUT) &&
	    (trigger != LX_OSS_PCM_ENABLE_OUTPUT))
		return (-EINVAL);

	/*
	 * We only support triggers on devices open for write access,
	 * but we don't need to check for that here since the driver will
	 * verify this for us.
	 */

	/* Send the trigger command to the audio device. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, LXA_IOC_MMAP_OUTPUT, "LXA_IOC_MMAP_OUTPUT");
	return ((ioctl(fd, LXA_IOC_MMAP_OUTPUT, &trigger) < 0) ? -errno : 0);
}

static int
/*ARGSUSED*/
ict_oss_sndctl_dsp_getoptr(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	static uint_t		bytes = 0;
	lx_oss_count_info_t	ci;
	lxa_frag_info_t		fi;
	audio_info_t		ai;
	int			ptr, err;

	assert(cmd == LX_OSS_SNDCTL_DSP_GETOPTR);

	/* Ioctl is only supported on dsp audio devices. */
	if ((err = i_is_dsp_dev(fd)) != 0)
		return (err);

	/* Query the current fragment size. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, LXA_IOC_GET_FRAG_INFO, "LXA_IOC_GET_FRAG_INFO");
	if (ioctl(fd, LXA_IOC_GET_FRAG_INFO, &fi) < 0)
		return (-errno);

	/* Figure out how many samples have been played. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, AUDIO_GETINFO, "AUDIO_GETINFO");
	if (ioctl(fd, AUDIO_GETINFO, &ai) < 0)
		return (-errno);
	ci.bytes = ai.play.samples + ai.record.samples;

	/*
	 * Figure out how many fragments of audio have gone out since
	 * the last call to this ioctl.
	 */
	ci.blocks = (ci.bytes - bytes) / fi.lxa_fi_size;
	bytes = ci.bytes;

	/* Figure out the current fragment offset for mmap audio output. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, LXA_IOC_MMAP_PTR, "LXA_IOC_MMAP_PTR");
	if (ioctl(fd, LXA_IOC_MMAP_PTR, &ptr) < 0) {
		/*
		 * We really should return an error here, but some
		 * application (*cough* *cough* flash) expect this
		 * ioctl to work even if they haven't mmaped the
		 * device.
		 */
		ci.ptr = 0;
	} else {
		ci.ptr = ptr;
	}

	lx_debug("\toss get output ptr result = ");
	lx_debug("\t\t"
	    "bytes = 0x%x (%u), blocks = 0x%x (%u), ptr = 0x%x (%u)",
	    ci.bytes, ci.bytes, ci.blocks, ci.blocks, ci.ptr, ci.ptr);

	if (uucopy(&ci, (void *)arg, sizeof (ci)) != 0)
		return (-errno);
	return (0);
}

static int
/*ARGSUSED*/
ict_oss_sndctl_dsp_sync(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	int		amode, err;

	assert(cmd == LX_OSS_SNDCTL_DSP_SYNC);

	/* Ioctl is only supported on dsp audio devices. */
	if ((err = i_is_dsp_dev(fd)) != 0)
		return (err);

	/* We need to know the access mode for the file. */
	if ((amode = fcntl(fd, F_GETFL)) < 0)
		return (-EINVAL);
	amode &= O_ACCMODE;
	assert((amode == O_RDONLY) || (amode == O_WRONLY) || (amode == O_RDWR));

	/*
	 * A sync is basically a noop for record only device.
	 * We check for this here because on Linux a sync on a record
	 * only device returns success immediately.  But the Solaris
	 * equivalent to a drain operation is a AUDIO_DRAIN, and if
	 * it's issued to a record only device it will fail and return
	 * EINVAL.
	 */
	if (amode == O_RDONLY)
		return (0);

	/* Drain any pending output. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, AUDIO_DRAIN, "AUDIO_DRAIN");
	return ((ioctl(fd, AUDIO_DRAIN, NULL) < 0) ? -errno : 0);
}

/*
 * /dev/mixer ioctl translators and support
 *
 * There are some interesting things to take note of for supporting
 * /dev/mixer ioctls.
 *
 * 1) We report support for the following mixer resources:
 * 	VOLUME, PCM, MIC
 *
 * 2) We assume the following number of channels for each mixer resource:
 *	VOLUME:	2 channels
 *	PCM:	2 channels
 *	MIC:	1 channel
 *
 * 3) OSS sets the gain on each channel independently but on Solaris
 *    there is only one gain value and a balance value.  So we need
 *    to do some translation back and forth.
 *
 * 4) OSS assumes direct access to hardware but Solaris provides
 *    virtualized audio device access (where everyone who opens /dev/audio
 *    get a virtualized audio channel stream, all of which are merged
 *    together by a software mixer before reaching the hardware).  Hence
 *    mapping OSS mixer resources to Solaris mixer resources takes some
 *    work.  VOLUME and Mic resources are mapped to the actual underlying
 *    audio hardware resources.  PCM resource are mapped to the virtual
 *    audio channel output level.  This mapping becomes more complicated
 *    if there are no open audio output channels.  In this case the
 *    lx_audio device caches the PCM channels setting for us and applies
 *    them to any new audio output channels that get opened.  (This
 *    is the reason that we don't use AUDIO_SETINFO ioctls directly
 *    but instead the lx_audio driver custom LXA_IOC_MIXER_SET_*
 *    and LXA_IOC_MIXER_GET_* ioctls.)  For more information see
 *    the comments in lx_audio.c.
 */
static int
i_is_mixer_dev(int fd)
{
	int minor;

	/*
	 * This is a cloning device so we have to ask the driver
	 * what kind of minor node this is.
	 */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, LXA_IOC_GETMINORNUM, "LXA_IOC_GETMINORNUM");
	if (ioctl(fd, LXA_IOC_GETMINORNUM, &minor) < 0)
		return (-EINVAL);
	if (minor != LXA_MINORNUM_MIXER)
		return (-EINVAL);
	return (0);
}

static int
i_oss_mixer_ml_to_val(lxa_mixer_levels_t *ml, uint_t *val)
{
	int range, val1, val2;

	/* Deal with the other easy case, both channels have the same level. */
	if (ml->lxa_ml_balance == AUDIO_MID_BALANCE) {
		*val = LX_OSS_MIXER_ENC2(
		    LX_OSS_S2L_GAIN(ml->lxa_ml_gain),
		    LX_OSS_S2L_GAIN(ml->lxa_ml_gain));
		assert(LX_OSS_MIXER_2CH_OK(*val));
		return (0);
	}

	/* Decode the balance/gain into two separate levels. */
	if (ml->lxa_ml_balance > AUDIO_MID_BALANCE) {
		val2 = ml->lxa_ml_gain;

		range = AUDIO_RIGHT_BALANCE - AUDIO_MID_BALANCE;
		val1 = AUDIO_RIGHT_BALANCE - ml->lxa_ml_balance;
		val1 = (val2 * val1) / range;
	} else {
		assert(ml->lxa_ml_balance < AUDIO_MID_BALANCE);
		val1 = ml->lxa_ml_gain;

		range = AUDIO_MID_BALANCE - AUDIO_LEFT_BALANCE;
		val2 = ml->lxa_ml_balance;
		val2 = (val1 * val2) / range;
	}

	*val = LX_OSS_MIXER_ENC2(LX_OSS_S2L_GAIN(val1),
	    LX_OSS_S2L_GAIN(val2));
	return (0);
}

static int
i_oss_mixer_val_to_ml(uint_t val, lxa_mixer_levels_t *ml_old,
    lxa_mixer_levels_t *ml)
{
	int range, val1, val2;

	if (!LX_OSS_MIXER_2CH_OK(val))
		return (-EINVAL);

	val1 = LX_OSS_MIXER_DEC1(val);
	val2 = LX_OSS_MIXER_DEC2(val);

	/*
	 * Deal with the easy case.
	 * Both channels have the same non-zero level.
	 */
	if ((val1 != 0) && (val1 == val2)) {
		ml->lxa_ml_gain = LX_OSS_L2S_GAIN(val1);
		ml->lxa_ml_balance = AUDIO_MID_BALANCE;
		return (0);
	}

	/* If both levels are zero, preserve the current balance setting. */
	if ((val1 == 0) && (val2 == 0)) {
		ml->lxa_ml_gain = 0;
		ml->lxa_ml_balance = ml_old->lxa_ml_balance;
		return (0);
	}

	/*
	 * First set the gain to match the highest channel value volume.
	 * Then use the balance to simulate lower volume on the second
	 * channel.
	 */
	if (val1 > val2) {
		ml->lxa_ml_gain = LX_OSS_L2S_GAIN(val1);

		range = AUDIO_MID_BALANCE - AUDIO_LEFT_BALANCE;
		ml->lxa_ml_balance = 0;
		ml->lxa_ml_balance += ((val2 * range) / val1);
	} else {
		assert(val1 < val2);

		ml->lxa_ml_gain = LX_OSS_L2S_GAIN(val2);

		range = AUDIO_RIGHT_BALANCE - AUDIO_MID_BALANCE;
		ml->lxa_ml_balance = AUDIO_RIGHT_BALANCE;
		ml->lxa_ml_balance -= ((val1 * range) / val2);
	}

	return (0);
}

static int
/*ARGSUSED*/
ict_oss_mixer_read_volume(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	lxa_mixer_levels_t	ml;
	uint_t			*valp = (uint_t *)arg;
	uint_t			val;
	char			*cmd_txt;
	int			err, cmd_new;

	assert((cmd == LX_OSS_SOUND_MIXER_READ_VOLUME) ||
	    (cmd == LX_OSS_SOUND_MIXER_READ_PCM));

	/* Ioctl is only supported on mixer audio devices. */
	if ((err = i_is_mixer_dev(fd)) != 0)
		return (err);

	if (cmd == LX_OSS_SOUND_MIXER_READ_VOLUME) {
		cmd_new = LXA_IOC_MIXER_GET_VOL;
		cmd_txt = "LXA_IOC_MIXER_GET_VOL";
	}
	if (cmd == LX_OSS_SOUND_MIXER_READ_PCM) {
		cmd_new = LXA_IOC_MIXER_GET_PCM;
		cmd_txt = "LXA_IOC_MIXER_GET_PCM";
	}

	/* Attempt to set the device output gain. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)", fd, cmd_new, cmd_txt);
	if (ioctl(fd, cmd_new, &ml) < 0)
		return (-errno);

	lx_debug("\tlx_audio mixer results, "
	    "gain = 0x%x (%u), balance = 0x%x (%u)",
	    ml.lxa_ml_gain, ml.lxa_ml_gain,
	    ml.lxa_ml_balance, ml.lxa_ml_balance);

	assert(LXA_MIXER_LEVELS_OK(&ml));

	/* Translate the mixer levels struct to an OSS mixer value. */
	if ((err = i_oss_mixer_ml_to_val(&ml, &val)) != 0)
		return (err);
	assert(LX_OSS_MIXER_2CH_OK(val));

	lx_debug("\toss get mixer %s result = 0x%x (%u)",
	    (cmd == LX_OSS_SOUND_MIXER_READ_VOLUME) ? "volume" : "pcm",
	    val, val);

	if (uucopy(&val, valp, sizeof (val)) != 0)
		return (-errno);
	return (0);
}

static int
/*ARGSUSED*/
ict_oss_mixer_write_volume(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	lxa_mixer_levels_t	ml, ml_old;
	uint_t			*valp = (uint_t *)arg;
	uint_t			val;
	char			*cmd_txt;
	int			err, cmd_new;

	assert((cmd == LX_OSS_SOUND_MIXER_WRITE_VOLUME) ||
	    (cmd == LX_OSS_SOUND_MIXER_WRITE_PCM));

	/* Ioctl is only supported on mixer audio devices. */
	if ((err = i_is_mixer_dev(fd)) != 0)
		return (err);

	if (uucopy(valp, &val, sizeof (val)) != 0)
		return (-errno);

	if (cmd == LX_OSS_SOUND_MIXER_WRITE_VOLUME) {
		cmd_new = LXA_IOC_MIXER_SET_VOL;
		cmd_txt = "LXA_IOC_MIXER_SET_VOL";

		/* Attempt to get the device output gain. */
		lx_debug("\tioctl(%d, 0x%x - %s, ...)", fd,
		    LXA_IOC_MIXER_GET_VOL, "LXA_IOC_MIXER_GET_VOL");
		if (ioctl(fd, LXA_IOC_MIXER_GET_VOL, &ml_old) < 0)
			return (-errno);
	}

	if (cmd == LX_OSS_SOUND_MIXER_WRITE_PCM) {
		cmd_new = LXA_IOC_MIXER_SET_PCM;
		cmd_txt = "LXA_IOC_MIXER_SET_PCM";

		/* Attempt to get the device output gain. */
		lx_debug("\tioctl(%d, 0x%x - %s, ...)", fd,
		    LXA_IOC_MIXER_GET_PCM, "LXA_IOC_MIXER_GET_PCM");
		if (ioctl(fd, LXA_IOC_MIXER_GET_PCM, &ml_old) < 0)
			return (-errno);
	}

	lx_debug("\toss set mixer %s request = 0x%x (%u)",
	    (cmd == LX_OSS_SOUND_MIXER_WRITE_VOLUME) ? "volume" : "pcm",
	    val, val);

	/* Translate an OSS mixer value to mixer levels. */
	if ((err = i_oss_mixer_val_to_ml(val, &ml_old, &ml)) != 0)
		return (err);
	assert(LXA_MIXER_LEVELS_OK(&ml));

	lx_debug("\tlx_audio mixer request, "
	    "gain = 0x%x (%u), balance = 0x%x (%u)",
	    ml.lxa_ml_gain, ml.lxa_ml_gain,
	    ml.lxa_ml_balance, ml.lxa_ml_balance);

	/* Attempt to set the device output gain. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)", fd, cmd_new, cmd_txt);
	if (ioctl(fd, cmd_new, &ml) < 0)
		return (-errno);

	return (0);
}

static int
/*ARGSUSED*/
ict_oss_mixer_read_mic(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	lxa_mixer_levels_t	ml;
	uint_t			*valp = (uint_t *)arg;
	uint_t			val;
	int			err;

	assert((cmd == LX_OSS_SOUND_MIXER_READ_MIC) ||
	    (cmd == LX_OSS_SOUND_MIXER_READ_IGAIN));

	/* Ioctl is only supported on mixer audio devices. */
	if ((err = i_is_mixer_dev(fd)) != 0)
		return (err);

	/* Attempt to get the device input gain. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, LXA_IOC_MIXER_GET_MIC, "LXA_IOC_MIXER_GET_MIC");
	if (ioctl(fd, LXA_IOC_MIXER_GET_MIC, &ml) < 0)
		return (-errno);

	/* Report the mixer as having two channels. */
	val = LX_OSS_MIXER_ENC2(
	    LX_OSS_S2L_GAIN(ml.lxa_ml_gain),
	    LX_OSS_S2L_GAIN(ml.lxa_ml_gain));

	if (cmd == LX_OSS_SOUND_MIXER_READ_MIC)
		lx_debug("\toss get mixer mic result = 0x%x (%u)", val, val);
	if (cmd == LX_OSS_SOUND_MIXER_READ_IGAIN)
		lx_debug("\toss get mixer igain result = 0x%x (%u)", val, val);

	if (uucopy(&val, valp, sizeof (val)) != 0)
		return (-errno);
	return (0);
}

static int
/*ARGSUSED*/
ict_oss_mixer_write_mic(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	lxa_mixer_levels_t	ml;
	uint_t			*valp = (uint_t *)arg;
	uint_t			val;
	int			err;

	assert((cmd == LX_OSS_SOUND_MIXER_WRITE_MIC) ||
	    (cmd == LX_OSS_SOUND_MIXER_WRITE_IGAIN));

	/* Ioctl is only supported on mixer audio devices. */
	if ((err = i_is_mixer_dev(fd)) != 0)
		return (err);

	if (uucopy(valp, &val, sizeof (val)) != 0)
		return (-errno);

	if (cmd == LX_OSS_SOUND_MIXER_WRITE_MIC)
		lx_debug("\toss set mixer mic request = 0x%x (%u)", val, val);
	if (cmd == LX_OSS_SOUND_MIXER_WRITE_IGAIN)
		lx_debug("\toss set mixer igain request = 0x%x (%u)", val, val);

	/* The mic only supports one channel. */
	val = LX_OSS_MIXER_DEC1(val);

	ml.lxa_ml_balance = AUDIO_MID_BALANCE;
	ml.lxa_ml_gain = LX_OSS_L2S_GAIN(val);

	/* Attempt to set the device input gain. */
	lx_debug("\tioctl(%d, 0x%x - %s, ...)",
	    fd, LXA_IOC_MIXER_SET_MIC, "LXA_IOC_MIXER_SET_MIC");
	if (ioctl(fd, LXA_IOC_MIXER_SET_MIC, &ml) < 0)
		return (-errno);

	return (0);
}

static int
/*ARGSUSED*/
ict_oss_mixer_read_devs(int fd, struct stat *stat,
    int cmd, char *cmd_str, intptr_t arg)
{
	uint_t		*resultp = (uint_t *)arg;
	uint_t		result = 0;
	int		err;

	if (cmd == LX_OSS_SOUND_MIXER_READ_DEVMASK) {
		/* Bitmap of all the mixer channels we supposedly support. */
		result = ((1 << LX_OSS_SM_PCM) |
		    (1 << LX_OSS_SM_MIC) |
		    (1 << LX_OSS_SM_VOLUME));
	}
	if (cmd == LX_OSS_SOUND_MIXER_READ_STEREODEVS) {
		/* Bitmap of the stereo mixer channels we supposedly support. */
		result = ((1 << LX_OSS_SM_PCM) |
		    (1 << LX_OSS_SM_VOLUME));
	}
	if ((cmd == LX_OSS_SOUND_MIXER_READ_RECMASK) ||
	    (cmd == LX_OSS_SOUND_MIXER_READ_RECSRC)) {
		/* Bitmap of the mixer input channels we supposedly support. */
		result = (1 << LX_OSS_SM_MIC);
	}
	assert(result != 0);

	/* Ioctl is only supported on mixer audio devices. */
	if ((err = i_is_mixer_dev(fd)) != 0)
		return (err);

	if (uucopy(&result, resultp, sizeof (result)) != 0)
		return (-errno);

	return (0);
}

/*
 * Audio ioctl conversion support structures.
 */
static oss_fmt_translator_t oft_table[] = {
	{ LX_OSS_AFMT_MU_LAW,		AUDIO_ENCODING_ULAW,	8 },
	{ LX_OSS_AFMT_A_LAW,		AUDIO_ENCODING_ALAW,	8 },
	{ LX_OSS_AFMT_S8,		AUDIO_ENCODING_LINEAR,	8 },
	{ LX_OSS_AFMT_U8,		AUDIO_ENCODING_LINEAR8,	8 },
	{ LX_OSS_AFMT_S16_NE,		AUDIO_ENCODING_LINEAR,	16 },
	{ 0,				0,			0 }
};

/*
 * Ioctl translator definitions.
 */

/*
 * Defines to help with creating ioctl translators.
 *
 * IOC_CMD_TRANSLATOR_NONE - Ioctl has the same semantics and argument
 * values on Solaris and Linux but may have different command values.
 * (Macro assumes the symbolic Linux name assigned to the ioctl command
 * value is the same as the Solaris symbol but pre-pended with an "LX_")
 *
 * IOC_CMD_TRANSLATOR_PASS - Ioctl is a Linux specific ioctl and should
 * be passed through unmodified.
 *
 * IOC_CMD_TRANSLATOR_FILTER - Ioctl has the same command name on
 * Solaris and Linux and needs a translation function that is common to
 * more than one ioctl. (Macro assumes the symbolic Linux name assigned
 * to the ioctl command value is the same as the Solaris symbol but
 * pre-pended with an "LX_")
 *
 * IOC_CMD_TRANSLATOR_CUSTOM - Ioctl needs special handling via a
 * translation function.
 */
#define	IOC_CMD_TRANSLATOR_NONE(ioc_cmd_sym)				\
	{ (int)LX_##ioc_cmd_sym, "LX_" #ioc_cmd_sym,			\
		ioc_cmd_sym, #ioc_cmd_sym, ict_pass },

#define	IOC_CMD_TRANSLATOR_PASS(ioc_cmd_sym)				\
	{ (int)ioc_cmd_sym, #ioc_cmd_sym,				\
		ioc_cmd_sym, #ioc_cmd_sym, ict_pass },

#define	IOC_CMD_TRANSLATOR_FILTER(ioc_cmd_sym, ioct_handler)		\
	{ (int)LX_##ioc_cmd_sym, "LX_" #ioc_cmd_sym,			\
		ioc_cmd_sym, #ioc_cmd_sym, ioct_handler },

#define	IOC_CMD_TRANSLATOR_CUSTOM(ioc_cmd_sym, ioct_handler)		\
	{ (int)ioc_cmd_sym, #ioc_cmd_sym,				\
		(int)ioc_cmd_sym, #ioc_cmd_sym, ioct_handler },

#define	IOC_CMD_TRANSLATOR_END						\
	{ 0, NULL, 0, NULL, NULL }

/* All files will need to support these ioctls. */
#define	IOC_CMD_TRANSLATORS_ALL						\
	IOC_CMD_TRANSLATOR_NONE(FIONREAD)				\
	IOC_CMD_TRANSLATOR_NONE(FIONBIO)

/* Any files supporting streams semantics will need these ioctls. */
#define	IOC_CMD_TRANSLATORS_STREAMS					\
	IOC_CMD_TRANSLATOR_NONE(TCXONC)					\
	IOC_CMD_TRANSLATOR_NONE(TCFLSH)					\
	IOC_CMD_TRANSLATOR_NONE(TIOCEXCL)				\
	IOC_CMD_TRANSLATOR_NONE(TIOCNXCL)				\
	IOC_CMD_TRANSLATOR_NONE(TIOCSPGRP)				\
	IOC_CMD_TRANSLATOR_NONE(TIOCSTI)				\
	IOC_CMD_TRANSLATOR_NONE(TIOCSWINSZ)				\
	IOC_CMD_TRANSLATOR_NONE(TIOCMBIS)				\
	IOC_CMD_TRANSLATOR_NONE(TIOCMBIC)				\
	IOC_CMD_TRANSLATOR_NONE(TIOCMSET)				\
	IOC_CMD_TRANSLATOR_NONE(TIOCSETD)				\
	IOC_CMD_TRANSLATOR_NONE(FIOASYNC)				\
	IOC_CMD_TRANSLATOR_NONE(FIOSETOWN)				\
	IOC_CMD_TRANSLATOR_NONE(TCSBRK)					\
									\
	IOC_CMD_TRANSLATOR_FILTER(TCSETS,		ict_tcsets)	\
	IOC_CMD_TRANSLATOR_FILTER(TCSETSW,		ict_tcsets)	\
	IOC_CMD_TRANSLATOR_FILTER(TCSETSF,		ict_tcsets)	\
	IOC_CMD_TRANSLATOR_FILTER(TCSETA,		ict_tcseta)	\
	IOC_CMD_TRANSLATOR_FILTER(TCSETAW,		ict_tcseta)	\
	IOC_CMD_TRANSLATOR_FILTER(TCSETAF,		ict_tcseta)	\
									\
	IOC_CMD_TRANSLATOR_CUSTOM(LX_TCSBRKP,		ict_tcsbrkp)


/*
 * Translators for non-device files.
 */
static ioc_cmd_translator_t ioc_translators_file[] = {
	IOC_CMD_TRANSLATORS_ALL
	IOC_CMD_TRANSLATOR_END
};

static ioc_cmd_translator_t ioc_translators_fifo[] = {
	IOC_CMD_TRANSLATORS_ALL
	IOC_CMD_TRANSLATORS_STREAMS
	IOC_CMD_TRANSLATOR_END
};

static ioc_cmd_translator_t ioc_translators_sock[] = {
	IOC_CMD_TRANSLATORS_ALL

	IOC_CMD_TRANSLATOR_NONE(FIOASYNC)
	IOC_CMD_TRANSLATOR_NONE(FIOGETOWN)
	IOC_CMD_TRANSLATOR_NONE(FIOSETOWN)
	IOC_CMD_TRANSLATOR_NONE(SIOCSPGRP)
	IOC_CMD_TRANSLATOR_NONE(SIOCGPGRP)

	IOC_CMD_TRANSLATOR_FILTER(SIOCATMARK,		ict_sioifoob)

	IOC_CMD_TRANSLATOR_FILTER(SIOCGIFFLAGS,		ict_sioifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCSIFFLAGS,		ict_sioifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCGIFADDR,		ict_sioifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCSIFADDR,		ict_sioifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCGIFDSTADDR,	ict_sioifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCSIFDSTADDR,	ict_sioifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCGIFBRDADDR,	ict_sioifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCSIFBRDADDR,	ict_sioifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCGIFNETMASK,	ict_sioifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCSIFNETMASK,	ict_sioifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCGIFMETRIC,	ict_sioifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCSIFMETRIC,	ict_sioifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCGIFMTU,		ict_sioifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCSIFMTU,		ict_sioifreq)

	IOC_CMD_TRANSLATOR_CUSTOM(LX_SIOCGIFCONF,	ict_siocgifconf)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_SIOCGIFHWADDR,	ict_siocifhwaddr)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_SIOCSIFHWADDR,	ict_siocifhwaddr)

	IOC_CMD_TRANSLATOR_END
};

/*
 * Translators for devices.
 */
static ioc_cmd_translator_t ioc_cmd_translators_ptm[] = {
	IOC_CMD_TRANSLATORS_ALL
	IOC_CMD_TRANSLATORS_STREAMS

	IOC_CMD_TRANSLATOR_NONE(TIOCPKT)

	IOC_CMD_TRANSLATOR_CUSTOM(LX_TIOCGPGRP,		ict_tiocgpgrp)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_TIOCSPTLCK,	ict_sptlock)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_TIOCGPTN,		ict_gptn)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_TIOCGWINSZ,	ict_tiocgwinsz)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_TCGETS,		ict_tcgets_emulate)

	IOC_CMD_TRANSLATOR_END
};
static ioc_dev_translator_t ioc_translator_ptm = {
	LX_PTM_DRV,	/* idt_driver */
	0,		/* idt_major */
	ioc_cmd_translators_ptm
};

static ioc_cmd_translator_t ioc_cmd_translators_pts[] = {
	IOC_CMD_TRANSLATORS_ALL
	IOC_CMD_TRANSLATORS_STREAMS

	IOC_CMD_TRANSLATOR_NONE(TIOCGETD)
	IOC_CMD_TRANSLATOR_NONE(TIOCGSID)
	IOC_CMD_TRANSLATOR_NONE(TIOCNOTTY)

	IOC_CMD_TRANSLATOR_CUSTOM(LX_TIOCGPGRP,		ict_tiocgpgrp)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_TCGETS,		ict_tcgets_native)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_TCGETA,		ict_tcgeta)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_TIOCGWINSZ,	ict_tiocgwinsz)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_TIOCSCTTY,		ict_tiocsctty)

	IOC_CMD_TRANSLATOR_END
};
static ioc_dev_translator_t ioc_translator_pts = {
	"pts",		/* idt_driver */
	0,		/* idt_major */
	ioc_cmd_translators_pts
};

static ioc_dev_translator_t ioc_translator_sy = {
	"sy",		/* idt_driver */
	0,		/* idt_major */

	/*
	 * /dev/tty (which is implemented via the "sy" driver) is basically
	 * a layered driver that passes on requests to the ctty for the
	 * current process.  Since ctty's are currently always implemented
	 * via the pts driver, we should make sure to support all the
	 * same ioctls on the sy driver as we do on the pts driver.
	 */
	ioc_cmd_translators_pts
};

static ioc_cmd_translator_t ioc_cmd_translators_zcons[] = {
	IOC_CMD_TRANSLATORS_ALL
	IOC_CMD_TRANSLATORS_STREAMS

	IOC_CMD_TRANSLATOR_NONE(TIOCNOTTY)

	IOC_CMD_TRANSLATOR_CUSTOM(LX_TCGETS,		ict_tcgets_native)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_TCGETA,		ict_tcgeta)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_TIOCGWINSZ,	ict_tiocgwinsz)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_TIOCSCTTY,		ict_tiocsctty)

	IOC_CMD_TRANSLATOR_CUSTOM(LX_TIOCLINUX,		ict_einval)

	IOC_CMD_TRANSLATOR_END
};
static ioc_dev_translator_t ioc_translator_zcons = {
	"zcons",	/* idt_driver */
	0,		/* idt_major */
	ioc_cmd_translators_zcons
};

static ioc_cmd_translator_t ioc_cmd_translators_lx_audio[] = {
	IOC_CMD_TRANSLATORS_ALL

	/* /dev/dsp ioctls */
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SNDCTL_DSP_RESET,
	    ict_oss_sndctl_dsp_reset)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SNDCTL_DSP_GETFMTS,
	    ict_oss_sndctl_dsp_getfmts)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SNDCTL_DSP_SETFMTS,
	    ict_oss_sndctl_dsp_setfmts)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SNDCTL_DSP_CHANNELS,
	    ict_oss_sndctl_dsp_channels)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SNDCTL_DSP_STEREO,
	    ict_oss_sndctl_dsp_channels)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SNDCTL_DSP_SPEED,
	    ict_oss_sndctl_dsp_speed)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SNDCTL_DSP_GETBLKSIZE,
	    ict_oss_sndctl_dsp_getblksize)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SNDCTL_DSP_SYNC,
	    ict_oss_sndctl_dsp_sync)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SNDCTL_DSP_SETFRAGMENT,
	    ict_oss_sndctl_dsp_setfragment)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SNDCTL_DSP_GETOSPACE,
	    ict_oss_sndctl_dsp_getspace)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SNDCTL_DSP_GETCAPS,
	    ict_oss_sndctl_dsp_getcaps)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SNDCTL_DSP_SETTRIGGER,
	    ict_oss_sndctl_dsp_settrigger)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SNDCTL_DSP_GETOPTR,
	    ict_oss_sndctl_dsp_getoptr)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SNDCTL_DSP_GETISPACE,
	    ict_oss_sndctl_dsp_getspace)

	/* /dev/mixer level ioctls */
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SOUND_MIXER_READ_VOLUME,
	    ict_oss_mixer_read_volume)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SOUND_MIXER_READ_PCM,
	    ict_oss_mixer_read_volume)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SOUND_MIXER_READ_MIC,
	    ict_oss_mixer_read_mic)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SOUND_MIXER_READ_IGAIN,
	    ict_oss_mixer_read_mic)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SOUND_MIXER_WRITE_VOLUME,
	    ict_oss_mixer_write_volume)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SOUND_MIXER_WRITE_PCM,
	    ict_oss_mixer_write_volume)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SOUND_MIXER_WRITE_MIC,
	    ict_oss_mixer_write_mic)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SOUND_MIXER_WRITE_IGAIN,
	    ict_oss_mixer_write_mic)

	/* /dev/mixer capability ioctls */
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SOUND_MIXER_READ_STEREODEVS,
	    ict_oss_mixer_read_devs)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SOUND_MIXER_READ_DEVMASK,
	    ict_oss_mixer_read_devs)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SOUND_MIXER_READ_RECMASK,
	    ict_oss_mixer_read_devs)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_OSS_SOUND_MIXER_READ_RECSRC,
	    ict_oss_mixer_read_devs)

	IOC_CMD_TRANSLATOR_END
};
static ioc_dev_translator_t ioc_translator_lx_audio = {
	"lx_audio",	/* idt_driver */
	0,		/* idt_major */
	ioc_cmd_translators_lx_audio
};

/*
 * An array of all the device translators.
 */
static ioc_dev_translator_t *ioc_translators_dev[] = {
	&ioc_translator_lx_audio,
	&ioc_translator_ptm,
	&ioc_translator_pts,
	&ioc_translator_sy,
	&ioc_translator_zcons,
	NULL
};

/*
 * Translators for filesystems.
 */
static ioc_cmd_translator_t ioc_cmd_translators_autofs[] = {
	IOC_CMD_TRANSLATOR_PASS(LX_AUTOFS_IOC_READY)
	IOC_CMD_TRANSLATOR_PASS(LX_AUTOFS_IOC_FAIL)
	IOC_CMD_TRANSLATOR_PASS(LX_AUTOFS_IOC_CATATONIC)
	IOC_CMD_TRANSLATOR_END
};

static ioc_fs_translator_t ioc_translator_autofs = {
	LX_AUTOFS_NAME,	/* ift_filesystem */
	ioc_cmd_translators_autofs
};

/*
 * An array of all the filesystem translators.
 */
static ioc_fs_translator_t *ioc_translators_fs[] = {
	&ioc_translator_autofs,
	NULL
};

/*
 * Ioctl error translator definitions.
 */
#define	IOC_ERRNO_TRANSLATOR(iet_cmd_sym, iet_errno)			\
	{ (int)LX_##iet_cmd_sym, "LX_" #iet_cmd_sym, iet_errno },

#define	IOC_ERRNO_TRANSLATOR_END					\
	{ 0, NULL, 0 }

static ioc_errno_translator_t ioc_translators_errno[] = {
	IOC_ERRNO_TRANSLATOR(TCGETS, ENOTTY)
	IOC_ERRNO_TRANSLATOR(TCSETS, ENOTTY)
	IOC_ERRNO_TRANSLATOR(TCSBRK, ENOTTY)
	IOC_ERRNO_TRANSLATOR(TCXONC, ENOTTY)
	IOC_ERRNO_TRANSLATOR(TCFLSH, ENOTTY)
	IOC_ERRNO_TRANSLATOR(TIOCGPGRP, ENOTTY)
	IOC_ERRNO_TRANSLATOR(TIOCSPGRP, ENOTTY)
	IOC_ERRNO_TRANSLATOR(TIOCGWINSZ, ENOTTY)
	IOC_ERRNO_TRANSLATOR_END
};

long
lx_vhangup(void)
{
	if (geteuid() != 0)
		return (-EPERM);

	vhangup();

	return (0);
}
