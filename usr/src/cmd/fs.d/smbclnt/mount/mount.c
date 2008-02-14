/*
 * Copyright (c) 2000-2001, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: mount_smbfs.c,v 1.28.44.2 2005/06/02 00:55:41 lindak Exp $
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/mount.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <sysexits.h>
#include <libintl.h>
#include <locale.h>
#include <libscf.h>

#include <sys/mntent.h>
#include <sys/mnttab.h>

#include <cflib.h>

#include <netsmb/smb.h>
#include <netsmb/smb_lib.h>

#include <sys/fs/smbfs_mount.h>

#include "mntopts.h"

static char mount_point[MAXPATHLEN + 1];
static void usage(void);
static int setsubopt(int, char *, struct smbfs_args *);

/* smbfs options */
#define	MNTOPT_RETRY		"retry"
#define	MNTOPT_TIMEOUT		"timeout"
#define	MNTOPT_DIRPERMS		"dirperms"
#define	MNTOPT_FILEPERMS	"fileperms"
#define	MNTOPT_GID		"gid"
#define	MNTOPT_UID		"uid"
#define	MNTOPT_NOPROMPT		"noprompt"

#define	OPT_RETRY	1
#define	OPT_TIMEOUT	2
#define	OPT_DIRPERMS	3
#define	OPT_FILEPERMS	4
#define	OPT_GID		5
#define	OPT_UID		6
#define	OPT_NOPROMPT	7

/* generic VFS options */
#define	OPT_RO		10
#define	OPT_RW		11
#define	OPT_SUID 	12
#define	OPT_NOSUID 	13
#define	OPT_DEVICES	14
#define	OPT_NODEVICES	15
#define	OPT_SETUID	16
#define	OPT_NOSETUID	17
#define	OPT_EXEC	18
#define	OPT_NOEXEC	19

struct smbfsopts {
	char *name;
	int index;
};

struct smbfsopts opts[] = {
	{MNTOPT_RETRY,		OPT_RETRY},
	{MNTOPT_TIMEOUT,	OPT_TIMEOUT},
	{MNTOPT_DIRPERMS,	OPT_DIRPERMS},
	{MNTOPT_FILEPERMS,	OPT_FILEPERMS},
	{MNTOPT_GID,		OPT_GID},
	{MNTOPT_UID,		OPT_UID},
	{MNTOPT_NOPROMPT,	OPT_NOPROMPT},
	{MNTOPT_RO,		OPT_RO},
	{MNTOPT_RW,		OPT_RW},
	{MNTOPT_SUID,		OPT_SUID},
	{MNTOPT_NOSUID,		OPT_NOSUID},
	{MNTOPT_DEVICES,	OPT_DEVICES},
	{MNTOPT_NODEVICES,	OPT_NODEVICES},
	{MNTOPT_SETUID,		OPT_SETUID},
	{MNTOPT_NOSETUID,	OPT_NOSETUID},
	{MNTOPT_EXEC,		OPT_EXEC},
	{MNTOPT_NOEXEC,		OPT_NOEXEC},
	{NULL,		0}
};

static int Oflg = 0;    /* Overlay mounts */
static int qflg = 0;    /* quiet - don't print warnings on bad options */
static int ro = 0;	/* read-only mount */
static int noprompt = 0;	/* don't prompt for password */
static int retry = -1;
static int timeout = -1;

#define	RET_ERR	33
#define	SERVICE "svc:/network/smb/client:default"

int
main(int argc, char *argv[])
{
	struct smb_ctx sctx, *ctx = &sctx;
	struct smbfs_args mdata;
	struct stat st;
	extern void dropsuid();
	int opt, error, mntflags;
	struct mnttab mnt;
	struct mnttab *mntp = &mnt;
	char optbuf[MAX_MNTOPT_STR];
	static char *fstype = MNTTYPE_SMBFS;
	char *env, *state;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);
	dropsuid();
	if (argc == 2) {
		if (strcmp(argv[1], "-h") == 0) {
			usage();
		} else if (strcmp(argv[1], "-v") == 0) {
			errx(EX_OK, gettext("version %d.%d.%d"),
			    SMBFS_VERSION / 100000,
			    (SMBFS_VERSION % 10000) / 1000,
			    (SMBFS_VERSION % 1000) / 100);
		}
	}
	if (argc < 3)
		usage();

	state = smf_get_state(SERVICE);
	if (state == NULL || strcmp(state, SCF_STATE_STRING_ONLINE) != 0) {
		fprintf(stderr,
		    gettext("mount_smbfs: service \"%s\" not enabled.\n"),
		    SERVICE);
		exit(1);
	}

	/* Debugging support. */
	if ((env = getenv("SMBFS_DEBUG")) != NULL) {
		smb_debug = atoi(env);
		if (smb_debug < 1)
			smb_debug = 1;
	}

	error = smb_lib_init();
	if (error)
		exit(error);

	mnt.mnt_mntopts = optbuf;
	mntflags = MS_DATA;
	bzero(&mdata, sizeof (mdata));
	mdata.uid = (uid_t)-1;
	mdata.gid = (gid_t)-1;
	mdata.caseopt = SMB_CS_NONE;

	error = smb_ctx_init(ctx, argc, argv, SMBL_SHARE, SMBL_SHARE,
	    SMB_ST_DISK);
	if (error)
		exit(error);
	error = smb_ctx_readrc(ctx);
	if (error)
		exit(error);

	while ((opt = getopt(argc, argv, "ro:Oq")) != -1) {
		switch (opt) {
		case 'O':
			Oflg++;
			break;

		case 'q':
			qflg++;
			break;

		case 'r':
			ro++;
			break;

		case 'o': {
			char *nextopt, *comma, *equals, *sopt, *soptval;
			int i, ret;

			if (strlen(optarg) >= MAX_MNTOPT_STR) {
				if (!qflg)
					warnx(gettext(
					    "option string too long"));
				exit(RET_ERR);
			}
			for (sopt = optarg; sopt != NULL; sopt = nextopt) {
				comma = strchr(sopt, ',');
				if (comma) {
					nextopt = comma + 1;
					*comma = '\0';
				} else
					nextopt = NULL;
				equals = strchr(sopt, '=');
				if (equals) {
					soptval = equals + 1;
					*equals = '\0';
				} else
					soptval = NULL;
				for (i = 0; opts[i].name != NULL; i++) {
					if (strcmp(sopt, opts[i].name) == 0)
						break;
				}
				if (opts[i].name == NULL) {
					if (equals)
						*equals = '=';
					if (!qflg)
						errx(RET_ERR, gettext(
						    "Bad option '%s'"), sopt);
					if (comma)
						*comma = ',';
					continue;
				}
				ret = setsubopt(opts[i].index, soptval, &mdata);
				if (ret != 0)
					exit(RET_ERR);
				if (equals)
					*equals = '=';
				(void) strcat(mnt.mnt_mntopts, sopt);
				if (comma)
					*comma = ',';
			}
			break;
		}

		case '?':
		default:
			usage();
		}
	}

	if (Oflg)
		mntflags |= MS_OVERLAY;

	if (ro) {
		char *p;

		mntflags |= MS_RDONLY;
		/* convert "rw"->"ro" */
		if (p = strstr(mntp->mnt_mntopts, "rw")) {
			if (*(p+2) == ',' || *(p+2) == '\0')
				*(p+1) = 'o';
		}
	}

	mnt.mnt_special = argv[optind];
	mnt.mnt_mountp = argv[optind+1];

	mdata.version = SMBFS_VERSION;		    /* smbfs mount version */

	if (optind == argc - 2)
		optind++;

	if (optind != argc - 1)
		usage();
	realpath(unpercent(argv[optind]), mount_point);

	if (stat(mount_point, &st) == -1)
		err(EX_OSERR, gettext("could not find mount point %s"),
		    mount_point);
	if (!S_ISDIR(st.st_mode)) {
		errno = ENOTDIR;
		err(EX_OSERR, gettext("can't mount on %s"), mount_point);
	}

	/*
	 * Darwin takes defaults from the
	 * mounted-on directory.
	 * We want the real uid/gid.
	 * XXX: Is this correct?
	 */
#ifdef __sun
	if (mdata.uid == (uid_t)-1)
		mdata.uid = getuid();
	if (mdata.gid == (gid_t)-1)
		mdata.gid = getgid();
#else
	if (mdata.uid == (uid_t)-1)
		mdata.uid = st.st_uid;
	if (mdata.gid == (gid_t)-1)
		mdata.gid = st.st_gid;
#endif

	if (mdata.file_mode == 0)
		mdata.file_mode = st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
	if (mdata.dir_mode == 0) {
		mdata.dir_mode = mdata.file_mode;
		if (mdata.dir_mode & S_IRUSR)
			mdata.dir_mode |= S_IXUSR;
		if (mdata.dir_mode & S_IRGRP)
			mdata.dir_mode |= S_IXGRP;
		if (mdata.dir_mode & S_IROTH)
			mdata.dir_mode |= S_IXOTH;
	}

	/*
	 * XXX: The driver can fill these in more reliably,
	 * so why do we set them here?  (Just set both = -1)
	 */
	ctx->ct_ssn.ioc_owner = ctx->ct_sh.ioc_owner = getuid();
	ctx->ct_ssn.ioc_group = ctx->ct_sh.ioc_group = getgid();
	opt = 0;
	if (mdata.dir_mode & S_IXGRP)
		opt |= SMBM_EXECGRP;
	if (mdata.dir_mode & S_IXOTH)
		opt |= SMBM_EXECOTH;
	ctx->ct_ssn.ioc_rights |= opt;
	ctx->ct_sh.ioc_rights |= opt;
	if (noprompt)
		ctx->ct_flags |= SMBCF_NOPWD;
	if (retry != -1)
		ctx->ct_ssn.ioc_retrycount = retry;
	if (timeout != -1)
		ctx->ct_ssn.ioc_timeout = timeout;

	/*
	 * If we got our password from the keychain and get an
	 * authorization error, we come back here to obtain a new
	 * password from user input.
	 */
reauth:
	error = smb_ctx_resolve(ctx);
	if (error)
		exit(error);

	mdata.devfd = ctx->ct_fd;		/* file descriptor */

again:
	error = smb_ctx_lookup(ctx, SMBL_SHARE, SMBLK_CREATE);
	if (error == ENOENT && ctx->ct_origshare) {
		strcpy(ctx->ct_sh.ioc_share, ctx->ct_origshare);
		free(ctx->ct_origshare);
		ctx->ct_origshare = NULL;
		goto again; /* try again using share name as given */
	}
	if (ctx->ct_flags & SMBCF_KCFOUND && smb_autherr(error)) {
		ctx->ct_ssn.ioc_password[0] = '\0';
		smb_error(gettext("main(lookup): bad keychain entry"), 0);
		ctx->ct_flags |= SMBCF_KCBAD;
		goto reauth;
	}
	if (error)
		exit(error);

	mdata.version = SMBFS_VERSION;
	mdata.devfd = ctx->ct_fd;

	if (mount(mntp->mnt_special, mntp->mnt_mountp,
	    mntflags, fstype, &mdata, sizeof (mdata),
	    mntp->mnt_mntopts, MAX_MNTOPT_STR) < 0) {
		if (errno != ENOENT) {
			err(EX_OSERR, gettext("mount_smbfs: %s"),
			    mntp->mnt_mountp);
		} else {
			struct stat sb;
			if (stat(mntp->mnt_mountp, &sb) < 0 &&
			    errno == ENOENT)
				err(EX_OSERR, gettext("mount_smbfs: %s"),
				    mntp->mnt_mountp);
			else
				err(EX_OSERR, gettext("mount_smbfs: %s"),
				    mntp->mnt_special);

			error = smb_ctx_tdis(ctx);
			if (error) /* unable to clean up?! */
				exit(error);
		}
	}

	smb_ctx_done(ctx);
	if (error) {
		smb_error(gettext("mount error: %s"), error, mount_point);
		exit(errno);
	}
	return (0);
}

int
setsubopt(int index, char *optarg, struct smbfs_args *mdatap)
{
	struct passwd *pwd;
	struct group *grp;
	long l;
	int err = 0;
	char *next;

	switch (index) {
	case OPT_RO:
	case OPT_RW:
	case OPT_SUID:
	case OPT_NOSUID:
	case OPT_DEVICES:
	case OPT_NODEVICES:
	case OPT_SETUID:
	case OPT_NOSETUID:
	case OPT_EXEC:
	case OPT_NOEXEC:
		/* We don't have to handle generic options here */
		return (0);
	case OPT_UID:
		pwd = isdigit(optarg[0]) ?
		    getpwuid(atoi(optarg)) : getpwnam(optarg);
		if (pwd == NULL) {
			if (!qflg)
				warnx(gettext("unknown user '%s'"), optarg);
			err = -1;
		} else {
			mdatap->uid = pwd->pw_uid;
		}
		break;
	case OPT_GID:
		grp = isdigit(optarg[0]) ?
		    getgrgid(atoi(optarg)) : getgrnam(optarg);
		if (grp == NULL) {
			if (!qflg)
				warnx(gettext("unknown group '%s'"), optarg);
			err = -1;
		} else {
			mdatap->gid = grp->gr_gid;
		}
		break;
	case OPT_DIRPERMS:
		errno = 0;
		l = strtol(optarg, &next, 8);
		if (errno || *next != 0) {
			if (!qflg)
				warnx(gettext(
				    "invalid value for directory mode"));
			err = -1;
		} else {
			mdatap->dir_mode = l;
		}
		break;
	case OPT_FILEPERMS:
		errno = 0;
		l = strtol(optarg, &next, 8);
		if (errno || *next != 0) {
			if (!qflg)
				warnx(gettext("invalid value for file mode"));
			err = -1;
		} else {
			mdatap->file_mode = l;
		}
		break;
	case OPT_RETRY:
		retry = atoi(optarg);
		break;
	case OPT_TIMEOUT:
		timeout = atoi(optarg);
		break;
	case OPT_NOPROMPT:
		noprompt++;
	}
	return (err);
}

static void
usage(void)
{
	fprintf(stderr, "%s\n",
	gettext("usage: mount -F smbfs [-Orq] [-o option[,option]]"
	"	//[workgroup;][user[:password]@]server[/share] path"));

	exit(EX_USAGE);
}
