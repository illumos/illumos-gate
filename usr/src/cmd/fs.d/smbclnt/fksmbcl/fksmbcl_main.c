/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Test & debug program for the SMB client
 *
 * This implements a simple command reader which accepts
 * commands to simulate system calls into the file system.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/dirent.h>
#include <sys/strlog.h>		/* SL_NOTE */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <unistd.h>

#include <sys/fs/smbfs_mount.h>
#include <netsmb/smb_lib.h>
#include <libfknsmb/common/libfknsmb.h>
#include <libfksmbfs/common/libfksmbfs.h>

#if _FILE_OFFSET_BITS != 64
#error "This calls (fake) VFS code which requires 64-bit off_t"
#endif

extern int list_shares(struct smb_ctx *);

#define	MAXARG	10

struct cmd_tbl_ent {
	void (*ce_func)(int, char **);
	const char *ce_name;
	const char *ce_argdesc;
};
static struct cmd_tbl_ent cmd_tbl[];

static struct smb_ctx *ctx = NULL;
static char *server = NULL;

static vfs_t *vfsp = NULL;

static void show_dents(vnode_t *, offset_t *, char *, int);
static void run_cli(void);

#define	TBUFSZ 8192
static char tbuf[TBUFSZ];

static void
fksmbcl_usage(void)
{
	printf("usage: fksmbcl //user@server (like smbutil)\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int error, opt;

	/*
	 * Initializations
	 */
	nsmb_drv_load();
	nsmb_drv_init();
	fksmbfs_init();

	while ((opt = getopt(argc, argv, "dv")) != -1) {
		switch (opt) {
		case 'd':
			smb_debug++;
			break;
		case 'v':
			smb_verbose++;
			break;
		case '?':
			fksmbcl_usage();
			break;
		}
	}
	if (optind >= argc)
		fksmbcl_usage();
	server = argv[optind];

	/*
	 * Setup the libsmbfs context
	 */
	error = smb_ctx_alloc(&ctx);
	if (error) {
		fprintf(stderr, "%s: smb_ctx_alloc failed (%d)\n",
		    argv[0], error);
		return (1);
	}

	error = smb_ctx_scan_argv(ctx, argc, argv,
	    SMBL_SERVER, SMBL_SERVER, USE_WILDCARD);
	if (error) {
		fprintf(stderr, "logon: smb_ctx_scan_argv, error %d\n", error);
		return (1);
	}
	error = smb_ctx_readrc(ctx);
	if (error) {
		fprintf(stderr, "logon: smb_ctx_readrc, error %d\n", error);
		return (1);
	}

	/* Do smb_ctx_setshare later, and smb_ctx_resolve. */

	/*
	 * Next would be smb_ctx_get_ssn() but don't do that until
	 * the "logon" command so one can set breakpoints etc.
	 */

	/*
	 * Run the CLI
	 */
	run_cli();

	/*
	 * Cleanup
	 */
	fksmbfs_fini();
	nsmb_drv_fini();

	return (0);
}

static void
run_cli()
{
	static char cmdbuf[100];
	int argc, i;
	char *argv[MAXARG];
	char *cmd;
	char *savep = NULL;
	char *sep = " \t\n";
	char *prompt = NULL;
	struct cmd_tbl_ent *ce;

	if (isatty(0)) {
		fputs("# Start with:\n"
		    "> logon [user [dom [pw]]]\n"
		    "> shares\n"
		    "> mount {share}\n\n",
		    stdout);
		prompt = "> ";
	}

	for (;;) {
		if (prompt) {
			fputs(prompt, stdout);
			fflush(stdout);
		}

		cmd = fgets(cmdbuf, sizeof (cmdbuf), stdin);
		if (cmd == NULL)
			break;
		if (cmd[0] == '#')
			continue;

		if (prompt == NULL) {
			/* Put commands in the output too. */
			fprintf(stdout, "+ %s", cmdbuf);
		}

		argv[0] = strtok_r(cmd, sep, &savep);
		if (argv[0] == NULL)
			continue;
		for (argc = 1; argc < MAXARG; argc++) {
			argv[argc] = strtok_r(NULL, sep, &savep);
			if (argv[argc] == NULL)
				break;
		}
		for (i = argc; i < MAXARG; i++)
			argv[i++] = NULL;

		for (ce = cmd_tbl; ce->ce_name != NULL; ce++)
			if (strcmp(ce->ce_name, argv[0]) == 0)
				break;
		if (ce->ce_name != NULL) {
			ce->ce_func(argc, argv);
		} else {
			fprintf(stderr, "%s unknown command. Try help\n",
			    argv[0]);
		}
	}
}

/*
 * Command handlers
 */

static void
do_exit(int argc, char **argv)
{
	exit(0);
}

static void
do_help(int argc, char **argv)
{
	struct cmd_tbl_ent *ce;

	printf("Commands:\n");
	for (ce = cmd_tbl; ce->ce_func != NULL; ce++)
		printf("%s %s\n", ce->ce_name, ce->ce_argdesc);
}

static void
do_logon(int argc, char **argv)
{
	int error;

	if (argc > 1) {
		if (argv[1][0] == '-') {
			smb_ctx_setuser(ctx, "", B_TRUE);
			ctx->ct_flags |= SMBCF_NOPWD;
		} else {
			smb_ctx_setuser(ctx, argv[1], B_TRUE);
		}
	}
	if (argc > 2)
		smb_ctx_setdomain(ctx, argv[2], B_TRUE);
	if (argc > 3)
		smb_ctx_setpassword(ctx, argv[3], 0);

	/*
	 * Resolve the server address, setup derived defaults.
	 */
	error = smb_ctx_resolve(ctx);
	if (error) {
		fprintf(stderr, "logon: smb_ctx_resolve, error %d\n", error);
		return;
	}

	/*
	 * Have server, share, etc. now.
	 * Get the logon session.
	 */
again:
	error = smb_ctx_get_ssn(ctx);
	if (error == EAUTH) {
		int err2;
		err2 = smb_get_authentication(ctx);
		if (err2 == 0)
			goto again;
	}
	if (error) {
		fprintf(stderr, "//%s: login failed, error %d\n",
		    ctx->ct_fullserver, error);
	}
}

/*
 * Drop session created by the "logon" command.
 */
static void
do_logoff(int argc, char **argv)
{

	(void) nsmb_ioctl(ctx->ct_dev_fd, SMBIOC_SSN_RELE, NULL);
	if (argc > 1) {
		smb_ctx_done(ctx);
		(void) smb_ctx_init(ctx);
	}
}

/*
 * List shares
 */
static void
do_shares(int argc, char **argv)
{
	int error;

	smb_ctx_setshare(ctx, "IPC$", USE_IPC);
	error = smb_ctx_get_tree(ctx);
	if (error) {
		fprintf(stderr, "shares, tcon IPC$, error=%d\n", error);
		return;
	}

	error = list_shares(ctx);
	if (error) {
		fprintf(stderr, "shares, enum, error=%d\n", error);
	}

	(void) nsmb_ioctl(ctx->ct_dev_fd, SMBIOC_TREE_RELE, NULL);
}

char mnt_opt_buf[MAX_MNTOPT_STR];
char mnt_resource[MAXPATHLEN];

/*
 * Minimal excerpt from vfs.c:domount()
 */
void
do_mount(int argc, char **argv)
{
	struct smbfs_args mdata;
	struct mounta ma;
	char *shrname;
	int error;

	if (vfsp != NULL) {
		fprintf(stderr, "Already mounted\n");
		return;
	}

	if (argc < 2) {
		fprintf(stderr, "%s: missing share name\n", argv[0]);
		return;
	}
	shrname = argv[1];
	if (argc > 2)
		strlcpy(mnt_opt_buf, argv[2], sizeof (mnt_opt_buf));
	else
		memset(mnt_opt_buf, 0, sizeof (mnt_opt_buf));

	smb_ctx_setshare(ctx, shrname, USE_DISKDEV);
	error = smb_ctx_get_tree(ctx);
	if (error) {
		fprintf(stderr, "//%s/%s: tree connect failed, %d\n",
		    server, shrname, error);
		return;
	}

	(void) snprintf(mnt_resource, sizeof (mnt_resource),
	    "//%s/%s", ctx->ct_fullserver, shrname);

	bzero(&mdata, sizeof (mdata));
	mdata.version = SMBFS_VERSION;		/* smbfs mount version */
	mdata.file_mode = S_IRWXU;
	mdata.dir_mode = S_IRWXU;
	mdata.devfd = ctx->ct_dev_fd;

	/* Build mount args */
	bzero(&ma, sizeof (ma));
	ma.spec = mnt_resource;
	ma.dir = "/";
	ma.flags =  MS_DATA | MS_OPTIONSTR | MS_NOSPLICE | MS_NOSUID;
	ma.fstype = "smbfs";
	ma.dataptr = (void *) &mdata;
	ma.datalen = sizeof (mdata);
	ma.optptr = mnt_opt_buf;
	ma.optlen = sizeof (mnt_opt_buf);

	error = fake_domount("smbfs", &ma, &vfsp);
	if (error != 0) {
		fprintf(stderr, "domount error=%d\n", error);
	}

	/* Mount takes a ref, so always rele here. */
	(void) nsmb_ioctl(ctx->ct_dev_fd, SMBIOC_TREE_RELE, NULL);
}

void
do_unmount(int argc, char **argv)
{
	int error;

	if (vfsp == NULL) {
		fprintf(stderr, "Not mounted\n");
		return;
	}

	error = fake_dounmount(vfsp, 0);
	if (error != 0) {
		fprintf(stderr, "dounmount error=%d\n", error);
		return;
	}
	vfsp = NULL;
}

void
do_statfs(int argc, char **argv)
{
	statvfs64_t st;
	int error;

	if (vfsp == NULL) {
		fprintf(stderr, "Not mounted\n");
		return;
	}

	error = fsop_statfs(vfsp, &st);
	if (error != 0) {
		fprintf(stderr, "df error=%d\n", error);
		return;
	}
	printf("bsize=%ld\n", st.f_bsize);
	printf("frsize=%ld\n", st.f_frsize);
	printf("blocks=%" PRIu64 "\n", st.f_blocks);
	printf(" bfree=%" PRIu64 "\n", st.f_bfree);
	printf("bavail=%" PRIu64 "\n", st.f_bavail);
}

void
do_dir(int argc, char **argv)
{
	char *rdir;
	vnode_t *vp = NULL;
	offset_t off;
	int cnt;
	int error;

	if (vfsp == NULL) {
		fprintf(stderr, "mnt required first\n");
		return;
	}
	if (argc > 1)
		rdir = argv[1];
	else
		rdir = "";

	error = vn_open(rdir, 0, FREAD, 0, &vp, 0, 0);
	if (error != 0) {
		fprintf(stderr, "do_dir, vn_open error=%d\n", error);
		return;
	}

	off = 0;
	do {
		cnt = fake_getdents(vp, &off, tbuf, TBUFSZ);
		if (cnt < 0) {
			fprintf(stderr, "do_dir, getdents %d\n", -cnt);
			break;
		}
		show_dents(vp, &off, tbuf, cnt);
	} while (cnt > 0);

	if (vp != NULL)
		vn_close_rele(vp, 0);
}

void
do_dirx(int argc, char **argv)
{
	char *rdir;
	vnode_t *vp = NULL;
	offset_t off;
	int cnt;
	int error;

	if (vfsp == NULL) {
		fprintf(stderr, "mnt required first\n");
		return;
	}
	if (argc > 1)
		rdir = argv[1];
	else
		rdir = "";

	error = vn_open(rdir, 0, FREAD|FXATTRDIROPEN, 0, &vp, 0, 0);
	if (error != 0) {
		fprintf(stderr, "do_dirx, vn_open error=%d\n", error);
		return;
	}

	off = 0;
	do {
		cnt = fake_getdents(vp, &off, tbuf, TBUFSZ);
		if (cnt < 0) {
			fprintf(stderr, "do_dirx, getdents %d\n", -cnt);
			break;
		}
		show_dents(vp, &off, tbuf, cnt);
	} while (cnt > 0);

	if (vp != NULL)
		vn_close_rele(vp, 0);
}

static void
show_dents(vnode_t *dvp, offset_t *offp, char *buf, int cnt)
{
	char time_buf[40];
	struct stat64 st;
	vnode_t *vp;
	char *p;
	dirent_t *d;
	offset_t offset = (offset_t)-1L;
	int error;
	uint_t mode;
	char type;

	p = buf;
	while (p < (buf + cnt)) {
		d = (dirent_t *)(void *)p;
		p += d->d_reclen;
		offset = d->d_off;

		error = fake_lookup(dvp, d->d_name, &vp);
		if (error != 0) {
			fprintf(stderr, "%s: lookup error=%d\n",
			    d->d_name, error);
			continue;
		}
		error = fake_stat(vp, &st, 0);
		vn_rele(vp);
		if (error != 0) {
			fprintf(stderr, "%s: stat error=%d\n",
			    d->d_name, error);
			continue;
		}

		/*
		 * Print type, mode, size, name
		 * First mode (only dir, file expected here)
		 */
		if (S_ISDIR(st.st_mode)) {
			type = 'd';
		} else if (S_ISREG(st.st_mode)) {
			type = ' ';
		} else {
			type = '?';
		}
		mode = st.st_mode & 0777;
		(void) strftime(time_buf, sizeof (time_buf),
		    "%b %e %T %Y", localtime(&st.st_mtime));

		printf("%c 0%3o %9" PRIu64 "  %s  %s\n",
		    type, mode,
		    (uint64_t)st.st_size,
		    time_buf,
		    d->d_name);
	}
	*offp = offset;
}

/*
 * get rname [lname]
 */
void
do_get(int argc, char **argv)
{
	struct stat64 st;
	char *rname;
	char *lname;
	vnode_t *vp = NULL;
	offset_t off;
	ssize_t cnt, x;
	int oflg = O_RDWR | O_CREAT;
	int lfd = -1;
	int error;

	if (vfsp == NULL) {
		fprintf(stderr, "mnt required first\n");
		return;
	}
	if (argc < 2) {
		fprintf(stderr, "rname required\n");
		return;
	}
	rname = argv[1];
	if (argc > 2) {
		lname = argv[2];
		/*
		 * When local name is specified, overwrite.
		 * Convenient for scripts etc.
		 */
		oflg |= O_TRUNC;
	} else {
		lname = rname;
		/* Local file should not exist. */
		oflg |= O_EXCL;
	}

	lfd = open(lname, oflg, 0644);
	if (lfd < 0) {
		perror(lname);
		return;
	}

	error = vn_open(rname, 0, FREAD, 0, &vp, 0, 0);
	if (error != 0) {
		fprintf(stderr, "do_get, vn_open error=%d\n", error);
		goto out;
	}
	error = fake_stat(vp, &st, 0);
	if (error != 0) {
		fprintf(stderr, "do_get, stat error=%d\n", error);
		goto out;
	}

	off = 0;
	do {
		cnt = fake_pread(vp, tbuf, TBUFSZ, off);
		if (cnt < 0) {
			fprintf(stderr, "do_get, read %d\n", -cnt);
			goto out;
		}
		x = write(lfd, tbuf, cnt);
		if (x < 0) {
			fprintf(stderr, "do_get, write %d\n", errno);
			goto out;
		}
		off += x;
	} while (off < st.st_size);

out:
	if (vp != NULL)
		vn_close_rele(vp, 0);
	if (lfd != -1)
		close(lfd);
}

/*
 * put lname [rname]
 */
void
do_put(int argc, char **argv)
{
	struct stat64 rst;
	struct stat st;
	char *rname;
	char *lname;
	vnode_t *vp = NULL;
	offset_t off;
	ssize_t cnt, x;
	int oflg = FREAD|FWRITE|FCREAT;
	int lfd = -1;
	int error;

	if (vfsp == NULL) {
		fprintf(stderr, "mnt required first\n");
		return;
	}
	if (argc < 2) {
		fprintf(stderr, "lname required\n");
		return;
	}
	lname = argv[1];
	if (argc > 2) {
		rname = argv[2];
		/*
		 * When remote name is specified, overwrite.
		 * Convenient for scripts etc.
		 */
		oflg |= FTRUNC;
	} else {
		rname = lname;
		/* Remote file should not exist. */
		oflg |= FEXCL;
	}

	lfd = open(lname, O_RDONLY, 0);
	if (lfd < 0) {
		perror(lname);
		return;
	}
	error = fstat(lfd, &st);
	if (error != 0) {
		fprintf(stderr, "do_put, stat error=%d\n", error);
		goto out;
	}

	error = vn_open(rname, 0, oflg, 0, &vp, 0, 0);
	if (error != 0) {
		fprintf(stderr, "do_put, vn_open error=%d\n", error);
		goto out;
	}

	off = 0;
	do {
		cnt = pread(lfd, tbuf, TBUFSZ, off);
		if (cnt < 0) {
			fprintf(stderr, "do_put, read %d\n", errno);
			goto out;
		}
		x = fake_pwrite(vp, tbuf, cnt, off);
		if (x < 0) {
			fprintf(stderr, "do_put, write %d\n", -x);
			goto out;
		}
		off += cnt;
	} while (off < st.st_size);

	/* This getattr should go OtW. */
	error = fake_stat(vp, &rst, 0);
	if (error != 0) {
		fprintf(stderr, "do_put, stat error=%d\n", error);
		goto out;
	}
	if (rst.st_size != st.st_size) {
		fprintf(stderr, "do_put, wrong size?\n");
	}

out:
	if (vp != NULL)
		vn_close_rele(vp, 0);
	if (lfd != -1)
		close(lfd);
}

/*
 * rm rname
 */
void
do_rm(int argc, char **argv)
{
	char *rname;
	int error;

	if (vfsp == NULL) {
		fprintf(stderr, "mnt required first\n");
		return;
	}
	if (argc < 2) {
		fprintf(stderr, "rname required\n");
		return;
	}
	rname = argv[1];

	error = fake_unlink(rname, 0);
	if (error != 0) {
		fprintf(stderr, "do_rm, unlink error=%d\n", error);
	}
}

/*
 * mv fromname toname
 */
void
do_mv(int argc, char **argv)
{
	int error;

	if (vfsp == NULL) {
		fprintf(stderr, "mnt required first\n");
		return;
	}
	if (argc < 3) {
		fprintf(stderr, "from_name to_name required\n");
		return;
	}

	error = fake_rename(argv[1], argv[2]);
	if (error != 0) {
		fprintf(stderr, "do_mv, rename error=%d\n", error);
	}
}

/*
 * mkdir rname
 */
void
do_mkdir(int argc, char **argv)
{
	char *rname;
	vnode_t *vp = NULL;
	int error;

	if (vfsp == NULL) {
		fprintf(stderr, "mnt required first\n");
		return;
	}
	if (argc < 2) {
		fprintf(stderr, "rname required\n");
		return;
	}
	rname = argv[1];

	error = vn_open(rname, 0, FCREAT, 0, &vp, CRMKDIR, 0);
	if (error != 0) {
		fprintf(stderr, "do_mkdir, vn_open error=%d\n", error);
	}

	if (vp != NULL)
		vn_close_rele(vp, 0);
}

/*
 * rmdir rname
 */
void
do_rmdir(int argc, char **argv)
{
	char *rname;
	int error;

	if (vfsp == NULL) {
		fprintf(stderr, "mnt required first\n");
		return;
	}
	if (argc < 2) {
		fprintf(stderr, "rname required\n");
		return;
	}
	rname = argv[1];

	error = fake_unlink(rname, AT_REMOVEDIR);
	if (error != 0) {
		fprintf(stderr, "do_rmdir, unlink error=%d\n", error);
	}
}

/*
 * Simple option setting
 *
 * Each arg is handled as one line in .nsmbrc [default]
 */
void
do_opt(int argc, char **argv)
{
	static char template[20] = "/tmp/fksmbclXXXXXX";
	static char rcname[30];
	char *tdname;
	char *save_home;
	FILE *fp;
	int err, i;

	if (argc < 2) {
		fprintf(stderr, "opt {key}[=value]\n");
		return;
	}

	tdname = mkdtemp(template);
	if (tdname == NULL) {
		perror("mkdtemp");
		return;
	}
	(void) snprintf(rcname, sizeof (rcname),
	    "%s/.nsmbrc", tdname);

	fp = fopen(rcname, "w");
	if (fp == NULL) {
		perror(rcname);
		goto out;
	}
	fprintf(fp, "[default]\n");
	for (i = 1; i < argc; i++)
		fprintf(fp, "%s\n", argv[i]);
	fclose(fp);

	save_home = ctx->ct_home;
	ctx->ct_home = tdname;
	err = smb_ctx_readrc(ctx);
	ctx->ct_home = save_home;

	if (err != 0)
		fprintf(stderr, "readrc, err=%d\n", err);

out:
	(void) unlink(rcname);
	(void) rmdir(tdname);
}

/*
 * Command table
 */
static struct cmd_tbl_ent
cmd_tbl[] = {
	{ do_help,	"help", "" },
	{ do_exit,	"exit", "" },
	{ do_logon,	"logon", "[user [dom [pass]]]" },
	{ do_logoff,	"logoff", "[close-driver]" },
	{ do_shares,	"shares", "" },
	{ do_mount,	"mount",  "{share} [optstr]" },
	{ do_unmount,	"umount", "" },
	{ do_unmount,	"unmount", "" },
	{ do_statfs,	"statfs", "" },
	{ do_dir,	"dir",  "{rdir} [lfile]" },
	{ do_dirx,	"dirx", "{rdir} [lfile]" },
	{ do_get,	"get",  "{rfile} [lfile]" },
	{ do_put,	"put",  "{lfile} [rfile]" },
	{ do_mv,	"mv",   "{from} {to}" },
	{ do_rm,	"rm",   "{rfile}" },
	{ do_mkdir,	"mkdir", "{rfile}" },
	{ do_rmdir,	"rmdir", "{rfile}" },
	{ do_opt,	"opt",   "{option}" },
	{ NULL, NULL, NULL }
};

/*
 * Provide a real function (one that prints something) to replace
 * the stub in libfakekernel.  This prints cmn_err() messages.
 */
void
fakekernel_putlog(char *msg, size_t len, int flags)
{

	/*
	 * [CE_CONT, CE_NOTE, CE_WARN, CE_PANIC] maps to
	 * [SL_NOTE, SL_NOTE, SL_WARN, SL_FATAL]
	 */
	if (smb_debug == 0 && (flags & SL_NOTE))
		return;
	(void) fwrite(msg, 1, len, stdout);
	(void) fflush(stdout);
}

/*
 * Print nsmb debug messages via driver smb_debugmsg()
 */
void
smb_debugmsg(const char *func, char *msg)
{
	if (smb_debug < 2)
		return;
	printf("[kmod] %s: %s\n", func, msg);
}

/*
 * Enable libumem debugging
 */
const char *
_umem_debug_init(void)
{
	return ("default,verbose"); /* $UMEM_DEBUG setting */
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents"); /* $UMEM_LOGGING setting */
}
