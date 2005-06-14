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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

	/*
	 * This command can now print the value of data items
	 * from [1] /dev/kmem is the default, and [2] a named
	 * file passed with the -n argument.  If the read is from
	 * /dev/kmem, we also print the value of BSS symbols.
	 * The logic to support this is: if read is from file,
	 * [1] find the section number of .bss, [2] look through
	 * nlist for symbols that are in .bss section and zero
	 * the n_value field.  At print time, if the n_value field
	 * is non-zero, print the info.
	 *
	 * This protects us from trying to read a bss symbol from
	 * the file and, possibly, dropping core.
	 *
	 * When reading from /dev/kmem, the n_value field is the
	 * seek address, and the contents are read from that address.
	 *
	 * NOTE: when reading from /dev/kmem, the actual, incore
	 * values will be printed, for example: the current nodename
	 * will be printed, etc.
	 *
	 * the cmn line usage is: sysdef -i -n namelist -h -d -D
	 * (-i for incore, though this is now the default, the option
	 * is left in place for SVID compatibility)
	 */
#include	<stdio.h>
#include	<nlist.h>
#include	<string.h>
#include	<sys/types.h>
#include	<sys/sysmacros.h>
#include	<sys/var.h>
#include	<sys/tuneable.h>
#include	<sys/modctl.h>
#include	<sys/fcntl.h>
#include	<sys/utsname.h>
#include	<sys/resource.h>
#include	<sys/conf.h>
#include	<sys/stat.h>
#include	<sys/signal.h>
#include	<sys/priocntl.h>
#include	<sys/procset.h>
#include	<sys/systeminfo.h>
#include	<sys/machelf.h>
#include	<dirent.h>
#include	<ctype.h>
#include	<stdlib.h>
#include	<time.h>
#include	<unistd.h>
#include	<fcntl.h>

#include	<libelf.h>

extern void sysdef_devinfo(void);

static gid_t egid;

#define	SYM_VALUE(sym)	(nl[(sym)].n_value)
#define	MEMSEEK(sym)	memseek(sym)
#define	MEMREAD(var)	fread((char *)&var, sizeof (var), 1, \
				(incore ? memfile : sysfile))

struct	var	v;
struct  tune	tune;

int incore = 1;		/* The default is "incore" */
int bss;		/* if read from file, don't read bss symbols */
int hostidf = 0;	/* 0 == print hostid with other info, */
			/* 1 == print just the hostid */
int devflag = 0;	/* SunOS4.x devinfo compatible output */
int drvname_flag = 0;	/* print the driver name as well as the node */
int nflag = 0;
char	*os = "/dev/ksyms";	/* Wont always have a /kernel/unix */
				/* This wont fully replace it funtionally */
				/* but is a reasonable default/placeholder */

char	*mem = "/dev/kmem";

int	nstrpush;
ssize_t	strmsgsz, strctlsz;
short	ts_maxupri;
char 	sys_name[10];
int	nlsize, lnsize;
FILE	*sysfile, *memfile;

void	setln(char *, int, int, int);
void	getnlist(void);
void	memseek(int);
void	devices(void);
void	sysdev(void);
int	setup(char *);
void	modules(void);

struct nlist	*nl, *nlptr;
int vs, tu, utsnm, bdev, pnstrpush,
    pstrmsgsz, pstrctlsz, endnm,
    pts_maxupri, psys_name, fd_cur, fd_max;

#define	MAXI	300
#define	MAXL	MAXI/11+10
#define	EXPAND	99

struct	link {
	char	*l_cfnm;	/* config name from master table */
	int l_funcidx;		/* index into name list structure */
	unsigned int l_soft :1;	/* software driver flag from master table */
	unsigned int l_dtype:1;	/* set if block device */
	unsigned int l_used :1;	/* set when device entry is printed */
} *ln, *lnptr, *majsrch();

	/* ELF Items */
Elf *elfd = NULL;
Ehdr *ehdr = NULL;

#ifdef _ELF64
#define	elf_getehdr elf64_getehdr
#define	elf_getshdr elf64_getshdr
#else
#define	elf_getehdr elf32_getehdr
#define	elf_getshdr elf32_getshdr
#endif

/* This procedure checks if module "name" is currently loaded */

int
loaded_mod(const char *name)
{
	struct modinfo modinfo;

	/* mi_nextid of -1 means we're getting info on all modules */
	modinfo.mi_id = modinfo.mi_nextid = -1;
	modinfo.mi_info = MI_INFO_ALL;

	while (modctl(MODINFO, modinfo.mi_id, &modinfo) >= 0)
		if (strcmp(modinfo.mi_name, name) == 0)
			return (1);

	return (0);
}

const char *sysv_transition =
	"*\n* IPC %s\n*\n"
	"* The IPC %s module no longer has system-wide limits.\n"
	"* Please see the \"Solaris Tunable Parameters Reference Manual\" for\n"
	"* information on how the old limits map to resource controls and\n"
	"* the prctl(1) and getrctl(2) manual pages for information on\n"
	"* observing the new limits.\n*\n";

const char *sysv_notloaded =
	"*\n* IPC %s module is not loaded\n*\n";

/*
 * Emit a message pointing script writers to the new source for
 * System V IPC information.
 */
void
sysvipc(const char *module, const char *name)
{
	if (loaded_mod(module))
		(void) printf(sysv_transition, name, name);
	else
		(void) printf(sysv_notloaded, name);
}

int
main(int argc, char *argv[])
{
	struct	utsname utsname;
	Elf_Scn *scn;
	Shdr *shdr;
	char *name;
	int ndx;
	int i;
	char hostid[256], *end;
	unsigned long hostval;
	uint_t	rlim_fd_cur, rlim_fd_max;

	egid = getegid();
	setegid(getgid());

	while ((i = getopt(argc, argv, "dihDn:?")) != EOF) {
		switch (i) {
		case 'D':
			drvname_flag++;
			break;
		case 'd':
			devflag++;
			break;
		case 'h':
			hostidf++;
			break;
		case 'i':
			incore++;	/* In case "-i and -n" passed */
			break;		/* Not logical, but not disallowed */
		case 'n':
			nflag = 1;
			incore--;	/* Not incore, use specified file */
			os = optarg;
			break;
		default:
			fprintf(stderr,
				"usage: %s [-D -d -i -h -n namelist]\n",
					argv[0]);
			return (1);
		}
	}

	/*
	 * Prints hostid of machine.
	 */
	if (sysinfo(SI_HW_SERIAL, hostid, sizeof (hostid)) == -1) {
		fprintf(stderr, "hostid: sysinfo failed\n");
		return (1);
	}
	hostval = strtoul(hostid, &end, 10);
	if (hostval == 0 && end == hostid) {
		fprintf(stderr, "hostid: hostid string returned by "
		    "sysinfo not numeric: \"%s\"\n", hostid);
		return (1);
	}
	if (!devflag)
		fprintf(stdout, "*\n* Hostid\n*\n  %8.8x\n", hostval);

	if (hostidf)
		return (0);

	if (((sysfile = fopen(os, "r")) == NULL) && nflag) {
		fprintf(stderr, "cannot open %s\n", os);
		return (1);
	}

	if (sysfile) {
		if (incore) {
			int memfd;

			setegid(egid);
			if ((memfile = fopen(mem, "r")) == NULL) {
				fprintf(stderr, "cannot open %s\n", mem);
				return (1);
			}
			setegid(getgid());

			memfd = fileno(memfile);
			fcntl(memfd, F_SETFD,
			    fcntl(memfd, F_GETFD, 0) | FD_CLOEXEC);
		}

		/*
		 *	Use libelf to read both COFF and ELF namelists
		 */

		if ((elf_version(EV_CURRENT)) == EV_NONE) {
			fprintf(stderr, "ELF Access Library out of date\n");
			return (1);
		}

		if ((elfd = elf_begin(fileno(sysfile), ELF_C_READ,
		    NULL)) == NULL) {
			fprintf(stderr, "Unable to elf begin %s (%s)\n",
				os, elf_errmsg(-1));
			return (1);
		}

		if ((ehdr = elf_getehdr(elfd)) == NULL) {
			fprintf(stderr, "%s: Can't read Exec header (%s)\n",
				os, elf_errmsg(-1));
			return (1);
		}

		if ((((elf_kind(elfd)) != ELF_K_ELF) &&
		    ((elf_kind(elfd)) != ELF_K_COFF)) ||
		    (ehdr->e_type != ET_EXEC)) {
			fprintf(stderr, "%s: invalid file\n", os);
			elf_end(elfd);
			return (1);
		}

		/*
		 *	If this is a file read, look for .bss section
		 */

		if (!incore) {
			ndx = 1;
			scn = NULL;
			while ((scn = elf_nextscn(elfd, scn)) != NULL) {
				if ((shdr = elf_getshdr(scn)) == NULL) {
					fprintf(stderr,
					    "%s: Error reading Shdr (%s)\n",
					    os, elf_errmsg(-1));
					return (1);
				}
				name = elf_strptr(elfd, ehdr->e_shstrndx,
				    (size_t)shdr->sh_name);
				if ((name) && ((strcmp(name, ".bss")) == 0)) {
					bss = ndx;
				}
				ndx++;
			}
		} /* (!incore) */
	}

	uname(&utsname);
	if (!devflag)
		printf("*\n* %s Configuration\n*\n", utsname.machine);

	if (sysfile) {
		nlsize = MAXI;
		lnsize = MAXL;
		nl = (struct nlist *)calloc(nlsize, sizeof (struct nlist));
		ln = (struct link *)calloc(lnsize, sizeof (struct link));
		nlptr = nl;
		lnptr = ln;

		bdev = setup("bdevsw");
		setup("");

		getnlist();

		if (!devflag)
			printf("*\n* Devices\n*\n");
		devices();
		if (devflag)
			return (0);

		printf("*\n* Loadable Objects\n");

		modules();
	}

	printf("*\n* System Configuration\n*\n");

	sysdev();

	if (sysfile) {
		/* easy stuff */
		printf("*\n* Tunable Parameters\n*\n");
		nlptr = nl;
		vs = setup("v");
		tu = setup("tune");
		utsnm = setup("utsname");
		pnstrpush = setup("nstrpush");
		pstrmsgsz = setup("strmsgsz");
		pstrctlsz = setup("strctlsz");
		pts_maxupri = setup("ts_maxupri");
		psys_name = setup("sys_name");
		fd_cur = setup("rlim_fd_cur");
		fd_max = setup("rlim_fd_max");

		/*
		 * This assignment to endnm must follow all calls to setup().
		 */
		endnm = setup("");

		getnlist();

		for (nlptr = &nl[vs]; nlptr != &nl[endnm]; nlptr++) {
			if (nlptr->n_value == 0 &&
			    (incore || nlptr->n_scnum != bss)) {
				fprintf(stderr, "namelist error on <%s>\n",
				    nlptr->n_name);
				/* return (1); */
			}
		}
		if (SYM_VALUE(vs)) {
			MEMSEEK(vs);
			MEMREAD(v);
		}
		printf("%8d	maximum memory allowed in buffer cache "
		    "(bufhwm)\n", v.v_bufhwm * 1024);
		printf("%8d	maximum number of processes (v.v_proc)\n",
		    v.v_proc);
		printf("%8d	maximum global priority in sys class "
		    "(MAXCLSYSPRI)\n", v.v_maxsyspri);
		printf("%8d	maximum processes per user id (v.v_maxup)\n",
		    v.v_maxup);
		printf("%8d	auto update time limit in seconds (NAUTOUP)\n",
		    v.v_autoup);
		if (SYM_VALUE(tu)) {
			MEMSEEK(tu);
			MEMREAD(tune);
		}
		printf("%8d	page stealing low water mark (GPGSLO)\n",
		    tune.t_gpgslo);
		printf("%8d	fsflush run rate (FSFLUSHR)\n",
		    tune.t_fsflushr);
		printf("%8d	minimum resident memory for avoiding "
		    "deadlock (MINARMEM)\n", tune.t_minarmem);
		printf("%8d	minimum swapable memory for avoiding deadlock "
		    "(MINASMEM)\n", tune.t_minasmem);
	}

	printf("*\n* Utsname Tunables\n*\n");
	if (sysfile && SYM_VALUE(utsnm)) {
		MEMSEEK(utsnm);
		MEMREAD(utsname);
	}
	printf("%8s  release (REL)\n", utsname.release);
	printf("%8s  node name (NODE)\n", utsname.nodename);
	printf("%8s  system name (SYS)\n", utsname.sysname);
	printf("%8s  version (VER)\n", utsname.version);

	if (sysfile) {
		printf("*\n* Process Resource Limit Tunables "
		    "(Current:Maximum)\n*\n");
		if (SYM_VALUE(fd_cur)) {
			MEMSEEK(fd_cur);
			MEMREAD(rlim_fd_cur);
		}
		if (SYM_VALUE(fd_max)) {
			MEMSEEK(fd_max);
			MEMREAD(rlim_fd_max);
		}

		printf("0x%16.16x:", rlim_fd_cur);
		printf("0x%16.16x", rlim_fd_max);
		printf("\tfile descriptors\n");

		printf("*\n* Streams Tunables\n*\n");
		if (SYM_VALUE(pnstrpush)) {
			MEMSEEK(pnstrpush);	MEMREAD(nstrpush);
			printf("%6d	maximum number of pushes allowed "
			    "(NSTRPUSH)\n", nstrpush);
		}
		if (SYM_VALUE(pstrmsgsz)) {
			MEMSEEK(pstrmsgsz);	MEMREAD(strmsgsz);
			printf("%6ld	maximum stream message size "
			    "(STRMSGSZ)\n", strmsgsz);
		}
		if (SYM_VALUE(pstrctlsz)) {
			MEMSEEK(pstrctlsz);	MEMREAD(strctlsz);
			printf("%6ld	max size of ctl part of message "
			    "(STRCTLSZ)\n", strctlsz);
		}
	}

	sysvipc("msgsys", "Messages");
	sysvipc("semsys", "Semaphores");
	sysvipc("shmsys", "Shared Memory");

	if (sysfile) {
		if (SYM_VALUE(pts_maxupri)) {
			printf("*\n* Time Sharing Scheduler Tunables\n*\n");
			MEMSEEK(pts_maxupri);	MEMREAD(ts_maxupri);
			printf("%d	maximum time sharing user "
			    "priority (TSMAXUPRI)\n", ts_maxupri);
		}

		if (SYM_VALUE(psys_name)) {
			MEMSEEK(psys_name);	MEMREAD(sys_name);
			printf("%s	system class name (SYS_NAME)\n",
			    sys_name);
		}

		if (elfd)
			elf_end(elfd);
	}
	return (0);
}

/*
 * setup - add an entry to a namelist structure array
 */
int
setup(char *nam)
{
	int idx;

	if (nlptr >= &nl[nlsize]) {
		if ((nl = (struct nlist *)realloc(nl,
		    (nlsize + EXPAND) * sizeof (struct nlist))) == NULL) {
			fprintf(stderr, "Namelist space allocation failed\n");
			exit(1);
		}
		nlptr = &nl[nlsize];
		nlsize += EXPAND;
	}

	nlptr->n_name = malloc(strlen(nam) + 1); /* pointer to next string */
	strcpy(nlptr->n_name, nam);	/* move name into string table */
	nlptr->n_type = 0;
	nlptr->n_value = 0;
	idx = nlptr++ - nl;
	return (idx);
}

/*
 * Handle the configured devices
 */
void
devices(void)
{
	setegid(egid);
	sysdef_devinfo();
	setegid(getgid());
}

char	*LS_MODULES = "/bin/ls -R -p -i -1 ";
char	*MODULES_TMPFILE = "/tmp/sysdef.sort.XXXXXX";

void
modules()
{
	int i;
	int n_dirs = 0;
	ino_t *inodes;
	char *curr, *next;
	char **dirs;
	char *modpath, *ls_cmd;
	char *tmpf;
	int curr_len, modpathlen;
	int ls_cmd_len = strlen(LS_MODULES);
	int sfd;

	if ((modctl(MODGETPATHLEN, NULL, &modpathlen)) != 0) {
		fprintf(stderr, "sysdef: fail to get module path length\n");
		exit(1);
	}
	if ((modpath = malloc(modpathlen + 1)) == NULL) {
		fprintf(stderr, "sysdef: malloc failed\n");
		exit(1);
	}
	if (modctl(MODGETPATH, NULL, modpath) != 0) {
		fprintf(stderr, "sysdef: fail to get module path\n");
		exit(1);
	}

	/*
	 * Figure out number of directory entries in modpath.
	 * Module paths are stored in a space separated string
	 */
	curr = modpath;
	while (curr) {
		n_dirs++;
		curr = strchr(curr + 1, ' ');
	}

	if (((inodes = (ino_t *)malloc(n_dirs * sizeof (ino_t))) == NULL) ||
	    ((dirs = (char **)malloc(n_dirs * sizeof (char *))) == NULL)) {
		fprintf(stderr, "sysdef: malloc failed\n");
		exit(1);
	}

	if ((tmpf = malloc(strlen(MODULES_TMPFILE) + 1)) == NULL) {
		fprintf(stderr, "sysdef: malloc failed\n");
		exit(1);
	}

	curr = modpath;
	for (i = 0; i < n_dirs; i++) {
		int j, len, inode, ino;
		char line[100], path[100], *pathptr = "";
		char srtbuf[100], *sorted_fname;
		FILE *lspipe, *srtpipe, *fp;
		struct stat stat_buf;

		if (next = strchr(curr, ' ')) {
			*next = '\0';
		}

		/*
		 * Make sure the module path is present.
		 */
		if (stat(curr, &stat_buf) == -1) {
			curr = next ? next + 1 : NULL;
			inodes[i] = (ino_t)-1;
			continue;
		}

		/*
		 * On sparcs, /platform/SUNW,... can be symbolic link to
		 * /platform/sun4x. We check the inode number of directory
		 * and skip any duplication.
		 */
		dirs[i] = curr;
		inodes[i] = stat_buf.st_ino;

		for (j = 0; inodes[i] != inodes[j]; j++)
			;
		if (j != i) {
			curr = next ? next + 1 : NULL;
			continue;
		}

		printf("*\n* Loadable Object Path = %s\n*\n", curr);

		curr_len = strlen(curr);
		if ((ls_cmd = malloc(ls_cmd_len + curr_len + 1)) == NULL) {
			fprintf(stderr, "sysdef: malloc failed\n");
			exit(1);
		}

		(void) sprintf(ls_cmd, "%s%s", LS_MODULES, curr);

		/*
		 * List the loadable objects in the directory tree, sorting
		 * them by inode so as to note any hard links.  A temporary
		 * file in /tmp  is used to store output from sort before
		 * listing.
		 */
		if ((lspipe = popen(ls_cmd, "r")) == NULL) {
			fprintf(stderr, "sysdef: cannot open ls pipe\n");
			exit(1);
		}
		free(ls_cmd);

		(void) strcpy(tmpf, MODULES_TMPFILE);
		if ((sorted_fname = mktemp(tmpf)) == NULL ||
		    (strcmp(sorted_fname, "") == 0)) {
			fprintf(stderr,
			    "sysdef: cannot create unique tmp file name\n");
			exit(1);
		}

		if ((sfd = open(sorted_fname, O_RDWR|O_CREAT|O_EXCL,
		    0600)) == -1) {
			fprintf(stderr, "sysdef: cannot open %s\n",
			    sorted_fname);
			exit(1);
		}

		sprintf(srtbuf, "/bin/sort - > %s", sorted_fname);
		if ((srtpipe = popen(srtbuf, "w")) == NULL) {
			fprintf(stderr, "sysdef: cannot open sort pipe\n");
			exit(1);
		}

		while (fgets(line, 99, lspipe) != NULL) {
			char *tmp;
			/*
			 * 'line' has <cr>, skip blank lines & dir entries
			 */
			if (((len = strlen(line)) <= 1) ||
			    (line[len-2] == '/'))
				continue;

			/* remember path of each subdirectory */

			if (line[0] == '/') {
				(void) strcpy(path, &line[curr_len]);
				tmp = strtok(&path[1], ":");
				if ((tmp == NULL) || (tmp[0] == '\n')) {
					continue;
				}
				pathptr = &path[1];
				(void) strcat(pathptr, "/");
				continue;
			} else {
				char *tmp1 = strtok(line, " ");
				tmp = strtok(NULL, "\n");
				/*
				 * eliminate .conf file
				 */
				if (strstr(tmp, ".conf")) {
					continue;
				}
				/*
				 * Printing the (inode, path, module)
				 * ripple.
				 */
				fprintf(srtpipe, "%s %s%s\n",
				    tmp1, pathptr, tmp);
			}
		}
		(void) pclose(lspipe);
		(void) pclose(srtpipe);

		/*
		 * A note on data synchronization. We opened sfd above,
		 * before calling popen, to ensure that the tempfile
		 * was created exclusively to prevent a malicious user
		 * from creating a link in /tmp to make us overwrite
		 * another file. We have never read from sfd, there
		 * can be no stale data cached anywhere.
		 */
		if ((fp = fdopen(sfd, "r")) == NULL) {
			fprintf(stderr, "sysdef: cannot open sorted file: %s",
			    sorted_fname);
			exit(1);
		}
		inode = -1;
		while (fgets(line, 99, fp) != NULL) {

			sscanf(line, "%d %s",  &ino, path);
			if (ino == inode)
				printf("\thard link:  ");
			printf("%s\n", path);
			inode = ino;
		}
		(void) fclose(fp);
		(void) unlink(sorted_fname);
		curr = next ? next + 1 : NULL;
	}
	free(tmpf);
	free(modpath);
}

void
sysdev(void)
{
	printf("  swap files\n");
	fflush(stdout);
	if (system("/usr/sbin/swap -l") < 0)
		fprintf(stderr, "unknown swap file(s)\n");
}

void
memseek(int sym)
{
	Elf_Scn *scn;
	Shdr *eshdr;
	long eoff;

	if (incore) {
		if ((fseek(memfile, nl[sym].n_value, 0)) != 0) {
			fprintf(stderr, "%s: fseek error (in memseek)\n", mem);
			exit(1);
		}
	} else {
		if ((scn = elf_getscn(elfd, nl[sym].n_scnum)) == NULL) {
			fprintf(stderr, "%s: Error reading Scn %d (%s)\n",
				os, nl[sym].n_scnum, elf_errmsg(-1));
			exit(1);
		}

		if ((eshdr = elf_getshdr(scn)) == NULL) {
			fprintf(stderr, "%s: Error reading Shdr %d (%s)\n",
				os, nl[sym].n_scnum, elf_errmsg(-1));
			exit(1);
		}

		eoff = (long)(nl[sym].n_value - eshdr->sh_addr +
		    eshdr->sh_offset);

		if ((fseek(sysfile, eoff, 0)) != 0) {
			fprintf(stderr, "%s: fseek error (in memseek)\n", os);
			exit(1);
		}
	}
}

/*
 * filter out bss symbols if the reads are from the file
 */
void
getnlist(void)
{
	struct nlist *p;

	nlist(os, nl);

	/*
	 * The nlist is done. If any symbol is a bss
	 * and we are not reading from incore, zero
	 * the n_value field. (Won't be printed if
	 * n_value == 0.)
	 */
	if (!incore) {
		for (p = nl; p->n_name && p->n_name[0]; p++) {
			if (p->n_scnum == bss) {
				p->n_value = 0;
			}
		}
	}
}
