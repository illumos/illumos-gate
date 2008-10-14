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

#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <values.h>
#include <locale.h>
#include <langinfo.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <strings.h>
#include <stdarg.h>
#include <ctype.h>
#include <math.h>
#include <sys/param.h>
#include <sys/mnttab.h>
#include <nsctl.h>
#include <netdb.h>
#include <search.h>

#include <sys/nsctl/cfg.h>
#include <sys/nsctl/nsc_hash.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_errors.h>
#include <sys/nsctl/dsw.h>
#include <sys/nsctl/dsw_dev.h>		/* for bit map header format */

#include <sys/nskernd.h>

typedef struct mstcount_s {
	int count;
} mstcount_t;
typedef struct shdvol_s {
	char master[ DSW_NAMELEN ];
} shdvol_t;
typedef struct grptag_s {
	char ctag[ DSW_NAMELEN ];
} grptag_t;
hash_node_t **volhash = NULL;

#define	DSW_TEXT_DOMAIN	"II"

#include <dlfcn.h>
#define	RDC_LIB "/usr/lib/librdc.so.1"
static int (*self_check)(char *);

/*
 * Support for the special cluster tag "local" to be used with -C in a
 * cluster for local volumes.
 */
#define	II_LOCAL_TAG	"local"

#define	II_NOT_CLUSTER	1
#define	II_CLUSTER	2
#define	II_CLUSTER_LCL	3

static char *cfg_cluster_tag = NULL;
static CFGFILE *cfg = NULL;

void sigterm(int sig);

#define	SD_BIT_CLR(bmap, bit)		(bmap &= ~(1 << bit))
#define	SD_BIT_ISSET(bmap, bit)		((bmap & (1 << bit)) != 0)

#define	MAX_LINE_SIZE 256	/* maximum characters per line in config file */
#define	MAX_GROUPS 1024		/* maximum number of groups to support */
#define	MAX_CLUSTERS 1024	/* maximum number of resource groups */

unsigned long	bm_size;		/* size in bytes of bitmap */
unsigned long	bm_actual;		/* original number of bits in bitmap */
int	debug = 0;

int	dsw_fd;

#define	LD_II		0x00000001
#define	LD_DSVOLS	0x00000002
#define	LD_SVOLS	0x00000004
#define	LD_SHADOWS	0x00000008

static int reload_vols = 0;
static int config_locked = 0;
static int last_lock;

/*
 * names for do_copy() flags.
 */

enum	copy_update {Copy = 0, Update};
enum	copy_direction {ToShadow = 0, ToMaster};
enum	copy_wait {WaitForStart = 0, WaitForEnd};

char	*cmdnam;

unsigned char	*allocate_bitmap(char *);
void		usage(char *);
void		enable(char *, char *, char *, char *);
int		disable(char *);
void		bitmap_op(char *, int, int, int, int);
void		print_status(dsw_config_t *, int);
int		abort_copy(char *);
int		reset(char *);
int		overflow(char *);
void		iiversion(void);
int		wait_for_copy(char *);
int		export(char *);
void		list_volumes(void);
void		dsw_error(char *, spcs_s_info_t *);
void		InitEnv();
static void	check_dg_is_local(char *dgname);
static int	check_resource_group(char *volume);
static int	check_diskgroup(char *path, char *result);
static int	check_cluster();
static void	unload_ii_vols();
static void	load_ii_vols(CFGFILE *);
static int	perform_autosv();
static int	is_exported(char *);
static void	conform_name(char **);
static void	do_attach(dsw_config_t *);
static int	ii_lock(CFGFILE *, int);
static void	verify_groupname(char *grp, int testDash);

void	dsw_list_clusters(char *);
void	dsw_enable(int, char **);
void	dsw_disable(int, char **);
void	dsw_copy_to_shadow(int, char **);
void	dsw_update_shadow(int, char **);
void	dsw_copy_to_master(int, char **);
void	dsw_update_master(int, char **);
void	dsw_abort_copy(int, char **);
void	dsw_display_status(int, char **);
void	dsw_display_bitmap(int, char **);
void	dsw_reset(int, char **);
void	dsw_overflow(int, char **);
void	dsw_version(int, char **);
void	dsw_wait(int, char **);
void	dsw_list_volumes(int, char **);
void	dsw_list_group_volumes();
void	dsw_export(int, char **);
void	dsw_import(int, char **);
void	dsw_join(int, char **);
void	dsw_attach(int, char **);
void	dsw_detach(int, char **);
void	dsw_params(int, char **);
void	dsw_olist(int, char **);
void	dsw_ostat(int, char **);
void	dsw_move_2_group(int, char **);
void	dsw_list_groups();
void	check_iishadow(char *);

extern char *optarg;
extern int optind, opterr, optopt;

int	Aflg;
int	Cflg;
int	CLflg;
int	Dflg;
int	Eflg;
int	Iflg;
int	Jflg;
int	Lflg;
int	Oflg;
int	Pflg;
int	Qflg;
int	Rflg;
int	aflg;
int	bflg;
int	cflg;
int	dflg;
int	eflg;
int	fflg;
int	gflg;
int	gLflg;
int	hflg;
int	iflg;
int	lflg;
int	mflg;
int	nflg;
int	pflg;
int	uflg;
int	vflg;
int	wflg;

int	errflg;
#ifdef DEBUG
const char single_opts[] =
	"a:b:c:d:e:f:g:hilmnpu:vw:A:C:D:E:I:J:LO:PQ:R:";
#else
/* no b or f flags */
const char single_opts[] = "a:c:d:e:g:hilmnpu:vw:A:C:D:E:I:J:LO:PQ:R:";
#endif
const char group_opts[] = "ac:de:ilmnpu:wA:C:DELPR";
const char *opt_list = single_opts;

char	buf[CFG_MAX_BUF];
char	key[CFG_MAX_KEY];
char	last_overflow[DSW_NAMELEN];
int	setnumber;
char	*group_name;
char	**group_volumes;
enum copy_direction direction;
char	*param_delay, *param_unit;
char	*overflow_file;

#ifdef lint
int
iiadm_lintmain(int argc, char *argv[])
#else
int
main(int argc, char *argv[])
#endif
{
	int c;
	int actions = 0;
	int ac;
	char *av[1024];

	InitEnv();

	memset(av, 0, sizeof (av));
	cmdnam = argv[0];
	while ((c = getopt(argc, argv, opt_list)) != EOF)
		switch (c) {
		case 'c':
			cflg++;
			actions++;
			if (strcmp(optarg, "m") == 0) {
				av[0] = "copy_to_master";
				direction = ToMaster;
			} else if (strcmp(optarg, "s") == 0) {
				av[0] = "copy_to_shadow";
				direction = ToShadow;
			} else {
				errflg ++;
				usage(gettext(
					"must specify m or s with -c"));
			}
			ac = 2;
			break;
		case 'd':
			dflg++;
			actions++;
			av[0] = "disable";
			av[1] = optarg;
			ac = 2;
			break;
		case 'e':
			eflg++;
			actions++;
			av[0] = "enable";
			if (strcmp(optarg, "ind") == 0)
				av[4] = "independent";
			else if (strcmp(optarg, "dep") == 0)
				av[4] = "dependent";
			else {
				errflg ++;
				usage(gettext(
					"must specify ind or dep with -e"));
			}
			ac = 1;
			break;
		case 'g':
			gflg++;
			opt_list = group_opts;
			group_name = optarg;
			if (group_name && *group_name == '-') {
				gLflg = (strcmp("-L", group_name) == 0);
				if (gLflg)
					actions++;
			}
			verify_groupname(group_name, !gLflg);
			break;
		case 'h':
			hflg++;
			actions++;
			break;
		case 'u':
			uflg++;
			actions++;
			if (strcmp(optarg, "m") == 0) {
				av[0] = "update_master";
				direction = ToMaster;
			} else if (strcmp(optarg, "s") == 0) {
				av[0] = "update_shadow";
				direction = ToShadow;
			} else {
				errflg ++;
				usage(gettext(
					"must specify m or s with -u"));
			}
			ac = 2;
			break;
		case 'i':
			iflg++;
			actions++;
			av[0] = "display_status";
			break;
		case 'l':
			lflg++;
			actions++;
			av[0] = "list_config";
			ac = 1;
			break;
		case 'm':
			mflg++;
			actions++;
			av[0] = "move_to_group";
			ac = 1;
			break;
		case 'n':
			nflg++;
			break;
		case 'p':
			pflg++;
			break;
		case 'b':
			bflg++;
			actions++;
			av[0] = "display_bitmap";
			av[1] = optarg;
			ac = 2;
			break;
		case 'a':
			aflg++;
			actions++;
			av[0] = "abort_copy";
			av[1] = optarg;
			ac = 2;
			break;
		case 'v':
			vflg++;
			actions++;
			av[1] = "version";
			ac = 1;
			break;
		case 'w':
			wflg++;
			actions++;
			av[0] = "wait";
			av[1] = optarg;
			ac = 2;
			break;
		case 'A':
			Aflg++;
			actions++;
			av[0] = "attach";
			av[1] = optarg;
			ac = 2;
			break;
		case 'C':
			Cflg++;
			cfg_cluster_tag = optarg;
			if (cfg_cluster_tag && *cfg_cluster_tag == '-') {
				CLflg = (strcmp("-L", cfg_cluster_tag) == 0);
				if (CLflg)
					actions++;
			}
			break;
		case 'D':
			Dflg++;
			actions++;
			av[0] = "detach";
			av[1] = optarg;
			ac = 2;
			break;
		case 'O':
			Oflg++;
			actions++;
			av[0] = "overflow";
			av[1] = optarg;
			ac = 2;
			break;
		case 'R':
			Rflg++;
			actions++;
			av[0] = "reset";
			av[1] = optarg;
			ac = 2;
			break;
		case 'E':
			Eflg++;
			actions++;
			av[0] = "export";
			av[1] = optarg;
			ac = 2;
			break;
		case 'I':
			Iflg++;
			actions++;
			av[0] = "import";
			av[1] = optarg;
			ac = 2;
			break;
		case 'J':
			Jflg++;
			actions++;
			av[0] = "join";
			av[1] = optarg;
			ac = 2;
			break;
		case 'P':
			Pflg++;
			actions++;
			av[0] = "parameter";
			ac = 1;
			break;
		case 'L':
			Lflg++;
			actions++;
			/* If -g group -L, force error */
			if (group_name) actions++;
			av[0] = "LIST";
			ac = 1;
			break;
		case 'Q':
			Qflg++;
			actions++;
			av[0] = "query";
			av[1] = optarg;
			ac = 2;
			break;
		case '?':
			errflg++;
			break;
		}
	if (hflg) {
		usage(NULL);
		exit(0);
		}

	if (errflg)
		usage(gettext("unrecognized argument"));
	switch (actions) {
		case 0:
			if (argc > 1)
				usage(gettext("must specify an action flag"));

			/* default behavior is to list configuration */
			lflg++; av[0] = "list_config"; ac = 1;
			break;
		case 1:
			break;
		default:
			usage(gettext("too many action flags"));
			break;
	}

	if (gflg && (Iflg || Jflg || Oflg || Qflg))
		usage(gettext("can't use a group with this option"));
	if (!gflg && (mflg))
		usage(gettext("must use a group with this option"));

	/*
	 * Open configuration file.
	 */
	if ((cfg = cfg_open(NULL)) == NULL) {
		perror("unable to access configuration");
		exit(2);
	}

	/*
	 * Set write locking (CFG_WRLOCK) for:
	 *	iiadm -e (enable)
	 * 	iiadm -d (disable)
	 *	iiadm -A (attach overflow)
	 *	iiadm -D (detach overflow)
	 *	iiadm -g grp -m volume (move volume into group)
	 *	iiadm -E (export shadow [needs to update dsvol section])
	 *	iiadm -I (import shadow [ditto])
	 *	iiadm -J (join shadow [ditto])
	 * read locking (CFG_RDLOCK) for all other commands
	 */
	last_lock = (eflg || dflg || mflg || Aflg || Dflg || Eflg || Iflg ||
	    Jflg)? CFG_WRLOCK : CFG_RDLOCK;
	if (!cfg_lock(cfg, last_lock)) {
		perror("unable to lock configuration");
		exit(2);
	}
	config_locked = 1;

	/*
	 * If we are in a cluster, set or derive a valid disk group
	 */
	switch (check_cluster()) {
	case II_CLUSTER:
		/*
		 * If in a Sun Cluster, can't Import an II shadow
		 * Must be done as -C local
		 */
		if (Iflg)
			dsw_error(gettext(
				"-I (import) only allowed as -C local"), NULL);
		/*FALLTHRU*/
	case II_CLUSTER_LCL:
		/*
		 * If a cluster tag was specified or derived, set it
		 */
		if (CLflg) {
			dsw_list_clusters(argv[optind]);
			cfg_close(cfg);
			exit(0);
		} else {
			cfg_resource(cfg, cfg_cluster_tag);
		}
		break;
	case II_NOT_CLUSTER:
		if (cfg_cluster_tag != NULL)
			dsw_error(gettext(
			    "-C is valid only in a Sun Cluster"), NULL);
		break;
	default:
		dsw_error(gettext(
		    "Unexpected return from check_cluster()"), NULL);
	}

	/* preload the ii config */
	load_ii_vols(cfg);
	reload_vols |= LD_II;

	if (eflg) {
		if (argc - optind != 3)
			usage(gettext("must specify 3 volumes with -e"));
		av[1] = argv[optind++];
		av[2] = argv[optind++];
		av[3] = argv[optind++];
		ac = 5;
		dsw_enable(ac, av);
	} else if (dflg) {
		dsw_disable(ac, av);
	} else if (uflg) {
		if (argv[optind] == NULL && group_name == NULL)
			usage(gettext("must specify volume with -u"));
		for (c = 1; argv[optind] != NULL; optind++)
			av[c++] = argv[optind];
		av[c] = NULL;

		if (direction == ToMaster)
			dsw_update_master(ac, av);
		else
			dsw_update_shadow(ac, av);
	} else if (iflg) {
		if (argv[optind]) {
			av[1] = argv[optind];
			ac = 2;
		} else
			ac = 1;
		dsw_display_status(ac, av);
	} else if (bflg) {
		dsw_display_bitmap(ac, av);
	} else if (cflg) {
		if (argv[optind] == NULL && group_name == NULL)
			usage(gettext("must specify volume with -c"));
		for (c = 1; argv[optind] != NULL; optind++)
			av[c++] = argv[optind];
		av[c] = NULL;

		if (direction == ToMaster)
			dsw_copy_to_master(ac, av);
		else
			dsw_copy_to_shadow(ac, av);
	} else if (aflg) {
		dsw_abort_copy(ac, av);
	} else if (Eflg) {
		dsw_export(ac, av);
	} else if (Iflg) {
		if (argc - optind != 1)
			usage(gettext("must specify 2 volumes with -I"));
		av[2] = argv[optind++];
		ac = 3;
		dsw_import(ac, av);
	} else if (Aflg) {
		if (group_name) {
			if (argc - optind != 0)
				usage(gettext("must specify overflow volume " \
				"when using groups with -A"));
			ac = 2;
		} else {
			if (argc - optind != 1)
				usage(gettext("specify 2 volumes with -A"));
			ac = 3;
			av[2] = argv[optind++];
		}
		dsw_attach(ac, av);
	} else if (Dflg) {
		dsw_detach(ac, av);
	} else if (Jflg) {
		if (argc - optind != 1)
			usage(gettext("must specify 2 volumes with -J"));
		av[2] = argv[optind++];
		ac = 3;
		dsw_join(ac, av);
	} else if (Pflg) {
		if (argc - optind == ((group_name) ? 0 : 1)) {
			av[1] = argv[optind++];
			ac = (group_name) ? 0 : 2;
		} else if (argc - optind == ((group_name) ? 2 : 3)) {
			av[1] = argv[optind++];
			av[2] = argv[optind++];
			av[3] = argv[optind++];
			ac = (group_name) ? 2 : 4;
		} else
			usage(gettext(
				"must specify delay, unit and shadow with -P"));
		dsw_params(ac, av);
	} else if (Oflg) {
		dsw_overflow(ac, av);
	} else if (Rflg) {
		dsw_reset(ac, av);
	} else if (vflg) {
		dsw_version(ac, av);
	} else if (wflg) {
		dsw_wait(ac, av);
	} else if (lflg) {
		if ((gflg) && (!group_name))
			dsw_list_group_volumes();
		else
			dsw_list_volumes(ac, av);
	} else if (Lflg) {
		dsw_olist(ac, av);
	} else if (gLflg) {
		dsw_list_groups();
	} else if (Qflg) {
		dsw_ostat(ac, av);
	} else if (mflg) {
		if (argc - optind < 1)
			usage(gettext("must specify one or more volumes"));
		for (c = 1; argv[optind] != NULL; optind++)
			av[c++] = argv[optind];
		av[c] = NULL;
		dsw_move_2_group(ac, av);
	}
	if (cfg)
		cfg_close(cfg);

	exit(0);
	return (0);
}

static int
ii_lock(CFGFILE *cfg, int locktype)
{
	last_lock = locktype;
	return (cfg_lock(cfg, locktype));
}

static int
do_ioctl(int fd, int cmd, void *arg)
{
	int unlocked = 0;
	int rc;
	int save_errno;

	if (config_locked) {
		switch (cmd) {
		case DSWIOC_ENABLE:
		case DSWIOC_RESUME:
		case DSWIOC_SUSPEND:
		case DSWIOC_COPY:
		case DSWIOC_BITMAP:
		case DSWIOC_DISABLE:
		case DSWIOC_SHUTDOWN:
		case DSWIOC_ABORT:
		case DSWIOC_RESET:
		case DSWIOC_OFFLINE:
		case DSWIOC_WAIT:
		case DSWIOC_ACOPY:
		case DSWIOC_EXPORT:
		case DSWIOC_IMPORT:
		case DSWIOC_JOIN:
		case DSWIOC_COPYP:
		case DSWIOC_OATTACH:
		case DSWIOC_ODETACH:
		case DSWIOC_SBITSSET:
		case DSWIOC_CBITSSET:
		case DSWIOC_SEGMENT:
		case DSWIOC_MOVEGRP:
		case DSWIOC_CHANGETAG:
			cfg_unlock(cfg);
			unlocked = 1;
			break;

		case DSWIOC_STAT:
		case DSWIOC_VERSION:
		case DSWIOC_LIST:
		case DSWIOC_OCREAT:
		case DSWIOC_OLIST:
		case DSWIOC_OSTAT:
		case DSWIOC_OSTAT2:
		case DSWIOC_LISTLEN:
		case DSWIOC_OLISTLEN:
		case DSWIOC_CLIST:
		case DSWIOC_GLIST:
			break;

		default:
			fprintf(stderr,
			    "cfg locking needs to be set for %08x\n", cmd);
			exit(1);
			break;
		}
	}
	if (unlocked) {
		/* unload vol hashes */
		if (reload_vols & LD_II)
			unload_ii_vols();
		if (reload_vols & LD_SHADOWS)
			cfg_unload_shadows();
		if (reload_vols & LD_DSVOLS)
			cfg_unload_dsvols();
		if (reload_vols & LD_SVOLS)
			cfg_unload_svols();
	}
	rc = ioctl(fd, cmd, arg);
	save_errno = errno;
	if (config_locked && unlocked) {
		cfg_lock(cfg, last_lock);
	}
	if (unlocked) {
		/* reload vol hashes */
		if (reload_vols & LD_SVOLS)
			cfg_load_svols(cfg);
		if (reload_vols & LD_DSVOLS)
			cfg_load_dsvols(cfg);
		if (reload_vols & LD_SHADOWS)
			cfg_load_shadows(cfg);
		if (reload_vols & LD_II)
			load_ii_vols(cfg);
	}

	errno = save_errno;
	return (rc);
}

static int
get_dsw_config(int setno, dsw_config_t *parms)
{
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];

	bzero(parms, sizeof (dsw_config_t));
	(void) snprintf(key, sizeof (key), "ii.set%d.master", setno);
	if (cfg_get_cstring(cfg, key, parms->master_vol, DSW_NAMELEN) < 0)
		return (-1);

	(void) snprintf(key, sizeof (key), "ii.set%d.shadow", setno);
	(void) cfg_get_cstring(cfg, key, parms->shadow_vol, DSW_NAMELEN);

	(void) snprintf(key, sizeof (key), "ii.set%d.bitmap", setno);
	(void) cfg_get_cstring(cfg, key, parms->bitmap_vol, DSW_NAMELEN);

	(void) snprintf(key, sizeof (key), "ii.set%d.mode", setno);
	(void) cfg_get_cstring(cfg, key, buf, sizeof (buf));
	if (strcmp(buf, "I") == 0)
		parms->flag |= DSW_GOLDEN;

	(void) snprintf(key, sizeof (key), "ii.set%d.overflow", setno);
	(void) cfg_get_cstring(cfg, key, last_overflow, DSW_NAMELEN);

	(void) snprintf(key, sizeof (key), "ii.set%d.group", setno);
	(void) cfg_get_cstring(cfg, key, parms->group_name, DSW_NAMELEN);

	(void) snprintf(key, sizeof (key), "ii.set%d.cnode", setno);
	(void) cfg_get_cstring(cfg, key, parms->cluster_tag, DSW_NAMELEN);
	return (0);
}

static int
find_next_cf_line(char *volume, int next)
{
	dsw_config_t cf_line;

	for (setnumber = next; get_dsw_config(setnumber, &cf_line) == 0;
								setnumber++) {
		if (strncmp(volume, cf_line.master_vol, DSW_NAMELEN) == 0 ||
		    strncmp(volume, cf_line.shadow_vol, DSW_NAMELEN) == 0 ||
		    strncmp(volume, cf_line.bitmap_vol, DSW_NAMELEN) == 0)
			return (1);
	}
	return (0);
}
int
find_any_cf_line(char *volume)
{
	return (find_next_cf_line(volume, 1));
}

static int
find_next_shadow_line(char *volume, int next)
{
	dsw_config_t cf_line;

	for (setnumber = next; get_dsw_config(setnumber, &cf_line) == 0;
	    setnumber++) {
		if (strncmp(volume, cf_line.shadow_vol, DSW_NAMELEN) == 0)
			return (1);
	}
	return (0);
}
int
find_shadow_line(char *volume)
{
	return (find_next_shadow_line(volume, 1));
}

/*
 * this function is designed to be called once, subsequent calls won't
 * free memory allocated by earlier invocations.
 */
char *
get_overflow_list()
{
	dsw_aioctl_t *acopy_args;
	int rc, num;

	num = do_ioctl(dsw_fd, DSWIOC_OLISTLEN, NULL);
	if (num < 0)
		dsw_error(gettext("Can't get overflow list length"), NULL);

	acopy_args = malloc(sizeof (dsw_aioctl_t) + num * DSW_NAMELEN);
	if (acopy_args == NULL)
		dsw_error(gettext("Can't get memory for list enquiry"), NULL);

	acopy_args->count = num;
	acopy_args->flags = 0;
	acopy_args->status = spcs_s_ucreate();

	rc = do_ioctl(dsw_fd, DSWIOC_OLIST, acopy_args);
	if (rc == -1)
		dsw_error(gettext("Overflow list access failure"),
			&acopy_args->status);
	else
		acopy_args->shadow_vol[DSW_NAMELEN*acopy_args->count] = NULL;

	return (acopy_args->shadow_vol);
}

/*
 * this function is designed to be called once, subsequent calls won't
 * free memory allocated by earlier invocations.
 */

int
find_group_members(char *group)
{
	int nmembers = 0;
	int vector_len = 0;

	group_volumes = NULL;
	for (setnumber = 1; /*CSTYLED*/; setnumber++) {
		(void) snprintf(key, sizeof (key), "ii.set%d.group", setnumber);
		if (cfg_get_cstring(cfg, key, buf,
					sizeof (buf)) < 0)
			break;

		if (strcmp(group, buf))
			continue;

		(void) snprintf(key, sizeof (key), "ii.set%d.shadow",
		    setnumber);
		if (cfg_get_cstring(cfg, key, buf,
					sizeof (buf)) < 0)
			break;

		if (nmembers >= vector_len) {
			vector_len += 10;
			group_volumes = realloc(group_volumes, (1+vector_len) *
					sizeof (char *));
		}
		group_volumes[nmembers] = strdup(buf);
		nmembers++;
	}
	if (group_volumes)
		group_volumes[nmembers] = NULL;	/* terminate list */
	return (nmembers);
}

static int
find_next_matching_cf_line(
	char *volume, dsw_config_t *conf, dsw_ioctl_t *io, int next)
{
	dsw_config_t config;

	if (!find_next_cf_line(volume, next)) {
		return (0);
	}

	if (conf == NULL)
		conf = &config;
	(void) get_dsw_config(setnumber, conf);
	if (io) {
		strncpy(io->shadow_vol, conf->shadow_vol, DSW_NAMELEN);
		io->shadow_vol[DSW_NAMELEN] = '\0';
	}
	return (1);
}

int
find_matching_cf_line(char *volume, dsw_config_t *conf, dsw_ioctl_t *io)
{
	return (find_next_matching_cf_line(volume, conf, io, 1));
}

int
find_shadow_config(char *volume, dsw_config_t *conf, dsw_ioctl_t *io)
{
	dsw_config_t *c, cf;

	if (io) {
		bzero(io, sizeof (dsw_ioctl_t));
	}
	c = conf ? conf : &cf;
	setnumber = 1;
	/* perform action for each line of the stored config file */
	for ((void) snprintf(key, sizeof (key), "ii.set%d.shadow", setnumber);
	    cfg_get_cstring(cfg, key, c->shadow_vol, DSW_NAMELEN) >= 0;
	    (void) snprintf(key, sizeof (key), "ii.set%d.shadow",
	    ++setnumber)) {
		if (strncmp(volume, c->shadow_vol, DSW_NAMELEN) == 0) {
			(void) get_dsw_config(setnumber, c);

			if (check_resource_group(c->bitmap_vol)) {
				setnumber = 0;
				continue;
			}

			switch (check_cluster()) {
			case II_CLUSTER:
				if ((cfg_cluster_tag) &&
				    (strcmp(cfg_cluster_tag, c->cluster_tag)))
					continue;
				break;
			case II_CLUSTER_LCL:
				if (strlen(c->cluster_tag))
					continue;
				break;
			}

			if (io) {
				strncpy(io->shadow_vol, c->shadow_vol,
								DSW_NAMELEN);
				io->shadow_vol[DSW_NAMELEN] = '\0';
			}
			return (1);
		}
	}
	return (0);
}

void
add_cfg_entry(dsw_config_t *parms)
{
	/* insert the well-known fields first */
	(void) snprintf(buf, sizeof (buf), "%s %s %s %s",
	    parms->master_vol, parms->shadow_vol, parms->bitmap_vol,
	    (parms->flag & DSW_GOLDEN) ? "I" : "D");

	if (cfg_put_cstring(cfg, "ii", buf, strlen(buf)) >=  0) {
		/* if we have a group name, add it */
		if (group_name) {
			if (find_any_cf_line(parms->shadow_vol)) {
				(void) sprintf(buf, "ii.set%d.group",
				    setnumber);
				if (cfg_put_cstring(cfg, buf,
					group_name, strlen(group_name)) < 0)
					perror("cfg_put_cstring");
			}
			else
				perror("cfg_location");
		}

		/* commit the record */
		(void) cfg_commit(cfg);
	}
	else
		perror("cfg_put_string");
}

void
remove_iiset(int setno, char *shadow, int shd_exp)
{
	mstcount_t *mdata;
	shdvol_t *sdata;
	char sn[CFG_MAX_BUF];

	if (perform_autosv()) {
		if (volhash) {
			unload_ii_vols();
		}
		load_ii_vols(cfg);
		if (cfg_load_dsvols(cfg) < 0 || cfg_load_svols(cfg) < 0) {
			dsw_error(gettext("Unable to parse config file"), NULL);
		}

		sdata = (shdvol_t *)nsc_lookup(volhash, shadow);
		if (sdata) {
			/*
			 * Handle the normal cases of disabling a set that is
			 * not an imported shadow volume
			 */
			if (strcmp(sdata->master, II_IMPORTED_SHADOW)) {
				/*
				 * Handle multiple-shadows of single master
				 */
				mdata = (mstcount_t *)
					nsc_lookup(volhash, sdata->master);
				if ((mdata) && (mdata->count == 1)) {
				    if (cfg_vol_disable(cfg, sdata->master,
					cfg_cluster_tag, "ii") < 0)
					    dsw_error(gettext(
						"SV disable of master failed"),
						NULL);
				}
			}

			/*
			 * Handle disk group name of different shadow
			 */
			if (shd_exp) {
				/*
				 * If shadow is exported, then do nothing
				 */
				/*EMPTY*/;
			} else if (cfg_cluster_tag &&
				    strcmp(cfg_cluster_tag, "") &&
				    cfg_dgname(shadow, sn, sizeof (sn)) &&
				    strlen(sn) &&
				    strcmp(sn, cfg_cluster_tag)) {
					/* reload disk group volumes */
					cfg_resource(cfg, sn);
					cfg_unload_dsvols();
					cfg_unload_svols();
					(void) cfg_load_dsvols(cfg);
					(void) cfg_load_svols(cfg);
					if (cfg_vol_disable(cfg, shadow, sn,
					    "ii") < 0)
					    dsw_error(gettext(
						"SV disable of shadow failed"),
						NULL);
					cfg_resource(cfg, cfg_cluster_tag);
			} else {
				if (cfg_vol_disable(cfg, shadow,
				    cfg_cluster_tag, "ii") < 0)
					dsw_error(gettext(
					    "SV disable of shadow failed"),
					    NULL);
			}
		}
		cfg_unload_svols();
		cfg_unload_dsvols();
		unload_ii_vols();
		reload_vols &= ~(LD_SVOLS | LD_DSVOLS | LD_II);
	}

	(void) sprintf(key, "ii.set%d", setno);
	if (cfg_put_cstring(cfg, key, NULL, 0) < 0) {
		perror("cfg_put_cstring");
	}
	(void) cfg_commit(cfg);
}

/*
 * determine if we are running in a Sun Cluster Environment
 */
int
check_cluster()
{
	static int is_cluster = -1;
	int rc;
#ifdef DEBUG
	char *cdebug = getenv("II_SET_CLUSTER");
#endif

	/*
	 * If this routine was previously called, just return results
	 */
	if (is_cluster != -1)
		return (is_cluster);

	/*
	 * See if Sun Cluster was installed on this node
	 */
#ifdef DEBUG
	if (cdebug) rc = atoi(cdebug);
	else
#endif
	rc = cfg_iscluster();
	if (rc > 0) {
		/*
		 * Determine if user specified -C local
		 */
		if ((cfg_cluster_tag == NULL) ||
		    (strcmp(cfg_cluster_tag, II_LOCAL_TAG))) {
			/*
			 * We're in a Sun Cluster, and no "-C local"
			 */
			is_cluster = II_CLUSTER;
		} else {
			/*
			 * We're in a Sun Cluster, but "-C local" was specified
			 */
			is_cluster = II_CLUSTER_LCL;
			cfg_cluster_tag = "";
		}
		return (is_cluster);
	} else if (rc == 0) {
		/*
		 * Not in a Sun Cluster
		 */
		is_cluster = II_NOT_CLUSTER;
		return (is_cluster);
	} else {
		dsw_error(gettext("unable to ascertain environment"), NULL);
		/*NOTREACHED*/
	}

	/* gcc */
	return (is_cluster);
}

/*
 * Determine if we need to set a cfg_resource based on this volume
 */
static int
check_resource_group(char *volume)
{
	char diskgroup[CFG_MAX_BUF];

	/*
	 * If we are in a cluster, attempt to derive a new resource group
	 */

#ifdef DEBUG
	if (getenv("II_SET_CLUSTER") || (check_cluster() == II_CLUSTER)) {
#else
	if (check_cluster() == II_CLUSTER) {
#endif
		if (check_diskgroup(volume, diskgroup)) {
			if (cfg_cluster_tag == NULL) {
				cfg_cluster_tag = strdup(diskgroup);
				if (cfg_cluster_tag == NULL)
					dsw_error(gettext(
					"Memory allocation failure"), NULL);
				cfg_resource(cfg, cfg_cluster_tag);
				return (1);
			} else {
			/*
			 * Check dgname and cluster tag from -C are the same.
			 */
			if (strcmp(diskgroup, cfg_cluster_tag) != 0) {
			    char error_buffer[128];
			    (void) snprintf(error_buffer, sizeof (error_buffer),
				gettext(
				    "-C (%s) does not match disk group "
				    "name (%s) for %s"), cfg_cluster_tag,
				    diskgroup, volume);
				spcs_log("ii", NULL, error_buffer);
				dsw_error(error_buffer, NULL);
			    }
			}
		} else if (cfg_cluster_tag == NULL)
			dsw_error(gettext(
				"Point-in-Time Copy volumes, that are not "
				"in a device group which has been "
				"registered with SunCluster, "
				"require usage of \"-C\""), NULL);
	}
	return (0);
}

static void
check_dg_is_local(char *dgname)
{
	char error_buffer[128];
	char *othernode;
	int rc;

	/*
	 * check where this disk service is mastered
	 */
	rc = cfg_dgname_islocal(dgname, &othernode);
	if (rc < 0) {
		(void) snprintf(error_buffer, sizeof (error_buffer),
		    gettext("Unable to find disk service:%s"), dgname);
		dsw_error(error_buffer, NULL);
	} else if (rc == 0) {
		(void) snprintf(error_buffer, sizeof (error_buffer),
		    gettext("disk service, %s, is active on node \"%s\"\n"
		    "Please re-issue the command on that node"), dgname,
		    othernode);
		dsw_error(error_buffer, NULL);
	}
}

/*
 * Carry out cluster based checks for a specified volume, or just
 * global options.
 */
static int
check_diskgroup(char *path, char *result)
{
	char dgname[CFG_MAX_BUF];
	char error_buffer[128];

#ifdef DEBUG
	char *override = getenv("II_CLUSTER_TAG");
	if (override) {
		strcpy(result, override);
		return (1);
	}
#endif
	/*
	 * Check on path name, a returned NULL dgname is valid
	 */
	if (cfg_dgname(path, dgname, sizeof (dgname)) == NULL) {
		(void) snprintf(error_buffer, sizeof (error_buffer), gettext(
		    "unable to determine disk group name for %s"), path);
		dsw_error(error_buffer, NULL);
	}
	if (strcmp(dgname, "") == 0)
		return (0);

	/*
	 * See if disk group is local to this node
	 */
	check_dg_is_local(dgname);

	/*
	 * Copy dgname into result
	 */
	strcpy(result, dgname);
	return (1);
}

/*
 * sigterm (): traps specified signal , usually termination one
 */
void
sigterm(int sig)
{
	spcs_log("ii", NULL, gettext("%s received signal %d"), cmdnam, sig);
	exit(1);
}

/*
 * sigchild; reap child and collect status.
 */

volatile pid_t	dead_child;
int	dead_stat;

/*ARGSUSED*/
void
sigchild(int sig)
{
	dead_child = wait(&dead_stat);
}

/*
 * InitEnv(): initializes environment
 */
void
InitEnv()
{
	(void) setlocale(LC_ALL, "");
	(void) textdomain(DSW_TEXT_DOMAIN);

#ifndef DEBUG
	sigset(SIGHUP, sigterm);
	sigset(SIGINT, sigterm);
	sigset(SIGQUIT, sigterm);
	sigset(SIGILL, sigterm);
	sigset(SIGEMT, sigterm);
	sigset(SIGABRT, sigterm);
	sigset(SIGFPE, sigterm);
	sigset(SIGBUS, sigterm);
	sigset(SIGSEGV, sigterm);
	sigset(SIGTERM, sigterm);
	sigset(SIGPWR, sigterm);
	sigset(SIGSTOP, sigterm);
	sigset(SIGTSTP, sigterm);
#endif

	dsw_fd = open(DSWDEV, O_RDONLY);
	if (dsw_fd < 0) {
		perror(DSWDEV);
		exit(1);
	}

	setsid();
}

/*
 * print an error message, followed by decoded errno then exit.
 */
void
dsw_error(char *str, spcs_s_info_t *status)
{
	char *sp;

	(void) fprintf(stderr, "%s: %s:\n", cmdnam, str);
	if (status == NULL) {
		/* deflect ESRCH */
		if (ESRCH == errno) {
			sp = "Set/volume not found";
		} else {
			sp = strerror(errno);
		}
		(void) fprintf(stderr, "%s\n", sp ? sp : "");
	} else {
		spcs_s_report(*status, stderr);
		spcs_s_ufree(status);
	}
	if (cfg)
		cfg_close(cfg);
	exit(2);
}


#undef size

void
free_bitmap(unsigned char *bitmap)
{
	free(bitmap);
}


int
get_bitmap(master_volume, shd_bitmap, copy_bitmap, size)
	char		*master_volume;
	unsigned char	*shd_bitmap;
	unsigned char	*copy_bitmap;
	unsigned long	size;
{
	dsw_bitmap_t parms;

	strncpy(parms.shadow_vol, master_volume, DSW_NAMELEN);
	parms.shadow_vol[DSW_NAMELEN-1] = '\0';
	parms.shd_bitmap = shd_bitmap;
	parms.shd_size = size;
	parms.copy_bitmap = copy_bitmap;
	parms.copy_size = size;

	return (do_ioctl(dsw_fd, DSWIOC_BITMAP, &parms));
}

unsigned char *
allocate_bitmap(char *shadow_volume)
{
	unsigned char	*shd_bitmap;
	unsigned char	*copy_bitmap;
	unsigned char	*p;
	unsigned char	*q;
	int		i;
	dsw_stat_t	args;
	int		stat_flags;

	strncpy(args.shadow_vol, shadow_volume, DSW_NAMELEN);
	args.shadow_vol[DSW_NAMELEN-1] = '\0';

	args.status = spcs_s_ucreate();
	if (do_ioctl(dsw_fd, DSWIOC_STAT, &args) == -1)
		dsw_error(gettext("Stat failed"), &args.status);

	stat_flags = args.stat;
	if (stat_flags & DSW_BMPOFFLINE)
		return (NULL);

	bm_size = args.size;
	bm_size = (bm_size + DSW_SIZE-1) / DSW_SIZE;
	bm_actual = bm_size;
	bm_size = (bm_size + DSW_BITS-1) / DSW_BITS;
	spcs_s_ufree(&args.status);

	p = shd_bitmap = (unsigned char *) malloc(bm_size);
	if (!shd_bitmap) {
		perror(gettext("malloc bitmap"));
		return (NULL);
	}

	q = copy_bitmap = (unsigned char *) malloc(bm_size);
	if (!copy_bitmap) {
		perror(gettext("malloc bitmap"));
		free(shd_bitmap);
		return (NULL);
	}

	memset(shd_bitmap, 0, bm_size);
	memset(copy_bitmap, 0, bm_size);

	if (get_bitmap(shadow_volume, shd_bitmap, copy_bitmap, bm_size) < 0) {
		free(copy_bitmap);
		free(shd_bitmap);
		return (NULL);
	}

	/*
	 * "or" the copy and shadow bitmaps together to return a composite
	 * bitmap that contains the total set of differences between the
	 * volumes.
	 */
	for (i = bm_size; i-- > 0; /*CSTYLED*/)
		*p++ |= *q++;

	free(copy_bitmap);

	return (shd_bitmap);
}

/*
 * print usage message and exit.
 */
void
usage(char *why)
{
	if (why) {
		(void) fprintf(stderr, "%s: %s\n", cmdnam, why);

		(void) fprintf(stderr, "%s\n",
		    gettext("\nBrief summary:"));
		(void) fprintf(stderr, "%s\n",
		    gettext("\t-e {ind|dep} master_vol shadow_vol "
		    "bitmap_vol"));
		(void) fprintf(stderr, "%s\n",
		    gettext("\t-[cu {s|m}] volume_set"));
		(void) fprintf(stderr, "%s\n",
		    gettext("\t-i all"));
		(void) fprintf(stderr, "%s\n",
		    gettext("\t-[adDEilPRw] volume_set"));
		(void) fprintf(stderr, "%s\n",
		    gettext("\t-g group_name [options]"));
		(void) fprintf(stderr, "%s\n",
		    gettext("\t-C cluster_tag [options]"));
		(void) fprintf(stderr, "%s\n",
		    gettext("\t-[hilLv]"));
		(void) fprintf(stderr, "%s\n",
		    gettext("\t-[IJ] volume_set bitmap"));
		(void) fprintf(stderr, "%s\n",
		    gettext("\t-A overflow_vol volume_set"));
		(void) fprintf(stderr, "%s\n",
		    gettext("\t-[OQ] overflow_vol"));
		(void) fprintf(stderr, "%s\n",
		    gettext("\t-P {delay} {units} volume_set"));

		/* assume we came here due to a user mistake */
		exit(1);
		/* NOTREACHED */
	} else {

		(void) fprintf(stdout, "%s\n",
		    gettext("Point-in-Time Copy Administrator CLI options"));
		(void) fprintf(stdout, "%s\n",
		    gettext("Usage summary:"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-e ind m s b\tenable independent master shadow "
		    "bitmap"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-e dep m s b\tenable dependent master shadow "
		    "bitmap"));
		if (check_cluster() == II_CLUSTER)
		    (void) fprintf(stdout, "%s\n",
			gettext("\t-ne ind m s b\tenable exportable master "
			"shadow bitmap"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-d v\t\tdisable volume"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-u s v\t\tupdate shadow volume"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-u m v\t\tupdate master volume"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-c s v\t\tcopy to shadow volume"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-c m v\t\tcopy to master volume"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-a v\t\tabort copy volume"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-w v\t\twait volume"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-i v\t\tdisplay volume status"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-i all\t\tdisplay all volume status"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-l\t\tlist all volumes"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-R v\t\treset volume"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-A o v\t\tattach overflow to volume"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-D v\t\tdetach overflow from volume"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-L\t\tlist all overflow volumes"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-O o\t\tinitialize overflow"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-Q o\t\tquery status of overflow"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-E v\t\texport shadow volume"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-I v b\t\timport volume bitmap"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-J v b\t\tjoin volume bitmap"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-P d u v\tset copy delay/units for volume"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-P v\t\tget copy delay/units for volume"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-C tag\t\tcluster resource tag"));
#ifdef DEBUG
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-b v\t\tdisplay bitmap volume"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-f f\t\tuse private configuration file"));
#endif
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-v\t\tprint software versions"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-n\t\tperform action without question"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-p [-c|-u] {m|s}"
			"enable PID locking on copy or update"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-p -w v\t\tdisable PID locking"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-h\t\tiiadm usage summary"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\nUsage summary for options that support "
		    "grouping (-g g):"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -e ind m s b group enable independent "
		    "master shadow bitmap"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -e dep m s b group enable dependent "
		    "master shadow bitmap"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -d\t\tdisable group"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -u s\tupdate shadow for all volumes in "
		    "group"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -u m\tupdate master for all volumes in "
		    "group"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -c s\tcopy to shadow for all volumes in "
		    "group"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -c m\tcopy to master for all volumes in "
		    "group"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -a\t\tabort copy for all volumes in "
		    "group"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -w\t\twait for all volumes in group"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -i\t\tdisplay status of all volumes in "
		    "group"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -l\t\tlist all volumes in group"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g -L\t\tlist all groups"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -m v v\tmove one or more volumes into "
		    "group"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g \"\" -m v\tremove volume from group"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -R\t\treset all volumes in group"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -A o\tattach overflow to all volumes in "
		    "group"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -D\t\tdetach overflow from all volumes in "
		    "group"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -E\t\texport shadow volume for all "
		    "volumes in group"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -P d u\tset copy delay/units for all "
		    "volumes in group"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\t-g g -P\t\tget copy delay/units for all "
		    "volumes in group"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\nLegend summary:"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\tind\t\tindependent volume set"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\tdep\t\tdependent volume set"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\tall\t\tall configured volumes"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\tm\t\tmaster volume"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\ts\t\tshadow volume"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\tv\t\tshadow volume (reference name)"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\to\t\toverflow volume"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\tb\t\tbitmap volume"));
#ifdef DEBUG
		(void) fprintf(stdout, "%s\n",
		    gettext("\tf\t\tconfiguration file name"));
#endif
		(void) fprintf(stdout, "%s\n",
		    gettext("\td\t\tdelay tick interval"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\tu\t\tunit size"));
		(void) fprintf(stdout, "%s\n",
		    gettext("\tg\t\tgroup name"));

		/* assume we came here because user request help text */
		exit(0);
		/* NOTREACHED */
	}

}

static  char    yeschr[MAX_LINE_SIZE + 2];
static  char    nochr[MAX_LINE_SIZE + 2];

static int
yes(void)
{
	int	i, b;
	char	ans[MAX_LINE_SIZE + 1];

	for (i = 0; /*CSTYLED*/; i++) {
		b = getchar();
		if (b == '\n' || b == '\0' || b == EOF) {
			if (i < MAX_LINE_SIZE)
				ans[i] = 0;
			break;
		}
		if (i < MAX_LINE_SIZE)
			ans[i] = b;
	}
	if (i >= MAX_LINE_SIZE) {
		i = MAX_LINE_SIZE;
		ans[MAX_LINE_SIZE] = 0;
	}
	if ((i == 0) || (strncmp(yeschr, ans, i))) {
		if (strncmp(nochr, ans, i) == 0)
			return (0);
		else if (strncmp(yeschr, ans, i) == 0)
			return (1);
		else {
			(void) fprintf(stderr, "%s %s/%s\n",
			    gettext("You have to respond with"),
			    yeschr, nochr);
			return (2);
		}
	}
	return (1);
}

static int
convert_int(char *str)
{
	int result, rc;
	char *buf;

	buf = (char *)calloc(strlen(str) + 256, sizeof (char));
	rc = sscanf(str, "%d%s", &result, buf);

	if (rc != 1) {
		(void) sprintf(buf, gettext("'%s' is not a valid number"), str);
		/* dsw_error calls exit which frees 'buf' */
		errno = EINVAL;
		dsw_error(buf, NULL);
	}
	free(buf);

	return (result);
}

void
check_action(char *will_happen)
{
	int answer;

	if (nflg || !isatty(fileno(stdin)))
		return;
	strncpy(yeschr, nl_langinfo(YESSTR), MAX_LINE_SIZE + 1);
	strncpy(nochr, nl_langinfo(NOSTR), MAX_LINE_SIZE + 1);

	/*CONSTCOND*/
	while (1) {
		(void) printf("%s %s/%s ", will_happen, yeschr, nochr);
		answer = yes();
		if (answer == 1 || answer == 0)
			break;
	}
	if (answer == 1)
		return;
	exit(1);
}

enum	child_event {Status, CopyStart};

/*
 * Wait for child process to get to some state, where some state may be:
 *
 *	Status		Set up the shadow enough so that it responds
 *			to status requests.
 *	CopyStart	Start copy/update operations.
 */

int
child_wait(pid_t child, enum child_event event, char *volume)
{
	dsw_stat_t	args;
	int rc;

	strncpy(args.shadow_vol, volume, DSW_NAMELEN);
	args.shadow_vol[DSW_NAMELEN-1] = '\0';

	for (; dead_child != child; sleep(1)) {

		/* poll shadow group with a status ioctl() */
		args.status = spcs_s_ucreate();
		errno = 0;
		rc = do_ioctl(dsw_fd, DSWIOC_STAT, &args);

		spcs_s_ufree(&args.status);

		if (event == Status) {
			/* keep polling while we fail with DSW_ENOTFOUND */
			if (rc != -1 || errno != DSW_ENOTFOUND)
				return (0);
		} else {
			/* event == CopyStart */
			if (rc == -1) {
				return (1);	/* something wrong */
			}
			if (args.stat & DSW_COPYINGP)
				return (0);	/* copying underway */
		}
	}
	/* child died */
	if (WIFEXITED(dead_stat))
		return (WEXITSTATUS(dead_stat));
	else
		return (1);
}

int
mounted(char *t)
{
	int	rdsk;
	int	i;
	FILE	*mntfp;
	struct mnttab mntref;
	struct mnttab mntent;
	char	target[DSW_NAMELEN];
	char	*s;

	rdsk = i = 0;
	for (s = target; i < DSW_NAMELEN && (*s = *t++); i++) {
		if (*s == 'r' && rdsk == 0)
			rdsk = 1;
		else
			s++;
	}
	*s = '\0';

	mntref.mnt_special = target;
	mntref.mnt_mountp = NULL;
	mntref.mnt_fstype = NULL;
	mntref.mnt_mntopts = NULL;
	mntref.mnt_time = NULL;

	if ((mntfp = fopen("/etc/mnttab", "r")) == NULL) {
		dsw_error(gettext("Can not check volume against mount table"),
					NULL);
	}
	if (getmntany(mntfp, &mntent, &mntref) != -1) {
		/* found something before EOF */
		(void) fclose(mntfp);
		return (1);
	}
	(void) fclose(mntfp);
	return (0);
}

void
enable(char *master_volume, char *shadow_volume,
	char *bitmap_volume, char *copy_type)
{
	dsw_config_t parms;
	dsw_ioctl_t temp;
	char	*p;
	int	rc;
	pid_t	child;
	spcs_s_info_t *sp_info;
	struct stat mstat, sstat, bstat;
	char	mst_dg[DSW_NAMELEN] = {0};
	char	shd_dg[DSW_NAMELEN] = {0};
	char	bmp_dg[DSW_NAMELEN] = {0};
	int	mvol_enabled;
	char	*altname;
	grptag_t *gdata;

	bzero(&parms, sizeof (dsw_config_t));

	if (strcmp(copy_type, "independent") == 0 ||
			strcmp(copy_type, gettext("independent")) == 0)
		parms.flag = DSW_GOLDEN;
	else if (strcmp(copy_type, "dependent") == 0 ||
			strcmp(copy_type, gettext("dependent")) == 0)
		parms.flag = 0;
	else
		dsw_error(gettext("don't understand shadow type"), NULL);

	/* validate volume names */
	if (perform_autosv()) {
		if (cfg_load_svols(cfg) < 0 || cfg_load_dsvols(cfg) < 0 ||
		    cfg_load_shadows(cfg) < 0) {
			dsw_error(gettext("Unable to parse config file"), NULL);
		}
		load_ii_vols(cfg);
		reload_vols = LD_SVOLS | LD_DSVOLS | LD_SHADOWS | LD_II;

		/* see if it's been used before under a different name */
		conform_name(&master_volume);
		conform_name(&shadow_volume);
		rc = cfg_get_canonical_name(cfg, bitmap_volume, &altname);
		if (rc < 0) {
			dsw_error(gettext("Unable to parse config file"), NULL);
		}
		if (rc) {
			errno = EBUSY;
			dsw_error(gettext("Bitmap in use"), NULL);
		}
	}

	/*
	 * If not local, determine disk group names for volumes in II set
	 */
	switch (check_cluster()) {
	case II_CLUSTER:
		/*
		 * Check if none or all volumes are in a disk group
		 */
		rc = 0;
		if (check_diskgroup(master_volume, mst_dg)) rc++;
		if (check_diskgroup(shadow_volume, shd_dg)) rc++;
		if (check_diskgroup(bitmap_volume, bmp_dg)) rc++;
		if ((rc != 0) && (rc != 3))
			dsw_error(gettext(
				"Not all Point-in-Time Copy volumes are "
				"in a disk group"), NULL);

		/*
		 * If volumes are not in a disk group, but are in a
		 * cluster, then "-C <tag>", must be set
		 */
		if (rc == 0 && cfg_cluster_tag == NULL)
			dsw_error(gettext(
				"Point-in-Time Copy volumes, that are not "
				"in a device group which has been "
				"registered with SunCluster, "
				"require usage of \"-C\""), NULL);

		/*
		 * the same disk group
		 * If -n, plus mst_dg==bmp_dg, then allow E/I/J in SunCluster
		 */
		if ((strcmp(mst_dg, bmp_dg)) ||
		    (strcmp(mst_dg, shd_dg) && (!nflg)))
			    dsw_error(gettext(
				"Volumes are not in same disk group"), NULL);

		/*
		 * Can never enable the same shadow twice, regardless of
		 * exportable shadow device group movement
		 */
		if (find_shadow_line(shadow_volume))
			dsw_error(gettext(
				"Shadow volume is already configured"), NULL);

		/*
		 * Groups cannot span multiple clusters
		 */
		if (group_name && perform_autosv()) {
			gdata = (grptag_t *)nsc_lookup(volhash, group_name);
			if (gdata &&
			    strncmp(gdata->ctag, mst_dg, DSW_NAMELEN) != 0) {
				errno = EINVAL;
				dsw_error(gettext("Group contains sets not "
				    "in the same cluster resource"), NULL);
			}
		}

		/*
		 * Check cluster tag and bitmap disk group
		 * set latter if different
		 */
		if (check_resource_group(bitmap_volume)) {
			/*
			 * Unload and reload in the event cluster tag has
			 * changed
			 */
			if (perform_autosv()) {
				unload_ii_vols();
				cfg_unload_shadows();
				cfg_unload_dsvols();
				cfg_unload_svols();
				if (cfg_load_svols(cfg) < 0 ||
				    cfg_load_dsvols(cfg) < 0 ||
				    cfg_load_shadows(cfg) < 0) {
					dsw_error(gettext(
					    "Unable to parse config "
					    "file"), NULL);
				}
				load_ii_vols(cfg);
			}
		}
		/*
		 * Copy cluster name into config
		 */
		strncpy(parms.cluster_tag, cfg_cluster_tag, DSW_NAMELEN);
		break;

	case II_CLUSTER_LCL:
		/* ensure that the -C local won't interfere with the set */
		if (group_name && perform_autosv()) {
			gdata = (grptag_t *)nsc_lookup(volhash, group_name);
			if (gdata) {
				if (strlen(gdata->ctag) != 0) {
					errno = EINVAL;
					dsw_error(gettext("Unable to put set "
					    "into -C local and specified "
					    "group"), NULL);
				}
			}
		}
		break;
	}

	/*
	 * If we've got a group name, add it into the config
	 */
	if (group_name) {
		strncpy(parms.group_name, group_name, DSW_NAMELEN);
	}

	/*
	 * Determine accessability of volumes
	 */
	if (stat(master_volume, &mstat) != 0)
		dsw_error(gettext(
			"Unable to access master volume"), NULL);
	if (!S_ISCHR(mstat.st_mode))
		dsw_error(gettext(
			"Master volume is not a character device"), NULL);
	/* check the shadow_vol hasn't be used as SNDR secondary vol */
	check_iishadow(shadow_volume);
	if (stat(shadow_volume, &sstat) != 0)
		dsw_error(gettext(
			"Unable to access shadow volume"), NULL);
	if (!S_ISCHR(sstat.st_mode))
		dsw_error(gettext(
			"Shadow volume is not a character device"), NULL);
	if (mounted(shadow_volume)) {
		errno = EBUSY;
		dsw_error(gettext(
			"Shadow volume is mounted, unmount it first"), NULL);
	}
	if (mstat.st_rdev == sstat.st_rdev) {
		errno = EINVAL;
		dsw_error(gettext(
		    "Master and shadow are the same device"), NULL);
	}
	if (stat(bitmap_volume, &bstat) != 0) {
		dsw_error(gettext("Unable to access bitmap"), NULL);
	}
	if (!S_ISCHR(bstat.st_mode))
		dsw_error(gettext(
			"Bitmap volume is not a character device"), NULL);
	if (S_ISCHR(bstat.st_mode)) {
		if (mstat.st_rdev == bstat.st_rdev) {
			errno = EINVAL;
			dsw_error(gettext(
			    "Master and bitmap are the same device"), NULL);
		} else if (sstat.st_rdev == bstat.st_rdev) {
			errno = EINVAL;
			dsw_error(gettext(
			    "Shadow and bitmap are the same device"), NULL);
		}
	}

	strncpy(parms.master_vol, master_volume, DSW_NAMELEN);
	strncpy(parms.shadow_vol, shadow_volume, DSW_NAMELEN);
	strncpy(parms.bitmap_vol, bitmap_volume, DSW_NAMELEN);
	errno = 0;
	parms.status = spcs_s_ucreate();

	/*
	 * Check that none of the member volumes forms part of another
	 * InstantImage group.
	 *
	 * -- this check has been removed; it is done in the kernel instead
	 * -- PJW
	 */

	/*
	 * Check against overflow volumes
	 */
	for (p = get_overflow_list(); *p != NULL; p += DSW_NAMELEN) {
		if (strncmp(master_volume, p, DSW_NAMELEN) == 0)
			dsw_error(gettext(
				"Master volume is already an overflow volume"),
				NULL);
		else if (strncmp(shadow_volume, p, DSW_NAMELEN) == 0)
			dsw_error(gettext(
				"Shadow volume is already an overflow volume"),
				NULL);
		else if (strncmp(bitmap_volume, p, DSW_NAMELEN) == 0)
			dsw_error(gettext(
				"Bitmap volume is already an overflow volume"),
				NULL);
	}

	/*
	 * Make sure that the shadow volume is not already configured
	 */
	if (find_shadow_config(shadow_volume, NULL, &temp))
		dsw_error(gettext(
			"Shadow volume is already configured"), NULL);
	if (perform_autosv()) {
		/*
		 * parse the dsvol entries to see if we need to place
		 * the master or shadow under SV control
		 */
		if (nsc_lookup(volhash, master_volume) == NULL) {
			if (cfg_vol_enable(cfg, master_volume, cfg_cluster_tag,
			    "ii") < 0) {
				dsw_error(
				    gettext("Cannot enable master volume"),
				    NULL);
			}
			mvol_enabled = 1;
		} else {
			mvol_enabled = 0;
		}
		if (nsc_lookup(volhash, shadow_volume) == NULL) {
			if (nflg) {
				cfg_resource(cfg, shd_dg);
				rc = cfg_vol_enable(cfg, shadow_volume,
					shd_dg, "ii");
				cfg_resource(cfg, cfg_cluster_tag);
			} else {
				rc = cfg_vol_enable(cfg, shadow_volume,
					cfg_cluster_tag, "ii");
			}
			if (rc < 0) {
				if (mvol_enabled) {
					if (cfg_vol_disable(cfg,
					    master_volume, cfg_cluster_tag,
					    "ii") < 0)
					    dsw_error(gettext(
						"SV disable of master failed"),
						NULL);
				}
				dsw_error(
				    gettext("Cannot enable shadow volume"),
				    NULL);
			}
		}
		unload_ii_vols();
		cfg_unload_shadows();
		cfg_unload_dsvols();
		cfg_unload_svols();
		reload_vols = 0;
	}

	add_cfg_entry(&parms);
	cfg_unlock(cfg);
	config_locked = 0;

	sigset(SIGCHLD, sigchild);
	switch (child = fork()) {

	case (pid_t)-1:
		dsw_error(gettext("Unable to fork"), NULL);
		break;

	case 0:
		rc = do_ioctl(dsw_fd, DSWIOC_ENABLE, &parms);
		if (rc == -1 && errno != DSW_EABORTED && errno != DSW_EIO) {
			/*
			 * Failed to enable shadow group, log problem and remove
			 * the shadow group from the config file.
			 */
			spcs_log("ii", &parms.status,
			    gettext("Enable failed %s %s %s (%s)"),
			    master_volume, shadow_volume, bitmap_volume,
			    parms.flag & DSW_GOLDEN ?
			    "independent" : "dependent");

			if (!ii_lock(cfg, CFG_WRLOCK) ||
			    !find_shadow_config(shadow_volume, NULL, &temp)) {
				dsw_error(gettext(
					"Enable failed, can't tidy up cfg"),
					&parms.status);
			}
			config_locked = 1;
			remove_iiset(setnumber, shadow_volume, 0);
			dsw_error(gettext("Enable failed"), &parms.status);
		}

		if (rc == -1)
			sp_info = &parms.status;
		else
			sp_info = NULL;
		spcs_log("ii", sp_info, gettext("Enabled %s %s %s (%s)"),
			master_volume, shadow_volume, bitmap_volume,
			parms.flag & DSW_GOLDEN ? "independent" : "dependent");
		spcs_s_ufree(&parms.status);
		break;

	default:
		exit(child_wait(child, Status, shadow_volume));
		break;
	}
}

int
reset(char *volume)
{
	dsw_ioctl_t args;
	dsw_config_t parms;
	int	rc;
	int	wait_loc;
	pid_t	child = (pid_t)0;
	enum copy_wait wait_action;
	spcs_s_info_t *stat;
	dsw_stat_t prev_stat;
	int stat_flags;
	static int unlocked = 0;
	int	do_enable = 0;
	char	key[CFG_MAX_KEY];
	char	optval[CFG_MAX_BUF];
	unsigned int flags;

	wait_action = WaitForStart;

	if (unlocked && !ii_lock(cfg, CFG_RDLOCK)) {
		dsw_error(gettext("Unable to set locking on the configuration"),
		    NULL);
	}
	config_locked = 1;
	if (!find_shadow_config(volume, &parms, &args))
		dsw_error(gettext("Volume is not in a Point-in-Time Copy "
		    "group"), NULL);

	cfg_unlock(cfg);
	config_locked = 0;
	unlocked = 1;

	spcs_log("ii", NULL, gettext("Start reset %s"), volume);
	strncpy(prev_stat.shadow_vol, volume, DSW_NAMELEN);
	prev_stat.shadow_vol[DSW_NAMELEN - 1] = '\0';
	prev_stat.status = spcs_s_ucreate();
	if (do_ioctl(dsw_fd, DSWIOC_STAT, &prev_stat) == -1) {
		/* set is suspended, so we do the enable processing instead */
		do_enable = 1;

		/* first check to see whether the set was offline */
		snprintf(key, CFG_MAX_KEY, "ii.set%d.options", setnumber);
		if (!ii_lock(cfg, CFG_RDLOCK)) {
			dsw_error(gettext("Unable to set locking on the "
			    "configuration"), NULL);
		}
		config_locked = 1;
		unlocked = 0;
		if (cfg_get_single_option(cfg, CFG_SEC_CONF, key,
		    NSKERN_II_BMP_OPTION, optval, CFG_MAX_BUF) < 0) {
			dsw_error(gettext("unable to read config file"), NULL);
		}
		cfg_unlock(cfg);
		config_locked = 0;
		unlocked = 1;
		sscanf(optval, "%x", &flags);
		if ((flags & DSW_OFFLINE) == 0) {
			/* set wasn't offline - don't reset */
			dsw_error(gettext("Set not offline, will not reset"),
			    NULL);
		}
		parms.status = spcs_s_ucreate();
		stat = &parms.status;
		stat_flags = DSW_BMPOFFLINE;
	} else {
		args.status = spcs_s_ucreate();
		stat = &args.status;
		stat_flags = prev_stat.stat;
	}
	spcs_s_ufree(&prev_stat.status);

	if (wait_action == WaitForStart)
		sigset(SIGCHLD, sigchild);

	switch (child = fork()) {

	case (pid_t)-1:
		dsw_error(gettext("Unable to fork"), NULL);
		break;

	case 0:
		if (do_enable) {
			rc = do_ioctl(dsw_fd, DSWIOC_ENABLE, &parms);
		} else {
			rc = do_ioctl(dsw_fd, DSWIOC_RESET, &args);
		}
		if (rc == -1 && errno != DSW_EABORTED && errno != DSW_EIO) {
			spcs_log("ii", stat, gettext("Fail reset %s"), volume);
			dsw_error(gettext("Reset shadow failed"), stat);
		}
		/* last_overflow is set during find_shadow_config */
		if (strlen(last_overflow) > 0 &&
		    (stat_flags & (DSW_SHDOFFLINE | DSW_BMPOFFLINE)) != 0) {
			/* reattach it */
			strncpy(parms.bitmap_vol, last_overflow, DSW_NAMELEN);
			do_attach(&parms);
		}
		spcs_log("ii", stat, gettext("Finish reset %s"), volume);
		spcs_s_ufree(stat);

		exit(0);
		break;
	default:
		if (wait_action == WaitForStart) {
			rc = child_wait(child, CopyStart, args.shadow_vol);
		} else { /* wait_action == WaitForEnd */
			wait_loc = 0;
			wait(&wait_loc);
			if (WIFEXITED(wait_loc) && (WEXITSTATUS(wait_loc) == 0))
				rc = 0;
			else
				rc = -1;
		}
		break;
	}
	/* if successful, remove flags entry from options field */
	if (rc >= 0) {
		if (!ii_lock(cfg, CFG_WRLOCK)) {
			dsw_error(gettext("Unable to set locking on the "
			    "configuration"), NULL);
		}
		config_locked = 1;
		if (!find_shadow_config(volume, &parms, &args)) {
			dsw_error(gettext("Volume is not in a Point-in-Time "
			    "Copy group"), NULL);
		}
		snprintf(key, CFG_MAX_KEY, "ii.set%d.options", setnumber);
		if (cfg_del_option(cfg, CFG_SEC_CONF, key, NSKERN_II_BMP_OPTION)
		    < 0) {
			dsw_error(gettext("Update of config failed"), NULL);
		}
		cfg_commit(cfg);
		cfg_unlock(cfg);
		config_locked = 0;
	}

	return (rc);
}

int
overflow(char *volume)
{
	dsw_ioctl_t args;
	int	rc;
	spcs_s_info_t *stat;

	check_action(gettext("Initialize this overflow volume?"));
	if (find_matching_cf_line(volume, NULL, &args))
		dsw_error(gettext("Volume is part of a Point-in-Time Copy "
					    "group"), NULL);
	args.status = spcs_s_ucreate();
	strncpy(args.shadow_vol, volume, DSW_NAMELEN);
	rc = do_ioctl(dsw_fd, DSWIOC_OCREAT, &args);
	if (rc == -1) {
		spcs_log("ii", &args.status,
			gettext("Create overflow failed %s"), volume);
		dsw_error(gettext("Create overflow failed"), &args.status);
	}
	if (rc == -1)
		stat = &args.status;
	else
		stat = NULL;
	spcs_log("ii", stat, gettext("Create overflow succeeded %s"), volume);
	spcs_s_ufree(&args.status);

	return (0);
}

void
bitmap_op(char *master_volume, int print_bitmap, int bitmap_percent, int used,
    int is_compact)
{
	unsigned char *bitmap;
	char *name;
	int i, x, y;
	unsigned j;
	unsigned long n;
	unsigned long percent;

	bitmap = allocate_bitmap(master_volume);
	if (bitmap == NULL)
		return;

	if (bitmap_percent) {
		/* count the number of bits set in bitmap */
		for (i = n = 0; i < bm_size; i++)
			for (j = (unsigned)bitmap[i]; j; j &= j -1)
				n++;
		if (is_compact)
			(void) printf(gettext("Chunks in map: %d used: %d\n"),
			    used, n);
		if (bm_actual < 100) {
			percent = 0;
		} else {
			percent = (n * 100) / bm_actual;
		}
		(void) printf(gettext("Percent of bitmap set: %u\n"), percent);
		percent = percent/100;
		/* distinguish between 0.0000% and 0.n% of bitmap set */
		if (percent < 1)
			(void) printf("\t(%s)\n", n > 0 ?
			    gettext("bitmap dirty") : gettext("bitmap clean"));
	}

	if (print_bitmap) {
		name = strrchr(master_volume, '/');
		if (name++ == NULL)
		name = master_volume;
		i = bm_size * 8;
		x = (int)ceil(sqrt((double)i));
		x += (8 - (x % 8));	/* round up to nearest multiple of 8 */
		y = i / x;
		if (y * x < i)
			y++;
		(void) printf("#define bm%s_width %d\n#define bm%s_height %d\n",
		    name, x, name, y);
		(void) printf("#define bm%s_x_hot 0\n#define bm%s_y_hot 0\n",
		    name, name);
		(void) printf("static char bm%s_bits[] = {\n", name);
		for (i = 0; i < bm_size; i++) {
			if (i % 12 == 0)
				(void) printf("\n");
			(void) printf("0x%02x, ", bitmap[i]);
		}
		y = x * y;
		for (; i < y; i++) {
			if (i % 12 == 0)
				(void) printf("\n");
			(void) printf("0x00, ");
		}
		(void) printf("\n};\n");
	}

	free_bitmap(bitmap);
}

static int
validate_group_names(char **vol_list, char *group)
{
	ENTRY item, *found;
	int i, rc, count;
	dsw_aioctl_t *group_list;
	char *ptr;

	if (group == NULL || *group == NULL) {
		/* no group set, just count volume list */
		for (i = 0; *vol_list++ != NULL; i++)
			;
		return (i);
	}

	if ((count = do_ioctl(dsw_fd, DSWIOC_LISTLEN, NULL)) < 0)
		dsw_error("DSWIOC_LISTLEN", NULL);

	group_list = malloc(sizeof (dsw_aioctl_t) + count * DSW_NAMELEN);
	if (group_list == NULL)
		dsw_error(gettext("Failed to allocate memory"), NULL);

	bzero(group_list, sizeof (dsw_aioctl_t) + count * DSW_NAMELEN);
	group_list->count = count;
	group_list->flags = 0;
	group_list->status = spcs_s_ucreate();
	strncpy(group_list->shadow_vol, group, DSW_NAMELEN);

	rc = do_ioctl(dsw_fd, DSWIOC_GLIST, group_list);
	if (rc < 0)
		dsw_error(gettext("Group list access failure"),
		    &group_list->status);

	group_list->shadow_vol[DSW_NAMELEN * group_list->count] = '\0';

	/* create hash and enter all volumes into it */
	if (hcreate(group_list->count) == 0)
		dsw_error(gettext("Failed to allocate memory"), NULL);
	ptr = group_list->shadow_vol;
	count = group_list->count;
	i = 0;
	while (i < count) {
		ptr[ DSW_NAMELEN - 1 ] = '\0';
		item.key = ptr;
		item.data = (void *) 0;
		(void) hsearch(item, ENTER);
		++i;
		ptr += DSW_NAMELEN;
	}

	/* now compare the volume list with the hash */
	for (i = 0; vol_list[ i ]; i++) {
		item.key = vol_list[ i ];
		found = hsearch(item, FIND);
		if (!found)
			dsw_error(gettext("Group config does not match kernel"),
			    NULL);
		if (found->data != (void *) 0)
			dsw_error(gettext("Duplicate volume specified"), NULL);
		found->data = (void *) 1;
	}
	if (i != count)
		dsw_error(gettext("Group config does not match kernel"), NULL);

	/* everything checks out */
	free(group_list);
	hdestroy();

	return (count);
}

int
do_acopy(char **vol_list, enum copy_update update_mode,
		enum copy_direction direction)
{
	dsw_aioctl_t *acopy_args;
	dsw_ioctl_t copy_args;
	dsw_config_t parms;
	dsw_stat_t	stat_s;
	int	i;
	int	rc;
	int	n_vols;
	char	*t;
	char	buf[1024];
	char	*sp;
	char	*ppid;

	n_vols = validate_group_names(vol_list, group_name);

	acopy_args = calloc(sizeof (dsw_aioctl_t) + n_vols * DSW_NAMELEN, 1);
	if (acopy_args == NULL)
		dsw_error(gettext("Too many volumes given for update"), NULL);

	acopy_args->count = n_vols;

	acopy_args->flags = 0;

	if (update_mode == Update)
		acopy_args->flags |= CV_BMP_ONLY;
	if (direction == ToMaster)
		acopy_args->flags |= CV_SHD2MST;
	if (pflg) {
		acopy_args->flags |= CV_LOCK_PID;
#ifdef DEBUG
		ppid = getenv("IIADM_PPID");
		if (ppid) {
			acopy_args->pid = atoi(ppid);
			fprintf(stderr, "(using %s for ppid)\n", ppid);
		} else {
			acopy_args->pid = getppid();
		}
#else
		acopy_args->pid = getppid();
#endif
	}

	for (i = 0; i < n_vols; i++) {
		if (!find_shadow_config(vol_list[i], &parms, &copy_args))
			dsw_error(gettext("Volume is not in a Point-in-Time "
			    "group"), NULL);
		if (direction == ToMaster) {
			t = parms.master_vol;
		} else {
			t = parms.shadow_vol;
		}

		if (mounted(t)) {
			errno = EBUSY;
			dsw_error(gettext("Target of copy/update is mounted, "
						"unmount it first"), NULL);
		}

		strncpy(stat_s.shadow_vol, parms.shadow_vol, DSW_NAMELEN);
		stat_s.shadow_vol[DSW_NAMELEN-1] = '\0';
		stat_s.status = spcs_s_ucreate();
		rc = do_ioctl(dsw_fd, DSWIOC_STAT, &stat_s);
		spcs_s_ufree(&stat_s.status);
		if (rc == -1) {
			(void) sprintf(buf,
			    gettext("Shadow group %s is suspended"),
			    vol_list[i]);
			dsw_error(buf, NULL);
		}

		if (stat_s.stat & DSW_COPYINGP) {
			(void) fprintf(stderr, "%s: %s\n", cmdnam,
			    gettext("Copy already in progress"));
			exit(1);
		}
	}
	acopy_args->status = spcs_s_ucreate();
	for (i = 0; i < n_vols; i++) {
		spcs_log("ii", NULL, gettext("Atomic %s %s %s"),
			update_mode == Update ?
				gettext("update") : gettext("copy"),
			vol_list[i],
			direction == ToMaster ?  gettext("from shadow") :
			gettext("to shadow"));
	}
	if (group_name == NULL || *group_name == NULL) {
		sp = acopy_args->shadow_vol;
		for (i = 0; i < n_vols; i++, sp += DSW_NAMELEN)
			strncpy(sp, vol_list[i], DSW_NAMELEN);
	} else {
		strncpy(acopy_args->shadow_vol, group_name, DSW_NAMELEN);
		acopy_args->flags |= CV_IS_GROUP;
	}
	rc = do_ioctl(dsw_fd, DSWIOC_ACOPY, acopy_args);
	if (rc == -1) {
		i = acopy_args->count;
		if (i < 0 || i >= n_vols) {
			spcs_log("ii", NULL, gettext("Atomic update failed"));
			(void) sprintf(buf, gettext("Update failed"));
		} else {
			spcs_log("ii", NULL,
				gettext("Atomic update of %s failed"),
				vol_list[acopy_args->count]);
			(void) sprintf(buf, gettext("Update of %s failed"),
			    vol_list[acopy_args->count]);
		}
		dsw_error(buf, &(acopy_args->status));
	}
	return (rc);
}

int
do_copy(char **vol_list, enum copy_update update_mode,
		enum copy_direction direction, enum copy_wait wait_action)
{
	dsw_ioctl_t copy_args;
	dsw_config_t parms;
	dsw_stat_t	stat_s;
	int	rc;
	int	wait_loc;
	char	*t;
	char	*volume;
	pid_t	child = (pid_t)0;
	char	*ppid;

	if (vol_list[0] && vol_list[1])
		return (do_acopy(vol_list, update_mode, direction));

	volume = vol_list[0];
	if (!find_shadow_config(volume, &parms, &copy_args))
		dsw_error(gettext("Volume is not in a Point-in-Time Copy "
					    "group"), NULL);

	cfg_unlock(cfg);
	config_locked = 0;
	copy_args.flags = 0;

	if (update_mode == Update)
		copy_args.flags |= CV_BMP_ONLY;
	if (direction == ToMaster) {
		copy_args.flags |= CV_SHD2MST;
		t = parms.master_vol;
	} else {
		t = parms.shadow_vol;
	}
	if (pflg) {
		copy_args.flags |= CV_LOCK_PID;
#ifdef DEBUG
		ppid = getenv("IIADM_PPID");
		if (ppid) {
			copy_args.pid = atoi(ppid);
			fprintf(stderr, "(using %s for ppid)\n", ppid);
		} else {
			copy_args.pid = getppid();
		}
#else
		copy_args.pid = getppid();
#endif
	}

	if (mounted(t)) {
		errno = EBUSY;
		dsw_error(gettext("Target of copy/update is mounted, "
					"unmount it first"), NULL);
	}

	strncpy(stat_s.shadow_vol, copy_args.shadow_vol, DSW_NAMELEN);
	stat_s.shadow_vol[DSW_NAMELEN-1] = '\0';
	stat_s.status = spcs_s_ucreate();
	rc = do_ioctl(dsw_fd, DSWIOC_STAT, &stat_s);
	spcs_s_ufree(&stat_s.status);
	if (rc == -1)
		dsw_error(gettext("Shadow group suspended"), NULL);

	if (stat_s.stat & DSW_COPYINGP) {
		(void) fprintf(stderr, "%s: %s\n", cmdnam,
		    gettext("Copy already in progress"));
		exit(1);
	}

	copy_args.status = spcs_s_ucreate();
	spcs_log("ii", NULL, gettext("Start %s %s %s"),
			update_mode == Update ?
				gettext("update") : gettext("copy"),
			volume,
			direction == ToMaster ?  gettext("from shadow") :
			gettext("to shadow"));

	if (wait_action == WaitForStart)
		sigset(SIGCHLD, sigchild);
	switch (child = fork()) {

	case (pid_t)-1:
		dsw_error(gettext("Unable to fork"),
					NULL);
		break;

	case 0:
		rc = do_ioctl(dsw_fd, DSWIOC_COPY, &copy_args);
		if (rc == -1) {
			spcs_log("ii", &copy_args.status,
			    gettext("Fail %s %s %s"),
			    update_mode == Update ?
					gettext("update") : gettext("copy"),
			    volume,
			    direction == ToMaster ?  gettext("from shadow")
					: gettext("to shadow"));
			dsw_error(gettext("Copy failed"), &copy_args.status);
		}
		spcs_s_ufree(&copy_args.status);
		spcs_log("ii", NULL, gettext("Finish %s %s %s"),
		    update_mode == Update ?
				gettext("update") : gettext("copy"),
		    volume,
		    direction == ToMaster ?  gettext("from shadow") :
				gettext("to shadow"));

		exit(0);
		break;
	default:
		if (wait_action == WaitForStart) {
			rc = child_wait(child, CopyStart, copy_args.shadow_vol);
		} else { /* wait_action == WaitForEnd */
			wait_loc = 0;
			wait(&wait_loc);
			if (WIFEXITED(wait_loc) && (WEXITSTATUS(wait_loc) == 0))
				rc = 0;
			else
				rc = 1;
		}
		break;
	}
	return (rc);
}

void
print_status(dsw_config_t *conf, int in_config)
{
	dsw_stat_t args;
	int	stat_flags;
	static int need_sep = 0;
	time_t tmp_time;

	if (need_sep++ > 0)
		(void) printf("--------------------------------------"
		    "----------------------------------------\n");
	strncpy(args.shadow_vol, conf->shadow_vol, DSW_NAMELEN);
	args.shadow_vol[DSW_NAMELEN-1] = '\0';
	if (in_config) {
		(void) printf("%s: %s\n",
		    conf->master_vol, gettext("(master volume)"));
		(void) printf("%s: %s\n",
		    conf->shadow_vol, gettext("(shadow volume)"));
		(void) printf("%s: %s\n",
		    conf->bitmap_vol, gettext("(bitmap volume)"));
	}

	/*
	 * Do special checking on the status of this volume in a Sun Cluster
	 */
	if (check_cluster() == II_CLUSTER) {
	    char dgname[CFG_MAX_BUF], *other_node;

	    if (cfg_dgname(conf->bitmap_vol, dgname, sizeof (dgname))) {
		if (strlen(dgname)) {
		    int rc = cfg_dgname_islocal(dgname, &other_node);
		    if (rc < 0) {
			(void) printf(gettext(
			    "Suspended on this node, not active elsewhere\n"));
			return;
		    } else if (rc == 0) {
			(void) printf(gettext(
				"Suspended on this node, active on %s\n"),
				other_node);
			return;
		    }
		}
	    }
	}

	args.status = spcs_s_ucreate();
	if (do_ioctl(dsw_fd, DSWIOC_STAT, &args) == -1) {

		/* Handle Not found or not in config */
		if (errno != DSW_ENOTFOUND || !in_config)
			dsw_error(gettext("Stat failed"), &args.status);

		/* Just suspend */
		(void) printf(gettext("Suspended.\n"));
		return;
	}

	if (args.overflow_vol[0] != '\0')
		(void) printf("%s: %s\n", args.overflow_vol,
		    gettext("(overflow volume)"));

	if (conf->group_name[0] != '\0')
		(void) printf(gettext("Group name: %s\n"),
			    conf->group_name);

	if (conf->cluster_tag[0] != '\0')
		(void) printf(gettext("Cluster tag: %s\n"),
			    conf->cluster_tag);

	stat_flags = args.stat;
	spcs_s_ufree(&args.status);
	if (stat_flags & DSW_GOLDEN)
		(void) printf(gettext("Independent copy"));
	else
		(void) printf(gettext("Dependent copy"));

	if (stat_flags & DSW_TREEMAP)
		(void) printf(gettext(", compacted shadow space"));

	if (stat_flags & DSW_COPYINGP)
		(void) printf(gettext(", copy in progress"));
	else if (stat_flags & DSW_COPYING)
		(void) printf(gettext(", copy not active"));

	if (stat_flags & DSW_COPYINGM)
		(void) printf(gettext(", copying master to shadow"));

	if (stat_flags & DSW_COPYINGS)
		(void) printf(gettext(", copying shadow to master"));

	if (stat_flags & DSW_COPYINGX)
		(void) printf(gettext(", abort of copy requested"));

	if (stat_flags & DSW_MSTOFFLINE)
		(void) printf(gettext(", master volume offline"));

	if (stat_flags & DSW_SHDOFFLINE)
		(void) printf(gettext(", shadow volume offline"));

	if (stat_flags & DSW_BMPOFFLINE)
		(void) printf(gettext(", bitmap volume offline"));

	if (stat_flags & DSW_OVROFFLINE)
		(void) printf(gettext(", overflow volume offline"));

	if (stat_flags & DSW_SHDEXPORT)
		(void) printf(gettext(", shadow volume exported"));

	if (stat_flags & DSW_SHDIMPORT)
		(void) printf(gettext(", shadow volume imported"));

	if (stat_flags & DSW_OVERFLOW)
		(void) printf(gettext(", out of space"));

	if (stat_flags & DSW_VOVERFLOW)
		(void) printf(gettext(", spilled into overflow volume"));
	(void) printf("\n");

	tmp_time = args.mtime;
	if (tmp_time != 0)
		(void) printf("%s %s", gettext("Latest modified time:"),
			ctime(&tmp_time));
	else
		(void) printf("%s\n", gettext("Latest modified time: unknown"));

	(void) printf("%s %8llu\n", gettext("Volume size:"), args.size);
	if (args.shdsize != 0) {
		(void) printf("%s %lld %s %lld\n",
			gettext("Shadow chunks total:"), args.shdsize,
			gettext("Shadow chunks used:"), args.shdused);
	}
	bitmap_op(args.shadow_vol, 0, 1, 0, 0);
}

int
abort_copy(char *volume)
{
	dsw_ioctl_t args;

	if (!find_shadow_config(volume, NULL, &args))
		dsw_error(gettext("Volume is not in a Point-in-Time Copy "
						"group"), NULL);
	args.status = spcs_s_ucreate();
	if (do_ioctl(dsw_fd, DSWIOC_ABORT, &args)  == -1)
		dsw_error(gettext("Abort failed"), &args.status);
	spcs_log("ii", NULL, gettext("Abort %s"), args.shadow_vol);
	spcs_s_ufree(&args.status);
	return (0);
}

void
iiversion()
{
	dsw_version_t args;

	args.status = spcs_s_ucreate();
	if (do_ioctl(dsw_fd, DSWIOC_VERSION, &args)  == -1)
		dsw_error(gettext("Version failed"), &args.status);
	spcs_s_ufree(&args.status);
#ifdef DEBUG
	(void) printf(gettext("Point in Time Copy version %d.%d.%d.%d\n"),
	    args.major, args.minor, args.micro, args.baseline);
#else
	if (args.micro) {
		(void) printf(gettext("Point in Time Copy version %d.%d.%d\n"),
		    args.major, args.minor, args.micro);
	} else {
		(void) printf(gettext("Point in Time Copy version %d.%d\n"),
		    args.major, args.minor);
	}
#endif
}

void
list_volumes()
{
	dsw_list_t args;
	int i, set, found;
	dsw_config_t *lp;
	ENTRY item, *ip;
	dsw_config_t parms;

	if ((i = do_ioctl(dsw_fd, DSWIOC_LISTLEN, &args)) == -1)
		dsw_error("DSWIOC_LISTLEN", NULL);

	args.status = spcs_s_ucreate();
	args.list_used = 0;
	args.list_size = i + 4;
	lp = args.list = (dsw_config_t *)
	    malloc(args.list_size * sizeof (dsw_config_t));

	if (args.list == NULL)
		dsw_error(gettext("Failed to allocate memory"), NULL);
	if (do_ioctl(dsw_fd, DSWIOC_LIST, &args)  == -1)
		dsw_error(gettext("List failed"), &args.status);
	spcs_s_ufree(&args.status);

	/* make a hashtable */
	if (args.list_used > 0) {
		if (hcreate(args.list_used) == 0) {
			dsw_error(gettext("Failed to allocate memory"), NULL);
			/*NOTREACHED*/
		}
	}

	/* populate the hashtable */
	for (i = 0; i < args.list_used; i++, lp++) {
		item.key = lp->shadow_vol;
		item.data = (char *)lp;
		if (hsearch(item, ENTER) == NULL) {
			dsw_error(gettext("Failed to allocate memory"), NULL);
			/*NOTREACHED*/
		}
	}

	/* perform action for each line of the stored config file */
	for (set = 1; get_dsw_config(set, &parms) == 0; set++) {

		/* Are there any II sets configured on this node? */
		if (args.list_used > 0) {
			item.key = parms.shadow_vol;

			/* Is this volume configured on this node? */
			if (ip = hsearch(item, FIND)) {

				/* Handle Imported Shadows */
				/* LINTED alignment of cast ok */
				lp = (dsw_config_t *)ip->data;
				if (strcmp(parms.master_vol,
					II_IMPORTED_SHADOW))
					found = !(lp->flag & DSW_SHDIMPORT);
				else
					found = (lp->flag & DSW_SHDIMPORT);
			}
			else
				found = FALSE;
		}
		else
			found = FALSE;

		if ((cfg_cluster_tag) &&
			strcmp(cfg_cluster_tag, parms.cluster_tag))
			continue;

		if ((group_name) && strcmp(group_name, parms.group_name))
			continue;

		(void) printf("%s %.*s %.*s %.*s%s\n",
		    (parms.flag & DSW_GOLDEN) ? "ind" : "dep",
		    DSW_NAMELEN, parms.master_vol,
		    DSW_NAMELEN, parms.shadow_vol,
		    DSW_NAMELEN, parms.bitmap_vol,
		    found ? "" : gettext(" (suspended)"));
	}
	hdestroy();
	free(args.list);
}

int
wait_for_copy(char *volume)
{
	dsw_ioctl_t parms;
	int rc;
	static int unlocked = 0;
	char *ppid;

	if (unlocked && !ii_lock(cfg, CFG_RDLOCK)) {
		dsw_error(gettext("Unable to set locking on the configuration"),
		    NULL);
	}
	config_locked = 1;
	if (!find_shadow_config(volume, NULL, &parms))
		dsw_error(gettext("Volume is not in a Point-in-Time Copy "
						"group"), NULL);
	cfg_unlock(cfg);
	config_locked = 0;
	unlocked = 1;

	parms.status = spcs_s_ucreate();
	if (pflg) {
#ifdef DEBUG
		ppid = getenv("IIADM_PPID");
		if (ppid) {
			parms.pid = atoi(ppid);
			fprintf(stderr, "(using %s for ppid)\n", ppid);
		} else {
			parms.pid = (nflg) ? -1 : getppid();
		}
#else
		parms.pid = (nflg) ? -1 : getppid();
#endif
		parms.flags |= CV_LOCK_PID;
	}

	rc = do_ioctl(dsw_fd, DSWIOC_WAIT, &parms);
	if (rc == -1)
		dsw_error(gettext("Wait failed"), &parms.status);
	spcs_s_ufree(&parms.status);
	return (0);
}

int
export(char *volume)
{
	dsw_ioctl_t parms;
	dsw_config_t conf;
	char *old_ctag, dgname[DSW_NAMELEN];
	int rc;

	if (!find_shadow_config(volume, &conf, &parms))
		dsw_error(gettext("Volume is not in a Point-in-Time Copy "
				"group"), NULL);
	if (mounted(volume))
		dsw_error(gettext("Can't export a mounted volume"), NULL);

	/* If this is an exportable shadow in the cluster, change ctag */
	if (strlen(conf.cluster_tag) &&
	    (cfg_dgname(volume, dgname, sizeof (dgname)))) {
		old_ctag = cfg_cluster_tag;
		cfg_resource(cfg, cfg_cluster_tag = strdup(dgname));
	} else	old_ctag = NULL;

	if (cfg_load_dsvols(cfg) < 0 || cfg_load_shadows(cfg) < 0) {
		dsw_error(gettext("Unable to parse config file"), NULL);
	}
	reload_vols = LD_DSVOLS | LD_SHADOWS;
	conform_name(&volume);

	spcs_log("ii", NULL, gettext("Export %s"), volume);
	parms.status = spcs_s_ucreate();
	rc = do_ioctl(dsw_fd, DSWIOC_EXPORT, &parms);
	if (rc == -1)
		dsw_error(gettext("Export failed"), &parms.status);
	if (perform_autosv()) {
		if (cfg_vol_disable(cfg, volume, cfg_cluster_tag, "ii") < 0) {
			dsw_error(gettext("SV-disable failed"), NULL);
		}
		cfg_commit(cfg);
	}

	/* restore old cluster tag, if changed */
	if (old_ctag != NULL)
		cfg_resource(cfg, cfg_cluster_tag = old_ctag);

	spcs_s_ufree(&parms.status);
	return (0);
}

int
detach(char *volume)
{
	dsw_ioctl_t parms;
	int rc;

	if (!find_shadow_config(volume, NULL, &parms))
		dsw_error(gettext("Volume is not in a Point-in-Time Copy "
						"group"), NULL);
	parms.status = spcs_s_ucreate();
	rc = do_ioctl(dsw_fd, DSWIOC_ODETACH, &parms);
	if (rc == 0) {
		/* remove overflow from cfg line */
		(void) sprintf(key, "ii.set%d.overflow", setnumber);
		if (cfg_put_cstring(cfg, key, "-", 1) < 0) {
				perror("cfg_put_cstring");
		}
		(void) cfg_commit(cfg);
	} else {
		spcs_log("ii", NULL, gettext("Detach of overflow %s failed"),
				parms.shadow_vol);
		dsw_error(gettext("Failed to detach overflow volume"),
				&parms.status);
	}
	return (rc);
}

static void
can_disable(char *vol)
{
	dsw_stat_t args;

	if (mounted(vol)) {
		strncpy(args.shadow_vol, vol, DSW_NAMELEN);
		args.shadow_vol[DSW_NAMELEN - 1] = '\0';
		args.status = spcs_s_ucreate();
		if (do_ioctl(dsw_fd, DSWIOC_STAT, &args) != -1 &&
		    (args.stat & DSW_GOLDEN) == 0) {
			errno = EBUSY;
			dsw_error(gettext("Shadow Volume is currently mounted "
			    "and dependent on the master volume"), NULL);
		}
		spcs_s_ufree(&args.status);
	}
}

static void
clean_up_after_failed_disable(dsw_ioctl_t *parms)
{
	char **p;
	dsw_stat_t args;

	for (p = group_volumes; *p; p++) {
		strncpy(args.shadow_vol, *p, DSW_NAMELEN);
		args.shadow_vol[DSW_NAMELEN - 1] = '\0';
		args.status = spcs_s_ucreate();
		if (do_ioctl(dsw_fd, DSWIOC_STAT, &args) == -1) {
			/* set was successfully disabled */
			if (find_shadow_config(*p, NULL, NULL))
				remove_iiset(setnumber, *p, 0);
		}
		spcs_s_ufree(&args.status);
	}

	dsw_error(gettext("Some sets in the group failed to disable"),
	    &parms->status);
}

int
dsw_group_or_single_disable(int argc, char *argv[])
{
	int rc = 0;
	char **p;
	dsw_ioctl_t parms;
	int flags = 0;
	dsw_config_t conf;
	int shd_exported = 0;

	if (argc != 2)
		usage(gettext("Incorrect number of arguments"));

	if (group_name) {
		if (find_group_members(group_name) < 1)
			dsw_error(gettext("Group does not exist or "
			    "has no members"), NULL);
		for (p = group_volumes; *p; p++) {
			can_disable(*p);
		}

		strncpy(parms.shadow_vol, group_name, DSW_NAMELEN);
		if (*group_name)
			flags = CV_IS_GROUP;
	} else {
		if (!find_shadow_config(argv[1], &conf, &parms)) {
			dsw_error(gettext("Volume is not in a Point-in-Time "
			    "Copy group"), NULL);
		}

		can_disable(argv[1]);
		flags = 0;
	}

	if (group_name && !*group_name) {
		/* user typed iiadm -g "" -d */
		for (p = group_volumes; *p; p++) {
			parms.status = spcs_s_ucreate();
			parms.flags = flags;
			strncpy(parms.shadow_vol, *p, DSW_NAMELEN);
			rc = do_ioctl(dsw_fd, DSWIOC_DISABLE, &parms);
			if (rc == -1 && errno != DSW_ENOTFOUND)
				dsw_error(gettext("Disable failed"),
				    &parms.status);
			if (!find_shadow_config(*p, NULL, NULL))
				dsw_error(gettext("Volume is not in a Point-in"
				    "-Time Copy group"), &parms.status);
			remove_iiset(setnumber, *p, 0);
			spcs_s_ufree(&parms.status);
			spcs_log("ii", NULL, gettext("Disabled %s"),
			    parms.shadow_vol);
		}
	} else {
		if (is_exported(conf.shadow_vol)) {
			shd_exported = 1;
		}
		if ((strcmp(conf.master_vol, II_IMPORTED_SHADOW) == 0) &&
		    is_exported(conf.shadow_vol)) {
			dsw_error(gettext(
			"Imported shadow not disabled"), NULL);
		}

		parms.status = spcs_s_ucreate();
		parms.flags = flags;
		rc = do_ioctl(dsw_fd, DSWIOC_DISABLE, &parms);
		if (rc == -1 && errno != DSW_ENOTFOUND) {
			if (errno == DSW_EDISABLE) {
				/*
				 * one or more sets within the group
				 * couldn't disable
				 */
				clean_up_after_failed_disable(&parms);
			} else {
				dsw_error(gettext("Disable failed"),
				    &parms.status);
			}
		}
		spcs_log("ii", NULL, gettext("Disabled %s"), parms.shadow_vol);
	}


	if (group_name && *group_name) {
		for (p = group_volumes; *p; p++) {
			if (!find_shadow_config(*p, NULL, NULL)) {
				/* argh! */
				fprintf(stderr, gettext("Volume '%s' is not "
				    "in a Point-in-Time Copy group"), *p);
			} else {
				remove_iiset(setnumber, *p, 0);
			}
		}
	} else if (!group_name) {
		if (!find_shadow_config(argv[1], NULL, NULL)) {
			/* argh! */
			dsw_error(gettext("Volume is not in a Point-in-Time "
			    "Copy group"), NULL);
		}

		remove_iiset(setnumber, argv[1], shd_exported);
	}

	return (0);
}

int
dsw_group_or_single_op(int argc, char *argv[], int (*op)(char *))
{
	int rc = 0;

	if (argc != 2)
		usage(gettext("Incorrect number of arguments"));

	if (group_name) {
		if (find_group_members(group_name) < 1)
			dsw_error(gettext("Group does not exist or "
				"has no members"),
						NULL);
		for (; *group_volumes; group_volumes++)
			rc |= (*op)(*group_volumes);
	} else {
		rc = (*op)(argv[1]);
	}
	return (rc);
}

void
dsw_list_clusters(char *cluster)
{
	dsw_aioctl_t *acopy_args;
	int rc, i, count;
	char *ptr;

	if ((count = do_ioctl(dsw_fd, DSWIOC_LISTLEN, NULL)) < 0)
		dsw_error("DSWIOC_LISTLEN", NULL);

	acopy_args = malloc(sizeof (dsw_aioctl_t) + count * DSW_NAMELEN);
	if (acopy_args == NULL)
		dsw_error(gettext("Can't get memory for list enquiry"), NULL);

	bzero(acopy_args, sizeof (dsw_aioctl_t) + count * DSW_NAMELEN);
	acopy_args->count = count;
	acopy_args->flags = 0;
	acopy_args->status = spcs_s_ucreate();
	if (cluster)
		strncpy(acopy_args->shadow_vol, cluster, DSW_NAMELEN);

	rc = do_ioctl(dsw_fd, DSWIOC_CLIST, acopy_args);
	if (rc == -1)
		dsw_error(gettext("Cluster list access failure"),
		    &acopy_args->status);

	acopy_args->shadow_vol[DSW_NAMELEN*acopy_args->count] = NULL;

	if (cluster) {
		printf(gettext("Sets in cluster resource group %s:\n"),
		    cluster);
	} else {
		printf(gettext("Currently configured resource groups\n"));
	}
	for (i = 0, ptr = acopy_args->shadow_vol; *ptr &&
	    i < acopy_args->count; i++, ptr += DSW_NAMELEN) {
		printf("  %-64.64s\n", ptr);
	}
}

void
dsw_enable(int argc, char *argv[])
{
	if (argc != 5)
		usage(gettext("Incorrect number of arguments"));

	enable(argv[1], argv[2], argv[3], argv[4]);
	exit(0);
}


void
dsw_disable(int argc, char *argv[])
{
	(void) dsw_group_or_single_disable(argc, argv);
	exit(0);
}


void
dsw_copy_to_shadow(int argc, char *argv[])
{
	char	**volume_list;

	if (argc != 2)
		usage(gettext("Incorrect number of arguments"));
	if (group_name == NULL)
		volume_list = ++argv;
	else {
		if (find_group_members(group_name) < 1)
			dsw_error(gettext("Group does not exist or "
				"has no members"),
						NULL);
		volume_list = group_volumes;
	}

	exit(do_copy(volume_list, Copy, ToShadow, WaitForStart));
}


void
dsw_update_shadow(int argc, char *argv[])
{
	char	**volume_list;

	if (argc != 2)
		usage(gettext("Incorrect number of arguments"));
	if (group_name == NULL)
		volume_list = ++argv;
	else {
		if (find_group_members(group_name) < 1)
			dsw_error(gettext("Group does not exist or "
				"has no members"),
						NULL);
		volume_list = group_volumes;
	}

	exit(do_copy(volume_list, Update, ToShadow, WaitForStart));
}


void
dsw_copy_to_master(int argc, char *argv[])
{
	char	**volume_list;

	if (argc != 2)
		usage(gettext("Incorrect number of arguments"));
	if (group_name == NULL) {
		volume_list = ++argv;
		check_action(gettext("Overwrite master with shadow volume?"));
	} else {
		check_action(gettext("Overwrite every"
			" master in this group with its shadow volume?"));
		if (find_group_members(group_name) < 1)
			dsw_error(gettext("Group does not exist or "
				"has no members"),
						NULL);
		volume_list = group_volumes;
	}

	exit(do_copy(volume_list, Copy, ToMaster, WaitForStart));
}


void
dsw_update_master(int argc, char *argv[])
{
	char	**volume_list;

	if (argc != 2)
		usage(gettext("Incorrect number of arguments"));
	if (group_name == NULL) {
		volume_list = ++argv;
		check_action(gettext("Overwrite master with shadow volume?"));
	} else {
		check_action(gettext("Overwrite every"
			" master in this group with its shadow volume?"));
		if (find_group_members(group_name) < 1)
			dsw_error(gettext("Group does not exist or "
				"has no members"),
						NULL);
		volume_list = group_volumes;
	}

	exit(do_copy(volume_list, Update, ToMaster, WaitForStart));
}


void
dsw_abort_copy(int argc, char *argv[])
{
	exit(dsw_group_or_single_op(argc, argv, abort_copy));
}


void
dsw_display_status(int argc, char *argv[])
{
	dsw_config_t parms;
	int	in_config;

	if (argc != 2 && argc != 1)
		usage(gettext("Incorrect number of arguments"));

	/* "iiadm -i" and "iiadm -i all" are equivalent */
	if (argc == 2 && strcmp("all", argv[1]) != 0) {
		in_config = find_shadow_config(argv[1], &parms, NULL);
		if (!in_config) {
			(void) printf(gettext(
			    "Volume is not in configuration file\n"), NULL);
			(void) fflush(stdout);
			strncpy(parms.shadow_vol, argv[1], DSW_NAMELEN);
			parms.shadow_vol[DSW_NAMELEN] = '\0';
		}
		print_status(&parms, in_config);
	} else if (group_name) {
		if (find_group_members(group_name) < 1)
			dsw_error(gettext("Group does not exist or "
				"has no members"),
						NULL);
		for (; *group_volumes; group_volumes++) {
			in_config = find_shadow_config(*group_volumes,
						&parms, NULL);
			if (in_config)
				print_status(&parms, in_config);
		}
	} else {
		/* perform action for each line of the stored config file */
		for (setnumber = 1;
			!get_dsw_config(setnumber, &parms); setnumber++) {
			switch (check_cluster()) {
			case II_CLUSTER:
			    if ((cfg_cluster_tag) &&
				(strcmp(cfg_cluster_tag, parms.cluster_tag)))
				    continue;
			    break;
			case II_CLUSTER_LCL:
			    if (strlen(parms.cluster_tag))
				    continue;
			    break;
			}
			print_status(&parms, 1);
		}
	}
	exit(0);
}

void
dsw_display_bitmap(int argc, char *argv[])
{
	dsw_config_t parms;
	int	in_config;

	if (argc != 2)
		usage(gettext("Incorrect number of arguments"));

	in_config = find_shadow_config(argv[1], &parms, NULL);
	if (!in_config) {
		(void) printf(gettext(
		    "Volume is not in configuration file\n"), NULL);
		(void) fflush(stdout);
		strncpy(parms.master_vol, argv[1], DSW_NAMELEN);
		parms.master_vol[DSW_NAMELEN] = '\0';
	}

	bitmap_op(parms.shadow_vol, 1, 0, 0, 0);
	exit(0);
}


/*ARGSUSED*/
void
dsw_version(int argc, char *argv[])
{
	iiversion();
	exit(0);
}

void
dsw_reset(int argc, char *argv[])
{
	exit(dsw_group_or_single_op(argc, argv, reset));
}

void
dsw_overflow(int argc, char *argv[])
{
	if (argc != 2)
		usage(gettext("Incorrect number of arguments"));

	exit(overflow(argv[1]));
}

void
dsw_wait(int argc, char *argv[])
{
	exit(dsw_group_or_single_op(argc, argv, wait_for_copy));
}

/*ARGSUSED*/
void
dsw_list_volumes(int argc, char *argv[])
{
	if (argc != 1)
		usage(gettext("Incorrect number of arguments"));

	list_volumes();
	exit(0);
}

void
dsw_export(int argc, char *argv[])
{
	if (argc != 2)
		usage(gettext("Incorrect number of arguments"));

	exit(dsw_group_or_single_op(argc, argv, export));
}

void
dsw_detach(int argc, char *argv[])
{
	(void) dsw_group_or_single_op(argc, argv, detach);
	exit(0);
}

void
import(char *shadow_volume, char *bitmap_volume)
{
	dsw_config_t parms = {0};
	int rc = 0;
	char	shd_dg[DSW_NAMELEN];
	char	bmp_dg[DSW_NAMELEN];

	/*
	 * If importing a shadow volume and the shadow volume is already
	 * configured, we only support this if we are in a Sun Cluster
	 * and the current user specified a cluster tag of -C local
	 */
	if (find_shadow_config(shadow_volume, &parms, NULL)) {
		dsw_error(gettext("Can't import volume on same node"), NULL);
	}

	switch (check_cluster()) {
	case II_CLUSTER:
	case II_CLUSTER_LCL:
		(void) check_resource_group(shadow_volume);
		if (cfg_cluster_tag) { /* check all volumes are in same dg */
			if (cfg_dgname(shadow_volume, shd_dg, DSW_NAMELEN)
			    == NULL)
				dsw_error(gettext("Shadow volume not in a"
				    " disk group"), NULL);
			if (cfg_dgname(bitmap_volume, bmp_dg, DSW_NAMELEN)
			    == NULL)
				dsw_error(gettext("Bitmap volume not in a"
				    " disk group"), NULL);
			if (strcmp(bmp_dg, shd_dg) != 0)
				dsw_error(gettext("Bitmap volume not in"
				    " same disk group as shadow set members"),
				    NULL);
		}
		break;
	case II_NOT_CLUSTER:
		/* do nothing */
		break;
	default:
		dsw_error(gettext(
		    "Unexpected return from check_cluster()"), NULL);
	}

	/* Local configuration volumes */
	if (cfg_load_dsvols(cfg) < 0 || cfg_load_shadows(cfg) < 0) {
		dsw_error(gettext("Unable to parse config file"), NULL);
	}

	reload_vols = LD_DSVOLS | LD_SHADOWS;
	conform_name(&shadow_volume);
	strcpy(parms.master_vol, II_IMPORTED_SHADOW);
	strncpy(parms.shadow_vol, shadow_volume, DSW_NAMELEN);
	parms.shadow_vol[DSW_NAMELEN-1] = '\0';
	strncpy(parms.bitmap_vol, bitmap_volume, DSW_NAMELEN);
	parms.bitmap_vol[DSW_NAMELEN-1] = '\0';
	parms.flag = DSW_GOLDEN;

	spcs_log("ii", NULL, gettext("Import %s %s"),
	    parms.shadow_vol, parms.bitmap_vol);
	parms.status = spcs_s_ucreate();
	rc = do_ioctl(dsw_fd, DSWIOC_IMPORT, &parms);
	if (rc == -1) {
		spcs_log("ii", NULL, gettext("Import failed %s %s"),
		    parms.shadow_vol, parms.bitmap_vol);
		dsw_error(gettext("Import failed"), &parms.status);
	}
	if (perform_autosv()) {
		if (cfg_vol_enable(cfg, shadow_volume, cfg_cluster_tag, "ii")
		    < 0) {
			dsw_error(gettext("SV-enable failed"), NULL);
		}
		/* cfg_commit is called by add_cfg_entry below */
	}
	spcs_s_ufree(&parms.status);
	add_cfg_entry(&parms);
}

void
dsw_import(int argc, char *argv[])
{
	if (argc != 3)
		usage(gettext("Incorrect number of arguments"));
	import(argv[1], argv[2]);

	exit(0);
}

void
join(char *shadow_volume, char *bitmap_file)
{
	dsw_ioctl_t shd;
	dsw_config_t conf;
	dsw_bitmap_t parms;
	int rc = 0;
	int size;
	FILE *bmpfp;
	uchar_t *shd_bitmap = 0;
	ii_header_t header;
	char dgname[DSW_NAMELEN];

	if (!find_shadow_config(shadow_volume, &conf, &shd))
		dsw_error(gettext("Volume is not in a Point-in-Time Copy "
				"group"), NULL);

	/* If this is an exportable shadow in the cluster, change ctag */
	if (strlen(conf.cluster_tag) &&
	    (cfg_dgname(shadow_volume, dgname, sizeof (dgname))))
		cfg_resource(cfg, cfg_cluster_tag = strdup(dgname));

	if (cfg_load_dsvols(cfg) < 0 || cfg_load_shadows(cfg) < 0) {
		dsw_error(gettext("Unable to parse config file"), NULL);
	}
	reload_vols = LD_DSVOLS | LD_SHADOWS;
	conform_name(&shadow_volume);

	if ((bmpfp = fopen(bitmap_file, "r")) == NULL) {
		perror(bitmap_file);
		(void) fprintf(stderr,
		    gettext("Can't open imported bitmap volume\n"));
		exit(1);
	}

	if (fread(&header, sizeof (header), 1, bmpfp) != 1) {
		(void) fprintf(stderr,
		    gettext("Can't read imported bitmap volume\n"));
		exit(1);
	}

	/* See if this is a bitmap header */
	switch (header.ii_magic) {
	case DSW_DIRTY:		/* A copy of a enable bitmap volume */
	case DSW_CLEAN:
		check_action(gettext("Use the never imported bitmap?"));
		break;
	case DSW_INVALID:	/* A valid diskable secondary bitmap */
		break;
	default:
		(void) fprintf(stderr,
		    gettext("Secondary bitmap is not a valid bitmap volume\n"));
		exit(1);
	}

	size = FBA_SIZE(header.ii_copyfba - header.ii_shdfba);
	if ((shd_bitmap = malloc(size)) == NULL) {
		perror("malloc");
		exit(1);
	}

	if (fseek(bmpfp, FBA_SIZE(header.ii_shdfba), SEEK_SET)) {
		perror("fseek");
		exit(1);
	}

	if (fread(shd_bitmap, 1, size, bmpfp) != size) {
		(void) fprintf(stderr,
		    gettext("Can't read imported bitmap volume\n"));
		exit(1);
	}

	(void) fclose(bmpfp);

	strncpy(parms.shadow_vol, shadow_volume, DSW_NAMELEN);
	parms.shadow_vol[DSW_NAMELEN-1] = '\0';
	parms.shd_bitmap = shd_bitmap;
	parms.shd_size = size;
	parms.copy_bitmap = NULL;
	parms.copy_size = 0;

	spcs_log("ii", NULL, gettext("Join %s %s"),
	    parms.shadow_vol, bitmap_file);
	parms.status = spcs_s_ucreate();
	rc = do_ioctl(dsw_fd, DSWIOC_JOIN, &parms);
	if (rc == -1) {
		spcs_log("ii", NULL, gettext("Join failed %s %s"),
		    parms.shadow_vol, bitmap_file);
		dsw_error(gettext("Join failed"), &parms.status);
	}
	if (perform_autosv()) {
		rc = cfg_vol_enable(cfg, shadow_volume, cfg_cluster_tag, "ii");
		if (rc < 0) {
			dsw_error(gettext("SV-enable failed"), NULL);
		}
		cfg_commit(cfg);
	}
	spcs_s_ufree(&parms.status);
}

int
params(char *shadow_volume)
{
	char *delay = param_delay;
	char *unit = param_unit;
	dsw_copyp_t parms;
	int rc = 0;
	int get = 0;
	int new_delay;
	int new_unit;

	strncpy(parms.shadow_vol, shadow_volume, DSW_NAMELEN);
	parms.shadow_vol[DSW_NAMELEN-1] = '\0';
	if (delay == NULL || unit == NULL) {
		get = 1;
		parms.copy_delay = -1;
		parms.copy_unit = -1;
	} else {
		new_delay = parms.copy_delay = convert_int(delay);
		new_unit = parms.copy_unit = convert_int(unit);
	}

	parms.status = spcs_s_ucreate();
	rc = do_ioctl(dsw_fd, DSWIOC_COPYP, &parms);
	if (rc == -1) {
		(void) fprintf(stderr,
		    gettext("Parameter ranges are delay(%d - %d), "
		    "units(%d - %d)\n"), MIN_THROTTLE_DELAY, MAX_THROTTLE_DELAY,
		    MIN_THROTTLE_UNIT, MAX_THROTTLE_UNIT);
		dsw_error(gettext("Set Copy Parameters failed"), &parms.status);
	}
	if (!get)
		spcs_log("ii", NULL, gettext("Changed copy parameters %s from "
		    "%d %d to %d %d"), parms.shadow_vol, parms.copy_delay,
		    parms.copy_unit, new_delay, new_unit);
	else
		(void) printf(gettext("volume: %s\ncopy delay: %d\ncopy unit:"
		    " %d\n"), parms.shadow_vol, parms.copy_delay,
		    parms.copy_unit);
	spcs_s_ufree(&parms.status);
	return (0);
}

static void
do_attach(dsw_config_t *parms)
{
	dsw_config_t io;
	int rc;
	int check = 0;

	spcs_log("ii", NULL, gettext("Attach %s %s"),
		parms->shadow_vol, parms->bitmap_vol);
	parms->status = spcs_s_ucreate();
	rc = do_ioctl(dsw_fd, DSWIOC_OATTACH, parms);
	if (rc == -1) {
		check = 1;
		/* if overflow() fails, it calls dsw_error to exit */
		(void) overflow(parms->bitmap_vol);
	}
	spcs_s_ufree(&parms->status);
	if (check == 1) {
		if (!find_shadow_config(parms->shadow_vol, &io, NULL))
			dsw_error(
			    gettext("Volume is not in a Point-in-Time Copy "
			    "group"), NULL);
		strncpy(io.bitmap_vol, parms->bitmap_vol, DSW_NAMELEN);
		io.bitmap_vol[DSW_NAMELEN-1] = '\0';
		io.status = spcs_s_ucreate();
		if (do_ioctl(dsw_fd, DSWIOC_OATTACH, &io) == -1) {
			spcs_log("ii", NULL, gettext("Attach failed %s %s"),
			    io.shadow_vol, parms->bitmap_vol);
			dsw_error(gettext("Attach failed"), &io.status);
		}
		spcs_s_ufree(&io.status);
	}
}

int
attach(char *shadow_volume)
{
	dsw_config_t parms;
	dsw_stat_t args;
	char	shd_dg[DSW_NAMELEN];
	char	ovr_dg[DSW_NAMELEN];

	switch (check_cluster()) {
	case II_CLUSTER:
	case II_CLUSTER_LCL:
		(void) check_resource_group(shadow_volume);
		if (cfg_cluster_tag) { /* check all volumes are in same dg */
			if (cfg_dgname(shadow_volume, shd_dg, DSW_NAMELEN)
			    == NULL)
				dsw_error(gettext("Shadow volume not in a"
				    " disk group"), NULL);
			if (cfg_dgname(overflow_file, ovr_dg, DSW_NAMELEN)
			    == NULL)
				dsw_error(gettext("Overflow volume not in a"
				    " disk group"), NULL);
			if (strcmp(ovr_dg, shd_dg) != 0)
				dsw_error(gettext("Overflow volume not in"
				    " same disk group as shadow set members"),
				    NULL);
		}
		break;
	case II_NOT_CLUSTER:
		/* do nothing */
		break;
	default:
		dsw_error(gettext(
		    "Unexpected return from check_cluster()"), NULL);
	}

	/* assure that the overflow_file is not an II volume */
	if (find_any_cf_line(overflow_file))
		dsw_error(gettext(
			"Overflow volume is already in a Point-in-Time Copy "
			"group"), NULL);

	/* use find_shadow_config() to find setnumber */
	if (!find_shadow_config(shadow_volume, &parms, NULL))
		dsw_error(gettext("Volume is not in a Point-in-Time Copy "
			"group"), NULL);

	/* can only attach an overflow volume to dependent, compact shadow */
	strncpy(args.shadow_vol, shadow_volume, DSW_NAMELEN);
	args.shadow_vol[DSW_NAMELEN-1] = '\0';

	args.status = spcs_s_ucreate();
	if ((do_ioctl(dsw_fd, DSWIOC_STAT, &args) == -1) ||
	    !(args.stat & DSW_TREEMAP))
		dsw_error(gettext("Not a compact dependent shadow"), NULL);

	/* bitmap_vol is overloaded */
	strncpy(parms.bitmap_vol, overflow_file, DSW_NAMELEN);
	parms.bitmap_vol[DSW_NAMELEN-1] = '\0';

	do_attach(&parms);

	/* add overflow to cfg line */
	(void) sprintf(key, "ii.set%d.overflow", setnumber);
	if (cfg_put_cstring(cfg, key, overflow_file,
		    strlen(overflow_file)) < 0) {
		perror("cfg_put_cstring");
	}
	(void) cfg_commit(cfg);
	return (0);
}

void
dsw_join(int argc, char *argv[])
{
	if (argc != 3)
		usage(gettext("Incorrect number of arguments"));

	join(argv[1], argv[2]);
	exit(0);
}

void
dsw_params(int argc, char *argv[])
{
	if (argc != 4 && argc != 2 && argc != 0)
		usage(gettext("Incorrect number of arguments"));

	if ((argc == 4) || (argc == 2)) {
		param_delay = argv[1];
		param_unit = argv[2];
		if (argc == 4) {
			argv[1] = argv[3];
			argv[2] = NULL;
		}
	}
	exit(dsw_group_or_single_op(2, argv, params));
}

/*ARGSUSED*/
void
dsw_attach(int argc, char *argv[])
{
	overflow_file = argv[1];
	argv[1] = argv[2];
	(void) dsw_group_or_single_op(2, argv, attach);
	exit(0);
}

/*ARGSUSED*/
void
dsw_olist(int argc, char *argv[])
{
	char	*sp, *overflow_list, **vol;
	int	count, i;
	ENTRY	item, *found;
	char	key[ CFG_MAX_KEY ], buf[ CFG_MAX_BUF ];

	overflow_list = get_overflow_list();

	/* count entries */
	count = 0;
	for (sp = overflow_list; *sp; sp += DSW_NAMELEN) {
		++count;
	}

	/* create hash (adding room for suspended overflow volumes) */
	if (hcreate(count + 1024) == 0) {
		dsw_error(gettext("Out of memory creating lookup table"), NULL);
		/*NOTREACHED*/
	}

	if (count > 0) {
		/* create memory to store copy of list */
		vol = (char **)calloc(count, sizeof (char *));
		if (!vol) {
			dsw_error(
			    gettext("Out of memory creating lookup table"),
			    NULL);
			/*NOTREACHED*/
		}

		/* fill hash */
		for (i = 0, sp = overflow_list; *sp; sp += DSW_NAMELEN, i++) {

			/* make copy of string */
			vol[ i ] = (char *)malloc(DSW_NAMELEN + 1);
			strncpy(vol[ i ], sp, DSW_NAMELEN);
			vol[ i ][ DSW_NAMELEN ] = '\0';

			item.key = vol[ i ];
			item.data = (char *)0;
			(void) hsearch(item, ENTER);
		}
	}

	/* loop through config file entries */
	i = 0;
	cfg_rewind(cfg, CFG_SEC_CONF);

	/*CONSTCOND*/
	while (1) {
		++i;
		(void) snprintf(key, CFG_MAX_KEY, "ii.set%d.overflow", i);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0) {
			break;
		}

		/* has this set got an overflow volume? */
		if (!*buf) {
			continue;
		}

		/* look up overflow in hash */
		item.key = buf;
		if (count > 0 && (found = hsearch(item, FIND)) != NULL) {
			if (0 == (int)found->data) {
				(void) printf("%s\n", buf);
				found->data = (char *)1;
				(void) hsearch(*found, ENTER);
			}
		} else {
			/* must be part of a suspended set */
			(void) printf("%s (attached to suspended set)\n", buf);
			item.key = buf;
			item.data = (char *)1;
			(void) hsearch(item, ENTER);
		}
	}

	exit(0);
}

void
dsw_ostat(int argc, char *argv[])
{
	dsw_ostat_t	args;
	int	stat_flags;

	if (argc != 2)
		usage(gettext("Incorrect number of arguments"));

	strncpy(args.overflow_vol, argv[1], DSW_NAMELEN);
	args.overflow_vol[DSW_NAMELEN-1] = '\0';

	args.status = spcs_s_ucreate();
	if (do_ioctl(dsw_fd, DSWIOC_OSTAT2, &args) == -1)
		dsw_error(gettext("Stat failed"), &args.status);
	spcs_s_ufree(&args.status);

	if ((args.hversion >= 1) && (args.hmagic == II_OMAGIC)) {
		stat_flags = args.flags;
		if (stat_flags & IIO_CNTR_INVLD)
			(void) printf(gettext("Clean shutdown of volume "
			"sets associated with overflow volume "
			"did not occur.\n"
			"Overflow counters will be inconsistent "
			"until new point-in-time(s) are taken.\n"));
	}
	(void) printf(gettext("Total number of attached shadows: %d\n"),
	    args.drefcnt);
	(void) printf(gettext("Number of currently attached shadows: %d\n"),
	    args.crefcnt);
	(void) printf(gettext("Total number of chunks: %lld\n"), args.nchunks);
	(void) printf(gettext("Number of chunks ever allocated: %lld\n"),
	    args.used);
	(void) printf(gettext("Number of used chunks: %lld\n"),
		(args.nchunks - args.unused));
	(void) printf(gettext("Number of unused chunks: %lld\n"), args.unused);
	exit(0);
}

/*ARGSUSED*/
void
dsw_move_2_group(int argc, char *argv[])
{
	dsw_config_t parms;
	dsw_movegrp_t movegrp;
	grptag_t *gdata;
	int waserr = 0;

	/* handle move to NULL group, or group of all spaces or tabs */
	strncpy(movegrp.new_group, group_name, DSW_NAMELEN);
	if ((strlen(group_name) == 0) || (strcspn(group_name, " \t") == 0)) {
		group_name = "-";
		bzero(movegrp.new_group, DSW_NAMELEN);
		gdata = NULL;
	} else {
		/* get the ctag for this group (if any) */
		gdata = (grptag_t *)nsc_lookup(volhash, group_name);
	}

	movegrp.status = spcs_s_ucreate();

	for (++argv; *argv; argv++) {
		if (!find_shadow_config(*argv, &parms, NULL))
			dsw_error(gettext("Volume is not in a Point-in-Time "
					"Copy group"), NULL);

		/* ensure the ctag matches the group */
		if (gdata && *gdata->ctag) {
			if (strncmp(parms.cluster_tag, gdata->ctag,
			    DSW_NAMELEN) != 0) {
				(void) fprintf(stderr, "%s: %s %s %s\n", cmdnam,
				    gettext("unable to move set"), *argv,
				    gettext("into new group - cluster "
				    "resource mismatch"));
				waserr = 1;
				continue;
			}
		}

		/* move the set in the kernel */
		strncpy(movegrp.shadow_vol, parms.shadow_vol, DSW_NAMELEN);
		if (do_ioctl(dsw_fd, DSWIOC_MOVEGRP, &movegrp) < 0)
			dsw_error(gettext("Failed to move group in kernel"),
			    NULL);

		/* now update the config */
		(void) sprintf(key, "ii.set%d.group", setnumber);
		if (cfg_put_cstring(cfg, key, group_name,
		    strlen(group_name)) < 0) {
			perror("cfg_put_cstring");
		}
		(void) cfg_commit(cfg);
	}
	spcs_s_ufree(&movegrp.status);
	cfg_close(cfg);
	exit(waserr);
}

void
dsw_list_groups()
{
	FILE *pfp;

	if ((pfp = popen("/usr/bin/sort -u", "w")) == NULL) {
		dsw_error(gettext("Can't open sort program"), NULL);
	}

	(void) fflush(stdout);
	for (setnumber = 1; /*CSTYLED*/; setnumber++) {
		(void) snprintf(key, sizeof (key), "ii.set%d.group", setnumber);
		if (cfg_get_cstring(cfg, key, buf, sizeof (buf)) < 0)
			break;

		/* skip if shadow set is not in any group */
		if (strcmp(buf, "") == 0)
			continue;
		(void) fprintf(pfp, "%s\n", buf);
	}
	(void) pclose(pfp);
}

void
dsw_list_group_volumes()
{
	FILE *pfp;

	if (find_group_members(group_name) < 1)
		dsw_error(gettext("Group does not exist or has no members"),
			NULL);

	if ((pfp = popen("/usr/bin/sort -u", "w")) == NULL) {
		dsw_error(gettext("Can't open sort program"), NULL);
	}

	(void) fflush(stdout);
	for (; *group_volumes; group_volumes++)
		(void) fprintf(pfp, "%s\n", *group_volumes);
	(void) pclose(pfp);
}

static void
load_ii_vols(CFGFILE *cfg)
{
	int set, entries;
	char *mst, *shd, *buf, **entry;
	char *ctag, *group;
	mstcount_t *mdata;
	shdvol_t *sdata;
	grptag_t *gdata;
	static int whinged = 0;

	if (volhash) {
		return;
	}

	volhash = nsc_create_hash();
	cfg_rewind(cfg, CFG_SEC_CONF);
	entries = cfg_get_section(cfg, &entry, "ii");
	for (set = 1; set <= entries; set++) {
		buf = entry[set - 1];

		/* grab master volume name */
		mst = strtok(buf, " ");
		if (!mst) {
			free(buf);
			break;
		}

		/* grab shadow, group & cnode fields */
		shd = strtok(NULL, " ");
		(void) strtok(NULL, " ");	/* bitmap */
		(void) strtok(NULL, " ");	/* mode */
		(void) strtok(NULL, " ");	/* overflow */
		ctag = strtok(NULL, " ");	/* cnode */
		(void) strtok(NULL, " ");	/* options */
		group = strtok(NULL, " ");	/* group */

		/* Fix optional tags */
		if (ctag)
			ctag += strspn(ctag, "-");
		if (group)
			group += strspn(group, "-");

		/* If cluster tags don't match, skip record */
		if ((cfg_cluster_tag && strcmp(ctag, cfg_cluster_tag)) ||
		    (!cfg_cluster_tag && strlen(ctag))) {
			free(buf);
			continue;
		}

		/* master volume, may be duplicates */
		mdata = (mstcount_t *)nsc_lookup(volhash, mst);
		if (mdata) {
			++mdata->count;
		} else {
			mdata = (mstcount_t *)malloc(sizeof (mstcount_t));
			mdata->count = 1;
			(void) nsc_insert_node(volhash, mdata, mst);
		}

		/* grab shadow volume name */
		sdata = (shdvol_t *)malloc(sizeof (shdvol_t));
		strncpy(sdata->master, mst, DSW_NAMELEN);
		(void) nsc_insert_node(volhash, sdata, shd);

		/* No need to continue if no groups or ctags */
		if (!group || !*group || !ctag || !*ctag) {
			free(buf);
			continue;
		}

		gdata = (grptag_t *)nsc_lookup(volhash, group);
		if (gdata) {
			/* group already exists - check ctag */
			if (*ctag &&
			    (strncmp(ctag, gdata->ctag, DSW_NAMELEN) != 0)) {
				if (!whinged) {
					printf(gettext("Warning: multiple "
					    "cluster resource groups "
					    "defined within a single "
					    "I/O group\n"));
					whinged = 1;
				}
			}
		} else {
			gdata = (grptag_t *)malloc(sizeof (grptag_t));
			strncpy(gdata->ctag, ctag, DSW_NAMELEN);
			(void) nsc_insert_node(volhash, gdata, group);
		}

		free(buf);
	}

	/* free up any leftovers */
	while (set < entries)
		free(entry[set++]);
	if (entries)
		free(entry);
}

static void
unload_ii_vols()
{
	nsc_remove_all(volhash, free);
	volhash = 0;
}

static int
perform_autosv()
{
	static int result;
	static int calculated = 0;
	int rc;

#ifdef DEBUG
	if (getenv("II_SET_CLUSTER"))
		return (1);
#endif

	if (calculated) {
		return (result);
	}

	/*
	 * we only perform auto-sv if we're in a sun cluster or if
	 * we're on a standalone system.  I.e. we don't do auto-sv on Harry
	 */
	rc = check_cluster();

	if (II_NOT_CLUSTER == rc) {
		result = 1;
	} else {
		result = cfg_issuncluster();
	}

	calculated = 1;
	return (result);
}

/*
 * Returns true if set has had the shadow volume exported.
 * Returns false if shadow volume is not exported, or set is suspended.
 */
static int
is_exported(char *set)
{
	dsw_stat_t args;
	int rc;

	strncpy(args.shadow_vol, set, DSW_NAMELEN);
	args.shadow_vol[DSW_NAMELEN-1] = '\0';
	args.status = spcs_s_ucreate();

	rc = do_ioctl(dsw_fd, DSWIOC_STAT, &args);
	spcs_s_ufree(&args.status);

	if (-1 == rc) {
		/* set must be suspended, or being disabled */
		return (0);
	}

	return ((args.stat & DSW_SHDEXPORT) == DSW_SHDEXPORT);
}

static void
conform_name(char **path)
{
	char *cfgname;
	int rc = cfg_get_canonical_name(cfg, *path, &cfgname);

	if (rc < 0) {
		dsw_error(gettext("Unable to parse config file"), NULL);
	}
	if (rc) {
		printf("  '%s'\n%s\n  '%s'\n", *path,
		    gettext("is currently configured as"), cfgname);
		check_action(gettext("Perform operation with indicated volume"
		    " name?"));
		*path = cfgname;
		/*
		 * NOTE: *path ought to be deallocated ('free(*path)') after
		 * we're done with it, but since this routine is called just
		 * before we exit, it doesn't really matter
		 */
	}
}

/*
 * verify_groupname(char *, int);
 *
 * Check the group name for the following rules:
 *	1. The name does not start with a '-'
 *	2. The name does not contain any space characters as defined by
 *	   isspace(3C).
 * If either of these rules are broken, error immediately. The check for a
 * leading dash can be skipped if the 'testDash' argument is false. This is to
 * allow for the '-g -L' functionality.
 *
 */
static void
verify_groupname(char *grp, int testDash)
{
	int i;

	if (testDash && grp[0] == '-') {
		errno = EINVAL;
		dsw_error(gettext("group name cannot start with a '-'"), NULL);
	}

	for (i = 0; grp[i] != '\0'; i++) {
		if (isspace(grp[i])) {
			errno = EINVAL;
			dsw_error(gettext("group name cannot contain a space"),
			    NULL);
		}
	}
}

void
check_iishadow(char *shadow_vol) {
	int i;
	int entries;
	char **entry;
	char *shost;
	char *svol;
	char *buf;
	void *librdc;

	/*
	 * See if librdc is around
	 * If not, we can just return
	 */
	if (librdc = dlopen(RDC_LIB, RTLD_LAZY | RTLD_GLOBAL))
		self_check = (int (*)(char *)) dlsym(librdc, "self_check");
	else {
		return;
	}

	entry = NULL;
	entries = cfg_get_section(cfg, &entry, "sndr");
	for (i = 0; i < entries; i++) {
		buf = entry[i];

		(void) strtok(buf, " ");	/* phost */
		(void) strtok(NULL, " ");	/* primary */
		(void) strtok(NULL, " ");	/* pbitmap */
		shost = strtok(NULL, " ");	/* shost */
		svol = strtok(NULL, " ");	/* secondary */

		if (self_check(shost) && (strcmp(shadow_vol, svol) == 0)) {
			free(buf);
			if (entries)
				free(entry);
			errno = EINVAL;
			dsw_error(gettext(
			    "shadow volume is in use as SNDR secondary volume"),
			    NULL);
		}
		free(buf);
	}

	(void) dlclose(librdc);
	if (entries)
		free(entry);
}
