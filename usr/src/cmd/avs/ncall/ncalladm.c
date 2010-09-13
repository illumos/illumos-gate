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
#include <sys/stat.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <locale.h>
#include <fcntl.h>
#include <libgen.h>

#include <sys/nsctl/cfg.h>
#include <sys/ncall/ncall.h>

static CFGFILE *cfg;
static int cfg_changed;
static char *progname;
static ncall_node_t *getnodelist(int, int *, int *);


static void
usage(int exitstat)
{
	(void) fprintf(stderr, gettext("usage:\n"));
	(void) fprintf(stderr, gettext("       %s -d\n"), progname);
	(void) fprintf(stderr, gettext("       %s -e\n"), progname);
	(void) fprintf(stderr, gettext("       %s -h\n"), progname);
#ifdef DEBUG
	(void) fprintf(stderr, gettext("       %s -c [nodeid <nodeid>]\n"),
	    progname);
	(void) fprintf(stderr, gettext("       %s -i\n"), progname);
	(void) fprintf(stderr, gettext("       %s -p <host>\n"), progname);
#endif

	(void) fprintf(stderr, gettext("where:\n"));
	(void) fprintf(stderr, gettext("       -d    disable ncall\n"));
	(void) fprintf(stderr, gettext("       -e    enable ncall core\n"));
	(void) fprintf(stderr, gettext("       -h    this help message\n"));
#ifdef DEBUG
	(void) fprintf(stderr,
	    gettext("       -c    set or print ncall configuration\n"));
	(void) fprintf(stderr, gettext("       -i    ncall information\n"));
	(void) fprintf(stderr, gettext("       -p    ncall ping <host>\n"));
#endif

	exit(exitstat);
}


static void
ncall_cfg_open(CFGLOCK lk)
{
	char hostid[32];

	if (cfg != NULL) {
		return;
	}

	if (snprintf(hostid, sizeof (hostid), "%lx", gethostid()) >=
	    sizeof (hostid)) {
		(void) fprintf(stderr, gettext("%s: hostid %lx too large\n"),
		    progname, gethostid());
		exit(1);
	}

	if ((cfg = cfg_open(NULL)) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: unable to access the configuration: %s\n"),
		    progname, cfg_error(NULL));
		exit(1);
	}

	if (!cfg_lock(cfg, lk)) {
		(void) fprintf(stderr,
		    gettext("%s: unable to lock the configuration: %s\n"),
		    progname, cfg_error(NULL));
		exit(1);
	}

	cfg_resource(cfg, hostid);
}


static void
ncall_cfg_close(void)
{
	if (cfg_changed && cfg_commit(cfg) < 0) {
		(void) fprintf(stderr,
		    gettext("%s: unable to update the configuration: %s\n"),
		    progname, cfg_error(NULL));
		exit(1);
	}

	cfg_close(cfg);
	cfg = NULL;
}


/*
 * Get config from dscfg.
 */
static int
get_nodeid_from_cfg(int *nodeid)
{
	char buf[CFG_MAX_BUF];
	int ret = -1;
	int rc;

	ncall_cfg_open(CFG_RDLOCK);

	if (cfg_get_cstring(cfg, "ncallcore.set1", buf, sizeof (buf)) >= 0) {
		rc = sscanf(buf, "%d", nodeid);
		if (rc == 1) {
			ret = 0;
		}
	}

	ncall_cfg_close();

	return (ret);
}


static void
ncall_print(void)
{
	int cfnodeid, clnodeid, rc;

	clnodeid = cfg_issuncluster();

	rc = get_nodeid_from_cfg(&cfnodeid);

	if (rc < 0 && clnodeid > 0) {
		(void) printf(gettext("%s: ncall is using the SunCluster "
		    "nodeid: %d\n"), progname, clnodeid);
	} else if (rc < 0) {
		(void) printf(gettext("%s: ncall is using the default "
		    "nodeid: %d\n"), progname, 0);
	} else {
		(void) printf(gettext("%s: current configuration:\n"),
		    progname);
		/* deliberately not i18n'd - "nodeid" is a keyword */
		(void) printf("nodeid %d\n", cfnodeid);
	}
}


static void
ncall_config(const int nodeid)
{
	char buf[CFG_MAX_BUF];

	ncall_cfg_open(CFG_WRLOCK);

	if (cfg_get_cstring(cfg, "ncallcore.set1", buf, sizeof (buf)) >= 0) {
		/* remove old config */
		if (cfg_put_cstring(cfg, "ncallcore.set1", NULL, 0) < 0) {
			(void) fprintf(stderr,
			    gettext("%s: unable to update the configuration: "
			    "%s\n"), cfg_error(NULL));
			exit(1);
		}
	}

	if (snprintf(buf, sizeof (buf), "%d", nodeid) >= sizeof (buf)) {
		(void) fprintf(stderr,
		    gettext("%s: unable to update configuration: "
		    "data too long\n"), progname);
		exit(1);
	}

	if (cfg_put_cstring(cfg, "ncallcore", buf, sizeof (buf)) < 0) {
		(void) fprintf(stderr,
		    gettext("%s: unable to update the configuration: %s\n"),
		    cfg_error(NULL));
		exit(1);
	}

	cfg_changed = 1;
	ncall_cfg_close();

	(void) printf(gettext("%s: configuration set to:\n"), progname);
	/* deliberately not i18n'd - "nodeid" is a keyword */
	(void) printf("nodeid %d\n", nodeid);
}

#ifdef lint
int
ncalladm_lintmain(int argc, char *argv[])
#else
int
main(int argc, char *argv[])
#endif
{
	const char *dev = "/dev/ncall";
	extern int optind, opterr;
	ncall_node_t nodeinfo, *nodes;
	int nsize;
	int i;
	int cflag, dflag, eflag, iflag, pflag;
	int rc, fd, opt;
	int clnodeid, cfnodeid;
	int up;
	char *cp, *ping;
	int mnode;	/* mirror nodeid */

	(void) setlocale(LC_ALL, "");
	(void) textdomain("ncalladm");

	opterr = 0;
	cflag = dflag = eflag = iflag = pflag = 0;
	ping = NULL;

	progname = basename(argv[0]);

	while ((opt = getopt(argc, argv,
#ifdef DEBUG
	    "cip:"
#endif
	    "deh")) != -1) {
		switch (opt) {
		case 'c':
			cflag = 1;
			break;

		case 'd':
			dflag = 1;
			break;

		case 'e':
			eflag = 1;
			break;

		case 'h':
			usage(0);
			break;

		case 'i':
			iflag = 1;
			break;

		case 'p':
			ping = optarg;
			pflag = 1;
			break;

		default:
			(void) fprintf(stderr, gettext("%s: unknown option\n"),
			    progname);
			usage(1);
			break;
		}
	}

	if (!(cflag || dflag || eflag || iflag || pflag)) {
		usage(1);
	}

	if (argc != optind) {
		if (!cflag ||
		    (argc - optind) != 2 ||
		    strcmp(argv[optind], "nodeid") != 0) {
			usage(1);
		}
	}

	if ((cflag + dflag + eflag + iflag + pflag) > 1) {
		(void) fprintf(stderr,
		    gettext("%s: multiple options are not supported\n"),
		    progname);
		usage(1);
	}

	if (!cflag) {
		fd = open(dev, O_RDONLY);
		if (fd < 0) {
			(void) fprintf(stderr,
			    gettext("%s: unable to open %s: %s\n"),
			    progname, dev, strerror(errno));
			exit(1);
		}
	}

	if (dflag) {
		/* ioctl stop into kernel */
		if (ioctl(fd, NC_IOC_STOP, 0) < 0) {
			(void) fprintf(stderr,
			    gettext("%s: unable to disable ncall: %s\n"),
			    progname, strerror(errno));
			exit(1);
		}
	} else if (eflag) {
		bzero(&nodeinfo, sizeof (nodeinfo));

		clnodeid = cfg_issuncluster();
		cfnodeid = 0;

		/* get node info */
		rc = gethostname(nodeinfo.nc_nodename,
		    sizeof (nodeinfo.nc_nodename));
		if (rc < 0) {
			(void) fprintf(stderr,
			    gettext("%s: unable to determine hostname: %s\n"),
			    progname, strerror(errno));
			exit(1);
		}

		rc = get_nodeid_from_cfg(&cfnodeid);

		if (clnodeid > 0 && rc == 0) {
			/*
			 * check that the nodeids from the cf file and
			 * cluster match.
			 */
			if (clnodeid != cfnodeid) {
				(void) fprintf(stderr,
				    gettext("%s: nodeid from configuration "
				    "(%d) != cluster nodeid (%d)\n"),
				    progname, cfnodeid, clnodeid);
				exit(1);
			}
		}

		if (rc == 0) {
			nodeinfo.nc_nodeid = cfnodeid;
		} else if (clnodeid > 0) {
			nodeinfo.nc_nodeid = clnodeid;
		} else {
			nodeinfo.nc_nodeid = 0;
		}

		/* ioctl node info into kernel and start ncall */
		rc = ioctl(fd, NC_IOC_START, &nodeinfo);
		if (rc < 0) {
			(void) fprintf(stderr,
			    gettext("%s: unable to enable ncall: %s\n"),
			    progname, strerror(errno));
			exit(1);
		}
	}

	if (iflag || pflag) {
		nodes = getnodelist(fd, &nsize, &mnode);

		if (nodes == NULL) {
			(void) fprintf(stderr,
			    gettext("%s: unable to get node info\n"),
			    progname);
			exit(1);
		}
	}

	if (iflag) {
		char *mname;
		char *pnodestr;

		(void) printf(gettext("Self Node Name: %s\n"),
		    nodes[0].nc_nodename);
		(void) printf(gettext("Self Node ID: %d\n"),
		    nodes[0].nc_nodeid);
		/*
		 * determine which slot is the mirror node.
		 */
		if (mnode != -1) {
			for (i = 1; i < nsize; i++) {
				if (nodes[i].nc_nodeid == mnode) {
					mname = nodes[i].nc_nodename;
					break;
				}
			}
		}
		if ((mnode == -1) || (i >= nsize)) {
			mname = gettext("unknown");
			mnode = -1;
		}

		(void) printf(gettext("Mirror Node Name: %s\n"), mname);
		(void) printf(gettext("Mirror Node ID: %d\n"), mnode);
		/*
		 * See if we need to translate the node strings.
		 */
		if (nsize > 1) {
			pnodestr = gettext("Node Name: %s\nNode ID: %d\n");
			for (i = 1; i < nsize; i++) {
				/*
				 * Don't print the mirror twice.
				 */
				if (nodes[i].nc_nodeid != mnode) {
					(void) printf(pnodestr,
					    nodes[i].nc_nodename,
					    nodes[i].nc_nodeid);
				}
			}
		}
	}

	if (pflag) {
		if (strlen(ping) >= sizeof (nodeinfo.nc_nodename)) {
			(void) fprintf(stderr,
			    gettext("%s: hostname '%s' is too long\n"),
			    progname, ping);
			exit(1);
		}
		up = 0;
		if (strcmp(nodes[0].nc_nodename, ping) == 0) {
			up = 1;		/* self */
		} else {
			/* not self, so ask kernel */
			bzero(&nodeinfo, sizeof (nodeinfo));
			/* strlen(ping) checked above */
			(void) strcpy(nodeinfo.nc_nodename, ping);
			up = ioctl(fd, NC_IOC_PING, nodeinfo);
		}

		/* model the ping messages on ping(1m) */

		if (up < 0) {
			(void) fprintf(stderr,
			    gettext("%s: unable to ping host '%s': %s\n"),
			    progname, ping, strerror(errno));
			exit(1);
		} else if (up > 0) {
			(void) printf(gettext("%s is alive\n"), ping);
		} else {
			(void) printf(gettext("no answer from %s\n"), ping);
			exit(1);
		}
	}

	if (iflag || pflag) {
		free(nodes);
	}

	if (cflag) {
		if (argc == optind) {
			ncall_print();
			return (0);
		}

		cp = NULL;
		cfnodeid = (int)strtol(argv[optind+1], &cp, 0);
		if (cp != NULL && *cp != '\0') {
			(void) fprintf(stderr,
			    gettext("%s: nodeid \"%s\" is not an "
			    "integer number\n"), progname, argv[optind+1]);
			exit(1);
		}

		clnodeid = cfg_issuncluster();
		if (clnodeid > 0 && cfnodeid != clnodeid) {
			(void) fprintf(stderr,
			    gettext("%s: nodeid from command line "
			    "(%d) != cluster nodeid (%d)\n"),
			    progname, cfnodeid, clnodeid);
			exit(1);
		}

		ncall_config(cfnodeid);
	}

	if (!cflag) {
		(void) close(fd);
	}

	return (0);
}


/*
 * return a pointer to a list of currently configured
 * nodes.
 * Return the number of nodes via the nodesizep pointer.
 * Return the mirror nodeid via the mirrorp pointer.
 * Return NULL on errors.
 */
static ncall_node_t *
getnodelist(int ifd, int *nodesizep, int *mirrorp)
{
	int maxsize;
	int cnt;
	ncall_node_t *noderet = NULL;
	ncall_node_t *nodelist;
	ncall_node_t thisnode;
	int mirror;
	int nonet;

	/*
	 * Get this host info and mirror nodeid.
	 */
	mirror = ioctl(ifd, NC_IOC_GETNODE, &thisnode);

	if (mirror < 0) {
		return (NULL);
	}

	/*
	 * See if we need to allocate the buffer.
	 */
	nonet = 0;
	maxsize = ioctl(ifd, NC_IOC_GETNETNODES, 0);
	if (maxsize < 1) {
		maxsize = 1;
		nonet = 1;
	}
	nodelist = malloc(sizeof (*nodelist) * maxsize);
	if (nodelist) {
		if (nonet == 0) {
			/*
			 * fetch the node data.
			 */
			cnt = ioctl(ifd, NC_IOC_GETNETNODES, nodelist);
			if (cnt > 0) {
				*nodesizep = cnt;
				noderet = nodelist;
				*mirrorp = mirror;
			} else {
				*nodesizep = 0;
				free(nodelist);
			}
		} else {
			(void) memcpy(nodelist, &thisnode, sizeof (*nodelist));
			*nodesizep = 1;
			noderet = nodelist;
			/*
			 * Although we know the mirror nodeid, there
			 * is no point in returning it as we have
			 * no information about any other hosts.
			 */
			*mirrorp = -1;
		}
	}
	return (noderet);
}
