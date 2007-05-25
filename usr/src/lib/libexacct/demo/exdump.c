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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/acct.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <fcntl.h>
#include <exacct.h>
#include <pwd.h>
#include <grp.h>
#include <project.h>
#include <stdlib.h>
#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifndef _LP64
#define	FMT_UINT64	"%-15llu"
#else
#define	FMT_UINT64	"%-15lu"
#endif

#define	MAX_DEPTH	25		/* maximum depth level */

static int vflag = 0;

typedef struct catalog_item {
	int	type;
	char	*name;
} catalog_item_t;

/*
 * The actual constants are defined in <sys/exacct_catalog.h>.
 */
static catalog_item_t catalog[] = {
	{ EXD_VERSION,			"version" },
	{ EXD_FILETYPE,			"filetype" },
	{ EXD_CREATOR,			"creator" },
	{ EXD_HOSTNAME,			"hostname" },

	{ EXD_GROUP_HEADER,		"group-header" },
	{ EXD_GROUP_PROC,		"group-proc" },
	{ EXD_GROUP_TASK,		"group-task" },
	{ EXD_GROUP_LWP,		"group-lwp" },
	{ EXD_GROUP_FLOW,		"group-flow" },
	{ EXD_GROUP_PROC_TAG,		"group-proc-tag" },
	{ EXD_GROUP_TASK_TAG,		"group-task-tag" },
	{ EXD_GROUP_LWP_TAG,		"group-lwp-tag" },
	{ EXD_GROUP_PROC_PARTIAL,	"group-proc-partial" },
	{ EXD_GROUP_TASK_PARTIAL,	"group-task-partial" },
	{ EXD_GROUP_TASK_INTERVAL,	"group-task-interval" },

	{ EXD_PROC_PID,			"pid" },
	{ EXD_PROC_ANCPID, 		"ppid" },
	{ EXD_PROC_UID,			"uid" },
	{ EXD_PROC_GID,			"gid" },
	{ EXD_PROC_TASKID,		"taskid" },
	{ EXD_PROC_PROJID,		"projid" },
	{ EXD_PROC_HOSTNAME,		"hostname" },
	{ EXD_PROC_COMMAND,		"command" },
	{ EXD_PROC_WAIT_STATUS,		"wait-status" },
	{ EXD_PROC_START_SEC,		"start-sec" },
	{ EXD_PROC_START_NSEC,		"start-nsec" },
	{ EXD_PROC_FINISH_SEC,		"finish-sec" },
	{ EXD_PROC_FINISH_NSEC,		"finish-nsec" },
	{ EXD_PROC_CPU_USER_SEC,	"cpu-user-sec" },
	{ EXD_PROC_CPU_USER_NSEC,	"cpu-user-nsec" },
	{ EXD_PROC_CPU_SYS_SEC,		"cpu-sys-sec" },
	{ EXD_PROC_CPU_SYS_NSEC,	"cpu-sys-nsec" },
	{ EXD_PROC_TTY_MAJOR,		"tty-major" },
	{ EXD_PROC_TTY_MINOR,		"tty-minor" },
	{ EXD_PROC_FAULTS_MAJOR,	"faults-major" },
	{ EXD_PROC_FAULTS_MINOR,	"faults-minor" },
	{ EXD_PROC_MESSAGES_RCV,	"msgs-recv" },
	{ EXD_PROC_MESSAGES_SND,	"msgs-snd" },
	{ EXD_PROC_BLOCKS_IN,		"blocks-in" },
	{ EXD_PROC_BLOCKS_OUT,		"blocks-out" },
	{ EXD_PROC_CHARS_RDWR,		"chars-rdwr" },
	{ EXD_PROC_CONTEXT_VOL,		"ctxt-vol" },
	{ EXD_PROC_CONTEXT_INV,		"ctxt-inv" },
	{ EXD_PROC_SIGNALS,		"signals" },
	{ EXD_PROC_SWAPS,		"swaps" },
	{ EXD_PROC_SYSCALLS,		"syscalls" },
	{ EXD_PROC_TAG,			"proc-tag" },
	{ EXD_PROC_ACCT_FLAGS,		"acctflags" },
	{ EXD_PROC_ZONENAME,		"zone" },
	{ EXD_PROC_MEM_RSS_AVG_K,	"memory-rss-avg-k" },
	{ EXD_PROC_MEM_RSS_MAX_K,	"memory-rss-max-k" },

	{ EXD_TASK_TASKID,		"taskid" },
	{ EXD_TASK_ANCTASKID,		"anctaskid" },
	{ EXD_TASK_PROJID,		"projid" },
	{ EXD_TASK_HOSTNAME,		"hostname" },
	{ EXD_TASK_START_SEC,		"start-sec" },
	{ EXD_TASK_START_NSEC,		"start-nsec" },
	{ EXD_TASK_FINISH_SEC,		"finish-sec" },
	{ EXD_TASK_FINISH_NSEC,		"finish-nsec" },
	{ EXD_TASK_CPU_USER_SEC,	"cpu-user-sec" },
	{ EXD_TASK_CPU_USER_NSEC,	"cpu-user-nsec" },
	{ EXD_TASK_CPU_SYS_SEC,		"cpu-sys-sec" },
	{ EXD_TASK_CPU_SYS_NSEC,	"cpu-sys-nsec" },
	{ EXD_TASK_FAULTS_MAJOR,	"faults-major" },
	{ EXD_TASK_FAULTS_MINOR,	"faults-minor" },
	{ EXD_TASK_MESSAGES_RCV,	"msgs-recv" },
	{ EXD_TASK_MESSAGES_SND,	"msgs-snd" },
	{ EXD_TASK_BLOCKS_IN,		"blocks-in" },
	{ EXD_TASK_BLOCKS_OUT,		"blocks-out" },
	{ EXD_TASK_CHARS_RDWR,		"chars-rdwr" },
	{ EXD_TASK_CONTEXT_VOL,		"ctxt-vol" },
	{ EXD_TASK_CONTEXT_INV,		"ctxt-inv" },
	{ EXD_TASK_SIGNALS,		"signals" },
	{ EXD_TASK_SWAPS,		"swaps" },
	{ EXD_TASK_SYSCALLS,		"syscalls" },
	{ EXD_TASK_TAG,			"task-tag" },
	{ EXD_TASK_ZONENAME,		"zone" },

	{ EXD_FLOW_V4SADDR,		"src-addr-v4" },
	{ EXD_FLOW_V4DADDR,		"dest-addr-v4" },
	{ EXD_FLOW_V6SADDR,		"src-addr-v6" },
	{ EXD_FLOW_V6DADDR,		"dest-addr-v6" },
	{ EXD_FLOW_SPORT,		"src-port" },
	{ EXD_FLOW_DPORT,		"dest-port" },
	{ EXD_FLOW_PROTOCOL,		"protocol" },
	{ EXD_FLOW_DSFIELD,		"diffserv-field" },
	{ EXD_FLOW_NBYTES,		"total-bytes" },
	{ EXD_FLOW_NPKTS,		"total-packets" },
	{ EXD_FLOW_CTIME,		"creation-time" },
	{ EXD_FLOW_LSEEN,		"last-seen" },
	{ EXD_FLOW_PROJID,		"projid" },
	{ EXD_FLOW_UID,			"uid" },
	{ EXD_FLOW_ANAME,		"action-name" },

	{ EXD_NONE,			"none" }
};

static void disp_obj(ea_object_t *o, int indent);

/*
 * Convert catalog ID into catalog name.
 */
static char *
catalog_name(int type)
{
	int i = 0;

	while (catalog[i].type != EXD_NONE) {
		if (catalog[i].type == type)
			return (catalog[i].name);
		i++;
	}

	return ("unknown");
}

/*
 * Display port information, if available
 */
static void
disp_port(uint16_t port)
{
	struct servent *port_info;

	port_info = getservbyport(htons(port), NULL);
	if (port_info != NULL) {
		(void) printf("%s", port_info->s_name);
	}
}

/*
 * Display host name for a given IP address if available.
 */
static void
disp_host(char *addr, int family)
{
	struct hostent *phe;
	uint_t len;
	int error_num;

	len = (family == AF_INET) ? sizeof (struct in_addr) :
	    sizeof (struct in6_addr);

	if ((phe = getipnodebyaddr(addr, len, family, &error_num)) != NULL) {
		(void) printf("%s", phe->h_name);
	}
}

/*
 * Display protocol information, if available.
 */
static void
disp_proto(uint8_t protocol)
{
	struct protoent *proto_ent;

	proto_ent = getprotobynumber(protocol);
	if (proto_ent != NULL) {
		(void) printf("%s", proto_ent->p_name);
	}

}

/*
 * Display recursively exacct objects in a given embedded group.
 */
static void
disp_embedded_group(ea_object_t *eo, int indent)
{
	while (eo != NULL) {
		disp_obj(eo, indent + 1);
		if (eo->eo_type == EO_GROUP)
			disp_embedded_group(eo->eo_group.eg_objs, indent + 1);
		eo = eo->eo_next;
	}
}

/*
 * Display the data stored in a given exacct object.
 */
static void
disp_obj(ea_object_t *o, int indent)
{
	char objname[30] = "                              ";
	int eol = 1;

	if (indent > MAX_DEPTH) {
		objname[0] = '>';
		indent = 1;
	}

	(void) printf("%6x\t", (o->eo_catalog & EXD_DATA_MASK));
	(void) snprintf(objname + indent, 30 - indent, "%-s",
	    catalog_name(o->eo_catalog & EXD_DATA_MASK));
	(void) printf("%-30s\t", objname);

	switch (o->eo_catalog & EXT_TYPE_MASK) {
	case EXT_UINT8:
		(void) printf("%-15u", o->eo_item.ei_uint8);
		if (vflag &&
		    ((o->eo_catalog & EXD_DATA_MASK) == EXD_FLOW_PROTOCOL)) {
			disp_proto(o->eo_item.ei_uint8);
		}
		break;
	case EXT_UINT16:
		(void) printf("%-15u", o->eo_item.ei_uint16);
		if (vflag &&
		    (((o->eo_catalog & EXD_DATA_MASK) == EXD_FLOW_SPORT) ||
		    ((o->eo_catalog & EXD_DATA_MASK) == EXD_FLOW_DPORT))) {
			disp_port(o->eo_item.ei_uint16);
		}
		break;
	case EXT_UINT32:
		switch (o->eo_catalog & EXD_DATA_MASK) {
		case EXD_PROC_WAIT_STATUS:
			{
				int wstat = o->eo_item.ei_uint32;

				if (vflag) {
					if (WIFEXITED(wstat))
						(void) printf("%-14d exit",
						    WEXITSTATUS(wstat));
					else if (WIFSIGNALED(wstat))
						(void) printf("%14d, signal",
						    WTERMSIG(wstat));
					else
						(void) printf("%d", wstat);
				} else {
					(void) printf("%d", wstat);
				}
			}
			break;
		case EXD_PROC_UID:
			{
				uid_t uid = o->eo_item.ei_uint32;

				(void) printf("%-15u", uid);
				if (vflag) {
					struct passwd *pwd;
					if ((pwd = getpwuid(uid)) != NULL)
						(void) printf("%s",
						    pwd->pw_name);
				}
			}
			break;
		case EXD_PROC_GID:
			{
				gid_t gid = o->eo_item.ei_uint32;

				(void) printf("%-15u", gid);
				if (vflag) {
					struct group *grp;
					if ((grp = getgrgid(gid)) != NULL)
						(void) printf("%s",
						    grp->gr_name);
				}
			}
			break;
		case EXD_PROC_PROJID:
		case EXD_TASK_PROJID:
			{
				projid_t projid = o->eo_item.ei_uint32;

				(void) printf("%-15lu", projid);
				if (vflag) {
					struct project proj;
					char projbuf[PROJECT_BUFSZ];

					if (getprojbyid(projid, &proj, projbuf,
					    PROJECT_BUFSZ) != NULL)
						(void) printf("%s",
						    proj.pj_name);
				}
			}
			break;
		case EXD_PROC_ACCT_FLAGS:
			{
				int flag = o->eo_item.ei_uint32;

				(void) printf("%-15u", flag);
				if (vflag) {
					if (flag & AFORK)
						(void) printf("FORK ");
					if (flag & ASU)
						(void) printf("SU");
				}
			}
			break;
		case EXD_FLOW_V4SADDR:
			/* FALLTHRU */
		case EXD_FLOW_V4DADDR:
			{
				char str[INET_ADDRSTRLEN];
				uint32_t addr = htonl(o->eo_item.ei_uint32);

				(void) printf("%-15s",
				    inet_ntop(AF_INET, &addr, str,
				    INET_ADDRSTRLEN));
				if (vflag) {
					disp_host((char *)&addr, AF_INET);
				}
			}
			break;
		default:
			(void) printf("%u", o->eo_item.ei_uint32);
		}
		break;
	case EXT_UINT64:
		{
			time_t _time;
			char timebuf[20];

			(void) printf(FMT_UINT64, o->eo_item.ei_uint64);
			if (!vflag)
				break;
			if (ea_match_object_catalog(o, EXD_TASK_START_SEC) ||
			    ea_match_object_catalog(o, EXD_TASK_FINISH_SEC) ||
			    ea_match_object_catalog(o, EXD_PROC_START_SEC) ||
			    ea_match_object_catalog(o, EXD_PROC_FINISH_SEC) ||
			    ea_match_object_catalog(o, EXD_FLOW_LSEEN) ||
			    ea_match_object_catalog(o, EXD_FLOW_CTIME)) {
				_time = o->eo_item.ei_uint64;
				(void) strftime(timebuf, sizeof (timebuf),
				    "%D %T", localtime(&_time));
				(void) fputs(timebuf, stdout);
			}
		}
		break;
	case EXT_DOUBLE:
		(void) printf("%f", o->eo_item.ei_double);
		break;
	case EXT_STRING:
		(void) printf("\"%s\"", o->eo_item.ei_string);
		break;
	case EXT_RAW:
		switch (o->eo_catalog & EXD_DATA_MASK) {
		case EXD_FLOW_V6SADDR:
			/* FALLTHRU */
		case EXD_FLOW_V6DADDR:
			{
				in6_addr_t *addr;
				char str[INET6_ADDRSTRLEN];

				addr = (in6_addr_t *)o->eo_item.ei_raw;
				(void) printf("%-28s", inet_ntop(AF_INET6,
				    &addr->s6_addr, str, INET6_ADDRSTRLEN));
				if (vflag) {
					disp_host((char *)&addr->s6_addr,
					    AF_INET6);
				}

			}
			break;
		default:
			{
				ea_size_t size = o->eo_item.ei_size;
				char *buf = o->eo_item.ei_raw;
				uint64_t i;

				for (i = 0; i < size && i < 6; i++)
					(void) printf("0x%2X ", buf[i]);
				if (size > 6)
					(void) printf("...");
			}
		}
		break;
	case EXT_GROUP:
		(void) printf("[group of %u object(s)]", o->eo_group.eg_nobjs);
		break;
	case EXT_EXACCT_OBJECT:
		/*
		 * Embedded exacct records.
		 */
		{
			ea_object_type_t ot;
			ea_object_t *op;
			ea_object_t *eo;

			ot = ea_unpack_object(&op, EUP_ALLOC,
			    o->eo_item.ei_object, o->eo_item.ei_size);

			if (ot == EO_ERROR) {
				(void) printf("error: couldn't unpack embedded "
				    "object\n");
				break;
			}
			eol = 0;
			if (ot == EO_GROUP) {
				(void) printf("[embedded group of %u "
				    "object(s)]\n", op->eo_group.eg_nobjs);
				eo = op->eo_group.eg_objs;
				disp_embedded_group(eo, indent);
			} else {
				(void) printf("[embedded object]\n");
				disp_obj(op, indent);
			}
			ea_free_object(op, EUP_ALLOC);
		}
		break;
	default:
		(void) printf("[complex value]");
		break;
	}

	if (eol)
		(void) printf("\n");

}

/*
 * Read and display a group of exacct objects from the file.
 */
static void
disp_group(ea_file_t *ef, uint_t nobjs, int indent)
{
	uint_t i;

	for (i = 0; i < nobjs; i++) {
		ea_object_t scratch;
		int res;

		if ((res = ea_get_object(ef, &scratch)) == -1) {
			(void) fprintf(stderr,
			    "bad file: ea_get_object()==%d\n", res);
			exit(2);
		}

		disp_obj(&scratch, indent + 1);

		if (scratch.eo_type == EO_GROUP)
			disp_group(ef, scratch.eo_group.eg_nobjs, indent + 1);
		else
			(void) ea_free_item(&scratch, EUP_ALLOC);
	}
}

static void
usage()
{
	(void) fprintf(stderr, "Usage: exdump [-v] <file>\n");
	exit(2);
}

int
main(int argc, char *argv[])
{
	ea_file_t ef;
	ea_object_t scratch;
	char *fname;
	int opt;

	while ((opt = getopt(argc, argv, "v")) != EOF) {
		switch (opt) {
		case 'v':
			vflag = 1;
			break;
		default:
			usage();
		}
	}

	if (argc == optind)
		usage();
	if (argc > optind)
		fname = argv[optind++];
	if (argc > optind)
		usage();

	if (ea_open(&ef, fname, NULL,
	    vflag ? EO_NO_VALID_HDR : 0, O_RDONLY, 0) == -1) {
		(void) fprintf(stderr, "exdump: cannot open %s\n", fname);
		return (1);
	}

	bzero(&scratch, sizeof (ea_object_t));
	while (ea_get_object(&ef, &scratch) != -1) {
		disp_obj(&scratch, 0);
		if (scratch.eo_type == EO_GROUP)
			disp_group(&ef, scratch.eo_group.eg_nobjs, 0);
		else
			(void) ea_free_item(&scratch, EUP_ALLOC);
		(void) bzero(&scratch, sizeof (ea_object_t));
	}

	(void) ea_close(&ef);
	return (0);
}
