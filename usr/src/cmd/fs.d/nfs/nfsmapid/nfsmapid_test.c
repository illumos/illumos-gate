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

/*
 * Test nfsmapid. This program is not shipped on the binary release.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stropts.h>
#include <strings.h>
#include <signal.h>
#include <fcntl.h>
#include <locale.h>
#include <unistd.h>
#include <netconfig.h>
#include <door.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <rpcsvc/nfs4_prot.h>
#include <nfs/nfsid_map.h>

static char nobody_str[] = "nobody";
static int nfs_idmap_str_uid(utf8string *, uid_t *);
static int nfs_idmap_uid_str(uid_t, utf8string *);
static int nfs_idmap_str_gid(utf8string *, gid_t *);
static int nfs_idmap_gid_str(gid_t, utf8string *);

static void
usage()
{
	fprintf(stderr, gettext(
	    "\nUsage:\tstr2uid string\n"
	    "\tstr2gid string\n"
	    "\tuid2str uid\n"
	    "\tgid2str gid\n"
	    "\techo string\n"
	    "\texit|quit\n"));
}

static int read_line(char *buf, int size)
{
	int len;

	/* read the next line. If cntl-d, return with zero char count */
	printf(gettext("\n> "));

	if (fgets(buf, size, stdin) == NULL)
		return (0);

	len = strlen(buf);
	buf[--len] = '\0';
	return (len);
}

static int
parse_input_line(char *input_line, int *argc, char ***argv)
{
	const char nil = '\0';
	char *chptr;
	int chr_cnt;
	int arg_cnt = 0;
	int ch_was_space = 1;
	int ch_is_space;

	chr_cnt = strlen(input_line);

	/* Count the arguments in the input_line string */

	*argc = 1;

	for (chptr = &input_line[0]; *chptr != nil; chptr++) {
		ch_is_space = isspace(*chptr);
		if (ch_is_space && !ch_was_space) {
			(*argc)++;
		}
		ch_was_space = ch_is_space;
	}

	if (ch_was_space) {
		(*argc)--;
	}	/* minus trailing spaces */

	/* Now that we know how many args calloc the argv array */

	*argv = calloc((*argc)+1, sizeof (char *));
	chptr = (char *)(&input_line[0]);

	for (ch_was_space = 1; *chptr != nil; chptr++) {
		ch_is_space = isspace(*chptr);
		if (ch_is_space) {
			*chptr = nil;	/* replace each space with nil  */
		} else if (ch_was_space) {	/* begining of word? */
			(*argv)[arg_cnt++] = chptr;	/* new argument ? */
		}

		ch_was_space = ch_is_space;
	}

	return (chr_cnt);
}

char *
mapstat(int stat)
{
	switch (stat) {
	case NFSMAPID_OK:
		return ("NFSMAPID_OK");
	case NFSMAPID_NUMSTR:
		return ("NFSMAPID_NUMSTR");
	case NFSMAPID_UNMAPPABLE:
		return ("NFSMAPID_UNMAPPABLE");
	case NFSMAPID_INVALID:
		return ("NFSMAPID_INVALID");
	case NFSMAPID_INTERNAL:
		return ("NFSMAPID_INTERNAL");
	case NFSMAPID_BADDOMAIN:
		return ("NFSMAPID_BADDOMAIN");
	case NFSMAPID_BADID:
		return ("NFSMAPID_BADID");
	case NFSMAPID_NOTFOUND:
		return ("NFSMAPID_NOTFOUND");
	case EINVAL:
		return ("EINVAL");
	case ECOMM:
		return ("ECOMM");
	case ENOMEM:
		return ("ENOMEM");
	default:
		printf(" unknown error %d ", stat);
		return ("...");
	}
}

int
do_test(char *input_buf)
{
	int argc, seal_argc;
	char **argv, **argv_array;
	char *cmd;
	int i, bufsize = 512;
	char str_buf[512];
	utf8string str;
	uid_t uid;
	gid_t gid;
	int stat;

	argv = 0;

	if (parse_input_line(input_buf, &argc, &argv) == 0) {
		printf(gettext("\n"));
		return (1);
	}

	/*
	 * remember argv_array address, which is memory calloc'd by
	 * parse_input_line, so it can be free'd at the end of the loop.
	 */
	argv_array = argv;

	if (argc < 1) {
		usage();
		free(argv_array);
		return (0);
	}

	cmd = argv[0];

	if (strcmp(cmd, "str2uid") == 0) {
		if (argc < 2) {
			usage();
			free(argv_array);
			return (0);
		}
		str.utf8string_val = argv[1];
		str.utf8string_len = strlen(argv[1]);
		stat = nfs_idmap_str_uid(&str, &uid);
		printf(gettext("%u stat=%s \n"), uid, mapstat(stat));

	} else if (strcmp(cmd, "str2gid") == 0) {
		if (argc < 2) {
			usage();
			free(argv_array);
			return (0);
		}
		str.utf8string_val = argv[1];
		str.utf8string_len = strlen(argv[1]);
		stat = nfs_idmap_str_gid(&str, &gid);
		printf(gettext("%u stat=%s \n"), gid, mapstat(stat));

	} else if (strcmp(cmd, "uid2str") == 0) {
		if (argc < 2) {
			usage();
			free(argv_array);
			return (0);
		}
		uid = atoi(argv[1]);
		bzero(str_buf, bufsize);
		str.utf8string_val = str_buf;
		stat = nfs_idmap_uid_str(uid, &str);
		printf(gettext("%s stat=%s\n"), str.utf8string_val,
		    mapstat(stat));

	} else if (strcmp(cmd, "gid2str") == 0) {
		if (argc < 2) {
			usage();
			free(argv_array);
			return (0);
		}
		gid = atoi(argv[1]);
		bzero(str_buf, bufsize);
		str.utf8string_val = str_buf;
		stat = nfs_idmap_gid_str(gid, &str);
		printf(gettext("%s stat=%s\n"), str.utf8string_val,
		    mapstat(stat));

	} else if (strcmp(cmd, "echo") == 0) {
		for (i = 1; i < argc; i++)
			printf("%s ", argv[i]);
		printf("\n");
	} else if (strcmp(cmd, "exit") == 0 ||
	    strcmp(cmd, "quit") == 0) {
		printf(gettext("\n"));
		free(argv_array);
		return (1);

	} else
		usage();

	/* free argv array */
	free(argv_array);
	return (0);
}


int
main(int argc, char **argv)
{
	char buf[512];
	int len, ret;

	(void) setlocale(LC_ALL, "");
#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	""
#endif
	(void) textdomain(TEXT_DOMAIN);

	usage();

	/*
	 * Loop, repeatedly calling parse_input_line() to get the
	 * next line and parse it into argc and argv. Act on the
	 * arguements found on the line.
	 */

	do {
		len = read_line(buf, 512);
		if (len)
			ret = do_test(buf);
	} while (!ret);

	return (0);
}

#define	NFSMAPID_DOOR	"/var/run/nfsmapid_door"

/*
 * Gen the door handle for connecting to the nfsmapid process.
 * Keep the door cached.  This call may be made quite often.
 */
int
nfs_idmap_doorget()
{
	static int doorfd = -1;

	if (doorfd != -1)
		return (doorfd);

	if ((doorfd = open(NFSMAPID_DOOR, O_RDWR)) == -1) {
		perror(NFSMAPID_DOOR);
		exit(1);
	}
	return (doorfd);
}

/*
 * Convert a user utf-8 string identifier into its local uid.
 */
int
nfs_idmap_str_uid(utf8string *u8s, uid_t *uid)
{
	struct mapid_arg *mapargp;
	struct mapid_res mapres;
	struct mapid_res *mapresp = &mapres;
	struct mapid_res *resp = mapresp;
	door_arg_t	door_args;
	int		doorfd;
	int		error = 0;
	static int	msg_done = 0;

	if (!u8s || !u8s->utf8string_val || !u8s->utf8string_len ||
	    (u8s->utf8string_val[0] == '\0')) {
		error = EINVAL;
		goto s2u_done;
	}

	if (bcmp(u8s->utf8string_val, "nobody", 6) == 0) {
		/*
		 * If "nobody", just short circuit and bail
		 */
		*uid = UID_NOBODY;
		goto s2u_done;

	}

	if ((mapargp = malloc(MAPID_ARG_LEN(u8s->utf8string_len))) == NULL) {
		(void) fprintf(stderr, "Unable to malloc %d bytes\n",
		    MAPID_ARG_LEN(u8s->utf8string_len));
		error = ENOMEM;
		goto s2u_done;
	}
	mapargp->cmd = NFSMAPID_STR_UID;
	mapargp->u_arg.len = u8s->utf8string_len;
	(void) bcopy(u8s->utf8string_val, mapargp->str, mapargp->u_arg.len);
	mapargp->str[mapargp->u_arg.len] = '\0';

	door_args.data_ptr = (char *)mapargp;
	door_args.data_size = MAPID_ARG_LEN(mapargp->u_arg.len);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = (char *)mapresp;
	door_args.rsize = sizeof (struct mapid_res);

	/*
	 * call to the nfsmapid daemon
	 */
	if ((doorfd = nfs_idmap_doorget()) == -1) {
		if (!msg_done) {
			fprintf(stderr, "nfs_idmap_str_uid: Can't communicate"
			    " with mapping daemon nfsmapid\n");
			msg_done = 1;
		}
		error = ECOMM;
		free(mapargp);
		goto s2u_done;
	}

	if (door_call(doorfd, &door_args) == -1) {
		perror("door_call failed");
		error = EINVAL;
		free(mapargp);
		goto s2u_done;
	}

	free(mapargp);

	resp = (struct mapid_res *)door_args.rbuf;
	switch (resp->status) {
	case NFSMAPID_OK:
		*uid = resp->u_res.uid;
		break;

	case NFSMAPID_NUMSTR:
		*uid = resp->u_res.uid;
		error = resp->status;
		goto out;

	default:
	case NFSMAPID_UNMAPPABLE:
	case NFSMAPID_INVALID:
	case NFSMAPID_INTERNAL:
	case NFSMAPID_BADDOMAIN:
	case NFSMAPID_BADID:
	case NFSMAPID_NOTFOUND:
		error = resp->status;
		goto s2u_done;
	}

s2u_done:
	if (error)
		*uid = UID_NOBODY;
out:
	if (resp != mapresp)
		munmap(door_args.rbuf, door_args.rsize);
	return (error);
}

/*
 * Convert a uid into its utf-8 string representation.
 */
int
nfs_idmap_uid_str(uid_t uid,		/* uid to map */
		utf8string *u8s)	/* resulting utf-8 string for uid */
{
	struct mapid_arg maparg;
	struct mapid_res mapres;
	struct mapid_res *mapresp = &mapres;
	struct mapid_res *resp = mapresp;
	door_arg_t	door_args;
	int		doorfd;
	int		error = 0;
	static int	msg_done = 0;

	if (uid == UID_NOBODY) {
		u8s->utf8string_len = strlen("nobody");
		u8s->utf8string_val = nobody_str;
		goto u2s_done;
	}

	/*
	 * Daemon call...
	 */
	maparg.cmd = NFSMAPID_UID_STR;
	maparg.u_arg.uid = uid;

	door_args.data_ptr = (char *)&maparg;
	door_args.data_size = sizeof (struct mapid_arg);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = (char *)mapresp;
	door_args.rsize = sizeof (struct mapid_res);

	if ((doorfd = nfs_idmap_doorget()) == -1) {
		if (!msg_done) {
			fprintf(stderr, "nfs_idmap_uid_str: Can't "
			    "communicate with mapping daemon nfsmapid\n");
			msg_done = 1;
		}
		error = ECOMM;
		goto u2s_done;
	}

	if (door_call(doorfd, &door_args) == -1) {
		perror("door_call failed");
		error = EINVAL;
		goto u2s_done;
	}

	resp = (struct mapid_res *)door_args.rbuf;
	if (resp->status != NFSMAPID_OK) {
		error = resp->status;
		goto u2s_done;
	}

	if (resp->u_res.len != strlen(resp->str)) {
		(void) fprintf(stderr, "Incorrect length %d expected %d\n",
		    resp->u_res.len, strlen(resp->str));
		error = NFSMAPID_INVALID;
		goto u2s_done;
	}
	u8s->utf8string_len = resp->u_res.len;
	bcopy(resp->str, u8s->utf8string_val, u8s->utf8string_len);

u2s_done:
	if (resp != mapresp)
		munmap(door_args.rbuf, door_args.rsize);
	return (error);
}

/*
 * Convert a group utf-8 string identifier into its local gid.
 */
int
nfs_idmap_str_gid(utf8string *u8s, gid_t *gid)
{
	struct mapid_arg *mapargp;
	struct mapid_res mapres;
	struct mapid_res *mapresp = &mapres;
	struct mapid_res *resp = mapresp;
	door_arg_t	door_args;
	int		doorfd;
	int		error = 0;
	static int	msg_done = 0;

	if (!u8s || !u8s->utf8string_val || !u8s->utf8string_len ||
	    (u8s->utf8string_val[0] == '\0')) {
		error = EINVAL;
		goto s2g_done;
	}

	if (bcmp(u8s->utf8string_val, "nobody", 6) == 0) {
		/*
		 * If "nobody", just short circuit and bail
		 */
		*gid = GID_NOBODY;
		goto s2g_done;

	}

	if ((mapargp = malloc(MAPID_ARG_LEN(u8s->utf8string_len))) == NULL) {
		(void) fprintf(stderr, "Unable to malloc %d bytes\n",
		    MAPID_ARG_LEN(u8s->utf8string_len));
		error = ENOMEM;
		goto s2g_done;
	}
	mapargp->cmd = NFSMAPID_STR_GID;
	mapargp->u_arg.len = u8s->utf8string_len;
	(void) bcopy(u8s->utf8string_val, mapargp->str, mapargp->u_arg.len);
	mapargp->str[mapargp->u_arg.len] = '\0';

	door_args.data_ptr = (char *)mapargp;
	door_args.data_size = MAPID_ARG_LEN(mapargp->u_arg.len);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = (char *)mapresp;
	door_args.rsize = sizeof (struct mapid_res);

	/*
	 * call to the nfsmapid daemon
	 */
	if ((doorfd = nfs_idmap_doorget()) == -1) {
		if (!msg_done) {
			fprintf(stderr, "nfs_idmap_str_uid: Can't communicate"
			    " with mapping daemon nfsmapid\n");
			msg_done = 1;
		}
		error = ECOMM;
		free(mapargp);
		goto s2g_done;
	}

	if (door_call(doorfd, &door_args) == -1) {
		perror("door_call failed");
		error = EINVAL;
		free(mapargp);
		goto s2g_done;
	}

	free(mapargp);

	resp = (struct mapid_res *)door_args.rbuf;
	switch (resp->status) {
	case NFSMAPID_OK:
		*gid = resp->u_res.gid;
		break;

	case NFSMAPID_NUMSTR:
		*gid = resp->u_res.gid;
		error = resp->status;
		goto out;

	default:
	case NFSMAPID_UNMAPPABLE:
	case NFSMAPID_INVALID:
	case NFSMAPID_INTERNAL:
	case NFSMAPID_BADDOMAIN:
	case NFSMAPID_BADID:
	case NFSMAPID_NOTFOUND:
		error = resp->status;
		goto s2g_done;
	}

s2g_done:
	if (error)
		*gid = GID_NOBODY;
out:
	if (resp != mapresp)
		munmap(door_args.rbuf, door_args.rsize);
	return (error);
}

/*
 * Convert a gid into its utf-8 string representation.
 */
int
nfs_idmap_gid_str(gid_t gid,		/* gid to map */
		utf8string *g8s)	/* resulting utf-8 string for gid */
{
	struct mapid_arg maparg;
	struct mapid_res mapres;
	struct mapid_res *mapresp = &mapres;
	struct mapid_res *resp = mapresp;
	door_arg_t	door_args;
	int		error = 0;
	int		doorfd;
	static int	msg_done = 0;

	if (gid == GID_NOBODY) {
		g8s->utf8string_len = strlen("nobody");
		g8s->utf8string_val = nobody_str;
		goto g2s_done;

	}

	/*
	 * Daemon call...
	 */
	maparg.cmd = NFSMAPID_GID_STR;
	maparg.u_arg.gid = gid;

	door_args.data_ptr = (char *)&maparg;
	door_args.data_size = sizeof (struct mapid_arg);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = (char *)mapresp;
	door_args.rsize = sizeof (struct mapid_res);

	if ((doorfd = nfs_idmap_doorget()) == -1) {
		if (!msg_done) {
			fprintf(stderr, "nfs_idmap_uid_str: Can't "
			    "communicate with mapping daemon nfsmapid\n");
			msg_done = 1;
		}
		error = ECOMM;
		goto g2s_done;
	}

	if (door_call(doorfd, &door_args) == -1) {
		perror("door_call failed");
		error = EINVAL;
		goto g2s_done;
	}

	resp = (struct mapid_res *)door_args.rbuf;
	if (resp->status != NFSMAPID_OK) {
		error = resp->status;
		goto g2s_done;
	}

	if (resp->u_res.len != strlen(resp->str)) {
		(void) fprintf(stderr, "Incorrect length %d expected %d\n",
		    resp->u_res.len, strlen(resp->str));
		error = NFSMAPID_INVALID;
		goto g2s_done;
	}
	g8s->utf8string_len = resp->u_res.len;
	bcopy(resp->str, g8s->utf8string_val, g8s->utf8string_len);

g2s_done:
	if (resp != mapresp)
		munmap(door_args.rbuf, door_args.rsize);
	return (error);
}
