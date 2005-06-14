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
 * Copyright 2000-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "rdlist.h"
#include "rdtable.h"

static int	list_read(int listt, int elemn);
static int	lwp_write(list_t *list);
static int	lwp_read(int lwpn);

/*
 * This procedure stores the current state of the lists (lwps, processes,
 * users and project) into the file defined by 'file'.
 * param file - the file name to be used
 * return 0, or -1 on error and store the error message in
 *		the global buffer 'errmsg'.
 */
int
list_store(char *file)
{
	int	storefd;
	time_t  tv;
	char 	*tstr;
	int 	ret = -1;

	if ((storefd = open(file, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR))
			== -1) {
		format_err("can't open list db: %s\n", file);
		(void) fprintf(stderr, errmsg);
		return (-1);
	}
	log_msg("writing persistence file: %s\n", file);

	/*
	 * the next do {..} while (false); statement is a replacement
	 * of goto;
	 */
	do {
		if (open_prot(storefd, "w") == -1) {
			format_err("can't open list db: %s\n", file);
			(void) fprintf(stderr, errmsg);
			break;
		}
		(void) time(&tv);
		tstr = ctime(&tv);
		if (wr_string("# RDS data base file generated on: ") == -1)
			break;
		if (wr_string(tstr) == -1)
			break;
		if (wr_value(LTDB_VERSION_KEY, LTDB_VERSION) == -1)
			break;
		if (wr_value(LTDB_TIMESTAMP, tv) == -1)
			break;
		/* we will write 4 lists */
		if (wr_lshead(4) != 0) {
			format_err("can't write into list db: %s\n",
					"./listdb");
			break;
		}
		if (list_write(L_LWP, 0) == -1)
			break;
		if (list_write(L_PRC_SI, 0) == -1)
			break;
		if (list_write(L_USR_SI, 0) == -1)
			break;
		if (list_write(L_PRJ_SI, 0) == -1)
			break;
		ret = 0;
	} while (ret);

	if (ret == 0) {
		struct stat stat_buf;
		(void) fstat(storefd, &stat_buf);
		log_msg("wrote: %ld bytes\n", stat_buf.st_size);
	}

	/* close_prot(); */
	(void) close(storefd);

	return (ret);
}

/*
 * This procedure restores the last state of the lists (lwps, processes,
 * users and project) from the file defined by 'file'.
 * param file - the file name to be used
 * return 0, or -1 on error and store the error message in
 *		the global buffer 'errmsg'.
 */
int
list_restore(char *file)
{
	int	storefd;
	int	listt, elemn, listn;
	int64_t	timestamp;
	time_t  tv;
	int	version;
	int 	ret = -1;

	if ((storefd = open(file, O_RDONLY)) == -1)
		return (ret);
	log_msg("reading persistence file: %s\n", file);

	/*
	 * the next do {..} while (false); statement is a replacement
	 * of goto;
	 */
	do {
		if (open_prot(storefd, "r") == -1)
			break;
		if (skip_line() == -1)
			break;
		if ((version = r_value(LTDB_VERSION_KEY)) == -1)
			break;
		if (version != LTDB_VERSION) {
			(void) fprintf(stderr,
				"wrong version %d of db file %s\n",
				version, file);
			break;
		}
		if ((timestamp = r_value(LTDB_TIMESTAMP)) == -1)
			break;
		/* check the file decay time is expired */
		(void) time(&tv);
		if ((tv - timestamp) > LTDB_DECAYTIME)
			break;
		if ((listn = r_lshead()) == -1)
			break;
		while (listn-- > 0) {
			if ((elemn = r_lhead(&listt)) == -1)
				break;
			if (list_read(listt, elemn) != 0) {
				break;
			}
		}
		ret = 0;
	} while (ret);

	if (ret == 0) {
		struct stat stat_buf;
		(void) fstat(storefd, &stat_buf);
		log_msg("read: %ld bytes\n", stat_buf.st_size);
	}

	/* close_prot(); */
	(void) close(storefd);
	(void) unlink(file);
	return (ret);
}

/*
 * This procedure writes a list of type 'listt' according to the
 * rds interface protocol. It uses the already opened and initialized
 * protocol module (see file protocol.[c,h]).
 * param listt	- the type of the list, see rdimpl.h
 * param Po	- print option, if 1 the list will be also printed on stdout.
 * return 0, or -1 on error and store the error message in
 *		the global buffer 'errmsg'.
 */
int
list_write(int listt, int Po)
{
	char		idstr[P_MAXVAL];
	list_t 		*list;
	id_info_t	*id = NULL, *nextid;

	if (listt == L_LWP) {
		return (lwp_write(&lwps));
	} else if (listt == L_SYSTEM) {
		if (wr_lhead(listt, 1) != 0) {
			format_err(
				"RDS protocol error: cannot write list header");
			return (-1);
		}
		(void) snprintf(idstr, sizeof (idstr), "%s", sys_info.name);
		if (wr_element(listt, (char *)(&sys_info), idstr) != 0) {
			format_err(
				"RDS protocol error: cannot write list header");
			return (-1);
		}

	} else {
		switch (listt) {
		case L_PRC_SI : list =  &processes;
				break;
		case L_AC_USR :
		case L_USR_SI : list =  &users;
				break;
		case L_AC_PRJ :
		case L_PRJ_SI : list =  &projects;
				break;
		}
		id = list->l_head;

		if (wr_lhead(listt, list->l_count) != 0) {
			format_err(
				"RDS protocol error: cannot write list header");
			return (-1);
		}
		while (id != NULL) {
			switch (listt) {
			case L_PRC_SI :
				(void) sprintf(idstr, "%d", id->id_pid);
				break;
			case L_AC_USR :
			case L_USR_SI :
				(void) sprintf(idstr, "%d", id->id_uid);
				break;
			case L_AC_PRJ :
			case L_PRJ_SI :
				(void) snprintf(idstr, sizeof (idstr), "%s",
				    id->id_name);
				break;
			}
			if (wr_element(listt, (char *)id, idstr) != 0) {
					format_err(
				"RDS protocol error: cannot write list header");
			}
			if (Po == 1)
				prtelement(stderr, id);
			nextid = id->id_next;
			id = nextid;
		}
	}
	return (0);
}

/*
 * This procedure prints out all list elements on stdout. The elements
 * int the list must be of type id_info_t.
 * param list - the list to be printed
 */
void
list_print(list_t *list, int xid)
{

	id_info_t *id = list->l_head;
	id_info_t *nextid;

	while (id) {
		if (xid == -1) {
			prtelement(stdout, id);
		} else {
			switch (list->l_type) {
			case LT_PROCESS : if (xid == id->id_pid)
						prtelement(stdout, id);
					break;
			case LT_USERS 	: if (xid == id->id_uid)
						prtelement(stdout, id);
					break;
			case LT_PROJECTS : if (xid == id->id_projid)
						prtelement(stdout, id);
					break;
			default: prtelement(stdout, id);
			}
		}
		nextid = id->id_next;
		id = nextid;
	}

}

static int
list_read(int listt, int elemn)
{
	char	idstr[P_MAXVAL];
	list_t	*list;
	id_info_t *id;

	if (listt == L_LWP)
		return (lwp_read(elemn));

	while (elemn-- > 0) {
		switch (listt) {
			case L_PRC_SI 	: list = &processes;
					break;
			case L_USR_SI 	: list = &users;
					break;
			case L_PRJ_SI 	: list = &projects;
					break;
		}

		if (list->l_head == NULL) { /* first element */
			list->l_head = list->l_tail = id =
					Zalloc(sizeof (id_info_t));
			list->l_count++;
		} else {
			/* a new element */
			id = list->l_tail;
			id->id_next = Zalloc(sizeof (id_info_t));
			id->id_next->id_prev = list->l_tail;
			id->id_next->id_next = NULL;
			list->l_tail = id->id_next;
			id = list->l_tail;
			list->l_count++;
		}
		if (r_element((char *)id, idstr) == -1) {
			list_clear(list);
			return (-1);
		}
	}
	return (0);
}

static int
lwp_write(list_t *list)
{
	lwpinfo_t	lwpsi;
	lwp_info_t	*li = NULL, *nextli;

	li = list->l_head;

	if (wr_lhead(L_LWP, list->l_count) != 0) {
		format_err(
			"RDS protocol error: cannot write list header");
		err_exit();
	}
	while (li != NULL) {
		lwpsi.pr_pid	= li->li_psinfo->pr_pid;
		lwpsi.pr_lwpid	= li->li_lwpsinfo->pr_lwpid;

		if (wr_element(L_LWP__I, (char *)&lwpsi, "lwpi") != 0) {
			format_err(
			"RDS protocol error: cannot write list header");
		}
		if (wr_element(L_LWP__U, (char *)&(li->li_usage), "lwpu")
				!= 0) {
			format_err(
			"RDS protocol error: cannot write list header");
		}
		if (wr_element(L_LWP, (char *)li, "lwp") != 0) {
			format_err(
			"RDS protocol error: cannot write list header");
		}
		nextli = li->li_next;
		li = nextli;
	}
	return (0);
}

static int
lwp_read(int lwpn)
{
	lwp_info_t	*lwp;
	lwpinfo_t	lwpsi;

	char		idstr[P_MAXVAL];

	while (lwpn-- > 0) {
		if (r_element((char *)&lwpsi, idstr) == -1) {
			return (-1);
		}
		lwp = list_add_lwp(&lwps, lwpsi.pr_pid, lwpsi.pr_lwpid);
		lwp->li_psinfo->pr_pid		= lwpsi.pr_pid;
		lwp->li_lwpsinfo->pr_lwpid	= lwpsi.pr_lwpid;
		if (r_element((char *)&(lwp->li_usage), idstr) == -1) {
			return (-1);
		}
		if (r_element((char *)lwp, idstr) == -1) {
			return (-1);
		}

	}
	return (0);
}
