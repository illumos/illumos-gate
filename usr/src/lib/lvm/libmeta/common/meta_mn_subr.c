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

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

#include <meta.h>
#include <sdssc.h>
#include <arpa/inet.h>
#include <sys/lvm/md_mddb.h>

#define	MAX_LINE_SIZE 1024

/*
 * Maximum amount of time to spend waiting for an ownership change to complete.
 */
static const int OWNER_TIMEOUT = 3;

/*
 * FUNCTION:	meta_is_mn_set()
 * INPUT:       sp      - the set name
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	- 1 if MultiNode set else 0
 * PURPOSE:	checks if the set is a MultiNode set
 */
int
meta_is_mn_set(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	md_set_desc	*sd;

	/* Local set cannot be MultiNode */
	if ((sp == NULL) || (sp->setname == NULL) ||
	    (strcmp(sp->setname, MD_LOCAL_NAME) == 0))
		return (0);
	sd = metaget_setdesc(sp, ep);
	ASSERT(sd != NULL);
	if (sd->sd_flags & MD_SR_MN)
		return (1);
	return (0);
}

/*
 * FUNCTION:	meta_is_mn_name()
 * INPUT:       spp     - ptr to the set name, if NULL the setname is derived
 *			  from the metadevice name (eg set/d10 )
 *		name	- the metadevice/hsp name
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	- 1 if MultiNode set else 0
 * PURPOSE:	checks if the metadevice is in a MultiNode set
 */
int
meta_is_mn_name(
	mdsetname_t	**spp,
	char		*name,
	md_error_t	*ep
)
{
	if (*spp == NULL) {
		char		*cname;

		/*
		 * if the setname is specified in uname and *spp is
		 * not set, then it is setup using that set name value.
		 * If *spp is set and a setname specified in uname and
		 * the set names don't agree then cname will be
		 * returned as NULL
		 */
		cname = meta_canonicalize_check_set(spp, name, ep);
		if (cname == NULL) {
			mdclrerror(ep);
			return (0);
		}

		Free(cname);
	}

	if ((strcmp((*spp)->setname, MD_LOCAL_NAME) != 0) &&
	    (metaget_setdesc(*spp, ep) != NULL) &&
	    ((*spp)->setdesc->sd_flags & MD_SR_MN)) {
		return (1);
	}
	return (0);
}

/*
 * meta_ping_mnset(set_t setno)
 * Send a test message for this set in order to make commd do some init stuff
 * Don't bother changelog.
 * If set is suspended, fail immediately.
 */
void
meta_ping_mnset(set_t setno)
{
	char		*data = "test";
	md_error_t	mde = mdnullerror;
	md_mn_result_t	*resp = NULL;

	(void) mdmn_send_message(setno, MD_MN_MSG_TEST2,
	    MD_MSGF_NO_LOG | MD_MSGF_FAIL_ON_SUSPEND, 0, data,
	    sizeof (data), &resp, &mde);

	if (resp != (md_mn_result_t *)NULL) {
		free_result(resp);
	}
}

/*
 *
 * FUNCTION:	print_stderr
 * INPUT:	errstr	- the error message returned by the command
 *		context	- the context string from metainit -a
 * PURPOSE:	called from meta_mn_send_command to print the error message
 *		to stderr. When context is NO_CONTEXT_STRING, the errstr string
 *		is output unchanged. When context is a string, it is the context
 *		string for the metainit -a command and in this case the errstr
 *		string has to be parsed to extract the command and node name
 *		and to send a message to stderr in the format
 *		command: node: context: error message
 */
static void
print_stderr(
	char	*errstr,
	char	*context
)
{
	char	*command;
	char	*node;
	char	*message;
	int	length = strlen(errstr + 1);

	if (context == NO_CONTEXT_STRING) {
		(void) fprintf(stderr, "%s", errstr);
	} else {
		command = Malloc(length);
		node = Malloc(length);
		message = Malloc(length);
		if (sscanf(errstr, "%[^:]: %[^:]: %[^\n]", command, node,
		    message) == 3) {
			(void) fprintf(stderr, "%s: %s: %s: %s\n", command,
			    node, context, message);
		} else {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "%s: Invalid format error message"), errstr);
		}
		Free(command);
		Free(node);
		Free(message);
	}
}

/*
 * FUNCTION:	meta_mn_send_command()
 * INPUT:	sp	- the set name
 *		argc	- number of arguments
 *		argv	- arg list
 *		flags	- some controlling flags
 *		initall_context	- context string for metainit -a
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	return exitval from mdmn_send_message
 * PURPOSE:	sends the command to the master node for execution
 */
int
meta_mn_send_command(
	mdsetname_t	*sp,
	int		argc,
	char		*argv[],
	int		flags,
	char		*initall_context,
	md_error_t	*ep
)
{
	int		a;
	int		err;
	int		retval;
	int		send_message_flags = MD_MSGF_DEFAULT_FLAGS;
	int		send_message_type;
	char		*cmd;
	md_mn_result_t	*resp = NULL;

	cmd = Malloc(1024);
	(void) strlcpy(cmd, argv[0], 1024);
	for (a = 1; a < argc; a++) {
		/* don't copy empty arguments */
		if (*argv[a] == '\0') {
			continue;
		}
		(void) strcat(cmd, " ");
		(void) strcat(cmd, argv[a]);
	}
	/*
	 * in dryrun mode stop on the first error
	 * use the CMD_RETRY message type if RETRY_BUSY flag set
	 */
	if (flags & MD_DRYRUN)
		send_message_flags |= MD_MSGF_STOP_ON_ERROR;
	if (flags & MD_NOLOG)
		send_message_flags |= MD_MSGF_NO_LOG;
	if (flags & MD_PANIC_WHEN_INCONSISTENT)
		send_message_flags |= MD_MSGF_PANIC_WHEN_INCONSISTENT;
	if (flags & MD_RETRY_BUSY)  {
		send_message_type = MD_MN_MSG_BC_CMD_RETRY;
	} else {
		send_message_type = MD_MN_MSG_BC_CMD;
	}
	err = mdmn_send_message(sp->setno, send_message_type,
	    send_message_flags, 0, cmd, 1024, &resp, ep);

	free(cmd);

	if (err == 0) {
		/*
		 * stderr may be turned off by IGNORE_STDERR
		 * In dryrun we only print stderr if the exit_val is non-zero
		 */
		if ((resp->mmr_err_size != 0) &&
		    ((flags & MD_IGNORE_STDERR) == 0)) {
			if (((flags & MD_DRYRUN) == 0) ||
			    (resp->mmr_exitval != 0)) {
				print_stderr(resp->mmr_err, initall_context);
			}
		}

		/*
		 * If dryrun is set, we don't display stdout,
		 * because the real run has yet to follow.
		 */
		if (((flags & MD_DRYRUN) == 0) && (resp->mmr_out_size != 0)) {
			(void) printf("%s", resp->mmr_out);
		}
		retval = resp->mmr_exitval;
		free_result(resp);
		return (retval);
	}
	if (resp != NULL) {
		if (resp->mmr_comm_state == MDMNE_CLASS_BUSY) {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "rpc.mdcommd currently busy. "
			    "Retry operation later.\n"));
		} else if (resp->mmr_comm_state == MDMNE_NOT_JOINED) {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "Node %s must join the %s multi-owner diskset to "
			    "issue commands.\n"
			    "To join, use: metaset -s %s -j\n"),
			    mynode(), sp->setname, sp->setname);
		} else if (resp->mmr_comm_state == MDMNE_LOG_FAIL) {
			mddb_config_t	c;

			(void) memset(&c, 0, sizeof (c));
			c.c_setno = sp->setno;
			(void) metaioctl(MD_DB_GETDEV, &c, &c.c_mde, NULL);
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "Command not attempted: Unable to log message "
			    "in set %s\n"), sp->setname);
			if (c.c_flags & MDDB_C_STALE) {
				(void) mdmddberror(ep, MDE_DB_STALE,
				    (minor_t)NODEV64, sp->setno, 0, NULL);
				mde_perror(ep, "");
			}
		} else {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "Command failed: Commd State %d "
			    "encountered.\n"), resp->mmr_comm_state);
		}
		free_result(resp);
	} else {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "Command failed: mdmn_send_message returned %d.\n"),
		    err);
	}


	return (1);
}

/*
 * FUNCTION:	meta_mn_send_suspend_writes()
 * INPUT:	mnum	- minor num of mirror
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	return value from mdmn_send_message()
 * PURPOSE:	sends message to all nodes to suspend writes to the mirror.
 */
int
meta_mn_send_suspend_writes(
	minor_t		mnum,
	md_error_t	*ep
)
{
	int			result;
	md_mn_msg_suspwr_t	suspwrmsg;
	md_mn_result_t		*resp = NULL;

	suspwrmsg.msg_suspwr_mnum =  mnum;
	/*
	 * This message is never directly issued.
	 * So we launch it with a suspend override flag.
	 * If the commd is suspended, and this message comes
	 * along it must be sent due to replaying a command or similar.
	 * In that case we don't want this message to be blocked.
	 * If the commd is not suspended, the flag does no harm.
	 */
	result = mdmn_send_message(MD_MIN2SET(mnum),
	    MD_MN_MSG_SUSPEND_WRITES,
	    MD_MSGF_NO_LOG | MD_MSGF_OVERRIDE_SUSPEND, 0,
	    (char *)&suspwrmsg, sizeof (suspwrmsg), &resp, ep);
	if (resp != NULL) {
		free_result(resp);
	}
	return (result);
}

/*
 * Parse the multi-node list file
 *
 * Return Values:	Zero	 - Success
 *			Non Zero - Failure
 *
 * File content:	The content of the nodelist file should consist of
 *			triplets of nodeid, nodename and private interconnect
 *			address seperated by one or more white space.
 * e.g.
 *			1 node_a 192.168.111.3
 *			2 node_b 192.168.111.5
 *
 *			Any missing fields will result in an error.
 */
int
meta_read_nodelist(
	int				*nodecnt,
	mndiskset_membershiplist_t	**nl,
	md_error_t			*ep
)
{
	FILE				*fp = NULL;
	char				line[MAX_LINE_SIZE];
	char				*buf;
	uint_t				i;
	int				sz;
	mndiskset_membershiplist_t	**tailp = nl;

	/* open file */
	if ((fp = fopen(META_MNSET_NODELIST, "r")) == NULL) {
		mndiskset_membershiplist_t	*nlp;
		struct hostent *hp;

		/* return this node with id of 1 */
		nlp = *tailp = Zalloc(sizeof (*nlp));
		tailp = &nlp->next;

		*nodecnt = 1;
		nlp->msl_node_id = 1;
		buf = mynode();
		sz = min(strlen(buf), sizeof (nlp->msl_node_name) - 1);
		(void) strncpy(nlp->msl_node_name, buf, sz);
		nlp->msl_node_name[sz] = '\0';

		/* retrieve info about our host */
		if ((hp = gethostbyname(buf)) == NULL) {
			return (mdsyserror(ep, EADDRNOTAVAIL, buf));
		}
		/* We only do IPv4 addresses, for now */
		if (hp->h_addrtype != AF_INET) {
			return (mdsyserror(ep, EPFNOSUPPORT, buf));
		}
		/* We take the first address only */
		if (*hp->h_addr_list) {
			struct in_addr in;

			(void) memcpy(&in.s_addr, *hp->h_addr_list,
			    sizeof (struct in_addr));
			(void) strncpy(nlp->msl_node_addr, inet_ntoa(in),
			    MD_MAX_NODENAME);
		} else {
			return (mdsyserror(ep, EADDRNOTAVAIL, buf));
		}

		return (0);
	}

	*nl = NULL;
	*nodecnt = 0;

	while ((fp != NULL) && ((buf = fgets(line, sizeof (line) - 1, fp)) !=
	    NULL)) {
		mndiskset_membershiplist_t	*nlp;

		/* skip leading spaces */
		while ((*buf != '\0') && (i = strcspn(buf, " \t\n")) == 0)
			buf++;

		/* skip comments and blank lines */
		if (*buf == '\0' || *buf == '#')
			continue;

		/* allocate memory and set tail pointer */
		nlp = *tailp = Zalloc(sizeof (*nlp));
		tailp = &nlp->next;

		/* parse node id */
		nlp->msl_node_id = strtoul(buf, NULL, 0);
		buf += i;

		/* skip leading spaces */
		while ((*buf != '\0') && (i = strcspn(buf, " \t\n")) == 0)
			buf++;

		/* fields missing, return error */
		if (*buf == '\0' || *buf == '#') {
			meta_free_nodelist(*nl);
			*nl = NULL;
			*nodecnt = 0;

			/* close file and return */
			if ((fp) && (fclose(fp) != 0))
				return (mdsyserror(ep, errno,
				    META_MNSET_NODELIST));

			return (mdsyserror(ep, EINVAL, META_MNSET_NODELIST));
		}

		/* parse node name */
		sz = min(i, sizeof (nlp->msl_node_name) - 1);
		(void) strncpy(nlp->msl_node_name, buf, sz);
		nlp->msl_node_name[sz] = '\0';
		buf += i;

		/* skip leading spaces */
		while ((*buf != '\0') && (i = strcspn(buf, " \t\n")) == 0)
			buf++;

		/* fields missing, return error */
		if (*buf == '\0' || *buf == '#') {
			meta_free_nodelist(*nl);
			*nl = NULL;
			*nodecnt = 0;

			/* close file and return */
			if ((fp) && (fclose(fp) != 0))
				return (mdsyserror(ep, errno,
				    META_MNSET_NODELIST));

			return (mdsyserror(ep, EINVAL, META_MNSET_NODELIST));
		}

		/* parse node address */
		sz = min(i, sizeof (nlp->msl_node_addr) - 1);
		(void) strncpy(nlp->msl_node_addr, buf, sz);
		nlp->msl_node_addr[sz] = '\0';

		++*nodecnt;
	}

	/* close file */
	if ((fp) && (fclose(fp) != 0))
		return (mdsyserror(ep, errno, META_MNSET_NODELIST));

	return (0);
}

/*
 * Populate the multi-node list file from a given list of node id's
 * The nids must have only one node id in each cell. Range of node
 * id's in the form 1-n are not allowed.
 *
 * Return Values:	Zero	 - Success
 *			Non Zero - Failure
 */
int
meta_write_nodelist(
	int		nodecnt,
	char		**nids,
	md_error_t	*ep
)
{
	FILE		*fp = NULL;
	char		name[MAX_LINE_SIZE], addr[MAX_LINE_SIZE];
	uint_t		i, nid;
	struct in_addr	ipaddr;
	int		err = 0;

	/* check if we are running on clustering */
	if ((err = sdssc_bind_library()) != SDSSC_OKAY) {
		return (mdsyserror(ep, err, META_MNSET_NODELIST));
	}

	/* open file for writing */
	if ((fp = fopen(META_MNSET_NODELIST, "w")) == NULL) {
		return (mdsyserror(ep, errno, META_MNSET_NODELIST));
	}

	for (i = 0; i < nodecnt; i++) {
		/* extract the node id */
		errno = 0;
		nid = strtoul(nids[i], NULL, 0);
		if (errno != 0) {
			if ((fp) && (fclose(fp) != 0))
				return (mdsyserror(ep, errno,
				    META_MNSET_NODELIST));

			return (mdsyserror(ep, EINVAL, META_MNSET_NODELIST));
		}

		/* get node name */
		(void) snprintf(name, sizeof (name), "%d", nid);
		sdssc_cm_nid2nm(name);

		/* finally get the private ip address */
		(void) snprintf(addr, sizeof (addr), "%s", name);
		if (sdssc_get_priv_ipaddr(addr, &ipaddr) != SDSSC_OKAY) {
			if ((fp) && (fclose(fp) != 0))
				return (mdsyserror(ep, errno,
				    META_MNSET_NODELIST));

			return (mdsyserror(ep, EINVAL, META_MNSET_NODELIST));
		}

		(void) fprintf(fp, "%d\t%s\t%s\n", nid, name,
		    inet_ntoa(ipaddr));
	}

	/* close file */
	if ((fp) && (fclose(fp) != 0))
		return (mdsyserror(ep, errno, META_MNSET_NODELIST));

	return (0);
}

/*
 * Free node list
 */
void
meta_free_nodelist(
	mndiskset_membershiplist_t	*nl
)
{
	mndiskset_membershiplist_t	*next = NULL;

	for (/* void */; (nl != NULL); nl = next) {
		next = nl->next;
		Free(nl);
	}
}

/*
 * FUNCTION:	meta_mn_send_setsync()
 * INPUT:	sp	- setname
 *		mirnp	- mirror name
 *		size	- buffer size, 0 if none
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	return value from meta_mn_send_command()
 * PURPOSE:  Send a setsync command to all nodes to set resync status
 */

int
meta_mn_send_setsync(
	mdsetname_t		*sp,
	mdname_t		*mirnp,
	daddr_t			size,
	md_error_t		*ep
)
{
	md_mn_msg_setsync_t	setsyncmsg;
	int			ret;
	md_mn_result_t		*resp = NULL;

	setsyncmsg.setsync_mnum = meta_getminor(mirnp->dev);
	setsyncmsg.setsync_copysize = size;
	setsyncmsg.setsync_flags = 0;

	/*
	 * We do not log the metasync command as it will have no effect on the
	 * underlying metadb state. If we have a master change the
	 * reconfiguration process will issue a new 'metasync' to all affected
	 * mirrors, so we would actually end up sending the message twice.
	 * Removing the logging of the message helps reduce the processing
	 * time required.
	 */
	ret = mdmn_send_message(sp->setno, MD_MN_MSG_SETSYNC,
	    MD_MSGF_NO_LOG | MD_MSGF_OVERRIDE_SUSPEND, 0,
	    (char *)&setsyncmsg, sizeof (setsyncmsg), &resp, ep);
	if (resp != NULL) {
		free_result(resp);
	}

	/*
	 * Unlike non-MN sets, the metasync command does not actually
	 * start a resync, it simply updates the state on all of the
	 * nodes. Therefore, to start a resync we send a resync starting
	 * message for the metadevice
	 */
	if (ret == 0)
		ret = meta_mn_send_resync_starting(mirnp, ep);
	return (ret);
}

/*
 * FUNCTION:	meta_mn_send_metaclear_command()
 * INPUT:	sp	- setname
 *		name	- metadevice name
 *		options - command options
 *		pflag	- clear all soft partitions for a given device
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	return value from meta_mn_send_command()
 * PURPOSE:  Send a metaclear command to all nodes with force(-f) and
 *	     recurse(-r) options set if required. For hotspare pool and
 *	     metadevices, the metadevice name is of the form setname/dxx or
 *	     setname/hspxxx so a '-s' argument isn't required. If pflag is set
 *	     the name refers to a metadevice or component and in the is case
 *	     a '-s' argument is required to define the set.
 */

int
meta_mn_send_metaclear_command(
	mdsetname_t		*sp,
	char			*name,
	mdcmdopts_t		options,
	int			pflag,
	md_error_t		*ep
)
{
	int	newargc;
	char	**newargv;
	int	ret;

	/*
	 * Allocate an array large enough to hold all of the possible
	 * metaclear arguments
	 */
	newargv = Calloc(7, sizeof (char *));
	newargv[0] = "metaclear";
	newargc = 1;
	if (pflag) {
		newargv[newargc] = "-s";
		newargc++;
		newargv[newargc] = sp->setname;
		newargc++;
	}
	if (options & MDCMD_FORCE) {
		newargv[newargc] = "-f";
		newargc++;
	}
	if (options & MDCMD_RECURSE) {
		newargv[newargc] = "-r";
		newargc++;
	}
	if (pflag) {
		newargv[newargc] = "-p";
		newargc++;
	}
	newargv[newargc] = name;
	newargc++;

	ret = meta_mn_send_command(sp, newargc, newargv,
	    MD_DISP_STDERR, NO_CONTEXT_STRING, ep);

	free(newargv);
	return (ret);
}

/*
 * FUNCTION:	meta_mn_send_resync_starting()
 * INPUT:	sp	- setname
 *		mirnp	- mirror name
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	return value from mdmn_send_message()
 * PURPOSE:  Send a resync starting message to all nodes.
 */

int
meta_mn_send_resync_starting(
	mdname_t		*mirnp,
	md_error_t		*ep
)
{
	int			result;
	md_mn_msg_resync_t	resyncmsg;
	md_mn_result_t		*resp = NULL;
	minor_t			mnum = meta_getminor(mirnp->dev);

	/*
	 * This message is never directly issued.
	 * So we launch it with a suspend override flag.
	 * If the commd is suspended, and this message comes
	 * along it must be sent due to replaying a command or similar.
	 * In that case we don't want this message to be blocked.
	 * If the commd is not suspended, the flag does no harm.
	 */
	resyncmsg.msg_resync_mnum =  mnum;
	result = mdmn_send_message(MD_MIN2SET(mnum),
	    MD_MN_MSG_RESYNC_STARTING,
	    MD_MSGF_NO_LOG | MD_MSGF_OVERRIDE_SUSPEND, 0,
	    (char *)&resyncmsg, sizeof (resyncmsg), &resp, ep);

	if (resp != NULL) {
		free_result(resp);
	}
	return (result);
}

/*
 * FUNCTION:	meta_mn_change_owner()
 * INPUT:	opp	- pointer to parameter block
 *		setno	- set number of mirror metadevice
 *		mnum	- minor number of mirror metadevice
 *		owner	- node ID of mirror owner
 *		flags	- flag field for ioctl
 * OUTPUT:	opp	- parameter block used to send ioctl
 * RETURNS:	int	- 0 success, -1 error
 * PURPOSE:	issue an ioctl to change the ownership of the specified mirror
 *		to our node ID. We need to be the owner before any watermarks
 *		are committed to the device otherwise we'll enter a deadly
 *		embrace when attempting to write the watermark.
 *		This function can also be used so set the owner on a node to
 *		NULL. In this case the change is only made on the local node.
 *		In addition by setting the MD_MN_MM_CHOOSE_OWNER flag, the
 *		function can also be used to choose a mirror resync owner. This
 *		function should only be called on the master and it will
 *		select the owner and request it to become the owner.
 */
int
meta_mn_change_owner(
	md_set_mmown_params_t 	**opp,	/* Returned parameter block */
	set_t			setno,	/* Mirror set number */
	uint_t 			mnum,	/* Minor number */
	uint_t			owner,	/* Node ID of mirror owner */
	uint_t			flags	/* Flags */
)
{
	md_set_mmown_params_t	*ownpar = *opp;
	md_mn_own_status_t	*ownstat = NULL;
	struct timeval tvs, tve;
	int			n = 0;
	int			rval;

	if (ownpar != NULL) {
		(void) memset(ownpar, 0, sizeof (*ownpar));
	} else {
		ownpar = Zalloc(sizeof (*ownpar));
	}
	ownstat = Zalloc(sizeof (*ownstat));

	ownpar->d.mnum = mnum;
	ownpar->d.owner = owner;
	ownpar->d.flags = flags;
	MD_SETDRIVERNAME(ownpar, MD_MIRROR, setno);
	MD_SETDRIVERNAME(ownstat, MD_MIRROR, setno);

	/*
	 * Attempt to change the ownership to the specified node. We retry this
	 * up to 10 times if we receive EAGAIN from the metadevice. This only
	 * happens if the underlying metadevice is busy with outstanding i/o
	 * that requires ownership change.
	 */
	while ((rval = metaioctl(MD_MN_SET_MM_OWNER, ownpar, &ownpar->mde,
	    NULL)) != 0) {
		md_sys_error_t	*ip =
		    &ownpar->mde.info.md_error_info_t_u.sys_error;
		if (ip->errnum != EAGAIN)
			break;
		if (n++ >= 10)
			break;
		(void) sleep(1);
	}

	/*
	 * There is no need to wait for the ioctl completion if we are setting
	 * the owner to NULL or requesting the master to choose the owner
	 */
	if ((owner == 0) || (flags & MD_MN_MM_CHOOSE_OWNER)) {
		Free(ownstat);
		*opp = ownpar;
		return (0);
	}

	/*
	 * Wait for ioctl completion or a timeout to occur. If we
	 * timeout we fail the i/o request.
	 */
	ownstat->mnum = ownpar->d.mnum;
	(void) gettimeofday(&tvs, NULL);

	while ((rval == 0) && !(ownstat->flags & MD_MN_MM_RESULT)) {
		while ((rval = metaioctl(MD_MN_MM_OWNER_STATUS, ownstat,
		    &ownstat->mde, NULL)) != 0) {
			(void) gettimeofday(&tve, NULL);
			if ((tve.tv_sec - tvs.tv_sec) > OWNER_TIMEOUT) {
				rval = -1;
				break;
			}
			(void) sleep(1);
		}
	}

	/* we did not not timeout but ioctl failed set rval */

	if (rval == 0) {
		rval = (ownstat->flags & MD_MN_MM_RES_FAIL) ? -1 : 0;
	}

	Free(ownstat);
	*opp = ownpar;
	return (rval);
}
/*
 * special handling is required when running on a single node
 * non-SC3.x environment.  This function determines tests
 * for that case.
 *
 * Return values:
 *	0 - no nodes or joined or in a SC3.x env
 *	1 - 1 node and not in SC3.x env
 */

int
meta_mn_singlenode()
{
	md_error_t			xep = mdnullerror;
	int				nodecnt;
	int				mnset_single_node = 0;
	mndiskset_membershiplist_t	*nl;

	/*
	 * If running on SunCluster, then don't validate MN sets,
	 * this is done during a reconfig cycle since all nodes must
	 * take the same action.
	 *
	 * Only cleanup in case of a single node situation
	 * when not running on SunCluster.  This single node
	 * situation occurs when the nodelist only contains
	 * this node and the MN setrecords only contain this
	 * node.
	 */
	if (meta_read_nodelist(&nodecnt, &nl, &xep) == -1) {
		nodecnt = 0;  /* no nodes are alive */
		nl = NULL;
		mdclrerror(&xep);
	} else {
		/*
		 * If only 1 node in nodelist and not running
		 * on SunCluster, set single_node flag.
		 */
		if ((nodecnt == 1) &&
		    (strcmp(nl->msl_node_name, mynode()) == 0) &&
		    ((sdssc_bind_library()) != SDSSC_OKAY)) {
			mnset_single_node = 1;
		}
		meta_free_nodelist(nl);
	}
	return (mnset_single_node);
}

/*
 * FUNCTION:	meta_mn_send_get_tstate()
 * INPUT:	dev	- dev_t of device
 * OUTPUT:	tstatep - tstate value
 *		ep	- return error pointer
 * RETURNS:	return value from mdmn_send_message()
 * PURPOSE:  Send a message to the master to get ui_tstate for a given device.
 */

int
meta_mn_send_get_tstate(
	md_dev64_t		dev,
	uint_t			*tstatep,
	md_error_t		*ep
)
{
	int			result;
	md_mn_msg_gettstate_t	tstatemsg;
	md_mn_result_t		*resp = NULL;
	minor_t			mnum = meta_getminor(dev);

	tstatemsg.gettstate_dev = dev;
	result = mdmn_send_message(MD_MIN2SET(mnum),
	    MD_MN_MSG_GET_TSTATE,
	    MD_MSGF_NO_LOG | MD_MSGF_NO_BCAST, 0,
	    (char *)&tstatemsg, sizeof (tstatemsg), &resp, ep);

	if (result == 0)
		*tstatep = resp->mmr_exitval;
	else
		/* If some error occurred set tstate to 0 */
		*tstatep = 0;

	if (resp != NULL) {
		free_result(resp);
	}
	return (result);
}
