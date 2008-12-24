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

#include <stdlib.h>
#include <unistd.h>
#include <wait.h>
#include <sys/time.h>
#include <meta.h>
#include <metad.h>
#include <mdmn_changelog.h>
#include <syslog.h>
#include <umem.h>

/*
 * Number of log entries per set.
 *
 * We want at least 4 spares available at all times
 * in case new classes are added during a live upgrade.
 *
 * Allocate the entries in chunks of 16
 */
#define	MDMN_LOGRECS_QUANTA	16
#define	MDMN_LOGRECS_MINSPARES	4
#define	MDMN_LOGHDR_SIZE	sizeof (mdmn_changelog_record_t)
#define	MDMN_LOGRECSIZE	(MDMN_LOGHDR_SIZE + MD_MN_MSG_MAXDATALEN)
#define	MDMN_LOGRECSIZE_OD	sizeof (mdmn_changelog_record_od_t)
#define	MDMN_LOGRECS_TRIMUP	((MD_MN_NCLASSES % MDMN_LOGRECS_QUANTA) > \
				(MDMN_LOGRECS_QUANTA - MDMN_LOGRECS_MINSPARES))

static int	mdmn_commitlog(md_set_desc *, md_error_t *);
static int	mdmn_log_it(set_t, md_error_t *, mdmn_changelog_record_t *lr);


/* Global variables */

mdmn_changelog_record_t	*mdmn_changelog[MD_MAXSETS];
int mdmn_changelog_snarfed[MD_MAXSETS];

/* Total number of log records */
int mdmn_logrecs = (MDMN_LOGRECS_QUANTA +
		((MD_MN_NCLASSES/MDMN_LOGRECS_QUANTA) * MDMN_LOGRECS_QUANTA));

#ifdef DEBUG
void
dump_rec(char *fn_name, mdmn_changelog_record_t *lr)
{
	syslog(LOG_DEBUG, "%s incore: selfid 0x%x class %d flags %d "
	    "msglen %d\n", fn_name, lr->lr_selfid, lr->lr_class,
	    lr->lr_flags, lr->lr_msglen);
}
void
dump_rec_od(char *fn_name, mdmn_changelog_record_od_t *lr)
{
	syslog(LOG_DEBUG, "%s ondisk: selfid 0x%x class %d flags %d "
	    "msglen %d\n", fn_name, lr->lr_selfid, lr->lr_class,
	    lr->lr_flags, lr->lr_msglen);
}

void
dump_array(char *fn_name, set_t setno)
{
	int i;
	char tchar[80];

	mdmn_changelog_record_t *tlr;

	for (i = 0; i < mdmn_logrecs; i++) {
		tlr = &mdmn_changelog[setno][i];
		(void) snprintf(tchar, sizeof (tchar), "%s class %d ",
		    fn_name, i);
		dump_rec(tchar, tlr);
	}
}
#endif

/*
 * copy_changelog: copies changelog ondisk<->incore records.
 * The argument "direction" controls the direction to copy the
 * the records. Incore and ondisk changlog structures must be
 * allocated when calling this routine.
 *
 * The purpose of changelog is to store a message that is in progress.
 * Therefore the changlog structure embeds the message structure.
 * Incore and ondisk changelog structures are created to handle the
 * incore and ondisk message formats. The incore message has a pointer
 * to the payload. The ondisk message format has payload embedded as
 * part of the message.
 *
 * Caveat Emptor: Incore and ondisk structures have the payload buffers
 * correctly allocated.
 */

static void
copy_changelog(mdmn_changelog_record_t *incp,
		mdmn_changelog_record_od_t *odp, int direction)
{
	assert(incp != NULL && odp != NULL);
	assert((direction == MD_MN_COPY_TO_ONDISK) ||
	    (direction == MD_MN_COPY_TO_INCORE));

	if (direction == MD_MN_COPY_TO_ONDISK) {
		odp->lr_revision = incp->lr_revision;
		odp->lr_flags = incp->lr_flags;
		odp->lr_selfid = incp->lr_selfid;
		odp->lr_class = incp->lr_class;
		odp->lr_msglen = incp->lr_msglen;
		if (incp->lr_msglen)
			copy_msg_2(&incp->lr_msg, &odp->lr_od_msg, direction);
	} else {
		incp->lr_revision = odp->lr_revision;
		incp->lr_flags = odp->lr_flags;
		incp->lr_selfid = odp->lr_selfid;
		incp->lr_class = odp->lr_class;
		incp->lr_msglen = odp->lr_msglen;
		if (odp->lr_msglen)
			copy_msg_2(&incp->lr_msg, &odp->lr_od_msg, direction);
	}
}

/*
 * mdmn_allocate_changelog
 *
 * Changelog records are allocated on a per multi-node basis.
 * This routine is called during MN set creation.
 * It pre-allocates the changelog, as user records
 * one per message class plus some spares.
 * Once the records are allocated they are never freed until
 * the mddb is deleted. The preallocation ensures that all nodes
 * will have a consistent view of the mddb.
 *
 * Each record is large enough to hold a maximum sized message
 * Return Values:
 *	0 - success
 *	-1 - fail
 */
int
mdmn_allocate_changelog(mdsetname_t *sp, md_error_t *ep)
{
	mddb_userreq_t		req;
	md_set_desc		*sd;
	mdmn_changelog_record_t	*tlr;
	int			i;
	set_t			setno;

	/* Get a pointer to the incore md_set_desc for this MN set */
	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);
	setno = sd->sd_setno;
	/*
	 * Round up the number of changelog records
	 * to the next value of MDMN_LOGRECS_QUANTA
	 *
	 * In all cases, make sure we have at least
	 * four more entries than the number of classes
	 * in order to provide space for live upgrades that
	 * might add classes.
	 */

	mdmn_logrecs += (MDMN_LOGRECS_TRIMUP) ? MDMN_LOGRECS_QUANTA : 0;

	mdmn_changelog[setno] = Zalloc(MDMN_LOGHDR_SIZE * mdmn_logrecs);

	for (i = 0; i < mdmn_logrecs; i++) {
		(void) memset(&req, 0, sizeof (req));
		METAD_SETUP_LR(MD_DB_CREATE, setno,  0);
		/* grab a record big enough for max message size */
		req.ur_size = MDMN_LOGRECSIZE_OD;

		if (metaioctl(MD_MN_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
			(void) mdstealerror(ep, &req.ur_mde);
#ifdef DEBUG
			syslog(LOG_DEBUG, "allocate_log: %s\n",
			    mde_sperror(ep, ""));
#endif
			Free(mdmn_changelog[setno]);
			return (-1);
		}

		tlr = &mdmn_changelog[setno][i];
		tlr->lr_selfid = req.ur_recid;
		tlr->lr_revision = MD_MN_CHANGELOG_RECORD_REVISION;
		tlr->lr_class = i;
	}

	/* commit class, and selfid */
	(void) mdmn_commitlog(sd, ep);
	Free(mdmn_changelog[setno]);
	return (0);
}

/*
 * mdmn_reset_changelog
 *
 * Called during reconfig step 2.
 * The only time the changelog is reset is when all nodes in a cluster
 * are starting up. In this case changelog must be ignored, therefore
 * it is reset.
 *
 * The function frees the incore data structures and zeros out the
 * records. The ondisk records are never freed.
 *
 * Return Values:
 *	0 - success
 *	-1 - fail
 */
int
mdmn_reset_changelog(mdsetname_t *sp, md_error_t *ep, int flag)
{
	md_set_desc		*sd;
	mdmn_changelog_record_t	*lr;
	set_t			setno;
	int			lrc;

	/* Get a pointer to the incore md_set_desc this MN set */
	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	setno = sd->sd_setno;

	if (mdmn_snarf_changelog(setno, ep) == 0) {
		return (0);
	}

	if (flag & MDMN_CLF_RESETLOG) {
		for (lrc = 0; lrc < mdmn_logrecs; lrc++) {
			lr = &mdmn_changelog[setno][lrc];
			Free(lr->lr_msg.msg_event_data);
			(void) memset(&lr->lr_msg, 0, sizeof (md_mn_msg_t));
			lr->lr_msglen = 0;
			lr->lr_flags = 0;
		}
		(void) mdmn_commitlog(sd, ep);
#ifdef DEBUG
		syslog(LOG_DEBUG, "reset_changelog: Log reset\n");
#endif
	}
	/* now zap the array */
	if (flag & MDMN_CLF_RESETCACHE) {
#ifdef DEBUG
		syslog(LOG_DEBUG, "reset_changelog: cache reset\n");
#endif
		Free(&mdmn_changelog[setno]);
		mdmn_changelog[setno] = NULL;
		mdmn_changelog_snarfed[setno] = 0;
	}
	return (0);
}

/*
 * Log a given message in the changelog.
 * This function is only executed by the master node
 * Return Values:
 *	MDMNE_NULL:
 *	    success, the log slot is free
 *
 *	MDMNE_ACK:
 *	    success,
 *	    the log slot is occupied with the same msg from a previous try.
 *
 *	MDMNE_CLASS_BUSY:
 *	    This means the appropriate slot is occupied with a different
 *	    message. In that case the stored message needs being replayed,
 *	    while the current message will be rejected with MDMNE_CLASS_BUSY
 *	    to the initiator.
 *
 *	MDMNE_LOG_FAIL:
 *	    Bad things happend, cannot continue.
 */
int
mdmn_log_msg(md_mn_msg_t *msg)
{
	set_t		setno;
	md_mn_msgclass_t	class;
	mdmn_changelog_record_t	*lr;
	md_error_t		err = mdnullerror;
	md_error_t		*ep = &err;
	int			retval = 0;

	setno = msg->msg_setno;
	class = mdmn_get_message_class(msg->msg_type);

	/* if not snarfed, snarf it */
	if (mdmn_snarf_changelog(setno, ep) <= 0) {
		syslog(LOG_DAEMON | LOG_ERR, dgettext(TEXT_DOMAIN,
		    "log_msg: No records snarfed\n"));
		return (-1);
	}


	/* log entry for the class */
	lr = &mdmn_changelog[setno][class];

	/* Check if the class is occupied */
	if (lr->lr_flags & MD_MN_LR_INUSE) {
		if (!MSGID_CMP(&(msg->msg_msgid), &(lr->lr_msg.msg_msgid))) {
			syslog(LOG_DAEMON | LOG_DEBUG, dgettext(TEXT_DOMAIN,
			    "log_msg: id mismatch:\n"
			    " stored    : ID = (%d, 0x%llx-%d)"
			    " setno %d class %d type %d\n"
			    " msg to log: ID = (%d, 0x%llx-%d)"
			    " setno %d class %d type %d.\n"),
			    MSGID_ELEMS(lr->lr_msg.msg_msgid), lr->lr_setno,
			    lr->lr_class, lr->lr_msgtype,
			    MSGID_ELEMS(msg->msg_msgid), msg->msg_setno, class,
			    msg->msg_type);
			return (MDMNE_CLASS_BUSY);
		} else {
			syslog(LOG_DAEMON | LOG_DEBUG, dgettext(TEXT_DOMAIN,
			    "log_msg: msgid already logged:\n ID = "
			    " (%d, 0x%llx-%d) setno %d class %d type %d\n"),
			    MSGID_ELEMS(lr->lr_msg.msg_msgid), lr->lr_setno,
			    lr->lr_class, lr->lr_msgtype);
			return (MDMNE_ACK);
		}
	}

	lr->lr_flags |= MD_MN_LR_INUSE;
	lr->lr_msglen = MD_MN_MSG_LEN(msg);
	assert(lr->lr_msg.msg_event_data == NULL);
	if (msg->msg_event_size)
		lr->lr_msg.msg_event_data = Zalloc(msg->msg_event_size);
	(void) copy_msg(msg, &(lr->lr_msg));
	retval = mdmn_log_it(setno, ep, lr);
	if (retval != 0) {
		syslog(LOG_DAEMON | LOG_ERR, dgettext(TEXT_DOMAIN,
		    "mdmn_log_msg - failure committing logged msg to disk\n"));
		return (MDMNE_LOG_FAIL);
	}

	return (MDMNE_NULL); /* this is good */
}

/*
 * mdmn_unlog_msg(md_mn_msg_t *)
 *
 * Clear the log entry holding the indicated message.
 * Only the set master can do this.
 *
 * Return Values:
 *	0 - success
 *	-1 - fail
 */
int
mdmn_unlog_msg(md_mn_msg_t *msg)
{
	set_t			setno;
	md_mn_msgclass_t	class;
	md_error_t		err = mdnullerror;
	md_error_t		*ep = &err;
	int			retval = 0;
	mdmn_changelog_record_t	*lr = NULL;

	setno = msg->msg_setno;
	class = mdmn_get_message_class(msg->msg_type);

	/* Find the log entry holding the indicated message */
	if (mdmn_snarf_changelog(setno, ep) == 0)
		return (-1);

	lr = &mdmn_changelog[setno][class];

	/* assert the message is still logged */
	assert(lr != NULL);
	if (!MSGID_CMP(&(msg->msg_msgid), &(lr->lr_msg.msg_msgid))) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "unlog_msg: msgid mismatch\n"
		    "\t\tstored: ID = (%d, 0x%llx-%d) setno %d "
		    "class %d type %d\n"
		    "\t\tattempting to unlog:\n"
		    "\t\tID = (%d, 0x%llx-%d) setno %d class %d type %d.\n"),
		    MSGID_ELEMS(lr->lr_msg.msg_msgid), lr->lr_setno,
		    lr->lr_class, lr->lr_msgtype, MSGID_ELEMS(msg->msg_msgid),
		    msg->msg_setno, class, msg->msg_type);
		return (-1);
	}
	lr->lr_msglen = 0;
	lr->lr_flags &= ~(MD_MN_LR_INUSE);
	if (lr->lr_msg.msg_event_data) {
		Free(lr->lr_msg.msg_event_data);
		lr->lr_msg.msg_event_data = NULL;
	}
	/* commit the updated log record to disk */
	retval = mdmn_log_it(setno, ep, lr);
#ifdef DEBUG
	dump_rec("mdmn_unlog_msg: ", lr);
#endif
	return (retval);
}


/*
 * mdmn_get_changelogrec(set_t , md_mn_msgclass_t)
 * Returns a pointer to incore changelog record.
 *
 * Return Values:
 *	non-NULL - success
 *	NULL - fail
 */
mdmn_changelog_record_t *
mdmn_get_changelogrec(set_t setno, md_mn_msgclass_t class)
{
	md_error_t	err = mdnullerror;

	if (mdmn_snarf_changelog(setno, &err) == 0)
		return (NULL);
	assert(mdmn_changelog[setno] != NULL);

	return (&mdmn_changelog[setno][class]);
}

/*
 * mdmn_commitlog(md_set_desc *, md_error_t *)
 *
 * Commit the set record and all of the changelog entry records to disk.
 * Don't bother with other stuff hanging off the set record
 * (e.g. drive records) since none of that is changing.
 * Called only at changelog pre-allocation time or when flushing a log.
 *
 * Return Values:
 *	0 - success
 *	errno - fail
 */

static int
mdmn_commitlog(md_set_desc *sd, md_error_t *ep)
{
	int			lrc;
	int			*recs;
	uint_t			size;
	mdmn_changelog_record_t	*lr;
	mdmn_changelog_record_od_t clodrec; /* changelog ondisk record */
	mddb_userreq_t		req;
	int			retval = 0;
	set_t			setno;

	/* Check for master and bounce non-master requests */
	if (!(MD_MNSET_DESC(sd)) || !sd->sd_mn_am_i_master) {
		if (!(MD_MNSET_DESC(sd))) {
			syslog(LOG_DAEMON | LOG_ERR, dgettext(TEXT_DOMAIN,
			    "mdmn_commitlog - Not MN Set\n"));
		} else {
			syslog(LOG_DAEMON | LOG_ERR, dgettext(TEXT_DOMAIN,
			    "mdmn_commit_log - Not Master\n"));
		}
		return (-1);
	}
	(void) memset(&req, 0, sizeof (req));
	/* create the records to commit the info to the mddb */

	size = (mdmn_logrecs + 1) * sizeof (int);
	recs = Zalloc(size);
	/* Initialize the log entry records for update */
	setno = sd->sd_setno;

	for (lrc = 0; lrc < mdmn_logrecs; lrc++) {
		lr = &mdmn_changelog[setno][lrc];
		recs[lrc] = lr->lr_selfid;
		copy_changelog(lr, &clodrec, MD_MN_COPY_TO_ONDISK);
		METAD_SETUP_LR(MD_DB_SETDATA, setno, lr->lr_selfid);
		req.ur_size  = MDMN_LOGRECSIZE_OD;
		req.ur_data = (uintptr_t)&clodrec;
		if ((retval = metaioctl(MD_MN_DB_USERREQ, &req, &req.ur_mde,
		    NULL)) != 0) {
			(void) mdstealerror(ep, &req.ur_mde);
#ifdef DEBUG
			syslog(LOG_DAEMON|LOG_DEBUG,
			    "mdmn_commitlog - metaioctl SETDATA failure\n%s",
			    mde_sperror(ep, ""));
#endif
			break;
		}
	}

	if (retval == 0) {
		/* set last rec to be 0 to indicate completion */
		recs[lrc] = 0;
		/* Commit to mddb  on disk */
		METAD_SETUP_LR(MD_DB_COMMIT_MANY, setno,
		    mdmn_changelog[setno][0].lr_selfid);
		req.ur_size = size;
		req.ur_data = (uintptr_t)recs;
		if ((retval = metaioctl(MD_MN_DB_USERREQ, &req,
		    &req.ur_mde, NULL)) != 0) {
			(void) mdstealerror(ep, &req.ur_mde);
#ifdef DEBUG
			syslog(LOG_DAEMON|LOG_DEBUG,
			    "mdmn_commitlog - metaioctl COMMIT_MANY"
			    "Failure\n%s",  mde_sperror(ep, ""));
#endif
		}
	}

	Free(recs);
	return (retval);
}

/*
 * mdmn_log_it(set_t, md_error_t *, mdmn_changelog_record_t *)
 *
 * Commit the changed log record to disk.
 *
 * Return Values:
 *	0 - success
 *	-1 - fail
 */
static int
mdmn_log_it(set_t set, md_error_t *ep, mdmn_changelog_record_t *lr)
{
	int			*recs;
	uint_t			size;
	mddb_userreq_t		req;
	mdmn_changelog_record_od_t	clodrec;

	(void) memset(&req, 0, sizeof (req));

	/* Initialize the log entry record for update */

	copy_changelog(lr, &clodrec, MD_MN_COPY_TO_ONDISK);
	METAD_SETUP_LR(MD_DB_SETDATA, set, lr->lr_selfid);
	req.ur_size = MDMN_LOGRECSIZE_OD;
	req.ur_data = (uintptr_t)&clodrec;
	if (metaioctl(MD_MN_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
		(void) mdstealerror(ep, &req.ur_mde);
#ifdef DEBUG
		syslog(LOG_DEBUG, "mdmn_log_it: DB_SETDATA  failed\n"
		    "set %d selfid %d, size %d\n%s", set, lr->lr_selfid,
		    req.ur_size, mde_sperror(ep, ""));
#endif
		return (-1);
	}
	/* Set up the recid to be updated */
	size = 2 * sizeof (int); /* the changed record, plus null terminator */
	recs = Zalloc(size);
	recs[0] = lr->lr_selfid;
	recs[1] = 0;
	/* Commit to mddb  on disk */
	METAD_SETUP_LR(MD_DB_COMMIT_ONE, set, lr->lr_selfid);
	req.ur_size = size;
	req.ur_data = (uintptr_t)recs;
	if (metaioctl(MD_MN_DB_USERREQ, &req, &req.ur_mde, NULL) != 0) {
		(void) mdstealerror(ep, &req.ur_mde);
#ifdef DEBUG
		syslog(LOG_DEBUG, "mdmn_log_it: DB_COMMIT_ONE  failed\n"
		    "set %d selfid %d, size %d\n%s", set, lr->lr_selfid,
		    req.ur_size, mde_sperror(ep, ""));
#endif
		Free(recs);
		return (-1);
	}
	Free(recs);
	return (0);
}

/*
 * mdmn_snarf_changelog(set_t, md_error_t *)
 *
 * snarf in the changelog entries and allocate incore structures
 * if required.
 * mdmn_changelog_snarfed array if set to MDMN_CLF_SNARFED, then
 * then the records are already snarfed.
 *
 * Called from set_snarf(), mdmn_log_msg(), and mdmn_unlog_msg()
 * Return Values:
 *	non-zero - success
 *	0 - fail
 */
int
mdmn_snarf_changelog(set_t set, md_error_t *ep)
{
	mdmn_changelog_record_t	 *tlr;
	mdmn_changelog_record_od_t	 *lr;
	mddb_recid_t		id;
	md_mn_msgclass_t	class;


	if (set == MD_LOCAL_SET)
		return (0);

	id = 0;

	if (mdmn_changelog_snarfed[set] & MDMN_CLF_SNARFED) {
		assert(mdmn_changelog[set] != NULL);
		return (mdmn_logrecs);
	}

	lr = (mdmn_changelog_record_od_t *)get_ur_rec(set, MD_UR_GET_NEXT,
	    MDDB_UR_LR, &id, ep);
	if (lr == NULL)
		return (0);

	/* only allocate if Log records exist */

	if (mdmn_changelog[set] == NULL) {
		/* Allocate incore state for the log */
		mdmn_changelog[set] = Zalloc(MDMN_LOGHDR_SIZE *
		    mdmn_logrecs);
	}

	do {
		class = lr->lr_class;
		tlr = &mdmn_changelog[set][class];
		copy_changelog(tlr, lr, MD_MN_COPY_TO_INCORE);
		Free(lr);
		lr = (mdmn_changelog_record_od_t *)get_ur_rec(set,
		    MD_UR_GET_NEXT, MDDB_UR_LR, &id, ep);
	} while (lr != NULL);

	/* Since log records counts are fixed return that value */
	mdmn_changelog_snarfed[set] |= MDMN_CLF_SNARFED;
	return (mdmn_logrecs);
}
