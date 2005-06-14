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
 *	db_log.cc
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <errno.h>

#include <malloc.h>
#include <string.h>
#ifdef TDRPC
#include <sysent.h>
#endif
#include <unistd.h>

#include "db_headers.h"
#include "db_log.h"

#include "nisdb_mt.h"

static void
delete_log_entry(db_log_entry *lentry)
{
	db_query *q;
	entry_object *obj;
	if (lentry) {
		if ((q = lentry->get_query())) {
			delete q;
		}
		if ((obj = lentry->get_object())) {
			free_entry(obj);
		}
		delete lentry;
	}
}

/*
 * Execute given function 'func' on log.
 * function takes as arguments: pointer to log entry, character pointer to
 * another argument, and pointer to an integer, which is used as a counter.
 * 'func' should increment this value for each successful application.
 * The log is traversed until either 'func' returns FALSE, or when the log
 * is exhausted.  The second argument to 'execute_on_log' is passed as the
 * second argument to 'func'.  The third argument, 'clean' determines whether
 * the log entry is deleted after the function has been applied.
 * Returns the number of times that 'func' incremented its third argument.
 */
int
db_log::execute_on_log(bool_t (*func) (db_log_entry *, char *, int *),
			    char* arg, bool_t clean)
{
	db_log_entry    *j;
	int count = 0;
	bool_t done = FALSE;

	WRITELOCK(this, 0, "w db_log::execute_on_log");
	if (open() == TRUE) {   // open log
		while (!done) {
			j = get();
			if (j == NULL)
				break;
			if ((*func)(j, arg, &count) == FALSE) done = TRUE;
			if (clean) delete_log_entry(j);
		}

		sync_log();
		close();
	}
	WRITEUNLOCK(this, count, "wu db_log::execute_on_log");

	return (count);
}

static bool_t
print_log_entry(db_log_entry *j, char * /* dummy */, int *count)
{
	j->print();
	++ *count;
	return (TRUE);
}

/* Print contents of log file to stdout */
int
db_log::print()
{
	return (execute_on_log(&(print_log_entry), NULL));
}

/* Make copy of current log to log pointed to by 'f'. */
int
db_log::copy(db_log *f)
{
	db_log_entry *j;
	int	l, ret = 0;

	WRITELOCK(f, -1, "w f db_log::copy");
	if ((l = acqnonexcl()) != 0) {
		WRITEUNLOCK(f, l, "wu f db_log::copy");
		return (l);
	}
	for (;;) {
		j = get();
		if (j == NULL)
			break;
		if (f->append(j) < 0) {
			WARNING_M(
			"db_log::copy: could not append to log file: ");
			ret = -1;
			break;
		}
		delete_log_entry(j);
	}
	if ((l = relnonexcl()) != 0) {
		ret = l;
	}
	WRITEUNLOCK(f, ret, "wu f db_log::copy");
	return (ret);
}

/* Rewinds current log */
int
db_log::rewind()
{
	return (fseek(file, 0L, 0));
}

/*
 * Return the next element in current log; return NULL if end of log or error.
 * Log must have been opened for READ.
 */
db_log_entry
*db_log::get()
{
	db_log_entry *j;

	READLOCK(this, NULL, "r db_log::get");
	if (mode != PICKLE_READ) {
		READUNLOCK(this, NULL, "ru db_log::get");
		return (NULL);
	}

	j = new db_log_entry;

	if (j == NULL) {
		READUNLOCK(this, NULL, "ru db_log::get");
		return (NULL);
	}
	if (xdr_db_log_entry(&(xdr), j) == FALSE) {
		delete_log_entry (j);
/*    WARNING("Could not sucessfully finish reading log"); */
		READUNLOCK(this, NULL, "ru db_log::get");
		return (NULL);
	}
	if (! j->sane()) {
		WARNING("truncated log entry found");
		delete_log_entry(j);
		j = NULL;
	}
	READUNLOCK(this, j, "ru db_log::get");
	return (j);
}

/* Append given log entry to log. */
int
db_log::append(db_log_entry *j)
{
	int status;

	WRITELOCK(this, -1, "w db_log::append");
	if (mode != PICKLE_APPEND) {
		WRITEUNLOCK(this, -1, "wu db_log::append");
		return (-1);
	}

	/* xdr returns TRUE if successful, FALSE otherwise */
	status = ((xdr_db_log_entry(&(xdr), j)) ? 0 : -1);
	if (status < 0) {
		WARNING("db_log: could not write log entry");
	} else {
		syncstate++;
	}
	WRITEUNLOCK(this, status, "wu db_log::append");
	return (status);
}

int
copy_log_file(char *oldname, char *newname) {

	int	from, to, ret = 0;
	ssize_t	size, w, b;
	char	buf[8192];

	if ((from = open(oldname, O_RDONLY, 0666)) < 0) {
		if (errno == ENOENT) {
			return (0);
		} else {
			return (errno);
		}
	}
	if ((to = open(newname, O_WRONLY|O_CREAT|O_TRUNC, 0660)) < 0) {
		ret = errno;
		(void) close(from);
		return (ret);
	}

	while ((size = read(from, buf, sizeof (buf))) > 0) {
		b = 0;
		while (size > 0) {
			w = write(to, &buf[b], size);
			if (w < 0) {
				size == -1;
				break;
			}
			size -= w;
			b += w;
		}
		if (size != 0) {
			ret = errno;
			break;
		}
	}

	(void) close(from);

	if (ret != 0) {
		errno = ret;
		WARNING_M("db_log: error copying log file")
		(void) close(to);
		return (ret);
	}

	if (fsync(to) != 0) {
		ret = errno;
		WARNING_M("db_log: error syncing log file");
	}

	(void) close(to);

	return (ret);

}

/*
 * Return value is expected to be the usual C convention of non-zero
 * for success, 0 for failure.
 */
int
db_log::sync_log()
{
	int status, err;

	WRITELOCK(this, -1, "w db_log::sync_log");
	status = fflush(file);
	if (status < 0) {
		WARNING("db_log: could not flush log entry to disk");
		WRITEUNLOCK(this, status, "wu db_log::sync_log");
		return (status);
	}

	status = fsync(fileno(file));
	if (status < 0) {
		WARNING("db_log: could not sync log entry to disk");
	} else if (tmplog != 0) {
		if (syncstate == 0) {
			/* Log already stable; nothing to do */
			err = 0;
		} else if ((err = copy_log_file(tmplog, stablelog)) == 0) {
			if (rename(stablelog, oldlog) != 0) {
				WARNING_M("db_log: could not mv stable log");
			} else {
				syncstate = 0;
			}
		} else {
			errno = err;
			WARNING_M("db_log: could not stabilize log");
		}
		status = (err == 0);
	} else {
		/*
		 * Successful sync of file, but no tmplog to sync
		 * so we make sure we return 'success'.
		 */
		status = 1;
	}
	WRITEUNLOCK(this, status, "wu db_log::sync_log");
	return (status);
}

int
db_log::close() {

	int ret;

	WRITELOCK(this, -1, "w db_log::close");
	if (mode != PICKLE_READ && oldlog != 0) {
		if (syncstate != 0) {
			WARNING("db_log: closing unstable tmp log");
		}
		filename = oldlog;
		oldlog = 0;
	}

	ret = pickle_file::close();
	if (tmplog != 0) {
		(void) unlink(tmplog);
		delete tmplog;
		tmplog = 0;
	}
	if (stablelog != 0) {
		delete stablelog;
		stablelog = 0;
	}
	WRITEUNLOCK(this, ret, "wu db_log::close");
	return (ret);
}

bool_t
db_log::open(void) {

	int	len, cpstat;
	bool_t	ret;

	WRITELOCK(this, FALSE, "w db_log::open");
	if (mode == PICKLE_READ || (!copylog)) {
		ret = pickle_file::open();
		WRITEUNLOCK(this, ret, "wu db_log::open");
		return (ret);
	}

	len = strlen(filename);
	tmplog = new char[len + sizeof (".tmp")];
	if (tmplog == 0) {
		WARNING("db_log: could not allocate tmp log name");
		ret = pickle_file::open();
		WRITEUNLOCK(this, ret, "wu db_log::open");
		return (ret);
	}
	stablelog = new char[len + sizeof (".stable")];
	if (stablelog == 0) {
		WARNING("db_log: could not allocate stable log name");
		delete tmplog;
		tmplog = 0;
		ret = pickle_file::open();
		WRITEUNLOCK(this, ret, "wu db_log::open");
		return (ret);
	}
	sprintf(tmplog, "%s.tmp", filename);
	sprintf(stablelog, "%s.stable", filename);

	if ((cpstat = copy_log_file(filename, tmplog)) == 0) {
		oldlog = filename;
		filename = tmplog;
	} else {
		syslog(LOG_WARNING,
			"db_log: Error copying \"%s\" to \"%s\": %s",
			filename, tmplog, strerror(cpstat));
		delete tmplog;
		tmplog = 0;
		delete stablelog;
		stablelog = 0;
	}

	ret = pickle_file::open();
	WRITEUNLOCK(this, ret, "wu db_log::open");
	return (ret);
}
