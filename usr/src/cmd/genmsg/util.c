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
 * Copyright (c) 1995 by Sun Microsystems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <libintl.h>
#include <locale.h>
#include <libgen.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "genmsg.h"

#define	SET_TOKEN	"$set"
#define	DELSET_TOKEN	"$delset"
#define	QUOTE_TOKEN	"$quote"

#define	SkipSpace(s)	while (*(s) == ' ' || *(s) == '\t') s++

extern char *program;		/* from main.c */
extern char *mctag;		/* from main.c */
extern char *sctag;		/* from main.c */
extern char *premsg;		/* from main.c */
extern char *sufmsg;		/* from main.c */
extern int suppress_error;	/* from main.c */
extern void warning(char *);	/* from genmsg.l */

typedef struct _SetID *SetID;
typedef struct _MsgID *MsgID;

typedef struct _SetID SetIDRec;
struct _SetID {
	int id;
	char *comment;
	MsgID top;
	SetID next;
};

typedef struct _MsgID MsgIDRec;
struct _MsgID {
	int no_write;
	int id;
	char *msg;
	int line;
	char *file;
	char *comment;
	MsgID next;
};


/* Top pointer of the setid list. */
static SetID setid_top;

/* comment for messages. */
static char *msg_comment;

/* comment for set numbers. */
static char *set_comment;

/* List of set number's maximum message numbers. */
static int msgid_table[NL_SETMAX+1];

/* Quote character to surround messages. */
static char quote = QUOTE;

/* Internal functions. */
static void add_msgid(SetID, int, char *, char *, int, int);
static void add_setid(int, int, char *, char *, int, int);
static SetID lookup_setid(int);
static MsgID lookup_msgid(SetID, int, char *, char *, int);
static void print_prefix(FILE *, char *, int, char *);
static int is_bs_terminated(char *);
static char *ustrdup(char *);
static void cat_msg(char *, char *, int);
static void makeup_msg(char **);

void
add_msg(int setid, int msgid, char *msg, char *file, int line, int no_write)
{
	SetID si;

	if (si = lookup_setid(setid)) {
		if (lookup_msgid(si, msgid, msg, file, line)) {
			return; /* we already have the one. */
		} else {
			add_msgid(si, msgid, msg, file, line, no_write);
		}
	} else {
		add_setid(setid, msgid, msg, file, line, no_write);
	}
}

int
is_writable(char *file)
{
	struct stat buf;

	if (stat(file, &buf) == -1)
		return (TRUE);

	if (access(file, W_OK) == 0)
		return (TRUE);

	return (FALSE);
}

void
write_msgfile(char *file)
{
	FILE *fp;
	SetID si = setid_top;
	char *mode = "w";
	char pquote[2];

	if (is_writable(file) == FALSE) {
		prg_err(gettext("cannot create \"%s\": permission denied"),
			file);
		return;
	}

	if (IsActiveMode(AppendMode)) {
		mode = "a";
	}

	if ((fp = fopen(file, mode)) == NULL) {
		prg_err(gettext("cannot create \"%s\""), file);
		return;
	}

	if (quote) {
		(void) sprintf(pquote, "%c", quote);
	} else {
		(void) sprintf(pquote, "");
	}

	/* AppendMode is already turned off if the file doesn't exist. */
	if (!IsActiveMode(AppendMode)) {
		(void) fprintf(fp, "\n$quote %s\n\n", pquote);
	}

	while (si) {
		int is_set = FALSE;
		MsgID mi = si->top;
		while (mi) {
			char msg[NL_TEXTMAX+32]; /* 32 is some other stuff. */

			if (mi->no_write) {
				mi = mi->next;
				continue;
			}
			if (is_set == FALSE) {
				if (si->comment &&
					!IsActiveMode(BackCommentMode)) {
					(void) fprintf(fp, "\n");
					print_prefix(fp, "$ ", TRUE,
							si->comment);
					(void) fprintf(fp, "$set\t%d\n",
							si->id);
				} else {
					(void) fprintf(fp, "\n$set\t%d\n",
							si->id);
				}
				if (si->comment &&
					IsActiveMode(BackCommentMode)) {
					print_prefix(fp, "$ ", TRUE,
							si->comment);
				}
				(void) fprintf(fp, "\n");
				is_set = TRUE;
			}

			makeup_msg(&(mi->msg));

			(void) sprintf(msg, "%d\t%s%s%s\n",
				mi->id, pquote, mi->msg, pquote);

			if (!IsActiveMode(BackCommentMode)) {
				if (mi->line && mi->file &&
					IsActiveMode(LineInfoMode)) {
					(void) fprintf(fp,
						"$ File:%s, line:%d\n",
						basename(mi->file), mi->line);
				}

				if (mi->comment) {
					print_prefix(fp, "$ ", TRUE,
						mi->comment);
				}

				if (IsActiveMode(DoubleLineMode)) {
					print_prefix(fp, "$ ", FALSE, msg);
				}
			}

			(void) fprintf(fp, "%s", msg);

			if (IsActiveMode(BackCommentMode)) {
				if (mi->line && mi->file &&
					IsActiveMode(LineInfoMode)) {
					(void) fprintf(fp,
						"$ File:%s, line:%d\n",
						basename(mi->file), mi->line);
				}

				if (mi->comment) {
					print_prefix(fp, "$ ", TRUE,
						mi->comment);
				}

				if (IsActiveMode(DoubleLineMode)) {
					print_prefix(fp, "$ ", FALSE, msg);
				}
			}

			(void) fprintf(fp, "\n");

			mi = mi->next;
		}
		si = si->next;
	}

	(void) fclose(fp);
}

static SetID
lookup_setid(int id)
{
	SetID si = setid_top;
	while (si) {
		if (si->id == id) {
			return (si);
		}
		si = si->next;
	}
	return (NULL);
}

static MsgID
lookup_msgid(SetID si, int msgid, char *msg, char *file, int line)
{
	MsgID mi = si->top;
	while (mi) {
		if (mi->id == msgid) {
			/* same setid & msgid, but different msg. */
			if (strcmp(mi->msg, msg)) {
			src_err(file, line,
		gettext("multiple messages: set number %d, message number %d\n"
			"	current : \"%s\"\n"
			"	previous: \"%s\" : \"%s\", line %d"),
				si->id, mi->id,
				msg,
				mi->msg, mi->file, mi->line);
			}
			return (mi);
		}
		mi = mi->next;
	}
	return (NULL);
}

static void
add_msgid(SetID si, int msgid, char *msg, char *file, int line, int no_write)
{
	MsgID mi = si->top, newmi, prev = NULL;
	int len = strlen(msg);

	if (msgid == 0) {
		src_err(file, line, gettext("improper message number: %d"),
			msgid);
		return;
	}

	if (msgid > NL_MSGMAX) {
		src_err(file, line, gettext("too large message number: %d"),
			msgid);
		return;
	}

	if (len > NL_TEXTMAX) {
		src_err(file, line, gettext("too long message text"));
		return;
	}

	while (mi) {
		if (mi->id > msgid) {
			break;
		}
		prev = mi;
		mi = mi->next;
	}

	if ((newmi = (MsgID) malloc(sizeof (MsgIDRec))) == NULL) {
		prg_err(gettext("fatal: out of memory"));
		exit(EXIT_FAILURE);
	}

	newmi->no_write = no_write;
	newmi->id = msgid;
	newmi->msg = (char *) ustrdup(msg);
	newmi->file = (char *) ustrdup(file);
	newmi->line = line;
	newmi->next = mi;

	if (msg_comment) {
		newmi->comment = (char *) ustrdup(msg_comment);
		free(msg_comment);
		msg_comment = NULL;
	} else {
		newmi->comment = NULL;
	}

	if (prev == NULL) {
		si->top = newmi;
	} else {
		prev->next = newmi;
	}
}

static void
add_setid(int setid, int msgid, char *msg, char *file, int line, int no_write)
{
	SetID si = setid_top, newsi, prev = NULL;

	while (si) {
		if (si->id > setid) {
			break;
		}
		prev = si;
		si = si->next;
	}

	if ((newsi = (SetID) malloc(sizeof (SetIDRec))) == NULL) {
		prg_err(gettext("fatal: out of memory"));
		exit(EXIT_FAILURE);
	}

	newsi->id = setid;
	newsi->top = NULL;
	newsi->next = si;

	if (set_comment) {
		newsi->comment = (char *) ustrdup(set_comment);
		free(set_comment);
		set_comment = NULL;
	} else {
		newsi->comment = NULL;
	}

	if (prev == NULL) {
		setid_top = newsi;
	} else {
		prev->next = newsi;
	}

	add_msgid(newsi, msgid, msg, file, line, no_write);
}

static void
print_prefix(FILE *fp, char *prefix, int rm_blank, char *str)
{
	(void) fprintf(fp, "%s", prefix);
	while (*str) {
		(void) fputc(*str, fp);
		if (*str == '\n' && *(str+1) != '\0') {
			(void) fprintf(fp, "%s", prefix);
			if (rm_blank == TRUE) {
				str++;
				SkipSpace(str);
				continue;
			}
		}
		str++;
	}
	if (*(str-1) != '\n') {
		(void) fputc('\n', fp);
	}
}

int
read_projfile(char *file)
{
	FILE *fp;
	char line[LINE_MAX];

	if (!file) {
		return (0);
	}

	if ((fp = fopen(file, "r")) == NULL) {
		return (0);
	}

	while (fgets(line, LINE_MAX, fp) != NULL) {
		char *p = line;
		int n, setid, msgid;

		SkipSpace(p);

		if (*p == '#' || *p == '\n') {
			continue;
		}

		n = sscanf(p, "%d %d", &setid, &msgid);

		if (n == 2) {
			if (setid > NL_SETMAX) {
			prg_err(gettext("%s: too large set number: %d"),
					file, setid);
				continue;
			}
			msgid_table[setid] = msgid;
		} else {
			prg_err(
			/* for stupid cstyle */
			gettext("warning: %s: missing or invalid entry"),
				file);
		}
	}

	(void) fclose(fp);

	return (1);
}

void
write_projfile(char *file)
{
	FILE *fp;
	register int i;

	if (is_writable(file) == FALSE) {
		prg_err(gettext("cannot create \"%s\": permission denied"),
			file);
		return;
	}

	if ((fp = fopen(file, "w")) == NULL) {
		prg_err(gettext("cannot create \"%s\""), file);
		return;
	}

	for (i = 1; i <= NL_SETMAX; i++) {
		if (msgid_table[i] > 0) {
			SetID si;
			char *com = NULL;

			if (IsActiveMode(SetCommentMode) &&
				(si = lookup_setid(i)) && si->comment) {
				com = si->comment;
			}

			if (com && !IsActiveMode(BackCommentMode)) {
				print_prefix(fp, "# ", TRUE, com);
			}

			(void) fprintf(fp, "%d\t%d\n", i, msgid_table[i]);

			if (com && IsActiveMode(BackCommentMode)) {
				print_prefix(fp, "# ", TRUE, com);
			}
		}
	}

	(void) fclose(fp);
}

int
get_msgid(char *file, int line, int setid, char *str)
{
	SetID si = setid_top;
	int id = msgid_table[setid];

	while (si) {
		if (si->id == setid) {
			MsgID mi = si->top;
			while (mi) {
				if (strcmp(mi->msg, str) == 0) {
					return (mi->id);
				}
				mi = mi->next;
			}
		}
		si = si->next;
	}

	id++;

	if (id > NL_MSGMAX) {
		src_err(file, line,
			gettext("run out of message number in set number: %d"),
			setid);
		return (NOMSGID);
	}

	return (msgid_table[setid] = id);
}

void
set_msgid(int setid, int msgid)
{
	if (msgid_table[setid] < msgid) {
		msgid_table[setid] = msgid;
	}
}

void
add_comment(Mode mode, char *str)
{
	char *tag = (mode == MsgCommentMode) ? mctag : sctag;
	char **comment = (mode == MsgCommentMode)
				? &msg_comment : &set_comment;

	if (!strstr(str, tag)) {
		return;
	}

	if (*comment) {
		free(*comment);
	}

	*comment = (char *) ustrdup(str);
}

void
read_msgfile(char *file)
{
	FILE *fp;
	char c = 0;
	int line = 0;
	int inmsg = FALSE;
	int setid = 0, unsetid = -1, msgid = 0;
	struct stat buf;

	if ((fp = fopen(file, "r")) == NULL) {
		prg_err(gettext("cannot open \"%s\""), file);
		ResetActiveMode(AppendMode);
		return;
	}

	if (stat(file, &buf) == -1 && buf.st_size == 0) {
		ResetActiveMode(AppendMode);
		return;
	}

	quote = c;

	/*CONSTCOND*/
	while (1) {
		char buf[LINE_MAX];
		char *ptr;
		char msg[NL_TEXTMAX];

		if (fgets(buf, sizeof (buf), fp) == NULL) {
			break;
		}

		line++;

		ptr = &buf[0];

		SkipSpace(ptr);

		if ((*ptr == '$' && (*(ptr+1) == ' ' || *(ptr+1) == '\t')) ||
			((*ptr == '\n') && inmsg == FALSE)) {
			inmsg = FALSE;
			continue;
		}

		if (strncmp(ptr, SET_TOKEN, sizeof (SET_TOKEN) - 1) == 0) {
			if (sscanf(ptr, "%*s %d", &setid) != 1) {
				setid = 0;
			}
			inmsg = FALSE;
			continue;
		} else if (strncmp(ptr, DELSET_TOKEN,
			sizeof (DELSET_TOKEN) - 1) == 0) {
			if (sscanf(ptr, "%*s %d", &unsetid) != 1) {
				unsetid = -1;
			}
			inmsg = FALSE;
			continue;
		} else if (strncmp(ptr, QUOTE_TOKEN,
			sizeof (QUOTE_TOKEN) - 1) == 0) {
			if (sscanf(ptr, "%*s %c", &c) != 1) {
				c = 0;
			}
			quote = c;
			inmsg = FALSE;
			continue;
		}

		if (setid == unsetid) {
			continue;
		}

		if (inmsg) {
			if (is_bs_terminated(ptr)) {
				(void) strcat(msg, ptr);
				inmsg = TRUE;
			} else {
				int len = strlen(ptr);
				*(ptr + len - 1) = '\0';
				if (c && (*(ptr + len - 2) == c)) {
					*(ptr + len - 2) = '\0';
				}
				(void) strcat(msg, ptr);
				add_msg(setid, msgid, msg, file, line, TRUE);
				inmsg = FALSE;
			}
			continue;
		}

		if (isdigit(*ptr)) {
			char tmp[32];
			int i = 0;

			SkipSpace(ptr);

			while (isdigit(*ptr)) {
				tmp[i++] = *ptr++;
			}
			tmp[i] = '\0';
			msgid = atoi(tmp);

			SkipSpace(ptr);

			if (is_bs_terminated(ptr)) {
				(void) memset(msg, 0, NL_TEXTMAX);
				if (c && (*ptr == c)) {
					ptr++;
				}
				(void) strcpy(msg, ptr);
				inmsg = TRUE;
			} else {
				int len = strlen(ptr);
				*(ptr + len - 1) = '\0';
				if (c && ((*ptr == c) &&
					(*(ptr + len - 2) == c))) {
					*(ptr + len - 2) = '\0';
					ptr++;
				}
				add_msg(setid, msgid, ptr, file, line, TRUE);
				inmsg = FALSE;
			}
		}
	}

	(void) fclose(fp);
}

static int
is_bs_terminated(char *msg)
{
	int len = strlen(msg);

	while (--len >= 0) {
		if (msg[len] == ' ' || msg[len] == '\t' || msg[len] == '\n') {
			continue;
		} else if (msg[len] == '\\') {
			len--;
			if (len >= 0 && msg[len] == '\\')
				return (0);
			return (1);
		} else {
			return (0);
		}
	}
	return (0);
}

static char *
ustrdup(char *str)
{
	char *tmp = strdup(str);
	if (!tmp) {
		prg_err(gettext("fatal: out of memory"));
		exit(EXIT_FAILURE);
	}
	return (tmp);
}

int
file_copy(char *in, char *out)
{
	int ret = TRUE;
	FILE *fin, *fout;
	int c;
	sigset_t newmask, oldmask;

	(void) sigemptyset(&newmask);
	(void) sigaddset(&newmask, SIGQUIT);
	(void) sigaddset(&newmask, SIGINT);
	(void) sigaddset(&newmask, SIGHUP);
	(void) sigaddset(&newmask, SIGTERM);
	(void) sigprocmask(SIG_BLOCK, &newmask, &oldmask);

	if ((fin = fopen(in, "r")) == NULL) {
		prg_err(gettext("cannot open \"%s\""), in);
		ret = FALSE;
		goto done;
	}

	if ((fout = fopen(out, "w")) == NULL) {
		prg_err(gettext("cannot create \"%s\""), out);
		ret = FALSE;
		goto done;
	}

	while ((c = getc(fin)) != EOF)
		(void) putc(c, fout);

	(void) fclose(fin);
	(void) fclose(fout);

done:
	(void) sigprocmask(SIG_SETMASK, &oldmask, NULL);
	return (ret);
}

static void
cat_msg(char *out, char *msg, int max)
{
	if (strlen(out) > max) {
		return;
	}

	(void) strncat(out, msg, max);

	if (strlen(out) > max) {
		out[max] = '\0';
	}
}

static void
makeup_msg(char **pmsg)
{
	char buf[NL_TEXTMAX];
	char *msg;

	msg = *pmsg;
	(void) memset((void *) buf, 0, NL_TEXTMAX);

	if (IsActiveMode(TripleMode) &&	!strchr(msg, '%')) {
		/* there is no '%' in message. */
		int len = strlen(msg);

		if (msg[len-2] == '\\' && msg[len-1] == 'n') {
			msg[len-2] = '\0';
			cat_msg(buf, msg, (NL_TEXTMAX - 2));
			cat_msg(buf, msg, (NL_TEXTMAX - 2));
			cat_msg(buf, msg, (NL_TEXTMAX - 2));
			cat_msg(buf, "\\n", NL_TEXTMAX);
		} else {
			cat_msg(buf, msg, NL_TEXTMAX);
			cat_msg(buf, msg, NL_TEXTMAX);
			cat_msg(buf, msg, NL_TEXTMAX);
		}
		free(msg);
		*pmsg = (char *) ustrdup(buf);
	}

	msg = *pmsg;
	(void) memset((void *) buf, 0, NL_TEXTMAX);

	if (IsActiveMode(PrefixMode)) {
		cat_msg(buf, premsg, NL_TEXTMAX);
		cat_msg(buf, msg, NL_TEXTMAX);
		free(msg);
		*pmsg = (char *) ustrdup(buf);
	}

	msg = *pmsg;
	(void) memset((void *) buf, 0, NL_TEXTMAX);

	if (IsActiveMode(SuffixMode)) {
		int len = strlen(msg);

		if (msg[len-2] == '\\' && msg[len-1] == 'n') {
			msg[len-2] = '\0';
			cat_msg(buf, msg, (NL_TEXTMAX - 2));
			cat_msg(buf, sufmsg, (NL_TEXTMAX - 2));
			cat_msg(buf, "\\n", NL_TEXTMAX);
		} else {
			cat_msg(buf, msg, NL_TEXTMAX);
			cat_msg(buf, sufmsg, NL_TEXTMAX);
		}
		free(msg);
		*pmsg = (char *) ustrdup(buf);
	}
}

void
prg_err(char *fmt, ...)
{
	va_list ap;
	char buf[BUFSIZ];

	va_start(ap, fmt);

	(void) vsprintf(buf, fmt, ap);

	(void) fprintf(stderr, "%s: %s\n", program, buf);

	va_end(ap);
}

void
src_err(char *file, int line, char *fmt, ...)
{
	va_list ap;
	char buf[BUFSIZ];
	char sbuf[BUFSIZ/2];
	char vbuf[BUFSIZ/2];

	if (suppress_error == TRUE) {
		return;
	}

	va_start(ap, fmt);

	(void) sprintf(sbuf, gettext("\"%s\", line %d: "), file, line);
	(void) vsprintf(vbuf, fmt, ap);

	(void) sprintf(buf, "%s%s\n", sbuf, vbuf);
	(void) fputs(buf, stderr);

	va_end(ap);
}
