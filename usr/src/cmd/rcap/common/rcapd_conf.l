%{
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
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include "rcapd.h"
#include "rcapd_conf.h"
#include "rcapd_stat.h"
#include "utils.h"

#define	LINELEN	256

/*PRINTFLIKE1*/
static void
parse_err(char *filename, char *str, ...)
{
	va_list alist;
	char buf[LINELEN];

	(void) snprintf(buf, LINELEN - 1, "%s: line %d: ", filename, yylineno);
	va_start(alist, str);
	(void) vsnprintf(buf + strlen(buf), LINELEN - 1 - strlen(buf), str,
	    alist);
	va_end(alist);
	dprintfe(RCM_ERR, buf);

	exit(E_ERROR);
	/*NOTREACHED*/
}

#define	CFG_EXPECT(ttype, context) {				\
		if (yylex() != ttype) {				\
			parse_err(name, context);		\
		}						\
	}

#define	YYSTYPE	yystype_t

typedef union {
	int	id;
} yystype_t;

extern yystype_t yylval;
%}

%x fn

%%

<fn>\=			{ return (RCT_EQUALS); }
<fn>[ \t]		{ break; }
<fn>[^ \t\n]+		{ BEGIN(INITIAL); return (RCT_FILENAME); }

"RCAPD_MODE" 		{ return (RCT_MODE_VAR); }
"RCAPD_STATE"		{ return (RCT_STATE); }
"RCAPD_PROC_WALK_INTERVAL"	{ return (RCT_PROC_WALK_INTERVAL_VAR); }

"RCAPD_RECONFIGURATION_INTERVAL"	{ return
					    (RCT_RECONFIGURATION_INTERVAL_VAR);
					}
"RCAPD_REPORT_INTERVAL" \
			{ return (RCT_REPORT_INTERVAL_VAR); }
"RCAPD_RSS_SAMPLE_INTERVAL" \
			{ return (RCT_RSS_SAMPLE_INTERVAL_VAR); }
"RCAPD_MEMORY_CAP_ENFORCEMENT_PRESSURE" \
			{ return (RCT_MEMORY_CAP_ENFORCEMENT_PRESSURE_VAR); }
"RCAPD_STATISTICS_FILE"	{ BEGIN(fn); return (RCT_STAT_FILE_VAR); }
\=			{ return (RCT_EQUALS); }
[0-9]+			{ return (RCT_NUMBER); }
"project"		{ return (RCT_PROJECT); }
"lnode"			{ return (RCT_LNODE); }
"on"			{ return (RCT_ON); }
"off"			{ return (RCT_OFF); }

[ \t]			{ break; }
\#.*			{ break; }
\n			{ break; }
[^ \t\n]*		{ return (RCT_INVALID); }

%%

/*
 * Read the supplied configuration file and set the fields of an rcfg_t
 * correspondingly.  Verify that the statistics file is writable, with the
 * optional verify_stat_file_creation() callback.
 *
 * fd should be the number of a low-numbered (<256) file descriptor on 32-bit
 * processes, as stdio requires them to be in that range.  The actual
 * descriptor will be recorded in rcfg and left open, and may be supplied in
 * future calls to rcfg_read(), simplifying descriptor distribution.
 */
int
rcfg_read(char *name, int fd, rcfg_t *_rcfg,
    int(*verify_stat_file_creation)(void))
{
	rctoken_t l;
	FILE *f;
	struct stat stat;

	if (fd >= 0)
		(void) close(fd);
	if ((fd = open(name, O_RDONLY)) < 0)
		return (-1);
	if ((f = fdopen(fd, "r")) == NULL)
		return (-1);
	if (strlen(name) >= sizeof (_rcfg->rcfg_filename)) {
		errno = EINVAL;
		return (-1);
	}

	rcfg_init(_rcfg);
	(void) strcpy(_rcfg->rcfg_filename, name);
	_rcfg->rcfg_fd = fd;
	if (fstat(fd, &stat) == 0)
		_rcfg->rcfg_last_modification = stat.st_mtime;

	yyin = f;
	l = 0;
	for (; (l = yylex()) != 0; ) {
		switch (l) {
		case RCT_MODE_VAR:
			if (_rcfg->rcfg_mode_name != NULL)
				parse_err(name, "RCAPD_MODE already set\n");
			CFG_EXPECT(RCT_EQUALS, "Expecting '='\n");
			l = yylex();
			if (l == RCT_PROJECT) {
				_rcfg->rcfg_mode = rctype_project;
				_rcfg->rcfg_mode_name = "project";
			} else if (l == RCT_LNODE) {
				/*
				 * Provided for compatibility with old
				 * configuration files.  The consumer is
				 * expected to warn that the mode setting is
				 * ineffective when anything other than
				 * "project" is specified.
				 */
				_rcfg->rcfg_mode_name = "lnode";
			} else
				parse_err(name, "RCAPD_MODE must be "
				    "\"project\", and is unused.\n");
			debug("%s: mode: %s\n", name,
			    _rcfg->rcfg_mode_name);
			break;
		case RCT_STATE:
			/* legacy variable is ignored */
			CFG_EXPECT(RCT_EQUALS, "Expecting '='\n");
			l = yylex();
			debug("%s: state ignored\n", name);
			break;
		case RCT_REPORT_INTERVAL_VAR:
			CFG_EXPECT(RCT_EQUALS, "Expecting '='\n");
			CFG_EXPECT(RCT_NUMBER, "Expecting time value "
			    "(seconds)\n");
			_rcfg->rcfg_report_interval = atoi(yytext);
			debug("%s: report interval: %d seconds\n", name,
			    _rcfg->rcfg_report_interval);
			break;
		case RCT_RSS_SAMPLE_INTERVAL_VAR:
			CFG_EXPECT(RCT_EQUALS, "Expecting '='\n");
			CFG_EXPECT(RCT_NUMBER, "Expecting time value "
			    "(seconds)\n");
			_rcfg->rcfg_rss_sample_interval = atoi(yytext);
			debug("%s: RSS sample interval: %d seconds\n", name,
			    _rcfg->rcfg_rss_sample_interval);
			break;
		case RCT_STAT_FILE_VAR:
			CFG_EXPECT(RCT_EQUALS, "Expecting '='\n");
			CFG_EXPECT(RCT_FILENAME, "Expecting filename\n");
			if (strlen(yytext) >= sizeof (_rcfg->rcfg_stat_file))
				parse_err(name, "Path too long");
			if (yytext[0] != '/')
				parse_err(name, "Path not absolute");
			(void) strcpy(_rcfg->rcfg_stat_file, yytext);
			debug("%s: statistics file: %s\n", name, _rcfg->rcfg_stat_file);
			break;
		case RCT_RECONFIGURATION_INTERVAL_VAR:
			CFG_EXPECT(RCT_EQUALS, "Expecting '='\n");
			CFG_EXPECT(RCT_NUMBER, "Expecting time value "
			    "(seconds)\n");
			_rcfg->rcfg_reconfiguration_interval = atoi(yytext);
			debug("%s: reconfiguration interval: %d seconds\n",
			    name, _rcfg->rcfg_reconfiguration_interval);
			break;
		case RCT_PROC_WALK_INTERVAL_VAR:
			CFG_EXPECT(RCT_EQUALS, "Expecting '='\n");
			CFG_EXPECT(RCT_NUMBER, "Expecting time value "
			    "(seconds)\n");
			_rcfg->rcfg_proc_walk_interval = atoi(yytext);
			debug("%s: proc_walk interval: %d seconds\n",
			    name, _rcfg->rcfg_proc_walk_interval);
			break;
		case RCT_MEMORY_CAP_ENFORCEMENT_PRESSURE_VAR:
			CFG_EXPECT(RCT_EQUALS, "Expecting '='\n");
			CFG_EXPECT(RCT_NUMBER, "Expecting integer value (%)\n");
			if ((_rcfg->rcfg_memory_cap_enforcement_pressure =
			    atoi(yytext)) < 0)
				_rcfg->rcfg_memory_cap_enforcement_pressure = 0;
			debug("%s: cap max pressure: %d%%\n", name,
			    _rcfg->rcfg_memory_cap_enforcement_pressure);
			break;
		default:
			parse_err(name, "Unexpected input: %s\n", yytext);
		}
	}
	if (_rcfg->rcfg_mode_name == NULL) {
		/*
		 * Set project mode, by default.
		 */
		_rcfg->rcfg_mode = rctype_project;
		_rcfg->rcfg_mode_name = "project";
		debug("%s: mode: %s\n", name, _rcfg->rcfg_mode_name);
	}
	if (verify_stat_file_creation != 0 && verify_stat_file_creation() != 0)
		die(gettext("cannot create statistics file, " "%s"),
		    _rcfg->rcfg_stat_file);
	debug("%s: done parsing\n", name);

	return (0);
}

void
rcfg_init(rcfg_t *rcfg)
{
	bzero(rcfg, sizeof (*rcfg));
	rcfg->rcfg_proc_walk_interval = 15;
	rcfg->rcfg_reconfiguration_interval = 60;
	rcfg->rcfg_report_interval = 5;
	rcfg->rcfg_rss_sample_interval = 5;
	rcfg->rcfg_memory_cap_enforcement_pressure = 0;
	(void) strcpy(rcfg->rcfg_stat_file, STAT_FILE_DEFAULT);
}

/*
 * Create the configuration file given the rcfg_t structure. If a rcfg_t
 * structure is NULL, create the configuration file with default parameters.
 */
void
create_config_file(rcfg_t *conf)
{
	char *fname = RCAPD_DEFAULT_CONF_FILE;
	char *template;
	FILE *fp;
	mode_t	mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
	int fd, olderrno, create_default = 0;

	if (conf == NULL) {
		create_default = 1;
		if ((conf = malloc(sizeof (*conf))) == NULL)
			die(gettext("memory allocation failure"));

		/* Initialize config file with default parameters */
		rcfg_init(conf);
		conf->rcfg_mode_name = "project";
	}

	if ((template = malloc(strlen(fname) +
	    strlen(CFG_TEMPLATE_SUFFIX) + 1)) == NULL)
		die(gettext("memory allocation failure"));

	(void) strcpy(template, fname);
	(void) strcat(template, CFG_TEMPLATE_SUFFIX);

	if ((fd = mkstemp(template)) < 0)
		die(gettext("failed to create a temporary file %s"),
		    template);

	if ((fp = fdopen(fd, "w")) == NULL) {
		olderrno = errno;
		(void) close(fd);
		if (unlink(template) < 0)
			warn(gettext("could not unlink temp file %s"),
			    template);
		errno = olderrno;
		die(gettext("Failed to open output file %s"), template);
	}

	(void) fputs("#\n# rcap.conf\n#\n"
	    "# Configuration parameters for resource capping daemon.\n"
	    "# Do NOT edit by hand -- use rcapadm(1m) instead.\n"
	    "#\n", fp);
	(void) fprintf(fp, "RCAPD_MEMORY_CAP_ENFORCEMENT_PRESSURE  "
	    "= %d\n", conf->rcfg_memory_cap_enforcement_pressure);
	(void) fprintf(fp, "RCAPD_RECONFIGURATION_INTERVAL         "
	    "= %d\n", conf->rcfg_reconfiguration_interval);
	(void) fprintf(fp, "RCAPD_PROC_WALK_INTERVAL               "
	    "= %d\n", conf->rcfg_proc_walk_interval);
	(void) fprintf(fp, "RCAPD_REPORT_INTERVAL                  "
	    "= %d\n", conf->rcfg_report_interval);
	(void) fprintf(fp, "RCAPD_RSS_SAMPLE_INTERVAL              "
	    "= %d\n", conf->rcfg_rss_sample_interval);

	if (fchmod(fd, mode) != 0) {
		olderrno = errno;
		(void) fclose(fp);
		if (unlink(template) < 0)
			warn(gettext("could not unlink temp file %s"),
			    template);
		errno = olderrno;
		die(gettext("failed to fchmod %s to %o"), template, mode);
	}

	if (rename(template, fname) != 0) {
		olderrno = errno;
		(void) fclose(fp);
		if (unlink(template) < 0)
			warn(gettext("could not unlink temp file %s"),
			    template);
		errno = olderrno;
		die(gettext("could not rename temporary file to %s"), fname);
	}

	(void) fclose(fp);
	free(template);

	if (create_default == 1)
		free(conf);
}
