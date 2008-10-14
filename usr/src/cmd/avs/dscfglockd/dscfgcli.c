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

#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <locale.h>
#include <sys/nsctl/cfg.h>

CFGFILE *cfg;
void	cfg_lockd_stat();
int	tty;

static void
test(int count)
{
	struct stat sb;
	int i;

	if (count < 1)
		count = 1;
	for (i = 0; count-- > 0; i++) {
		if (cfg_lock(cfg, CFG_RDLOCK) < 0)
			(void) printf("CFG_RDLOCK error\n");
		else
			fstat(0, &sb);

		cfg_unlock(cfg);
		fstat(1, &sb);

		if (cfg_lock(cfg, CFG_RDLOCK) < 0)
			(void) printf("CFG_RDLOCK error\n");
		else
			fstat(0, &sb);

		cfg_unlock(cfg);
		fstat(1, &sb);

		if (cfg_lock(cfg, CFG_WRLOCK) < 0)
			(void) printf("CFG_WRLOCK error\n");
		else
			fstat(0, &sb);

		cfg_unlock(cfg);
		fstat(1, &sb);

		if (i > 0) {
			if (i % 100 == 0)
				(void) write(1, "+", 1);
			if (i % 5000 == 0)
				(void) write(1, "\n", 1);
		}
	}
	(void) printf("\nTest complete\n");
}

static void
cmd_loop()
{
	char	host[1024];
	char	buffer[1024];
	int	i;

	(void) gethostname(host, sizeof (host));
	for (;;) {
		if (tty)
			(void) printf(":%s: ", host);
		(void) fgets(buffer, sizeof (buffer), stdin);
		switch (tolower(buffer[0])) {
			case 'p':
				i = atoi(buffer + 1);
				(void) sleep(i);
				break;
			case 'q':
				exit(0);
				break;
			case 'r':
				if (cfg_lock(cfg, CFG_RDLOCK) < 0)
					(void) printf("CFG_RDLOCK error\n");
				break;
			case 's':
				cfg_lockd_stat();
				break;
			case 't':
				i = atoi(buffer + 1);
				test(i);
				break;
			case 'u':
				cfg_unlock(cfg);
				break;
			case 'w':
				if (cfg_lock(cfg, CFG_WRLOCK) < 0)
					(void) printf("CFG_WRLOCK error\n");
				break;
			default:
				(void) printf("don't understand %s\n", buffer);
				break;
		}
	}
}

static void
init()
{
	tty = isatty(0);
	if (tty)
		(void) printf("dscfglockd cli %s\n", "07/06/12");
	if ((cfg = cfg_open(NULL)) == NULL) {
		perror("cfg_open");
		exit(1);
	}
}

int
main(void)
{
	init();
	cmd_loop();
	return (0);
}
