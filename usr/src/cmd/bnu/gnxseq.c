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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include "uucp.h"

/*
 * get next conversation sequence number
 *	rmtname	-> name of remote system
 * returns:
 *	0	-> no entery
 *	1	-> 0 sequence number
 */
int
gnxseq(char *rmtname)
{
	register FILE *fp0, *fp1;
	register struct tm *tp;
	int count = 0, ct, ret;
	char buf[BUFSIZ], name[NAMESIZE];
	time_t clock;

	if (access(SQFILE, 0) != 0)
		return (0);

	{
		int i;
		for (i = 0; i < 5; i++)
			if ((ret = mklock(SQLOCK)) == SUCCESS)
				break;
		sleep(5);
	}
	if (ret != SUCCESS) {
		logent("CAN'T LOCK", SQLOCK);
		DEBUG(4, "can't lock %s\n", SQLOCK);
		return (0);
	}
	if ((fp0 = fopen(SQFILE, "r")) == NULL)
		return (0);
	if ((fp1 = fopen(SQTMP, "w")) == NULL) {
		fclose(fp0);
		return (0);
	}
	chmod(SQTMP, DFILEMODE);

	while (fgets(buf, BUFSIZ, fp0) != NULL) {
		ret = sscanf(buf, "%s%d", name, &ct);
		if (ret < 2)
			ct = 0;
		name[7] = '\0';
		if (ct > 9998)
			ct = 0;
		if (strncmp(rmtname, name, SYSNSIZE) != SAME) {
			fputs(buf, fp1);
			continue;
		}

		/*
		 * found name
		 */
		count = ++ct;
		time(&clock);
		tp = localtime(&clock);
		fprintf(fp1, "%s %d %d/%d-%d:%2.2d\n", name, ct,
		    tp->tm_mon + 1, tp->tm_mday, tp->tm_hour,
		    tp->tm_min);

		/*
		 * write should be checked
		 */
		while (fgets(buf, BUFSIZ, fp0) != NULL)
			fputs(buf, fp1);
	}
	fclose(fp0);
	fclose(fp1);
	if (count == 0) {
		rmlock(SQLOCK);
		unlink(SQTMP);
	}
	return (count);
}

/*
 * commit sequence update
 * returns:
 *	0	-> ok
 *	other	-> link failed
 */
int
cmtseq(void)
{
	int ret;

	if ((ret = access(SQTMP, 0)) != 0) {
		rmlock(SQLOCK);
		return (0);
	}
	unlink(SQFILE);
	ret = link(SQTMP, SQFILE);
	unlink(SQTMP);
	rmlock(SQLOCK);
	return (ret);
}

/*
 * unlock sequence file
 */
void
ulkseq(void)
{
	unlink(SQTMP);
	rmlock(SQLOCK);
}
