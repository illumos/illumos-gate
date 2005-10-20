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
 * Copyright 1992 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/label.h> 
#include <sys/audit.h> 
#include <auevents.h> 

#define ON 1
#define OK 0 
#define OFF -1
#define COMMA  ','
#define COMMASTR ","

#define COMMON 0
#define SUCCESS 1
#define FAILURE 2

#define MAXFLDLEN 25 
#define MAXSTRLEN 360
#define MAXEVENT 11 

/* GLOBALS */

static int length;
static int pos = 0;

struct list {
	short count;
	short on[MAXEVENT+1]; 
	short off;
}; 
typedef struct list list_t; 

struct exception {
	short type;
	short exception;
};
typedef struct exception except_t;

static int	stringcopy(char *, char *, int);

/*
 * getauditflagschar() - convert bit flag to character string  
 * 
 * input: masks->as_success - audit on success 
 *	  masks->as_failure - audit on failure 
 *  	  verbose     - string format. 0 if short name; 1 if long name;  
 *
 * output: auditstring - resultant audit string 
 *
 * returns:  	0 - entry read ok
 *    		-1 - error
 */

int
getauditflagschar(char *auditstring, audit_state_t *masks, int verbose)  
{
	int i, j, k, mask_num;
	int list = -1, retstat = 0; 
	int except_list[3];
	char *prefix = "  ";
	except_t except[2];
	list_t lists[3]; 

	/* 
	 * initialize input buffer 
	 */
	strcpy(auditstring, "");
	/* 
	 * initialize lists struct 
	 */
	for (mask_num = COMMON; mask_num <= FAILURE; mask_num++) {
		lists[mask_num].count = 0;
		lists[mask_num].off = -1;
		for (i=0;i<MAXEVENT+1;i++)
			lists[mask_num].on[i] = -1;
	}
	/* 
	 * initialize exception lists 
	 */
	for (i = 0; i < 2; i++) {
		except[i].type = -1;
		except[i].exception = -1;
	}

	for (i = 0; i < 3; i++)
		except_list[i] = 0;

	/* 
	 * set length global 
	 */
	length = verbose;
	pos = 0;

	/* 
	 * find turned-on events - if on, store index of event  
	 * in one of the three event lists, common, success, failure.
	 */
	for ( i = 0; i < MAXEVENT; i++) {
		if (((event_class[i].event_mask & masks->as_success) > 0) ||
		  ((event_class[i].event_mask & masks->as_failure) > 0)) {

			/* 
			 * check for events in common 
			 */
			if (((event_class[i].event_mask & masks->as_success) > 
			  0) && 
			  ((event_class[i].event_mask & masks->as_failure) > 0))
				lists[COMMON].on[lists[COMMON].count++] = i;  
  
			/* 
			 * check for success events 
			 */
			if ((event_class[i].event_mask & masks->as_success) > 0)
				lists[SUCCESS].on[lists[SUCCESS].count++] = i;  
			else {
				except_list[SUCCESS]++;
			if (lists[SUCCESS].off == -1) 
				lists[SUCCESS].off = i;
			}
			/* 
			 * check for failure events 
			 */
			if ((event_class[i].event_mask & masks->as_failure) > 0)
				lists[FAILURE].on[lists[FAILURE].count++] = i;  
			else { 
				except_list[FAILURE]++;
				if (lists[FAILURE].off == -1)
				lists[FAILURE].off = i;
			}
		} else {
			except_list[COMMON]++;
			if (lists[COMMON].off == -1)  
			lists[COMMON].off = i;
		}
	}
	/* 
	* check for all set or all-1 set - output all and common exceptions. 
	*   the all or common state is exclusive; only one of the
	*   three, (+-)all, allowed
	*/
	/* 
	 * no exceptions 
	 */
	if (lists[COMMON].count >= MAXEVENT-2) {
		if (lists[COMMON].count == MAXEVENT)
			list = COMMON;

		/* 
		 * one exception 
		 */
		else if (lists[COMMON].count == MAXEVENT-1) {
			for (i=COMMON;i<=FAILURE && (list == -1);i++) {
				if (except_list[i] == 1) {
					list = COMMON;
					except[0].type = i;
					except[0].exception = lists[i].off;
				}
			}
		}
		/* 
		 * two exceptions 
		 */
		else if (lists[COMMON].count == MAXEVENT-2) {
			if (except_list[COMMON] == 1) {
				list = COMMON;
				except[0].type = COMMON;
				except[0].exception = lists[COMMON].off;
				for (i=SUCCESS;i<=FAILURE;i++) {
					if (except_list[i] == 1) {
						except[1].type = i;
						except[1].exception = lists[i].off;
					}
				}

			 } else if (except_list[COMMON] == 0) {
				for (i=SUCCESS,j=0;i<=FAILURE;i++) {
					if (except_list[i] == 1) {
						list = COMMON;
						except[j].type = i;
						except[j++].exception = lists[i].off;
					}
				}
			}
		}
	} else {
		/* 
		 * check for +all or -all 
		 */
		for (i=SUCCESS,j=0;i<=FAILURE;i++) { 
			if (lists[i].count >= MAXEVENT-1) {
				list = i; 
				except[j].type = i;
				if (lists[i].count != MAXEVENT) {
					if (lists[i].off != -1)
						except[j++].exception = 
						  lists[i].off;
					else
						except[j++].exception = 
						  lists[COMMON].off;
				} 
			}
		}
	}
	/* 
	 * output all and exceptions 
	 */
	if (list != -1) {
		if(list==SUCCESS) {
			if ((stringcopy(auditstring, "+", 0)) == -1)
				retstat = -1;
		}
		if(list==FAILURE) {
			if ((stringcopy(auditstring, "-", 0)) == -1)
				retstat = -1;
		}

		if (retstat == 0) {
			if (length) {
				if 
				  ((stringcopy(auditstring,event_class[11].event_lname,1)) == -1) 
					retstat = -1;
			} else 
				if ((stringcopy(auditstring, event_class[11].event_sname,1)) == -1) 
					retstat = -1;
		}

		if (retstat == 0) {
			/* 
			 * output exceptions 
			 */ 
			for (i=0;i<2 && except[i].exception != -1; i++) {
				if ((stringcopy(auditstring, "^", 0)) == -1)
					retstat = -1;
				if(except[i].type==SUCCESS) {
					if ((stringcopy(auditstring, "+", 0)) == -1)
						retstat = -1;
				}
				if (except[i].type==FAILURE) {
					if ((stringcopy(auditstring, "-", 0)) == -1)
						retstat = -1;
				}
				if (length == 1 && retstat == 0) {
					if ((stringcopy(auditstring, 
					 event_class[except[i].exception].event_lname, 1))==-1)
						retstat = -1;
				} else if (retstat == 0) {
					if ((stringcopy(auditstring, 
					event_class[except[i].exception].event_sname, 1))==-1) 
						retstat = -1;
				}
			}
		}
	} /* end of " all " processing */
   
	/* 
	 * process common events if no "all" was output 
	 */
	if (list == -1 && (lists[COMMON].count > 0) && retstat == 0) {
		/* 
		 * output common events first 
		 */
		for (j=0;j<lists[COMMON].count;j++) {
			if (length == 1) { 
				if ((stringcopy(auditstring, 
				 event_class[lists[COMMON].on[j]].event_lname, 1)) == -1)
					retstat = -1;
			} else if ((stringcopy(auditstring, 
			 event_class[lists[COMMON].on[j]].event_sname, 1)) == -1) 
				retstat = -1;
		}
		/* 
		 * remove common events from individual lists 
		 */
		if (retstat == 0) {
			for (i=SUCCESS;i<=FAILURE;i++) {
				for(j=0;j<lists[COMMON].count;j++) {
					for(k=0;k < lists[i].count;k++) { 
						if (lists[COMMON].on[j] == 
						  lists[i].on[k]) 
							lists[i].on[k] = -1;
					}
				}
			}
		}
	}

	/* 
	 * start processing individual event flags in success 
	 * and failure lists 
	 */
	if (list != COMMON && retstat == 0) {
		for (i=SUCCESS;i<=FAILURE;i++) {
			if(list != i) {
				if (i==SUCCESS) strcpy(prefix, "+");
				if (i==FAILURE) strcpy(prefix, "-");
				for (j=0;j<MAXEVENT && j<lists[i].count;j++) {
					if (lists[i].on[j] != -1) {
						if ((stringcopy(auditstring, prefix, 0)) == -1)
							retstat = -1;
						if (length == 1 && 
						  retstat == 0) {    
							if ((stringcopy(auditstring, 
							  event_class[lists[i].on[j]].event_lname, 1))==-1) 
							retstat = -1;
						} else if (retstat == 0) {
							if ((stringcopy(auditstring, 
							 event_class[lists[i].on[j]].event_sname, 1))==-1)
								retstat = -1;
						}
					}
				}
			}
		}
	}
	if ((stringcopy(auditstring, "\0", 2)) == -1)
		retstat = -1;

	return (retstat);
}

static int
stringcopy(char *auditstring, char *event,
    int flag)	/* if set, output comma after event */
{
	int retstat = 0;

	/* 
	 * check size 
	 */
	if (pos >= MAXSTRLEN) {
		fprintf(stderr,"getauditflagschar: Inputted buffer too small.\n");
		retstat = -1;
	} else if (flag != 2) {
		strcpy(auditstring+pos, event); 
		pos += strlen(event);
		if(flag) {
			strcpy(auditstring+pos, COMMASTR); 
			pos += strlen(COMMASTR); 
		}
	} else {
		/* 
		 * add null terminator only 
		 */
		if (pos)
			strcpy(auditstring+(pos-1), event);

	}
	return (retstat);
}

/*
 * getauditflagsbin() -  converts character string to success and 
 *			 failure bit masks
 * 
 * input: auditstring - audit string 
 *  	  cnt - number of elements in the masks array 
 *
 * output: masks->as_success - audit on success 
 *         masks->as_failure - audit on failure 
 *
 * returns: 0 - ok
 *    	    -1 - error - string contains characters which do 
 *        		not match event flag names
 */

int
getauditflagsbin(char *auditstring, audit_state_t *masks)  
{
	int i, gotone, done = 0, invert = 0, tryagain;
	int retstat = 0, succ_event, fail_event;
	char *ptr, tmp_buff[MAXFLDLEN];

	/* 
	 * process character string 
	 */
	do {
		gotone = 0;
		/* 
		 * read through string storing chars. until a comma 
		 */
		for (ptr=tmp_buff; !gotone;) {
			if(*auditstring!=COMMA && *auditstring!='\0' && 
			  *auditstring!='\n' && *auditstring!=' ')
				*ptr++ = *auditstring++;
			else if (*auditstring == ' ')
				*auditstring++;
			else {
				if (*auditstring == '\0' || 
				  *auditstring == '\n') {
					done = 1;
					if (ptr == tmp_buff)
						done = 2;
				}
				gotone = 1;
			}
		}
		/* 
		 * process audit state 
		 */
		if(gotone && done != 2) { 
			if(!done) auditstring++;
			*ptr++ = '\0';
			ptr = tmp_buff;
			gotone = 0;
			succ_event = ON;
			fail_event = ON;
			tryagain = 1;
			invert = 0;

			/* 
			 * get flags 
			 */
			do { 
				switch (*ptr++) {
				case '^':
					invert = 1;
					succ_event = OFF;
					fail_event = OFF;
					break;
				case '+':
					if (invert) 
						fail_event = OK;
					else {
						succ_event = ON;
						fail_event = OK;
					}
					break;
				case '-':
					if (invert) 
						succ_event = OK;
					else {
						fail_event = ON;
						succ_event = OK;
					}
					break;
				default:
					tryagain = 0;
					ptr--;
					break;
				}
			} while(tryagain);

			/* add audit state to mask */
			for (i=0;i<MAXEVENT+1 && !gotone;i++) {
				if ((!(strcmp(ptr, event_class[i].event_sname))) ||
				 (!(strcmp(ptr, event_class[i].event_lname)))) {
					if (succ_event == ON)
						masks->as_success |= event_class[i].event_mask;
					else if (succ_event == OFF)
						masks->as_success &= ~(event_class[i].event_mask);
					if (fail_event == ON)
						masks->as_failure |= event_class[i].event_mask;
					else if (fail_event == OFF)
						masks->as_failure &= ~(event_class[i].event_mask);
					gotone = 1;
				}
			}
			if(!gotone) {
				retstat = -1;
				done = 1;
			}
		} 
	} while (!done);
			
	return (retstat); 
}
