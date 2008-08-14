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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <mms.h>
#include <mms_cores.h>
#include <ctype.h>

#define	BUFSZ 1024


typedef struct cli_data cli_data_t;
struct cli_data {
	char			*host;
	char			*port;
	char			*client;
	char			*instance;
	char			*password;
	char			*tag;
	char			*mm_pass;
	char			*net_file;
	mms_network_cfg_t		net;
	int			exiting;
	mms_list_t			async_list;
	int			async_waiting;
	pthread_mutex_t		cli_async_lock;
	char			*tag_to_sync;
	int			wait_for_sync;
	int			sync_has_namevalue;
	void			*ssl_data;
	int			waiting_to_exit;
	pthread_cond_t		async_cv;
	pthread_mutex_t		async_mutex;
};

typedef struct cli_cmd cli_cmd_t;
struct cli_cmd {
	mms_list_node_t		cli_cmd_next;
	int			cmd_is_sync;
	char			*cmd_text;
	char			*cmd_task;
	void			*cmd_rsp;
	mms_par_node_t		*cmd_root;
	int			cmd_namevalue;
	char			*cmd_tag;
};

cli_data_t data;
void	*sp;

pthread_attr_t	event_attr;
pthread_attr_t	cmd_attr;

extern
int mms_ainit(void **, int *, mms_callbk_t *, mms_rsp_callbk_t *);

cli_cmd_t *
cli_alloc_cmd() {
	cli_cmd_t *cmd;

	cmd = (cli_cmd_t *)calloc(1, sizeof (cli_cmd_t));
	if (cmd == NULL) {
		printf("could not allocate mem for new command");
		exit(1);
	}
	cmd->cmd_text = NULL;
	cmd->cmd_task = NULL;
	cmd->cmd_rsp = NULL;
	cmd->cmd_namevalue = 0;
	return (cmd);
}

void
cli_destroy_cmd(cli_cmd_t *cmd) {

	if (cmd->cmd_text != NULL) {
		free(cmd->cmd_text);
	}
	if (cmd->cmd_task != NULL) {
		free(cmd->cmd_task);
	}
	if (cmd->cmd_rsp != NULL) {
		mms_free_rsp(cmd->cmd_rsp);
	}
	if (cmd->cmd_tag != NULL) {
		free(cmd->cmd_tag);
	}
	if (cmd->cmd_root != NULL) {
		mms_pn_destroy(cmd->cmd_root);
	}
	free(cmd);
}

void
/* LINTED: void arg is required */
mms_catch_reader(void *ev)
{
	printf("mms_catch_reader: Reader shutting down\n");
}

void
mms_client_errlog(char *prefix, char *msg)
{
	printf("mms_client_errlog: prefix - %s\nmsg - %s\n", prefix, msg);
}

/*ARGSUSED*/
static void
client_handle_event(void *param, void *ev)
{
	mms_rsp_ele_t *lev = (mms_rsp_ele_t *)ev;

	if (lev->mms_rsp_str != NULL) {
		printf("Event received:\n    %s\n",
		    lev->mms_rsp_str);
		fflush(stdout);
	}
}

static
void
attrlist(mms_par_node_t *attrlist, int namevalue)
{
	mms_par_node_t	*arg;
	mms_par_node_t	*work;

	printf("   attrlist\n");
	work = NULL;
	for (arg = mms_pn_lookup_arg(attrlist, NULL, NULL, &work);
	    arg != NULL;
	    arg = mms_pn_lookup_arg(attrlist, NULL, NULL, &work)) {
		if (arg->pn_type & MMS_PN_STRING) {
			if (namevalue) {
				/* print 2 */
				printf("    %s",
				    arg->pn_string);
				arg = mms_pn_lookup_arg(attrlist,
				    NULL, NULL, &work);
				printf(" %s\n",
				    arg->pn_string);

			} else {
				/* print 1 */
				printf("    %s\n",
				    arg->pn_string);
			}
		}
	}
}


static
void
text_clause(mms_par_node_t *text, int namevalue)
{
	mms_par_node_t	*arg;
	mms_par_node_t	*work;

	printf(" text\n");
	work = NULL;
	for (arg = mms_pn_lookup_arg(text, NULL, NULL, &work);
	    arg != NULL;
	    arg = mms_pn_lookup_arg(text, NULL, NULL, &work)) {

		if ((arg->pn_type & MMS_PN_CLAUSE) &&
		    (strcmp(arg->pn_string, "attrlist") == 0)) {
			attrlist(arg, namevalue);

		}
		if (arg->pn_type & MMS_PN_STRING) {
			if (namevalue) {
				/* print 2 */
				printf("  %s",
				    arg->pn_string);
				arg = mms_pn_lookup_arg(text,
				    NULL, NULL, &work);
				printf(" %s\n",
				    arg->pn_string);

			} else {
				/* print 1 */
				printf("  %s\n",
				    arg->pn_string);
			}
		}

	}
}

static void
cli_print_async_rsp(mms_rsp_ele_t *lrsp) {
	/* lrsp->mms_rsp_cmd is */
	/* the parse tree of the response */
	mms_par_node_t	*work;
	mms_par_node_t	*text;
	mms_par_node_t	*cmd;

	cli_cmd_t *cur_cmd;
	cli_cmd_t *next;

	int namevalue = 0;

	cmd = lrsp->mms_rsp_cmd;

	printf("success, %s\n",
	    lrsp->mms_rsp_tid);

	for (cur_cmd = mms_list_head(&data.async_list);
	    cur_cmd != NULL;
	    cur_cmd = next) {
		next = mms_list_next(&data.async_list, cur_cmd);
		/* Test task and remove if the same */
		if (strcmp(cur_cmd->cmd_task,
		    lrsp->mms_rsp_tid) == 0) {
			namevalue = cur_cmd->cmd_namevalue;
			break;
		}
	}



	work = NULL;
	/* For each text clause print the results */

	for (text = mms_pn_lookup(cmd,
	    "text", MMS_PN_CLAUSE, &work);
	    text != NULL;
	    text = mms_pn_lookup(cmd,
	    "text", MMS_PN_CLAUSE, &work)) {
		text_clause(text, namevalue);
	}
	fflush(stdout);
}

static void
cli_print_sync_rsp(mms_rsp_ele_t *lrsp) {
	/* lrsp->mms_rsp_cmd is */
	/* the parse tree of the response */
	mms_par_node_t	*work;
	mms_par_node_t	*text;
	mms_par_node_t	*cmd;
	cmd = lrsp->mms_rsp_cmd;

	printf("success, %s\n",
	    lrsp->mms_rsp_tid);
	work = NULL;
	/* For each text clause print the results */

	for (text = mms_pn_lookup(cmd,
	    "text", MMS_PN_CLAUSE, &work);
	    text != NULL;
	    text = mms_pn_lookup(cmd,
	    "text", MMS_PN_CLAUSE, &work)) {
		text_clause(text, data.sync_has_namevalue);
	}
	data.sync_has_namevalue = 0;
	fflush(stdout);
}

static void
mms_client_handle_rsp(void *rsp)
{
	int	class;
	int	code;
	char	*msg;

	mms_rsp_ele_t	*lrsp = (mms_rsp_ele_t *)rsp;

	switch (mms_rsp_type(rsp)) {
		case MMS_API_RSP_UNACC:
			printf("Command was not accepted\n");
			printf("Response - %s\n", lrsp->mms_rsp_str);
			break;
		case MMS_API_RSP_FINAL:
			printf("Command was successful\n");
			cli_print_sync_rsp(lrsp);
			break;
		case MMS_API_RSP_FINAL_ERR:
			printf("Command received an error response\n");
			printf("Response - %s\n", lrsp->mms_rsp_str);
			if (mms_handle_err_rsp(rsp, &class, &code,
			    &msg) != MMS_API_OK) {
				printf("Error response handler failed\n");
				break;
			}
			printf("Error class %d, %s\n", class,
			    mms_sym_code_to_str(class));
			printf("Error code %d, %s\n", code,
			    mms_sym_code_to_str(code));
			if (msg != NULL)
				printf("Error message:\n%s\n", msg);
			else
				printf("No message clause in error rsp\n");
			break;
		case MMS_API_RSP_FINAL_CANC:
			printf("Command received a cancelled response\n");
			printf("Response - %s\n", lrsp->mms_rsp_str);
			break;
		default:
			printf("Unknow response type\n");
			printf("Response - %s\n", lrsp->mms_rsp_str);
			break;
	}
}


void
/* LINTED: param required */
mms_client_handle_async_rsp(void *param, void *rsp)
{

	int	class;
	int	code;

	char	*msg;

	mms_rsp_ele_t	*lrsp = (mms_rsp_ele_t *)rsp;

	cli_cmd_t *cur_cmd;
	cli_cmd_t *next;
	cli_cmd_t *remove_cmd;

	int found_other = 0;

	pthread_mutex_lock(&data.
	    cli_async_lock);

	switch (mms_rsp_type(rsp)) {
		case MMS_API_RSP_UNACC:
			printf("Command was not accepted\n");
			printf("Response - %s\n", lrsp->mms_rsp_str);
			break;
		case MMS_API_RSP_FINAL:
			printf("\n\nCommand was successful\n");
			cli_print_async_rsp(lrsp);
			printf("\n\n");
			break;
		case MMS_API_RSP_FINAL_ERR:
			printf("Command received an error response\n");
			printf("Response - %s\n", lrsp->mms_rsp_str);
			if (mms_handle_err_rsp(rsp, &class, &code,
			    &msg) != MMS_API_OK) {
				printf("Error response handler failed\n");
				break;
			}
			printf("Error class %d, %s\n", class,
			    mms_sym_code_to_str(class));
			printf("Error code %d, %s\n", code,
			    mms_sym_code_to_str(code));
			if (msg != NULL)
				printf("Error message:\n%s\n", msg);
			else
				printf("No message clause in error rsp\n");
			break;
		case MMS_API_RSP_FINAL_CANC:
			printf("Command received a cancelled response\n");
			printf("Response - %s\n", lrsp->mms_rsp_str);
			break;
		default:
			printf("Unknow response type\n");
			printf("Response - %s\n", lrsp->mms_rsp_str);
			break;
	}


	for (cur_cmd = mms_list_head(&data.async_list);
	    cur_cmd != NULL;
	    cur_cmd = next) {
		next = mms_list_next(&data.async_list, cur_cmd);
		/* Test task and remove if the same */
		if (strcmp(cur_cmd->cmd_task,
		    lrsp->mms_rsp_tid) == 0) {
			mms_list_remove(&data.async_list,
			    cur_cmd);
			remove_cmd = cur_cmd;
		} else {
			/* there is at least one other */
			/* async command waiting */
			found_other = 1;
		}
	}

	/* There are no async commands left */
	if (!found_other) {
		pthread_mutex_lock(&data.async_mutex);
		data.async_waiting = 0;
		if (data.waiting_to_exit) {
			pthread_cond_signal(&data.async_cv);
		}
		pthread_mutex_unlock(&data.async_mutex);
	}

	/* If we are waiting for a sync point check if this is the response */
	/* we are waiting for */
	if (data.wait_for_sync == 1 && data.tag_to_sync != NULL) {
		if (strstr(data.tag_to_sync, lrsp->mms_rsp_tid) != NULL) {
			/* Got the response we are waiting for */
			free(data.tag_to_sync);
			data.tag_to_sync = NULL;
			data.wait_for_sync = 0;
		}
	}

	mms_free_rsp(rsp);
	remove_cmd->cmd_rsp = NULL;
	cli_destroy_cmd(remove_cmd);
	pthread_mutex_unlock(&data.
	    cli_async_lock);

}

int
cli_need_arsp(char *buf) {
	cli_cmd_t *cur_cmd;
	cli_cmd_t *next;

	pthread_mutex_lock(&data.
	    cli_async_lock);
	for (cur_cmd = mms_list_head(&data.async_list);
	    cur_cmd != NULL;
	    cur_cmd = next) {
		next = mms_list_next(&data.async_list, cur_cmd);
		if (strstr(buf, cur_cmd->cmd_task) != NULL) {

			pthread_mutex_unlock(&data.
			    cli_async_lock);
			return (1);
		}
	}

	pthread_mutex_unlock(&data.
	    cli_async_lock);
	return (0);
}

static void
mms_client_signal_handler(int signo)
{
	if (signo == SIGPIPE)
		data.exiting = 1;
}

static void
mms_client_signal(int sig, void (*handler) ())
{
	struct sigaction act, oact;

	memset(&act, 0, sizeof (act));
	act.sa_sigaction = handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sig != SIGALRM) {
		act.sa_flags |= SA_RESTART;
	}
	if (sigaction(sig, &act, &oact) < 0) {
		(void) printf("Can't set signal handler for "
		    "signal %d: %s", sig, strerror(errno));
		exit(1);
	}
}

static void
mms_client_init()
{
	int	rc;
	int	vers;

	mms_callbk_t		err_callbk;
	mms_rsp_callbk_t	ev_callbk;

	mms_err_t	 mms_err;
	char		 mms_ebuf[MMS_EBUF_LEN];

	sigset_t	new_mask;
	sigset_t	old_mask;

	sigemptyset(&new_mask);
	sigaddset(&new_mask, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask);
	mms_client_signal(SIGPIPE, mms_client_signal_handler);

	err_callbk.mms_func = &mms_catch_reader;
	err_callbk.mms_param = NULL;

	ev_callbk.mms_func = &client_handle_event;
	ev_callbk.mms_param = NULL;

	if ((rc = mms_ainit(&sp, &vers, &err_callbk,
	    &ev_callbk)) != MMS_API_OK) {
		printf("Error in mms_ainit(), %d, %s\n", rc,
		    mms_sym_code_to_str(rc));
		exit(1);
	}

	if (vers != MMS_API_VERSION) {
		printf("Mismatch of versions between client %d and API %d\n",
		    MMS_API_VERSION, vers);
		exit(1);
	}

	printf("Connect to MM:\n");
	printf("    Host: %s\n", data.host);
	printf("    Port: %s\n", data.port);
	printf("    Client: %s\n", data.client);
	printf("    Instance: %s\n", data.instance);
	printf("    Password:\n");
	printf("    Tag: %s\n", data.tag);


#ifdef	MMS_OPENSSL
	if (mms_ssl_client(&data.net, &data.ssl_data, &mms_err)) {

		mms_get_error_string(&mms_err, mms_ebuf, MMS_EBUF_LEN);
		fprintf(stderr, "ssl init - %s\n", mms_ebuf);

		fprintf(stderr, "Couldn't init ssl\n");
		exit(1);
	}
#endif	/* MMS_OPENSSL */


	if ((rc = mms_hello(sp, data.host, data.port,
	    data.client, data.instance, data.tag,
	    data.password, data.mm_pass, data.ssl_data)) != MMS_API_OK) {
		printf("Error in mms_hello(), %d, %s\n", rc,
		    mms_sym_code_to_str(rc));
		exit(1);
	}

	if ((rc = pthread_attr_init(&cmd_attr)) != 0) {
		printf("Error in attr_init, errno - %s\n", strerror(errno));
		exit(1);
	}

	if ((rc = pthread_attr_setdetachstate(&cmd_attr,
	    PTHREAD_CREATE_DETACHED)) != 0) {
		printf("Error in attr setdetachstate, errno - %s\n",
		    strerror(errno));
		pthread_attr_destroy(&cmd_attr);
		exit(1);
	}
	if ((rc = pthread_attr_init(&event_attr)) != 0) {
		printf("Error in attr_init, errno - %s\n", strerror(errno));
		exit(1);
	}

	if ((rc = pthread_attr_setdetachstate(&event_attr,
	    PTHREAD_CREATE_DETACHED)) != 0) {
		printf("Error in attr setdetachstate, errno - %s\n",
		    strerror(errno));
		pthread_attr_destroy(&event_attr);
		exit(1);
	}

	printf("Client API initialized\n");

}



void
set_default_connect_info() {

	if (data.net_file != NULL) {
		/* Net file was passed */
		if (data.net.cli_host)
			data.host =
			    mms_strapp(data.host,
			    data.net.cli_host);
		if (data.net.cli_port)
			data.port =
			    mms_strapp(data.port,
			    data.net.cli_port);
		if (data.net.cli_name)
			data.client =
			    mms_strapp(data.client,
			    data.net.cli_name);
		if (data.net.cli_inst)
			data.instance =
			    mms_strapp(data.instance,
			    data.net.cli_inst);
		if (data.net.cli_pass)
			data.password =
			    mms_strapp(data.password,
			    data.net.cli_pass);
		if (data.net.mm_pass)
			data.mm_pass =
			    mms_strapp(data.mm_pass,
			    data.net.mm_pass);

	}

	if (data.host == NULL) {
		data.host = mms_strapp(data.host, "localhost");
	}
	if (data.port == NULL) {
		data.port = mms_strapp(data.port, "7151");
	}
	if (data.client == NULL) {
		data.client = mms_strapp(data.client, "MMS");
	}
	if (data.instance == NULL) {
		data.instance = mms_strapp(data.instance, "admin");
	}

	if (data.tag == NULL) {
		data.tag = mms_strapp(data.tag, "mms_client-pid=%d",
		    getpid());
	}
}

void
usage(void)
{
	fprintf(stderr, "Usage: mms_client\n");
	fprintf(stderr, "-h Help\n");
	fprintf(stderr, "-f File name\n");
	fprintf(stderr, "-A Application name\n");
	fprintf(stderr, "-i Instance name\n");
	fprintf(stderr, "-s System name (MM_Host_Name)\n");
	fprintf(stderr, "-P Password File\n");
	fprintf(stderr, "-p Port\n");
	fprintf(stderr, "-t Tag\n");
	fprintf(stderr, "-n Network config file\n");
	exit(2);
}

int
cli_parse_cmd(cli_cmd_t *cmd) {
	int	rc;
	mms_list_t		err_list;
	mms_par_err_t	*err = NULL;
	rc = mms_mmp_parse(&cmd->cmd_root, &err_list, cmd->cmd_text);
	mms_list_foreach(&err_list, err) {
		printf("error parse, "
			"line %d, col %d, near token \"%s\", err code %d, %s\n",
			err->pe_line,
			err->pe_col,
			err->pe_token,
			err->pe_code,
			err->pe_msg);
	}
	mms_pe_destroy(&err_list);
	if (rc) {
		return (1);
	}
	return (0);
}

int
use_namevalue(cli_cmd_t *command) {
	mms_par_node_t	*cmd;
	mms_par_node_t	*reportmode;

	cmd = command->cmd_root;

	if ((reportmode = mms_pn_lookup(cmd, "reportmode",
			MMS_PN_CLAUSE, 0)) != NULL) {
		if (mms_pn_lookup(reportmode, "namevalue",
				    NULL, 0) != NULL) {
			if (command->cmd_is_sync == 1) {
				data.sync_has_namevalue = 1;
			}
			return (1);
		}
	}

	if (command->cmd_is_sync == 1) {
		data.sync_has_namevalue = 0;
	}
	return (0);
}

char *
cli_return_task(cli_cmd_t *cmd) {
	mms_par_node_t	*task_clause = NULL;
	mms_par_node_t	*work = NULL;
	mms_par_node_t	*task_str = NULL;

	if (cmd->cmd_root == NULL) {
		printf("cli_return_task: cmd->cmd_root is NULL\n");
		exit(1);
	}
	task_clause = mms_pn_lookup(cmd->cmd_root, "task", MMS_PN_CLAUSE,
	    &work);
	if (task_clause == NULL) {
		return (NULL);
	}
	task_str = mms_pn_lookup(task_clause, NULL, MMS_PN_STRING, &work);
	if (task_str == NULL) {
		return (NULL);
	}

	if (cmd->cmd_task == NULL) {
		cmd->cmd_task = mms_strapp(cmd->cmd_task,
		    task_str->pn_string);
	}
	/* Also set namevalue for printing later */
	cmd->cmd_namevalue = use_namevalue(cmd);

	return (task_str->pn_string);
}

void
cli_send_sync(cli_cmd_t *cmd) {

	if (cli_return_task(cmd) == NULL) {
		printf("not task found in:\n%s\n",
		    cmd->cmd_text);
		exit(1);
	}

	printf("-----------------------\n");
	printf("* Send Sync:\n");
	printf("%s\n", cmd->cmd_text);
	printf("-----------------------\n");

	if (mms_send_cmd(sp, cmd->cmd_text,
	    &cmd->cmd_rsp) != MMS_API_OK) {
		printf("error show command failed\n");
		exit(1);
	}
	printf("* Sync Sent\n");
	fflush(stdout);


	mms_client_handle_rsp(cmd->cmd_rsp);
	mms_free_rsp(cmd->cmd_rsp);
	cmd->cmd_rsp = NULL;

}

void
cli_send_async(cli_cmd_t *cmd) {

	if (cli_return_task(cmd) == NULL) {
		printf("not task found in:\n%s\n",
		    cmd->cmd_text);
		exit(1);
	}

	printf("-----------------------\n");
	printf("@ Send Async:\n");
	printf("%s\n", cmd->cmd_text);
	printf("-----------------------\n");

	if (mms_send_acmd(sp, cmd->cmd_text,
	    mms_client_handle_async_rsp,
	    &cmd->cmd_rsp) != MMS_API_OK) {
		printf("error async command failed\n");
		exit(1);
	}
	printf("@ Async Sent\n");
	fflush(stdout);
}

static void
cli_print_events() {
	char		cmd_buf[BUFSZ];

	printf("press any key to continue with the script\n\n");
	fflush(stdout);
	(void) fgets(cmd_buf, BUFSZ, stdin);
}

void
cli_mmp_prompt() {
	char cmd_buf[BUFSZ];
	cli_cmd_t *command1 = NULL;
	int go = 0;

	printf("MMP prompt, enter \"q\" to quit" \
	    " and continue\n");

	fflush(stdout);

	go = 1;
	while (go) {
		if (command1 == NULL) {
			command1 = cli_alloc_cmd();
		}

		printf("\n>");
		(void) fgets(cmd_buf, BUFSZ, stdin);
		if (cmd_buf[0] == 'q') {
			go = 0;
			if (command1->cmd_text != NULL) {
				memset(command1->cmd_text,
				    0,
				    sizeof (command1->cmd_text));
			}
			cli_destroy_cmd(command1);
			command1 = NULL;
			continue;
		}
		command1->cmd_text =
		    mms_strapp(command1->cmd_text, cmd_buf);


		if (strrchr(command1->cmd_text, ';') != NULL) {
			if (cli_parse_cmd(command1)) {
				printf("could not "
				    "parse command, "
				    "check syntax\n");
				memset(cmd_buf, 0,
				    sizeof (cmd_buf));
				cli_destroy_cmd(command1);
				command1 = NULL;

			} else {
				/* Command is sync */
				command1->cmd_is_sync = 1;
				cli_send_sync(command1);
				cli_destroy_cmd(command1);
				command1 = NULL;
			}
		}
	}
}


void
cli_print_async() {

	cli_cmd_t *cur_cmd;
	cli_cmd_t *next;


	pthread_mutex_lock(&data.
	    cli_async_lock);
	printf("Outstanding async commands:\n");
	for (cur_cmd = mms_list_head(&data.async_list);
	    cur_cmd != NULL;
	    cur_cmd = next) {
		next = mms_list_next(&data.async_list, cur_cmd);
		if (cur_cmd->cmd_task != NULL) {

			printf("    %s\n", cur_cmd->cmd_task);

		}
	}

	pthread_mutex_unlock(&data.
	    cli_async_lock);

}


int
main(int argc, char **argv)
{
	int	c;

	int	is_async = 0;

	cli_cmd_t *command1;

	FILE		*fp = NULL;
	FILE		*pass_fp = NULL;
	char		buf[BUFSZ];
	char		*cur_cmd_text = NULL;
	char		*shell_cmd = NULL;
	int		prompt_only = 0;

	const char	*optflags = "A:i:s:p:t:f:n:hP:";
	char		*prompt = NULL;
	char		*corename;

	int		i = 0;

	command1 = NULL;

	data.host = NULL;
	data.port = NULL;
	data.client = NULL;
	data.instance = NULL;
	data.password = NULL;
	data.tag = NULL;
	data.tag_to_sync = NULL;

	data.ssl_data = NULL;
	data.net_file = NULL;

	data.exiting = 0;
	data.async_waiting = 0;
	data.wait_for_sync = 0;
	data.sync_has_namevalue = 0;
	data.waiting_to_exit = 0;
	pthread_mutex_init(&data.async_mutex, NULL);
	pthread_cond_init(&data.async_cv, NULL);


	if (mms_set_core(MMS_CORES_DIR, NULL)) {
		fprintf(stderr, "core setup %s\n", strerror(errno));
		fprintf(stderr, "Run as ROOT for cores\n");
	}

	corename = mms_strapp(NULL, "core.mmsclient");
	/* Check to see how many core files exist */
	if (mms_man_cores(MMS_CORES_DIR, corename)) {
		fprintf(stderr, "core management %s\n", strerror(errno));
		fprintf(stderr, "Run as ROOT for cores\n");
	}
	free(corename);

	pthread_mutex_init(&data.cli_async_lock, NULL);

	/* real optarg processing */
	while ((c = getopt(argc, argv, optflags)) != EOF) {
		switch (c) {
		case 'A':
			data.client = mms_strapp(data.client, optarg);
			break;
		case 'i':
			data.instance = mms_strapp(data.instance, optarg);
			break;
		case 's':
			data.host = mms_strapp(data.host, optarg);
			break;
		case 'P':
			if ((pass_fp = fopen(optarg, "r")) == NULL) {
				fprintf(stderr, "error opening file %s\n",
				    optarg);
				return (1);
			}
			break;
		case 'p':
			data.port = mms_strapp(data.port, optarg);
			break;
		case 't':
			data.tag = mms_strapp(data.tag, optarg);
			break;
		case 'f':
			if ((fp = fopen(optarg, "r")) == NULL) {
				fprintf(stderr, "error opening file %s\n",
				    optarg);
				return (1);
			}
			break;
		case 'n':
			data.net_file = mms_strapp(data.net_file, optarg);
			break;
		case 'h':
			usage();
		default:
			usage();
		}
	}

	if (fp == NULL) {
		prompt_only = 1;
	}


	/* Read the network config file */
	(void) memset(&data.net, 0, sizeof (mms_network_cfg_t));
	if (data.net_file != NULL) {
		printf("Using net config file, %s\n",
		    data.net_file);
		if (mms_net_cfg_read(&data.net, data.net_file)) {
			fprintf(stderr, "Unable to get net info from "
			    "network config file, %s\n", data.net_file);
			exit(1);
		}
	}

	/* init the async command list */
	mms_list_create(&data.async_list, sizeof (cli_cmd_t),
	    offsetof(cli_cmd_t, cli_cmd_next));

	/* Set defaults for connect */
	set_default_connect_info();

	/* Get password */
	if (data.net_file == NULL) {

		if (pass_fp == NULL) {
			/* Prompt for password */
			prompt = mms_strapp(prompt, "MM Password for %s %s : ",
			    data.client, data.instance);
			data.password = getpassphrase(prompt);
			free(prompt);
		} else {
			/* Read pass word from pass_fp */
			if (fgets(buf, sizeof (buf), pass_fp) == NULL) {
				fprintf(stderr,
				    "Unable to read password from passfile\n");
				exit(1);
			}
			for (i = 0; i < sizeof (buf); i++) {
				if ((buf[i] == NULL) ||
				    (isspace(buf[i]) &&
				    !isblank(buf[i]))) {
					buf[i] = '\0';
					break;
				}
			}
			data.password = mms_strapp(data.password, buf);
		}
	} else if (pass_fp != NULL) {
		fprintf(stdout,
		    "WARNING: -P and -n used, "
		    "using password in network config file\n");
	}

	mms_client_init();

	/* Read file and send commands, dont exit if an async command */
	/* is waiting for a response */

	if (prompt_only) {
		while ((!data.exiting) ||
		    data.async_waiting) {
			cli_mmp_prompt();
			data.exiting = 1;
		}
	}

	while ((!data.exiting) ||
	    data.async_waiting) {
		if (fgets(buf, sizeof (buf), fp) == NULL) {
			data.exiting = 1;
			break;
		}

		/* If this is a blank line or a comment */
		if (buf[0] == '#' || buf[0] == '\n') {
			if (buf[0] == '#')
				printf("%s\n",
				    buf);
			continue; }

		/* client should wait and print incomming events */
		if (buf[0] == '%') {
			cli_print_events();
		}
		/* execute a shell command */
		if (buf[0] == '!') {
			shell_cmd = &buf[1];
			printf("Execute: \n  %s\n", shell_cmd);
			system(shell_cmd);
			printf("Done\n");
			shell_cmd = NULL;
			continue;
		}

		/* Interactive MMP prompt */
		if (buf[0] == '>') {
			cli_mmp_prompt();
			continue;
		}

		/* The next command will be async */
		if (buf[0] == '@') {
			is_async = 1;
			continue; }

		/* client should wait for the response */
		/* to this command */
		if (buf[0] == '$') {
			printf("^^^^^^^^^^^^^^^^^^^^^^^\n");
			printf("sync point: \n  %s\n",
			    buf);
			printf("^^^^^^^^^^^^^^^^^^^^^^^\n");
			if (cli_need_arsp(buf)) {

				pthread_mutex_lock(&data.
				    cli_async_lock);
				data.wait_for_sync = 1;
				data.tag_to_sync =
				    mms_strapp(data.tag_to_sync,
				    buf);

				pthread_mutex_unlock(&data.
				    cli_async_lock);
				while (data.wait_for_sync) {
				}

				printf("=======================\n");
				printf("synced with tag : %s\n",
				    buf);
				printf("=======================\n");


			} else {
				printf("already got "
				    "response for %s",
				    buf);
			}
			continue; }

		/* This is a command */

		cur_cmd_text = mms_strapp(cur_cmd_text, buf);
		if (strrchr(cur_cmd_text, ';') == NULL) {
			continue; }

		command1 = cli_alloc_cmd();
		command1->cmd_text = mms_strapp(command1->cmd_text,
		    cur_cmd_text);

		if (cli_parse_cmd(command1)) {
			printf("could not parse command, "
			    "check syntax\n\n%s\n",
			    command1->cmd_text);
			exit(1);
		}

		if (is_async) {
			/* Command is async */
			pthread_mutex_lock(&data.async_mutex);
			data.async_waiting = 1;
			pthread_mutex_unlock(&data.async_mutex);
			command1->cmd_is_sync = 0;

			pthread_mutex_lock(&data.
			    cli_async_lock);
			mms_list_insert_tail(&data.async_list,
			    command1);
			pthread_mutex_unlock(&data.
			    cli_async_lock);
			cli_send_async(command1);
			is_async = 0;
			command1 = NULL;
		} else {
			/* Command is sync */
			command1->cmd_is_sync = 1;
			cli_send_sync(command1);
			cli_destroy_cmd(command1);
			command1 = NULL;
		}

		free(cur_cmd_text);
		cur_cmd_text = NULL;
	}

	/* Wait for any remaining async commands */
	pthread_mutex_lock(&data.async_mutex);
	if (data.async_waiting == 1) {
		data.waiting_to_exit = 1;
		pthread_cond_wait(&data.async_cv,
		    &data.async_mutex);
	}
	pthread_mutex_unlock(&data.async_mutex);
	printf("All Commands finished\n");

	return (0);
}
