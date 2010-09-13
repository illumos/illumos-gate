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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <ipsec_util.h>
#include <netdb.h>
#include <locale.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <net/pfpolicy.h>
#include <strings.h>
#include <errno.h>
#include <sys/crypto/common.h>
#include <zone.h>

#define	SPDSOCK_DIAG_BUF_LEN	128

typedef enum cmd_s {
	CMD_NONE = 0,
	CMD_ADD,
	CMD_ADD_PROTO,
	CMD_DEL,
	CMD_DEL_PROTO,
	CMD_EXEC_MODE,
	CMD_LIST_KERNEL
} cmd_t;

static const char *comma = ",";
static int adddel_flags, increment = 0, default_keylen;
static boolean_t synch_kernel;
static cmd_t cmd = CMD_NONE;
static int proto_number = -1, alg_number = -1, alg_flags = 0;
static char *proto_name, *alg_names_string, *block_sizes_string;
static char *key_sizes_string, *mech_name, *exec_mode_string;
static char *flag_string;
static ipsecalgs_exec_mode_t proto_exec_mode = LIBIPSEC_ALGS_EXEC_SYNC;
enum param_values {iv_len, mac_len, salt_bytes, max_param};
static int mech_params[max_param];

/*
 * Used by the algorithm walker callback to populate a SPD_UPDATEALGS
 * request.
 */

#define	SYNC_REQ_SIZE	4096

static uint64_t sync_req_buf[SYNC_REQ_SIZE];
static struct spd_attribute *sync_req_attr;
static uint_t sync_req_alg_count, sync_req_proto_count;

#define	EMIT(ap, tag, value) {					\
		(ap)->spd_attr_tag = (tag);			\
		(ap)->spd_attr_value = (value);			\
		(ap)++;						\
		if ((char *)(ap) + sizeof (*ap) -		\
		    (char *)sync_req_buf > SYNC_REQ_SIZE)	\
			bail_nomem();				\
	}

static void dump_alg(struct ipsecalgent *);
static void algs_walker(void (*)(struct ipsecalgent *), void (*)(uint_t));

static int
parse_flag(char *flag_str, uint_t flag)
{
	static struct flagtable {
		char *label;
		int token;
	} table[] = {
		{"VALID", 	ALG_FLAG_VALID},
		{"COUNTER",	ALG_FLAG_COUNTERMODE},
		{"COMBINED",	ALG_FLAG_COMBINED},
		{"CCM",		ALG_FLAG_CCM},
		{"GCM",		ALG_FLAG_GCM},
		{NULL,		0}
	};
	struct flagtable *ft = table;

	if (flag_str == NULL) {
		/* Print out flag labels for each flag set. */
		if ((ALG_FLAG_KERNELCHECKED & flag) && !(ALG_FLAG_VALID & flag))
			(void) printf("INVALID ");
		while (ft->token != 0) {
			if (ft->token & flag) {
				(void) printf("%s ", ft->label);
			}
			ft++;
		}
		return (0);
	}
	/* Or, lookup flag for supplied label. */
	while (ft->label != NULL && strcmp(ft->label, flag_str) != 0)
		ft++;
	return (ft->token);
}

static void
usage(void)
{
	errx(EXIT_FAILURE, gettext("Usage:\tipsecalgs\n"
	    "\tipsecalgs -l\n"
	    "\tipsecalgs -s\n"
	    "\tipsecalgs -a [-P protocol-number | -p protocol-name]\n"
	    "\t\t-k keylen-list [-i inc]\n"
	    "\t\t[-K default-keylen] -b blocklen-list\n"
	    "\t\t-n alg-names -N alg-number -m mech-name\n"
	    "\t\t[-M MAC length] [-S salt length] [-I IV length]\n"
	    "\t\t[-F COMBINED,COUNTER,CCM|GCM ] [-f] [-s]\n"
	    "\tipsecalgs -P protocol-number -p protocol-name\n"
	    "\t\t[-e exec-mode] [-f] [-s]\n"
	    "\tipsecalgs -r -p protocol-name -n alg-name [-s]\n"
	    "\tipsecalgs -r -p protocol-name -N alg-number [-s]\n"
	    "\tipsecalgs -R -P protocol-number [-s]\n"
	    "\tipsecalgs -R -p protocol-name [-s]\n"
	    "\tipsecalgs -e exec-mode -P protocol-number [-s]\n"
	    "\tipsecalgs -e exec-mode -p protocol-number [-s]"));
}

static void
bail_nomem(void)
{
	errx(EXIT_FAILURE, gettext("Out of memory."));
}

/*
 * Return the number of key or block sizes in the specified array.
 */
static uint_t
num_sizes(int *sizes)
{
	uint_t nsizes = 0;

	while (sizes[nsizes] != 0)
		nsizes++;

	return (nsizes);
}

/*
 * Algorithms walker callback. Adds an algorithm to the current SPD_UPDATEALGS
 * request.
 */
static void
synch_emit_alg(struct ipsecalgent *alg)
{
	uint_t nkey_sizes, nblock_sizes, i;
	uint_t nparams;

	EMIT(sync_req_attr, SPD_ATTR_ALG_ID, alg->a_alg_num);
	EMIT(sync_req_attr, SPD_ATTR_ALG_PROTO, alg->a_proto_num);
	EMIT(sync_req_attr, SPD_ATTR_ALG_INCRBITS, alg->a_key_increment);

	nkey_sizes = num_sizes(alg->a_key_sizes);
	EMIT(sync_req_attr, SPD_ATTR_ALG_NKEYSIZES, nkey_sizes);
	for (i = 0; i < nkey_sizes; i++)
		EMIT(sync_req_attr, SPD_ATTR_ALG_KEYSIZE, alg->a_key_sizes[i]);

	nblock_sizes = num_sizes(alg->a_block_sizes);
	nparams = num_sizes(alg->a_mech_params);
	EMIT(sync_req_attr, SPD_ATTR_ALG_NBLOCKSIZES, nblock_sizes);
	for (i = 0; i < nblock_sizes; i++) {
		EMIT(sync_req_attr, SPD_ATTR_ALG_BLOCKSIZE,
		    alg->a_block_sizes[i]);
	}
	EMIT(sync_req_attr, SPD_ATTR_ALG_NPARAMS, nparams);
	for (i = 0; i < nparams; i++) {
		EMIT(sync_req_attr, SPD_ATTR_ALG_PARAMS,
		    alg->a_mech_params[i]);
	}
	EMIT(sync_req_attr, SPD_ATTR_ALG_FLAGS, alg->a_alg_flags);

	EMIT(sync_req_attr, SPD_ATTR_ALG_MECHNAME, CRYPTO_MAX_MECH_NAME);
	(void) strncpy((char *)sync_req_attr, alg->a_mech_name,
	    CRYPTO_MAX_MECH_NAME);
	sync_req_attr = (struct spd_attribute *)((uint64_t *)sync_req_attr +
	    SPD_8TO64(CRYPTO_MAX_MECH_NAME));

	EMIT(sync_req_attr, SPD_ATTR_NEXT, 0);

	sync_req_alg_count++;
}

/*
 * Protocol walker callback. Add protocol related info to the current
 * SPD_UPDATEALGS request.
 */
static void
synch_emit_proto(uint_t proto_num)
{
	ipsecalgs_exec_mode_t exec_mode;
	uint32_t exec_mode_spdval;

	EMIT(sync_req_attr, SPD_ATTR_PROTO_ID, proto_num);

	/* execution mode */
	if (ipsecproto_get_exec_mode(proto_num, &exec_mode) != 0) {
		errx(EXIT_FAILURE, gettext("cannot get execution mode for "
		    "proto %d"), proto_num);
	}

	switch (exec_mode) {
	case LIBIPSEC_ALGS_EXEC_SYNC:
		exec_mode_spdval = SPD_ALG_EXEC_MODE_SYNC;
		break;
	case LIBIPSEC_ALGS_EXEC_ASYNC:
		exec_mode_spdval = SPD_ALG_EXEC_MODE_ASYNC;
		break;
	}
	EMIT(sync_req_attr, SPD_ATTR_PROTO_EXEC_MODE, exec_mode_spdval);

	EMIT(sync_req_attr, SPD_ATTR_NEXT, 0);

	sync_req_proto_count++;
}

/*
 * Causes the kernel to be re-synched with the contents of /etc/inet/algs
 */
static void
kernel_synch(void)
{
	int sfd = socket(PF_POLICY, SOCK_RAW, PF_POLICY_V1);
	int cnt, req_len;
	struct spd_msg *msg;
	struct spd_ext_actions *act;
	struct spd_attribute *attr;

	if (sfd < 0) {
		err(EXIT_FAILURE, gettext("Unable to open policy socket"));
	}

	/*
	 * Initialize the SPD message header and action. Some fields
	 * are set after having walked through the algorithms (number
	 * of algorithms, sizes, etc.)
	 */
	msg = (struct spd_msg *)sync_req_buf;
	(void) memset(msg, 0, sizeof (*msg));
	msg->spd_msg_version = PF_POLICY_V1;
	msg->spd_msg_type = SPD_UPDATEALGS;

	act = (struct spd_ext_actions *)(msg + 1);
	act->spd_actions_exttype = SPD_EXT_ACTION;
	act->spd_actions_reserved = 0;

	/*
	 * Walk through the algorithms defined and populate the
	 * request buffer.
	 */
	sync_req_alg_count = 0;
	sync_req_proto_count = 0;
	sync_req_attr = (struct spd_attribute *)(act + 1);
	algs_walker(synch_emit_alg, synch_emit_proto);
	act->spd_actions_count = sync_req_alg_count + sync_req_proto_count;

	/*
	 * Replace the last SPD_ATTR_NEXT attribute by a SPD_ATTR_END.
	 */
	attr = sync_req_attr - 1;
	attr->spd_attr_tag = SPD_ATTR_END;

	/*
	 * Now that the message is built, compute its total length and
	 * update the length fields that depend on this value.
	 */
	req_len = (char *)sync_req_attr - (char *)sync_req_buf;
	msg->spd_msg_len = SPD_8TO64(req_len);
	act->spd_actions_len = SPD_8TO64(req_len - sizeof (*msg));

	/* ship the update request to spdsock */
	cnt = write(sfd, sync_req_buf, req_len);
	if (cnt != req_len) {
		if (cnt < 0) {
			err(EXIT_FAILURE, gettext("algs update write failed"));
		} else {
			errx(EXIT_FAILURE, gettext("algs update short write"));
		}
		/* err/errx call exit(). */
	}

	cnt = read(sfd, sync_req_buf, req_len);

	if (cnt == -1) {
		err(EXIT_FAILURE, gettext("algs update read failed"));
	}

	if (cnt < sizeof (struct spd_msg)) {
		errx(EXIT_FAILURE, gettext(
		    "algs update failed while reading reply (short read)"));
	}

	msg = (struct spd_msg *)sync_req_buf;
	if (msg->spd_msg_errno != 0) {
		errno = msg->spd_msg_errno;
		warn(gettext("algs update failed"));
		if (msg->spd_msg_diagnostic != 0) {
			warnx("%s", spdsock_diag(msg->spd_msg_diagnostic));
		}
		exit(EXIT_FAILURE);
	}

	(void) close(sfd);
}

static void
list_kernel_algs(void)
{
	int sfd = socket(PF_POLICY, SOCK_RAW, PF_POLICY_V1);
	int cnt, retval;
	uint64_t reply_buf[2048];
	spd_ext_t *exts[SPD_EXT_MAX+1];
	struct spd_msg msg;
	struct spd_ext_actions *actp;
	struct spd_attribute *attr, *endattr;
	uint64_t *start, *end;
	struct ipsecalgent alg;
	uint_t cur_key, cur_block;
	uint_t nkey_sizes, nblock_sizes, nparams;
	char diag_buf[SPDSOCK_DIAG_BUF_LEN];

	if (sfd < 0) {
		err(EXIT_FAILURE, gettext("Unable to open policy socket"));
	}

	(void) memset(&msg, 0, sizeof (msg));
	msg.spd_msg_version = PF_POLICY_V1;
	msg.spd_msg_type = SPD_DUMPALGS;
	msg.spd_msg_len = SPD_8TO64(sizeof (msg));

	cnt = write(sfd, &msg, sizeof (msg));
	if (cnt != sizeof (msg)) {
		if (cnt < 0) {
			err(EXIT_FAILURE, gettext("dump algs write failed"));
		} else {
			errx(EXIT_FAILURE, gettext("dump algs short write"));
		}
		/* err/errx call exit(). */
	}

	cnt = read(sfd, reply_buf, sizeof (reply_buf));

	if (cnt == -1) {
		err(EXIT_FAILURE, gettext("dump algs read failed"));
	}

	if (cnt < sizeof (struct spd_msg)) {
		errx(EXIT_FAILURE, gettext(
		    "dump algs failed while reading reply (short read)"));
	}

	(void) close(sfd);

	retval = spdsock_get_ext(exts, (spd_msg_t *)reply_buf, SPD_8TO64(cnt),
	    diag_buf, SPDSOCK_DIAG_BUF_LEN);

	if (retval == KGE_LEN && exts[0]->spd_ext_len == 0) {
		/*
		 * No algorithms are defined in the kernel, which caused
		 * the extension length to be zero, and spdsock_get_ext()
		 * to fail with a KGE_LEN error. This is not an error
		 * condition, so we return nicely.
		 */
		return;
	} else if (retval != 0) {
		if (strlen(diag_buf) != 0)
			warnx("%s", diag_buf);
		errx(EXIT_FAILURE, gettext("invalid extension "
		    "in dump algs reply (%d)"), retval);
	}

	if (exts[SPD_EXT_ACTION] == NULL) {
		errx(EXIT_FAILURE,
		    gettext("action missing in dump algs reply"));
	}

	actp = (struct spd_ext_actions *)exts[SPD_EXT_ACTION];
	start = (uint64_t *)actp;
	end = (start + actp->spd_actions_len);
	endattr = (struct spd_attribute *)end;
	attr = (struct spd_attribute *)&actp[1];

	bzero(&alg, sizeof (alg));
	nkey_sizes = nblock_sizes = 0;

	(void) printf("Kernel list of algorithms:\n\n");

	while (attr < endattr) {
		switch (attr->spd_attr_tag) {
		case SPD_ATTR_NOP:
		case SPD_ATTR_EMPTY:
			break;
		case SPD_ATTR_END:
			attr = endattr;
			/* FALLTHRU */
		case SPD_ATTR_NEXT:
			/*
			 * Note that if the message received from the spdsock
			 * has a premature SPD_ATTR_END or SPD_ATTR_NEXT, this
			 * could cause the current algorithm to be only
			 * partially initialized.
			 */
			alg.a_alg_flags |= ALG_FLAG_KERNELCHECKED;
			dump_alg(&alg);
			free(alg.a_key_sizes);
			free(alg.a_block_sizes);
			free(alg.a_mech_name);
			free(alg.a_mech_params);
			bzero(&alg, sizeof (alg));
			nkey_sizes = nblock_sizes = 0;
			break;

		case SPD_ATTR_ALG_ID:
			alg.a_alg_num = attr->spd_attr_value;
			break;

		case SPD_ATTR_ALG_PROTO:
			alg.a_proto_num = attr->spd_attr_value;
			break;

		case SPD_ATTR_ALG_INCRBITS:
			alg.a_key_increment = attr->spd_attr_value;
			break;

		case SPD_ATTR_ALG_NKEYSIZES:
			nkey_sizes = attr->spd_attr_value;
			if (alg.a_key_sizes != NULL) {
				errx(EXIT_FAILURE, gettext("duplicate number "
				    "of keys in dump algs reply"));
			}
			alg.a_key_sizes = calloc(nkey_sizes + 1, sizeof (int));
			if (alg.a_key_sizes == NULL)
				bail_nomem();
			cur_key = 0;
			break;

		case SPD_ATTR_ALG_KEYSIZE:
			if (cur_key >= nkey_sizes) {
				errx(EXIT_FAILURE, gettext("too many key sizes"
				    " in dump algs reply"));
			}
			alg.a_key_sizes[cur_key++] = attr->spd_attr_value;
			break;

		case SPD_ATTR_ALG_NBLOCKSIZES:
			nblock_sizes = attr->spd_attr_value;
			if (alg.a_block_sizes != NULL) {
				errx(EXIT_FAILURE, gettext("duplicate number "
				    "of blocks in dump algs reply"));
			}
			alg.a_block_sizes = calloc(nblock_sizes + 1,
			    sizeof (int));
			if (alg.a_block_sizes == NULL)
				bail_nomem();
			cur_block = 0;
			break;

		case SPD_ATTR_ALG_BLOCKSIZE:
			if (cur_block >= nblock_sizes) {
				errx(EXIT_FAILURE, gettext("too many block "
				    "sizes in dump algs reply"));
			}
			alg.a_block_sizes[cur_block++] = attr->spd_attr_value;
			break;

		case SPD_ATTR_ALG_NPARAMS:
			nparams = attr->spd_attr_value;
			if (alg.a_mech_params != NULL) {
				errx(EXIT_FAILURE, gettext("duplicate number "
				    "of params in dump algs reply"));
			}
			alg.a_mech_params = calloc(nparams + 1,
			    sizeof (int));
			if (alg.a_mech_params == NULL)
				bail_nomem();
			cur_block = 0;
			break;

		case SPD_ATTR_ALG_PARAMS:
			if (cur_block >= nparams) {
				errx(EXIT_FAILURE, gettext("too many params "
				    "in dump algs reply"));
			}
			alg.a_mech_params[cur_block++] = attr->spd_attr_value;
			break;

		case SPD_ATTR_ALG_FLAGS:
			alg.a_alg_flags = attr->spd_attr_value;
			break;

		case SPD_ATTR_ALG_MECHNAME: {
			char *mech_name;

			if (alg.a_mech_name != NULL) {
				errx(EXIT_FAILURE, gettext(
				    "duplicate mech name in dump algs reply"));
			}

			alg.a_mech_name = malloc(attr->spd_attr_value);
			if (alg.a_mech_name == NULL)
				bail_nomem();

			mech_name = (char *)(attr + 1);
			bcopy(mech_name, alg.a_mech_name, attr->spd_attr_value);
			attr = (struct spd_attribute *)((uint64_t *)attr +
			    SPD_8TO64(attr->spd_attr_value));
			break;
		}
		}
		attr++;
	}

}


static int *
parse_intlist(char *args, int *num_args)
{
	int *rc = NULL;
	char *holder = NULL;

	while ((holder = strtok((holder == NULL) ? args : NULL, comma)) !=
	    NULL) {
		(*num_args)++;
		rc = realloc(rc, ((*num_args) + 1) * sizeof (int));
		if (rc == NULL)
			bail_nomem();
		rc[(*num_args) - 1] = atoi(holder);
		if (rc[(*num_args) - 1] == 0)
			usage();	/* Malformed integer list! */
		rc[*num_args] = 0;
	}

	return (rc);
}

static void
new_alg(void)
{
	struct ipsecalgent newbie;
	int num_names = 0, num_block_sizes = 0, num_key_sizes = 0;
	int i, rc;
	char *holder = NULL;

	/* Parameter reality check... */
	if (proto_number == -1) {
		if (proto_name == NULL) {
			warnx(gettext("Missing protocol number."));
			usage();
		}
		proto_number = getipsecprotobyname(proto_name);
		if (proto_number == -1) {
			warnx(gettext("Unknown protocol."));
			usage();
		}
	}
	if (alg_number == -1) {
		warnx(gettext("Missing algorithm number."));
		usage();
	}
	if (key_sizes_string == NULL) {
		warnx(gettext("Missing key size(s)."));
		usage();
	}
	if (alg_names_string == NULL) {
		warnx(gettext("Missing algorithm name(s)."));
		usage();
	}
	if (block_sizes_string == NULL) {
		warnx(gettext("Missing block/MAC lengths"));
		usage();
	}
	if (mech_name == NULL) {
		warnx(gettext("Missing mechanism name."));
		usage();
	}
	newbie.a_proto_num = proto_number;
	newbie.a_alg_num = alg_number;
	newbie.a_key_increment = increment;
	newbie.a_mech_name = mech_name;
	newbie.a_alg_flags = alg_flags;

	/*
	 * The ALG_FLAG_VALID is somewhat irrelevant as an input from the
	 * user, the kernel will decide if the algorithm description is
	 * valid or not and set the ALG_FLAG_VALID when the user dumps
	 * the kernel tables. To avoid confusion when the user dumps the
	 * contents off the ipsecalgs file, we set the ALG_FLAG_VALID here.
	 */
	newbie.a_alg_flags |= ALG_FLAG_VALID;
	while ((holder = strtok((holder == NULL) ? flag_string : NULL,
	    comma)) != NULL) {
		alg_flags = parse_flag(holder, 0);
		if (!alg_flags) {
			warnx(gettext("Invalid flag: %s\n"), holder);
			usage();
		}
		newbie.a_alg_flags |= alg_flags;
	}
	newbie.a_names = NULL;
	while ((holder = strtok((holder == NULL) ? alg_names_string : NULL,
	    comma)) != NULL) {
		newbie.a_names = realloc(newbie.a_names,
		    sizeof (char *) * ((++num_names) + 1));
		if (newbie.a_names == NULL)
			bail_nomem();
		newbie.a_names[num_names - 1] = holder;
		newbie.a_names[num_names] = NULL;
	}

	/* Extract block sizes. */
	newbie.a_block_sizes = parse_intlist(block_sizes_string,
	    &num_block_sizes);
	newbie.a_mech_params = &mech_params[0];

	/* Extract key sizes. */
	if ((holder = strchr(key_sizes_string, '-')) != NULL) {
		/* key sizes by range, key size increment required */
		if (newbie.a_key_increment == 0) {
			warnx(gettext("Missing key increment"));
			usage();
		}
		newbie.a_key_sizes = calloc(sizeof (int),
		    LIBIPSEC_ALGS_KEY_NUM_VAL);
		if (newbie.a_key_sizes == NULL)
			bail_nomem();
		*holder = '\0';
		holder++;
		/*
		 * At this point, holder points to high, key_sizes_string
		 * points to low.
		 */
		newbie.a_key_sizes[LIBIPSEC_ALGS_KEY_MIN_IDX] =
		    atoi(key_sizes_string);
		if (newbie.a_key_sizes[LIBIPSEC_ALGS_KEY_MIN_IDX] == 0) {
			warnx(gettext("Invalid lower key size range"));
			usage();
		}
		newbie.a_key_sizes[LIBIPSEC_ALGS_KEY_MAX_IDX] = atoi(holder);
		if (newbie.a_key_sizes[LIBIPSEC_ALGS_KEY_MAX_IDX] == 0) {
			warnx(gettext("Invalid higher key size range"));
			usage();
		}

		/* sanity check key range consistency */
		if (newbie.a_key_sizes[LIBIPSEC_ALGS_KEY_MIN_IDX] >=
		    newbie.a_key_sizes[LIBIPSEC_ALGS_KEY_MAX_IDX]) {
			warnx(gettext("Invalid key size range (min >= max)"));
			usage();
		}

		/* check key increment vs key range */
		if (((newbie.a_key_sizes[LIBIPSEC_ALGS_KEY_MAX_IDX] -
		    newbie.a_key_sizes[LIBIPSEC_ALGS_KEY_MIN_IDX]) %
		    newbie.a_key_increment) != 0) {
			warnx(gettext("Key size increment"
			    " not consistent with key size range"));
			usage();
		}

		/* default key size */
		if (default_keylen != 0) {
			/* check specified default key size */
			if (default_keylen <
			    newbie.a_key_sizes[LIBIPSEC_ALGS_KEY_MIN_IDX] ||
			    default_keylen >
			    newbie.a_key_sizes[LIBIPSEC_ALGS_KEY_MAX_IDX] ||
			    ((default_keylen -
			    newbie.a_key_sizes[LIBIPSEC_ALGS_KEY_MIN_IDX]) %
			    newbie.a_key_increment) != 0) {
				warnx(gettext("Default key size not consistent"
				    " with key size range"));
				usage();
			}
			newbie.a_key_sizes[LIBIPSEC_ALGS_KEY_DEF_IDX] =
			    default_keylen;
		} else {
			/* min key size in range if not specified */
			newbie.a_key_sizes[LIBIPSEC_ALGS_KEY_DEF_IDX] =
			    newbie.a_key_sizes[LIBIPSEC_ALGS_KEY_MIN_IDX];
		}
	} else {
		/* key sizes by enumeration */
		if (newbie.a_key_increment != 0) {
			warnx(gettext("Key increment must "
			    "not be specified with key sizes enumeration"));
			usage();
		}
		newbie.a_key_sizes = parse_intlist(key_sizes_string,
		    &num_key_sizes);

		/* default key size */
		if (default_keylen != 0 && default_keylen !=
		    newbie.a_key_sizes[0]) {
			/*
			 * The default key size is not at the front of the
			 * list. Swap it with the first element of the list.
			 */
			for (i = 1; i < num_key_sizes; i++) {
				if (newbie.a_key_sizes[i] == default_keylen)
					break;
				if (i >= num_key_sizes) {
					warnx(gettext("Default key size not "
					    "in list of key sizes"));
					usage();
				}
				newbie.a_key_sizes[i] = newbie.a_key_sizes[0];
				newbie.a_key_sizes[0] = default_keylen;
			}
		}
	}

	/* Call things! */
	if ((rc = addipsecalg(&newbie, adddel_flags)) != 0) {
		errx(EXIT_FAILURE, gettext("addipsecalg() call failed: "
		    "%s"), ipsecalgs_diag(rc));
	}

	free(newbie.a_names);
	free(newbie.a_block_sizes);
	free(newbie.a_key_sizes);
}

static void
new_proto(void)
{
	int rc;

	if ((rc = addipsecproto(proto_name, proto_number, proto_exec_mode,
	    adddel_flags))
	    != 0) {
		errx(EXIT_FAILURE, gettext(
		    "Cannot add protocol %1$d \"%2$s\": %3$s"), proto_number,
		    proto_name, ipsecalgs_diag(rc));
	}
}

static void
remove_alg(void)
{
	int rc;

	if (proto_number == -1) {
		if (proto_name == NULL) {
			warnx(gettext("Missing protocol number."));
			usage();
		}
		proto_number = getipsecprotobyname(proto_name);
		if (proto_number == -1) {
			errx(EXIT_FAILURE, gettext(
			    "Unknown protocol \"%s\"."), proto_name);
		}
	}

	if (alg_number == -1) {
		if (alg_names_string == NULL) {
			errx(EXIT_FAILURE, gettext("Missing algorithm ID."));
		}
		if (strchr(alg_names_string, ',') != NULL) {
			errx(EXIT_FAILURE, gettext(
			    "Specify a single algorithm name for removal, "
			    "not a list."));
		}
		if ((rc = delipsecalgbyname(alg_names_string, proto_number))
		    != 0) {
			errx(EXIT_FAILURE, gettext(
			    "Could not remove algorithm %1$s: %2$s"),
			    alg_names_string, ipsecalgs_diag(rc));
		}
	} else {
		if ((rc = delipsecalgbynum(alg_number, proto_number)) != 0) {
			errx(EXIT_FAILURE, gettext(
			    "Could not remove algorithm %1$d: %2$s"),
			    alg_number, ipsecalgs_diag(rc));
		}
	}
}

static void
remove_proto(void)
{
	int rc;

	if (proto_number == -1) {
		if (proto_name == NULL) {
			warnx(gettext("Please specify protocol to remove."));
			usage();
		}
		if ((rc = delipsecprotobyname(proto_name)) != 0) {
			errx(EXIT_FAILURE, gettext(
			    "Could not remove protocol %1$s: %2$s"),
			    proto_name, ipsecalgs_diag(rc));
		}
	} else {
		if ((rc = delipsecprotobynum(proto_number)) != 0) {
			errx(EXIT_FAILURE, gettext(
			    "Could not remove protocol %1$d: %2$s"),
			    proto_number, ipsecalgs_diag(rc));
		}
	}
}

static void
set_exec_mode(void)
{
	int rc;

	if (proto_number == -1) {
		if (proto_name == NULL) {
			warnx(gettext(
			    "Please specify protocol name or number."));
			usage();
		}
		proto_number = getipsecprotobyname(proto_name);
		if (proto_number == -1) {
			errx(EXIT_FAILURE, gettext("Unknown protocol %s"),
			    proto_name);
		}
	}

	if ((rc = ipsecproto_set_exec_mode(proto_number, proto_exec_mode))
	    != 0) {
		errx(EXIT_FAILURE, gettext("Cannot set execution mode: %s"),
		    ipsecalgs_diag(rc));
	}
}

/*
 * Print a description of an algorithm to standard output.
 */
static void
dump_alg(struct ipsecalgent *alg)
{
	int *ifloater;
	char **floater;

	/* protocol number */
	(void) printf(gettext("\tProtocol number: %d\n"), alg->a_proto_num);

	/* algorithm number */
	(void) printf(gettext("\tAlgorithm number: %d\n"), alg->a_alg_num);

	/* algorithm name(s) */
	if (alg->a_names != NULL) {
		(void) printf(gettext("\tAlgorithm names: "));
		floater = alg->a_names;
		assert(floater != NULL && *floater != NULL);
		do {
			/* Assume at least one string. */
			(void) printf("%s", *floater);
			if (*(++floater) != NULL)
				(void) putchar(',');
		} while (*floater != NULL);
		(void) putchar('\n');
	}

	/* mechanism name */
	(void) printf(gettext("\tMechanism Name: %s\n"), alg->a_mech_name);

	/* block/MAC sizes */
	(void) printf(gettext("\tBlock sizes or MAC sizes: "));
	ifloater = alg->a_block_sizes;
	(void) list_ints(stdout, ifloater);
	(void) putchar('\n');

	/* key sizes */
	(void) printf(gettext("\tKey sizes: "));
	if (alg->a_key_increment != 0)
		/* key specified by range */
		(void) printf(gettext(
		    "%1$d-%2$d, increment %3$d, default %4$d"),
		    alg->a_key_sizes[LIBIPSEC_ALGS_KEY_MIN_IDX],
		    alg->a_key_sizes[LIBIPSEC_ALGS_KEY_MAX_IDX],
		    alg->a_key_increment,
		    alg->a_key_sizes[LIBIPSEC_ALGS_KEY_DEF_IDX]);
	else
		/* key specified by enumeration */
		(void) list_ints(stdout, alg->a_key_sizes);
	(void) putchar('\n');

	/* Alg parameters */
	(void) printf(gettext("\tAlgorithm parameters: "));
	ifloater = alg->a_mech_params;
	(void) list_ints(stdout, ifloater);
	(void) putchar('\n');

	/* Alg flags */
	(void) printf(gettext("\tAlgorithm flags: "));
	(void) parse_flag(NULL, alg->a_alg_flags);

	(void) putchar('\n');
	(void) putchar('\n');
}

/*
 * Print the description of a protocol.
 */
static void
dump_proto(uint_t proto_id)
{
	char *proto_name;
	ipsecalgs_exec_mode_t exec_mode;

	/* protocol name and number */
	proto_name = getipsecprotobynum(proto_id);
	(void) printf(gettext("Protocol %1$d/%2$s "),
	    proto_id, proto_name != NULL ? proto_name : gettext("<unknown>"));

	/* execution mode */
	(void) printf("(%s", gettext("execution mode: "));

	if (ipsecproto_get_exec_mode(proto_id, &exec_mode) != 0) {
		(void) printf(gettext("<unknown>"));
	} else {
		switch (exec_mode) {
		case LIBIPSEC_ALGS_EXEC_SYNC:
			(void) printf("sync");
			break;
		case LIBIPSEC_ALGS_EXEC_ASYNC:
			(void) printf("async");
			break;
		}
	}

	(void) printf(")\n\n");

	free(proto_name);
}


/*
 * Algorithm walker table. Call proto_action() for each protocol,
 * and alg_action() for each algorithm.
 */
static void
algs_walker(void (*alg_action)(struct ipsecalgent *),
    void (*proto_action)(uint_t))
{
	int *proto_nums, proto_count, i;
	int *alg_nums, alg_count, j;
	struct ipsecalgent *alg;

	proto_nums = getipsecprotos(&proto_count);
	if (proto_nums == NULL) {
		errx(EXIT_FAILURE, gettext("getipsecprotos() failed."));
	}

	for (i = 0; i < proto_count; i++) {

		if (proto_action != NULL)
			proto_action(proto_nums[i]);

		alg_nums = getipsecalgs(&alg_count, proto_nums[i]);
		if (alg_nums == NULL) {
			free(proto_nums);
			errx(EXIT_FAILURE, gettext("getipsecalgs() failed."));
		}

		for (j = 0; j < alg_count; j++) {
			alg = getipsecalgbynum(alg_nums[j], proto_nums[i],
			    NULL);
			if (alg == NULL)
				continue;
			if (alg_action != NULL)
				alg_action(alg);
			freeipsecalgent(alg);
		}
		free(alg_nums);
	}
	free(proto_nums);
}

/*
 * Use just the libnsl/libipsecutil APIs to dump out all of the algorithms.
 */
static void
show_algs(void)
{
	/* Yes, I'm aware that this'll produce TWO newlines. */
	(void) puts(gettext(
	    "List of algorithms, grouped by IPsec protocol:\n"));

	algs_walker(dump_alg, dump_proto);
}

static int
try_int(char *optarg, const char *what)
{
	int rc = atoi(optarg);

	if (rc <= 0) {
		warnx(gettext("Invalid %s value"), what);
		usage();
	}
	return (rc);
}

static void
try_cmd(cmd_t newcmd)
{
	if (cmd != CMD_NONE)
		usage();
	cmd = newcmd;
}

int
main(int argc, char *argv[])
{
	int c;
	zoneid_t zoneid;
	ushort_t flags;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc == 1) {
		show_algs();
		return (EXIT_SUCCESS);
	}

	while ((c = getopt(argc, argv,
	    "aflrRsb:p:P:i:k:K:m:n:N:e:S:M:I:F:")) != EOF) {
		switch (c) {
		case 'a':
			try_cmd(CMD_ADD);
			break;
		case 'f':
			/* multiple occurences of -f are harmless */
			adddel_flags = LIBIPSEC_ALGS_ADD_FORCE;
			break;
		case 'l':
			try_cmd(CMD_LIST_KERNEL);
			break;
		case 'r':
			try_cmd(CMD_DEL);
			break;
		case 'R':
			try_cmd(CMD_DEL_PROTO);
			break;
		case 's':
			/* multiple occurences of -s are harmless */
			synch_kernel = B_TRUE;
			break;
		case 'n':
			if (alg_names_string != NULL)
				usage();
			alg_names_string = optarg;
			break;
		case 'b':
			if (block_sizes_string != NULL)
				usage();
			block_sizes_string = optarg;
			break;
		case 'p':
			if (proto_name != NULL)
				usage();
			proto_name = optarg;
			break;
		case 'P':
			if (proto_number != -1)
				usage();
			proto_number = try_int(optarg,
			    gettext("protocol number"));
			break;
		case 'e':
			if (exec_mode_string != NULL)
				usage();
			exec_mode_string = optarg;
			if (_str_to_ipsec_exec_mode(exec_mode_string,
			    &proto_exec_mode) == -1) {
				warnx(gettext("Invalid execution mode \"%s\""),
				    exec_mode_string);
				usage();
			}
			break;
		case 'i':
			if (increment != 0)
				usage();
			increment = try_int(optarg,
			    gettext("key size increment"));
			break;
		case 'k':
			if (key_sizes_string != NULL)
				usage();
			key_sizes_string = optarg;
			break;
		case 'K':
			if (default_keylen != 0)
				usage();
			default_keylen = try_int(optarg,
			    gettext("default key size"));
			break;
		case 'm':
			if (mech_name != NULL)
				usage();
			mech_name = optarg;
			break;
		case 'N':
			if (alg_number != -1)
				usage();
			alg_number = try_int(optarg,
			    gettext("algorithm number"));
			break;
		case 'I':
			if (mech_params[iv_len] != 0)
				usage();
			mech_params[iv_len] = try_int(optarg,
			    gettext("Initialization Vector length"));
			break;
		case 'M':
			if (mech_params[mac_len] != 0)
				usage();
			mech_params[mac_len] = try_int(optarg,
			    gettext("Integrity Check Vector length"));
			break;
		case 'S':
			if (mech_params[salt_bytes] != 0)
				usage();
			mech_params[salt_bytes] = try_int(optarg,
			    gettext("Salt length"));
			break;
		case 'F':
			/*
			 * Multiple flags can be specified, the results
			 * are OR'd together.  Flags can be specified as
			 * number or  a comma separated string
			 */
			flags = atoi(optarg);
			if (flags) {
				alg_flags |= flags;
				flag_string = NULL;
			} else {
				flag_string = optarg;
			}
			break;
		default:
			usage();
		}
	}

	/*
	 * When both protocol name (-p) and protocol number (-P) are
	 * specified, a new protocol is being defined.
	 */
	if (proto_number != -1 && proto_name != NULL)
		try_cmd(CMD_ADD_PROTO);
	else if (exec_mode_string != NULL)
		try_cmd(CMD_EXEC_MODE);

	/*
	 * Process specified command.
	 */
	switch (cmd) {
	case CMD_ADD:
		new_alg();
		break;
	case CMD_ADD_PROTO:
		new_proto();
		break;
	case CMD_DEL:
		remove_alg();
		break;
	case CMD_DEL_PROTO:
		remove_proto();
		break;
	case CMD_EXEC_MODE:
		set_exec_mode();
		break;
	case CMD_LIST_KERNEL:
		if (synch_kernel)
			usage();
		list_kernel_algs();
		break;
	default:
		if (!synch_kernel)
			usage();
	}

	if (synch_kernel) {
		/*
		 * This will only work in the global zone or
		 * a zone with an exclusive IP stack.
		 */
		if ((zoneid = getzoneid()) == 0) {
			kernel_synch();
		} else {
			if (zone_getattr(zoneid, ZONE_ATTR_FLAGS, &flags,
			    sizeof (flags)) < 0) {
				err(EXIT_FAILURE, gettext(
				    "Unable to determine zone IP type"));
			}
			if (flags & ZF_NET_EXCL) {
				kernel_synch();
			} else {
				(void) printf(gettext("Synchronization with "
				    "kernel not appropriate in this zone.\n"));
			}
		}
	}

	return (EXIT_SUCCESS);
}
