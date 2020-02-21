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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */
#include <alloca.h>

#include "libfmnotify.h"

/*ARGSUSED*/
void
nd_cleanup(nd_hdl_t *nhdl)
{
	nd_debug(nhdl, "Cleaning up ...");
	if (nhdl->nh_evhdl)
		(void) fmev_shdl_fini(nhdl->nh_evhdl);

	if (nhdl->nh_msghdl)
		fmd_msg_fini(nhdl->nh_msghdl);

	nhdl->nh_keep_running = B_FALSE;
	(void) fclose(nhdl->nh_log_fd);
}

static void
get_timestamp(char *buf, size_t bufsize)
{
	time_t utc_time;
	struct tm *p_tm;

	(void) time(&utc_time);
	p_tm = localtime(&utc_time);

	(void) strftime(buf, bufsize, "%b %d %H:%M:%S", p_tm);
}

/* PRINTFLIKE2 */
void
nd_debug(nd_hdl_t *nhdl, const char *format, ...)
{
	char timestamp[64];
	va_list ap;

	if (nhdl->nh_debug) {
		get_timestamp(timestamp, sizeof (timestamp));
		(void) fprintf(nhdl->nh_log_fd, "[ %s ", timestamp);
		va_start(ap, format);
		(void) vfprintf(nhdl->nh_log_fd, format, ap);
		va_end(ap);
		(void) fprintf(nhdl->nh_log_fd, " ]\n");
	}
	(void) fflush(nhdl->nh_log_fd);
}

void
nd_dump_nvlist(nd_hdl_t *nhdl, nvlist_t *nvl)
{
	if (nhdl->nh_debug)
		nvlist_print(nhdl->nh_log_fd, nvl);
}

/* PRINTFLIKE2 */
void
nd_error(nd_hdl_t *nhdl, const char *format, ...)
{
	char timestamp[64];
	va_list ap;

	get_timestamp(timestamp, sizeof (timestamp));
	(void) fprintf(nhdl->nh_log_fd, "[ %s ", timestamp);
	va_start(ap, format);
	(void) vfprintf(nhdl->nh_log_fd, format, ap);
	va_end(ap);
	(void) fprintf(nhdl->nh_log_fd, " ]\n");
	(void) fflush(nhdl->nh_log_fd);
}

/* PRINTFLIKE2 */
void
nd_abort(nd_hdl_t *nhdl, const char *format, ...)
{
	char timestamp[64];
	va_list ap;

	get_timestamp(timestamp, sizeof (timestamp));
	(void) fprintf(nhdl->nh_log_fd, "[ %s ", timestamp);
	va_start(ap, format);
	(void) vfprintf(nhdl->nh_log_fd, format, ap);
	va_end(ap);
	(void) fprintf(nhdl->nh_log_fd, " ]\n");
	(void) fflush(nhdl->nh_log_fd);
	nd_cleanup(nhdl);
}

void
nd_daemonize(nd_hdl_t *nhdl)
{
	pid_t pid;

	if ((pid = fork()) < 0)
		nd_abort(nhdl, "Failed to fork child (%s)", strerror(errno));
	else if (pid > 0)
		exit(0);

	(void) setsid();
	(void) close(0);
	(void) close(1);
	/*
	 * We leave stderr open so we can write debug/err messages to the SMF
	 * service log
	 */
	nhdl->nh_is_daemon = B_TRUE;
}

/*
 * This function returns a pointer to the specified SMF property group for the
 * specified SMF service.  The caller is responsible for freeing the property
 * group.  On failure, the function returns NULL.
 */
static scf_propertygroup_t *
nd_get_pg(nd_hdl_t *nhdl, scf_handle_t *handle, const char *svcname,
    const char *pgname)
{
	scf_scope_t *sc = NULL;
	scf_service_t *svc = NULL;
	scf_propertygroup_t *pg = NULL, *ret = NULL;

	sc = scf_scope_create(handle);
	svc = scf_service_create(handle);
	pg = scf_pg_create(handle);

	if (sc == NULL || svc == NULL || pg == NULL) {
		nd_error(nhdl, "Failed to allocate libscf structures");
		scf_pg_destroy(pg);
		goto get_pg_done;
	}

	if (scf_handle_bind(handle) != -1 &&
	    scf_handle_get_scope(handle, SCF_SCOPE_LOCAL, sc) != -1 &&
	    scf_scope_get_service(sc, svcname, svc) != -1 &&
	    scf_service_get_pg(svc, pgname, pg) != -1)
		ret = pg;
	else
		scf_pg_destroy(pg);

get_pg_done:
	scf_service_destroy(svc);
	scf_scope_destroy(sc);

	return (ret);
}

int
nd_get_astring_prop(nd_hdl_t *nhdl, const char *svcname, const char *pgname,
    const char *propname, char **val)
{
	scf_handle_t *handle = NULL;
	scf_propertygroup_t *pg;
	scf_property_t *prop = NULL;
	scf_value_t *value = NULL;
	char strval[255];
	int ret = -1;

	if ((handle = scf_handle_create(SCF_VERSION)) == NULL)
		return (ret);

	if ((pg = nd_get_pg(nhdl, handle, svcname, pgname)) == NULL) {
		nd_error(nhdl, "Failed to read retrieve %s "
		    "property group for %s", pgname, svcname);
		goto astring_done;
	}
	prop = scf_property_create(handle);
	value = scf_value_create(handle);
	if (prop == NULL || value == NULL) {
		nd_error(nhdl, "Failed to allocate SMF structures");
		goto astring_done;
	}
	if (scf_pg_get_property(pg, propname, prop) == -1 ||
	    scf_property_get_value(prop, value) == -1 ||
	    scf_value_get_astring(value, strval, 255) == -1) {
		nd_error(nhdl, "Failed to retrieve %s prop (%s)", propname,
		    scf_strerror(scf_error()));
		goto astring_done;
	}
	*val = strdup(strval);
	ret = 0;

astring_done:
	scf_value_destroy(value);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	scf_handle_destroy(handle);

	return (ret);
}

int
nd_get_boolean_prop(nd_hdl_t *nhdl, const char *svcname, const char *pgname,
    const char *propname, uint8_t *val)
{
	scf_handle_t *handle = NULL;
	scf_propertygroup_t *pg;
	scf_property_t *prop = NULL;
	scf_value_t *value = NULL;
	int ret = -1;

	if ((handle = scf_handle_create(SCF_VERSION)) == NULL)
		return (ret);

	if ((pg = nd_get_pg(nhdl, handle, svcname, pgname)) == NULL) {
		nd_error(nhdl, "Failed to read retrieve %s "
		    "property group for %s", pgname, svcname);
		goto bool_done;
	}
	prop = scf_property_create(handle);
	value = scf_value_create(handle);
	if (prop == NULL || value == NULL) {
		nd_error(nhdl, "Failed to allocate SMF structures");
		goto bool_done;
	}
	if (scf_pg_get_property(pg, propname, prop) == -1 ||
	    scf_property_get_value(prop, value) == -1 ||
	    scf_value_get_boolean(value, val) == -1) {
		nd_error(nhdl, "Failed to retrieve %s prop (%s)", propname,
		    scf_strerror(scf_error()));
		goto bool_done;
	}
	ret = 0;

bool_done:
	scf_value_destroy(value);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	scf_handle_destroy(handle);

	return (ret);
}

char *
nd_get_event_fmri(nd_hdl_t *nhdl, fmev_t ev)
{
	nvlist_t *ev_nvl, *attr_nvl;
	char *svcname;

	if ((ev_nvl = fmev_attr_list(ev)) == NULL) {
		nd_error(nhdl, "Failed to lookup event attr nvlist");
		return (NULL);
	}
	if (nvlist_lookup_nvlist(ev_nvl, "attr", &attr_nvl) ||
	    nvlist_lookup_string(attr_nvl, "svc-string", &svcname)) {
		nd_error(nhdl, "Malformed event 0x%p", (void *)ev_nvl);
		return (NULL);
	}

	return (strdup((const char *)svcname));
}

int
nd_get_notify_prefs(nd_hdl_t *nhdl, const char *mech, fmev_t ev,
    nvlist_t ***pref_nvl, uint_t *nprefs)
{
	nvlist_t *ev_nvl, *top_nvl, **np_nvlarr, *mech_nvl;
	int ret = 1;
	uint_t nelem;

	if ((ev_nvl = fmev_attr_list(ev)) == NULL) {
		nd_error(nhdl, "Failed to lookup event attr nvlist");
		return (-1);
	}

	if ((ret = smf_notify_get_params(&top_nvl, ev_nvl)) != SCF_SUCCESS) {
		ret = scf_error();
		if (ret == SCF_ERROR_NOT_FOUND) {
			nd_debug(nhdl, "No notification preferences specified "
			    "for this event");
			goto pref_done;
		} else {
			nd_error(nhdl, "Error looking up notification "
			    "preferences (%s)", scf_strerror(ret));
			nd_dump_nvlist(nhdl, top_nvl);
			goto pref_done;
		}
	}

	if (nvlist_lookup_nvlist_array(top_nvl, SCF_NOTIFY_PARAMS, &np_nvlarr,
	    &nelem) != 0) {
		nd_error(nhdl, "Malformed nvlist");
		nd_dump_nvlist(nhdl, top_nvl);
		ret = 1;
		goto pref_done;
	}
	*pref_nvl = malloc(nelem * sizeof (nvlist_t *));
	*nprefs = 0;

	for (int i = 0; i < nelem; i++) {
		if (nvlist_lookup_nvlist(np_nvlarr[i], mech, &mech_nvl) == 0) {
			(void) nvlist_dup(mech_nvl, *pref_nvl + *nprefs, 0);
			++*nprefs;
		}
	}

	if (*nprefs == 0) {
		nd_debug(nhdl, "No %s notification preferences specified",
		    mech);
		free(*pref_nvl);
		ret = SCF_ERROR_NOT_FOUND;
		goto pref_done;
	}
	ret = 0;
pref_done:
	nvlist_free(top_nvl);
	return (ret);
}

static int
nd_seq_search(char *key, char **list, uint_t nelem)
{
	for (int i = 0; i < nelem; i++)
		if (strcmp(key, list[i]) == 0)
			return (1);
	return (0);
}

/*
 * This function takes a single string list and splits it into
 * an string array (analogous to PERL split)
 *
 * The caller is responsible for freeing the array.
 */
int
nd_split_list(nd_hdl_t *nhdl, char *list, char *delim, char ***arr,
    uint_t *nelem)
{
	char *item, *tmpstr;
	int i = 1, size = 1;

	tmpstr = strdup(list);
	item = strtok(tmpstr, delim);
	while (item && strtok(NULL, delim) != NULL)
		size++;
	free(tmpstr);

	if ((*arr = calloc(size, sizeof (char *))) == NULL) {
		nd_error(nhdl, "Error allocating memory (%s)", strerror(errno));
		return (-1);
	}
	if (size == 1)
		(*arr)[0] = strdup(list);
	else {
		tmpstr = strdup(list);
		item = strtok(tmpstr, delim);
		(*arr)[0] = strdup(item);
		while ((item = strtok(NULL, delim)) != NULL)
			(*arr)[i++] = strdup(item);
		free(tmpstr);
	}
	*nelem = size;
	return (0);
}

/*
 * This function merges two string arrays into a single array, removing any
 * duplicates
 *
 * The caller is responsible for freeing the merged array.
 */
int
nd_merge_strarray(nd_hdl_t *nhdl, char **arr1, uint_t n1, char **arr2,
    uint_t n2, char ***buf)
{
	char **tmparr;
	int uniq = -1;

	tmparr = alloca((n1 + n2) * sizeof (char *));
	bzero(tmparr, (n1 + n2) * sizeof (char *));

	while (++uniq < n1)
		tmparr[uniq] = strdup(arr1[uniq]);

	for (int j = 0; j < n2; j++)
		if (!nd_seq_search(arr2[j], tmparr, uniq))
			tmparr[uniq++] = strdup(arr2[j]);

	if ((*buf = calloc(uniq, sizeof (char *))) == NULL) {
		nd_error(nhdl, "Error allocating memory (%s)", strerror(errno));
		for (int j = 0; j < uniq; j++) {
			if (tmparr[j])
				free(tmparr[j]);
		}
		return (-1);
	}

	bcopy(tmparr, *buf, uniq * sizeof (char *));
	return (uniq);
}

void
nd_free_strarray(char **arr, uint_t arrsz)
{
	for (uint_t i = 0; i < arrsz; i++)
		free(arr[i]);
	free(arr);
}

/*
 * This function joins all the strings in a string array into a single string
 * Each element will be delimited by a comma
 *
 * The caller is responsible for freeing the joined string.
 */
int
nd_join_strarray(nd_hdl_t *nhdl, char **arr, uint_t arrsz, char **buf)
{
	uint_t len = 0;
	char *jbuf;
	int i;

	/*
	 * First, figure out how much space we need to allocate to store the
	 * joined string.
	 */
	for (i = 0; i < arrsz; i++)
		len += strlen(arr[i]) + 1;

	if ((jbuf = calloc(len, sizeof (char))) == NULL) {
		nd_error(nhdl, "Error allocating memory (%s)", strerror(errno));
		return (-1);
	}

	(void) snprintf(jbuf, len, "%s", arr[0]);
	for (i = 1; i < arrsz; i++) {
		(void) strlcat(jbuf, ",", len);
		(void) strlcat(jbuf, arr[i], len);
	}

	*buf = jbuf;
	return (0);
}

void
nd_free_nvlarray(nvlist_t **arr, uint_t arrsz)
{
	for (uint_t i = 0; i < arrsz; i++)
		nvlist_free(arr[i]);
	free(arr);
}

/*
 * This function takes a dictionary name and event class and then uses
 * libdiagcode to compute the MSG ID.  We need this for looking up messages
 * for the committed ireport.* events.  For FMA list.* events, the MSG ID is
 * is contained in the event payload.
 */
int
nd_get_diagcode(nd_hdl_t *nhdl, const char *dict, const char *class, char *buf,
    size_t buflen)
{
	fm_dc_handle_t *dhp;
	size_t dlen;
	char *dirpath;
	const char *key[2];
	int ret = 0;

	dlen = (strlen(nhdl->nh_rootdir) + strlen(ND_DICTDIR) + 2);
	dirpath = alloca(dlen);
	(void) snprintf(dirpath, dlen, "%s/%s", nhdl->nh_rootdir, ND_DICTDIR);

	if ((dhp = fm_dc_opendict(FM_DC_VERSION, dirpath, dict)) == NULL) {
		nd_error(nhdl, "fm_dc_opendict failed for %s/%s",
		    dirpath, dict);
		return (-1);
	}

	key[0] = class;
	key[1] = NULL;
	if (fm_dc_key2code(dhp, key, buf, buflen) < 0) {
		nd_error(nhdl, "fm_dc_key2code failed for %s", key[0]);
		ret = -1;
	}
	fm_dc_closedict(dhp);
	return (ret);
}

/*
 * This function takes an event and extracts the bits of the event payload that
 * are of interest to notification daemons and conveniently tucks them into a
 * single struct.
 *
 * The caller is responsible for freeing ev_info and any contained strings and
 * nvlists.  A convenience function, nd_free_event_info(), is provided for this
 * purpose.
 */
int
nd_get_event_info(nd_hdl_t *nhdl, const char *class, fmev_t ev,
    nd_ev_info_t **ev_info)
{
	nvlist_t *ev_nvl, *attr_nvl;
	nd_ev_info_t *evi;
	char *code, *uuid, *fmri, *from_state, *to_state, *reason;

	if ((evi = calloc(1, sizeof (nd_ev_info_t))) == NULL) {
		nd_error(nhdl, "Failed to allocate memory");
		return (-1);
	}

	/*
	 * Hold event; class and payload will be valid for as long as
	 * we hold the event.
	 */
	fmev_hold(ev);
	evi->ei_ev = ev;
	ev_nvl = fmev_attr_list(ev);

	/*
	 * Lookup the MSGID, event description and severity and KA URL
	 *
	 * For FMA list.* events we just pull it out of the the event nvlist.
	 * For all other events we call a utility function that computes the
	 * diagcode using the dict name and class.
	 */
	evi->ei_diagcode = calloc(32, sizeof (char));
	if ((nvlist_lookup_string(ev_nvl, FM_SUSPECT_DIAG_CODE, &code) == 0 &&
	    strcpy(evi->ei_diagcode, code)) ||
	    nd_get_diagcode(nhdl, "SMF", class, evi->ei_diagcode, 32)
	    == 0) {
		evi->ei_severity = fmd_msg_getitem_id(nhdl->nh_msghdl,
		    NULL, evi->ei_diagcode, FMD_MSG_ITEM_SEVERITY);
		evi->ei_descr = fmd_msg_getitem_id(nhdl->nh_msghdl,
		    NULL, evi->ei_diagcode, FMD_MSG_ITEM_DESC);
		evi->ei_url = fmd_msg_getitem_id(nhdl->nh_msghdl,
		    NULL, evi->ei_diagcode, FMD_MSG_ITEM_URL);
	} else
		(void) strcpy(evi->ei_diagcode, ND_UNKNOWN);

	if (!evi->ei_severity)
		evi->ei_severity = strdup(ND_UNKNOWN);
	if (!evi->ei_descr)
		evi->ei_descr = strdup(ND_UNKNOWN);
	if (!evi->ei_url)
		evi->ei_url = strdup(ND_UNKNOWN);

	evi->ei_payload = ev_nvl;
	evi->ei_class = fmev_class(ev);
	if (nvlist_lookup_string(ev_nvl, FM_SUSPECT_UUID, &uuid) == 0)
		evi->ei_uuid = strdup(uuid);
	else {
		nd_error(nhdl, "Malformed event");
		nd_dump_nvlist(nhdl, evi->ei_payload);
		nd_free_event_info(evi);
		return (-1);
	}

	if (strncmp(class, "ireport.os.smf", 14) == 0) {
		if ((fmri = nd_get_event_fmri(nhdl, ev)) == NULL) {
			nd_error(nhdl, "Failed to get fmri from event payload");
			nd_free_event_info(evi);
			return (-1);
		}
		if (nvlist_lookup_nvlist(evi->ei_payload, "attr", &attr_nvl) ||
		    nvlist_lookup_string(attr_nvl, "from-state", &from_state) ||
		    nvlist_lookup_string(attr_nvl, "to-state", &to_state) ||
		    nvlist_lookup_string(attr_nvl, "reason-long", &reason)) {
			nd_error(nhdl, "Malformed event");
			nd_dump_nvlist(nhdl, evi->ei_payload);
			nd_free_event_info(evi);
			free(fmri);
			return (-1);
		}
		evi->ei_fmri = fmri;
		evi->ei_to_state = strdup(to_state);
		evi->ei_from_state = strdup(from_state);
		evi->ei_reason = strdup(reason);
	}
	*ev_info = evi;
	return (0);
}

static void
condfree(void *buf)
{
	if (buf != NULL)
		free(buf);
}

void
nd_free_event_info(nd_ev_info_t *ev_info)
{
	condfree(ev_info->ei_severity);
	condfree(ev_info->ei_descr);
	condfree(ev_info->ei_diagcode);
	condfree(ev_info->ei_url);
	condfree(ev_info->ei_uuid);
	condfree(ev_info->ei_fmri);
	condfree(ev_info->ei_from_state);
	condfree(ev_info->ei_to_state);
	condfree(ev_info->ei_reason);
	fmev_rele(ev_info->ei_ev);
	free(ev_info);
}
