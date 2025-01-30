/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Programmatic interface to NVMe Devices
 *
 * libnvme exists to provide a means of performing non-I/O related operations on
 * an NVMe device. This is intended to allow software, regardless of whether it
 * is part of illumos or not, to operate on NVMe devices and perform most of the
 * administrative and operator tasks that might come up. This library does not
 * provide a stable interface yet. The rest of this block comment goes into the
 * organization and background into why it looks the way it does.
 *
 * --------------------
 * Library Organization
 * --------------------
 *
 * There are two large classes of source files that make up this library
 * currently:
 *
 *   1. Source code that implements the library's interfaces is found alongside
 *      this file in lib/libnvme/common. This code is generally organized based
 *      around the portion of the NVMe specification that it implements. So for
 *      example, code that implements logic related to the features is found
 *      in libnvme_feature.c, formatting namespaces in libnvme_format.c, log
 *      pages in libnvme_log.c, etc. All files in the library begin with
 *      'libnvme_' as a way to help namespace the file names from the second set
 *      of files.
 *
 *   2. Validation logic that is shared between libnvme and the kernel is found
 *      in common/nvme/. While the kernel must validate requests regardless, we
 *      leverage this shared information as a means for trying to ensure that we
 *      have useful errors early. That code is factored in a way to facilitate
 *      easier unit testing.
 *
 * Because of the nature of this split, all of the opaque structures that we
 * create and their relationships are all maintained in the library (group 1).
 * All of the logic in group 2 is designed to be constant data tables and
 * functions that are fed information about the controller they are operating on
 * to answer them.
 *
 * There are several general classes of interfaces and related structures that
 * we have in the library. We break them into the following general categories
 * based on their purpose:
 *
 * DISCOVERY
 *
 * One of the large responsibilities of this library is helping someone discover
 * information about something, whether that be a controller, a namespace, a log
 * page, a feature, a unique command, etc. Information about one of these items
 * is contained in a generally opaque discovery structure. For example, the
 * nvme_log_disc_t.
 *
 * The goal of these structures is to contain all of the metadata for working
 * with the object in question. Continuing on the log page discovery example, it
 * can tell us information about what fields are required, whether or not the
 * log might be supported, whether it operates on a controller, a namespace, or
 * something else, as well as more human-usable things such as names and
 * descriptions.
 *
 * Discovery objects are both for humans and for programmatic consumption. There
 * are several cases where requests can be created directly from discovery
 * objects. A well designed discovery object can allow a general implementation
 * of a consumer such as nvmeadm to build up a request without having to
 * hardcode everything about what is needed for each request (though most
 * consumers still need to have information about the actual contents, meaning,
 * and semantics of a log or feature).
 *
 * Discovery objects are obtained in two general ways. The first is using one of
 * the iterator/callback based functions to discover a given class of data. The
 * second path is that several of the functions which operate based on the name
 * of something, e.g. nvme_log_req_init_by_name(),
 * nvme_get_feat_req_init_by_name(), etc. will return a discovery object.
 *
 * When a discovery object is returned based on iteration (more below), the
 * memory is owned by the iterator. When it is returned by a request
 * initialization function, then it has its own life time and must be freed.
 * We try to make this distinction clear in the API based on whether or not the
 * discovery object is 'const'.
 *
 * All discovery objects should be fully filled out before they are handed back
 * to a caller. It is an explicit design goal that every function that gets data
 * from the discovery structure operates on a const version of the pointer. This
 * is the hint that you cannot perform additional I/O or related after handing
 * out the discovery structure. Attempts to loosen this constraint should be
 * considered carefully due to how we communicate ownership.
 *
 * ITERATORS
 *
 * A common pattern of the library is iterating over items. This includes
 * controllers and namespaces, but also as part of discovering what specific
 * logs, commands, features, etc. are actually supported by the device.
 * Iteration always follows the same general pattern:
 *
 * 1. An iterator is initialized with a call to nvme_<name>_discover_init().
 * This will generally return a structure of the form nvme_<name>_iter_t. This
 * structure contains the memory for the corresponding value that is returned
 * from step in (2).
 *
 * 2. To actually pull values out of an iterator, one must call the
 * nvme_<name>_step() function for the iterator. This will return a
 * corresponding nvme_<name>_disc_t structure that is opaque and has a suite of
 * functions that are usable for getting information out from it. This structure
 * is valid only until the next time the nvme_<name>_step() is called. The
 * return value of step indicates the state of the data and indicates whether or
 * not there is an error, the iterator has finished, or we successfully stepped
 * and the data is filled out.
 *
 * If discovery data needs to outlive a given iteration, then it can be
 * duplicated which will give it a separate lifetime, though that comes with
 * the responsibility that it must then be freed.
 *
 * 3. To finish using iterators, one finally calls the corresponding
 * nvme_<name>_discover_fini(). That will deallocate the iterator structure and
 * finish everything up.
 *
 * REQUESTS
 *
 * One of the chief goals of this library is to be able to perform requests.
 * Each request has a structure that can be initialized, filled out, and then
 * executed. A request structure can be reused multiple times with minor
 * adjustments in-between (though changes aren't required). Request structures
 * are either initialized in a blank mode where every value must be filled out
 * or they can be initialized through their discovery object (or the common name
 * of such an object).
 *
 * When a request structure is initialized through a discovery object, it
 * automatically sets several of the fields, knows which ones are still required
 * to be set, and which fields cannot be set. For example, if you create a get
 * log page request from a log discovery object, it will not allow you to change
 * the log page you're requesting; however, in return you don't have to specify
 * the command set interface or log identifier.
 *
 * Request objects are tied to a controller. See 'Parallelism, Thread Safety,
 * and Errors' for more information.
 *
 * INFORMATION SNAPSHOTS
 *
 * To get information about a namespace or controller, one has to take an
 * information snapshot. Once an information snapshot is obtained, this snapshot
 * answers all questions about the controller with a mostly consistent set of
 * point-in-time data. The main reason for this design was to try and simplify
 * where errors can occur and to provide a straightforward serialization point
 * so that way the raw underlying data could be gathered at one system and then
 * interpreted later on another.
 *
 * The only reason that there are some fallible operations on the snapshot are
 * things that are not guaranteed to exist for all such NVMe controllers.
 *
 * LIBRARY, CONTROLLER, NAMESPACE and SNAPSHOT HANDLES
 *
 * The last major set of types used in this library are opaque handles. As you
 * might have guessed given the request structures, all of the objects which
 * represent something are opaque. Each library handle is independent of one
 * another and each controller handle is independent of one another. In general,
 * it is expected that only a single controller handle is used at a given time
 * for a given library handle, but this is not currently enforced.  Error
 * information and parallelism is tied into this, see 'Parallelism, Thread
 * Safety, and Errors' for more information.
 *
 * -----------------
 * Opaque Structures
 * -----------------
 *
 * One of the things that might stand out in libnvme is the use of opaque
 * structures everywhere with functions to access every arbitrary piece of data.
 * This and the function pattern around building up a request were done to try
 * and deal with the evolutionary nature of the NVMe specification. If you look
 * at the various requests, with the exception of firmware download, almost
 * every request has added additional features through the spec revisions. NVMe
 * 2.0 changed most things again with the requirement to specify the command set
 * interface.
 *
 * While the way that the NVMe specification has done this is quite reasonable,
 * it makes it much more difficult to use a traditional series of arguments to
 * functions or a structure without having to try to version the symbol through
 * clever games. If instead we accept that the specification will change and
 * that the specification is always taking these additional arguments out of
 * values that must be zero, then an opaque request structure where you have to
 * make an explicit function call and recompile to get slightly different
 * behavior is mostly reasonable. We may not be able to be perfect given we're
 * at the mercy of the specification, but at least this is better than the
 * alternative.
 *
 * This is ultimately why all the request structures are opaque and use a
 * pseudo-builder pattern to fill out the request information. Further evidence
 * to this point is that there was no way to avoid changing every kernel
 * structure here while retaining semantic operations. No one wants to manually
 * assemble cdw12-15 here. That's not how we can add value for the library.
 *
 * Similarly, for all discovery objects we ended up utilizing opaque objects.
 * The main reason here is that we want to be able to embed this library as a
 * committed interface in other languages and having the discovery structures be
 * something that everyone can see means it'll be harder to extend it. While
 * this concern is somewhat more theoretical given the iterator pattern, given
 * the other bits in the request structure we decided to lean into the
 * opaqueness.
 *
 * --------------------------------------
 * Parallelism, Thread Safety, and Errors
 * --------------------------------------
 *
 * One of the library's major design points is how do we achieve thread-safety,
 * how does ownership work, where do errors appear, and what is the degree of
 * parallelism that is achievable. To work through this we look at a few
 * different things:
 *
 * 1. The degree to which the hardware allows for parallelism
 * 2. The degree to which users might desire parallelism
 * 3. The ergonomics of getting and storing errors
 *
 * The NVMe specification allows for different degrees of admin command
 * parallelism on a per-command basis. This is discoverable, but the main point
 * is that there are a class of commands where only one can be outstanding at a
 * time, which likely fall into the case of most of the destructive commands
 * like Format NVM, Activate Firmware, etc. Our expectation to some extent is
 * that most admin queue commands don't need to be issued in parallel; however,
 * beyond how we structure the library and error handling, we don't try to
 * enforce that here. The kernel does do some enforcement through requiring
 * mandatory write locks to perform some operations.
 *
 * When we get to how do folks want to use this, during the initial design phase
 * we mostly theorized based on how nvmeadm is using it today and how various
 * daemons like a FRU monitor or an appliance kit's software might want to
 * interact with it. Our general starting assumption is that it's very
 * reasonable for each discovered controller to be handled in parallel, but that
 * operations on a controller itself are likely serial given that we're not
 * issuing I/O through this mechanism. If we were, then that'd be an entirely
 * different set of constraints.
 *
 * To discuss the perceived ergonomics, we need to first discuss what error
 * information we want to be able to have. It's an important goal of both the
 * NVMe driver and this library to give useful semantic errors. In particular,
 * for any operation we want to make sure that we include the following
 * information:
 *
 *   o A hopefully distinguishable semantic error
 *   o Saving errno as a system error if relevant (e.g if open(2) failed)
 *   o A message for humans that gives more specifics about what happened and is
 *     intended to be passed along to the output of a command or another error
 *     message.
 *   o If a controller error occurs, we want to be able to provide the
 *     controller's sc (status code) and sct (status code type).
 *
 * With this we get to the questions around ergonomics and related which are
 * entirely subjective. Given that we want to capture that information how do we
 * best do this given the tooling that we have. When the library was first being
 * prototyped all errors were on the nvme_t, basically the top-level handle.
 * This meant that each operation on a controller had to be done serially or you
 * would have to use different handles. However, the simplicity was that there
 * was one thing to check.
 *
 * This evolution changed slightly when we introduced information snapshots.
 * Because the information snapshots are meant to be separate entities whose
 * lifetime can extend beyond the nvme_t library handle, they ended up
 * developing their own error codes and functions. This has been okay because
 * there aren't too many use cases there, though the need to duplicate error
 * handling functions is a bit painful.
 *
 * From there, we did consider what if each request had its own error
 * information that could be extracted. That would turn into a lot of functions
 * to get at that data. The controller's allowed parallelism for admin commands
 * varies based on each command. Some commands must occur when there are no
 * other admin commands on the controller and others when there there is nothing
 * on the namespace. However, due to that nuance, it would lead to forcing the
 * consumer to understand the controller's specifics more than is often
 * necessary for a given request. To add to that, it'd also just be a pain to
 * try to get all the error information out in a different way and the consumers
 * we started writing in this fashion were not looking good.
 *
 * We also considered whether we could consolidate all the error functions on
 * each request into one structure that we get, but that didn't move the needle
 * too much. It also raised some more concerns around how we minimize races and
 * how data changes around that.
 *
 * So all of this led us to our current compromise position: we allow for
 * parallelism at the controller level. More specifically:
 *
 * 1. Operations which take the nvme_t handle set errors on it and must operate
 *    serially. That is the nvme_t should only be used from one thread at any
 *    time, but may move between threads. Errors are set on it.
 *
 * 2. The nvme_ctrl_t has its own error information. A given nvme_ctrl_t should
 *    only be used serially; however, different ones can be used in parallel. A
 *    controller doesn't guarantee exclusivity. That requires an explicit
 *    locking operation.
 *
 * 3. Both request structures and namespaces place their errors on the
 *    corresponding controller that they were created from. Therefore the
 *    per-controller serialization in (2) applies here as well. If two requests
 *    are tied to different controllers, they can proceed in parallel.
 *
 * 4. Once a controller or namespace snapshot is obtained, they fall into a
 *    similar pattern: each one can be operated on in parallel, but generally
 *    one should only operate on a single one serially.
 *
 * Other than the constraints defined above, the library does not care which
 * threads that an operation occurs on. These can be moved to wherever it needs
 * to be. Locking and related in the kernel is based on the open file descriptor
 * to the controller.
 *
 * ----------------
 * Field Validation
 * ----------------
 *
 * Every request is made up of fields that correspond to parts of the NVMe
 * specification. Our requests operate in terms of the logical fields that we
 * opt to expose and that the kernel knows how to consume. In general, we don't
 * expose the raw cdw values that make up the commands (except for the vendor
 * unique commands or arguments that are explicitly that way ala get features).
 * While operating on raw cdw arguments would be a simple way to create ABI
 * stability, it would leave everyone having to break up all the fields
 * themselves and we believe end up somewhat more error prone than the
 * interfaces we expose today.
 *
 * Requests are created in one of two ways today: they are either initialized
 * from corresponding discovery data e.g. nvme_log_req_init_by_disc() and
 * nvme_get_feat_req_init_by_name(), or one creates a raw request ala
 * nvme_get_feat_req_init(). In the former cases, we fill out a bunch of the
 * fields that would normally need to be set such as the log or feature ID. We
 * also will note which fields are allowed and expected. For example, the health
 * log page does not take or expect a lsp (log specific parameter) or related
 * and therefore we can flag that with an _UNUSE class error. Conversely,
 * requests that are created from their raw form will not have any such error
 * checking performed until they are finalized and checked by the kernel. The
 * set of fields that can be set in a request is usually tracked in the
 * structure with a member of the form <prefix>_allow.
 *
 * One set of library error checking that is uniform between both types is that
 * of missing fields. There are minimum fields that must be set for different
 * types of requests. That check will always be performed regardless of the path
 * that is taken through the system. Tracking which members must still be set is
 * done by a member of the form <prefix>_need.
 *
 * When we perform validation, we try to push the vast majority of it into the
 * common validation code that is shared between the kernel and userland. This
 * is wrapped up through the nvme_field_check_one() logic. The common code will
 * check if the field is supported by the controller (generating an _UNSUP class
 * error if not) and if the value of the field is within a valid range
 * (generating a _RANGE class error if not).
 *
 * While we try to fold the majority of such checks into the common code as
 * possible, it isn't perfect and some things have to be checked outside of
 * that. Those consist of the following general cases:
 *
 * 1) Items that are not semantically fields in the actual command but are
 * things that we are tracking ourselves in the library. An example of this
 * would be fields in the vuc request structure that we are synthesizing
 * ourselves.
 *
 * 2) While the field logic has the specifics of what controller is being
 * operated upon, it doesn't have all the knowledge of what things can be
 * combined or not. It can answer the specifics about its field, but cannot look
 * at the broader request.
 *
 * As a result, there are some duplicated checks in the library and the kernel,
 * though several are left just to the kernel. However, the vast majority of
 * validation does happen through these common routines which leaves the library
 * nvme_<type>_req_set_<field> functions generally wrappers around checking
 * common code and updating our tracking around what fields are set or not so we
 * can issue an ioctl.
 */

#include <stdlib.h>
#include <stdarg.h>
#include <libdevinfo.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <upanic.h>

#include "libnvme_impl.h"

bool
nvme_vers_ctrl_atleast(const nvme_ctrl_t *ctrl, const nvme_version_t *targ)
{
	return (nvme_vers_atleast(&ctrl->nc_vers, targ));
}

bool
nvme_vers_ctrl_info_atleast(const nvme_ctrl_info_t *ci,
    const nvme_version_t *targ)
{
	return (nvme_vers_atleast(&ci->nci_vers, targ));
}

bool
nvme_vers_ns_info_atleast(const nvme_ns_info_t *info,
    const nvme_version_t *targ)
{
	return (nvme_vers_atleast(&info->nni_vers, targ));
}

bool
nvme_guid_valid(const nvme_ctrl_t *ctrl, const uint8_t guid[16])
{
	const uint8_t zero_guid[16] = { 0 };

	return (nvme_vers_ctrl_atleast(ctrl, &nvme_vers_1v2) &&
	    memcmp(zero_guid, guid, sizeof (zero_guid)) != 0);
}

bool
nvme_eui64_valid(const nvme_ctrl_t *ctrl, const uint8_t eui64[8])
{
	const uint8_t zero_eui[8] = { 0 };

	return (nvme_vers_ctrl_atleast(ctrl, &nvme_vers_1v1) &&
	    memcmp(zero_eui, eui64, sizeof (zero_eui)) != 0);
}

int
nvme_format_nguid(const uint8_t nguid[16], char *buf, size_t len)
{
	return (snprintf(buf, len, "%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X"
	    "%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X",
	    nguid[0], nguid[1], nguid[2], nguid[3], nguid[4], nguid[5],
	    nguid[6], nguid[7], nguid[8], nguid[9], nguid[10], nguid[11],
	    nguid[12], nguid[13], nguid[14], nguid[15]));
}

int
nvme_format_eui64(const uint8_t eui64[8], char *buf, size_t len)
{
	return (snprintf(buf, len, "%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X",
	    eui64[0], eui64[1], eui64[2], eui64[3], eui64[4], eui64[5],
	    eui64[6], eui64[7]));
}

void
nvme_fini(nvme_t *nvme)
{
	if (nvme == NULL)
		return;

	if (nvme->nh_devinfo != DI_NODE_NIL) {
		di_fini(nvme->nh_devinfo);
	}

	free(nvme);
}

nvme_t *
nvme_init(void)
{
	nvme_t *nvme;

	nvme = calloc(1, sizeof (nvme_t));
	if (nvme == NULL) {
		return (NULL);
	}

	nvme->nh_devinfo = di_init("/", DINFOCPYALL);
	if (nvme->nh_devinfo == DI_NODE_NIL) {
		nvme_fini(nvme);
		return (NULL);
	}

	return (nvme);
}

void
nvme_ctrl_discover_fini(nvme_ctrl_iter_t *iter)
{
	free(iter);
}

nvme_iter_t
nvme_ctrl_discover_step(nvme_ctrl_iter_t *iter, const nvme_ctrl_disc_t **discp)
{
	di_minor_t m;

	*discp = NULL;
	if (iter->ni_done) {
		return (NVME_ITER_DONE);
	}

	for (;;) {
		if (iter->ni_cur == NULL) {
			iter->ni_cur = di_drv_first_node("nvme",
			    iter->ni_nvme->nh_devinfo);
		} else {
			iter->ni_cur = di_drv_next_node(iter->ni_cur);
		}

		if (iter->ni_cur == NULL) {
			iter->ni_done = true;
			return (NVME_ITER_DONE);
		}

		for (m = di_minor_next(iter->ni_cur, DI_MINOR_NIL);
		    m != DI_MINOR_NIL; m = di_minor_next(iter->ni_cur, m)) {
			if (strcmp(di_minor_nodetype(m),
			    DDI_NT_NVME_NEXUS) == 0) {
				break;
			}
		}

		if (m == DI_MINOR_NIL) {
			continue;
		}

		iter->ni_disc.ncd_devi = iter->ni_cur;
		iter->ni_disc.ncd_minor = m;
		*discp = &iter->ni_disc;
		return (NVME_ITER_VALID);
	}

	return (NVME_ITER_DONE);
}

bool
nvme_ctrl_discover_init(nvme_t *nvme, nvme_ctrl_iter_t **iterp)
{
	nvme_ctrl_iter_t *iter;

	if (iterp == NULL) {
		return (nvme_error(nvme, NVME_ERR_BAD_PTR, 0, "encountered "
		    "invalid nvme_ctrl_iter_t output pointer: %p", iterp));
	}

	iter = calloc(1, sizeof (nvme_ctrl_iter_t));
	if (iter == NULL) {
		int e = errno;
		return (nvme_error(nvme, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_ctrl_iter_t: %s",
		    strerror(e)));
	}
	iter->ni_nvme = nvme;
	*iterp = iter;
	return (nvme_success(nvme));
}

bool
nvme_ctrl_discover(nvme_t *nvme, nvme_ctrl_disc_f func, void *arg)
{
	nvme_ctrl_iter_t *iter;
	const nvme_ctrl_disc_t *disc;
	nvme_iter_t ret;

	if (func == NULL) {
		return (nvme_error(nvme, NVME_ERR_BAD_PTR, 0, "encountered "
		    "invalid nvme_ctrl_disc_f function pointer: %p", func));
	}

	if (!nvme_ctrl_discover_init(nvme, &iter)) {
		return (false);
	}

	while ((ret = nvme_ctrl_discover_step(iter, &disc)) ==
	    NVME_ITER_VALID) {
		if (!func(nvme, disc, arg))
			break;
	}

	nvme_ctrl_discover_fini(iter);
	if (ret == NVME_ITER_ERROR) {
		return (false);
	}

	return (nvme_success(nvme));
}

di_node_t
nvme_ctrl_disc_devi(const nvme_ctrl_disc_t *discp)
{
	return (discp->ncd_devi);
}

di_minor_t
nvme_ctrl_disc_minor(const nvme_ctrl_disc_t *discp)
{
	return (discp->ncd_minor);
}

void
nvme_ctrl_fini(nvme_ctrl_t *ctrl)
{
	if (ctrl == NULL) {
		return;
	}

	if (ctrl->nc_sup_logs != NULL) {
		free(ctrl->nc_sup_logs);
	}

	if (ctrl->nc_sup_logs_err != NULL) {
		free(ctrl->nc_sup_logs_err);
	}

	if (ctrl->nc_devi_path != NULL) {
		di_devfs_path_free(ctrl->nc_devi_path);
	}

	if (ctrl->nc_fd >= 0) {
		(void) close(ctrl->nc_fd);
		ctrl->nc_fd = -1;
	}

	free(ctrl);
}

bool
nvme_ctrl_init(nvme_t *nvme, di_node_t di, nvme_ctrl_t **outp)
{
	const char *drv;
	int32_t inst;
	di_minor_t minor;
	char *path, buf[PATH_MAX];
	nvme_ctrl_t *ctrl;
	nvme_ioctl_ctrl_info_t ctrl_info;

	if (di == DI_NODE_NIL) {
		return (nvme_error(nvme, NVME_ERR_BAD_PTR, 0, "encountered "
		    "invalid di_node_t: %p", di));
	}

	if (outp == NULL) {
		return (nvme_error(nvme, NVME_ERR_BAD_PTR, 0, "encountered "
		    "invalid nvme_ctrl_t output pointer: %p", outp));
	}
	*outp = NULL;

	drv = di_driver_name(di);
	inst = di_instance(di);
	if (drv == NULL || inst < 0) {
		return (nvme_error(nvme, NVME_ERR_BAD_DEVI, 0, "devi %s has "
		    "no driver attached", di_node_name(di)));
	}

	if (strcmp(drv, "nvme") != 0) {
		return (nvme_error(nvme, NVME_ERR_BAD_DEVI, 0, "devi %s isn't "
		    "attached to nvme, found %s", di_node_name(di), drv));
	}

	/*
	 * We have an NVMe node. Find the right minor that corresponds to the
	 * attachment point. Once we find that then we can go ahead and open a
	 * path to that and construct the device.
	 */
	minor = DI_MINOR_NIL;
	while ((minor = di_minor_next(di, minor)) != DI_MINOR_NIL) {
		if (strcmp(di_minor_nodetype(minor), DDI_NT_NVME_NEXUS) == 0) {
			break;
		}
	}

	if (minor == DI_MINOR_NIL) {
		return (nvme_error(nvme, NVME_ERR_BAD_DEVI, 0, "devi %s isn't "
		    "attached to nvme, found %s", di_node_name(di), drv));
	}

	path = di_devfs_minor_path(minor);
	if (path == NULL) {
		int e = errno;
		return (nvme_error(nvme, NVME_ERR_LIBDEVINFO, e, "failed to "
		    "obtain /devices path for the requested minor: %s",
		    strerror(e)));
	}

	if (snprintf(buf, sizeof (buf), "/devices%s", path) >= sizeof (buf)) {
		di_devfs_path_free(path);
		return (nvme_error(nvme, NVME_ERR_INTERNAL, 0, "failed to "
		    "construct full /devices minor path, would have overflown "
		    "internal buffer"));
	}
	di_devfs_path_free(path);

	ctrl = calloc(1, sizeof (*ctrl));
	if (ctrl == NULL) {
		int e = errno;
		return (nvme_error(nvme, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_ctrl_t: %s", strerror(e)));
	}

	ctrl->nc_nvme = nvme;
	ctrl->nc_devi = di;
	ctrl->nc_minor = minor;
	ctrl->nc_inst = inst;
	ctrl->nc_fd = open(buf, O_RDWR | O_CLOEXEC);
	if (ctrl->nc_fd < 0) {
		int e = errno;
		nvme_ctrl_fini(ctrl);
		return (nvme_error(nvme, NVME_ERR_OPEN_DEV, e, "failed to open "
		    "device path %s: %s", buf, strerror(e)));
	}

	ctrl->nc_devi_path = di_devfs_path(di);
	if (ctrl->nc_devi_path == NULL) {
		int e = errno;
		nvme_ctrl_fini(ctrl);
		return (nvme_error(nvme, NVME_ERR_LIBDEVINFO, e, "failed to "
		    "obtain /devices path for the controller: %s",
		    strerror(e)));
	}

	if (!nvme_ioc_ctrl_info(ctrl, &ctrl_info)) {
		nvme_err_data_t err;

		nvme_ctrl_err_save(ctrl, &err);
		nvme_err_set(nvme, &err);
		nvme_ctrl_fini(ctrl);
		return (false);
	}

	ctrl->nc_vers = ctrl_info.nci_vers;
	ctrl->nc_info = ctrl_info.nci_ctrl_id;

	nvme_vendor_map_ctrl(ctrl);

	*outp = ctrl;
	return (nvme_success(nvme));
}

typedef struct {
	bool ncia_found;
	int32_t ncia_inst;
	nvme_ctrl_t *ncia_ctrl;
	nvme_err_data_t ncia_err;
} nvme_ctrl_init_arg_t;

bool
nvme_ctrl_init_by_instance_cb(nvme_t *nvme, const nvme_ctrl_disc_t *disc,
    void *arg)
{
	nvme_ctrl_init_arg_t *init = arg;

	if (di_instance(disc->ncd_devi) != init->ncia_inst) {
		return (true);
	}

	/*
	 * If we fail to open the controller, we need to save the error
	 * information because it's going to end up being clobbered because this
	 * is a callback function surrounded by other libnvme callers.
	 */
	init->ncia_found = true;
	if (!nvme_ctrl_init(nvme, disc->ncd_devi, &init->ncia_ctrl)) {
		nvme_err_save(nvme, &init->ncia_err);
	}

	return (false);
}

bool
nvme_ctrl_init_by_instance(nvme_t *nvme, int32_t inst, nvme_ctrl_t **outp)
{
	nvme_ctrl_init_arg_t init;

	if (inst < 0) {
		return (nvme_error(nvme, NVME_ERR_ILLEGAL_INSTANCE, 0,
		    "encountered illegal negative instance number: %d", inst));
	}

	if (outp == NULL) {
		return (nvme_error(nvme, NVME_ERR_BAD_PTR, 0, "encountered "
		    "invalid nvme_ctrl_t output pointer: %p", outp));
	}

	init.ncia_found = false;
	init.ncia_inst = inst;
	init.ncia_ctrl = NULL;

	if (!nvme_ctrl_discover(nvme, nvme_ctrl_init_by_instance_cb, &init)) {
		return (false);
	}

	if (!init.ncia_found) {
		return (nvme_error(nvme, NVME_ERR_BAD_CONTROLLER, 0,
		    "failed to find NVMe controller nvme%d", inst));
	}

	/*
	 * If we don't have an NVMe controller structure but we did find the
	 * instance, then we must have had an error constructing this will which
	 * be on our handle. We have to reconstruct the error from saved
	 * information as nvme_ctrl_discover will have clobbered it.
	 */
	if (init.ncia_ctrl == NULL) {
		nvme_err_set(nvme, &init.ncia_err);
		return (false);
	}

	*outp = init.ncia_ctrl;
	return (nvme_success(nvme));
}

bool
nvme_ctrl_devi(nvme_ctrl_t *ctrl, di_node_t *devip)
{
	*devip = ctrl->nc_devi;
	return (nvme_ctrl_success(ctrl));
}

bool
nvme_ioc_ctrl_info(nvme_ctrl_t *ctrl, nvme_ioctl_ctrl_info_t *info)
{
	(void) memset(info, 0, sizeof (nvme_ioctl_ctrl_info_t));

	if (ioctl(ctrl->nc_fd, NVME_IOC_CTRL_INFO, info) != 0) {
		int e = errno;
		return (nvme_ioctl_syserror(ctrl, e, "controller info"));
	}

	if (info->nci_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		return (nvme_ioctl_error(ctrl, &info->nci_common,
		    "controller info"));
	}

	return (true);
}

bool
nvme_ioc_ns_info(nvme_ctrl_t *ctrl, uint32_t nsid, nvme_ioctl_ns_info_t *info)
{
	(void) memset(info, 0, sizeof (nvme_ioctl_ns_info_t));
	info->nni_common.nioc_nsid = nsid;

	if (ioctl(ctrl->nc_fd, NVME_IOC_NS_INFO, info) != 0) {
		int e = errno;
		return (nvme_ioctl_syserror(ctrl, e, "namespace info"));
	}

	if (info->nni_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		return (nvme_ioctl_error(ctrl, &info->nni_common,
		    "namespace info"));
	}

	return (true);
}

const char *
nvme_tporttostr(nvme_ctrl_transport_t tport)
{
	switch (tport) {
	case NVME_CTRL_TRANSPORT_PCI:
		return ("PCI");
	case NVME_CTRL_TRANSPORT_TCP:
		return ("TCP");
	case NVME_CTRL_TRANSPORT_RDMA:
		return ("RDMA");
	default:
		return ("unknown transport");
	}
}

static bool
nvme_ns_discover_validate(nvme_ctrl_t *ctrl, nvme_ns_disc_level_t level)
{
	switch (level) {
	case NVME_NS_DISC_F_ALL:
	case NVME_NS_DISC_F_ALLOCATED:
	case NVME_NS_DISC_F_ACTIVE:
	case NVME_NS_DISC_F_NOT_IGNORED:
	case NVME_NS_DISC_F_BLKDEV:
		return (true);
	default:
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_FLAG, 0, "invalid "
		    "namespace discovery level specified: 0x%x", level));
	}
}

void
nvme_ns_discover_fini(nvme_ns_iter_t *iter)
{
	free(iter);
}

const char *
nvme_nsleveltostr(nvme_ns_disc_level_t level)
{
	switch (level) {
	case NVME_NS_DISC_F_ALL:
		return ("unallocated");
	case NVME_NS_DISC_F_ALLOCATED:
		return ("allocated");
	case NVME_NS_DISC_F_ACTIVE:
		return ("active");
	case NVME_NS_DISC_F_NOT_IGNORED:
		return ("not ignored");
	case NVME_NS_DISC_F_BLKDEV:
		return ("blkdev");
	default:
		return ("unknown level");
	}
}

nvme_ns_disc_level_t
nvme_ns_state_to_disc_level(nvme_ns_state_t state)
{
	if ((state & NVME_NS_STATE_ALLOCATED) == 0) {
		return (NVME_NS_DISC_F_ALL);
	}

	if ((state & NVME_NS_STATE_ACTIVE) == 0) {
		return (NVME_NS_DISC_F_ALLOCATED);
	}

	if ((state & NVME_NS_STATE_IGNORED) != 0) {
		return (NVME_NS_DISC_F_ACTIVE);
	}

	if ((state & NVME_NS_STATE_ATTACHED) == 0) {
		return (NVME_NS_DISC_F_NOT_IGNORED);
	} else {
		return (NVME_NS_DISC_F_BLKDEV);
	}
}

nvme_iter_t
nvme_ns_discover_step(nvme_ns_iter_t *iter, const nvme_ns_disc_t **discp)
{
	nvme_ctrl_t *ctrl = iter->nni_ctrl;

	if (iter->nni_err) {
		return (NVME_ITER_ERROR);
	}

	if (iter->nni_done) {
		return (NVME_ITER_DONE);
	}

	while (iter->nni_cur_idx <= ctrl->nc_info.id_nn) {
		uint32_t nsid = iter->nni_cur_idx;
		nvme_ioctl_ns_info_t ns_info = { 0 };
		nvme_ns_disc_level_t level;

		if (!nvme_ioc_ns_info(ctrl, nsid, &ns_info)) {
			iter->nni_err = true;
			return (NVME_ITER_ERROR);
		}

		iter->nni_cur_idx++;
		level = nvme_ns_state_to_disc_level(ns_info.nni_state);
		if (iter->nni_level > level) {
			continue;
		}

		(void) memset(&iter->nni_disc, 0, sizeof (nvme_ns_disc_t));
		iter->nni_disc.nnd_nsid = nsid;
		iter->nni_disc.nnd_level = level;

		if (nvme_guid_valid(ctrl, ns_info.nni_id.id_nguid)) {
			iter->nni_disc.nnd_flags |= NVME_NS_DISC_F_NGUID_VALID;
			(void) memcpy(iter->nni_disc.nnd_nguid,
			    ns_info.nni_id.id_nguid,
			    sizeof (ns_info.nni_id.id_nguid));
		}

		if (nvme_eui64_valid(ctrl, ns_info.nni_id.id_eui64)) {
			iter->nni_disc.nnd_flags |= NVME_NS_DISC_F_EUI64_VALID;
			(void) memcpy(iter->nni_disc.nnd_eui64,
			    ns_info.nni_id.id_eui64,
			    sizeof (ns_info.nni_id.id_eui64));
		}

		*discp = &iter->nni_disc;
		return (NVME_ITER_VALID);
	}

	iter->nni_done = true;
	return (NVME_ITER_DONE);
}

bool
nvme_ns_discover_init(nvme_ctrl_t *ctrl, nvme_ns_disc_level_t level,
    nvme_ns_iter_t **iterp)
{
	nvme_ns_iter_t *iter;

	if (!nvme_ns_discover_validate(ctrl, level)) {
		return (false);
	}

	if (iterp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_ns_iter_t output pointer: %p",
		    iterp));
	}

	iter = calloc(1, sizeof (nvme_ns_iter_t));
	if (iter == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_ns_iter_t: %s",
		    strerror(e)));
	}

	iter->nni_ctrl = ctrl;
	iter->nni_level = level;
	iter->nni_cur_idx = 1;

	*iterp = iter;
	return (nvme_ctrl_success(ctrl));
}

bool
nvme_ns_discover(nvme_ctrl_t *ctrl, nvme_ns_disc_level_t level,
    nvme_ns_disc_f func, void *arg)
{
	nvme_ns_iter_t *iter;
	nvme_iter_t ret;
	const nvme_ns_disc_t *disc;

	if (!nvme_ns_discover_validate(ctrl, level)) {
		return (false);
	}

	if (func == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_ns_disc_f function pointer: %p",
		    func));
	}

	if (!nvme_ns_discover_init(ctrl, level, &iter)) {
		return (false);
	}

	while ((ret = nvme_ns_discover_step(iter, &disc)) == NVME_ITER_VALID) {
		if (!func(ctrl, disc, arg))
			break;
	}

	nvme_ns_discover_fini(iter);
	if (ret == NVME_ITER_ERROR) {
		return (false);
	}

	return (nvme_ctrl_success(ctrl));
}

uint32_t
nvme_ns_disc_nsid(const nvme_ns_disc_t *discp)
{
	return (discp->nnd_nsid);
}

nvme_ns_disc_level_t
nvme_ns_disc_level(const nvme_ns_disc_t *discp)
{
	return (discp->nnd_level);
}

nvme_ns_disc_flags_t
nvme_ns_disc_flags(const nvme_ns_disc_t *discp)
{
	return (discp->nnd_flags);
}

const uint8_t *
nvme_ns_disc_eui64(const nvme_ns_disc_t *discp)
{
	if ((discp->nnd_flags & NVME_NS_DISC_F_EUI64_VALID) == 0) {
		return (NULL);
	}

	return (discp->nnd_eui64);
}

const uint8_t *
nvme_ns_disc_nguid(const nvme_ns_disc_t *discp)
{
	if ((discp->nnd_flags & NVME_NS_DISC_F_NGUID_VALID) == 0) {
		return (NULL);
	}

	return (discp->nnd_nguid);
}

void
nvme_ns_fini(nvme_ns_t *ns)
{
	free(ns);
}

bool
nvme_ns_init(nvme_ctrl_t *ctrl, uint32_t nsid, nvme_ns_t **nsp)
{
	nvme_ns_t *ns;

	if (nsp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_ns_t output pointer: %p", nsp));
	}

	if (nsid < NVME_NSID_MIN || nsid > ctrl->nc_info.id_nn) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_NS_RANGE, 0, "requested "
		    "namespace 0x%x is invalid, valid namespaces are [0x%x, "
		    "0x%x]", nsid, NVME_NSID_MIN, ctrl->nc_info.id_nn));
	}

	ns = calloc(1, sizeof (nvme_ns_t));
	if (ns == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_ns_t: %s", strerror(e)));
	}

	ns->nn_ctrl = ctrl;
	ns->nn_nsid = nsid;

	*nsp = ns;
	return (nvme_ctrl_success(ctrl));
}

typedef struct {
	nvme_ctrl_t *nnia_ctrl;
	const char *nnia_name;
	bool nnia_found;
	nvme_ns_t *nnia_ns;
	nvme_err_data_t nnia_err;
} nvme_ns_init_arg_t;

static bool
nvme_ns_init_by_name_cb(nvme_ctrl_t *ctrl, const nvme_ns_disc_t *disc,
    void *arg)
{
	nvme_ns_init_arg_t *init = arg;
	char buf[NVME_NGUID_NAMELEN];
	CTASSERT(NVME_NGUID_NAMELEN > NVME_EUI64_NAMELEN);

	if ((disc->nnd_flags & NVME_NS_DISC_F_NGUID_VALID) != 0) {
		(void) nvme_format_nguid(disc->nnd_nguid, buf, sizeof (buf));
		if (strcasecmp(init->nnia_name, buf) == 0)
			goto match;
	}

	if ((disc->nnd_flags & NVME_NS_DISC_F_EUI64_VALID) != 0) {
		(void) nvme_format_eui64(disc->nnd_eui64, buf, sizeof (buf));
		if (strcasecmp(init->nnia_name, buf) == 0)
			goto match;
	}

	(void) snprintf(buf, sizeof (buf), "%u", disc->nnd_nsid);
	if (strcasecmp(init->nnia_name, buf) == 0)
		goto match;

	return (true);

match:
	init->nnia_found = true;
	if (!nvme_ns_init(ctrl, disc->nnd_nsid, &init->nnia_ns)) {
		nvme_ctrl_err_save(ctrl, &init->nnia_err);
	}

	return (false);
}

/*
 * Attempt to find a namespace by 'name'. A name could be the NGUID, EUI64, or
 * just the plain old namespace ID.
 */
bool
nvme_ns_init_by_name(nvme_ctrl_t *ctrl, const char *ns_name, nvme_ns_t **nsp)
{
	nvme_ns_init_arg_t init;

	if (ns_name == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid namespace name: %p", ns_name));
	}

	if (nsp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_ns_t output pointer: %p", nsp));
	}

	init.nnia_ctrl = ctrl;
	init.nnia_name = ns_name;
	init.nnia_found = false;
	init.nnia_ns = NULL;

	if (!nvme_ns_discover(ctrl, NVME_NS_DISC_F_ALL, nvme_ns_init_by_name_cb,
	    &init)) {
		return (false);
	}

	if (!init.nnia_found) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_NS_RANGE, 0, "failed to "
		    "find NVMe namespace %s on nvme%d", ns_name,
		    ctrl->nc_inst));
	}

	if (init.nnia_ns == NULL) {
		nvme_ctrl_err_set(ctrl, &init.nnia_err);
		return (false);
	}

	*nsp = init.nnia_ns;
	return (nvme_ctrl_success(ctrl));
}

bool
nvme_ctrl_ns_init(nvme_t *nvme, const char *name, nvme_ctrl_t **ctrlp,
    nvme_ns_t **nsp)
{
	const char *slash, *ns_name;
	char *eptr;
	nvme_ctrl_t *ctrl;
	nvme_ns_t *ns;
	unsigned long inst;
	size_t ctrl_namelen;

	if (name == NULL) {
		return (nvme_error(nvme, NVME_ERR_BAD_PTR, 0, "encountered "
		    "invalid name to search for: %p", name));
	}

	/*
	 * We require a controller, but the namespace output pointer is only
	 * required if we end up having a namespace present.
	 */
	if (ctrlp == NULL) {
		return (nvme_error(nvme, NVME_ERR_BAD_PTR, 0, "encountered "
		    "invalid nvme_ctrl_t output pointer: %p", ctrlp));
	}

	slash = strchr(name, '/');
	if (slash != NULL) {
		ctrl_namelen = (uintptr_t)slash - (uintptr_t)name;
		ns_name = slash + 1;

		if (nsp == NULL) {
			return (nvme_error(nvme, NVME_ERR_BAD_PTR, 0,
			    "encountered invalid nvme_ns_t output pointer: %p",
			    nsp));
		}

	} else {
		ctrl_namelen = strlen(name);
		ns_name = NULL;
	}

	*ctrlp = NULL;
	if (nsp != NULL) {
		*nsp = NULL;
	}

	if (strncmp(name, "nvme", 4) != 0) {
		return (nvme_error(nvme, NVME_ERR_BAD_CONTROLLER, 0, "unable "
		    "to map controller '%.*s' to a known device class, "
		    "expected the controller to start with 'nvme'",
		    (int)ctrl_namelen, name));
	}

	/*
	 * Before we go ahead and try to parse this with strtoul we need to
	 * manually check two things that strtoul will not:
	 *
	 * 1) If we have a null terminator, then we'll just get a 0 back.
	 * 2) If there are multiple leading zeros in a row then that's an error.
	 * We don't want to conflate 001 and 1 as the same here. The only valid
	 * case is 'nvme0' which is 5 characters long, hence the check below.
	 */
	if (ctrl_namelen == 4) {
		return (nvme_error(nvme, NVME_ERR_BAD_CONTROLLER, 0,
		    "no controller instance specified in %.*s",
		    (int)ctrl_namelen, name));
	}

	if (name[4] == '0' && ctrl_namelen > 5) {
		return (nvme_error(nvme, NVME_ERR_BAD_CONTROLLER, 0,
		    "leading zeros aren't allowed for the instance specified "
		    "in %.*s", (int)ctrl_namelen, name));
	}

	errno = 0;
	inst = strtoul(name + 4, &eptr, 10);
	if (errno != 0 || (*eptr != '\0' && eptr != slash)) {
		return (nvme_error(nvme, NVME_ERR_BAD_CONTROLLER, 0,
		    "failed to parse controller instance from %.*s",
		    (int)ctrl_namelen, name));
	}

	if (inst > INT32_MAX) {
		return (nvme_error(nvme, NVME_ERR_ILLEGAL_INSTANCE, 0,
		    "parsed controller instance %lu is outside the valid "
		    "range [0, %d]", inst, INT32_MAX));
	}

	if (!nvme_ctrl_init_by_instance(nvme, (int32_t)inst, &ctrl)) {
		return (false);
	}

	if (ns_name == NULL) {
		*ctrlp = ctrl;
		return (nvme_success(nvme));
	}

	if (!nvme_ns_init_by_name(ctrl, ns_name, &ns)) {
		nvme_err_data_t err;

		nvme_ctrl_err_save(ctrl, &err);
		nvme_err_set(nvme, &err);
		nvme_ctrl_fini(ctrl);
		return (false);
	}

	*ctrlp = ctrl;
	*nsp = ns;

	return (nvme_success(nvme));
}

bool
nvme_ns_bd_attach(nvme_ns_t *ns)
{
	nvme_ctrl_t *ctrl = ns->nn_ctrl;
	nvme_ioctl_common_t com;

	(void) memset(&com, 0, sizeof (com));
	com.nioc_nsid = ns->nn_nsid;

	if (ioctl(ns->nn_ctrl->nc_fd, NVME_IOC_ATTACH, &com) != 0) {
		int e = errno;
		return (nvme_ioctl_syserror(ctrl, e, "namespace attach"));
	}

	if (com.nioc_drv_err != NVME_IOCTL_E_OK) {
		return (nvme_ioctl_error(ctrl, &com, "namespace attach"));
	}

	return (nvme_ctrl_success(ctrl));
}

bool
nvme_ns_bd_detach(nvme_ns_t *ns)
{
	nvme_ctrl_t *ctrl = ns->nn_ctrl;
	nvme_ioctl_common_t com;

	(void) memset(&com, 0, sizeof (com));
	com.nioc_nsid = ns->nn_nsid;

	if (ioctl(ns->nn_ctrl->nc_fd, NVME_IOC_DETACH, &com) != 0) {
		int e = errno;
		return (nvme_ioctl_syserror(ctrl, e, "namespace detach"));
	}

	if (com.nioc_drv_err != NVME_IOCTL_E_OK) {
		return (nvme_ioctl_error(ctrl, &com, "namespace detach"));
	}

	return (nvme_ctrl_success(ctrl));
}

/*
 * Check for a lock programming error and upanic() if so.
 */
static void
nvme_lock_check(nvme_ctrl_t *ctrl)
{
	char msg[1024];
	int ret;
	const char *up;
	size_t ulen;
	const char *base = "fatal libnvme locking error detected";

	if (ctrl->nc_err.ne_err != NVME_ERR_LOCK_PROG) {
		return;
	}

	ret = snprintf(msg, sizeof (msg), "%s: %s (controller %p)", base,
	    ctrl->nc_err.ne_errmsg, ctrl);
	if (ret >= sizeof (msg)) {
		ulen = sizeof (msg);
		up = msg;
	} else if (ret <= 0) {
		ulen = strlen(base) + 1;
		up = base;
	} else {
		ulen = (size_t)ret + 1;
		up = msg;
	}

	upanic(up, ulen);
}

static bool
nvme_lock_common(nvme_ctrl_t *ctrl, uint32_t nsid, nvme_lock_level_t level,
    nvme_lock_flags_t flags)
{
	nvme_ioctl_lock_t lock;
	const nvme_lock_flags_t all_flags = NVME_LOCK_F_DONT_BLOCK;

	if (level != NVME_LOCK_L_READ && level != NVME_LOCK_L_WRITE) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_FLAG, 0, "unknown "
		    "lock level: 0x%x", level));
	}

	if ((flags & ~all_flags) != 0) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_FLAG, 0, "unknown "
		    "lock flags: 0x%x", flags & ~all_flags));
	}

	(void) memset(&lock, 0, sizeof (lock));
	lock.nil_common.nioc_nsid = nsid;
	if (nsid != 0) {
		lock.nil_ent = NVME_LOCK_E_NS;
	} else {
		lock.nil_ent = NVME_LOCK_E_CTRL;
	}
	lock.nil_level = level;
	lock.nil_flags = flags;

	if (ioctl(ctrl->nc_fd, NVME_IOC_LOCK, &lock) != 0) {
		int e = errno;
		return (nvme_ioctl_syserror(ctrl, e, "lock"));
	}

	if (lock.nil_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		(void) nvme_ioctl_error(ctrl, &lock.nil_common, "lock");
		nvme_lock_check(ctrl);
		return (false);
	}

	return (nvme_ctrl_success(ctrl));
}

/*
 * You may reasonably be wondering why does this return and why do we basically
 * panic everywhere. The reality is twofold. The first part of this is that we
 * know from experience in libc that error checking mutexes are not the most
 * common and the kernel simplicity of mutex_enter() and mutex_exit() are really
 * a boon. The second piece here is that the way that the ioctl path works here,
 * only programming errors or mischief in the library could cause this to fail
 * at the raw ioctl / errno level. That is EBADF/EFAULT, etc. are our fault and
 * if you cannot unlock because of that you're not going to get much further.
 */
void
nvme_unlock_common(nvme_ctrl_t *ctrl, uint32_t nsid)
{
	nvme_ioctl_unlock_t unlock;

	(void) memset(&unlock, 0, sizeof (unlock));
	unlock.niu_common.nioc_nsid = nsid;
	if (nsid != 0) {
		unlock.niu_ent = NVME_LOCK_E_NS;
	} else {
		unlock.niu_ent = NVME_LOCK_E_CTRL;
	}

	/*
	 * Because all unlock ioctls errors are promoted to an error, we don't
	 * bother calling nvme_ioctl_syserror() here.
	 */
	if (ioctl(ctrl->nc_fd, NVME_IOC_UNLOCK, &unlock) != 0) {
		int e = errno;
		(void) nvme_ctrl_error(ctrl, NVME_ERR_LOCK_PROG, e, "internal "
		    "programming error: failed to issue unlock ioctl: %s",
		    strerror(e));
		nvme_lock_check(ctrl);
		return;
	}

	if (unlock.niu_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		(void) nvme_ioctl_error(ctrl, &unlock.niu_common, "unlock");
		/*
		 * Promote any other failure to a new fatal failure. Consumers
		 * expect this to have worked.
		 */
		if (ctrl->nc_err.ne_err != NVME_ERR_LOCK_PROG) {
			nvme_err_data_t err;
			nvme_ctrl_err_save(ctrl, &err);
			(void) nvme_ctrl_error(ctrl, NVME_ERR_LOCK_PROG, 0,
			    "internal programming error: received unexpected "
			    "libnvme error 0x%x: %s", err.ne_err,
			    err.ne_errmsg);
		}
		nvme_lock_check(ctrl);
		return;
	}

	(void) nvme_ctrl_success(ctrl);
}

bool
nvme_ctrl_lock(nvme_ctrl_t *ctrl, nvme_lock_level_t level,
    nvme_lock_flags_t flags)
{
	return (nvme_lock_common(ctrl, 0, level, flags));
}

bool
nvme_ns_lock(nvme_ns_t *ns, nvme_lock_level_t level,
    nvme_lock_flags_t flags)
{
	return (nvme_lock_common(ns->nn_ctrl, ns->nn_nsid, level, flags));
}

void
nvme_ctrl_unlock(nvme_ctrl_t *ctrl)
{
	nvme_unlock_common(ctrl, 0);
}

void
nvme_ns_unlock(nvme_ns_t *ns)
{
	nvme_unlock_common(ns->nn_ctrl, ns->nn_nsid);
}
