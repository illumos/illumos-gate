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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <meta.h>
#include <metad.h>

#pragma weak mdrpc_nullproc_1_svc = _mdrpc_nullproc_1_svc
#pragma weak mdrpc_hostname_1_svc = _mdrpc_hostname_1_svc
#pragma weak mdrpc_addhosts_1_svc = _mdrpc_addhosts_1_svc
#pragma weak mdrpc_delhosts_1_svc = _mdrpc_delhosts_1_svc
#pragma weak mdrpc_createset_1_svc = _mdrpc_createset_1_svc
#pragma weak mdrpc_delset_1_svc = _mdrpc_delset_1_svc
#pragma weak mdrpc_getset_1_svc = _mdrpc_getset_1_svc
#pragma weak mdrpc_setnumbusy_1_svc = _mdrpc_setnumbusy_1_svc
#pragma weak mdrpc_setnameok_1_svc = _mdrpc_setnameok_1_svc
#pragma weak mdrpc_ownset_1_svc = _mdrpc_ownset_1_svc
#pragma weak mdrpc_adddrvs_1_svc = _mdrpc_adddrvs_1_svc
#pragma weak mdrpc_deldrvs_1_svc = _mdrpc_deldrvs_1_svc
#pragma weak mdrpc_upd_dr_dbinfo_1_svc = _mdrpc_upd_dr_dbinfo_1_svc
#pragma weak mdrpc_devinfo_1_svc = _mdrpc_devinfo_1_svc
#pragma weak mdrpc_drvused_1_svc = _mdrpc_drvused_1_svc
#pragma weak mdrpc_add_drv_sidenms_1_svc = _mdrpc_add_drv_sidenms_1_svc
#pragma weak mdrpc_del_drv_sidenms_1_svc = _mdrpc_del_drv_sidenms_1_svc
#pragma weak mdrpc_gtimeout_1_svc = _mdrpc_gtimeout_1_svc
#pragma weak mdrpc_stimeout_1_svc = _mdrpc_stimeout_1_svc
#pragma weak mdrpc_upd_dr_flags_1_svc = _mdrpc_upd_dr_flags_1_svc
#pragma weak mdrpc_upd_sr_flags_1_svc = _mdrpc_upd_sr_flags_1_svc
#pragma weak mdrpc_unlock_set_1_svc = _mdrpc_unlock_set_1_svc
#pragma weak mdrpc_lock_set_1_svc = _mdrpc_lock_set_1_svc
#pragma weak mdrpc_updmeds_1_svc = _mdrpc_updmeds_1_svc

#pragma weak mdrpc_nullproc_2_svc =		_mdrpc_nullproc_2_svc
#pragma weak mdrpc_hostname_2_svc =		_mdrpc_hostname_2_svc
#pragma weak mdrpc_addhosts_2_svc =		_mdrpc_addhosts_2_svc
#pragma weak mdrpc_delhosts_2_svc =		_mdrpc_delhosts_2_svc
#pragma weak mdrpc_createset_2_svc =		_mdrpc_createset_2_svc
#pragma weak mdrpc_delset_2_svc =		_mdrpc_delset_2_svc
#pragma weak mdrpc_getset_2_svc =		_mdrpc_getset_2_svc
#pragma weak mdrpc_setnumbusy_2_svc =		_mdrpc_setnumbusy_2_svc
#pragma weak mdrpc_setnameok_2_svc =		_mdrpc_setnameok_2_svc
#pragma weak mdrpc_ownset_2_svc =		_mdrpc_ownset_2_svc
#pragma weak mdrpc_adddrvs_2_svc =		_mdrpc_adddrvs_2_svc
#pragma weak mdrpc_imp_set_drvs_2_svc =		_mdrpc_imp_set_drvs_2_svc
#pragma weak mdrpc_deldrvs_2_svc =		_mdrpc_deldrvs_2_svc
#pragma weak mdrpc_upd_dr_dbinfo_2_svc =	_mdrpc_upd_dr_dbinfo_2_svc
#pragma weak mdrpc_devinfo_2_svc =		_mdrpc_devinfo_2_svc
#pragma weak mdrpc_devid_2_svc =		_mdrpc_devid_2_svc
#pragma weak mdrpc_devinfo_by_devid_2_svc =	_mdrpc_devinfo_by_devid_2_svc
#pragma weak mdrpc_devinfo_by_devid_name_2_svc =\
					_mdrpc_devinfo_by_devid_name_2_svc
#pragma weak mdrpc_drvused_2_svc =		_mdrpc_drvused_2_svc
#pragma weak mdrpc_add_drv_sidenms_2_svc =	_mdrpc_add_drv_sidenms_2_svc
#pragma weak mdrpc_del_drv_sidenms_2_svc =	_mdrpc_del_drv_sidenms_2_svc
#pragma weak mdrpc_gtimeout_2_svc =		_mdrpc_gtimeout_2_svc
#pragma weak mdrpc_stimeout_2_svc =		_mdrpc_stimeout_2_svc
#pragma weak mdrpc_upd_dr_flags_2_svc =		_mdrpc_upd_dr_flags_2_svc
#pragma weak mdrpc_upd_sr_flags_2_svc =		_mdrpc_upd_sr_flags_2_svc
#pragma weak mdrpc_unlock_set_2_svc =		_mdrpc_unlock_set_2_svc
#pragma weak mdrpc_lock_set_2_svc =		_mdrpc_lock_set_2_svc
#pragma weak mdrpc_updmeds_2_svc =		_mdrpc_updmeds_2_svc
#pragma weak mdrpc_mncreateset_2_svc =		_mdrpc_mncreateset_2_svc
#pragma weak mdrpc_mngetset_2_svc =		_mdrpc_mngetset_2_svc
#pragma weak mdrpc_mnsetmaster_2_svc =		_mdrpc_mnsetmaster_2_svc
#pragma weak mdrpc_joinset_2_svc =		_mdrpc_joinset_2_svc
#pragma weak mdrpc_withdrawset_2_svc =		_mdrpc_withdrawset_2_svc
#pragma weak mdrpc_upd_nr_flags_2_svc =		_mdrpc_upd_nr_flags_2_svc
#pragma weak mdrpc_mn_is_stale_2_svc =		_mdrpc_mn_is_stale_2_svc
#pragma weak mdrpc_mdcommdctl_2_svc =		_mdrpc_mdcommdctl_2_svc
#pragma weak mdrpc_upd_dr_reconfig_2_svc =	_mdrpc_upd_dr_reconfig_2_svc
#pragma weak mdrpc_getdrivedesc_2_svc =		_mdrpc_getdrivedesc_2_svc
#pragma weak mdrpc_reset_mirror_owner_2_svc =	_mdrpc_reset_mirror_owner_2_svc
#pragma weak mdrpc_mn_susp_res_io_2_svc =	_mdrpc_mn_susp_res_io_2_svc
#pragma weak mdrpc_resnarf_set_2_svc =		_mdrpc_resnarf_set_2_svc
#pragma weak mdrpc_mn_mirror_resync_all_2_svc = \
					_mdrpc_mn_mirror_resync_all_2_svc
#pragma weak mdrpc_imp_adddrvs_2_svc =		_mdrpc_imp_adddrvs_2_svc

/*ARGSUSED*/
bool_t
_mdrpc_nullproc_1_svc(
	mdrpc_null_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_hostname_1_svc(
	mdrpc_null_args	*a,
	mdrpc_hostname_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_addhosts_1_svc(
	mdrpc_host_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_delhosts_1_svc(
	mdrpc_host_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_createset_1_svc(
	mdrpc_createset_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_delset_1_svc(
	mdrpc_sp_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_getset_1_svc(
	mdrpc_getset_args *a,
	mdrpc_getset_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_setnumbusy_1_svc(
	mdrpc_setno_args *a,
	mdrpc_bool_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_setnameok_1_svc(
	mdrpc_sp_args *a,
	mdrpc_bool_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_ownset_1_svc(
	mdrpc_sp_args *a,
	mdrpc_bool_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_adddrvs_1_svc(
	mdrpc_drives_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_deldrvs_1_svc(
	mdrpc_drives_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_upd_dr_dbinfo_1_svc(
	mdrpc_drives_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_devinfo_1_svc(
	mdrpc_devinfo_args *a,
	mdrpc_devinfo_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_drvused_1_svc(
	mdrpc_drvused_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_add_drv_sidenms_1_svc(
	mdrpc_drv_sidenm_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_del_drv_sidenms_1_svc(
	mdrpc_sp_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_gtimeout_1_svc(
	mdrpc_sp_args *a,
	mdrpc_gtimeout_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_stimeout_1_svc(
	mdrpc_stimeout_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_upd_dr_flags_1_svc(
	mdrpc_upd_dr_flags_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_upd_sr_flags_1_svc(
	mdrpc_upd_sr_flags_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_unlock_set_1_svc(
	mdrpc_null_args *a,
	mdrpc_setlock_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_lock_set_1_svc(
	mdrpc_null_args *a,
	mdrpc_setlock_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_updmeds_1_svc(
	mdrpc_updmeds_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}


/*ARGSUSED*/
bool_t
_mdrpc_nullproc_2_svc(
	mdrpc_null_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_hostname_2_svc(
	mdrpc_null_args	*a,
	mdrpc_hostname_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_addhosts_2_svc(
	mdrpc_host_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_delhosts_2_svc(
	mdrpc_host_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_createset_2_svc(
	mdrpc_createset_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_delset_2_svc(
	mdrpc_sp_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_getset_2_svc(
	mdrpc_getset_args *a,
	mdrpc_getset_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_setnumbusy_2_svc(
	mdrpc_setno_args *a,
	mdrpc_bool_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_setnameok_2_svc(
	mdrpc_sp_args *a,
	mdrpc_bool_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_ownset_2_svc(
	mdrpc_sp_args *a,
	mdrpc_bool_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_adddrvs_2_svc(
	mdrpc_drives_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_imp_set_drvs_2_svc(
	mdrpc_drives_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_deldrvs_2_svc(
	mdrpc_drives_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_upd_dr_dbinfo_2_svc(
	mdrpc_drives_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_devinfo_2_svc(
	mdrpc_devinfo_2_args *a,
	mdrpc_devinfo_2_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_devid_2_svc(
	mdrpc_devid_args *a,
	mdrpc_devid_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_devinfo_by_devid_2_svc(
	mdrpc_devidstr_args *a,
	mdrpc_devinfo_2_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_devinfo_by_devid_name_2_svc(
	mdrpc_devid_name_2_args *a,
	mdrpc_devinfo_2_res *b,
	struct svc_req *c
)
{
	assert(0);
	return (TRUE);
}


/*ARGSUSED*/
bool_t
_mdrpc_drvused_2_svc(
	mdrpc_drvused_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_add_drv_sidenms_2_svc(
	mdrpc_drv_sidenm_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_del_drv_sidenms_2_svc(
	mdrpc_sp_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_gtimeout_2_svc(
	mdrpc_sp_args *a,
	mdrpc_gtimeout_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_stimeout_2_svc(
	mdrpc_stimeout_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_upd_dr_flags_2_svc(
	mdrpc_upd_dr_flags_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_upd_sr_flags_2_svc(
	mdrpc_upd_sr_flags_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c
)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_unlock_set_2_svc(
	mdrpc_null_args *a,
	mdrpc_setlock_res *b,
	struct svc_req *c
)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_lock_set_2_svc(
	mdrpc_null_args *a,
	mdrpc_setlock_res *b,
	struct svc_req *c
)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_updmeds_2_svc(
	mdrpc_updmeds_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c
)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_mncreateset_2_svc(
	mdrpc_mncreateset_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c
)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_mngetset_2_svc(
	mdrpc_getset_2_args *a,
	mdrpc_mngetset_res *b,
	struct svc_req *c
)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_mnsetmaster_2_svc(
	mdrpc_mnsetmaster_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c
)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_joinset_2_svc(
	mdrpc_sp_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c
)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_withdrawset_2_svc(
	mdrpc_sp_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_upd_nr_flags_2_svc(
	mdrpc_upd_nr_flags_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_mn_is_stale_2_svc(
	mdrpc_setno_2_args *a,
	mdrpc_bool_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_mdcommdctl_2_svc(
	mdrpc_mdcommdctl_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_resnarf_set_2_svc(
	mdrpc_setno_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_upd_dr_reconfig_2_svc(
	mdrpc_upd_dr_flags_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_getdrivedesc_2_svc(
	mdrpc_sp_2_args *a,
	mdrpc_getdrivedesc_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_reset_mirror_owner_2_svc(
	mdrpc_nodeid_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_mn_susp_res_io_2_svc(
	mdrpc_mn_susp_res_io_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_mn_mirror_resync_all_2_svc(
	mdrpc_setno_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}

/*ARGSUSED*/
bool_t
_mdrpc_imp_adddrvs_2_svc(
	mdrpc_drives_2_args *a,
	mdrpc_generic_res *b,
	struct svc_req *c)
{
	assert(0);
	return (TRUE);
}
