/* ext.h --- Header file for non-standard GSS-API functions.
 * Copyright (C) 2003-2012 Simon Josefsson
 *
 * This file is part of the Generic Security Service (GSS).
 *
 * GSS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GSS is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GSS; if not, see http://www.gnu.org/licenses or write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA.
 *
 */

#ifndef GSS_EXT_H_
#define GSS_EXT_H_

/* Get size_t. */
#include <stddef.h>

/* See version.c. */
extern const char *gss_check_version (const char *req_version);

/* See ext.c. */
extern int gss_userok (const gss_name_t name, const char *username);

/* Static versions of the public OIDs for use, e.g., in static
   variable initalization.  See oid.c. */
extern gss_OID_desc GSS_C_NT_USER_NAME_static;
extern gss_OID_desc GSS_C_NT_MACHINE_UID_NAME_static;
extern gss_OID_desc GSS_C_NT_STRING_UID_NAME_static;
extern gss_OID_desc GSS_C_NT_HOSTBASED_SERVICE_X_static;
extern gss_OID_desc GSS_C_NT_HOSTBASED_SERVICE_static;
extern gss_OID_desc GSS_C_NT_ANONYMOUS_static;
extern gss_OID_desc GSS_C_NT_EXPORT_NAME_static;

/* Solaris, Heimdal and MIT Kerberos V5 have the following two. */
extern OM_uint32
gss_acquire_cred_with_password (OM_uint32 *minor_status,
				const gss_name_t desired_name,
				const gss_buffer_t password,
				OM_uint32 time_req,
				const gss_OID_set desired_mechs,
				gss_cred_usage_t cred_usage,
				gss_cred_id_t *output_cred_handle,
				gss_OID_set *actual_mechs,
				OM_uint32 *time_rec);
extern OM_uint32
gss_add_cred_with_password (OM_uint32 * minor_status,
			    const gss_cred_id_t input_cred_handle,
			    const gss_name_t desired_name,
			    const gss_OID desired_mech,
			    const gss_buffer_t password,
			    gss_cred_usage_t cred_usage,
			    OM_uint32 initiator_time_req,
			    OM_uint32 acceptor_time_req,
			    gss_cred_id_t * output_cred_handle,
			    gss_OID_set * actual_mechs,
			    OM_uint32 * initiator_time_rec,
			    OM_uint32 * acceptor_time_rec);

#endif
