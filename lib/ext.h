/* ext.h --- Header file for non-standard GSS-API functions.
 * Copyright (C) 2003, 2004  Simon Josefsson
 *
 * This file is part of the Generic Security Service (GSS).
 *
 * GSS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GSS is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GSS; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

#ifndef GSS_EXT_H_
#define GSS_EXT_H_

/* Get size_t. */
#include <stddef.h>

/* See version.c. */
extern const char *gss_check_version (const char *req_version);

/* See ext.c. */
extern int gss_oid_equal (gss_OID first_oid, gss_OID second_oid);
extern OM_uint32
gss_copy_oid (OM_uint32 * minor_status,
	      const gss_OID src_oid, gss_OID dest_oid);
extern OM_uint32
gss_duplicate_oid (OM_uint32 * minor_status,
		   const gss_OID src_oid, gss_OID * dest_oid);
extern int gss_userok (const gss_name_t name, const char *username);

/* See asn1.c. */
extern int
gss_encapsulate_token (gss_buffer_t input_message,
		       gss_OID token_oid, gss_buffer_t output_message);
extern int
gss_encapsulate_token_prefix (gss_buffer_t input_message,
			      char *prefix, size_t prefixlen,
			      gss_OID token_oid, gss_buffer_t output_message);
extern int
gss_decapsulate_token (gss_buffer_t input_message,
		       gss_OID token_oid, gss_buffer_t output_message);

/* Static versions of the public OIDs for use, e.g., in static
   variable initalization.  See oid.c. */
extern gss_OID_desc GSS_C_NT_USER_NAME_static;
extern gss_OID_desc GSS_C_NT_MACHINE_UID_NAME_static;
extern gss_OID_desc GSS_C_NT_STRING_UID_NAME_static;
extern gss_OID_desc GSS_C_NT_HOSTBASED_SERVICE_X_static;
extern gss_OID_desc GSS_C_NT_HOSTBASED_SERVICE_static;
extern gss_OID_desc GSS_C_NT_ANONYMOUS_static;
extern gss_OID_desc GSS_C_NT_EXPORT_NAME_static;

#endif
