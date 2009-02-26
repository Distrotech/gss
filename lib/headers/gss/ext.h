/* ext.h --- Header file for non-standard GSS-API functions.
 * Copyright (C) 2003, 2004, 2005, 2006, 2007  Simon Josefsson
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

/* If non-NULL, call this function when memory is exhausted. */
extern void (*gss_alloc_fail_function) (void);

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
gss_encapsulate_token (const gss_buffer_t input_message,
		       gss_OID token_oid, gss_buffer_t output_message);
extern int
gss_encapsulate_token_prefix (const gss_buffer_t input_message,
			      const char *prefix, size_t prefixlen,
			      gss_OID token_oid, gss_buffer_t output_message);
extern int
gss_decapsulate_token (const gss_buffer_t input_message,
		       const gss_OID token_oid,
		       char **dataptr, size_t * datalen);

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
