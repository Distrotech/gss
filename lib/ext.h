/* ext.h	Header file for non-standard GSS-API functions.
 * Copyright (C) 2003  Simon Josefsson
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

extern const char *
gss_check_version (const char *req_version);

extern int
gss_oid_equal (gss_OID first_oid, gss_OID second_oid);

extern OM_uint32
gss_duplicate_oid (OM_uint32 * minor_status,
		   const gss_OID src_oid, gss_OID * dest_oid);

extern int
gss_encapsulate_token (gss_buffer_t input_message,
		       gss_OID token_oid,
		       gss_buffer_t output_message);

extern int
gss_decapsulate_token (gss_buffer_t input_message,
		       gss_OID token_oid,
		       gss_buffer_t output_message);

#endif
