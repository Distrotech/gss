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

#endif
