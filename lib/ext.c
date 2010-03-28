/* ext.c --- Implementation of GSS specific extensions.
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2009, 2010  Simon Josefsson
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

#include "internal.h"

/**
 * gss_oid_equal:
 * @first_oid: (Object ID, read) First Object identifier.
 * @second_oid: (Object ID, read) First Object identifier.
 *
 * Compare two OIDs for equality.  The comparison is "deep", i.e., the
 * actual byte sequences of the OIDs are compared instead of just the
 * pointer equality.
 *
 * WARNING: This function is a GNU GSS specific extension, and is not
 * part of the official GSS API.
 *
 * Return value: Returns boolean value true when the two OIDs are
 *   equal, otherwise false.
 **/
int
gss_oid_equal (const gss_OID first_oid, const gss_OID second_oid)
{
  return first_oid && second_oid &&
    first_oid->length == second_oid->length &&
    memcmp (first_oid->elements, second_oid->elements,
	    second_oid->length) == 0;
}

/**
 * gss_userok:
 * @name: (gss_name_t, read) Name to be compared.
 * @username: Zero terminated string with username.
 *
 * Compare the username against the output from gss_export_name()
 * invoked on @name, after removing the leading OID.  This answers the
 * question whether the particular mechanism would authenticate them
 * as the same principal
 *
 * WARNING: This function is a GNU GSS specific extension, and is not
 * part of the official GSS API.
 *
 * Return value: Returns 0 if the names match, non-0 otherwise.
 **/
int
gss_userok (const gss_name_t name, const char *username)
{
  /* FIXME: Call gss_export_name, then remove OID. */
  return name->length == strlen (username) &&
    memcmp (name->value, username, name->length) == 0;
}
