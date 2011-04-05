/* saslname.c --- Implementation of the SASL GS2 interfaces.
 * Copyright (C) 2010-2011 Simon Josefsson
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

/* _gss_find_mech* */
#include "meta.h"

static OM_uint32
dup_data (OM_uint32 * minor_status,
	  gss_buffer_t out, const char *str, int translate)
{
  if (!out)
    return GSS_S_COMPLETE;

  if (translate)
    out->value = strdup (_(str));
  else
    out->value = strdup (str);
  if (!out->value)
    {
      if (minor_status)
	*minor_status = ENOMEM;
      return GSS_S_FAILURE;
    }
  out->length = strlen (str);

  return GSS_S_COMPLETE;
}

/**
 * gss_inquire_saslname_for_mech:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @desired_mech: (OID, read) Identifies the GSS-API mechanism to query.
 * @sasl_mech_name: (buffer, character-string, modify, optional)
 *   Buffer to receive SASL mechanism name.  The application must free
 *   storage associated with this name after use with a call to
 *   gss_release_buffer().
 * @mech_name: (buffer, character-string, modify, optional) Buffer to
 *   receive human readable mechanism name.  The application must free
 *   storage associated with this name after use with a call to
 *   gss_release_buffer().
 * @mech_description: (buffer, character-string, modify, optional)
 *   Buffer to receive description of mechanism.  The application must
 *   free storage associated with this name after use with a call to
 *   gss_release_buffer().
 *
 * Output the SASL mechanism name of a GSS-API mechanism.  It also
 * returns a name and description of the mechanism in a user friendly
 * form.
 *
 * Returns:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_BAD_MECH`: The @desired_mech OID is unsupported.
 **/
OM_uint32
gss_inquire_saslname_for_mech (OM_uint32 * minor_status,
			       const gss_OID desired_mech,
			       gss_buffer_t sasl_mech_name,
			       gss_buffer_t mech_name,
			       gss_buffer_t mech_description)
{
  _gss_mech_api_t m;

  if (!desired_mech)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_CALL_INACCESSIBLE_READ;
    }

  m = _gss_find_mech_no_default (desired_mech);
  if (!m)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_BAD_MECH;
    }

  bindtextdomain (PACKAGE PO_SUFFIX, LOCALEDIR);

  if (dup_data (minor_status, sasl_mech_name,
		m->sasl_name, 0) != GSS_S_COMPLETE)
    return GSS_S_FAILURE;
  if (dup_data (minor_status, mech_name, m->mech_name, 0) != GSS_S_COMPLETE)
    {
      if (sasl_mech_name)
	free (sasl_mech_name->value);
      return GSS_S_FAILURE;
    }
  if (dup_data (minor_status, mech_description,
		m->mech_description, 1) != GSS_S_COMPLETE)
    {
      if (sasl_mech_name)
	free (sasl_mech_name->value);
      if (mech_name)
	free (mech_name->value);
      return GSS_S_FAILURE;
    }

  return GSS_S_COMPLETE;
}

/**
 * gss_inquire_mech_for_saslname:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @sasl_mech_name: (buffer, character-string, read) Buffer with SASL
 *   mechanism name.
 * @mech_type: (OID, modify, optional) Actual mechanism used.  The OID
 *   returned via this parameter will be a pointer to static storage
 *   that should be treated as read-only; In particular the
 *   application should not attempt to free it.  Specify NULL if not
 *   required.
 *
 * Output GSS-API mechanism OID of mechanism associated with given
 * @sasl_mech_name.
 *
 * Returns:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_BAD_MECH`: There is no GSS-API mechanism known as @sasl_mech_name.
 **/
OM_uint32
gss_inquire_mech_for_saslname (OM_uint32 * minor_status,
			       const gss_buffer_t sasl_mech_name,
			       gss_OID * mech_type)
{
  _gss_mech_api_t m;

  if (!sasl_mech_name)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_CALL_INACCESSIBLE_READ;
    }

  m = _gss_find_mech_by_saslname (sasl_mech_name);
  if (!m)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_BAD_MECH;
    }

  if (mech_type)
    *mech_type = m->mech;

  return GSS_S_COMPLETE;
}
