/* name.c	Implementation of GSS-API Name Manipulation functions.
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

#include "internal.h"

OM_uint32
gss_import_name (OM_uint32 * minor_status,
		 const gss_buffer_t input_name_buffer,
		 const gss_OID input_name_type, gss_name_t * output_name)
{
  OM_uint32 major_stat;

  if (!output_name)
    return GSS_S_FAILURE;

  *output_name = xmalloc (sizeof (**output_name));
  (*output_name)->length = input_name_buffer->length;
  (*output_name)->value = xmalloc (input_name_buffer->length);
  memcpy ((*output_name)->value, input_name_buffer->value,
	  input_name_buffer->length);

  if (input_name_type)
    {
      major_stat = gss_duplicate_oid (minor_status, input_name_type,
				      &(*output_name)->type);
      if (major_stat != GSS_S_COMPLETE)
	return major_stat;
    }
  else
    (*output_name)->type = GSS_C_NO_OID;

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

OM_uint32
gss_display_name (OM_uint32 * minor_status,
		  const gss_name_t input_name,
		  gss_buffer_t output_name_buffer, gss_OID * output_name_type)
{
  if (!input_name)
    return GSS_S_BAD_NAME;

  output_name_buffer->length = input_name->length;
  output_name_buffer->value = xmalloc (input_name->length + 1);
  if (input_name->value)
    memcpy (output_name_buffer->value, input_name->value, input_name->length);

  if (output_name_type)
    if (input_name->type)
      *output_name_type = &input_name->type;
    else
      *output_name_type = GSS_C_NO_OID;

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

OM_uint32
gss_compare_name (OM_uint32 * minor_status,
		  const gss_name_t name1,
		  const gss_name_t name2, int *name_equal)
{
  if (!name1 || !name2)
    return GSS_S_BAD_NAME;

  if (!gss_oid_equal (name1->type, name2->type))
    return GSS_S_BAD_NAMETYPE;

  name_equal == (name1->length == name2->length) &&
    memcmp (name1->value, name2->value, name1->length) == 0;

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

/**
 * gss_release_name:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @name: (gss_name_t, modify) The name to be deleted.
 *
 * Free GSSAPI-allocated storage associated with an internal-form
 * name.  Implementations are encouraged to set the name to
 * GSS_C_NO_NAME on successful completion of this call.
 *
 * Valid return values and their meaning:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_BAD_NAME`: The name parameter did not contain a valid name.
 **/
OM_uint32
gss_release_name (OM_uint32 * minor_status, gss_name_t * name)
{
  if (minor_status)
    *minor_status = 0;

  if (!name || *name == GSS_C_NO_NAME)
    return GSS_S_BAD_NAME;

  if ((*name)->value)
    free ((*name)->value);

  free (*name);
  *name = GSS_C_NO_NAME;

  return GSS_S_COMPLETE;
}

OM_uint32
gss_inquire_names_for_mech (OM_uint32 * minor_status,
			    const gss_OID mechanism, gss_OID_set * name_types)
{
  OM_uint32 maj_stat;
  _gss_mech_api_t mech;
  int i;

  mech = _gss_find_mech (mechanism);

  maj_stat = gss_create_empty_oid_set (minor_status, name_types);
  if (maj_stat != GSS_S_COMPLETE)
    return maj_stat;

  for (i = 0; mech->name_types[i]; i++)
    {
      maj_stat = gss_add_oid_set_member (minor_status, mech->name_types[i],
					 name_types);
      if (maj_stat != GSS_S_COMPLETE)
	{
	  gss_release_oid_set (minor_status, name_types);
	  return maj_stat;
	}
    }

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

static OM_uint32
_gss_inquire_mechs_for_name2 (OM_uint32 * minor_status,
			      _gss_mech_api_t mech,
			      gss_OID name_type, gss_OID_set * mech_types)
{
  gss_OID_set oids;
  int supported;
  OM_uint32 maj_stat;

  maj_stat = gss_inquire_names_for_mech (minor_status, mech->mech, &oids);
  if (maj_stat != GSS_S_COMPLETE)
    return maj_stat;

  maj_stat = gss_test_oid_set_member (minor_status, name_type,
				      oids, &supported);
  if (maj_stat != GSS_S_COMPLETE)
    {
      gss_release_oid_set (minor_status, &oids);
      return maj_stat;
    }

  if (supported)
    {
      maj_stat = gss_add_oid_set_member (minor_status,
					 mech->mech, mech_types);
      if (maj_stat != GSS_S_COMPLETE)
	{
	  gss_release_oid_set (minor_status, &oids);
	  return maj_stat;
	}
    }
  gss_release_oid_set (minor_status, &oids);

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

static OM_uint32
_gss_inquire_mechs_for_name1 (OM_uint32 * minor_status,
			      gss_OID name_type, gss_OID_set * mech_types)
{
  OM_uint32 maj_stat;
  int i;

  for (i = 0; _gss_mech_apis[i].mech; i++)
    {
      maj_stat = _gss_inquire_mechs_for_name2 (minor_status,
					       &_gss_mech_apis[i],
					       name_type, mech_types);
      if (maj_stat != GSS_S_COMPLETE)
	return maj_stat;
    }

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

OM_uint32
gss_inquire_mechs_for_name (OM_uint32 * minor_status,
			    const gss_name_t input_name,
			    gss_OID_set * mech_types)
{
  int i;
  OM_uint32 maj_stat;

  maj_stat = gss_create_empty_oid_set (minor_status, mech_types);
  if (maj_stat != GSS_S_COMPLETE)
    return maj_stat;

  maj_stat = _gss_inquire_mechs_for_name1 (minor_status, input_name->type,
					   mech_types);
  if (maj_stat != GSS_S_COMPLETE)
    {
      gss_release_oid_set (minor_status, mech_types);
      return maj_stat;
    }

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

OM_uint32
gss_export_name (OM_uint32 * minor_status,
		 const gss_name_t input_name, gss_buffer_t exported_name)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_canonicalize_name (OM_uint32 * minor_status,
		       const gss_name_t input_name,
		       const gss_OID mech_type, gss_name_t * output_name)
{
  _gss_mech_api_t mech;

  mech = _gss_find_mech (mech_type);

  return mech->canonicalize_name (minor_status, input_name,
				  mech_type, output_name);
}

OM_uint32
gss_duplicate_name (OM_uint32 * minor_status,
		    const gss_name_t src_name, gss_name_t * dest_name)
{
  OM_uint32 maj_stat;

  if (src_name == GSS_C_NO_NAME)
    return GSS_S_BAD_NAME;

  if (!dest_name || !*dest_name)
    return GSS_S_FAILURE;

  maj_stat = gss_duplicate_oid (minor_status, src_name->type,
				&((*dest_name)->type));
  if (GSS_ERROR (maj_stat))
    return maj_stat;
  (*dest_name)->length = src_name->length;
  (*dest_name)->value = xmalloc (src_name->length);
  memcpy ((*dest_name)->value, src_name->value, src_name->length);

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}
