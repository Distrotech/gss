/* name.c	Implementation of GSS-API Name Manipulation functions.
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

#include "internal.h"

OM_uint32
gss_import_name (OM_uint32 * minor_status,
		 const gss_buffer_t input_name_buffer,
		 const gss_OID input_name_type, gss_name_t * output_name)
{
  OM_uint32 major_stat;

  if (!output_name)
    return GSS_S_FAILURE;

  *output_name = malloc (sizeof (*output_name));
  if (!*output_name)
    return GSS_S_FAILURE;

  (*output_name)->length = input_name_buffer->length;
  (*output_name)->value = malloc (input_name_buffer->length);
  if (!(*output_name)->value)
    return GSS_S_FAILURE;

  memcpy ((*output_name)->value, input_name_buffer->value,
	  input_name_buffer->length);

  major_stat = gss_duplicate_oid (minor_status, input_name_type,
				  &(*output_name)->type);
  if (major_stat != GSS_S_COMPLETE)
    return major_stat;

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
  output_name_buffer->value = malloc (input_name->length);
  if (!output_name_buffer->value)
    return GSS_S_FAILURE;
  memcpy (output_name_buffer->value, input_name->value, input_name->length);

  if (output_name_type)
    *output_name_type = &input_name->type;

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
    memcmp(name1->value, name2->value, name1->length) == 0;

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

OM_uint32
gss_release_name (OM_uint32 * minor_status, gss_name_t * name)
{
  if (!name || *name == GSS_C_NO_NAME)
    return GSS_S_BAD_NAME;

  if ((*name)->value)
    free ((*name)->value);

  free(*name);
  *name = GSS_C_NO_NAME;

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

/* See meta.c for gss_inquire_names_for_mech() and
   gss_inquire_mechs_for_name() */

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
  if (src_name == GSS_C_NO_NAME)
    return GSS_S_BAD_NAME;

  if (!dest_name || !*dest_name)
    return GSS_S_FAILURE;

  (*dest_name)->type = src_name->type; /* XXX duplicate oid? */
  (*dest_name)->length = src_name->length;
  (*dest_name)->value = malloc(src_name->length);
  if (!(*dest_name)->value)
    return GSS_S_FAILURE;
  memcpy((*dest_name)->value, src_name->value, src_name->length);

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}
