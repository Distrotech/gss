/* misc.c	Implementation of GSS-API Miscellaneous functions.
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

int
gss_oid_equal (gss_OID first_oid, gss_OID second_oid)
{
  /* This function is not part of the official GSS API */

  return first_oid && second_oid &&
    first_oid->length == second_oid->length &&
    memcmp(first_oid->elements, second_oid->elements, second_oid->length) == 0;
}

OM_uint32
gss_copy_oid (OM_uint32 * minor_status,
	      const gss_OID src_oid, gss_OID dest_oid)
{
  /* This function is not part of the official GSS API */

  if (minor_status)
    *minor_status = 0;

  if (!src_oid || src_oid->length == 0 || src_oid->elements == NULL)
    return GSS_S_FAILURE;

  dest_oid->length = src_oid->length;
  dest_oid->elements = malloc(src_oid->length);
  if (!dest_oid->elements)
    return GSS_S_FAILURE;

  memcpy(dest_oid->elements, src_oid->elements, src_oid->length);

  return GSS_S_COMPLETE;
}

OM_uint32
gss_duplicate_oid (OM_uint32 * minor_status,
		   const gss_OID src_oid, gss_OID * dest_oid)
{
  OM_uint32 maj_stat;

  if (minor_status)
    *minor_status = 0;

  if (!src_oid || src_oid->length == 0 || src_oid->elements == NULL)
    return GSS_S_FAILURE;

  *dest_oid = malloc(sizeof(**dest_oid));
  if (!*dest_oid)
    return GSS_S_FAILURE;

  maj_stat = gss_copy_oid (minor_status, src_oid, *dest_oid);
  if (maj_stat != GSS_S_COMPLETE)
    {
      free(*dest_oid);
      return maj_stat;
    }

  return GSS_S_COMPLETE;
}

OM_uint32
gss_create_empty_oid_set (OM_uint32 * minor_status, gss_OID_set * oid_set)
{
  if (minor_status)
    *minor_status = 0;

  *oid_set = malloc(sizeof(**oid_set));
  if (!*oid_set)
    return GSS_S_FAILURE;

  (*oid_set)->count = 0;
  (*oid_set)->elements = NULL;

  return GSS_S_COMPLETE;
}

OM_uint32
gss_add_oid_set_member (OM_uint32 * minor_status,
			const gss_OID member_oid, gss_OID_set * oid_set)
{
  OM_uint32 major_stat;
  gss_OID new_oid;
  gss_OID *p;
  int present;

  if (minor_status)
    *minor_status = 0;

  if (!member_oid || member_oid->length == 0 || member_oid->elements == NULL)
    return GSS_S_FAILURE;

  major_stat = gss_test_oid_set_member (minor_status, member_oid,
					*oid_set, &present);
  if (major_stat != GSS_S_COMPLETE)
    return major_stat;

  if (present)
    return GSS_S_COMPLETE;

  if ((*oid_set)->count + 1 == 0) /* integer overflow */
    return GSS_S_FAILURE;

  (*oid_set)->count++;
  (*oid_set)->elements = realloc((*oid_set)->elements,
				 (*oid_set)->count *
				 sizeof(*(*oid_set)->elements));
  if (!(*oid_set)->elements)
    return GSS_S_FAILURE;

  major_stat = gss_copy_oid (minor_status, member_oid,
			     (*oid_set)->elements + ((*oid_set)->count - 1));
  if (major_stat != GSS_S_COMPLETE)
    return major_stat;

  return GSS_S_COMPLETE;
}

OM_uint32
gss_test_oid_set_member (OM_uint32 * minor_status,
			 const gss_OID member,
			 const gss_OID_set set, int *present)
{
  int i;
  gss_OID cur;

  if (minor_status)
    *minor_status = 0;

  *present = 0;

  for (i = 0, cur = set->elements; i < set->count; i++, cur++)
    {
      if (cur->length == member->length &&
	  memcmp(cur->elements, member->elements, member->length) == 0)
	{
	  *present = 1;
	  return GSS_S_COMPLETE;
	}
    }

  return GSS_S_COMPLETE;
}

OM_uint32
gss_release_oid_set (OM_uint32 * minor_status, gss_OID_set * set)
{
  int i;
  gss_OID cur;

  if (minor_status)
    *minor_status = 0;

  for (i = 0, cur = (*set)->elements; i < (*set)->count; i++, cur++)
    free(cur->elements);

  free(*set);
  *set = GSS_C_NO_OID_SET;

  return GSS_S_COMPLETE;
}

/* See error.c for gss_display_status() */

/* See meta.c for gss_indicate_mechs() */

OM_uint32
gss_release_buffer (OM_uint32 * minor_status, gss_buffer_t buffer)
{
  if (minor_status)
    *minor_status = 0;

  if (buffer != GSS_C_NO_BUFFER)
    {
      if (buffer->value)
	free (buffer->value);
      buffer->length = 0;
    }

  return GSS_S_COMPLETE;
}
