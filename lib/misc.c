/* misc.c	Implementation of GSS-API Miscellaneous functions.
 * Copyright (C) 2003  Simon Josefsson
 *
 * This file is part of GPL GSS-API.
 *
 * GPL GSS-API is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GPL GSS-API is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GPL GSS-API; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "internal.h"

int
_gss_oid_equal (gss_OID first_oid, gss_OID second_oid)
{
  return first_oid && second_oid &&
    first_oid->length == second_oid->length &&
    memcmp(first_oid->elements, second_oid->elements, second_oid->length) == 0;
}

OM_uint32
_gss_duplicate_oid (OM_uint32 * minor_status,
		    const gss_OID src_oid, gss_OID * dest_oid)
{
  if (src_oid->length == 0 || src_oid->elements == NULL)
    return GSS_S_FAILURE;

  *dest_oid = malloc(sizeof(**dest_oid));
  if (!*dest_oid)
    return GSS_S_FAILURE;

  (*dest_oid)->length = src_oid->length;
  (*dest_oid)->elements = malloc(src_oid->length);
  if (!(*dest_oid)->elements)
    return GSS_S_FAILURE;

  memcpy((*dest_oid)->elements, src_oid->elements, src_oid->length);

  return GSS_S_COMPLETE;
}

/**
 * gss_create_empty_oid_set:
 * @minor_status: Mechanism specific status code
 * @oid_set: The empty object identifier set. The routine will
 *   allocate the gss_OID_set_desc object, which the application must free
 *   after use with a call to gss_release_oid_set().
 *
 * Create an object-identifier set containing no object identifiers,
 * to which members may be subsequently added using the
 * gss_add_oid_set_member() routine.  These routines are intended to
 * be used to construct sets of mechanism object identifiers, for
 * input to gss_acquire_cred.
 *
 * Return value: Returns GSS_S_COMPLETE for successful completion.
 **/
OM_uint32
gss_create_empty_oid_set (OM_uint32 * minor_status, gss_OID_set * oid_set)
{
  *oid_set = malloc(sizeof(**oid_set));
  if (!*oid_set)
    return GSS_S_FAILURE;

  (*oid_set)->count = 0;
  (*oid_set)->elements = NULL;

  return GSS_S_COMPLETE;
}

/**
 * gss_add_oid_set_member:
 * @minor_status: Mechanism specific status code
 * @member_oid: The object identifier to copied into the set.
 * @oid_set: The set in which the object identifier should be inserted.
 *
 * Add an Object Identifier to an Object Identifier set.  This routine
 * is intended for use in conjunction with gss_create_empty_oid_set
 * when constructing a set of mechanism OIDs for input to
 * gss_acquire_cred.  The oid_set parameter must refer to an OID-set
 * that was created by GSS-API (e.g. a set returned by
 * gss_create_empty_oid_set()). GSS-API creates a copy of the
 * member_oid and inserts this copy into the set, expanding the
 * storage allocated to the OID-set's elements array if necessary.
 * The routine may add the new member OID anywhere within the elements
 * array, and implementations should verify that the new member_oid is
 * not already contained within the elements array; if the member_oid
 * is already present, the oid_set should remain unchanged.
 *
 * Return value: Returns GSS_S_COMPLETE for successful completion.
 **/
OM_uint32
gss_add_oid_set_member (OM_uint32 * minor_status,
			const gss_OID member_oid, gss_OID_set * oid_set)
{
  OM_uint32 major_stat;
  gss_OID new_oid;
  int present;

  if (member_oid->length == 0 || member_oid->elements == NULL)
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

  major_stat = _gss_duplicate_oid (minor_status, member_oid,
				   &((*oid_set)->elements));
  if (major_stat != GSS_S_COMPLETE)
    return major_stat;

  return GSS_S_COMPLETE;
}

/**
 * gss_test_oid_set_member:
 * @minor_status: Mechanism specific status code
 * @member: The object identifier whose presence is to be tested.
 * @set: The Object Identifier set.
 * @present: output indicating if the specified OID is a member of the
 *   set, zero if not.
 *
 * Interrogate an Object Identifier set to determine whether a
 * specified Object Identifier is a member.  This routine is intended
 * to be used with OID sets returned by gss_indicate_mechs(),
 * gss_acquire_cred(), and gss_inquire_cred(), but will also work with
 * user-generated sets.
 *
 * Return value: Returns GSS_S_COMPLETE for successful completion.
 **/
OM_uint32
gss_test_oid_set_member (OM_uint32 * minor_status,
			 const gss_OID member,
			 const gss_OID_set set, int *present)
{
  int i;
  gss_OID cur;

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

/**
 * gss_release_oid_set:
 * @minor_status: Mechanism specific status code
 * @set: The storage associated with the gss_OID_set will be deleted.
 *
 * Free storage associated with a GSSAPI-generated gss_OID_set object.
 * The set parameter must refer to an OID-set that was returned from a
 * GSS-API routine.  gss_release_oid_set() will free the storage
 * associated with each individual member OID, the OID set's elements
 * array, and the gss_OID_set_desc.
 *
 * Implementations are encouraged to set the gss_OID_set parameter to
 * GSS_C_NO_OID_SET on successful completion of this routine.
 *
 * Return value: Returns GSS_S_COMPLETE for successful completion.
 **/
OM_uint32
gss_release_oid_set (OM_uint32 * minor_status, gss_OID_set * set)
{
  int i;
  gss_OID cur;

  for (i = 0, cur = (*set)->elements; i < (*set)->count; i++, cur++)
    {
      free(cur->elements);
      free(cur);
    }

  free(*set);
  *set = GSS_C_NO_OID_SET;

  return GSS_S_COMPLETE;
}

OM_uint32
gss_display_status (OM_uint32 * minor_status,
		    OM_uint32 status_value,
		    int status_type,
		    const gss_OID mech_type,
		    OM_uint32 * message_context, gss_buffer_t status_string)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_indicate_mechs (OM_uint32 * minor_status, gss_OID_set * mech_set)
{
  return GSS_S_FAILURE;
}

/**
 * gss_release_buffer:
 * @minor_status: Mechanism specific status code.
 * @buffer: The storage associated with the buffer will be deleted.
 *   The gss_buffer_desc object will not be freed, but its length field
 *   will be zeroed.
 *
 * Free storage associated with a buffer.  The storage must have been
 * allocated by a GSS-API routine.  In addition to freeing the
 * associated storage, the routine will zero the length field in the
 * descriptor to which the buffer parameter refers, and
 * implementations are encouraged to additionally set the pointer
 * field in the descriptor to NULL.  Any buffer object returned by a
 * GSS-API routine may be passed to gss_release_buffer (even if there
 * is no storage associated with the buffer).
 *
 * Return value: Returns GSS_S_COMPLETE for successful completion.
 **/
OM_uint32
gss_release_buffer (OM_uint32 * minor_status, gss_buffer_t buffer)
{
  if (buffer != GSS_C_NO_BUFFER)
    {
      if (buffer->value)
	free (buffer->value);
      buffer->length = 0;
    }

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}
