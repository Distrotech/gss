/* misc.c	Implementation of GSS-API Miscellaneous functions.
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

/**
 * gss_oid_equal:
 * @first_oid: (Object ID, read) First Object identifier.
 * @second_oid: (Object ID, read) First Object identifier.
 *
 * Compare two OIDs for equality.  The comparison is "deep", i.e., the
 * actual byte sequences of the OIDs are compared instead of just the
 * pointer equality.
 *
 * WARNING: This function is a GNU GSSLib specific extension, and is
 * not part of the official GSS API.
 *
 * Return value: Returns boolean value true when the two OIDs are
 *   equal, otherwise false.
 **/
int
gss_oid_equal (gss_OID first_oid, gss_OID second_oid)
{

  return first_oid && second_oid &&
    first_oid->length == second_oid->length &&
    memcmp (first_oid->elements, second_oid->elements,
	    second_oid->length) == 0;
}

/**
 * gss_copy_oid:
 * @minor_status: (integer, modify) Mechanism specific status code.
 * @src_oid: (Object ID, read) The object identifier to copy.
 * @dest_oid: (Object ID, modify) The resultant copy of @src_oid.
 *   Storage associated with this name must be freed by the
 *   application, but gss_release_oid() cannot be used generally as it
 *   deallocate the the oid structure itself too (use
 *   gss_duplicate_oid() if you don't want this problem.)
 *
 * Make an exact copy of the given OID, that shares no memory areas
 * with the original.
 *
 * WARNING: This function is a GNU GSSLib specific extension, and is
 * not part of the official GSS API.
 *
 * Valid return values and their meaning:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 **/
OM_uint32
gss_copy_oid (OM_uint32 * minor_status,
	      const gss_OID src_oid, gss_OID dest_oid)
{
  if (minor_status)
    *minor_status = 0;

  if (!src_oid)
    return GSS_S_FAILURE | GSS_S_CALL_INACCESSIBLE_READ;

  if (src_oid->length == 0 || src_oid->elements == NULL)
    return GSS_S_FAILURE | GSS_S_CALL_BAD_STRUCTURE;

  dest_oid->length = src_oid->length;
  dest_oid->elements = xmalloc (src_oid->length);
  memcpy (dest_oid->elements, src_oid->elements, src_oid->length);

  return GSS_S_COMPLETE;
}

/**
 * gss_duplicate_oid:
 * @minor_status: (integer, modify) Mechanism specific status code.
 * @src_oid: (Object ID, read) The object identifier to duplicate.
 * @dest_oid: (Object ID, modify) The resultant copy of @src_oid.
 *   Storage associated with this name must be freed by the
 *   application, by calling gss_release_oid().
 *
 * Allocate a new OID and make it an exact copy of the given OID, that
 * shares no memory areas with the original.
 *
 * WARNING: This function is a GNU GSSLib specific extension, and is
 * not part of the official GSS API.
 *
 * Valid return values and their meaning:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 **/
OM_uint32
gss_duplicate_oid (OM_uint32 * minor_status,
		   const gss_OID src_oid, gss_OID * dest_oid)
{
  /* This function is not part of the official GSS API */

  OM_uint32 maj_stat;

  if (minor_status)
    *minor_status = 0;

  if (!src_oid)
    return GSS_S_FAILURE | GSS_S_CALL_INACCESSIBLE_READ;

  if (src_oid->length == 0 || src_oid->elements == NULL)
    return GSS_S_FAILURE | GSS_S_CALL_BAD_STRUCTURE;

  *dest_oid = xmalloc (sizeof (**dest_oid));

  maj_stat = gss_copy_oid (minor_status, src_oid, *dest_oid);
  if (GSS_ERROR (maj_stat))
    {
      free (*dest_oid);
      return maj_stat;
    }

  return GSS_S_COMPLETE;
}

/**
 * gss_release_oid:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @oid: (gss_name_t, modify) The OID to be deleted.
 *
 * Free GSSAPI-allocated storage associated with an OID.  The OID is
 * set to GSS_C_NO_NAME on successful completion of this call.
 *
 * WARNING: This function is a GNU GSSLib specific extension, and is
 * not part of the official GSS API.
 *
 * Valid return values and their meaning:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 **/
OM_uint32
gss_release_oid (OM_uint32 * minor_status, gss_OID *oid)
{
  if (minor_status)
    *minor_status = 0;

  if (!oid)
    return GSS_S_FAILURE | GSS_S_CALL_INACCESSIBLE_READ;

  if (*oid != GSS_C_NO_OID)
    {
      if ((*oid)->elements)
	free ((*oid)->elements);
      free (*oid);
      *oid = GSS_C_NO_OID;
    }

  return GSS_S_COMPLETE;
}

/**
 * gss_create_empty_oid_set:
 * @minor_status: (integer, modify) Mechanism specific status code.
 * @oid_set: (Set of Object IDs, modify) The empty object identifier
 *   set.  The routine will allocate the gss_OID_set_desc object,
 *   which the application must free after use with a call to
 *   gss_release_oid_set().
 *
 * Create an object-identifier set containing no object identifiers,
 * to which members may be subsequently added using the
 * gss_add_oid_set_member() routine.  These routines are intended to
 * be used to construct sets of mechanism object identifiers, for
 * input to gss_acquire_cred.
 *
 * Valid return values and their meaning:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 **/
OM_uint32
gss_create_empty_oid_set (OM_uint32 * minor_status, gss_OID_set * oid_set)
{
  if (minor_status)
    *minor_status = 0;

  *oid_set = xmalloc (sizeof (**oid_set));
  (*oid_set)->count = 0;
  (*oid_set)->elements = NULL;

  return GSS_S_COMPLETE;
}

/**
 * gss_add_oid_set_member:
 * @minor_status: (integer, modify) Mechanism specific status code.
 * @member_oid: (Object ID, read) The object identifier to copied into
 *   the set.
 * @oid_set: (Set of Object ID, modify) The set in which the object
 *   identifier should be inserted.
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
 * Valid return values and their meaning:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 **/
OM_uint32
gss_add_oid_set_member (OM_uint32 * minor_status,
			const gss_OID member_oid, gss_OID_set * oid_set)
{
  OM_uint32 major_stat;
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

  if ((*oid_set)->count + 1 == 0)	/* integer overflow */
    return GSS_S_FAILURE;

  (*oid_set)->count++;
  (*oid_set)->elements = xrealloc ((*oid_set)->elements,
				   (*oid_set)->count *
				   sizeof (*(*oid_set)->elements));

  major_stat = gss_copy_oid (minor_status, member_oid,
			     (*oid_set)->elements + ((*oid_set)->count - 1));
  if (major_stat != GSS_S_COMPLETE)
    return major_stat;

  return GSS_S_COMPLETE;
}

/**
 * gss_test_oid_set_member:
 * @minor_status: (integer, modify) Mechanism specific status code.
 * @member: (Object ID, read) The object identifier whose presence is
 *   to be tested.
 * @set: (Set of Object ID, read) The Object Identifier set.
 * @present: (Boolean, modify) Non-zero if the specified OID is a
 *   member of the set, zero if not.
 *
 * Interrogate an Object Identifier set to determine whether a
 * specified Object Identifier is a member.  This routine is intended
 * to be used with OID sets returned by gss_indicate_mechs(),
 * gss_acquire_cred(), and gss_inquire_cred(), but will also work with
 * user-generated sets.
 *
 * Valid return values and their meaning:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 **/
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

  if (member == GSS_C_NO_OID)
    return GSS_S_COMPLETE;

  for (i = 0, cur = set->elements; i < set->count; i++, cur++)
    {
      if (cur->length == member->length &&
	  memcmp (cur->elements, member->elements, member->length) == 0)
	{
	  *present = 1;
	  return GSS_S_COMPLETE;
	}
    }

  return GSS_S_COMPLETE;
}

/**
 * gss_release_oid_set:
 * @minor_status: (integer, modify) Mechanism specific status code.
 * @set: (Set of Object IDs, modify) The storage associated with the
 *   gss_OID_set will be deleted.
 *
 * Free storage associated with a GSSAPI-generated gss_OID_set object.
 * The set parameter must refer to an OID-set that was returned from a
 * GSS-API routine.  gss_release_oid_set() will free the storage
 * associated with each individual member OID, the OID set's elements
 * array, and the gss_OID_set_desc.
 *
 * The gss_OID_set parameter is set to GSS_C_NO_OID_SET on successful
 * completion of this routine.
 *
 * Valid return values and their meaning:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 **/
OM_uint32
gss_release_oid_set (OM_uint32 * minor_status, gss_OID_set * set)
{
  int i;
  gss_OID cur;

  if (minor_status)
    *minor_status = 0;

  if (!set || *set == GSS_C_NO_OID_SET)
    return GSS_S_COMPLETE;

  for (i = 0, cur = (*set)->elements; i < (*set)->count; i++, cur++)
    free (cur->elements);

  free (*set);
  *set = GSS_C_NO_OID_SET;

  return GSS_S_COMPLETE;
}

/**
 * gss_indicate_mechs:
 * @minor_status: (integer, modify) Mechanism specific status code.
 * @mech_set: (set of Object IDs, modify) Set of
 *   implementation-supported mechanisms.  The returned gss_OID_set
 *   value will be a dynamically-allocated OID set, that should be
 *   released by the caller after use with a call to
 *   gss_release_oid_set().
 *
 * Allows an application to determine which underlying security
 * mechanisms are available.
 *
 * Valid return values and their meaning:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 **/
OM_uint32
gss_indicate_mechs (OM_uint32 * minor_status, gss_OID_set * mech_set)
{
  OM_uint32 maj_stat;
  int i;

  maj_stat = gss_create_empty_oid_set (minor_status, mech_set);
  if (maj_stat != GSS_S_COMPLETE)
    return maj_stat;

  for (i = 0; _gss_mech_apis[i].mech; i++)
    {
      maj_stat = gss_add_oid_set_member (minor_status, _gss_mech_apis[i].mech,
					 mech_set);
      if (maj_stat != GSS_S_COMPLETE)
	{
	  gss_release_oid_set (minor_status, mech_set);
	  return maj_stat;
	}
    }

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

/**
 * gss_release_buffer:
 * @minor_status: (integer, modify) Mechanism specific status code.
 * @buffer: (buffer, modify) The storage associated with the buffer
 *   will be deleted.  The gss_buffer_desc object will not be freed,
 *   but its length field will be zeroed.
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
 * Valid return values and their meaning:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 **/
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
