/* misc.c --- Implementation of GSS-API Miscellaneous functions.
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010  Simon Josefsson
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

/* _gss_indicate_mechs1 */
#include "meta.h"

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
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 **/
OM_uint32
gss_create_empty_oid_set (OM_uint32 * minor_status, gss_OID_set * oid_set)
{
  if (minor_status)
    *minor_status = 0;

  *oid_set = malloc (sizeof (**oid_set));
  if (!*oid_set)
    {
      if (minor_status)
	*minor_status = ENOMEM;
      return GSS_S_FAILURE;
    }
  (*oid_set)->count = 0;
  (*oid_set)->elements = NULL;

  return GSS_S_COMPLETE;
}

/*
 * gss_copy_oid:
 * @minor_status: (integer, modify) Mechanism specific status code.
 * @src_oid: (Object ID, read) The object identifier to copy.
 * @dest_oid: (Object ID, modify) The resultant copy of @src_oid.
 *   Storage associated with this name must be freed by the
 *   application, but gss_release_oid() cannot be used generally as it
 *   deallocate the oid structure itself too.
 *
 * Make an exact copy of the given OID, that shares no memory areas
 * with the original.
 *
 * WARNING: This function is a GNU GSS specific extension, and is not
 * part of the official GSS API.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 **/
OM_uint32
_gss_copy_oid (OM_uint32 * minor_status,
	       const gss_OID src_oid, gss_OID dest_oid)
{
  if (minor_status)
    *minor_status = 0;

  if (!src_oid)
    return GSS_S_FAILURE | GSS_S_CALL_INACCESSIBLE_READ;

  if (src_oid->length == 0 || src_oid->elements == NULL)
    return GSS_S_FAILURE | GSS_S_CALL_BAD_STRUCTURE;

  dest_oid->length = src_oid->length;
  dest_oid->elements = malloc (src_oid->length);
  if (!dest_oid->elements)
    {
      if (minor_status)
	*minor_status = ENOMEM;
      return GSS_S_FAILURE;
    }
  memcpy (dest_oid->elements, src_oid->elements, src_oid->length);

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
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 **/
OM_uint32
gss_add_oid_set_member (OM_uint32 * minor_status,
			const gss_OID member_oid, gss_OID_set * oid_set)
{
  OM_uint32 major_stat;
  int present;

  if (!member_oid || member_oid->length == 0 || member_oid->elements == NULL)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_FAILURE;
    }

  major_stat = gss_test_oid_set_member (minor_status, member_oid,
					*oid_set, &present);
  if (GSS_ERROR (major_stat))
    return major_stat;

  if (present)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_COMPLETE;
    }

  if ((*oid_set)->count + 1 == 0)	/* integer overflow */
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_FAILURE;
    }

  (*oid_set)->count++;
  {
    gss_OID tmp;

    tmp = realloc ((*oid_set)->elements, (*oid_set)->count *
		   sizeof (*(*oid_set)->elements));
    if (!tmp)
      {
	if (minor_status)
	  *minor_status = ENOMEM;
	return GSS_S_FAILURE;
      }

    (*oid_set)->elements = tmp;
  }

  major_stat = _gss_copy_oid (minor_status, member_oid,
			      (*oid_set)->elements + ((*oid_set)->count - 1));
  if (GSS_ERROR (major_stat))
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
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 **/
OM_uint32
gss_test_oid_set_member (OM_uint32 * minor_status,
			 const gss_OID member,
			 const gss_OID_set set, int *present)
{
  gss_OID cur;
  size_t i;

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
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 **/
OM_uint32
gss_release_oid_set (OM_uint32 * minor_status, gss_OID_set * set)
{
  gss_OID cur;
  size_t i;

  if (minor_status)
    *minor_status = 0;

  if (!set || *set == GSS_C_NO_OID_SET)
    return GSS_S_COMPLETE;

  for (i = 0, cur = (*set)->elements; i < (*set)->count; i++, cur++)
    free (cur->elements);
  free ((*set)->elements);
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
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 **/
OM_uint32
gss_indicate_mechs (OM_uint32 * minor_status, gss_OID_set * mech_set)
{
  OM_uint32 maj_stat;

  maj_stat = gss_create_empty_oid_set (minor_status, mech_set);
  if (GSS_ERROR (maj_stat))
    return maj_stat;

  maj_stat = _gss_indicate_mechs1 (minor_status, mech_set);
  if (GSS_ERROR (maj_stat))
    {
      gss_release_oid_set (NULL, mech_set);
      return maj_stat;
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
 * Return value:
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
      free (buffer->value);
      buffer->value = NULL;
      buffer->length = 0;
    }

  return GSS_S_COMPLETE;
}
