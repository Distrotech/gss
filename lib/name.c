/* name.c --- Implementation of GSS-API Name Manipulation functions.
 * Copyright (C) 2003-2014 Simon Josefsson
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

/* _gss_find_mech */
#include "meta.h"

/**
 * gss_import_name:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @input_name_buffer: (buffer, octet-string, read) Buffer containing
 *   contiguous string name to convert.
 * @input_name_type: (Object ID, read, optional) Object ID specifying
 *   type of printable name.  Applications may specify either
 *   GSS_C_NO_OID to use a mechanism-specific default printable
 *   syntax, or an OID recognized by the GSS-API implementation to
 *   name a specific namespace.
 * @output_name: (gss_name_t, modify) Returned name in internal form.
 *   Storage associated with this name must be freed by the
 *   application after use with a call to gss_release_name().
 *
 * Convert a contiguous string name to internal form.  In general, the
 * internal name returned (via the @output_name parameter) will not
 * be an MN; the exception to this is if the @input_name_type
 * indicates that the contiguous string provided via the
 * @input_name_buffer parameter is of type GSS_C_NT_EXPORT_NAME, in
 * which case the returned internal name will be an MN for the
 * mechanism that exported the name.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_BAD_NAMETYPE`: The input_name_type was unrecognized.
 *
 * `GSS_S_BAD_NAME`: The input_name parameter could not be interpreted
 * as a name of the specified type.
 *
 * `GSS_S_BAD_MECH`: The input name-type was GSS_C_NT_EXPORT_NAME, but
 * the mechanism contained within the input-name is not supported.
 **/
OM_uint32
gss_import_name (OM_uint32 * minor_status,
		 const gss_buffer_t input_name_buffer,
		 const gss_OID input_name_type, gss_name_t * output_name)
{
  if (!output_name)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_BAD_NAME | GSS_S_CALL_INACCESSIBLE_WRITE;
    }

  *output_name = malloc (sizeof (**output_name));
  if (!*output_name)
    {
      if (minor_status)
	*minor_status = ENOMEM;
      return GSS_S_FAILURE;
    }
  (*output_name)->length = input_name_buffer->length;
  (*output_name)->value = malloc (input_name_buffer->length);
  if (!(*output_name)->value)
    {
      free (*output_name);
      if (minor_status)
	*minor_status = ENOMEM;
      return GSS_S_FAILURE;
    }
  memcpy ((*output_name)->value,
	  input_name_buffer->value, input_name_buffer->length);

  (*output_name)->type = input_name_type;

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

/**
 * gss_display_name:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @input_name: (gss_name_t, read) Name to be displayed.
 * @output_name_buffer: (buffer, character-string, modify) Buffer to
 *   receive textual name string.  The application must free storage
 *   associated with this name after use with a call to
 *   gss_release_buffer().
 * @output_name_type: (Object ID, modify, optional) The type of the
 *   returned name.  The returned gss_OID will be a pointer into
 *   static storage, and should be treated as read-only by the caller
 *   (in particular, the application should not attempt to free
 *   it). Specify NULL if not required.
 *
 * Allows an application to obtain a textual representation of an
 * opaque internal-form name for display purposes.  The syntax of a
 * printable name is defined by the GSS-API implementation.
 *
 * If input_name denotes an anonymous principal, the implementation
 * should return the gss_OID value GSS_C_NT_ANONYMOUS as the
 * output_name_type, and a textual name that is syntactically distinct
 * from all valid supported printable names in output_name_buffer.
 *
 * If input_name was created by a call to gss_import_name, specifying
 * GSS_C_NO_OID as the name-type, implementations that employ lazy
 * conversion between name types may return GSS_C_NO_OID via the
 * output_name_type parameter.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_BAD_NAME`: @input_name was ill-formed.
 **/
OM_uint32
gss_display_name (OM_uint32 * minor_status,
		  const gss_name_t input_name,
		  gss_buffer_t output_name_buffer, gss_OID * output_name_type)
{
  if (!input_name)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_BAD_NAME;
    }

  output_name_buffer->length = input_name->length;
  output_name_buffer->value = malloc (input_name->length + 1);
  if (!output_name_buffer->value)
    {
      if (minor_status)
	*minor_status = ENOMEM;
      return GSS_S_FAILURE;
    }
  if (input_name->value)
    memcpy (output_name_buffer->value, input_name->value, input_name->length);

  if (output_name_type)
    *output_name_type = input_name->type;

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

/**
 * gss_compare_name:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @name1: (gss_name_t, read) Internal-form name.
 * @name2: (gss_name_t, read) Internal-form name.
 * @name_equal: (boolean, modify) Non-zero - names refer to same
 *   entity. Zero - names refer to different entities (strictly, the
 *   names are not known to refer to the same identity).
 *
 * Allows an application to compare two internal-form names to
 * determine whether they refer to the same entity.
 *
 * If either name presented to gss_compare_name denotes an anonymous
 * principal, the routines should indicate that the two names do not
 * refer to the same identity.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_BAD_NAMETYPE`: The two names were of incomparable types.
 *
 * `GSS_S_BAD_NAME`: One or both of name1 or name2 was ill-formed.
 **/
OM_uint32
gss_compare_name (OM_uint32 * minor_status,
		  const gss_name_t name1,
		  const gss_name_t name2, int *name_equal)
{
  if (minor_status)
    *minor_status = 0;

  if (!name1 || !name2)
    return GSS_S_BAD_NAME | GSS_S_CALL_INACCESSIBLE_READ;

  if (!gss_oid_equal (name1->type, name2->type))
    return GSS_S_BAD_NAMETYPE;

  if (name_equal)
    *name_equal = (name1->length == name2->length) &&
      memcmp (name1->value, name2->value, name1->length) == 0;

  return GSS_S_COMPLETE;
}

/**
 * gss_release_name:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @name: (gss_name_t, modify) The name to be deleted.
 *
 * Free GSSAPI-allocated storage associated with an internal-form
 * name.  The name is set to GSS_C_NO_NAME on successful completion of
 * this call.
 *
 * Return value:
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

  if (!name)
    return GSS_S_BAD_NAME | GSS_S_CALL_INACCESSIBLE_READ;

  if (*name != GSS_C_NO_NAME)
    {
      if ((*name)->value)
	free ((*name)->value);

      free (*name);
      *name = GSS_C_NO_NAME;
    }

  return GSS_S_COMPLETE;
}

/**
 * gss_inquire_names_for_mech:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @mechanism: (gss_OID, read) The mechanism to be interrogated.
 * @name_types: (gss_OID_set, modify) Set of name-types supported by
 *   the specified mechanism.  The returned OID set must be freed by
 *   the application after use with a call to gss_release_oid_set().
 *
 * Returns the set of nametypes supported by the specified mechanism.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 **/
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

/* Add mechanism MECH to OID set MECH_TYPES if mechanism MECH support
   the NAME_TYPE name type. */
static OM_uint32
_gss_inquire_mechs_for_name3 (OM_uint32 * minor_status,
			      gss_OID mech,
			      gss_OID name_type, gss_OID_set * mech_types)
{
  gss_OID_set oids;
  int supported;
  OM_uint32 maj_stat;

  maj_stat = gss_inquire_names_for_mech (minor_status, mech, &oids);
  if (GSS_ERROR (maj_stat))
    return maj_stat;

  maj_stat = gss_test_oid_set_member (minor_status, name_type,
				      oids, &supported);
  gss_release_oid_set (minor_status, &oids);
  if (GSS_ERROR (maj_stat))
    return maj_stat;

  if (supported)
    {
      maj_stat = gss_add_oid_set_member (minor_status, mech, mech_types);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
    }

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

/* Iterate over SUPPORTED_MECH_TYPES and invoke
   gss_inquire_mechs_for_name3 on each type, thus adding all mechanism
   OIDs, that support the NAME_TYPE name type, to OUT_MECH_TYPES. */
static OM_uint32
_gss_inquire_mechs_for_name2 (OM_uint32 * minor_status,
			      gss_OID name_type,
			      gss_OID_set * out_mech_types,
			      gss_OID_set supported_mech_types)
{
  OM_uint32 maj_stat;
  size_t i;

  for (i = 0; i < supported_mech_types->count; i++)
    {
      maj_stat = _gss_inquire_mechs_for_name3
	(minor_status, &(supported_mech_types->elements)[i],
	 name_type, out_mech_types);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
    }

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

/* List all supported mechanisms, and invoke
   gss_inquire_mechs_for_name2, thus adding all mechanism OIDs, that
   support the NAME_TYPE name type, to OUT_MECH_TYPES. */
static OM_uint32
_gss_inquire_mechs_for_name1 (OM_uint32 * minor_status,
			      gss_OID name_type, gss_OID_set * out_mech_types)
{
  OM_uint32 maj_stat;
  gss_OID_set supported_mech_types;

  maj_stat = gss_indicate_mechs (minor_status, &supported_mech_types);
  if (GSS_ERROR (maj_stat))
    return maj_stat;

  maj_stat = _gss_inquire_mechs_for_name2 (minor_status, name_type,
					   out_mech_types,
					   supported_mech_types);
  gss_release_oid_set (minor_status, &supported_mech_types);
  if (GSS_ERROR (maj_stat))
    return maj_stat;

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

/**
 * gss_inquire_mechs_for_name:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @input_name: (gss_name_t, read) The name to which the inquiry
 *   relates.
 * @mech_types: (gss_OID_set, modify) Set of mechanisms that may
 *   support the specified name.  The returned OID set must be freed
 *   by the caller after use with a call to gss_release_oid_set().
 *
 * Returns the set of mechanisms supported by the GSS-API
 * implementation that may be able to process the specified name.
 *
 * Each mechanism returned will recognize at least one element within
 * the name.  It is permissible for this routine to be implemented
 * within a mechanism-independent GSS-API layer, using the type
 * information contained within the presented name, and based on
 * registration information provided by individual mechanism
 * implementations.  This means that the returned mech_types set may
 * indicate that a particular mechanism will understand the name when
 * in fact it would refuse to accept the name as input to
 * gss_canonicalize_name, gss_init_sec_context, gss_acquire_cred or
 * gss_add_cred (due to some property of the specific name, as opposed
 * to the name type).  Thus this routine should be used only as a
 * prefilter for a call to a subsequent mechanism-specific routine.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_BAD_NAME`: The input_name parameter was ill-formed.
 *
 * `GSS_S_BAD_NAMETYPE`: The input_name parameter contained an invalid
 * or unsupported type of name.
 **/
OM_uint32
gss_inquire_mechs_for_name (OM_uint32 * minor_status,
			    const gss_name_t input_name,
			    gss_OID_set * mech_types)
{
  OM_uint32 maj_stat;

  if (input_name == GSS_C_NO_NAME)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_BAD_NAME | GSS_S_CALL_INACCESSIBLE_READ;
    }

  maj_stat = gss_create_empty_oid_set (minor_status, mech_types);
  if (GSS_ERROR (maj_stat))
    return maj_stat;

  maj_stat = _gss_inquire_mechs_for_name1 (minor_status,
					   input_name->type, mech_types);
  if (GSS_ERROR (maj_stat))
    {
      gss_release_oid_set (minor_status, mech_types);
      return maj_stat;
    }

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

/**
 * gss_export_name:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @input_name: (gss_name_t, read) The MN to be exported.
 * @exported_name: (gss_buffer_t, octet-string, modify) The canonical
 *   contiguous string form of @input_name.  Storage associated with
 *   this string must freed by the application after use with
 *   gss_release_buffer().
 *
 * To produce a canonical contiguous string representation of a
 * mechanism name (MN), suitable for direct comparison (e.g. with
 * memcmp) for use in authorization functions (e.g. matching entries
 * in an access-control list).  The @input_name parameter must specify
 * a valid MN (i.e. an internal name generated by
 * gss_accept_sec_context() or by gss_canonicalize_name()).
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_NAME_NOT_MN`: The provided internal name was not a mechanism
 * name.
 *
 * `GSS_S_BAD_NAME`: The provided internal name was ill-formed.
 *
 * `GSS_S_BAD_NAMETYPE`: The internal name was of a type not supported
 * by the GSS-API implementation.
 **/
OM_uint32
gss_export_name (OM_uint32 * minor_status,
		 const gss_name_t input_name, gss_buffer_t exported_name)
{
  OM_uint32 maj_stat;
  gss_OID_set mechs;
  _gss_mech_api_t mech;

  maj_stat = gss_inquire_mechs_for_name (minor_status, input_name, &mechs);
  if (GSS_ERROR (maj_stat))
    return maj_stat;

  if (mechs->count == 0)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_BAD_NAMETYPE;
    }

  /* We just select a random mechanism that support this name-type.
     I'm not sure how we can be more predicatable, given the
     definition of this function. */

  mech = _gss_find_mech (mechs->elements);
  if (mech == NULL)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_BAD_MECH;
    }

  return mech->export_name (minor_status, input_name, exported_name);
}

/**
 * gss_canonicalize_name:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @input_name: (gss_name_t, read) The name for which a canonical form
 *   is desired.
 * @mech_type: (Object ID, read) The authentication mechanism for
 *   which the canonical form of the name is desired.  The desired
 *   mechanism must be specified explicitly; no default is provided.
 * @output_name: (gss_name_t, modify) The resultant canonical name.
 *   Storage associated with this name must be freed by the
 *   application after use with a call to gss_release_name().
 *
 * Generate a canonical mechanism name (MN) from an arbitrary internal
 * name.  The mechanism name is the name that would be returned to a
 * context acceptor on successful authentication of a context where
 * the initiator used the input_name in a successful call to
 * gss_acquire_cred, specifying an OID set containing @mech_type as
 * its only member, followed by a call to gss_init_sec_context(),
 * specifying @mech_type as the authentication mechanism.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 **/
OM_uint32
gss_canonicalize_name (OM_uint32 * minor_status,
		       const gss_name_t input_name,
		       const gss_OID mech_type, gss_name_t * output_name)
{
  _gss_mech_api_t mech;

  mech = _gss_find_mech (mech_type);
  if (mech == NULL)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_BAD_MECH;
    }

  return mech->canonicalize_name (minor_status, input_name,
				  mech_type, output_name);
}

/**
 * gss_duplicate_name:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @src_name: (gss_name_t, read) Internal name to be duplicated.
 * @dest_name: (gss_name_t, modify) The resultant copy of @src_name.
 *   Storage associated with this name must be freed by the application
 *   after use with a call to gss_release_name().
 *
 * Create an exact duplicate of the existing internal name @src_name.
 * The new @dest_name will be independent of src_name (i.e. @src_name
 * and @dest_name must both be released, and the release of one shall
 * not affect the validity of the other).
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_BAD_NAME`: The src_name parameter was ill-formed.
 **/
OM_uint32
gss_duplicate_name (OM_uint32 * minor_status,
		    const gss_name_t src_name, gss_name_t * dest_name)
{
  if (src_name == GSS_C_NO_NAME)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_BAD_NAME;
    }

  if (!dest_name)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_FAILURE | GSS_S_CALL_INACCESSIBLE_WRITE;
    }

  *dest_name = malloc (sizeof (**dest_name));
  if (!*dest_name)
    {
      if (minor_status)
	*minor_status = ENOMEM;
      return GSS_S_FAILURE;
    }
  (*dest_name)->type = src_name->type;
  (*dest_name)->length = src_name->length;
  (*dest_name)->value = malloc (src_name->length + 1);
  if (!(*dest_name)->value)
    {
      free (*dest_name);
      if (minor_status)
	*minor_status = ENOMEM;
      return GSS_S_FAILURE;
    }
  memcpy ((*dest_name)->value, src_name->value, src_name->length);
  (*dest_name)->value[src_name->length] = '\0';

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}
