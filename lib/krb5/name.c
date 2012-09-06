/* krb5/name.c --- Implementation of Kerberos 5 GSS-API Name functions.
 * Copyright (C) 2003-2013 Simon Josefsson
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

/* Get specification. */
#include "k5internal.h"

OM_uint32
gss_krb5_canonicalize_name (OM_uint32 * minor_status,
			    const gss_name_t input_name,
			    const gss_OID mech_type, gss_name_t * output_name)
{
  OM_uint32 maj_stat;

  if (minor_status)
    *minor_status = 0;

  /* We consider (a zero terminated) GSS_KRB5_NT_PRINCIPAL_NAME the
     canonical mechanism name type.  Convert everything into it.  */

  if (gss_oid_equal (input_name->type, GSS_C_NT_EXPORT_NAME))
    {
      if (input_name->length > 15)
	{
	  *output_name = malloc (sizeof (**output_name));
	  if (!*output_name)
	    {
	      if (minor_status)
		*minor_status = ENOMEM;
	      return GSS_S_FAILURE;
	    }
	  (*output_name)->type = GSS_KRB5_NT_PRINCIPAL_NAME;
	  (*output_name)->length = input_name->length - 15;
	  (*output_name)->value = malloc ((*output_name)->length + 1);
	  if (!(*output_name)->value)
	    {
	      free (*output_name);
	      if (minor_status)
		*minor_status = ENOMEM;
	      return GSS_S_FAILURE;
	    }
	  memcpy ((*output_name)->value, input_name->value + 15,
		  (*output_name)->length);
	  (*output_name)->value[(*output_name)->length] = '\0';
	}
      else
	{
	  return GSS_S_BAD_NAME;
	}
    }
  else if (gss_oid_equal (input_name->type, GSS_C_NT_HOSTBASED_SERVICE))
    {
      char *p;

      /* We don't support service-names without hostname part because
         we can't compute a canonicalized name of the local host.
         Calling gethostname does not give a canonicalized name. */
      if (!memchr (input_name->value, '@', input_name->length))
	{
	  *minor_status = GSS_KRB5_S_G_BAD_SERVICE_NAME;
	  return GSS_S_COMPLETE;
	}

      /* We don't do DNS name canoncalization since that is
         insecure. */

      maj_stat = gss_duplicate_name (minor_status, input_name, output_name);
      if (GSS_ERROR (maj_stat))
	return maj_stat;

      (*output_name)->type = GSS_KRB5_NT_PRINCIPAL_NAME;

      p = memchr ((*output_name)->value, '@', (*output_name)->length);
      if (p)
	*p = '/';
    }
  else if (gss_oid_equal (input_name->type, GSS_KRB5_NT_PRINCIPAL_NAME))
    {
      maj_stat = gss_duplicate_name (minor_status, input_name, output_name);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
    }
  else
    {
      *output_name = GSS_C_NO_NAME;
      return GSS_S_BAD_NAMETYPE;
    }

  return GSS_S_COMPLETE;
}

#define TOK_LEN 2
#define MECH_OID_LEN_LEN 2
#define MECH_OID_ASN1_LEN_LEN 2
#define NAME_LEN_LEN 4

OM_uint32
gss_krb5_export_name (OM_uint32 * minor_status,
		      const gss_name_t input_name, gss_buffer_t exported_name)
{
  size_t msglen = input_name->length & 0xFFFFFFFF;
  size_t len = TOK_LEN +
    MECH_OID_LEN_LEN + MECH_OID_ASN1_LEN_LEN + GSS_KRB5->length +
    NAME_LEN_LEN + msglen;
  char *p;

  exported_name->length = len;
  p = exported_name->value = malloc (len);
  if (!p)
    {
      if (minor_status)
	*minor_status = ENOMEM;
      return GSS_S_FAILURE;
    }

  sprintf (p, "\x04\x01\x01\x0B\x06\x09%s", (char *) GSS_KRB5->elements);
  p[2] = '\0';
  p += 15;
  *p++ = (msglen >> 24) & 0xFF;
  *p++ = (msglen >> 16) & 0xFF;
  *p++ = (msglen >> 8) & 0xFF;
  *p++ = msglen & 0xFF;
  memcpy (p, input_name->value, msglen);

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}
