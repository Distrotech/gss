/* krb5/name.c --- Implementation of Kerberos 5 GSS-API Name functions.
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

/* Get specification. */
#include "k5internal.h"

/* Get xgethostname. */
#include "xgethostname.h"

OM_uint32
gss_krb5_canonicalize_name (OM_uint32 * minor_status,
			    const gss_name_t input_name,
			    const gss_OID mech_type, gss_name_t * output_name)
{
  OM_uint32 maj_stat;

  if (minor_status)
    *minor_status = 0;

  if (gss_oid_equal (input_name->type, GSS_C_NT_HOSTBASED_SERVICE))
    {
      char *p;

      /* XXX we don't do DNS name canoncalization, it may be insecure */

      maj_stat = gss_duplicate_name (minor_status, input_name, output_name);
      if (GSS_ERROR (maj_stat))
	return maj_stat;
      (*output_name)->type = GSS_KRB5_NT_PRINCIPAL_NAME;

      if ((p = memchr ((*output_name)->value, '@', (*output_name)->length)))
	{
	  *p = '/';
	}
      else
	{
	  char *hostname = xgethostname ();
	  size_t hostlen = strlen (hostname);
	  size_t oldlen = (*output_name)->length;
	  size_t newlen = oldlen + 1 + hostlen;
	  (*output_name)->value = xrealloc ((*output_name)->value, newlen);
	  (*output_name)->value[oldlen] = '/';
	  memcpy ((*output_name)->value + 1 + oldlen, hostname, hostlen);
	  (*output_name)->length = newlen;
	}
    }
  else
    {
      *output_name = GSS_C_NO_NAME;
      return GSS_S_BAD_NAMETYPE;
    }

  return GSS_S_COMPLETE;
}
