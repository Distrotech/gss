/* asn1.c	Wrapper around ASN.1 code for GSS.
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
#include "gss_asn1_tab.c"

#define WARN(msg) fprintf(stderr, "gss: libtasn1 error: %s", msg)

int
_gss_wrap_token (char *oid, char *in, size_t inlen, char **out, size_t *outlen)
{
  ASN1_TYPE definitions = NULL;
  ASN1_TYPE token = NULL;
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  char *der;
  int len;
  int rc;

  rc = asn1_array2tree (gss_asn1_tab, &definitions, errorDescription);
  if (rc != ASN1_SUCCESS)
    {
      WARN (errorDescription);
      WARN (libtasn1_strerror(rc));
      return 0;
    }

  rc = asn1_create_element (definitions, "GSS-API.InitialContextToken",
			    &token);
  if (rc != ASN1_SUCCESS)
    {
      WARN (libtasn1_strerror (rc));
      return 0;
    }

  rc = asn1_write_value (token, "thisMech",
			 oid, 1);
  if (rc != ASN1_SUCCESS)
    {
      WARN (libtasn1_strerror (rc));
      return 0;
    }

  rc = asn1_write_value (token, "innerContextToken",
			 in, inlen);
  if (rc != ASN1_SUCCESS)
    {
      WARN (libtasn1_strerror (rc));
      return 0;
    }

  len = 0;
  rc = asn1_der_coding (token, "", NULL, &len,
			errorDescription);
  if (rc != ASN1_MEM_ERROR)
    {
      WARN (libtasn1_strerror (rc));
      return 0;
    }

  der = malloc(len);
  if (!der)
    return 0;

  rc = asn1_der_coding (token, "", der, &len,
			errorDescription);
  if (rc != ASN1_SUCCESS)
    {
      WARN(libtasn1_strerror (rc));
      free(der);
      return 0;
    }

#if 0
  /* This doesn't appear to work (warn/crashes).
     XXX Memory leak as a result? */

  rc = asn1_delete_structure(token);
  if (rc != ASN1_SUCCESS)
    WARN(libtasn1_strerror (rc));

  rc = asn1_delete_structure(definitions);
  if (rc != ASN1_SUCCESS)
    WARN(libtasn1_strerror (rc));
#endif

  *out = der;
  *outlen = len;

  return 1;
}
