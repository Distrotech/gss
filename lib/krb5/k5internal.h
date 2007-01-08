/* k5internal.h --- Internal header file for Kerberos 5 GSS.
 * Copyright (C) 2003, 2004, 2005, 2006, 2007  Simon Josefsson
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
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include "internal.h"
#include "krb5.h"
#include "protos.h"

#include <shishi.h>

typedef struct _gss_krb5_cred_struct
{
  Shishi *sh;
  gss_name_t peerptr;
  /* For user-to-user, we could have a Shishi_tkt here too. */
  Shishi_key *key;
} _gss_krb5_cred_desc, *_gss_krb5_cred_t;

typedef struct _gss_krb5_ctx_struct
{
  Shishi *sh;
  Shishi_ap *ap;
  Shishi_tkt *tkt;
  Shishi_key *key;
  gss_name_t peerptr;
  int acceptor;
  uint32_t acceptseqnr;
  uint32_t initseqnr;
  OM_uint32 flags;
  int reqdone;
  int repdone;
} _gss_krb5_ctx_desc, *_gss_krb5_ctx_t;

OM_uint32 gss_krb5_tktlifetime (Shishi_tkt * tkt);
