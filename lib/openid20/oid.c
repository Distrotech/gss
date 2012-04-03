/* openid20/oid.c --- Definition of static OPENID20 OIDs.
 * Copyright (C) 2012 Simon Josefsson
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

/*
 * https://www.iana.org/assignments/smi-numbers
 * Prefix: iso.org.dod.internet.security.mechanisms (1.3.6.1.5.5)
 * 16 openID20 OpenID 2.0 mechanism [RFC-ietf-kitten-sasl-openid-08]
 */
gss_OID_desc GSS_OPENID20_static = {
  6, (void *) "\x2b\x06\x01\x05\x05\x10"
};

gss_OID GSS_OPENID20 = &GSS_OPENID20_static;
