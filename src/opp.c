/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Nokia Corporation
 *  Copyright (C) 2007-2008  Instituto Nokia de Tecnologia (INdT)
 *  Copyright (C) 2007-2008  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include <glib.h>

#include "obex.h"

void opp_connect(obex_t *obex, obex_object_t *obj)
{

}

void opp_put(obex_t *obex, obex_object_t *obj)
{

}

void opp_get(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os = NULL;

	os = OBEX_GetUserData(obex);
	if (os == NULL)
		return;

	if (os->name)
		goto fail;

	if (os->type == NULL)
		goto fail;

fail:
	/* FIXME: answer with something more informative */
	OBEX_ObjectSetRsp (obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
	return;
}

