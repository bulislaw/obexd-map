/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2010-2011  Nokia Corporation
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

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "messages.h"

static char *root_folder = NULL;

struct session {
	char *cwd;
	char *cwd_absolute;
	void *request;
	messages_event_cb cb;
	void *ev_data;
};

struct folder_listing_data {
	struct session *session;
	const char *name;
	messages_folder_listing_cb callback;
	void *user_data;
	uint16_t max;
	uint16_t offset;
};

int messages_init(void)
{
	char *tmp;

	if (root_folder)
		return 0;

	tmp = getenv("MAP_ROOT");
	if (tmp) {
		root_folder = g_strdup(tmp);
		return 0;
	}

	tmp = getenv("HOME");
	if (!tmp)
		return -ENOENT;

	root_folder = g_build_filename(tmp, "map-messages", NULL);

	return 0;
}

void messages_exit(void)
{
	g_free(root_folder);
	root_folder = NULL;
}

int messages_connect(void **s)
{
	struct session *session;

	session = g_new0(struct session, 1);
	session->cwd = g_strdup("");
	session->cwd_absolute = g_strdup(root_folder);

	*s = session;

	return 0;
}

void messages_disconnect(void *s)
{
	struct session *session = s;

	g_free(session->cwd);
	g_free(session->cwd_absolute);
	g_free(session);
}

static gboolean trigger(gpointer data)
{
	struct session *session = data;
	struct messages_event ev = { 0, };

	DBG("Triggeeerrrring");
	ev.type = MET_NEW_MESSAGE;
	ev.handle = "012345";
	ev.folder = "";
	ev.old_folder = "";
	ev.msg_type = "";

	session->cb(session, &ev, session->ev_data);

	return FALSE;
}

int messages_set_notification_registration(void *s,
		void (*send_event)(void *session,
			const struct messages_event *event, void *user_data),
		void *user_data)
{
	struct session *session = s;
	session->cb = send_event;
	session->ev_data = user_data;

	g_timeout_add(1000*20, trigger, session);

	return -EINVAL;
}

int messages_set_folder(void *s, const char *name, gboolean cdup)
{
	struct session *session = s;
	char *newrel = NULL;
	char *newabs;
	char *tmp;

	if (name && (strchr(name, '/') || strcmp(name, "..") == 0))
		return -EBADR;

	if (cdup) {
		if (session->cwd[0] == 0)
			return -ENOENT;

		newrel = g_path_get_dirname(session->cwd);

		/* We use empty string for indication of the root directory */
		if (newrel[0] == '.' && newrel[1] == 0)
			newrel[0] = 0;
	}

	tmp = newrel;
	if (!cdup && (!name || name[0] == 0))
		newrel = g_strdup("");
	else
		newrel = g_build_filename(newrel ? newrel : session->cwd, name,
				NULL);
	g_free(tmp);

	newabs = g_build_filename(root_folder, newrel, NULL);

	if (!g_file_test(newabs, G_FILE_TEST_IS_DIR)) {
		g_free(newrel);
		g_free(newabs);
		return -ENOENT;
	}

	g_free(session->cwd);
	session->cwd = newrel;

	g_free(session->cwd_absolute);
	session->cwd_absolute = newabs;

	return 0;
}

/* NOTE: Neither IrOBEX nor MAP specs says that folder listing needs to
 * be sorted (in IrOBEX examples it is not). However existing implementations
 * seem to follow the fig. 3-2 from MAP specification v1.0, and I've seen a
 * test suite requiring folder listing to be in that order.
 */
static gint folder_names_cmp(gconstpointer a, gconstpointer b,
						gpointer user_data)
{
	static const char *order[] = {
		"inbox", "outbox", "sent", "deleted", "draft", NULL
	};
	struct session *session = user_data;
	int ia, ib;

	if (g_strcmp0(session->cwd, "telecom/msg") == 0) {
		for (ia = 0; order[ia]; ++ia) {
			if (g_strcmp0(a, order[ia]) == 0)
				break;
		}
		for (ib = 0; order[ib]; ++ib) {
			if (g_strcmp0(b, order[ib]) == 0)
				break;
		}
		if (ia != ib)
			return ia - ib;
	}

	return g_strcmp0(a, b);
}

static int get_subdirs(struct folder_listing_data *fld, GSList **list,
								uint16_t *n)
{
	DIR *dp;
	struct dirent *ep;
	char *path;
	char *abs;
	char *name;

	*n = 0;

	path = g_build_filename(fld->session->cwd_absolute, fld->name, NULL);
	dp = opendir(path);

	if (dp == NULL) {
		int err = errno;

		DBG("opendir(): %d, %s", err, strerror(err));
		g_free(path);

		return -err;
	}

	while ((ep = readdir(dp)) != NULL) {
		if (ep->d_name[0] == '.' &&
				(ep->d_name[1] == 0 || ep->d_name[1] == '.'))
			continue;

		abs = g_build_filename(path, ep->d_name,
				NULL);

		if (!g_file_test(abs, G_FILE_TEST_IS_DIR)) {
			g_free(abs);
			continue;
		}

		g_free(abs);
		name = g_filename_to_utf8(ep->d_name, -1, NULL, NULL, NULL);

		if (name == NULL) {
			error("g_filename_to_utf8(): invalid filename");
			continue;
		}

		++*n;

		if (fld->max != 0)
			*list = g_slist_prepend(*list, name);
	}

	closedir(dp);
	g_free(path);

	*list = g_slist_sort_with_data(*list, folder_names_cmp, fld->session);

	return 0;
}

static gboolean get_folder_listing(void *d)
{
	struct folder_listing_data *fld = d;
	struct session *session = fld->session;
	uint16_t n;
	uint16_t o;
	GSList *list = NULL;
	GSList *cur;
	int err;

	err = get_subdirs(fld, &list, &n);

	if (err < 0) {
		fld->callback(session, err, 0, NULL, fld->user_data);
		return FALSE;
	}

	if (fld->max == 0) {
		fld->callback(session, 0, n, NULL, fld->user_data);
		return FALSE;
	}

	n = 0;
	o = 0;

	/* XXX: This isn't really documented for MAP. Need to take a look at
	 * other implementations.
	 */
	if (session->cwd[0] != 0 && fld->offset == 0) {
		++n;
		fld->callback(session, -EAGAIN, 0, "..", fld->user_data);
	} else {
		++o;
	}

	for (cur = list; o < fld->offset; ++o) {
		cur = cur->next;
		if (cur == NULL)
			break;
	}

	for (; cur != NULL && n < fld->max; cur = cur->next, ++n)
		fld->callback(session, -EAGAIN, 0, cur->data, fld->user_data);

	fld->callback(session, 0, 0, NULL, fld->user_data);

	g_slist_free_full(list, g_free);

	return FALSE;
}

int messages_get_folder_listing(void *s,
		const char *name,
		uint16_t max, uint16_t offset,
		messages_folder_listing_cb callback,
		void *user_data)
{
	struct session *session = s;
	struct folder_listing_data *fld;

	fld = g_new0(struct folder_listing_data, 1);
	fld->name = name;
	fld->max = max;
	fld->offset = offset;
	fld->callback = callback;
	fld->session = session;
	fld->user_data = user_data;
	session->request = fld;

	g_idle_add_full(G_PRIORITY_DEFAULT_IDLE, get_folder_listing,
				fld, g_free);

	return 0;
}

int messages_get_messages_listing(void *session,
		const char *name,
		uint16_t max, uint16_t offset,
		const struct messages_filter *filter,
		messages_get_messages_listing_cb callback,
		void *user_data)
{
	return -EINVAL;
}

int messages_get_message(void *session,
		const char *handle,
		unsigned long flags,
		messages_get_message_cb callback,
		void *user_data)
{
	return -EINVAL;
}

void messages_abort(void *s)
{
	struct session *session = s;

	if (session->request) {
		g_idle_remove_by_data(session->request);
		session->request = NULL;
	}
}
