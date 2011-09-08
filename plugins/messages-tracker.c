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

#include <errno.h>
#include <glib.h>
#include <string.h>

#include "messages.h"

struct message_folder {
	char *name;
	GSList *subfolders;
	char *query;
};

struct request {
	char *name;
	uint16_t max;
	uint16_t offset;
	void *user_data;
	union {
		messages_folder_listing_cb folder_list;
	} cb;
};

struct session {
	char *cwd;
	struct message_folder *folder;
	gboolean aborted;
	struct request *request;
};

static struct message_folder *folder_tree = NULL;

static struct message_folder *get_folder(const char *folder)
{
	GSList *folders = folder_tree->subfolders;
	struct message_folder *last = NULL;
	char **path;
	int i;

	if (g_strcmp0(folder, "/") == 0)
		return folder_tree;

	path = g_strsplit(folder, "/", 0);

	for (i = 1; path[i] != NULL; i++) {
		gboolean match_found = FALSE;
		GSList *l;

		for (l = folders; l != NULL; l = g_slist_next(l)) {
			struct message_folder *folder = l->data;

			if (g_strcmp0(folder->name, path[i]) == 0) {
				match_found = TRUE;
				last = l->data;
				folders = folder->subfolders;
				break;
			}
		}

		if (!match_found) {
			g_strfreev(path);
			return NULL;
		}
	}

	g_strfreev(path);

	return last;
}

static struct message_folder *create_folder(const char *name, const char *query)
{
	struct message_folder *folder = g_new0(struct message_folder, 1);

	folder->name = g_strdup(name);
	folder->query = g_strdup(query);

	return folder;
}

static void destroy_folder_tree(void *root)
{
	struct message_folder *folder = root;
	GSList *tmp, *next;

	if (folder == NULL)
		return;

	g_free(folder->name);
	g_free(folder->query);

	tmp = folder->subfolders;
	while (tmp != NULL) {
		next = g_slist_next(tmp);
		destroy_folder_tree(tmp->data);
		tmp = next;
	}

	g_slist_free(folder->subfolders);
	g_free(folder);
}

static void create_folder_tree()
{
	struct message_folder *parent, *child;

	folder_tree = create_folder("/", "FILTER (!BOUND(?msg))");

	parent = create_folder("telecom", "FILTER (!BOUND(?msg))");
	folder_tree->subfolders = g_slist_append(folder_tree->subfolders,
								parent);

	child = create_folder("msg", "FILTER (!BOUND(?msg))");
	parent->subfolders = g_slist_append(parent->subfolders, child);

	parent = child;

	child = create_folder("inbox", "?msg nmo:isSent \"false\" ; "
				"nmo:isDeleted \"false\" ; "
				"nmo:isDraft \"false\". ");
	parent->subfolders = g_slist_append(parent->subfolders, child);

	child = create_folder("sent", "?msg nmo:isDeleted \"false\" ; "
				"nmo:isSent \"true\" . ");
	parent->subfolders = g_slist_append(parent->subfolders, child);

	child = create_folder("deleted", " ");
	parent->subfolders = g_slist_append(parent->subfolders, child);
}

int messages_init(void)
{
	create_folder_tree();

	return 0;
}

void messages_exit(void)
{
	destroy_folder_tree(folder_tree);
}

int messages_connect(void **s)
{
	struct session *session = g_new0(struct session, 1);

	session->cwd = g_strdup("/");
	session->folder = folder_tree;

	*s = session;

	return 0;
}

void messages_disconnect(void *s)
{
	struct session *session = s;

	g_free(session->cwd);
	g_free(session);
}

int messages_set_notification_registration(void *session,
		void (*send_event)(void *session,
			const struct messages_event *event, void *user_data),
		void *user_data)
{
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

	if (newrel[0] != '/')
		newabs = g_build_filename("/", newrel, NULL);
	else
		newabs = g_strdup(newrel);

	session->folder = get_folder(newabs);
	if (session->folder == NULL) {
		g_free(newrel);
		g_free(newabs);

		return -ENOENT;
	}

	g_free(newrel);
	g_free(session->cwd);
	session->cwd = newabs;

	return 0;
}

static gboolean async_get_folder_listing(void *s)
{
	struct session *session = s;
	struct request *request = session->request;
	gboolean count = FALSE;
	int folder_count = 0;
	char *path = NULL;
	struct message_folder *folder;
	GSList *dir;

	if (session->aborted)
		goto aborted;

	if (request->name && strchr(request->name, '/') != NULL)
		goto done;

	path = g_build_filename(session->cwd, request->name, NULL);

	if (path == NULL || strlen(path) == 0)
		goto done;

	folder = get_folder(path);

	if (folder == NULL)
		goto done;

	if (request->max == 0) {
		request->max = 0xffff;
		request->offset = 0;
		count = TRUE;
	}

	for (dir = folder->subfolders; dir &&
				(folder_count - request->offset) < request->max;
				folder_count++, dir = g_slist_next(dir)) {
		struct message_folder *dir_data = dir->data;

		if (count == FALSE && request->offset <= folder_count)
			request->cb.folder_list(session, -EAGAIN, 1,
							dir_data->name,
							request->user_data);
	}

done:
	request->cb.folder_list(session, 0, folder_count, NULL,
							request->user_data);

	g_free(path);

aborted:
	g_free(request->name);
	g_free(request);

	return FALSE;
}

int messages_get_folder_listing(void *s, const char *name,
					uint16_t max, uint16_t offset,
					messages_folder_listing_cb callback,
					void *user_data)
{
	struct session *session = s;
	struct request *request = g_new0(struct request, 1);

	request->name = g_strdup(name);
	request->max = max;
	request->offset = offset;
	request->cb.folder_list = callback;
	request->user_data = user_data;

	session->aborted = FALSE;
	session->request = request;

	g_idle_add_full(G_PRIORITY_DEFAULT_IDLE, async_get_folder_listing,
						session, NULL);

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

	session->aborted = TRUE;
}
