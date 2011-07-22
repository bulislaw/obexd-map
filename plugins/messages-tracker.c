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
#include <gdbus.h>

#include "messages.h"
#include "log.h"

#define TRACKER_SERVICE "org.freedesktop.Tracker1"
#define TRACKER_RESOURCES_PATH "/org/freedesktop/Tracker1/Resources"
#define TRACKER_RESOURCES_INTERFACE "org.freedesktop.Tracker1.Resources"

#define QUERY_RESPONSE_SIZE 13
#define MESSAGE_HANDLE_SIZE 16
#define MESSAGE_HANDLE_PREFIX_LEN 8

/*
 * As stated in MAP errata bmessage-body-content-length-property should be
 * length of: "BEGIN:MSG<CRLF>" + <message content> + "END:MSG<CRLF>"
 */
#define BMESSAGE_BASE_LEN (9 + 2 + 2 + 7 + 2)

#define MESSAGE_HANDLE 0
#define MESSAGE_SUBJECT 1
#define MESSAGE_SDATE 2
#define MESSAGE_RDATE 3
#define MESSAGE_FROM_N 4
#define MESSAGE_FROM_LASTN 5
#define MESSAGE_FROM_PHONE 6
#define MESSAGE_TO_N 7
#define MESSAGE_TO_LASTN 8
#define MESSAGE_TO_PHONE 9
#define MESSAGE_READ 10
#define MESSAGE_SENT 11
#define MESSAGE_CONTENT 12

#define LIST_MESSAGES_QUERY						\
"SELECT "								\
"?msg "									\
"nmo:messageSubject(?msg) "						\
"nmo:sentDate(?msg) "							\
"nmo:receivedDate(?msg) "						\
"nco:nameGiven(?from_c) "						\
"nco:nameFamily(?from_c) "						\
"nco:phoneNumber(?from_phone) "						\
"nco:nameGiven(?to_c) "							\
"nco:nameFamily(?to_c) "						\
"nco:phoneNumber(?to_phone) "						\
"nmo:isRead(?msg) "							\
"nmo:isSent(?msg) "							\
"nie:plainTextContent(?msg) "						\
"WHERE { "								\
	"?msg a nmo:SMSMessage . "					\
	"%s "								\
	"%s "								\
	"OPTIONAL { "							\
		"?msg nmo:from ?from . "				\
		"?from nco:hasPhoneNumber ?from_phone . "		\
		"?from_phone maemo:localPhoneNumber ?from_lphone . "	\
		"OPTIONAL { "						\
			"?from_c a nco:PersonContact . "		\
			"OPTIONAL {?from_c nco:hasPhoneNumber ?phone .} "\
			"OPTIONAL {?from_c nco:hasAffiliation ?af . "	\
				"?af nco:hasPhoneNumber ?phone . } "	\
			"?phone maemo:localPhoneNumber ?from_lphone . "	\
		"} "							\
	"} "								\
	"OPTIONAL { "							\
		"?msg nmo:to ?to . "					\
		"?to nco:hasPhoneNumber ?to_phone . "			\
		"?to_phone maemo:localPhoneNumber ?to_lphone . "	\
		"OPTIONAL { "						\
			"?to_c a nco:PersonContact . "			\
			"OPTIONAL {?to_c nco:hasPhoneNumber ?phone1 .} "\
			"OPTIONAL {?to_c nco:hasAffiliation ?af . "	\
				"?af nco:hasPhoneNumber ?phone1 . } "	\
			"?phone1 maemo:localPhoneNumber ?to_lphone "	\
		"} "							\
	"} "								\
"} ORDER BY DESC(nmo:sentDate(?msg)) "

typedef void (*reply_list_foreach_cb)(const char **reply, void *user_data);

struct message_folder {
	char *name;
	GSList *subfolders;
	char *query;
};

struct session {
	char *cwd;
	struct message_folder *folder;
	char *name;
	uint16_t max;
	uint16_t offset;
	uint16_t size;
	void *user_data;
	gboolean count;
	gboolean new_message;
	reply_list_foreach_cb generate_response;
	union {
		messages_folder_listing_cb folder_list;
		messages_get_messages_listing_cb messages_list;
	} cb;
};

static struct message_folder *folder_tree = NULL;
static DBusConnection *session_connection = NULL;

static gboolean trace_call(void *data)
{
	DBusPendingCall *call = data;

	if (dbus_pending_call_get_completed(call) == TRUE) {
		dbus_pending_call_unref(call);

		return FALSE;
	}

	return TRUE;
}

static void new_call(DBusPendingCall *call)
{
	g_timeout_add_seconds(5, trace_call, call);
}

static void free_msg_data(struct messages_message *msg)
{
	g_free(msg->handle);
	g_free(msg->subject);
	g_free(msg->datetime);
	g_free(msg->sender_name);
	g_free(msg->sender_addressing);
	g_free(msg->replyto_addressing);
	g_free(msg->recipient_name);
	g_free(msg->recipient_addressing);
	g_free(msg->type);
	g_free(msg->reception_status);
	g_free(msg->size);
	g_free(msg->attachment_size);

	g_free(msg);
}

static char **string_array_from_iter(DBusMessageIter iter, int array_len)
{
	DBusMessageIter sub;
	char **result;
	int i;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		return NULL;

	result = g_new0(char *, array_len + 1);

	dbus_message_iter_recurse(&iter, &sub);

	i = 0;
	while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
		char *arg;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING) {
			g_free(result);

			return NULL;
		}

		dbus_message_iter_get_basic(&sub, &arg);

		result[i++] = arg;

		dbus_message_iter_next(&sub);
	}

	return result;
}

static void query_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct session *session = user_data;
	DBusMessageIter iter, element;
	DBusError derr;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("Replied with an error: %s, %s", derr.name, derr.message);
		dbus_error_free(&derr);

		goto done;
	}

	dbus_message_iter_init(reply, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
		error("SparqlQuery reply is not an array");

		goto done;
	}

	dbus_message_iter_recurse(&iter, &element);

	while (dbus_message_iter_get_arg_type(&element) != DBUS_TYPE_INVALID) {
		char **node;

		if (dbus_message_iter_get_arg_type(&element)
							!= DBUS_TYPE_ARRAY) {
			error("Element is not an array\n");

			goto done;
		}

		node = string_array_from_iter(element, QUERY_RESPONSE_SIZE);

		session->generate_response((const char **) node, session);

		g_free(node);

		dbus_message_iter_next(&element);
	}

done:
	session->generate_response(NULL, session);

	dbus_message_unref(reply);
}

static DBusPendingCall *query_tracker(char *query, void *user_data, int *err)
{
	DBusPendingCall *call;
	DBusMessage *msg;

	msg = dbus_message_new_method_call(TRACKER_SERVICE,
						TRACKER_RESOURCES_PATH,
						TRACKER_RESOURCES_INTERFACE,
						"SparqlQuery");
	if (msg == NULL) {
		if (err)
			*err = -EPERM;

		return NULL;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &query,
							 DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(session_connection, msg, &call,
								-1) == FALSE) {
		error("Could not send dbus message");

		dbus_message_unref(msg);
		if (err)
			*err = -EPERM;

		return NULL;
	}

	dbus_pending_call_set_notify(call, query_reply, user_data, NULL);

	dbus_message_unref(msg);

	return call;
}

static char *folder2query(const struct message_folder *folder,
							const char *query)
{
	return g_strdup_printf(query, folder->query, "");
}

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

	child = create_folder("deleted", "?msg nmo:isDeleted \"true\" . ");
	parent->subfolders = g_slist_append(parent->subfolders, child);
}

static char *fill_handle(const char *handle)
{
	int fill_size = MESSAGE_HANDLE_SIZE - strlen(handle);
	char *fill = g_strnfill(fill_size, '0');
	char *ret = g_strdup_printf("%s%s", fill, handle);

	g_free(fill);

	return ret;
}

static char *strip_handle(const char *handle)
{
	const char *ptr_new = handle;

	while (*ptr_new++ == '0') ;

	return g_strdup(ptr_new - 1);
}

static char *merge_names(const char *name, const char *lastname)
{
	char *tmp = NULL;

	if (strlen(lastname) != 0) {
		if (strlen(name) == 0)
			tmp = g_strdup(lastname);
		else
			tmp = g_strdup_printf("%s %s", name, lastname);

	} else if (strlen(name) != 0)
		tmp = g_strdup(name);
	else
		tmp = g_strdup("");

	return tmp;
}

static struct messages_message *pull_message_data(const char **reply)
{
	struct messages_message *data = NULL;

	if (reply == NULL)
		return NULL;

	data = g_new0(struct messages_message, 1);

	data->handle = fill_handle(reply[MESSAGE_HANDLE] +
					MESSAGE_HANDLE_PREFIX_LEN);

	if (strlen(reply[MESSAGE_SUBJECT]) != 0)
		data->subject = g_strdup(reply[MESSAGE_SUBJECT]);
	else
		data->subject = g_strdup(reply[MESSAGE_CONTENT]);

	data->mask |= PMASK_SUBJECT;

	if (strlen(reply[MESSAGE_SDATE]) != 0) {
		char **date = g_strsplit_set(reply[MESSAGE_SDATE], ":-Z", -1);

		data->datetime = g_strjoinv(NULL, date);
		g_strfreev(date);
	} else if (strlen(reply[MESSAGE_RDATE]) != 0) {
		char **date = g_strsplit_set(reply[MESSAGE_RDATE], ":-Z", -1);

		data->datetime = g_strjoinv(NULL, date);
		g_strfreev(date);
	} else {
		data->datetime = g_strdup("");
	}

	data->mask |= PMASK_DATETIME;

	data->sender_name = merge_names(reply[MESSAGE_FROM_N],
					reply[MESSAGE_FROM_LASTN]);
	data->mask |= PMASK_SENDER_NAME;

	data->sender_addressing = g_strdup(reply[MESSAGE_FROM_PHONE]);
	data->mask |= PMASK_SENDER_ADDRESSING;

	data->recipient_name = merge_names(reply[MESSAGE_TO_N],
						reply[MESSAGE_TO_LASTN]);
	data->mask |= PMASK_RECIPIENT_NAME;

	data->recipient_addressing = g_strdup(reply[MESSAGE_TO_PHONE]);
	data->mask |= PMASK_RECIPIENT_ADDRESSING;

	data->type = g_strdup("SMS_GSM");
	data->mask |= PMASK_TYPE;

	data->size = g_strdup_printf("%d", strlen(reply[MESSAGE_CONTENT]) +
					BMESSAGE_BASE_LEN);
	data->mask |= PMASK_SIZE;

	data->text = TRUE;
	data->mask |= PMASK_TEXT;

	data->reception_status = g_strdup("complete");
	data->mask |= PMASK_RECEPTION_STATUS;

	data->attachment_size = g_strdup("0");
	data->mask |= PMASK_ATTACHMENT_SIZE;

	data->priority = FALSE;
	data->mask |= PMASK_PRIORITY;

	data->read = g_strcmp0(reply[MESSAGE_READ], "true") == 0 ? TRUE : FALSE;
	data->mask |= PMASK_READ;

	data->sent = g_strcmp0(reply[MESSAGE_SENT], "true") == 0 ? TRUE : FALSE;
	data->mask |= PMASK_SENT;

	data->protect = FALSE;
	data->mask |= PMASK_PROTECTED;

	return data;
}

static void get_messages_listing_resp(const char **reply, void *user_data)
{
	struct session *session = user_data;
	struct messages_message *msg_data;

	DBG("reply %p", reply);

	if (reply == NULL)
		goto done;

	msg_data = pull_message_data(reply);
	msg_data->handle = strip_handle(msg_data->handle);

	session->size++;

	if (!msg_data->read)
			session->new_message = TRUE;

	if (session->count == TRUE) {
		free_msg_data(msg_data);
		return;
	}

	if (session->size > session->offset)
		session->cb.messages_list(session, -EAGAIN, 1,
						session->new_message, msg_data,
						session->user_data);

	free_msg_data(msg_data);
	return;

 done:
	session->cb.messages_list(session, 0, session->size,
						session->new_message, NULL,
						session->user_data);
}

int messages_init(void)
{
	session_connection = dbus_bus_get(DBUS_BUS_SESSION, NULL);
	if (session_connection == NULL) {
		error("Unable to connect to the session bus.");

		return -1;
	}

	create_folder_tree();

	return 0;
}

void messages_exit(void)
{
	destroy_folder_tree(folder_tree);

	dbus_connection_unref(session_connection);
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

	newabs = g_build_filename("/", newrel, NULL);

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

static gboolean async_get_folder_listing(void *s) {
	struct session *session = s;
	gboolean count = FALSE;
	int folder_count = 0;
	char *path = NULL;
	struct message_folder *folder;
	GSList *dir;

	if (session->name && strchr(session->name, '/') != NULL)
		goto done;

	path = g_build_filename(session->cwd, session->name, NULL);

	if (path == NULL || strlen(path) == 0)
		goto done;

	folder = get_folder(path);

	if (folder == NULL)
		goto done;

	if (session->max == 0) {
		session->max = 0xffff;
		session->offset = 0;
		count = TRUE;
	}

	for (dir = folder->subfolders; dir &&
				(folder_count - session->offset) < session->max;
				folder_count++, dir = g_slist_next(dir)) {
		struct message_folder *dir_data = dir->data;

		if (count == FALSE && session->offset <= folder_count)
			session->cb.folder_list(session, -EAGAIN, 1,
					dir_data->name, session->user_data);
	}

 done:
	session->cb.folder_list(session, 0, folder_count, NULL,
							session->user_data);

	g_free(path);
	g_free(session->name);

	return FALSE;
}

int messages_get_folder_listing(void *s, const char *name,
		uint16_t max, uint16_t offset,
		void (*callback)(void *session, int err, uint16_t size,
			const char *name, void *user_data),
		void *user_data)
{
	struct session *session = s;
	session->name = g_strdup(name);
	session->max = max;
	session->offset = offset;
	session->cb.folder_list = callback;
	session->user_data = user_data;

	g_idle_add_full(G_PRIORITY_DEFAULT_IDLE, async_get_folder_listing,
						session, NULL);

	return 0;
}

int messages_get_messages_listing(void *s, const char *name,
				uint16_t max, uint16_t offset,
				const struct messages_filter *filter,
				messages_get_messages_listing_cb callback,
				void *user_data)
{
	struct session *session = s;
	char *path, *query;
	struct message_folder *folder = NULL;
	DBusPendingCall *call;
	int err = 0;

	if (name == NULL || strlen(name) == 0) {
		path = g_strdup(session->cwd);

		folder = session->folder;
		if (folder == NULL)
			folder = get_folder(path);
	} else {
		if (strchr(name, '/') != NULL)
			return -EBADR;

		path = g_build_filename(session->cwd, name, NULL);
		folder = get_folder(path);
	}

	g_free(path);

	if (folder == NULL)
		return -EBADR;

	query = folder2query(folder, LIST_MESSAGES_QUERY);
	if (query == NULL)
		return -ENOENT;

	session->generate_response = get_messages_listing_resp;
	session->cb.messages_list = callback;
	session->offset = offset;
	session->max = max;
	session->user_data = user_data;
	session->new_message = FALSE;
	session->count = FALSE;
	session->size = 0;

	if (max == 0) {
		session->max = 0xffff;
		session->offset = 0;
		session->count = TRUE;
	}

	call = query_tracker(query, session, &err);
	if (err == 0)
		new_call(call);

	g_free(query);

	return err;
}

int messages_get_message(void *session,
		const char *handle,
		unsigned long flags,
		void (*callback)(void *session, int err, gboolean fmore,
			const char *chunk, void *user_data),
		void *user_data)
{
	return -EINVAL;
}

int messages_set_message_status(void *session, const char *handle,
		uint8_t indicator, uint8_t value)
{
	return -EINVAL;
}

void messages_abort(void *session)
{
}
