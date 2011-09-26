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

#include "log.h"
#include "messages.h"
#include "bmsg.h"

#define TRACKER_SERVICE "org.freedesktop.Tracker1"
#define TRACKER_RESOURCES_PATH "/org/freedesktop/Tracker1/Resources"
#define TRACKER_RESOURCES_INTERFACE "org.freedesktop.Tracker1.Resources"

#define QUERY_RESPONSE_SIZE 21
#define MESSAGE_HANDLE_SIZE 16
#define MESSAGE_HANDLE_PREFIX_LEN 8

#define SMS_DEFAULT_CHARSET "UTF-8"

#define STATUS_NOT_SET 0xFF

#define MESSAGES_FILTER_BY_HANDLE "FILTER (xsd:string(?msg) = \"message:%s\" ) ."

#define MESSAGE_HANDLE 0
#define MESSAGE_SUBJECT 1
#define MESSAGE_SDATE 2
#define MESSAGE_RDATE 3
#define MESSAGE_FROM_FN 4
#define MESSAGE_FROM_GIVEN 5
#define MESSAGE_FROM_FAMILY 6
#define MESSAGE_FROM_ADDITIONAL 7
#define MESSAGE_FROM_PREFIX 8
#define MESSAGE_FROM_SUFFIX 9
#define MESSAGE_FROM_PHONE 10
#define MESSAGE_TO_FN 11
#define MESSAGE_TO_GIVEN 12
#define MESSAGE_TO_FAMILY 13
#define MESSAGE_TO_ADDITIONAL 14
#define MESSAGE_TO_PREFIX 15
#define MESSAGE_TO_SUFFIX 16
#define MESSAGE_TO_PHONE 17
#define MESSAGE_READ 18
#define MESSAGE_SENT 19
#define MESSAGE_CONTENT 20

#define LIST_MESSAGES_QUERY						\
"SELECT "								\
"?msg "									\
"nmo:messageSubject(?msg) "						\
"nmo:sentDate(?msg) "							\
"nmo:receivedDate(?msg) "						\
"nco:fullname(?from_c) "						\
"nco:nameGiven(?from_c) "						\
"nco:nameFamily(?from_c) "						\
"nco:nameAdditional(?from_c) "						\
"nco:nameHonorificPrefix(?from_c) "					\
"nco:nameHonorificSuffix(?from_c) "					\
"nco:phoneNumber(?from_phone) "						\
"nco:fullname(?to_c) "							\
"nco:nameGiven(?to_c) "							\
"nco:nameFamily(?to_c) "						\
"nco:nameAdditional(?to_c) "						\
"nco:nameHonorificPrefix(?to_c) "					\
"nco:nameHonorificSuffix(?to_c) "					\
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

struct request {
	char *name;
	uint16_t max;
	uint16_t offset;
	uint16_t size;
	void *user_data;
	gboolean count;
	gboolean new_message;
	reply_list_foreach_cb generate_response;
	struct messages_filter *filter;
	unsigned long flags;
	gboolean deleted;
	union {
		messages_folder_listing_cb folder_list;
		messages_get_messages_listing_cb messages_list;
		messages_get_message_cb message;
	} cb;
};

struct message_status {
	uint8_t read;
	uint8_t deleted;
};

struct session {
	char *cwd;
	struct message_folder *folder;
	gboolean aborted;
	void *event_user_data;
	messages_event_cb event_cb;
	struct request *request;
	GHashTable *msg_stat;
};

static struct message_folder *folder_tree = NULL;
static DBusConnection *session_connection = NULL;
static GSList *mns_srv;
static gint event_watch_id;

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

static void free_event_data(struct messages_event *event)
{
	g_free(event->handle);
	g_free(event->folder);
	g_free(event->old_folder);
	g_free(event->msg_type);

	g_free(event);
}

static struct messages_filter *copy_messages_filter(
					const struct messages_filter *orig)
{
	struct messages_filter *filter = g_new0(struct messages_filter, 1);
	filter->parameter_mask = orig->parameter_mask;
	filter->type = orig->type;
	filter->period_begin = g_strdup(orig->period_begin);
	filter->period_end = g_strdup(orig->period_end);
	filter->read_status = orig->read_status;
	filter->recipient = g_strdup(orig->recipient);
	filter->originator = g_strdup(orig->originator);
	filter->priority = orig->priority;

	return filter;
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

		if (node != NULL)
			session->request->generate_response((const char **) node,
								session);

		g_free(node);

		dbus_message_iter_next(&element);
	}

done:
	session->request->generate_response(NULL, session);

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

	child = create_folder("deleted", " ");
	parent->subfolders = g_slist_append(parent->subfolders, child);
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

static char *message2folder(const struct messages_message *data)
{
	if (data->sent == TRUE)
		return g_strdup("telecom/msg/sent");

	if (data->sent == FALSE)
		return g_strdup("telecom/msg/inbox");

	return NULL;
}

static char *path2query(const char *folder, const char *query,
							const char *user_rule)
{
	if (g_str_has_suffix(folder, "telecom/msg/inbox") == TRUE)
		return g_strdup_printf(query, "?msg nmo:isSent \"false\" ; "
					"nmo:isDeleted \"false\" ; "
					"nmo:isDraft \"false\". ", user_rule);

	if (g_str_has_suffix(folder, "telecom/msg/sent") == TRUE)
		return g_strdup_printf(query, "?msg nmo:isSent \"true\" ; "
				"nmo:isDeleted \"false\" . ", user_rule);

	if (g_str_has_suffix(folder, "telecom/msg/deleted") == TRUE)
		return g_strdup_printf(query, "?msg nmo:isDeleted \"true\" . ",
					user_rule);

	if (g_str_has_suffix(folder, "telecom/msg") == TRUE)
		return g_strdup_printf(query, "", user_rule);

	return NULL;
}

static gboolean filter_message(struct messages_message *message,
						struct messages_filter *filter)
{
	if (filter->type != 0) {
		if (g_strcmp0(message->type, "SMS_GSM") == 0 &&
				(filter->type & 0x01))
			return FALSE;

		if (g_strcmp0(message->type, "SMS_CDMA") == 0 &&
				(filter->type & 0x02))
			return FALSE;

		if (g_strcmp0(message->type, "SMS_EMAIL") == 0 &&
				(filter->type & 0x04))
			return FALSE;

		if (g_strcmp0(message->type, "SMS_MMS") == 0 &&
				(filter->type & 0x08))
			return FALSE;
	}

	if (filter->read_status != 0) {
		if (filter->read_status == 0x01 && message->read != FALSE)
			return FALSE;

		if (filter->read_status == 0x02 && message->read != TRUE)
			return FALSE;
	}

	if (filter->priority != 0) {
		if (filter->priority == 0x01 && message->priority == FALSE)
			return FALSE;

		if (filter->priority == 0x02 && message->priority == TRUE)
			return FALSE;
	}

	if (filter->period_begin != NULL &&
			g_strcmp0(filter->period_begin, message->datetime) > 0)
		return FALSE;

	if (filter->period_end != NULL &&
			g_strcmp0(filter->period_end, message->datetime) < 0)
		return FALSE;

	if (filter->originator != NULL) {
		char *orig = g_strdup_printf("*%s*", filter->originator);

		if (g_pattern_match_simple(orig,
					message->sender_addressing) == FALSE &&
				g_pattern_match_simple(orig,
					message->sender_name) == FALSE) {
			g_free(orig);
			return FALSE;
		}
		g_free(orig);
	}

	if (filter->recipient != NULL) {
		char *recip = g_strdup_printf("*%s*", filter->recipient);

		if (g_pattern_match_simple(recip,
					message->recipient_addressing) == FALSE
				&& g_pattern_match_simple(recip,
					message->recipient_name) == FALSE) {
			g_free(recip);
			return FALSE;
		}

		g_free(recip);
	}

	return TRUE;
}

static struct phonebook_contact *pull_message_contact(const char **reply)
{
	struct phonebook_contact *contact;
	struct phonebook_field *number;

	contact = g_new0(struct phonebook_contact, 1);

	contact->fullname = g_strdup(reply[MESSAGE_FROM_FN]);
	contact->given = g_strdup(reply[MESSAGE_FROM_GIVEN]);
	contact->family = g_strdup(reply[MESSAGE_FROM_FAMILY]);
	contact->additional = g_strdup(reply[MESSAGE_FROM_ADDITIONAL]);
	contact->prefix = g_strdup(reply[MESSAGE_FROM_PREFIX]);
	contact->suffix = g_strdup(reply[MESSAGE_FROM_SUFFIX]);

	number = g_new0(struct phonebook_field, 1);
	number->text = g_strdup(reply[MESSAGE_FROM_PHONE]);
	number->type = TEL_TYPE_NONE;
	contact->numbers = g_slist_append(contact->numbers, number);

	return contact;
}

static struct messages_message *pull_message_data(const char **reply)
{
	struct messages_message *data = g_new0(struct messages_message, 1);

	data->handle = g_strdup(reply[MESSAGE_HANDLE] +
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

	data->sender_name = merge_names(reply[MESSAGE_FROM_GIVEN],
					reply[MESSAGE_FROM_FAMILY]);
	data->mask |= PMASK_SENDER_NAME;

	data->sender_addressing = g_strdup(reply[MESSAGE_FROM_PHONE]);
	data->mask |= PMASK_SENDER_ADDRESSING;

	data->recipient_name = merge_names(reply[MESSAGE_TO_GIVEN],
						reply[MESSAGE_TO_FAMILY]);
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
	struct request *request = session->request;
	struct messages_message *msg_data;
	struct message_status *stat;

	DBG("reply %p", reply);

	if (reply == NULL)
		goto end;

	if (session->aborted)
		goto aborted;

	msg_data = pull_message_data(reply);

	stat = g_hash_table_lookup(session->msg_stat, msg_data->handle);
	if (stat == NULL) {
		stat = g_new0(struct message_status, 1);
		stat->read = msg_data->read;

		g_hash_table_insert(session->msg_stat,
					g_strdup(msg_data->handle), stat);
	} else if (stat != NULL && stat->read != STATUS_NOT_SET)
		msg_data->read = stat->read;

	if (request->deleted && (stat == NULL || !stat->deleted))
		goto done;

	if (!request->deleted && (stat != NULL && stat->deleted))
		goto done;

	request->size++;

	if (!msg_data->read)
		request->new_message = TRUE;

	if (request->count == TRUE)
		goto done;

	if (request->size > request->offset && filter_message(msg_data,
							request->filter))
		request->cb.messages_list(session, -EAGAIN, 1,
						request->new_message, msg_data,
						request->user_data);

done:
	free_msg_data(msg_data);
	return;

end:
	request->cb.messages_list(session, 0, request->size,
						request->new_message, NULL,
						request->user_data);
aborted:
	g_free(request->filter->period_begin);
	g_free(request->filter->period_end);
	g_free(request->filter->originator);
	g_free(request->filter->recipient);
	g_free(request->filter);

	g_free(request);
}

static void get_message_resp(const char **reply, void *s)
{
	struct session *session = s;
	struct request *request = session->request;
	struct messages_message *msg_data;
	struct bmsg *bmsg;
	char *final_bmsg, *status, *folder, *handle;
	struct phonebook_contact *contact;
	struct message_status *stat;
	int err;

	DBG("reply %p", reply);

	if (reply == NULL)
		goto done;

	if (session->aborted)
		goto aborted;

	msg_data = pull_message_data(reply);
	handle = fill_handle(msg_data->handle);
	g_free(msg_data->handle);
	msg_data->handle = handle;

	contact = pull_message_contact(reply);

	stat = g_hash_table_lookup(session->msg_stat, msg_data->handle);
	if (stat != NULL && stat->read != STATUS_NOT_SET)
		msg_data->read = stat->read;

	status = msg_data->read ? "READ" : "UNREAD";

	folder = message2folder(msg_data);

	bmsg = g_new0(struct bmsg, 1);
	bmsg_init(bmsg, BMSG_VERSION_1_0, status, BMSG_SMS, folder);

	bmsg_add_originator(bmsg, contact);
	bmsg_add_envelope(bmsg);
	bmsg_add_content(bmsg, -1, NULL, SMS_DEFAULT_CHARSET, NULL,
						reply[MESSAGE_CONTENT]);

	final_bmsg = bmsg_text(bmsg);

	request->cb.message(session, 0, FALSE, final_bmsg, request->user_data);

	bmsg_destroy(bmsg);
	g_free(folder);
	g_free(final_bmsg);
	free_msg_data(msg_data);
	phonebook_contact_free(contact);

	request->count++;

	return;

done:
	if (request->count == 0)
		err = -ENOENT;
	else
		err = 0;

	request->cb.message(session, err, FALSE, NULL, request->user_data);

aborted:
	g_free(request->name);
	g_free(request);
}

static void notify_new_sms(const char *handle)
{
	struct messages_event *data;
	GSList *next;

	data = g_new0(struct messages_event, 1);
	data->folder = g_strdup("telecom/msg/inbox");
	data->type = MET_NEW_MESSAGE;
	data->msg_type = g_strdup("SMS_GSM");
	data->old_folder = g_strdup("");
	data->handle = fill_handle(handle);

	next = mns_srv;
	for (next = mns_srv; next != NULL; next = g_slist_next(next)) {
		struct session *session = next->data;

		session->event_cb(session, data, session->event_user_data);
	}

	free_event_data(data);
}

static gboolean handle_new_sms(DBusConnection * connection, DBusMessage * msg,
							void *user_data)
{
	DBusMessageIter arg, inner_arg, struct_arg;
	unsigned ihandle = 0;
	char *handle;

	DBG("");

	if (!dbus_message_iter_init(msg, &arg))
		return TRUE;

	if (dbus_message_iter_get_arg_type(&arg) != DBUS_TYPE_ARRAY)
		return TRUE;

	dbus_message_iter_recurse(&arg, &inner_arg);

	if (dbus_message_iter_get_arg_type(&inner_arg) != DBUS_TYPE_STRUCT)
		return TRUE;

	dbus_message_iter_recurse(&inner_arg, &struct_arg);

	if (dbus_message_iter_get_arg_type(&struct_arg) != DBUS_TYPE_INT32)
		return TRUE;

	dbus_message_iter_get_basic(&struct_arg, &ihandle);

	handle = g_strdup_printf("%d", ihandle);

	DBG("new message: %s", handle);

	notify_new_sms(handle);

	g_free(handle);

	return TRUE;
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

	session->msg_stat = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);

	*s = session;

	return 0;
}

void messages_disconnect(void *s)
{
	struct session *session = s;

	if (session->msg_stat)
		g_hash_table_destroy(session->msg_stat);
	g_free(session->cwd);
	g_free(session);
}

int messages_set_notification_registration(void *s, messages_event_cb cb,
							void *user_data)
{
	struct session *session = s;

	if (cb != NULL) {
		if (g_slist_length(mns_srv) == 0)
			event_watch_id = g_dbus_add_signal_watch(
							session_connection,
							NULL, NULL,
							"com.nokia.commhistory",
							"eventsAdded",
							handle_new_sms,
							NULL, NULL);
		if (event_watch_id == 0)
			return -EIO;

		session->event_user_data = user_data;
		session->event_cb = cb;

		mns_srv = g_slist_prepend(mns_srv, session);
	} else {
		mns_srv = g_slist_remove(mns_srv, session);

		if (g_slist_length(mns_srv) == 0)
			g_dbus_remove_watch(session_connection, event_watch_id);
	}

	return 0;
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

static gboolean async_get_folder_listing(void *s) {
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

int messages_get_messages_listing(void *s, const char *name,
				uint16_t max, uint16_t offset,
				const struct messages_filter *filter,
				messages_get_messages_listing_cb callback,
				void *user_data)
{
	struct session *session = s;
	struct request *request;
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

	request = g_new0(struct request, 1);

	request->filter = copy_messages_filter(filter);
	request->generate_response = get_messages_listing_resp;
	request->cb.messages_list = callback;
	request->offset = offset;
	request->max = max;
	request->user_data = user_data;
	request->deleted = g_strcmp0(folder->name, "deleted") ? FALSE : TRUE;

	session->aborted = FALSE;
	session->request = request;

	if (max == 0) {
		request->max = 0xffff;
		request->offset = 0;
		request->count = TRUE;
	}

	call = query_tracker(query, session, &err);
	if (err == 0)
		new_call(call);

	g_free(query);

	return err;
}

int messages_get_message(void *s, const char *h, unsigned long flags,
				messages_get_message_cb cb, void *user_data)
{
	struct session *session = s;
	struct request *request;
	DBusPendingCall *call;
	int err = 0;
	char *handle = strip_handle(h);
	char *query_handle = g_strdup_printf(MESSAGES_FILTER_BY_HANDLE, handle);
	char *query = path2query("telecom/msg", LIST_MESSAGES_QUERY,
								 query_handle);

	if (query == NULL) {
		err = -ENOENT;

		goto failed;
	}

	if (flags & MESSAGES_FRACTION || flags & MESSAGES_NEXT) {
		err = -EBADR;

		goto failed;
	}

	request = g_new0(struct request, 1);

	request->name = g_strdup(handle);
	request->flags = flags;
	request->cb.message = cb;
	request->generate_response = get_message_resp;
	request->user_data = user_data;

	session->aborted = FALSE;
	session->request = request;

	call = query_tracker(query, session, &err);
	if (err == 0)
		new_call(call);

failed:
	g_free(query_handle);
	g_free(handle);
	g_free(query);

	return err;
}

int messages_set_message_status(void *s, const char *handle, uint8_t indicator,
								uint8_t value)
{
	struct session *session = s;
	struct message_status *stat = NULL;

	stat = g_hash_table_lookup(session->msg_stat, handle);
	if (stat == NULL) {
		stat = g_new0(struct message_status, 1);
		stat->read = STATUS_NOT_SET;

		g_hash_table_insert(session->msg_stat, g_strdup(handle), stat);
	}

	switch (indicator) {
		case 0x0:
			stat->read = value;
			break;
		case 0x1:
			stat->deleted = value;
			break;
		default:
			return -EBADR;
	}

	return 0;
}

int messages_push_message(void *session, struct bmsg_bmsg *bmsg,
				const char *name, unsigned long flags,
				messages_push_message_cb cb, void *user_data)
{
	return -EINVAL;
}

int messages_push_message_body(void *session, const char *body, size_t len)
{
	return -EINVAL;
}

void messages_abort(void *s)
{
	struct session *session = s;

	session->aborted = TRUE;
}
