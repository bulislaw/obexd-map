#include <QCoreApplication>
#include <CommHistory/SingleEventModel>
#include <CommHistory/GroupModel>
#include <CommHistory/Event>

#include "messages-qt-log.h"
#include "messagepusher.h"
#include "messageupdater.h"

#include "messages-qt.h"

extern "C" {

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#include "messages.h"
#include "glib.h"

}

static QCoreApplication *app = NULL;

int messages_qt_init(void)
{
	static char *argv[] = {(char *)""};
	static int argc = 1;

	/* QCoreApplication is required when using libcommhistory */
	if (app == NULL)
		app = new QCoreApplication(argc, argv);

	return 0;
}

void messages_qt_exit(void)
{
	if (app != NULL) {
		delete app;
		app = NULL;
	}
}

void messages_qt_set_abort(void *p)
{
	MessageUpdater *messageUpdater = (MessageUpdater *)p;
	messageUpdater->abort();
}

int messages_qt_set_deleted(void **p, const char *handle, gboolean deleted,
			messages_qt_callback_t callback, void *user_data)
{
	MessageUpdater *messageUpdater;
	int ret;

	ret = MessageUpdater::setDeleted(&messageUpdater, handle, deleted,
							callback, user_data);
	if (ret < 0)
		return ret;

	if (p)
		*p = messageUpdater;

	return 0;
}


int messages_qt_set_read(void **p, const char *handle, gboolean read,
			messages_qt_callback_t callback, void *user_data)
{
	MessageUpdater *messageUpdater;
	int ret;

	ret = MessageUpdater::setIsRead(&messageUpdater, handle, read,
							callback, user_data);
	if (ret < 0)
		return ret;

	if (p)
		*p = messageUpdater;

	return 0;
}

void messages_qt_insert_message_abort(void *p)
{
	MessagePusher *messagePusher = (MessagePusher *)p;
	messagePusher->abort();
}

int messages_qt_insert_message(void **p, const char *remote, const char *body,
						const char *folder,
						messages_qt_callback_t callback,
						void *user_data)
{
	MessagePusher *messagePusher;
	int ret;

	ret = MessagePusher::push(&messagePusher, remote, body, folder,
							callback, user_data);

	if (ret < 0)
		return ret;

	if (p)
		*p = messagePusher;

	return 0;
}
