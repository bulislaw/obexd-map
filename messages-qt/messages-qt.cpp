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

struct updater_call {
	int ret;
	gboolean done;
};

static void updater_callback(int err, void *user_data)
{
	struct updater_call *uc = (struct updater_call *)user_data;

	uc->ret = err;
	uc->done = TRUE;
}

int messages_qt_set_deleted(const char *handle, gboolean deleted)
{
	struct updater_call uc;
	int ret;

	ret = MessageUpdater::setDeleted(handle, deleted, updater_callback,
									&uc);
	if (ret < 0)
		return ret;

	uc.done = FALSE;
	/* XXX: This actually makes whole glib main loop to iterate, things may
	 * go wrong. Needs reimplementing API to do SetMessageStatus
	 * asynchronously. */
	while (!uc.done)
		app->processEvents();

	return uc.ret;
}


int messages_qt_set_read(const char *handle, gboolean read)
{
	struct updater_call uc;
	int ret;

	ret = MessageUpdater::setIsRead(handle, read, updater_callback, &uc);
	if (ret < 0)
		return ret;

	uc.done = FALSE;
	while (!uc.done)
		app->processEvents();

	return uc.ret;
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
