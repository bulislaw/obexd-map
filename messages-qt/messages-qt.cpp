#include <QCoreApplication>
#include <CommHistory/SingleEventModel>
#include <CommHistory/GroupModel>
#include <CommHistory/Event>

extern "C" {
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#include "messages-qt.h"
#include "messages.h"
#include "log.h"
#include "glib.h"
}

static QCoreApplication *app = NULL;

int messages_qt_init(void)
{
	static char *argv[] = {(char *)""};
	static int argc = 1;

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

static int messages_qt_get_event(CommHistory::SingleEventModel &model,
				CommHistory::Event &event, const char *handle)
{
	QString uri = QString("message:");

	uri += QString::number(QString(handle).toLong());

	model.setQueryMode(CommHistory::EventModel::SyncQuery);

	if (!model.getEventByUri(QUrl(uri))) {
		obex_debug("Cannot retrieve given event: %s", handle);
		return -ENOENT;
	}

	event = model.event(model.index(0, 0));

	return 0;
}

static int messages_qt_sync_event(CommHistory::SingleEventModel &model,
						CommHistory::Event &event)
{
	if (!model.modifyEvent(event)) {
		obex_debug("Cannot modify event!");
		return -EACCES;
	}

	CommHistory::GroupModel gm;

	/* Getting group model seems to be enough for libcommhistory to update
	 * groups (and thus UI) related to this event
	 */
	gm.setQueryMode(CommHistory::EventModel::SyncQuery);
	gm.getGroups(event.localUid(), event.remoteUid());

	return 0;
}

int messages_qt_set_deleted(const char *handle, gboolean deleted)
{
	CommHistory::SingleEventModel model;
	CommHistory::Event event;
	int ret;

	ret = messages_qt_get_event(model, event, handle);
	if (ret < 0)
		return ret;

	event.setDeleted(deleted);

	return messages_qt_sync_event(model, event);
}


int messages_qt_set_read(const char *handle, gboolean read)
{
	CommHistory::SingleEventModel model;
	CommHistory::Event event;
	int ret;

	ret = messages_qt_get_event(model, event, handle);
	if (ret < 0)
		return ret;

	event.setIsRead(read);

	return messages_qt_sync_event(model, event);
}
