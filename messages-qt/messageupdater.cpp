#include "messages-qt-log.h"
#include "messageupdater.h"

extern "C" {
#include <errno.h>
}

MessageUpdater::MessageUpdater() :
		callback(NULL),
		aborted(false)
{
	QObject::connect(&singleEventModel,
			SIGNAL(modelReady(bool)),
			this,
			SLOT(modelReady(bool)));
	QObject::connect(&singleEventModel,
			SIGNAL(eventsCommitted(
					const QList<CommHistory::Event> &,
					bool)),
			this,
			SLOT(eventsCommitted(
					const QList<CommHistory::Event> &,
					bool)));
}

void MessageUpdater::abort()
{
	callback = NULL;
	aborted = true;
}

void MessageUpdater::reportError(int err)
{
	if (callback)
		callback(err, user_data);

	this->deleteLater();
}

void MessageUpdater::eventsCommitted(const QList<CommHistory::Event> &,
								bool success)
{
	DBG("%p", this);

	if (!success) {
		DBG("Unsuccessful event commit!");
		reportError(-EIO);

		return;
	}

	if (callback)
		callback(0, user_data);

	this->deleteLater();
}

void MessageUpdater::modelReady(bool success)
{
	DBG("%p", this);

	if (aborted) {
		DBG("Updating has been aborted.");
		this->deleteLater();

		return;
	}

	if (!success) {
		DBG("Event retrieval failed!");
		reportError(-EIO);

		return;
	}

	if (singleEventModel.rowCount() == 0) {
		DBG("Event not found!");
		reportError(-ENOENT);

		return;
	}

	(this->*(action))();
}

void MessageUpdater::doSetIsRead()
{
	CommHistory::Event event =
		singleEventModel.event(singleEventModel.index(0, 0));

	event.setIsRead(value);

	if (!singleEventModel.modifyEvent(event)) {
		DBG("SingleEventModel::modifyEvent() failed!");
		reportError(-EIO);
	}
}

void MessageUpdater::doSetDeleted()
{
	CommHistory::Event event =
		singleEventModel.event(singleEventModel.index(0, 0));

	event.setDeleted(value);

	if (!singleEventModel.modifyEvent(event)) {
		DBG("SingleEventModel::modifyEvent() failed!");
		reportError(-EIO);
	}
}

int MessageUpdater::getEvent(const char *handle)
{
	QString uri = QString("message:");

	uri += QString::number(QString(handle).toLong());

	if (!singleEventModel.getEventByUri(QUrl(uri))) {
		DBG("SingleEventModel::getEventsByUri() failed!");

		return -EIO;
	}

	return 0;
}

int MessageUpdater::setIsRead(const char *handle, bool isRead,
			MessageUpdaterCallback callback, void *user_data)
{
	MessageUpdater *messageUpdater = new MessageUpdater();
	DBG("this = %p, handle = %s, isRead = %d", messageUpdater, handle,
									isRead);

	messageUpdater->value = isRead;
	messageUpdater->callback = callback;
	messageUpdater->user_data = user_data;
	messageUpdater->action = &MessageUpdater::doSetIsRead;

	int ret = messageUpdater->getEvent(handle);
	if (ret < 0) {
		DBG("MessageUpdater::getEvent() failed!");
		delete messageUpdater;

		return ret;
	}

	return 0;
}

int MessageUpdater::setDeleted(const char *handle, bool deleted,
			MessageUpdaterCallback callback, void *user_data)
{
	MessageUpdater *messageUpdater = new MessageUpdater();
	DBG("this = %p, handle = %s, deleted = %d", messageUpdater,
							handle, deleted);

	messageUpdater->value = deleted;
	messageUpdater->callback = callback;
	messageUpdater->user_data = user_data;
	messageUpdater->action = &MessageUpdater::doSetDeleted;

	int ret = messageUpdater->getEvent(handle);
	if (ret < 0) {
		DBG("MessageUpdater::getEvent() failed!");
		delete messageUpdater;

		return ret;
	}

	return 0;
}
