#include "messages-manager.h"
#include <CommHistory/GroupModel>

extern "C" {
#include <errno.h>
#include <glib.h>
#include "log.h"
}

#define TELEPATHY_ACCOUNT_PREFIX       QLatin1String("/org/freedesktop/Telepathy/Account/")
#define TELEPATHY_RING_ACCOUNT_POSTFIX QLatin1String("ring/tel/ring")

#define RING_ACCOUNT TELEPATHY_ACCOUNT_PREFIX + TELEPATHY_RING_ACCOUNT_POSTFIX

#ifdef DBG
#undef DBG
#endif
#define DBG(fmt, arg...) obex_debug("%s:%s() " fmt,  __FILE__, __FUNCTION__ , ## arg)

void MessagesManager::cleanup()
{
	if (eventModel)
		delete eventModel;

	if (groupModel)
		delete groupModel;

	if (event)
		delete event;

	if (group)
		delete group;

	this->deleteLater();
}

void MessagesManager::abort(int err)
{
	callback(err, user_data);
	cleanup();
}

void MessagesManager::eventsCommitted(const QList<CommHistory::Event> &,
								bool success)
{
	if (!success) {
		DBG("Unsuccessful event commit!");
		abort(-EIO);
		return;
	}

	DBG("Event id: %d", event->id());
	callback(event->id(), user_data);
}

void MessagesManager::groupsCommitted(const QList<int> &ids, bool success)
{
	DBG("");

	if (!ids.contains(group->id())) {
		DBG("No expected id.");
		return;
	}

	if (!success) {
		DBG("Unsuccessful group commit!");
		abort(-EIO);
		return;
	}

	event = new CommHistory::Event();

	event->setType(CommHistory::Event::SMSEvent);
	event->setDirection(direction);
	event->setGroupId(group->id());
	event->setLocalUid(RING_ACCOUNT);
	event->setIsRead(false);
	event->setRemoteUid(remoteUid);
	event->setStartTime(QDateTime::currentDateTime());
	event->setEndTime(QDateTime::currentDateTime());
	event->setFreeText(messageBody);

	eventModel = new CommHistory::EventModel(this);

	eventModel->setQueryMode(CommHistory::EventModel::AsyncQuery);
	QObject::connect(eventModel,
				SIGNAL(eventsCommitted(const QList<CommHistory::Event> &, bool)),
				this,
				SLOT(eventsCommitted(const QList<CommHistory::Event> &, bool)));

	eventModel->addEvent(*event, false);

	delete groupModel;
	groupModel = NULL;
}

void MessagesManager::modelReady(bool)
{
	DBG("");

	if (groupModel->rowCount() > 0) {
		group = new CommHistory::Group(groupModel->group(
						groupModel->index(0, 0)));

		DBG("Using existing group, id: %d", group->id());

		QList<int> ids;
		ids << group->id();
		groupsCommitted(ids, true);

		return;
	}

	DBG("Adding new group.");

	group = new CommHistory::Group();

	group->setLocalUid(RING_ACCOUNT);
	group->setRemoteUids(QStringList(remoteUid));

	QObject::connect(groupModel,
			SIGNAL(groupsCommitted(const QList<int> &, bool)),
			this,
			SLOT(groupsCommitted(const QList<int> &, bool)));

	DBG("addGroup: %s", groupModel->addGroup(*group) ? "true" : "false");
}

int MessagesManager::addMessage(const char *remote, const char *body,
						const char *folder,
						messages_qt_callback_t callback,
						void *user_data)
{
	QString destFolder(folder);

	if (destFolder == QString("/telecom/msg/inbox"))
		direction = CommHistory::Event::Inbound;
	else if (destFolder == QString("/telecom/msg/sent"))
		direction = CommHistory::Event::Outbound;
	else {
		DBG("No such folder: %s", folder);
		return -ENOENT;
	}

	this->callback = callback;
	this->user_data = user_data;
	remoteUid = QString(remote);
	messageBody = QString(body);

	groupModel = new CommHistory::GroupModel(this);

	groupModel->setQueryMode(CommHistory::EventModel::AsyncQuery);
	QObject::connect(groupModel, SIGNAL(modelReady(bool)),
						this, SLOT(modelReady(bool)));

	groupModel->getGroups(RING_ACCOUNT, QString(remote));

	return 0;
}
