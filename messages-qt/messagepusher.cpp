#include <CommHistory/Group>
#include <CommHistory/Event>

#include "messages-qt-log.h"
#include "messagepusher.h"

extern "C" {
#include <errno.h>
}

#define TELEPATHY_ACCOUNT_PREFIX       QLatin1String("/org/freedesktop/Telepathy/Account/")
#define TELEPATHY_RING_ACCOUNT_POSTFIX QLatin1String("ring/tel/ring")

#define RING_ACCOUNT TELEPATHY_ACCOUNT_PREFIX + TELEPATHY_RING_ACCOUNT_POSTFIX


MessagePusher::MessagePusher() :
		callback(NULL),
		aborted(false)
{
	QObject::connect(&groupModel,
			SIGNAL(modelReady(bool)),
			this,
			SLOT(modelReady(bool)));
	QObject::connect(&groupModel,
			SIGNAL(groupsCommitted(const QList<int> &, bool)),
			this,
			SLOT(groupsCommitted(const QList<int> &, bool)));
	QObject::connect(&eventModel,
			SIGNAL(eventsCommitted(
					const QList<CommHistory::Event> &,
					bool)),
			this,
			SLOT(eventsCommitted(
					const QList<CommHistory::Event> &,
					bool)));
}

void MessagePusher::abort()
{
	DBG("%p", this);

	callback = NULL;
	aborted = true;
}

void MessagePusher::reportError(int err)
{
	if (callback)
		callback(err, user_data);

	this->deleteLater();
}

void MessagePusher::eventsCommitted(const QList<CommHistory::Event> &,
								bool success)
{
	DBG("%p", this);

	if (!success) {
		DBG("Unsuccessful event commit!");
		reportError(-EIO);

		return;
	}

	if (callback)
		callback(eventId, user_data);

	this->deleteLater();
}

void MessagePusher::groupsCommitted(const QList<int> &, bool success)
{
	DBG("%p", this);

	if (aborted)
		DBG("Abort has been requested, but at this point "
							"I'd rather proceed.");

	if (!success) {
		DBG("Unsuccessful group commit!");
		reportError(-EIO);

		return;
	}

	CommHistory::Event event;

	event.setType(CommHistory::Event::SMSEvent);
	event.setDirection(direction);
	event.setGroupId(groupId);
	event.setLocalUid(RING_ACCOUNT);
	event.setRemoteUid(remoteUid);
	event.setIsRead(false);			/* TODO */
	event.setStartTime(QDateTime::currentDateTime());
	event.setEndTime(QDateTime::currentDateTime());
	event.setFreeText(messageBody);
	event.setStatus(CommHistory::Event::DeliveredStatus);

	if (!eventModel.addEvent(event)) {
		DBG("EventModel::addEvent failed!");
		reportError(-EIO);
	}

	eventId = event.id();
}

void MessagePusher::modelReady(bool success)
{
	DBG("%p", this);

	if (aborted) {
		DBG("Pushing has been aborted.");
		this->deleteLater();

		return;
	}

	if (!success) {
		DBG("Groups retrieval failed!");
		reportError(-EIO);

		return;
	}

	if (groupModel.rowCount() > 0) {
		CommHistory::Group group(groupModel.group(
						groupModel.index(0, 0)));

		groupId = group.id();

		DBG("Using existing group, id: %d", groupId);

		QList<int> ids;
		ids << groupId;
		groupsCommitted(ids, true);

		return;
	}


	CommHistory::Group group;

	group.setLocalUid(RING_ACCOUNT);
	group.setRemoteUids(QStringList(remoteUid));

	if (!groupModel.addGroup(group)) {
		DBG("GroupModel::addGroup() failed!");
		reportError(-EIO);
	}

	groupId = group.id();
	DBG("Added new group, id: %d", groupId);
}

int MessagePusher::push(MessagePusher **p, const char *remote,
					const char *body,
					const char *folder,
					MessagePusherCallback callback,
					void *user_data)
{
	DBG("remote = \"%s\", body = \"%s\", folder = \"%s\"",
							remote, body, folder);

	CommHistory::Event::EventDirection direction;
	QString destFolder(folder);

	if (destFolder == QString("/telecom/msg/inbox"))
		direction = CommHistory::Event::Inbound;
	else if (destFolder == QString("/telecom/msg/sent"))
		direction = CommHistory::Event::Outbound;
	else {
		DBG("Tried to push to unsupported folder: %s", folder);
		return -ENOENT;
	}

	MessagePusher *messagePusher = new MessagePusher();
	DBG("this = %p", messagePusher);

	messagePusher->callback = callback;
	messagePusher->user_data = user_data;

	messagePusher->remoteUid = QString(remote);
	messagePusher->messageBody = QString::fromUtf8(body);
	messagePusher->direction = direction;

	if (!messagePusher->groupModel.getGroups(RING_ACCOUNT, QString(remote)))
	{
		DBG("GroupModel::getGroups() failed!");
		delete messagePusher;

		return -EIO;
	}

	if (p)
		*p = messagePusher;

	return 0;
}
