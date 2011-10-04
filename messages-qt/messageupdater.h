#include <QObject>
#include <CommHistory/SingleEventModel>

typedef void (*MessageUpdaterCallback)(int err, void *user_data);

class MessageUpdater : public QObject {
	Q_OBJECT

public:
	static int setIsRead(const char *handle, bool isRead,
					MessageUpdaterCallback callback = NULL,
					void *user_data = NULL);
	static int setDeleted(const char *handle, bool deleted,
					MessageUpdaterCallback callback = NULL,
					void *user_data = NULL);
	void abort();
private:
	MessageUpdaterCallback callback;
	void *user_data;

	CommHistory::SingleEventModel singleEventModel;

	void (MessageUpdater::*action)();
	bool value;
	bool aborted;

	MessageUpdater();
	void reportError(int err);
	int getEvent(const char *handle);
	void doSetIsRead();
	void doSetDeleted();

private slots:
	void eventsCommitted(const QList<CommHistory::Event> &ids,
								bool success);
	void modelReady(bool success);
};
