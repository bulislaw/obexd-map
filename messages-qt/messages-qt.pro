TEMPLATE = lib
CONFIG += staticlib link_pkgconfig

TARGET = messages-qt
DEPENDPATH += . ../plugins ../src
INCLUDEPATH += . ../plugins ../src
PKGCONFIG += glib-2.0
PKGCONFIG += commhistory

# Input
SOURCES += messages-qt.cpp messages-qt.h

mc.target = maintainer-clean
mc.commands = 
mc.depends = 

QMAKE_EXTRA_TARGETS += mc
