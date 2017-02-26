#!/bin/bash

apt-get install build-essential autoconf libtool pkg-config python-opengl python-imaging python-pyrex python-pyside.qtopengl idle-python2.7 qt4-dev-tools qt4-designer libqtgui4 libqtcore4 libqt4-xml libqt4-test libqt4-script libqt4-network libqt4-dbus python-qt4 python-qt4-gl libgle3 python-dev
apt-get install python-pip
pip install -U setuptools
apt-get install libssl-dev libffi-dev
apt-get install python-numpy
apt-get install libpcap0.8 libpcap0.8-dev
apt-get install libjpeg-dev
apt-get install python-lxml
apt-get install libxml2-dev libxslt1-dev

pip install -r requirements.pip
