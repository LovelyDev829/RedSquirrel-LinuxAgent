# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'screen.ui'
#
# Created by: PyQt5 UI code generator 5.15.6
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_LinuxAgentUI(object):
    def setupUi(self, LinuxAgentUI):
        LinuxAgentUI.setObjectName("LinuxAgentUI")
        LinuxAgentUI.resize(313, 102)
        LinuxAgentUI.setMinimumSize(QtCore.QSize(313, 102))
        LinuxAgentUI.setMaximumSize(QtCore.QSize(313, 102))
        self.title = QtWidgets.QLabel(LinuxAgentUI)
        self.title.setGeometry(QtCore.QRect(10, 10, 141, 16))
        self.title.setObjectName("title")
        self.installedTime = QtWidgets.QLabel(LinuxAgentUI)
        self.installedTime.setGeometry(QtCore.QRect(160, 10, 141, 16))
        self.installedTime.setObjectName("installedTime")
        self.startBtn = QtWidgets.QPushButton(LinuxAgentUI)
        self.startBtn.setEnabled(True)
        self.startBtn.setGeometry(QtCore.QRect(10, 40, 141, 25))
        self.startBtn.setMinimumSize(QtCore.QSize(141, 25))
        self.startBtn.setMaximumSize(QtCore.QSize(141, 25))
        self.startBtn.setObjectName("startBtn")
        self.stopBtn = QtWidgets.QPushButton(LinuxAgentUI)
        self.stopBtn.setGeometry(QtCore.QRect(160, 40, 141, 25))
        self.stopBtn.setObjectName("stopBtn")
        self.uninstallBtn = QtWidgets.QPushButton(LinuxAgentUI)
        self.uninstallBtn.setGeometry(QtCore.QRect(10, 70, 291, 25))
        self.uninstallBtn.setObjectName("uninstallBtn")

        self.retranslateUi(LinuxAgentUI)
        QtCore.QMetaObject.connectSlotsByName(LinuxAgentUI)

    def retranslateUi(self, LinuxAgentUI):
        _translate = QtCore.QCoreApplication.translate
        LinuxAgentUI.setWindowTitle(_translate("LinuxAgentUI", "Linux Agent"))
        self.title.setText(_translate("LinuxAgentUI", "Installed Date Time : "))
        self.installedTime.setText(_translate("LinuxAgentUI", "5/4/2022 5:04:25 AM"))
        self.startBtn.setText(_translate("LinuxAgentUI", "Start Service"))
        self.stopBtn.setText(_translate("LinuxAgentUI", "Stop Service"))
        self.uninstallBtn.setText(_translate("LinuxAgentUI", "Uninstall Service"))
