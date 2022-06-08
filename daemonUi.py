import sys
from screen import *
from PyQt5.QtWidgets import *
from daemon import *

class MainWindow(QWidget):
    def __init__(self, parent=None):
        QWidget.__init__(self)
        self.parent = parent
        self.ui = Ui_LinuxAgentUI()
        self.ui.setupUi(self)
        self.myDaemon = MyDaemon()

        self.ui.startBtn.clicked.connect(self.startSlot)
        self.ui.stopBtn.clicked.connect(self.stopSlot)

    def startSlot(self):
        self.myDaemon.start()
    def stopSlot(self):
        self.myDaemon.stop()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())