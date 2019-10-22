import sys
import r2pipe
import pymongo
from PyQt5.QtWidgets import QMainWindow, QApplication, QWidget, QPushButton, QAction, QLabel, QFileDialog, QSplitter, QHBoxLayout, QFrame, QTabWidget, QVBoxLayout, QHBoxLayout
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSlot, Qt
from PyQt5 import QtCore

class App(QMainWindow):

    def __init__(self):
        super().__init__()
        self.title = 'Behavior Extraction Analysis Tool B.E.A.T!'
        self.left = 10
        self.top = 10
        self.width = 1500
        self.height = 800
        self.initUI()

    def initUI(self):

        mainMenu = self.menuBar()
        fileMenu = mainMenu.addMenu('File')

        OpenButton = QAction(QIcon('Open.png'), 'Open File', self)
        OpenButton.setShortcut('Ctrl+O')
        OpenButton.setStatusTip('Select a Binary for Network Analysis')
        OpenButton.triggered.connect(self.on_click_load)
        fileMenu.addAction(OpenButton)

        exitButton = QAction(QIcon('exit24.png'), 'Exit', self)
        exitButton.setShortcut('Ctrl+Q')
        exitButton.setStatusTip('Exit application')
        exitButton.triggered.connect(self.close)
        fileMenu.addAction(exitButton)

        leftFrame = QFrame(self)
        leftFrame.setFrameShape(QFrame.StyledPanel)

        fileTitle = QLabel(self)
        formatTitle = QLabel(self)
        archTitle = QLabel(self)
        endianTitle = QLabel(self)
        feedbackTitle = QLabel(self)

        fileTitle.setText("File:")
        formatTitle.setText("Format:")
        archTitle.setText("Arch:")
        endianTitle.setText("Endian:")
        feedbackTitle.setText("Feedback:")

        global file, format, arch, endian, feedback
        file   = QLabel(self)
        format = QLabel(self)
        arch   = QLabel(self)
        endian = QLabel(self)
        feedback = QLabel(self)

        leftLayout = QVBoxLayout()

        fileLayout = QHBoxLayout()
        fileLayout.addWidget(fileTitle)
        fileLayout.addWidget(file)
        fileLayout.addStretch()
        leftLayout.addLayout(fileLayout)

        formatLayout = QHBoxLayout()
        formatLayout.addWidget(formatTitle)
        formatLayout.addWidget(format)
        formatLayout.addStretch()
        leftLayout.addLayout(formatLayout)

        archLayout = QHBoxLayout()
        archLayout.addWidget(archTitle)
        archLayout.addWidget(arch)
        archLayout.addStretch()
        leftLayout.addLayout(archLayout)

        endianLayout = QHBoxLayout()
        endianLayout.addWidget(endianTitle)
        endianLayout.addWidget(endian)
        endianLayout.addStretch()
        leftLayout.addLayout(endianLayout)

        feedbackLayout = QHBoxLayout()
        feedbackLayout.addWidget(feedbackTitle)
        feedbackLayout.addWidget(feedback)
        feedbackLayout.addStretch()
        leftLayout.addLayout(feedbackLayout)

        leftLayout.addStretch()

        leftFrame.setLayout(leftLayout)

        rightFrame = QFrame(self)
        rightFrame.setFrameShape(QFrame.StyledPanel)

        rightLayout = QVBoxLayout()
        tabs = QTabWidget()
        tab1 = QWidget()
        tab2 = QWidget()
        tab3 = QWidget()

        # Add tabs
        tabs.addTab(tab1,"Network Plugin")
        tabs.addTab(tab2,"Plugin 2")
        tabs.addTab(tab3,"Plugin 3")

        staticButton = QPushButton('Static Analysis', tab1)
        staticButton.setToolTip('Statically analyze the binary.')
        staticButton.move(200,70)
        staticButton.clicked.connect(self.on_click_static)

        dynamicButton = QPushButton('Dynamic Analysis', tab1)
        dynamicButton.setToolTip('Dynamically analyze the binary.')
        dynamicButton.move(310,70)
        dynamicButton.clicked.connect(self.on_click_dynamic)

        tab1.layout = QVBoxLayout()
        tab1.layout.addWidget(staticButton)
        tab1.layout.addWidget(dynamicButton)

        rightLayout.addWidget(tabs)

        rightFrame.setLayout(rightLayout)

        leftFrame.setGeometry(QtCore.QRect(0, 0, 20, 800))

        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.addWidget(leftFrame)
        self.splitter.addWidget(rightFrame)

        self.setCentralWidget(self.splitter)

        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)
        self.show()

    @pyqtSlot()
    def on_click_load(self):
        self.openFileNameDialog()

    @pyqtSlot()
    def on_click_dynamic(self):

        curr_procs = rlocal.cmd("dpt")

        if curr_procs is "":
            print("about to doo")
            rlocal.cmd("doo 12345")
            global feedback
            feedback.setText("Process is currently running.")

        staticInfo = beatDb["staticInfo"]

        for recv in staticInfo.find({"opcode": "call sym.imp.recv", "binary_key": binId}):
            r2breakpoint = 'db ' + recv["address"] # Create r2 command to add breakpoint
            rlocal.cmd(r2breakpoint)

        while True:
            rlocal.cmd("dc") # Tell r2 to continue until it hits the breakpoint.

            rlocal.cmd("dso") # Tell r2 to execute over the recv call.

            messageAddr = rlocal.cmd("dr rsi") # Memory location to what recv received is in register rsi.
            print(messageAddr)
            lookInBuff = "pxj @" + messageAddr # create command to get contents of memory where recv received a message.
            print(lookInBuff)
            messageArr = rlocal.cmdj(lookInBuff) # get contents of memory where recv received a message.
            print(messageArr)
            byteStr = "" # variable that will hold hex values of message

            # Loop over byte array and remove each hex value (ie each letter sent in message)
            for i in range(len(messageArr)):

                # If found 0 byte...then is end of message in memory.
                if messageArr[i] == 0:
                    break
                # building byte string.
                byteStr = byteStr + str(hex(messageArr[i]))[2:] + " "
            print(byteStr)
            break

        feedback.setText("Process has quit running...found string in binary: " + bytearray.fromhex(byteStr).decode())
        rlocal.cmd("exit")
        staticInfo = beatDb["staticInfo"]
        insert_string = {"found_string" : bytearray.fromhex(byteStr).decode(), "binary_key" : binId}
        staticInfo.insert_one(insert_string)

    @pyqtSlot()
    def on_click_static(self):

        try:
            rlocal.cmd("aaa")
            all_recvs = rlocal.cmdj("axtj sym.imp.recv")
            all_sends = rlocal.cmdj("axtj sym.imp.send")

            staticInfo = beatDb["staticInfo"]

            for rec in all_recvs:
                insert_recv = {"address" : hex(rec["from"]), "opcode" : rec["opcode"], "calling_function" : rec["fcn_name"], "binary_key" : binId}
                staticInfo.insert_one(insert_recv)

            for send in all_sends:
                insert_send = {"address" : hex(send["from"]), "opcode" : send["opcode"], "calling_function" : send["fcn_name"], "binary_key" : binId}
                staticInfo.insert_one(insert_send)

            global feedback

            feedback.setText("Done with static analysis :0)")

        except NameError:
            print("Please select a binary to analyze.")
            #raise

    def openFileNameDialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(self,"QFileDialog.getOpenFileName()", "","All Files (*);;Python Files (*.py)", options=options)
        if fileName:

            global rlocal
            rlocal = r2pipe.open(fileName)
            r2BinInfo = rlocal.cmdj("ij")

            if r2BinInfo["core"]["format"] == 'any':
                print("Unsupported format")
                return

            global file, format, arch, endian, feedback
            file.setText(r2BinInfo["core"]["file"])
            format.setText(r2BinInfo["core"]["format"])
            arch.setText(r2BinInfo["bin"]["arch"])
            endian.setText(r2BinInfo["bin"]["endian"])

            global beatDb
            mongoClient = pymongo.MongoClient("mongodb://localhost:27017/")
            beatDb = mongoClient["BEAT"]
            binInfo = beatDb["binaryInfo"]

            global binId
            insertObj = binInfo.insert_one(r2BinInfo)
            binId = insertObj.inserted_id

            feedback.setText("Done Loading File :0)")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())
