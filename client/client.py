#!/usr/bin/env python
# -*- coding:utf-8 -*- 

import os
import sys
import json
import time
import signal
import socket
import select
import psutil
import pickle
import struct
from threading import *

from PyQt5 import uic
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from time import strftime,localtime

from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS

signal.signal(signal.SIGINT,signal.SIG_DFL)

marshall = pickle.dumps
unmarshall = pickle.loads

ROOT = os.path.abspath(os.path.dirname(__file__))
icon = os.path.join(ROOT,"telegram.svg")
MainWindowUI = os.path.join(ROOT,"pchat.ui")
serverdb = os.path.join(ROOT,"servers.json")
ChatRoomUI = os.path.join(ROOT,"chatroom.ui")
AddServerWindowUI = os.path.join(ROOT,"add_server.ui")

if os.path.isfile(serverdb):
	pass
else:
	data = {
	"server1" : {
		"host" : "127.0.0.1",
		"port" : 1100
		}
	}
	with open(serverdb,"w+") as file:
		json.dump(data,file,indent=4)

def timed():
	return(strftime("%H:%M:%S",localtime()))

def formatResult(color="black",text=""):
	return ('<font color="{0}">[{1}] * {2}</font>'.format(color,timed(),text
		)
	)

def kill_proc_tree(pid, including_parent=True):
	parent = psutil.Process(pid)
	if including_parent:
		parent.kill()

def send(channel, *args):
	buf = marshall(args)
	value = socket.htonl(len(buf))
	size = struct.pack("L",value)
	channel.send(size)
	channel.send(buf)

def receive(channel):

	size = struct.calcsize("L")
	size = channel.recv(size)
	try:
		size = socket.ntohl(struct.unpack("L", size)[0])
	except struct.error as e:
		return ''

	buf = ""

	while len(buf) < size:
		buf = channel.recv(size - len(buf))

	return unmarshall(buf)[0]

class AddServerWindow(QDialog):
	def __init__(self):
		QDialog.__init__(self)
		uic.loadUi(AddServerWindowUI,self)
		self.pushButton.clicked.connect(self.close)
		self.pushButton_2.clicked.connect(self.add_server)
		self.exec_()

	def add_server(self):
		server = self.lineEdit.text()
		port = int(self.lineEdit_2.text())

		with open(serverdb) as file:
			data = json.load(file)
		new_server = {"server" + str(len(data)+1) : {
					"host" : server,
					"port" : int(port)
				}
			}
		data.update(new_server)
		with open(serverdb,"w+") as file:
			json.dump(data,file,indent=4)

		window.listWidget.addItem("%s:%d" % (server,port))
		if window.listWidget.count() >= 2:
			window.pushButton_2.setEnabled(True)
		self.close()

class ChatRoom(QMainWindow):
	def __init__(self,parent=None,server="127.0.0.1"):
		super(ChatRoom,self).__init__(parent)
		uic.loadUi(ChatRoomUI,self)

		self.setWindowIcon(QIcon(QPixmap(icon)))

		self.pushButton.clicked.connect(self.send_msg)
		self.pushButton_2.clicked.connect(self.close)

		self.textEdit.setReadOnly(True)
		self.textEdit.insertHtml(formatResult
			(
				color="blue",text="Trying to connect server {}".format(server)
			)
		)
		self.actionHome.triggered.connect(self.backToHome)
		self.actionExit.triggered.connect(self.close)

	def backToHome(self):
		client_socket.shutdown(socket.SHUT_RDWR)
		client_socket.close()
		self.close()
		new_window = PchatWindow(self)
		new_window.show()

	def send_msg(self):
		msg = self.lineEdit.text()
		if msg != "":
			prompt = "[Me] > " + msg
			send(client_socket,msg)
			self.textEdit.append(formatResult(text=prompt))
			self.lineEdit.setText("")

class ChatThread(Thread):
	def __init__(self,window,host,name):
		Thread.__init__(self)
		self.window = window
		self.host = host
		self.name = name

		self.state = False

		self.client_privkey = RSA.generate(4096, os.urandom)
		self.client_pubkey = self.client_privkey.publickey()

		self.decryptor = self.client_privkey

	def updateRooms(self,rooms):
		if rooms == {}:
			root = QTreeWidgetItem(self.window.treeWidget,['No rooms avaiable'])

		else:
			self.window.treeWidget.clear()
			for n in rooms:
				root = QTreeWidgetItem(self.window.treeWidget)
				root.setText(0,n)
				root.setFlags(root.flags())
				for u in rooms[n]:
					child = QTreeWidgetItem(root)
					child.setText(0,u)
					child.setFlags(child.flags())
					
			
	def run(self):
		element = self.host.split(":")
		host = element[0]
		port = int(element[1])

		global client_socket
		client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		try:
			client_socket.connect((host,port))
		except:
			self.window.textEdit.append(formatResult(color="red",text="Failed connect to server"))
			self.window.pushButton.setEnabled(False)
		else:
			send(client_socket,'NAME: ' + self.name)
			send(client_socket,self.client_pubkey.exportKey())
			server_pubkey = receive(client_socket)

			self.encryptor = RSA.importKey(server_pubkey)

			self.window.textEdit.append(formatResult(color="green",text="Connected to server %s" % (self.host)))

			self.updateRooms(receive(client_socket))


		while not self.state:
			socket_list = [0,client_socket]
			try:
				read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])
			except : pass
			for sock in read_sockets:
				if sock == client_socket:
					try:
						data = receive(client_socket)
						if not data:
							self.window.textEdit.append(formatResult(color="red",text="Disconnected from server"))
							self.window.pushButton.setEnabled(False)

						else:
							try:
								if 'PLAIN:' in data: data = data.strip('PLAIN:').strip()
								data = self.decryptor.decrypt(data)
								msg = data.decode("UTF-8")
							except:
								if type(data) == dict:
									self.updateRooms(data)
									msg = ""
								else:
									msg = data

							if msg != "":
								self.window.textEdit.append(formatResult(color="#44dbe2",text=msg))
					except : pass

			time.sleep(.1)
		client_socket.close()

class PchatWindow(QMainWindow):
	def __init__(self,parent=None):
		super(QMainWindow,self).__init__(parent=parent)
		uic.loadUi(MainWindowUI,self)
		self.setWindowIcon(QIcon(QPixmap(icon)))
		self.dialogs = list()
		self.setupServers()
		if self.listWidget.count() < 2:
			self.pushButton_2.setEnabled(False)

		matching_item = self.listWidget.findItems("127.0.0.1:1100",Qt.MatchExactly)
		for item in matching_item:
			item.setSelected(True)

		self.pushButton.clicked.connect(self.add_server)
		self.pushButton_2.clicked.connect(self.remove_server)
		self.pushButton_3.clicked.connect(self.connect_to_server)
		self.pushButton_4.clicked.connect(self.close)

	def setupServers(self):
		with open(serverdb,"r") as file:
			data = json.load(file)
			for server in data:
				host = data[server]['host']
				port = data[server]['port']
				self.listWidget.addItem("%s:%d" % (host,int(port)))

	def add_server(self):
		dialog = AddServerWindow()
		dialog.setGeometry(100, 200, 100, 100)
		dialog.show()

	def remove_server(self):
		row = [x.row()+1 for x in self.listWidget.selectedIndexes()]
		pop_item = "server" + str(row[0])

		with open(serverdb) as file:
			data = json.load(file)
			data.pop(pop_item)
			
		with open(serverdb,"w+") as file:
			json.dump(data,file,indent=4)

		for x in row:
			self.listWidget.takeItem(x-1)

		if self.listWidget.count() < 2:
			self.pushButton_2.setEnabled(False)

	def connect_to_server(self):
		name = self.lineEdit.text()
		selected_item = self.listWidget.selectedItems()

		for item in selected_item:
			server = item.text()

		dialog = ChatRoom(server=server)
		chatThread = ChatThread(dialog,server,name)
		chatThread.start()
		self.dialogs.append(dialog)
		dialog.show()
		self.close()

if __name__ == '__main__':
	app = QApplication(sys.argv)
	window = PchatWindow()
	window.show()
	app.exec_()
	me = os.getpid()
	sys.exit(kill_proc_tree(me))
