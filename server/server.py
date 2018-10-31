#!/usr/bin/env python
# -*- coding:utf-8 -*- 

import os
import sys
import time
import json
import signal
import socket
import psutil
import select
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
serverui = os.path.join(ROOT,"server.ui")
icon = os.path.join(ROOT,"telegram.svg")

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

class ServerWindow(QMainWindow):
	def __init__(self,host="127.0.0.1",port=1100):
		super(ServerWindow,self).__init__()
		uic.loadUi(serverui,self)

		self.host = host
		self.port = port
		self.clients = 0
		self.STATE = True
		self.outputs = []
		self.rooms = {}
		self.clientmap = {}
		self.socket_list = []
		self.RECV_BUFFER = 4096

		self.setWindowIcon(QIcon(QPixmap(icon)))

		self.textEdit.setReadOnly(True)
		self.pushButton.clicked.connect(self.setupServer)
		self.pushButton_2.clicked.connect(self.close_server)

		self.tableWidget.resizeColumnsToContents()
		self.tableWidget.setAlternatingRowColors(True)
		self.tableWidget.setEditTriggers(QTableWidget.NoEditTriggers)
		self.tableWidget.setSelectionBehavior(QTableWidget.SelectRows)
		self.tableWidget.setSelectionMode(QTableWidget.SingleSelection)
		self.tableWidget.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)

	def get_just_name(self, client):
		return self.clientmap[client][1]

	def get_address(self, client):
		return self.clientmap[client][0]

	def send_encrypted(self, to_who, message, name):
		try:
			message = message.encode()
			encryptor = self.clientmap[to_who][2]
			msg = encryptor.encrypt(message,0)
			send(to_who, msg)

		except IOError:
			send(to_who, 'PLAIN: cannot find public key for: %s' % name)

	def updateTableWidget(self,update,*args):
		if update == True:
			currentRow = self.tableWidget.rowCount()
			self.tableWidget.insertRow(currentRow)
			for x in range(3):
				self.tableWidget.setItem(currentRow,x,QTableWidgetItem(str(args[x])))

		else:
			for row in range(self.tableWidget.rowCount()):
				name = self.tableWidget.item(row,0)
				addr = self.tableWidget.item(row,1)
				port = self.tableWidget.item(row,2)
				if (name.data(Qt.DisplayRole),addr.data(Qt.DisplayRole),int(port.data(Qt.DisplayRole))) == args:
					index = self.tableWidget.indexFromItem(name)

			self.tableWidget.removeRow(index.row())

	def setupServer(self):
		self.pushButton.setEnabled(False)
		self.textEdit.insertHtml(formatResult(color="blue",text="Setting up server !"))
		self.server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.server.bind((self.host, int(self.port)))

		self.textEdit.append(formatResult(color="blue",text="Generating RSA keys..."))

		self.server_privkey = RSA.generate(4096, os.urandom)
		self.server_pubkey = self.server_privkey.publickey()

		self.textEdit.append(formatResult(color="green",text="Server is ready"))

		self.server.listen(10)
		self.socket_list.append(self.server)
		self.textEdit.append(formatResult(color="green",text="Listening for clients..."))

		self.thread_event = Event()
		self.c_thread = Thread(target=self.handle_socket,args=(self.thread_event,))
		self.c_thread.start()

	def handle_socket(self,thread_event):
		while self.STATE and not thread_event.isSet():

			ready_input,ready_ouput,error = select.select(self.socket_list,self.outputs,[],3)

			for sock in ready_input:
				if sock == self.server:
					client,address = self.server.accept()
					self.socket_list.append(client)
					cname = receive(client).split("NAME: ")[1]
					pubkey = RSA.importKey(receive(client))
					send(client, self.server_pubkey.exportKey())

					self.textEdit.append(formatResult
						(
							color="green",text="Got a new connection %d from %s %s" % (client.fileno(),cname,address)
						)
					)

					self.clientmap[client] = (address, cname, pubkey)
					self.updateTableWidget(True,cname,address[0],address[1])
					
					send(client,self.rooms)

					msg = "Client (%d) %s entered to the room" % (client.fileno(),self.get_just_name(client))

					for o in self.outputs:
						try:
							self.send_encrypted(o, msg, self.get_just_name(o))

						except socket.error:
							if o in self.outputs:
								self.outputs.remove(o)
							if o in self.socket_list:
								self.socket_list.remove(o)

					self.outputs.append(client)

				else:
					try:
						data = receive(sock)
						if data:
							dataparts = data.split('#^[[')
							data = dataparts[0]
							text = "[{0}] > {1}".format(self.get_just_name(sock),data)
							for o in self.outputs:
								if o != sock:
									self.send_encrypted(o,text,self.get_just_name(sock))
						else:

							msg = "Client %d (%s) is offline" % (sock.fileno(),self.get_just_name(sock))

							self.socket_list.remove(sock)
							self.outputs.remove(sock)

							for o in self.outputs:
								self.send_encrypted(o,msg,self.get_just_name(o))

							if sock in self.socket_list:
								self.socket_list.remove(sock)
							self.textEdit.append(formatResult
								(
									color="red",text="Client %s %s disconnected" % (self.get_just_name(sock),self.get_address(sock))
								)
							)
							address = self.get_address(sock)
							self.updateTableWidget(False,self.get_just_name(sock),address[0],address[1])
					except:
						self.socket_list.remove(sock)
						self.outputs.remove(sock)
			time.sleep(0.1)
			QCoreApplication.processEvents()
		self.server.close()
		
	def close_server(self):
		try:
			self.thread_event.set()
			self.server.close()
		except : pass
		self.close()
 
if __name__ == '__main__':
	app = QApplication(sys.argv)
	window = ServerWindow()
	window.show()
	app.exec_()
	me = os.getpid()
	sys.exit(kill_proc_tree(me))