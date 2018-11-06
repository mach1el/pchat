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
signal.signal(signal.SIGPIPE,signal.SIG_DFL)

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

def send(channel, *msg):
	buf = marshall(msg)
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

class UserMap:
	def __init__(self,sock,name):
		self.sock = sock
		self.name = name

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
		self.room_map = {}
		self.client_map = {}
		self.socket_list = []
		self.commands = ["-create","-join","-leave"]
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
		return self.client_map[client][1]

	def get_address(self, client):
		return self.client_map[client][0]

	def send_encrypted(self, to_who, message, name):
		try:
			message = message.encode()
			encryptor = self.client_map[to_who][2]
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

	def join_room(self,sock,data):
		room_name = data.split()[1]
		user_name = self.get_just_name(sock)
		host = self.get_address(sock)

		if room_name in self.rooms.keys():
			self.rooms[room_name].append(user_name)
			self.room_map[room_name].append(UserMap(sock,user_name))

			self.textEdit.append(formatResult
					(
						color="#f99a34",text="User %s@%s:%d joined the #%s room" % (user_name,host[0],host[1],room_name)
					)
			)

			for user in self.room_map[room_name]:
				if user.sock != sock: send(user.sock,"User %s joined to the room" % user_name)

				else: send(user.sock,"Welcome,to the #%s room" % room_name)

			for o in self.client_map.keys(): send(o,self.rooms)

		else: send(sock,"No such that room !!!")

	def leave_room(self,sock,user_name,room):
		host = self.get_address(sock)
		self.rooms[room].remove(user_name)

		for user in self.room_map[room]:
			if user.name == user_name and user.sock == sock:
				self.room_map[room].remove(user)

		self.textEdit.append(formatResult
			(
				color="#f99a34",text="User %s@%s:%d left #%s room" % (user_name,host[0],host[1],room)
			)
		)

		for o in self.client_map.keys(): send(o,self.rooms)

	def create_room(self,sock,data):
		room_name = data.split()[1]

		if room_name in self.rooms.keys(): send(sock,"That room is avaiable,you can join in.")

		else:
			user = self.get_just_name(sock)
			host = self.get_address(sock)

			self.rooms[room_name] = [user]
			self.room_map[room_name] = [UserMap(sock,user)]

			for o in self.client_map.keys():
				send(o,self.rooms)
				if o != sock:
					send(o,"New room #%s is avaiable now." % room_name)

			self.textEdit.append(formatResult
					(
						color="#f99a34",text="User %s@%s:%d created #%s room" % (user,host[0],host[1],room_name)
					)
			)

	def setupServer(self):
		self.pushButton.setEnabled(False)
		self.textEdit.insertHtml(formatResult(color="blue",text="Setting up server !"))
		self.server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.server.setblocking(0)
		self.server.bind((self.host, int(self.port)))

		self.textEdit.append(formatResult(color="blue",text="Generating RSA keys..."))

		self.server_privkey = RSA.generate(4096, os.urandom)
		self.server_pubkey = self.server_privkey.publickey()

		self.textEdit.append(formatResult(color="green",text="Server is ready"))

		self.server.listen(30)
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

					self.client_map[client] = (address, cname, pubkey)
					self.updateTableWidget(True,cname,address[0],address[1])
					send(client,self.rooms)
					self.outputs.append(client)

				else:
					try:
						flag = False
						data = receive(sock)

						if data:
							if self.rooms == {}:
								if data.split()[0] not in self.commands:
									send(sock,"No one hear you at here.Join the rooms!!!")
									send(sock,"Use -create command to create a new room.")
									send(sock,"Ex: -create hacking.")

								else:
									if data.split()[0] == "-join" or data.split()[0] == "-leave":
										send(sock,"No rooms avaiable to %s" % data.split()[0])

									else: self.create_room(sock,data)

							elif self.rooms != {}:
								user_name = self.get_just_name(sock)
								for room in self.room_map:
									for user in self.room_map[room]:
										if user.sock == sock and user.name == user_name:
											room_name = room
											flag = True

								if not flag:
									if data.split()[0] not in self.commands:
										send(sock,"You was not joining any rooms,please join the room to chat!!!")
										send(sock,"Ex: -join room_name")

									elif data.split()[0] == "-leave": send(sock,"You was not joining,so you can't leave.")

									elif data.split()[0] == "-create": self.create_room(sock,data)

									elif data.split()[0] == "-join": self.join_room(sock,data)

								else:
									if data.split()[0] == "-leave":
										self.leave_room(sock,user_name,room_name)
										for o in self.room_map[room_name]:
											self.send_encrypted(o.sock,"User %s left the room" % user_name,user_name)

									else:
										dataparts = data.split('#^[[')
										data = dataparts[0]
										text = "[{0}] > {1}".format(user_name,data)

										for o in self.room_map[room_name]:
											if o.sock != sock:
												self.send_encrypted(o.sock,text,user_name)

						else:
							self.outputs.remove(sock)
							address = self.get_address(sock)
							user_name = self.get_just_name(sock)
							msg = "User %d (%s) is offline" % (sock.fileno(),user_name)

							for room in self.rooms:
								if user_name in self.rooms[room]:
									self.rooms[room].remove(user_name)
									for user in self.room_map[room]:
										if user.name == user_name and user.sock == sock:
											self.room_map[room].remove(user)

										self.send_encrypted(user.sock,msg,user_name)

							if sock in self.socket_list: self.socket_list.remove(sock)

							if sock in self.client_map: del self.client_map[sock]

							for o in self.outputs: send(o,self.rooms)

							self.textEdit.append(formatResult
								(
									color="red",text="Client %s %s disconnected" % (user_name,address)
								)
							)
							
							self.updateTableWidget(False,user_name,address[0],address[1])
					except:
						self.outputs.remove(sock)
						self.socket_list.remove(sock)
						
			time.sleep(.1)
		self.server.close()
		
	def close_server(self):
		try:
			self.thread_event.set()
			self.server.shutdown(SHUT_RDWR)
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
