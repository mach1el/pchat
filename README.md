# Pchat ![VERSION](https://img.shields.io/badge/version-1.5-green.svg)

![PyPI - Python Version](https://img.shields.io/pypi/pyversions/Django.svg)
![PyQt5 - PyQt Version](https://img.shields.io/badge/PyQt5-5.11.1%2B-lightgrey.svg)

Multi users chat,this simple application using python socket to handle the connection and using PyQt framework to create GUI for this app.To make secure data transformation i using Python cryptography with RSA technique to decrypt all message before sending between clients.

## Logs
   * ver 1.5.1
    
    - Add leave room feature.
   
   * ver 1.5
    
    - Add features create,join,leave room (leave room feature still in development)
    - In client side,now using QTreeWidget to listing all rooms avaiable
      and user who joined to that room.
    - You can only chat with other user in the same room.
   
   * ver 1.1
   
    - Server side now, listing user who connected to it,
      will appear on QTableWidget instead of QTreeWidget.
   
   * ver 1.0
    
    - Tested on Arch linux.
    - Have not been support for windows platform yet.
    - Threading still have not been optimized on Client side.
    - Using pycrypto library with RSA technique to decrypt and encrypt 
      data transformation between clients.

## Install Requirements
    pip install -r requirements.txt

## License
[![AUR](https://img.shields.io/aur/license/yaourt.svg)](https://github.com/t7hm1/Pchat/blob/master/LICENSE)
