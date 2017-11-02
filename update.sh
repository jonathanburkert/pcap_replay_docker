#!/bin/bash

echo "Cleaning earlier protoShark installation"

sudo rm -rf /usr/local/lib/python2.7/dist-packages/protoShark*
sudo rm -rf /protoShark
cd /

echo "Updating protoShark from gitlab"
sudo git clone https://gitlab.com/MLandriscina/protoShark.git
sudo chown -R user:user /protoShark
cd /protoShark
echo "Reinstalling protoShark"
sudo /usr/bin/python setup.py install

echo "Cleaning up"
sudo rm -rf /protoShark/build

/bin/bash
