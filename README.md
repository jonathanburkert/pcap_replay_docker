# ProtoShark Jupyter Notebook Docker
Docker image with ProtoShark, and jupyter-notebook installed

## Build Image
- `git clone git@github.com:jonathanburkert/protoshark_jupyter.git`
- `cd protoshark_jupyter`
- `docker build -t protoshark_jupyter .`

## Run
- `docker run -d --name protoshark_jupyter --privileged --net=host -p 127.0.0.1:8888:8888 protoshark_jupyter`
- You should now have port 8888 open on the lo interface, use a web browser to connect and the password is `password`

## Examples
### Server
```
from protoShark.dissect import Server

proto_pipe = '/tmp/proto_pipe'

# To read from an interface: 
options = '-i eno1'

# To read from a PCAP:
#options = '-r traffic.pcap'

s = Server(proto_pipe, options)
s.start()
```

### Client
```
from protoShark.dissect import Client
from protoShark.packets import Packet
from protoShark.write import FileWriter
import binascii

proto_pipe = '/tmp/proto_pipe'
c = Client(proto_pipe)
c.connect()

pkts = []
while True:
    pkt = c.read_next()
    if pkt is None:
        break
    pkts.append(pkt)
```
