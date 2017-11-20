# PCAP Replay

## Actions to take on Host
None...

## Building the image
`cd pcap_replay`
`docker build -t pcap_replay .`

## Creating a container
`docker create --name pcap_replay -v {path to pcap_replay}/pcap_replay:/pcap_replay --privileged --net=host --env CAPTURE_INTERFACE={interface} pcap_replay`

## Starting a container
`docker start pcap_replay`

## Starting Jupyter-Notebook
`docker exec pcap_replay /usr/local/bin/jupyter-notebook --no-browser --allow-root`
