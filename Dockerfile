FROM registry.gitlab.com/mlandriscina/protoshark:latest

USER root
RUN curl https://bootstrap.pypa.io/get-pip.py | python
RUN pip install netaddr
RUN pip install jupyter
RUN jupyter-notebook --generate-config
ENV PASSWD='sha1:d611329768de:7217062c8ae43ac48ac199a74829ec58de411fe6'
# Password is "password"
RUN sed -i s/"#c.NotebookApp.password = u''"/"c.NotebookApp.password = u'$PASSWD'"/ /root/.jupyter/jupyter_notebook_config.py
RUN mkdir /ipynb
RUN apt-get update && apt-get install tcpreplay tcpdump
RUN mkdir /pcap_server
WORKDIR /ipynb
COPY files/interfaces /etc/network/
CMD ["sh", "-c", "python /pcap_replay/pcap_replay_server.py --capture-interface ${CAPTURE_INTERFACE} --replay-interface ${REPLAY_INTERFACE}"]
#CMD ["python",  "/pcap_replay/pcap_replay_server.py", "--capture-interface", "$CAPTURE_INTERFACE"]
