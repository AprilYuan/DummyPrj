# -*- coding: utf-8 -*-
"""
:copyright: Nokia Networks
:author: Zhang Haijun
:contact: haofeng.zhu@nokia-sbell.com
:maintainer: None
:contact: None
"""



from taf.transport.ssh import ssh
import logging
import re


class deployment:

    def __init__(self):
        pass

    def setup(self, gnbip):
        """get container ID

         :param nodename: container name. eg. CPIF
         :type nodename: string
         :return: NB of filtered packets matching condition expression
         :rtype: string
         """
        self.config = {
            "ASIK": {
                "ip": gnbip,
                "nodeid": "0x1011",
                "container": []},
            "FCT": {
                "ip": "192.168.253.17",
                "nodeid": "0x1021",
                "container": []},
            "FSP": {
                "ip": "192.168.253.20",
                "nodeid": "0x123D",
                "container": []}
        }
        self.username = "toor4nsn"
        self.password = "oZPS0POrRieRtu"
        self.conn = ssh()
        self._get_containers()

    def _ssh_connect(self, nodename):
        proxy = None
        if nodename != "ASIK":
            proxy = "alias_ASIK"
        self.conn.connect_to(
            hostname=self.config[nodename]['ip'],
            username=self.username,
            password=self.password,
            proxy=proxy,
            alias="alias_{}".format(nodename))

    def _get_containers(self):
        self._ssh_connect("ASIK")
        for node in self.config:
            cmd = "export PYTHONPATH=/opt/hwmt/python; \
            python3 /opt/hwmt/python/hwapi/SupervisorS.py -n {} -o list_cbts -p 15004 |grep {}".format(
                self.config[node]['nodeid'], self.config[node]['nodeid'])
            outcome = self.conn.execute(command=cmd, connection="alias_ASIK")
            lines = outcome.strip().split("\r\n")
            for line in lines:
                res = re.findall(
                    r"nodeId:(0x[A-F|0-9]*), nodeState:.*nodeName:([A-Z|0-9|-]*),?", line)
                if len(res) > 0:
                    self.config[node]['container'].append(res[0])

    def get_container(self, nodename):
        """get container ID

        :param nodename: container name. eg. CPIF
        :return: NB of filtered packets matching condition expression
        """
        for key in self.config:
            for node in self.config[key]["container"]:
                if nodename in node[1]:
                    self._ssh_connect(key)
                    outcome = self.conn.execute(
                        command="ls /tmp/node_{}".format(node[0].lower()), connection="alias_{}".format(key))
                    if "No such file or directory" not in outcome:
                        return (key, self.config[key]['ip'], node[0].lower(
                        ), node[1], "/tmp/node_{}".format(node[0].lower()))
                    outcome = self.conn.execute(
                        command="ls /tmp/node_{}".format(node[1]), connection="alias_{}".format(key))
                    if "No such file or directory" not in outcome:
                        return (key, self.config[key]['ip'], node[0].lower(), node[1], "/tmp/node_{}".format(node[1]))

    def download_file_from_container(self, filename, nodename, localpath):
        res = self.get_container(nodename)
        localpath = "{}/{}".format(localpath, filename)
        remotepath = "{}/tmp/{}".format(res[4], filename)
        self.conn.download_file(remotepath, localpath, connection="alias_{}".format(res[0]))
