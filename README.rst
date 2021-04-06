SECEF reverse web gateway (pull mode)
#####################################

This repository contains a small daemon that fetches security alerts encoded using
IDMEFv1 XML messages from a remote web server and forwards them to a web gateway.

This daemon is useful in contexts where the IDMEF sensors are unable to send their
alerts to a manager directly (e.g. in a DMZ) and instead expect the manager
to establish a reverse connection to fetch new alerts periodically.

An implementation of a compatible web gateway is also available at
https://github.com/SECEF/secef-web-gateway.
This particular implementation forwards IDMEFv1 messages to a Prelude SIEM manager.

For more information about the Intrusion Detection Message Exchange Format (IDMEF) version 1,
see https://tools.ietf.org/html/rfc4765.

For more information about Prelude SIEM, see https://www.prelude-siem.org/.

Installation
============

This module has been tested with CentOS 7.x.

Disable SELinux:

..  sourcecode:: sh

    sudo setenforce 0

..  note::

    You may want to disable SELinux permanently by editing ``/etc/selinux/config``
    and rebooting.

Install dependencies:

..  sourcecode:: sh

    sudo yum install -y epel-release
    sudo yum install -y python-lxml python-requests

On both the sensor and the manager, create ``/usr/local/secef/``
and copy all the files into that folder.

Install the script on the sensor:

..  sourcecode:: sh

    sudo ln -s /usr/local/secef/reverse-server.service       /etc/systemd/system/
    sudo ln -s /usr/local/secef/secef.xml                    /etc/firewalld/services/
    sudo systemctl daemon-reload
    sudo systemctl enable reverse-server.service
    sudo systemctl reload firewalld
    sudo firewall-cmd --add-service=secef --permanent
    sudo firewall-cmd --add-service=secef

Install the script on the manager:

..  sourcecode:: sh

    sudo ln -s /usr/local/secef/http-proxy@.service  /etc/systemd/system/
    sudo ln -s /usr/local/secef/http-proxy@.timer    /etc/systemd/system/
    sudo ln -s /usr/local/secef/http-proxy           /etc/sysconfig/
    sudo systemctl daemon-reload
    sudo systemctl enable http-proxy@<profile>.timer

(replace ``<profile>`` in the commands above with an alphanumeric identifier)

Usage
=====

On the sensor
-------------

Start the local server:

..  sourcecode:: sh

    /usr/local/bin/reverse-server.py --cert server.crt --key server.key --cacert CA.crt

The ``--cert``, ``--key`` and ``--cacert`` options are mandatory.
You may also want to run ``/usr/local/bin/reverse-server.py --help`` to get more information
on other available options.

On the manager
--------------

To query the server manually (assuming the default port is used), run:

..  sourcecode:: sh

    curl -s -S --cert client.crt --key client.key --cacert CA.crt https://$(hostname):3128/

The ``http-proxy`` service will periodically fetch IDMEF messages from a remote sensor
and then forward those messages to Prelude SIEM's IDMEF web gateway.

Several sensors can be queried by enabling multiple instances of the service's timer, e.g.:

..  sourcecode:: sh

    sudo systemctl enable http-proxy@sensor1.timer http-proxy@sensor2.timer

The file ``/etc/sysconfig/http-proxy`` serves as a common configuration file for
every instance, while ``/etc/sysconfig/http-proxy@{profile}`` serves as an
instance-specific configuration file for the instance named ``profile``.

..  note::

    The same TLS settings (e.g. X.509 certificate)  will be used both when fetching messages
    from the sensor and when forwarding them to Prelude SIEM's IDMEF web gateway.
