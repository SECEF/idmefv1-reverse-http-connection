Installation
============

This module has been tested with CentOS 7.x.

Disable SELinux:

..  sourcecode:: sh

    sudo setenforce 0

..  note::

    You may want to disable SELinux permanently by editing :file:`/etc/selinux/config`
    and rebooting.

Install dependencies:

..  sourcecode:: sh

    sudo yum install -y epel-release
    sudo yum install -y python-lxml python-requests

On both the sensor and the manager, create :file:`/usr/local/secef/`
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

The file :file:`/etc/sysconfig/http-proxy` serves as a common configuration file for
every instance, while :file:`/etc/sysconfig/http-proxy@{profile}` serves as an
instance-specific configuration file for the instance named ``profile``.

..  note::

    The same TLS settings (e.g. X.509 certificate)  will be used both when fetching messages
    from the sensor and when forwarding them to Prelude SIEM's IDMEF web gateway.
