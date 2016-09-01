# ztreamy: a framework for publishing semantic events on the Web
# Copyright (C) 2011-2015 Jesus Arias Fisteus
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
#
""" Implementation of streams and an asynchronous HTTP server for them.

Two kinds of streams are provided: 'Stream' and 'RelayStream'.

'Stream' is a basic stream of events. It can transmit events received
from remote sources or generated at the process of the server.

'RelayStream' extends the basic stream with functionality to listen to
other streams and retransmitting their events. Events from remote
sources or generated at the process of the server can also be
published in this type of stream.

The server is asynchronous. Be careful when doing blocking calls from
callbacks (for example, sources of events and filters), because the
server will be blocked.

"""

from IPy import IP

class IPAuthorizationManager(object):
    def __init__(self, whitelist=None):
        self.whitelist = []
        if whitelist is not None:
            self.load_from_list(whitelist)

    def load_from_list(self, whitelist):
        for ip_exp in whitelist:
            self.whitelist.append(IP(ip_exp))

    def load_from_file(self, filename):
        with open(filename) as f:
            for line in f:
                self.whitelist.append(IP(line.strip()))

    def authorize_ip(self, ip):
        if len(self.whitelist) == 0:
            return False
        else:
            ip_aux = IP(ip)
            if (ip_aux in self.whitelist) == True:
                return True
            for i in self.whitelist:
                for x in i:
                    if ip == str(x):
                        return True
        return False

    def authorize(self, request):
        return self.authorize_ip(request.remote_ip)
