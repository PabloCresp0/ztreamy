# ztreamy: a framework for publishing semantic events on the Web
# Copyright (C) 2016 Pablo Crespo Bellido
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
""" Implementation of authorization based on IP whitelisting,
HTTP Basic Authentication and HTTP Digest Authentication.

The IPy module is used to manage IP addresses. 

The methods implemented in this module are  used in the 
module server.py to allow a client publish and/or subscribe 
streams with authorization and authentication features.

"""

from IPy import IP, IPSet
from tornado.web import *
from hashlib import md5
from tornado.escape import utf8

class IPAuthorizationManager(object):
    def __init__(self, whitelist=None):
        self.whitelist = IPSet()
        if whitelist is not None:
            self.load_from_list(whitelist)

    def load_from_list(self, whitelist):
        for ip_exp in whitelist:
            self.whitelist.add(IP(ip_exp))

    def load_from_file(self, filename):
        with open(filename) as f:
            for line in f:
                self.whitelist.add(IP(line.strip()))

    def authorize_ip(self, ip):
        ip_aux = IPSet([IP(ip)])
        if ip_aux.isdisjoint(self.whitelist)==True:
            return [False,0]
        return [True,0]

    def authorize(self, request):
        return self.authorize_ip(request.remote_ip)

class BasicAuthorizationManager(object):
    def __init__(self, userslist=None):
        self.userslist = []
        if userslist is not None:
            self.load_from_list(userslist)

    def load_from_list(self, userslist):
        for userpass in userslist:
            self.userslist.append(userpass)

    def load_from_file(self, filename):
        with open(filename) as f:
            for line in f:
                self.userslist.append((line.strip()))

    def separate_user_password(self):
        userlistaux = []
        if len(self.userslist[0]) != 2:
            for userpass in self.userslist:
                aux = userpass.split(':',1)
                userlistaux.append(aux)
            self.userslist=userlistaux
            return self.userslist
        return self.userslist

    def authorize_user(self, user, password):
        self.userslist = self.separate_user_password()
        search = [user, password]
        if(search in self.userslist):
            return True
        return False

    def authorize(self, request):
        code_ok = [True, 0]
        code_ko_1 = [False, 1]
        code_ko_3 = [False, 3]
        realm = 'ztreamy'
        auth_header = request.headers.get('Authorization', None)
        if auth_header is not None:
            auth_mode, auth_base64 = auth_header.split(' ', 1)
            assert auth_mode == 'Basic'
            auth_username, auth_password = auth_base64.decode('base64'). \
                                                            split(':', 1)
            if not self.authorize_user(auth_username, auth_password):
                return code_ko_3
        else:
            return code_ko_1
        return code_ok


class DigestAuthorizationManager(BasicAuthorizationManager):
    def __init__(self, userslist=None):
        self.userslist = []
        if userslist is not None:
            self.load_from_list(userslist)

    def authorize(self, request):
        realm = 'ztreamy'
        opaque = 'asdf'
        nonce = "1234"
        code_ko_2 = [False, 2]
        code_ko_3 = [False, 3]
        code_ok = [True, 0]
        auth_header = request.headers.get('Authorization', None)
        if auth_header is not None:
            auth_mode, params = auth_header.split(' ', 1)
            assert auth_mode == 'Digest'
            param_dict = {}
            #Loop to extract the Authentication Header parameters
            for pair in params.split(','):
                k, v = pair.strip().split('=', 1)
                if v[0] == '"' and v[-1] == '"':
                    v = v[1:-1]
                param_dict[k] = v
            if not ((param_dict['realm'] == realm) and
                 (param_dict['opaque'] == opaque) and
                 (param_dict['nonce'] == nonce) and
                 ((param_dict['uri'].split('?',1)[0]) == \
                         request.path.split('?',1)[0])):
                return code_ko_2
            request.path = param_dict['uri']
            self.userslist = self.separate_user_password()
            digest = []
            for user_pass in self.userslist:
                h1 = md5(utf8('%s:%s:%s' % (user_pass[0], realm, \
                                         user_pass[1]))).hexdigest()
                h2 = md5(utf8('%s:%s' % (request.method, \
                                         request.path))).hexdigest()
                digest_aux = md5(utf8('%s:%s:%s' % (h1, nonce, h2))) \
                                                        .hexdigest()
                digest.append(digest_aux)
            if not(param_dict['response'] in digest):
                return code_ko_3
        else:
            return code_ko_2
        return code_ok
