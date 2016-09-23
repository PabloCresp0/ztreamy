# ztreamy: a framework for publishing semantic events on the Web
# Copyright (C) 2014-2015 Jesus Arias Fisteus
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

import unittest

import ztreamy.authorization as authorization

from IPy import IP


class TestAuthorization(unittest.TestCase):

    def test_authorize_ipv4(self):
        w = [IP('165.2.3.0'), IP('10.128.1.253'), IP('175.0.2.0'),\
            IP('197.0.0.1'), IP('100.2.3.0'), IP('83.128.0.0')]
        whitelist = authorization.IPAuthorizationManager(w)
        self.assertEqual(whitelist.authorize_ip('165.2.3.0'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('10.128.1.253'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('175.0.2.0'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('197.0.0.1'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('100.2.3.0'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('83.128.0.0'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('50.15.0.0'), [False, 0])
        self.assertEqual(whitelist.authorize_ip('255.128.0.253'), [False, 0])
        self.assertEqual(whitelist.authorize_ip( \
                      '1993:0db8:85a3::1319:8a2e:0370:7344'), [False, 0])
        self.assertEqual(whitelist.authorize_ip( \
                              '756:0DBB::15:0000:1900:cdab'), [False, 0])

    def test_authorize_ipv4_netmask(self):
        w = [IP('165.2.3.0/30'), IP('10.128.0.0/28'), IP('175.0.0.0/22')]
        whitelist = authorization.IPAuthorizationManager(w)
        self.assertEqual(whitelist.authorize_ip('165.2.3.0'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('165.2.3.1'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('165.2.3.2'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('165.2.3.3'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('165.2.3.4'), [False, 0])
        self.assertEqual(whitelist.authorize_ip('165.2.4.4'), [False, 0])
        self.assertEqual(whitelist.authorize_ip('10.128.0.0'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('10.128.0.1'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('10.128.0.15'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('10.128.0.16'), [False, 0])
        self.assertEqual(whitelist.authorize_ip('10.128.1.16'), [False, 0])
        self.assertEqual(whitelist.authorize_ip('175.0.0.0'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('175.0.1.155'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('175.0.2.10'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('175.0.3.90'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('175.0.3.255'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('175.0.4.0'), [False, 0])
        self.assertEqual(whitelist.authorize_ip( \
                      '2001:0db8:85a3::1319:8a2e:0370:7344'), [False, 0])
        self.assertEqual(whitelist.authorize_ip( \
                          '2000:0DB8:0000:1408::1428:57a5'), [False, 0])

    def test_authorize_ipv6(self):
        w = [IP('2001:0123:0004:00ab:0cde:3403:0001:0063'), \
             IP('2001:0:0:0:0:0:0:4'), \
             IP('2001:0db8:85a3:0000:1319:8a2e:0370:7344'), \
             IP('2016:0DB8:0000:0000:0000:0000:1428:57ab'), \
             IP('2001:DB8:02de::0e13'), \
             IP('2001:db8:3c4d:15:0:d234:3eee::')]
        whitelist = authorization.IPAuthorizationManager(w)
        self.assertEqual(whitelist.authorize_ip( \
                            '2001:123:4:ab:cde:3403:1:63'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('2001::4'), [True, 0])
        self.assertEqual(whitelist.authorize_ip( \
                    '2001:0db8:85a3::1319:8a2e:0370:7344'), [True, 0])
        self.assertEqual(whitelist.authorize_ip( \
                '2016:0DB8:0000:0000:0000:0000:1428:57ab'), [True, 0])
        self.assertEqual(whitelist.authorize_ip( \
                    '2016:0DB8:0000:0000:0000::1428:57ab'), [True, 0])
        self.assertEqual(whitelist.authorize_ip( \
                            '2016:0DB8:0:0:0:0:1428:57ab'), [True, 0])
        self.assertEqual(whitelist.authorize_ip( \
                               '2016:0DB8:0::0:1428:57ab'), [True, 0])
        self.assertEqual(whitelist.authorize_ip( \
                                   '2016:0DB8::1428:57ab'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('2001:0DB8:2de::e13'), \
                                                               [True, 0])
        self.assertEqual(whitelist.authorize_ip('2001::454'), [False, 0])
        self.assertEqual(whitelist.authorize_ip( \
                  '2001:0db8:3c4d:0015:0000:0000:1a2f:1a2b'), [False, 0])
        self.assertEqual(whitelist.authorize_ip( \
                            '2011:db8:3c4:18:0:d234:3eee::'), [False, 0])
        self.assertEqual(whitelist.authorize_ip( \
               '2001:0db8:3c4d:0015:0000:d234:3eee:0000'), [True, 0])
        self.assertEqual(whitelist.authorize_ip( \
                                        '11:db8:3c4:3eee::'), [False, 0])
        self.assertEqual(whitelist.authorize_ip('250.15.0.10'), [False, 0])
        self.assertEqual(whitelist.authorize_ip('197.0.0.15'), [False, 0])

    def test_authorize_ipv6_netmask(self):
        w = [IP('2652:1500:0000:0000:5000:0000:0000:0000/120'),\
             IP('175.0.2.0'), IP('197.0.0.1'), IP('4000::/116'),
             IP('100.2.3.0'), IP('83.128.0.0')]
        whitelist = authorization.IPAuthorizationManager(w)
        self.assertEqual(whitelist.authorize_ip('4000::1'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('4000::ff'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('4000::500'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('4000::ffff:ff0a'), \
                                                             [False, 0])
        self.assertEqual(whitelist.authorize_ip('4000::f'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('4000::fff'), [True, 0])
        self.assertEqual(whitelist.authorize_ip('4000::ffff'), [False, 0])
        self.assertEqual(whitelist.authorize_ip('2652:1500::5000:0:0:1'),\
                                                              [True, 0])
        self.assertEqual(whitelist.authorize_ip('2652:1500::5000:0:0:ff'),\
                                                              [True, 0])
        self.assertEqual(whitelist.authorize_ip('2653:1500::8000:0:0:ff'),\
                                                              [False, 0])
        self.assertEqual(whitelist.authorize_ip('2652:1500::5000:0:0:1ff'),\
                                                              [False, 0])
        self.assertEqual(whitelist.authorize_ip('50.15.0.0'), [False, 0])
        self.assertEqual(whitelist.authorize_ip('255.128.0.253'), [False, 0])

    def test_authorize_user_password(self):
        userpass = ['Mohamed:123456', 'Peter:password', 'fatima:123456',
                    'laura:qwerty', 'maria:football', 'ana:baseball',
                    'james:welcome', 'stevenson:abc123', 'sofia:111111',
                    'manuel:1qaz2wsx', 'tomas:dragon', 'jesus:master',
                    'george:monkey', 'santiago:letmein', 'daniel:login',
                    'mirian:princess', 'ramon:qwertyuiop', 'jackson:solo',
                    'karim:g0al', 'r2d2:starwars', 'luka:password']
        userspasslist = authorization.BasicAuthorizationManager(userpass)
        self.assertEqual(userspasslist.authorize_user('Mohamed','123456'), \
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('Peter','password'), \
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('fatima','123456'), \
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('laura','qwerty'), \
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('maria','football'), \
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('ana','baseball'), \
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('james','welcome'), \
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('stevenson','abc123'),\
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('sofia','111111'), \
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('manuel','1qaz2wsx'),\
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('tomas','dragon'), \
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('jesus','master'), \
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('george','monkey'), \
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('santiago','letmein'),\
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('daniel','login'), \
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('mirian','princess'), \
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('ramon','qwertyuiop'),\
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('jackson','solo'), \
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('karim','g0al'),  \
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('r2d2','starwars'), \
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('luka','password'), \
                                                                       True)
        self.assertEqual(userspasslist.authorize_user('',''), \
                                                                 False)
        self.assertEqual(userspasslist.authorize_user('mohamed','123456'),\
                                                                 False)
        self.assertEqual(userspasslist.authorize_user('password','Peter'),\
                                                                 False)
        self.assertEqual(userspasslist.authorize_user('Sofia','111111'), \
                                                                 False)
        self.assertEqual(userspasslist.authorize_user('admin','admin'), \
                                                                 False)
        self.assertEqual(userspasslist.authorize_user('perico','hi'), \
                                                                 False)
        self.assertEqual(userspasslist.authorize_user('login','login'), \
                                                                 False)
        self.assertEqual(userspasslist.authorize_user('','starwars'), \
                                                                 False)
        self.assertEqual(userspasslist.authorize_user('ramon',''), \
                                                                 False)
        self.assertEqual(userspasslist.authorize_user('GEORGE','monkey'),\
                                                                 False)
        self.assertEqual(userspasslist.authorize_user('daniel','LOGIN'), \
                                                                 False)
        self.assertEqual(userspasslist.authorize_user('fatima','password'),\
                                                                 False)
        self.assertEqual(userspasslist.authorize_user('r2d2','dragon'), \
                                                                 False)
        self.assertEqual(userspasslist.authorize_user('stevenson','111111'),\
                                                                 False)
        self.assertEqual(userspasslist.authorize_user('','1234'), \
                                                                 False)
        self.assertEqual(userspasslist.authorize_user('1234',''),  \
                                                                 False)
