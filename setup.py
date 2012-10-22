# streamsem: a framework for publishing semantic events on the Web
# Copyright (C) 2011-2012 Jesus Arias Fisteus
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
import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "streamsem",
    version = "0.1",
    author = "Jesus Arias Fisteus",
    description = ("A framework for publishing semantic events on the Web"),
    keywords = "rdf sensors web semantic-sensor-web",
    url = "http://www.it.uc3m.es/jaf/streamsem",
    packages=['streamsem', 'streamsem.utils', 'streamsem.tools',
              'streamsem.examples', 'streamsem.experiments',
              'streamsem.casestudy'],
    long_description=read('README'),
    install_requires = ['setuptools',
                        'tornado',
                        'rdflib',
                        'rdfextras',
                        'tweepy',
                        ],
)
