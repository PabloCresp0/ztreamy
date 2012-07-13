# streamsem: a framework for publishing semantic events on the Web
# Copyright (C) 2011-2012 Norberto Fernandez Garcia
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
import httplib2
import rdflib
import tornado
import traceback
import simplejson as json

from rdflib import Graph
from rdflib import Namespace
from rdflib import Literal
from rdflib import URIRef
from tornado.httpclient import AsyncHTTPClient, HTTPRequest, HTTPResponse
from tornado.simple_httpclient import SimpleAsyncHTTPClient

import streamsem
from streamsem import events
from streamsem import rdfevents
from streamsem import client

#
# Explaining the URL used in the call
#
# action = query (method to be invoked)
# list = recentchanges (information to be obtained)
# redirects (solve redirections)
# format = json (output format)
# rcnamespace = 0 (only changes in pages in the Main namespace -No talk, categories, ...-)
# rclimit = 500 (maximum number of results to be obtained MAX=500, unless a bot is used)
# 
# Answer structure: 
#
# {"type":"edit","ns":0,"title":"Makes No Difference","rcid":480336437,"pageid":3005612,"revid":466353130,"old_revid":466353059,"timestamp":"2011-12-17T16:21:51Z"}
#

class WikipediaStreamSensor():
   
    def __init__(self, publisher, app_id = "WikipediaSensor", source_id = "WikipediaSensor0"):
    	self.API_URL = "http://en.wikipedia.org/w/api.php?action=query&list=recentchanges&redirects&format=json&rcnamespace=0&rclimit=500"
	self.NS = Namespace("http://webtlab.it.uc3m.es/")
	self.DC = Namespace("http://purl.org/dc/elements/1.1/")
        self.http = httplib2.Http()		
	self.publisher = publisher
	self.app_id = app_id
	self.source_id = source_id
	self.last_change = 0

    def toN3(self, changes_dict):

	graph = Graph()

	graph.bind("webtlab", "http://webtlab.it.uc3m.es/")
	graph.bind("dc", "http://purl.org/dc/elements/1.1/")

	total_changes = 0
	biggest_change_id = 0

	for change in changes_dict:
	  this_change_id = change["rcid"]
	  # Avoid duplicates
	  if this_change_id > self.last_change:
	    if this_change_id > biggest_change_id:
	      biggest_change_id = this_change_id
	    change_id = URIRef("_" + str(change["rcid"]))
	    graph.add( ( change_id, self.DC["created"], Literal(change["timestamp"]) ))
	    graph.add( ( change_id, self.NS["title"], Literal(change["title"]) ))	  
	    graph.add( ( change_id, self.NS["pageid"], Literal(str(change["pageid"])) ))	  
	    total_changes += 1
	    
        self.last_change = biggest_change_id

	if total_changes > 0:
	  return (total_changes, graph)
	else:
	  return (total_changes, None)

    def decode(self, updates):
	updates_dict = json.loads(updates)
	# Check format of updates
	if "query" in updates_dict:
	  if "recentchanges" in updates_dict["query"]:
	    return self.toN3(updates_dict["query"]["recentchanges"])

    def lookForUpdates(self):
        response, content = self.http.request(self.API_URL)
        # Check response code
        if response.status != 200:
	  return
        # Process data and publish events
  	try:
          (num_changes, graph) = self.decode(content)
	  if graph != None:
            self.publish(graph)
	    print "*** Number of updates detected ",num_changes," ***"
        except:
          return
       
    def publish(self, graph):	
	event = rdfevents.RDFEvent(self.source_id, 'text/n3', graph)
	print event
	self.publisher.publish(event)

def main():
    period = 30.0;
    publisher = client.EventPublisher("http://localhost:9001/events/publish")
    enc = WikipediaStreamSensor(publisher,"AppID","SrcID")
    sched = tornado.ioloop.PeriodicCallback(enc.lookForUpdates, period * 1000)
    sched.start()
    tornado.ioloop.IOLoop.instance().start()

if __name__ == "__main__":
    main()


