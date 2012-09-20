# ztreamy: a framework for publishing semantic events on the Web
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
"""Representation and  manipulation of events.

"""
import time

import ztreamy
from ztreamy import ZtreamyException


class Deserializer(object):
    """Object that deserializes events.

    The deserializer processes the data from an internal data buffer
    in a stream model: data chunks can be continously added to the
    buffer and parsed. Data chunks do not need to finish at complete
    events. When a partial event is at the end of a chunk, its data is
    maintained for the next parse attempt.

    It maintains a context, so a separate deserialized must be used
    for each event client, in order to not mix the contexts of
    different events.

    A normal workflow is:

    deserializer = Deserializer()
    while new_data arrives:
        events = deserializer.deserialize(new_data)

    """
    def __init__(self):
        """Creates a new 'Deserializer' object."""
        self.reset()

    def append_data(self, data):
        """Appends new data to the data buffer of the deserializer."""
        self._data = self._data + data
        self._previous_len = len(self._data)

    def data_consumed(self):
        """Amount of bytes consumed since the last 'append_data()'."""
        return self._previous_len - len(self._data)

    def reset(self):
        """Resets the state of the parser and discards pending data."""
        self._data = ''
        self.previous_len = 0
        self._event_reset()

    def _event_reset(self):
        """Method to be called internally after an event is read."""
        self._event = {}
        self._extra_headers = {}
        self._header_complete = False

    def deserialize(self, data, parse_body=True, complete=False):
        """Deserializes and returns a list of events.

        Deserializes all the events until no more events can be parsed
        from the data stored in this deserializer object. The remaining
        data is kept for being parsed in future calls to this method.

        If 'data' is provided, it is appended to the data buffer. It
        may be None.

        If 'parse_body' is True (the default value), the parser will
        deserialize also the body of the events according to their
        types. If not, their body will be stored only in their
        serialized form (as a string).

        The list of deserialized event objects is returned. The list
        is empty when no events are deserialized.

        """
        if data is not None:
            self.append_data(data)
        events = []
        event = self.deserialize_next(parse_body=parse_body)
        while event is not None:
            events.append(event)
            event = self.deserialize_next(parse_body=parse_body)
        if complete and len(self._data) > 0:
            self.reset()
            raise ZtreamyException('Spurious data in the input event',
                                   'event_deserialize')
        return events

    def deserialize_next(self, parse_body=True):
        """Deserializes and returns an event from the data buffer.

        Returns None and keeps the pending data stored when a complete
        event is not in the stored data fragment.

        If 'parse_body' is True (the default value), the parser will
        deserialize also the body of the events according to their
        types. If not, their body will be stored only in their
        serialized form (as a string).

        """
        # Read headers
        pos = 0
        while not self._header_complete and pos < len(self._data):
            end = self._data.find('\n', pos)
            if end == -1:
                self._data = self._data[pos:]
                return None
            part = self._data[pos:end]
            pos = end + 1
            if part == '':
                self._header_complete = True
                break
            comps = part.split(':')
            if len(comps) < 2:
                    raise ZtreamyException('Event syntax error',
                                           'event_deserialize')
            header = comps[0].strip()
            value = part[len(comps[0]) + 1:].strip()
            self._update_header(header, value)
        if not self._header_complete:
            self._data = self._data[pos:]
            return None
        if not 'Body-Length' in self._event:
            body_length = 0
        else:
            body_length = int(self._event['Body-Length'])
        Deserializer._check_mandatory_headers(self._event)
        end = pos + int(body_length)
        if end > len(self._data):
            self._data = self._data[pos:]
            return None
        body = self._data[pos:end]
        self._data = self._data[end:]
        if parse_body or self._event['Syntax'] in Event._always_parse:
            event = Deserializer.create_event(self._event, self._extra_headers,
                                              body)
        else:
            event = Event( \
                self._event.get('Source-Id'),
                self._event.get('Syntax'),
                body,
                event_id=self._event.get('Event-Id'),
                application_id=self._event.get('Application-Id'),
                aggregator_id=self._event.get('Aggregator-Ids', []),
                event_type=self._event.get('Event-Type'),
                timestamp=self._event.get('Timestamp'),
                extra_headers=self._extra_headers)
        self._event_reset()
        return event

    def _update_header(self, header, value):
        if header not in Event.headers:
            self._extra_headers[header] = value
        elif header == 'Aggregator-Ids':
            self._event[header] = value.split(',')
        elif header not in self._event:
            self._event[header] = value
        else:
            raise ZtreamyException('Duplicate header in event',
                                   'event_deserialize')

    @staticmethod
    def _check_mandatory_headers(headers):
        if (not 'Event-Id' in headers
            or not 'Source-Id' in headers
            or not 'Syntax' in headers):
            raise StreamsemException('Missing headers in event',
                                     'event_deserialize')

    @staticmethod
    def deserialize_headers(text):
        """A simple deserializer just for event headers.

        It parses from a string the headers of a single event. It does
        not support streaming situations. There cannot be blank lines
        (even at the end).

        """
        if type(text) == unicode:
            text = text.encode('utf-8')
        headers = {}
        extra_headers = {}
        parts = text.split('\n')
        for part in parts:
            pos = part.find(':')
            if pos == -1:
                raise StreamsemException('Syntax error in event header',
                                         error_type='event_syntax')
            header = part[:pos].strip()
            value = part[pos + 1:].strip()
            if header not in Event.headers:
                extra_headers[header] = value
            elif header == 'Aggregator-Ids':
                headers[header] = value.split(',')
            elif header not in headers:
                headers[header] = value
            else:
                raise StreamsemException('Duplicate header in event',
                                         'event_deserialize')
        Deserializer._check_mandatory_headers(headers)
        return headers, extra_headers

    @staticmethod
    def create_event(headers, extra_headers, body):
        return Event.create( \
            headers.get('Source-Id'),
            headers.get('Syntax'),
            body,
            event_id=headers.get('Event-Id'),
            application_id=headers.get('Application-Id'),
            aggregator_id=headers.get('Aggregator-Ids', []),
            event_type=headers.get('Event-Type'),
            timestamp=headers.get('Timestamp'),
            extra_headers=extra_headers)


class Event(object):
    """Generic event in the system.

    It is intended to be subclassed for application-specific types
    of events.

    """

    _subclasses = {}
    _always_parse = []
    headers = [
        'Event-Id',
        'Source-Id',
        'Syntax',
        'Application-Id',
        'Aggregator-Ids',
        'Event-Type',
        'Timestamp',
        'Body-Length'
        ]

    @staticmethod
    def register_syntax(syntax, subclass, always_parse=False):
        """Registers a subclass of `Event` for a specific syntax.

        `subclass`should be a subclass of `Event`.  Overrides a
        previous registration for the same syntax.

        """
        assert issubclass(subclass, Event), \
            '{0} must be a subclass of Event'.format(subclass)
        Event._subclasses[syntax] = subclass
        if always_parse:
            Event._always_parse.append(syntax)

    @staticmethod
    def create(source_id, syntax, body, **kwargs):
        """Creates an instance of the appropriate subclass of `Event`.

        The subclass to use is the one registered for the syntax
        of the event (see 'register_syntax'). If no subclass has
        been registered for than syntax, an instance of 'Event'
        is returned instead.

        """
        if syntax in Event._subclasses:
            subclass = Event._subclasses[syntax]
        else:
            subclass = Event
        return subclass(source_id, syntax, body, **kwargs)

    def __init__(self, source_id, syntax, body, event_id=None,
                 application_id=None, aggregator_id=[], event_type=None,
                 timestamp=None, extra_headers=None):
        """Creates a new event.

        'body' must be the textual representation of the event, or an
        object providing that textual representation through 'str()'.

        When the created event has to be an instance of a specific
        subclass (e.g. an 'RDFEvent'), the static 'create()' method
        should be used instead.

        """
        self.event_id = event_id or ztreamy.random_id()
        self.source_id = source_id
        self.syntax = syntax
        self.body = body
        if aggregator_id is None:
            aggregator_id = []
        else:
            if type(aggregator_id) is not list:
                self.aggregator_id = [str(aggregator_id)]
            else:
                self.aggregator_id = [str(e) for e in aggregator_id]
        self.event_type = event_type
        self.timestamp = timestamp or ztreamy.get_timestamp()
        self.application_id = application_id
        if extra_headers is not None:
            self.extra_headers = extra_headers
        else:
            self.extra_headers = {}

    def set_extra_header(self, header, value):
        """Adds an extra header to the event."""
        self.extra_headers[header] = value

    def append_aggregator_id(self, aggregator_id):
        """Appends a new aggregator id to the event."""
        self.aggregator_id.append(aggregator_id)

    def __str__(self):
        """Returns the string serialization of the event."""
        return self._serialize()

    def serialize_body(self):
        """Returns a string representation of the body of the event.

        Raises a `ZtreamyException` if the body is None. This method
        should be overriden by subclasses in order to provide a
        syntax-specific serialization.

        """
        if self.body is not None:
            return str(self.body)
        else:
            raise ZtreamyException('Empty body in event', 'even_serialize')

    def serialize_headers(self):
        data = []
        self._serialize_headers_internal(data)
        return '\n'.join(data)

    def time(self):
        """Returns the event timestamp as a seconds since the epoch value.

        Note that the timezone information from the timestamp is
        lost. Returns None if the event has no timestamp set.

        """
        if self.timestamp is not None:
            return ztreamy.rfc3339_as_time(self.timestamp)
        else:
            return None

    def _serialize(self):
        data = []
        self._serialize_headers_internal(data)
        serialized_body = self.serialize_body()
        data.append('Body-Length: ' + str(len(serialized_body)))
        data.append('')
        data.append(serialized_body)
        return '\n'.join(data)

    def _serialize_headers_internal(self, data):
        data.append('Event-Id: ' + self.event_id)
        data.append('Source-Id: ' + str(self.source_id))
        data.append('Syntax: ' + str(self.syntax))
        if self.application_id is not None:
            data.append('Application-Id: ' + str(self.application_id))
        if self.aggregator_id != []:
            data.append('Aggregator-Ids: ' + ','.join(self.aggregator_id))
        if self.event_type is not None:
            data.append('Event-Type: ' + str(self.event_type))
        if self.timestamp is not None:
            data.append('Timestamp: ' + str(self.timestamp))
        for header, value in self.extra_headers.iteritems():
            data.append(header + ': ' + value)


class Command(Event):
    """Special event used for control at the middleware layer.

    These events are consumed by the event parser and never delivered
    to the rest of the application.

    """
    valid_commands = [
        'Set-Compression',
        'Set-Compression-rdz',
        'Test-Connection',
        'Event-Source-Started',
        'Event-Source-Finished',
        'Stream-Finished',
        ]

    def __init__(self, source_id, syntax, command, **kwargs):
        """Creates a new command event.

        `command` must be the textual representation of the command or
        provide that textual representation through `str()`. It will
        be the body of the event.

        """
        if syntax != 'ztreamy-command':
            raise ZtreamyException('Usupported syntax in Command',
                                   'programming')
        super(Command, self).__init__(source_id, syntax, None, **kwargs)
        self.body = command
        self.command = command
        if not command in Command.valid_commands:
            raise ZtreamyException('Usupported command ' + command,
                                   'programming')

Event.register_syntax('ztreamy-command', Command, always_parse=True)


class TestEvent(Event):
    """Special event used for benchmarking and testing.

    The event encapsulates a sequence number and a timestamp.

    """
    def __init__(self, source_id, syntax, body, sequence_num=0, **kwargs):
        """Creates a new command event.

        ``sequence_num`` represents the sequence number (integer) of
        the event, and is transmitted in its body along with the
        timestamp. It is only used when body is None. If ``body`` is
        not None, the sequence number is read from ``body`` instead.

        """
        if syntax != 'ztreamy-test':
            raise ZtreamyException('Usupported syntax in TestEvent',
                                   'programming')
        super(TestEvent, self).__init__(source_id, syntax, None, **kwargs)
        if body is not None:
            self._parse_body(body)
            parts = self.extra_headers['X-Float-Timestamp'].split('/')
            self.float_time = float(parts[1])
            self.sequence_num = int(parts[0])
        else:
            self.float_time = time.time()
            self.sequence_num = sequence_num
            self.extra_headers['X-Float-Timestamp'] = \
                str(sequence_num) + '/' + str(self.float_time)

    def serialize_body(self):
        return ''

    def _parse_body(self, body):
        # This event has an empty body
        pass

Event.register_syntax('ztreamy-test', TestEvent, always_parse=True)


def create_command(source_id, command):
    return Command(source_id, 'ztreamy-command', command)

def parse_aggregator_id(data):
    return [v.strip() for v in data.split(',') if v != '']