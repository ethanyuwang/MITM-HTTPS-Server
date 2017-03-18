import argparse
import logging
import threading
import select
import sys

import httplib
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import socket
import SocketServer
from SocketServer import ThreadingMixIn
import urllib
import urlparse
from HTMLParser import HTMLParser

import ssl
import gzip
import zlib
import time
import json
import re

logger = logging.getLogger(__name__)
timeout = 5 #defualt
packet_size_max = 8192 #maximum size of a package sending via network


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
	address_family = socket.AF_INET6
	daemon_threads = True


class ProxyRequestHandler(BaseHTTPRequestHandler):
	lock = threading.Lock()
	
	def __init__(self, *args, **kwargs):
		self.tls = threading.local()
		self.tls.conns = {}

		BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

	def do_CONNECT(self):
		self.connect_pass()

	#helper function simply parses connect request and then start a socket to connect to the destiantion
	def connect_pass(self):
		logging.debug('Connect request: %s', self.path)

		address = self.path.split(':')
		if int(address[1])>0:
			address[1] = int(address[1])
		else: 
			address[1] = 443 #443 as the default SSL port

		#start a socket for connection betwen proxy and destination
		try:
			s_ser = socket.create_connection(address, timeout=timeout)
		except Exception as e:
			self.send_error(502)
			return

		#Adds a response header to the headers buffer and logs the accepted request
		self.send_response(200, 'Connection Established') #200 as OK
		self.end_headers()

		inputs = [self.connection, s_ser]
		self.close_connection = 0
		while not self.close_connection:
			readable, writable, exceptional = select.select(inputs, [], inputs, timeout)
			#exit when exception happens or no more readable
			if exceptional or not readable:
				break
			for source in readable:
				#rotate source and destination so flow is bidirectional
				if source is inputs[0]:
					destination = inputs[1]
				else:
					destination = inputs[0]
				#get data from source and forward to destination
				data = source.recv(packet_size_max)
				if not data:
					self.close_connection = 1
					break
				destination.sendall(data)

	#TODO: intercept data flow using self generated certifcates
	def connect_intercept(self):
		print "empty"

	def do_GET(self):

			req = self


			if req.path[0] == '/':
				if isinstance(self.connection, ssl.SSLSocket):
					req.path = "https://%s%s" % (req.headers['Host'], req.path)
				else:
					req.path = "http://%s%s" % (req.headers['Host'], req.path)
			url = urlparse.urlsplit(req.path)
			scheme, netloc, path = url.scheme, url.netloc, (url.path + '?' + url.query if url.query else url.path)
			print "url.query: "+ url.query
			print "url.path: "+ url.path
			print "path: "+ path

			if url.netloc:
				req.headers['Host'] = url.netloc
			setattr(req, 'headers', self.filter_headers(req.headers))

			content_length = int(req.headers.get('Content-Length', 0))
			req_body = self.rfile.read(content_length) if content_length else None
			origin = (url.scheme, url.netloc)

			try:


				#origin = (url.scheme, url.netloc)
				if not origin in self.tls.conns:
					if scheme == 'https':
						self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=timeout)
					else:
						self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=timeout)
				conn = self.tls.conns[origin]
				conn.request(self.command, path, req_body, dict(req.headers))
				res = conn.getresponse()

				version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
				setattr(res, 'headers', res.msg)
				setattr(res, 'response_version', version_table[res.version])


				res_body = res.read()
			except Exception as e:
				if origin in self.tls.conns:
					del self.tls.conns[origin]
				self.send_error(502)
				return

			setattr(res, 'headers', self.filter_headers(res.headers))

			self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
			for line in res.headers.headers:
				self.wfile.write(line)
			self.end_headers()
			self.wfile.write(res_body)
			self.wfile.flush()


	def filter_headers(self, headers):
		# http://tools.ietf.org/html/rfc2616#section-13.5.1
		hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
		for k in hop_by_hop:
			del headers[k]

		return headers






def main(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer):
	parser = argparse.ArgumentParser(description='This is a simple proxy http server')

	parser.add_argument('-v', '--version', default='version', help='Prints out version')
	parser.add_argument('-p', '--port', default='8899', help='Default: 8899')
	parser.add_argument('-n', '--numworker', default='10', help='The number of workers in the thread pool')
	parser.add_argument('-t', '--timeout', default='-1', help='Default: -1, Infinite')
	parser.add_argument('-l', '--log', default='INFO', help='INFO')
	args = parser.parse_args()

	logging.basicConfig(level=logging.INFO) #, format='%(asctime)s - %(levelname)s - pid:%(process)d - %(message)s')"""

	port = int(args.port)
	numworker = int(args.numworker)
	timeout = args.timeout

	HandlerClass.protocol_version = "HTTP/1.1"
	server_address = ('', port)
	httpd = ServerClass(server_address, HandlerClass)

	sa = httpd.socket.getsockname()
	print "Serving HTTP Proxy on", sa[0], "port", sa[1], "..."
	httpd.serve_forever()

if __name__ == "__main__":
	main()