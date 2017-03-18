import argparse
import logging
import threading
import select
import sys
import os

import httplib
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import socket
import SocketServer
from SocketServer import ThreadingMixIn
import urllib
import urlparse
from HTMLParser import HTMLParser

import ssl
import time

logger = logging.getLogger(__name__)
timeout = 6 #defualt
packet_size_max = 8192 #maximum size of a package sending via network
log_path = "log_files/"


class HTTPServerThread(ThreadingMixIn, HTTPServer):
	address_family = socket.AF_INET6
	daemon_threads = True


class ProxyHandler(BaseHTTPRequestHandler):
	lock = threading.Lock()
	save_log = False
	index = 0
	
	def __init__(self, *args, **kwargs):
		self.tls = threading.local()
		self.tls.conns = {}

		BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

	def do_CONNECT(self):
		self.connect_pass()

	#helper function simply parses connect requestuest and then start a socket to connect to the destiantion
	def connect_pass(self):
		logging.debug('Connect requestuest: %s', self.path)

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

		#Adds a response header to the headers buffer and logs the accepted requestuest
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

				#save log file
				log_buffer = data + '\n'
				if source is inputs[1]:
					log_buffer += data
					source_addr = self.connection.getpeername()
					source_addr_ip4_and_extra=source_addr[0].split(':')
					self.save_log_file(source_addr_ip4_and_extra[3], address[0], log_buffer)

	#TODO: intercept data flow using self generated certifcates
	def connect_intercept(self):
		print "empty"

	def do_GET(self):
		request = self

		#get URL
		if request.path[0] == '/':
			if isinstance(self.connection, ssl.SSLSocket):
				request.path = "https://%s%s" % (request.headers['Host'], request.path)
			else:
				request.path = "http://%s%s" % (request.headers['Host'], request.path)
		url = urlparse.urlsplit(request.path)
		path = (url.path + '?' + url.query if url.query else url.path)
		print "url.query: "+ url.query
		print "url.path: "+ url.path
		print "path: "+ path
		if url.netloc:
			request.headers['Host'] = url.netloc
		setattr(request, 'headers', self.filter_headers(request.headers))


		#get request
		content_length = int(request.headers.get('Content-Length', 0))
		request_body = self.rfile.read(content_length) if content_length else None
		log_buffer = ""
		'''if content_length>0:
			requestuest_body = self.rfile.read(content_length) 
			log_buffer = request_body + '\n'
		else:
			request_body = None
			log_buffer = ""'''
		origin = (url.scheme, url.netloc)

		try:
			#send request
			if not origin in self.tls.conns:
				if scheme == 'https':
					self.tls.conns[origin] = httplib.HTTPSConnection(url.netloc, timeout=timeout)
				else:
					self.tls.conns[origin] = httplib.HTTPConnection(url.netloc, timeout=timeout)
			conn = self.tls.conns[origin]
			conn.request(self.command, path, request_body, dict(request.headers))


			#get response body
			response = conn.getresponse()
			version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
			setattr(response, 'headers', response.msg)
			setattr(response, 'response_version', version_table[response.version])
			response_body = response.read()

			log_buffer += response_body

		except Exception as e:
			if origin in self.tls.conns:
				del self.tls.conns[origin]
			self.send_error(502)
			return

		#save log buffer
		source_addr = self.connection.getpeername()
		source_addr_ip4_and_extra=source_addr[0].split(':')
		self.save_log_file(source_addr_ip4_and_extra[3], url.netloc, log_buffer)



	def filter_headers(self, headers):
		# http://tools.ietf.org/html/rfc2616#section-13.5.1
		hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
		for k in hop_by_hop:
			del headers[k]
		return headers

	def save_log_file(self, source_IP, server_name, content):
		if not self.save_log:
			return
		log_file_name = str(self.index) + '_' + str(source_IP) + '_' + str(server_name) + '.txt'
		with open(os.path.join(log_path, log_file_name), 'w+') as temp_file:
			temp_file.write(content)
			self.index=+1
			temp_file.close








def main(HandlerClass=ProxyHandler, ServerClass=HTTPServerThread):
	parser = argparse.ArgumentParser(description='This is a simple proxy http server')

	parser.add_argument('-v', '--version', action='store_true', help='Prints out version')
	parser.add_argument('-p', '--port', default='8899', help='Default: 8899')
	parser.add_argument('-n', '--numworker', default='10', help='The number of workers in the thread pool')
	parser.add_argument('-t', '--timeout', default='-1', help='Default: -1, Infinite')
	parser.add_argument('-l', '--log', action='store_true', help='Store log files when selected')
	args = parser.parse_args()


	logging.basicConfig(level=logging.INFO) #, format='%(asctime)s - %(levelname)s - pid:%(process)d - %(message)s')"""

	if args.version:
		print "Current version: 0.1, Author: Ethan Wang"
		return

	if args.log:
		if not os.path.exists(log_path):
			os.makedirs(log_path)
		save_log = True
		HandlerClass.save_log = True
	else:
		HandlerClass.save_log = False

	port = int(args.port)
	numworker = int(args.numworker)
	timeout = args.timeout

	HandlerClass.protocol_version = "HTTP/1.1"
	server_address = ('', port)
	httpd = ServerClass(server_address, HandlerClass)

	sa = httpd.socket.getsockname()
	print "Starting HTTP/HTTPS Proxy on", sa[0], "Port", sa[1], "..."
	httpd.serve_forever()

if __name__ == "__main__":
	main()