# MITM-HTTPS-Server

This is an HTTP(S) proxy server that intercepts requests coming from different applications. Currently it forwards requests and replies. By adding fake certificate generator it can decrypts data to monitor information sent through internet. In addition you could modify the response to provide false content to users.


## Usage

To start the proxy server: `python mproxy.py -p port number` <br />

Additional commands:

-h or --help:  <br />
Prints a synopsis of the application usage.  <br />
-v or --version:  <br />
Prints the name of the application, the version number  <br />
[-p port] or [--port port]:  <br />
The port your server will be listening on.  <br />
[-t timeout] or [--timeout timeout]:  <br />
The time (seconds) to wait before give up waiting for response from server.  <br />
[-l log] or [--log log]:  <br />
Logs all the HTTP requests and their corresponding responses under the directory specified by
log.
