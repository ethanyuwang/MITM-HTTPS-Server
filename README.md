# MITM-HTTPS-Server

This is an HTTP(S) proxy server that intercepts requests coming from different applications. Currently it forwards requests and replies. By adding fake certificate generator it can decrypts data to monitor information sent through internet. In addition you could modify the response to provide false content to users.


## Usage

To start the proxy server: `python mproxy.py -p port number` <br />

Additional commands:
-h or --help
Prints a synopsis of the application usage.
-v or --version
Prints the name of the application, the version number 
[-p port] or [--port port]
The port your server will be listening on.
[-t timeout] or [--timeout timeout]
The time (seconds) to wait before give up waiting for response from server.
[-l log] or [--log log]
Logs all the HTTP requests and their corresponding responses under the directory specified by
log.
