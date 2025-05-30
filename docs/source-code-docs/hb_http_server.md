

# Module hb_http_server #
* [Description](#description)

A router that attaches a HTTP server to the AO-Core resolver.

<a name="description"></a>

## Description ##

Because AO-Core is built to speak in HTTP semantics, this module
only has to marshal the HTTP request into a message, and then
pass it to the AO-Core resolver.

`hb_http:reply/4` is used to respond to the client, handling the
process of converting a message back into an HTTP response.

The router uses an `Opts` message as its Cowboy initial state,
such that changing it on start of the router server allows for
the execution parameters of all downstream requests to be controlled.<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#allowed_methods-2">allowed_methods/2</a></td><td>Return the list of allowed methods for the HTTP server.</td></tr><tr><td valign="top"><a href="#cors_reply-2">cors_reply/2*</a></td><td>Reply to CORS preflight requests.</td></tr><tr><td valign="top"><a href="#get_opts-1">get_opts/1</a></td><td></td></tr><tr><td valign="top"><a href="#handle_request-3">handle_request/3*</a></td><td>Handle all non-CORS preflight requests as AO-Core requests.</td></tr><tr><td valign="top"><a href="#http3_conn_sup_loop-0">http3_conn_sup_loop/0*</a></td><td></td></tr><tr><td valign="top"><a href="#init-2">init/2</a></td><td>Entrypoint for all HTTP requests.</td></tr><tr><td valign="top"><a href="#new_server-1">new_server/1*</a></td><td></td></tr><tr><td valign="top"><a href="#read_body-1">read_body/1*</a></td><td>Helper to grab the full body of a HTTP request, even if it's chunked.</td></tr><tr><td valign="top"><a href="#read_body-2">read_body/2*</a></td><td></td></tr><tr><td valign="top"><a href="#set_default_opts-1">set_default_opts/1</a></td><td></td></tr><tr><td valign="top"><a href="#set_opts-1">set_opts/1</a></td><td>Update the <code>Opts</code> map that the HTTP server uses for all future
requests.</td></tr><tr><td valign="top"><a href="#start-0">start/0</a></td><td>Starts the HTTP server.</td></tr><tr><td valign="top"><a href="#start-1">start/1</a></td><td></td></tr><tr><td valign="top"><a href="#start_http2-3">start_http2/3*</a></td><td></td></tr><tr><td valign="top"><a href="#start_http3-3">start_http3/3*</a></td><td></td></tr><tr><td valign="top"><a href="#start_node-0">start_node/0</a></td><td>Test that we can start the server, send a message, and get a response.</td></tr><tr><td valign="top"><a href="#start_node-1">start_node/1</a></td><td></td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="allowed_methods-2"></a>

### allowed_methods/2 ###

`allowed_methods(Req, State) -> any()`

Return the list of allowed methods for the HTTP server.

<a name="cors_reply-2"></a>

### cors_reply/2 * ###

`cors_reply(Req, ServerID) -> any()`

Reply to CORS preflight requests.

<a name="get_opts-1"></a>

### get_opts/1 ###

`get_opts(NodeMsg) -> any()`

<a name="handle_request-3"></a>

### handle_request/3 * ###

`handle_request(RawReq, Body, ServerID) -> any()`

Handle all non-CORS preflight requests as AO-Core requests. Execution
starts by parsing the HTTP request into HyerBEAM's message format, then
passing the message directly to `meta@1.0` which handles calling AO-Core in
the appropriate way.

<a name="http3_conn_sup_loop-0"></a>

### http3_conn_sup_loop/0 * ###

`http3_conn_sup_loop() -> any()`

<a name="init-2"></a>

### init/2 ###

`init(Req, ServerID) -> any()`

Entrypoint for all HTTP requests. Receives the Cowboy request option and
the server ID, which can be used to lookup the node message.

<a name="new_server-1"></a>

### new_server/1 * ###

`new_server(RawNodeMsg) -> any()`

<a name="read_body-1"></a>

### read_body/1 * ###

`read_body(Req) -> any()`

Helper to grab the full body of a HTTP request, even if it's chunked.

<a name="read_body-2"></a>

### read_body/2 * ###

`read_body(Req0, Acc) -> any()`

<a name="set_default_opts-1"></a>

### set_default_opts/1 ###

`set_default_opts(Opts) -> any()`

<a name="set_opts-1"></a>

### set_opts/1 ###

`set_opts(Opts) -> any()`

Update the `Opts` map that the HTTP server uses for all future
requests.

<a name="start-0"></a>

### start/0 ###

`start() -> any()`

Starts the HTTP server. Optionally accepts an `Opts` message, which
is used as the source for server configuration settings, as well as the
`Opts` argument to use for all AO-Core resolution requests downstream.

<a name="start-1"></a>

### start/1 ###

`start(Opts) -> any()`

<a name="start_http2-3"></a>

### start_http2/3 * ###

`start_http2(ServerID, ProtoOpts, NodeMsg) -> any()`

<a name="start_http3-3"></a>

### start_http3/3 * ###

`start_http3(ServerID, ProtoOpts, NodeMsg) -> any()`

<a name="start_node-0"></a>

### start_node/0 ###

`start_node() -> any()`

Test that we can start the server, send a message, and get a response.

<a name="start_node-1"></a>

### start_node/1 ###

`start_node(Opts) -> any()`

