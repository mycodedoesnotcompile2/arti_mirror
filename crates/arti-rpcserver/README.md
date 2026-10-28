# arti-rpcserver

Backend for Arti's RPC service.

Note that despite the `arti-*` crate name,
which typically indicates a user-facing crate,
this crate is intended solely for low-level implementation of arti,
and should only be used if you have a need to implement an arti RPC server.

## Overview

This crate provides the code to listen as an Arti RPC server,
accept and authenticate incoming connections,
and decode and dispatch requests from clients,
and maintain state necessary for a client RPC sessions.

License: MIT OR Apache-2.0
