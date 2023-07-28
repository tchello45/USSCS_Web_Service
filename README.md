# Universal Serverside Chat System Web Service (USSCS_WS) Version 1.0.0 beta    
# USSCS Version 3.0.1
Developed by: Tilman Kurmayer

## Description
USSCS_WS is a web service that provides a chat system for multiple clients. It is based on the Universal Serverside Chat System (USSCS). The USSCS is a chat system that is based on a client-server architecture. The USSCS_WS is the server component of the USSCS. It provides a REST API web service that can be used by multiple clients to communicate with each other. The USSCS_WS is written in Python and uses the Flask framework. The USSCS_WS is currently in a beta state and is not ready for production use. 
USSCS provides a encrypted an non-encrypted Chat System. USSCS_WS should provide a REST API for both systems.
Later USSCS_WS should provide a Docker Container for easy deployment.

## Files
| Name: | Layer: | File: | Version: | Beta: | Description: |
| --- | --- | --- | --- | --- | --- |
| USSCS_WS | Web Service | `main.py` | 1.0.0 | beta | Main file of the USSCS_WS. |
| USSCS_WS_error_system | Server | `error.py` | 1.0.0 | beta | Status Generator file. |

# In combination with:
`encpp` - encryption library for Python [encpp](https://github.com/tchello45/encpp) 
`USSCS` - Universal Serverside Chat System Version: 3.0.1 [USSCS](https://github.com/tchello45/USSCS/tree/Version-3.0.1)