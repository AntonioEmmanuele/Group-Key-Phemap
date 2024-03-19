# Group-Key-Phemap
This repository contains a proof of concept implementation of the Group Key Phemap Protocol. 
The implementation is done in order to be independant from the target board and/or simulator in use. 
Particularly, each role, e.g. AS/LV/Device, has been implemented as a library that can be easily deployed into the target. 
Each role is implemented as a struct object encapsulating all the required data to execute the protocol, additionally each function exposes an 
"automa" function, this function allows the automatic management of protocol operation when receiving a GK-PHEMAP message. 
The main idea is in fact that when a packet is received, then an automa function is called automatically saving in its internal buffers the eventual response message. 
In fact, the library does not make assumptions on the type of underlying communication protocol but saves
response message in its buffers allowing the user to configure its default communication protocol. 
