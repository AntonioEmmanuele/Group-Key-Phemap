# Group-Key-Phemap
This repository contains a proof of concept implementation of the Group Key Phemap Protocol. 

The implementation is done in order to be independant from the target board and/or simulator in use. 

Particularly, each role, e.g. AS/LV/Device, has been implemented as a library that can be easily deployed into the target. 

Each role is implemented as a struct object encapsulating all the required data to execute the protocol, additionally each function exposes an 
"automa" function, this function allows the automatic management of protocol operation when receiving a GK-PHEMAP message. 

The main idea is in fact that when a packet is received, then an automa function is called automatically saving in its internal buffers the eventual response message. 

In fact, the library does not make assumptions on the type of underlying communication protocol but saves
response message in its buffers allowing the user to configure its default communication protocol. 

This library has been applied in the following papers.

> [Barbareschi, M., Casola, V., Emmanuele, A., Lombardi, D. *A Lightweight PUF-Based Protocol for Dynamic and Secure Group Key Management in IoT*. IEEE Internet of Things Journal (2024). DOI: 10.1109/JIOT.2024.3418207](https://doi.org/10.1109/JIOT.2024.3418207)


Please, cite us!
```
@ARTICLE{10614146,
  author={Barbareschi, Mario and Casola, Valentina and Emmanuele, Antonio and Lombardi, Daniele},
  journal={IEEE Internet of Things Journal}, 
  title={A Lightweight PUF-Based Protocol for Dynamic and Secure Group Key Management in IoT}, 
  year={2024},
  volume={11},
  number={20},
  pages={32969-32984},
  keywords={Internet of Things;Protocols;Physical unclonable function;Authentication;Performance evaluation;Synchronization;Proposals;Constrained devices;group key management;Internet of Things (IoT);physically unclonable function (PUF)},
  doi={10.1109/JIOT.2024.3418207}
}
```
