# SDN-project

In this project we have two networks, Network A is composed of three clients and a SDN-enabled switch (SS), which is managed by a SDN controller. The
Network B is composed of two servers and one legacy switch (LS). The two networks are connected by means of two routers.
The aim of the project is to implement a centralized mechanism to let clients in Network A communicate with servers in Network B through one gateway
(R1 or R2) that can be changed dynamically. At any time only one router must operate as the gateway for all clients, while the other one is available as
a backup. Therefore, no load balancing between routers must be implemented.
Moreover, clients must be unaware of which router is acting as a gateway at all times.
