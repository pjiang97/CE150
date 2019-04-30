Peter Jiang
pjiang1@ucsc.edu
CMPE150
03/10/2019

Files Submitted:
final.py
final_controller.py
README


High Level Controller Logic

First, we get the packet in and check for ipv4 packets. Next, I check hosts 1-3. The logic for hosts 1-3 
is: 
1. first get the appropriate switchID, then check the destination ip address matching the appropriate host
2. Next check if the packet source ip is that of the untrusted host. If so, block only if it is icmp.
3. If ip not from untrusted host, send packet to correct port
4. If the destination is not for the correct host, send back to core switch

Logic for server:
1. Check for correct destination ip of server. 
2. If packet source is from untrusted host, drop the packet.
3. Send packet to correct port for server
4. If not correct destination, send back to core switch

Logic for Core Switch
1. If it is the Core Switch ID, do the following
2. Check the destination ip of the packet, based on the ip of the host, send to the corresponding switch using the port
3. Also for trusted and untrusted host, send to the correct port.

If not ip, use OFTP_FLOOD to send packet to all ports besides itself.\

More general version:
Check for ip
Check hosts 1-3, if packet is from untrusted and is icmp drop, else send to port. If not correct destination, send back to Core Switch
For server drop if from untrusted, send if correct destination, send to core switch if incorrect.
For core switch, get packet and send to correct port based on ip destination.
If not ip, flood ports.