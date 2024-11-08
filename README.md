# WireGuard.NET

Prototype of the WireGuard Protocol in .NET (dont use in production)
This project was developed as part of a degree course.

It was used to establish a WireGuard connection to several WireGuard servers in user space as a client. 
The next step was to set up a TCP/IP stack within the tunnel to enable communication through this tunnel.

Many things were tried, from RAW sockets to a prototype TCP/IP stack implementation. 
A fully functioning prototype was developed. However, it was not stable, not to mention the thousands of reasons why you should not build a TCP/IP stack yourself.
This repo therefore only contains the WireGuard part.
It should be noted that the code was written by a student and should be treated as such. 
Nevertheless, great care has been taken to be compliant with the technical whitepaper (https://www.wireguard.com/papers/wireguard.pdf). 
However, it should be noted that the ‘Under Load: Cookie Reply Message’ described in section 5.4.7 has not been implemented.

If anyone is interested in the code or sees a way to use it for the use case described, please do not hesitate to contact me.

# Foreign Code Used

- https://github.com/Metalnem/noise - MIT License - The ‘Noise’ folder contains a greatly reduced version that has been adapted to WireGuard