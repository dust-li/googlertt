googlertt
=========

this is a tool to test the connection between your host and google's global ip addresses


This python based tool tries to ping IP addresses of Google from all over the world to find 
out which is faster and reachable. 

Because of the GFW, some addresses might be not reachable, and some might be reachable but 
may drop packets now and then. So, the tool will test different addresses to found out the
"good" ones, and will sort them in a file named "good.txt".


The addresses can be found at
https://github.com/justjavac/Google-IPs/blob/master/README.md
and was copied to "GoogleIP.txt" split by space.
