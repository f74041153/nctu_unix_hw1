all: hw1.cpp
	g++ -std=c++11 -o hw1 hw1.cpp
clean: 
	rm -f npshell
show:
	netstat -nap | grep 'tcp\|udp'
