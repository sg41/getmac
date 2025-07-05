all: getmac

getmac: getmac.cpp icmp_mac_resolver.h
	g++ -o getmac getmac.cpp -std=c++11

test: test_icmp_mac_resolver.cpp icmp_mac_resolver.h
	g++ -o test_icmp test_icmp_mac_resolver.cpp -std=c++11
	sudo ./test_icmp

clean:
	rm -f getmac