SUDO=sudo

all: getmac

getmac: getmac.cpp icmp_mac_resolver.h
	g++ -o getmac getmac.cpp -std=c++11

tests: test

test: test_icmp_mac_resolver.cpp icmp_mac_resolver.h
	g++ -o test_icmp test_icmp_mac_resolver.cpp -std=c++11
	${SUDO} ./test_icmp

docker_test: SUDO=
docker_test: test

docker_build:
	docker build -t getmac .

clean:
	rm -f getmac test_icmp