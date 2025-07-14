SUDO=sudo

all: getmac

getmac: getmac.cpp icmp_mac_resolver.h
	g++ -o getmac getmac.cpp -std=c++11

tests: test

test: test_icmp_mac_resolver.cpp icmp_mac_resolver.h
	g++ $(CXXFLAGS) -o test_icmp test_icmp_mac_resolver.cpp $(LDFLAGS) -std=c++11
	${SUDO} ./test_icmp

test_icmp_mac_resolver: test_icmp_mac_resolver_gtest.cpp icmp_mac_resolver.h
	g++ $(CXXFLAGS) -o $@ $^ -std=c++11 $(LDFLAGS) -lgtest -lgtest_main -lpthread

docker_test: SUDO=
docker_test: test

docker_build:
	docker build -t getmac .

COVERAGE_DIR = coverage

build_with_coverage: CXXFLAGS += --coverage -fprofile-arcs -ftest-coverage
build_with_coverage: LDFLAGS += --coverage
build_with_coverage: clean test test_icmp_mac_resolver
	$(SUDO) ./test_icmp
	$(SUDO) ./test_icmp_mac_resolver

coverage: build_with_coverage
	mkdir -p ${COVERAGE_DIR}
	lcov --capture --directory . --output-file ${COVERAGE_DIR}/coverage.info
	lcov --remove ${COVERAGE_DIR}/coverage.info '/usr/*' '*/gtest/*' '*/test_*' --output-file ${COVERAGE_DIR}/filtered.info
	genhtml ${COVERAGE_DIR}/filtered.info --output-directory ${COVERAGE_DIR}/html
	gcovr --xml-pretty --output ${COVERAGE_DIR}/coverage.xml
	echo "Coverage report available at ${COVERAGE_DIR}/html/index.html"

clean:
	rm -f getmac test_icmp test_icmp_mac_resolver
	rm -f *.gcda *.gcno *.gcov
	rm -rf $(COVERAGE_DIR)