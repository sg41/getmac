
# getmac - ICMP MAC Address Resolver

A lightweight utility to discover MAC addresses by sending ICMP echo requests.

## Features
- IPv4 support
- Raw socket implementation
- Automatic interface detection
- Docker container support
- Comprehensive test suite

## Building

### Local Build
1. Install compiler:  
   ```bash
   sudo apt install g++
   ```
2. Build:  
   ```bash
   make
   ```
3. Run:  
   ```bash
   sudo ./getmac <IP_ADDRESS>
   ```

### Docker Build
1. Build image:  
   ```bash
   make docker_build
   ```
2. Run:  
   ```bash
   docker run getmac <IP_ADDRESS>
   ```

## File Structure
- `getmac.cpp` - Main application
- `icmp_mac_resolver.h` - Header file
- `icmp_mac_resolver.cpp` - Core functionality
- `test_icmp_mac_resolver.cpp` - Test cases
- `Makefile` - Build automation
- `Dockerfile` - Container configuration

## Testing
Run the test suite:
```bash
make test
```

## Requirements
- Linux kernel
- Root privileges (for raw sockets)
- g++ (C++11 or newer)
- Docker (optional)

## Usage Examples

1. **Basic usage**:
   ```bash
   sudo ./getmac 192.168.1.1
   ```

2. **Docker usage**:
   ```bash
   docker run getmac 10.0.0.1
   ```

3. **Run tests**:
   ```bash
   make test
   ```

## Notes
- Requires `CAP_NET_RAW` capability in containers
- Timeout is set to 2 seconds by default
- Falls back to `eth0` if auto-detection fails

## License
[MIT](LICENSE)
