import sys
import socket
import struct
import select

def calculate_checksum(packet):#rfc1071 подсчет контрольной суммы
    checksum = 0
    overflow = 0
    for i in range(0, len(packet), 2):
        word = packet[i] + (packet[i+1] << 8)
        checksum = checksum + word
        overflow = checksum >> 16
        while overflow > 0:
            checksum = checksum & 0xFFFF
            checksum = checksum + overflow
            overflow = checksum >> 16
    overflow = checksum >> 16
    while overflow > 0:
        checksum = checksum & 0xFFFF
        checksum = checksum + overflow
        overflow = checksum >> 16
    checksum = ~checksum
    checksum = checksum & 0xFFFF
    return checksum

def ping(ttl, destination_address, Socket):
    timeout = 0.5 #время ожидания ответа
    temp_header = struct.pack("bbHHh", 8, 0, 0,  0, 0)
    checksum = calculate_checksum(temp_header)
    main_header = struct.pack("bbHHh", 8, 0, checksum, 0, 0) 
    Socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    Socket.sendto(main_header, (destination_address, 33434)) #отправляем запрос
    if select.select([Socket], [], [], timeout)[0] == []: #проверяем наличие ответа либо таймаут
        print(ttl, " The waiting interval for the request has been exceeded")
        return False
    IP = Socket.recvfrom(1024)[1][0]
    print(ttl, "IP:", IP)
    if IP == destination_address:
        return True
    return False

def tracert(host):
  max_ttl = 30
  destination_address = socket.gethostbyname(host)
  ttl = 1
  icmp_protocol = socket.getprotobyname("icmp")
  while(ttl < max_ttl):
      Socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_protocol)
      if (ping(ttl, destination_address, Socket)):
          Socket.close()
          break
      ttl += 1
      Socket.close()
  sys.exit()

if __name__ == "__main__":
    tracert("google.com")
