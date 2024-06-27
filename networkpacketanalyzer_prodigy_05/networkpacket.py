from scapy.all import sniff, getmacbyip

def analyze_packet(packet):

  # Get Layer information
  ip_layer = packet.getlayer(scapy.layers.inet.IP)
  tcp_layer = packet.getlayer(scapy.layers.inet.TCP)
  udp_layer = packet.getlayer(scapy.layers.inet.UDP)

  # Source and Destination information
  src_ip = ip_layer.src
  src_mac = getmacbyip(src_ip)  # Get MAC address from IP (if available)
  dst_ip = ip_layer.dst
  dst_mac = getmacbyip(dst_ip)  # Get MAC address from IP (if available)

  # Protocol information
  protocol = "N/A"
  if tcp_layer:
    protocol = "TCP"
  elif udp_layer:
    protocol = "UDP"

  print(f"Source: {src_ip} ({src_mac})")
  print(f"Destination: {dst_ip} ({dst_mac})")
  print(f"Protocol: {protocol}")

def main():
  print("Sniffing network traffic...")
  sniff(iface="eth0", prn=analyze_packet)  # Replace "eth0" with your network interface

if __name__ == "__main__":
  main()
