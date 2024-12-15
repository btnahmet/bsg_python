from scapy.all import sniff

# Paketlerin işlendiği callback fonksiyonu
def packet_callback(packet):
    print(packet.summary())  # Paket özet bilgisi
    # Eğer paket detaylarını görmek istiyorsanız:
    # packet.show()

# Ağ arayüzünü seç
interface = "Wi-Fi"  # Dinlemek istediğiniz arayüz adını yazın (örneğin: eth0, wlan0)

# Trafiği dinle
print(f"{interface} adaptöründe tüm trafiği dinliyorum... (Ctrl+C ile durdurabilirsiniz)")
sniff(iface=interface, prn=packet_callback,count=0)
# from scapy.all import sniff, UDP

# # Paketlerin işlendiği callback fonksiyonu
# def packet_callback(packet):
#     if UDP in packet:  # Sadece UDP paketlerini kontrol et
#         print(packet.summary())  # Paket özet bilgisi
#         # Eğer paket detaylarını görmek istiyorsanız:
#         # packet.show()

# # Ağ arayüzünü seç
# interface = "Wi-Fi"  # Dinlemek istediğiniz arayüz adını yazın (örneğin: eth0, wlan0)

# # UDP trafiğini dinle
# print(f"{interface} adaptöründe UDP trafiğini dinliyorum... (Ctrl+C ile durdurabilirsiniz)")
# sniff(iface=interface, filter="udp", prn=packet_callback, count=0)
# from scapy.all import sniff, UDP

# # Paketlerin işlendiği callback fonksiyonu
# def packet_callback(packet):
#     if UDP not in packet:  # UDP içermeyen paketleri göster
#         print(packet.summary())  # Paket özet bilgisi
#         # Eğer paket detaylarını görmek istiyorsanız:
#         # packet.show()

# # Ağ arayüzünü seç
# interface = "Wi-Fi"  # Dinlemek istediğiniz arayüz adını yazın (örneğin: eth0, wlan0)

# # Trafiği dinle (UDP hariç)
# print(f"{interface} adaptöründe UDP hariç tüm trafiği dinliyorum... (Ctrl+C ile durdurabilirsiniz)")
# sniff(iface=interface, prn=packet_callback, count=0)
