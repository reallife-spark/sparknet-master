# Deployment Scenarios & Hardware BOMs

Three scenarios from blueprint:
1. Same building (short distance, low-latency)
2. Large campus (medium distance)
3. Geographically distributed (long distance, requires optics/DWDM considerations)

## Network fabric
- ConnectX-7 200G RoCEv2
- DMA-BUF zero-copy
- Jumbo Frames MTU 9000
- Dual-tier: Daytime isolated, Nocturnal UMA pooling (512GB+)

## WLAN emergency routing
- Primary (ethernet): metric 100
- WLAN backup: metric 600
- nftables restricts wlan0 to Master Anchor only
