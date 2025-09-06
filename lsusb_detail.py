#!/usr/bin/env python3
import usb.core
import usb.util

VENDOR_ID  = 0x048d
PRODUCT_ID = 0x6006

dev = usb.core.find(idVendor=VENDOR_ID, idProduct=PRODUCT_ID)
if dev is None:
    raise ValueError("Keyboard not found (048d:6006)")

print(f"Device {hex(dev.idVendor)}:{hex(dev.idProduct)}")
print(f"Configurations: {dev.bNumConfigurations}")

for cfg in dev:
    print(f"\nConfiguration {cfg.bConfigurationValue}:")
    for intf in cfg:
        print(f"  Interface {intf.bInterfaceNumber}, "
              f"Class {intf.bInterfaceClass}, "
              f"SubClass {intf.bInterfaceSubClass}, "
              f"Protocol {intf.bInterfaceProtocol}, "
              f"Endpoints {len(intf.endpoints())}")
        for ep in intf:
            print(f"    Endpoint {hex(ep.bEndpointAddress)}, "
                  f"Type {ep.bmAttributes & 3}, "
                  f"MaxPacketSize {ep.wMaxPacketSize}, "
                  f"Interval {ep.bInterval}")

