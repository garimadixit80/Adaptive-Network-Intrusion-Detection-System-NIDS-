import asyncio
import pyshark

# Python 3.14 fix
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

# Your Wi-Fi adapter
INTERFACE = r"\Device\NPF_{B63D7F2A-1E69-4D81-B8A9-10CFD597A177}"

print("=" * 60)
print("LIVE PACKET CAPTURE")
print("=" * 60)

print(f"\nUsing Interface:\n{INTERFACE}\n")
print("Open YouTube, Google, GitHub, etc.")
print("Waiting for packets...\n")

capture = pyshark.LiveCapture(interface=INTERFACE)

packet_count = 0

try:
    for packet in capture.sniff_continuously():

        try:
            if hasattr(packet, "ip"):

                packet_count += 1

                src_ip = packet.ip.src
                dst_ip = packet.ip.dst

                protocol = getattr(
                    packet,
                    "highest_layer",
                    "Unknown"
                )

                packet_size = getattr(
                    packet,
                    "length",
                    "N/A"
                )

                print(
                    f"[{packet_count}] "
                    f"{src_ip} -> {dst_ip} | "
                    f"Protocol={protocol} | "
                    f"Size={packet_size}"
                )

                if packet_count >= 50:
                    print("\nCapture Complete.")
                    break

        except Exception as packet_error:
            print(f"Packet Parse Error: {packet_error}")

except KeyboardInterrupt:
    print("\nCapture stopped by user.")

except Exception as capture_error:
    print(f"\nCapture Error: {capture_error}")

finally:
    try:
        capture.close()
    except:
        pass

print("\nProgram Finished.")