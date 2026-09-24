import math

def process_windows(packet_generator, window_size=5.0):
    """
    Groups streaming normalized packets into consecutive time windows of size `window_size` seconds.
    Yields windows as soon as they are completed.
    """
    current_window_id = 0
    current_window_start = None
    current_window_end = None
    current_packets = []

    for pkt in packet_generator:
        ts = pkt["timestamp"]

        # Initialize the very first window
        if current_window_start is None:
            current_window_start = math.floor(ts / window_size) * window_size
            current_window_end = current_window_start + window_size
            current_packets = []

        # If packet belongs to the current window
        if ts < current_window_end:
            if ts >= current_window_start:
                current_packets.append(pkt)
            continue

        # Yield the completed current window
        yield {
            "window_id": current_window_id,
            "window_start": current_window_start,
            "window_end": current_window_end,
            "packets": current_packets
        }
        current_window_id += 1

        # Advance boundaries
        next_window_start = current_window_end
        next_window_end = next_window_start + window_size

        while ts >= next_window_end:
            yield {
                "window_id": current_window_id,
                "window_start": next_window_start,
                "window_end": next_window_end,
                "packets": []
            }
            current_window_id += 1
            next_window_start = next_window_end
            next_window_end = next_window_start + window_size

        current_window_start = next_window_start
        current_window_end = next_window_end
        current_packets = [pkt]

    # Yield last pending window
    if current_window_start is not None:
        yield {
            "window_id": current_window_id,
            "window_start": current_window_start,
            "window_end": current_window_end,
            "packets": current_packets
        }
