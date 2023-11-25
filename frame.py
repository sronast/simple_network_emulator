class Frame:
    def __init__(self, ip_packet) -> None:
        self.source = None
        self.destination = None
        self.ip_packet = ip_packet