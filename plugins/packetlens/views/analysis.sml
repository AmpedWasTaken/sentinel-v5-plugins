<screen name="analysis" version="3">
  <column>
    <panel title="PACKETLENS / OFFLINE PCAP" border="round" padding="1">
      <metric label="CAPTURE" value="{{data.capture}}"/>
      <metric label="FRAMES" value="{{data.frames}}"/>
      <metric label="WIRE BYTES" value="{{data.wire_bytes}}"/>
      <metric label="CAPTURED BYTES" value="{{data.captured_bytes}}"/>
      <text>IPv4 {{data.ipv4}} | IPv6 {{data.ipv6}} | ARP {{data.arp}}</text>
      <text>TCP {{data.tcp}} | UDP {{data.udp}} | ICMP {{data.icmp}} | Other {{data.other}}</text>
      <text>TCP SYN-only {{data.syn}} | TCP RST {{data.rst}} | Malformed {{data.malformed}}</text>
      <text>DNS (53) {{data.dns}} | HTTP (80) {{data.http}} | TLS/QUIC (443) {{data.tls}}</text>
      <text>Untracked source packets {{data.untracked_sources}} | port packets {{data.untracked_ports}}</text>
      <text>Observation: {{data.signal}}</text>
      <text>{{data.note}}</text>
    </panel>
    <panel title="TOP SOURCE ADDRESSES (BOUNDED)">
      <table source="data.sources" style="compact-lite" sort="packets" order="desc" page-size="6">
        <column key="ip" label="SOURCE IP" width="40"/>
        <column key="packets" label="PACKETS" width="12"/>
        <column key="bytes" label="WIRE BYTES" width="14"/>
      </table>
    </panel>
    <panel title="TOP DESTINATION PORTS (BOUNDED)">
      <table source="data.ports" style="compact-lite" sort="packets" order="desc" page-size="6">
        <column key="proto" label="PROTOCOL" width="10"/>
        <column key="port" label="PORT" width="8"/>
        <column key="packets" label="PACKETS" width="12"/>
      </table>
    </panel>
  </column>
</screen>
