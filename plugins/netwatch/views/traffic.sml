<screen name="traffic" version="2">
  <column>
    <panel title="SENTINEL / NETWATCH">
      <badge>REAL HOST COUNTERS / 1s SAMPLE</badge>
      <grid columns="2" collapse-below="65">
        <metric label="INTERFACE" value="{{data.interface}}"/>
        <metric label="SAMPLE" value="{{data.interval}}"/>
        <metric label="DOWNLOAD" value="{{data.rx_rate}}"/>
        <metric label="UPLOAD" value="{{data.tx_rate}}"/>
        <metric label="RX TOTAL" value="{{data.rx_total}}"/>
        <metric label="TX TOTAL" value="{{data.tx_total}}"/>
        <metric label="RX PACKETS" value="{{data.rx_packets}}"/>
        <metric label="TX PACKETS" value="{{data.tx_packets}}"/>
        <metric label="RX PACKETS/S" value="{{data.rx_pps}}"/>
        <metric label="TX PACKETS/S" value="{{data.tx_pps}}"/>
        <metric label="RX ERRORS" value="{{data.rx_errors}}"/>
        <metric label="TX ERRORS" value="{{data.tx_errors}}"/>
      </grid>
      <divider/>
      <text>{{data.info}}</text>
    </panel>
  </column>
</screen>
