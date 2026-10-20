<screen name="interfaces" version="2">
 <column>
  <panel title="SENTINEL / NETWATCH / INTERFACES">
   <metric label="INTERFACES" value="{{data.count}}"/>
   <table source="data.rows" style="compact-lite" sort="name" page-size="24">
    <column key="name" label="INTERFACE" width="21"/>
    <column key="rx" label="RX TOTAL" width="15"/>
    <column key="tx" label="TX TOTAL" width="15"/>
    <column key="rx_errors" label="RX ERR" width="9"/>
    <column key="tx_errors" label="TX ERR" width="9"/>
   </table>
   <text>Use netwatch watch interface=eth0 for a one-second throughput sample.</text>
  </panel>
 </column>
</screen>
