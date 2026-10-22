<screen name="captures" version="3">
  <panel title="PACKETLENS / LOCAL CAPTURES" border="round">
    <metric label="AVAILABLE" value="{{data.count}}"/>
    <table source="data.files" style="compact-lite" sort="name" page-size="20">
      <column key="name" label="CAPTURE" width="32"/>
      <column key="bytes" label="FILE SIZE" width="14"/>
    </table>
    <text>Run packetlens analyze capture=sample</text>
  </panel>
</screen>
