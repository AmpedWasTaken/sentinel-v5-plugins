<screen name="relay-health-degraded" version="2">
  <column>
    <text>! HEALTH CHECK DEGRADED</text>
    <divider/>
    <panel title="READ-ONLY HEALTH">
      <field label="Response" key="data.summary" fallback="—"/>
      <field label="Timeout" key="data.timeout" fallback="—"/>
    </panel>
    <text>Some approved health endpoints could not be reached.</text>
  </column>
</screen>
