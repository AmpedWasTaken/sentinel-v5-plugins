<screen name="relay-health-ok" version="2">
  <column>
    <text>✓ HEALTH CHECK SUCCESS</text>
    <divider/>
    <panel title="READ-ONLY HEALTH">
      <field label="Response" key="data.summary" fallback="—"/>
      <field label="Timeout" key="data.timeout" fallback="—"/>
    </panel>
    <text>Fixed approved /health or /status GET only.</text>
  </column>
</screen>
