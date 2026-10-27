<screen name="status" version="3">
  <column>
    <panel title="SENTINEL SANDBOX / READINESS" border="round" padding="1">
      <badge tone="warning" variant="outline">SOURCE PREVIEW / EXECUTION DISABLED</badge>
      <field label="STATUS" key="data.health"/>
      <field label="EXECUTION" key="data.execution"/>
      <field label="HOST BROKER" key="data.broker"/>
      <field label="RUNTIME" key="data.runtime"/>
      <divider variant="dotted"/>
      <field label="SECURITY" key="data.security"/>
      <text>This is not a sandbox isolation attestation.</text>
      <text>Use sentinel-sandbox doctor for remaining release blockers.</text>
    </panel>
  </column>
</screen>
