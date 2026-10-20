<screen name="relay-backend-fault" version="2">
  <column>
    <text>× HEALTH API FAILED</text>
    <divider/>
    <panel title="DIAGNOSTICS FAULT">
      <field label="Reason" key="data.detail" fallback="—"/>
      <field label="Response" key="data.summary" fallback="—"/>
    </panel>
    <text>No attack URL was contacted.</text>
  </column>
</screen>
