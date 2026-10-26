<screen name="bench" version="3">
  <column>
    <panel title="SENTINEL AI LAB" border="round" padding="1">
      <badge tone="info" variant="outline">LOCAL MODEL BENCHMARK</badge>
      <field label="RUN" key="data.id"/>
      <field label="MODEL" key="data.model"/>
      <field label="SUITE" key="data.suite"/>
      <field label="STATUS" key="data.status"/>
      <metric label="TESTS PASSED" value="{{data.passed}}"/>
      <field label="PROGRESS" key="data.progress"/>
      <field label="AVERAGE LATENCY" key="data.latency"/>
      <field label="COMPLETION TOKENS" key="data.tokens"/>
      <divider/>
      <text>AI model output is scored only. No generated programs are executed.</text>
      <text>Run: ai-lab status id=RUN_ID / ai-lab cancel id=RUN_ID</text>
    </panel>
  </column>
</screen>
