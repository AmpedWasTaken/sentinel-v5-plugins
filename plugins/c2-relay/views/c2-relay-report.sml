<screen name="c2-relay-report" version="2">
  <column>
    <panel title="C2 RELAY / {{data.mode}}">
      <badge>READ-ONLY DIAGNOSTICS</badge>
      <field label="Scenario" key="data.scenario"/>
      <field label="Group" key="data.group"/>
      <field label="Duration" key="data.duration"/>
      <field label="Limit" key="data.concurrency"/>
      <field label="Timeout" key="data.timeout"/>
      <field label="DNS labels" key="data.dns"/>
      <divider/>
      <field label="Details" key="data.summary"/>
      <text>{{data.notice}}</text>
    </panel>
  </column>
</screen>
