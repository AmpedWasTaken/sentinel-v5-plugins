<screen name="counter" version="3">
  <derive key="derived.activity" op="coalesce" source="data.message" fallback="Waiting for counter data"/>
  <derive key="derived.uptime" op="duration" source="data.uptime"/>
  <column>
    <panel title="PERSISTENT GO PLUGIN">
      <badge>RPC / STORAGE / EVENTS</badge>
      <metric label="TOTAL INVOCATIONS" value="{{data.count}}"/>
      <metric label="ONLINE SESSIONS" value="{{data.sessions}}"/>
      <field label="SERVER UPTIME" key="derived.uptime"/>
      <divider/>
      <field label="LAST ACTION" key="derived.activity"/>
    </panel>
  </column>
</screen>
