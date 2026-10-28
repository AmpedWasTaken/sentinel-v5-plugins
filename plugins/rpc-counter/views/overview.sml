<screen name="overview" version="3">
  <column>
    <panel title="PERSISTENT COUNTER">
      <text>Native Sentinel App with a persistent Go RPC worker.</text>
      <metric label="TOTAL INVOCATIONS" value="{{plugin.rpc_counter.count}}"/>
      <metric label="PLUGIN STATUS" value="{{plugin.rpc_counter.health}}"/>
      <button id="increment" label="Increment Counter" action="app.increment"/>
      <button id="details" label="How It Works" page="details"/>
    </panel>
  </column>
</screen>
