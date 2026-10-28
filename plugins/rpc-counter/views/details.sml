<screen name="details" version="3">
  <column>
    <panel title="COUNTER APP / DETAILS">
      <text>Increments are stored in a plugin-specific server-managed store.</text>
      <text>Live values are published through a scoped ui.publish grant.</text>
      <text>Changes from another authorized session appear on refresh.</text>
      <metric label="CURRENT COUNT" value="{{plugin.rpc_counter.count}}"/>
      <button id="back" label="Back to Overview" page="overview"/>
    </panel>
  </column>
</screen>
