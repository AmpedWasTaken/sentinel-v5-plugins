<screen name="go-preview" version="3">
  <column>
    <text case="upper">SML / GO PLUGIN PREVIEW</text>
    <divider variant="dotted"/>
    <panel title="GO SDK DATA BINDINGS" border="single" padding="1">
      <text>{{data.message}}</text>
      <grid columns="3" gap="1" collapse-below="70">
        <metric label="CPU %" value="{{data.cpu}}"/>
        <metric label="RAM %" value="{{data.memory}}"/>
        <metric label="DISK %" value="{{data.disk}}"/>
      </grid>
      <gauge label="CPU" value="{{data.cpu}}" width="20"/>
      <progress label="DISK" value="{{data.disk}}"/>
      <sparkline label="HISTORY" values="{{data.history}}" width="24"/>
      <badge tone="success" variant="outline">{{data.status}}</badge>
    </panel>
    <panel title="SDK RETURN VALUE" border="single" padding="1">
      <text>Result.View selects a plugin-local SML template.</text>
      <text>Result.Values becomes sanitized data.* bindings.</text>
    </panel>
  </column>
</screen>
