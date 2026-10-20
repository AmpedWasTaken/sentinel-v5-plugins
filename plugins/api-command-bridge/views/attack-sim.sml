<screen name="attack-sim" version="2">
  <column>
    <panel title="SIMPLE C2 / TEST SIMULATOR">
      <badge>DRY RUN — NO NETWORK DISPATCH</badge>
      <grid columns="2" collapse-below="65">
        <metric label="REQUEST" value="{{data.request_id}}"/>
        <metric label="STATUS" value="{{data.status}}"/>
        <metric label="TARGET" value="{{data.target}}"/>
        <metric label="METHOD" value="{{data.method}}"/>
        <metric label="PORT" value="{{data.port}}"/>
        <metric label="DURATION" value="{{data.duration}}"/>
      </grid>
      <divider/>
      <text>{{data.detail}}</text>
      <text>Created (UTC): {{data.created_at}}</text>
    </panel>
  </column>
</screen>
