<screen name="web-status" version="3">
  <derive key="derived.uptime" op="duration" source="data.uptime"/>
  <column>
    <panel title="SENTINEL / WEB SERVER" border="round" padding="1">
      <badge tone="success" variant="outline">PERSISTENT GO WORKER</badge>
      <grid columns="2" collapse-below="68">
        <metric label="STATUS" value="{{data.state}}"/>
        <metric label="TLS" value="{{data.tls}}"/>
        <metric label="REQUESTS" value="{{data.requests}}"/>
        <metric label="RATE LIMITED" value="{{data.rate_limited}}"/>
        <metric label="VIRTUAL HOSTS" value="{{data.sites}}"/>
        <metric label="CUSTOM ROUTES" value="{{data.routes}}"/>
        <metric label="2XX RESPONSES" value="{{data.responses_2xx}}"/>
        <metric label="4XX RESPONSES" value="{{data.responses_4xx}}"/>
      </grid>
      <divider/>
      <field label="LISTENER" key="data.listen"/>
      <field label="UPTIME" key="derived.uptime"/>
      <field label="5XX RESPONSES" key="data.responses_5xx"/>
      <field label="RESPONSE BYTES" key="data.bytes"/>
      <field label="LAST LISTENER ERROR" key="data.last_error"/>
    </panel>
  </column>
</screen>
