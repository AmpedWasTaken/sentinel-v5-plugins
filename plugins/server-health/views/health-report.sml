<screen name="health-report" version="2">
  <column>
    <text>
      TELEMETRY  /  SERVER HEALTH
    </text>
    <divider/>
    <panel title="{{plugin.name}} / METRICS">
      <badge>
        READ-ONLY TELEMETRY
      </badge>
      <grid columns="2" collapse-below="65">
        <metric label="INSTANCE" value="{{api.instance}}"/>
        <metric label="HEALTH" value="{{api.health}}"/>
        <metric label="CPU / %" value="{{api.cpu}}"/>
        <metric label="MEMORY / %" value="{{api.memory}}"/>
      </grid>
      <divider/>
      <text>
        Source: approved HTTPS metrics provider.
      </text>
    </panel>
  </column>
</screen>
