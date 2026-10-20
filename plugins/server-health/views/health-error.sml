<screen name="health-error" version="2">
  <column>
    <text>
      TELEMETRY  /  REPORT ERROR
    </text>
    <divider/>
    <panel title="SERVER HEALTH / UNAVAILABLE">
      <alert>
        REPORT NOT AVAILABLE
      </alert>
      <text>
        {{api.error}}
      </text>
      <divider/>
      <text>
        Verify plugin settings and provider permissions.
      </text>
    </panel>
  </column>
</screen>
