<screen name="loadtest-report" version="2">
  <column>
    <panel title="LOCAL DIAGNOSTICS / REPORT">
      <badge>SEQUENTIAL LOOPBACK REQUESTS</badge>
      <metric label="PROFILE" value="{{data.profile}}"/>
      <metric label="DESTINATION" value="{{data.destination}}"/>
      <metric label="SAMPLES" value="{{data.count}}"/>
      <metric label="SUCCEEDED" value="{{data.success}}"/>
      <metric label="FAILED" value="{{data.errors}}"/>
      <metric label="LAST HTTP STATUS" value="{{data.last_status}}"/>
      <metric label="MEAN LATENCY (MS)" value="{{data.average_ms}}"/>
      <divider/>
      <text>Case: {{data.case}}</text>
      <text>For authorized local development services only.</text>
    </panel>
  </column>
</screen>
