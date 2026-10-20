<screen name="loadtest-info" version="2">
  <column>
    <panel title="LOCAL DIAGNOSTICS / PROFILES">
      <badge>LOOPBACK ONLY · BOUNDED</badge>
      <text>Destination: {{data.destination}}</text>
      <text>Profiles: {{data.profiles}}</text>
      <divider/>
      <text>Run: plugins run local-loadtest loadtest profile=health count=2 case=smoke</text>
      <text>Limits: {{data.limits}}</text>
      <text>No public endpoints or arbitrary URL arguments are accepted.</text>
    </panel>
  </column>
</screen>
