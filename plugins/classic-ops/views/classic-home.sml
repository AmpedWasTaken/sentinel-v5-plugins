<screen name="classic-home" version="2">
  <column>
    <text>
      CLASSIC OPERATIONS  /  {{user.name}} [{{user.role}}]
    </text>
    <divider/>
    <panel title="WORKSPACE TELEMETRY">
      <grid columns="3" collapse-below="65">
        <metric label="SSH ONLINE" value="{{sessions.online}}"/>
        <metric label="TOTAL JOBS" value="{{jobs.total}}"/>
        <metric label="COMMANDS" value="{{commands.total}}"/>
      </grid>
      <text>
        SERVER UPTIME  {{server.uptime}}
      </text>
    </panel>
    <panel title="CLASSIC SHORTCUTS">
      <text>
        methods      Offline resilience scenarios
      </text>
      <text>
        attack       Synthetic workload simulation
      </text>
      <text>
        ongoing      Active lab operations
      </text>
      <text>
        myattacks    Simulation history
      </text>
      <text>
        plugins      Experience packages
      </text>
    </panel>
  </column>
</screen>
