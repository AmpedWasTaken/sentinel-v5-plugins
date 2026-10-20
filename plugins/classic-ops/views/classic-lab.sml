<screen name="classic-lab" version="2">
  <column>
    <text>
      CLASSIC LAB  /  OFFLINE SCENARIOS
    </text>
    <divider/>
    <panel title="SAFETY &amp; CAPACITY">
      <badge>
        SYNTHETIC  ·  ZERO NETWORK TRAFFIC
      </badge>
      <grid columns="2" collapse-below="65">
        <metric label="SCENARIOS" value="{{lab.scenarios}}"/>
        <metric label="ACTIVE RUNS" value="{{lab.active}}"/>
      </grid>
    </panel>
    <panel title="COMMAND REFERENCE">
      <text>
        methods              List simulated methods
      </text>
      <text>
        attack http-burst 5  Start bounded synthetic run
      </text>
      <text>
        ongoing              Active simulation queue
      </text>
      <text>
        myattacks            Simulation history
      </text>
      <text>
        stop ID              Cancel a run
      </text>
      <divider/>
      <text>
        All generated measurements are synthetic.
      </text>
    </panel>
  </column>
</screen>
