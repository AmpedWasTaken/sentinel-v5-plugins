<screen name="cpu-result" version="2">
  <column>
    <text>
      CAPACITY  /  MEASUREMENT COMPLETE
    </text>
    <divider/>
    <panel title="LOCAL CPU / RESULTS">
      <badge>
        REAL LOCAL MEASUREMENT
      </badge>
      <grid columns="2" collapse-below="65">
        <metric label="PROFILE" value="{{test.profile}}"/>
        <metric label="TARGET" value="{{test.target}}"/>
        <metric label="ELAPSED / MS" value="{{test.elapsed_ms}}"/>
        <metric label="BYTES HASHED" value="{{test.bytes_hashed}}"/>
        <metric label="THROUGHPUT / MiB/s" value="{{test.throughput_mib_s}}"/>
        <metric label="DURATION / S" value="{{test.duration_seconds}}"/>
      </grid>
      <divider/>
      <text>
        {{test.workload}}
      </text>
      <text>
        JOB ID  {{job.id}}
      </text>
    </panel>
  </column>
</screen>
