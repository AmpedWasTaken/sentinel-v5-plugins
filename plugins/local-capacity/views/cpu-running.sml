<screen name="cpu-running" version="2">
  <column>
    <text>
      CAPACITY  /  ACTIVE WORKLOAD
    </text>
    <divider/>
    <panel title="{{plugin.name}} / LOCAL HOST">
      <badge>
        BOUNDED  ·  LOCAL MACHINE ONLY
      </badge>
      <text>
        JOB ID  {{job.id}}
      </text>
      <text>
        STATE   {{job.status}}
      </text>
      <progress label="WORK COMPLETED" value="{{job.progress}}"/>
      <divider/>
      <text>
        {{job.output}}
      </text>
      <text>
        plugins test show JOB_ID   Refresh details
      </text>
      <text>
        plugins test stop JOB_ID   Cancel the job
      </text>
    </panel>
  </column>
</screen>
