<screen name="cpu-error" version="2">
  <column>
    <text>
      CAPACITY  /  TEST INTERRUPTED
    </text>
    <divider/>
    <panel title="LOCAL CPU WORKLOAD">
      <alert>
        STATUS  {{job.status}}
      </alert>
      <text>
        JOB ID   {{job.id}}
      </text>
      <text>
        ERROR    {{job.error}}
      </text>
      <divider/>
      <text>
        Review permissions and run another bounded local test.
      </text>
    </panel>
  </column>
</screen>
