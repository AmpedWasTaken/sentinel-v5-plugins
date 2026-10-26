<screen name="profile" version="3">
  <column>
    <panel title="SANDBOX PROFILE / PREVIEW ONLY" border="round" padding="1">
      <badge tone="warning" variant="outline">NO CONTAINER OR VM WILL BE STARTED</badge>
      <field label="PROFILE" key="data.id"/>
      <field label="RUNTIME" key="data.runtime"/>
      <field label="CPU (MILLICORES)" key="data.cpu"/>
      <field label="MEMORY (MiB)" key="data.memory"/>
      <field label="WALL TIME (SEC)" key="data.timeout"/>
      <field label="NETWORK" key="data.network"/>
      <divider variant="dotted"/>
      <field label="POLICY HASH" key="data.digest"/>
      <field label="EXECUTION" key="data.execution"/>
      <text>Example image digest is a placeholder, not an approved guest.</text>
    </panel>
  </column>
</screen>
