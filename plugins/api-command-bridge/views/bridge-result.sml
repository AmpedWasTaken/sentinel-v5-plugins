<screen name="bridge-result" version="2">
  <column>
    <panel title="SIMPLE C2 / API LOOKUP">
      <badge>AUTHORIZED HTTPS REPORT</badge>
      <grid columns="2" collapse-below="65">
        <metric label="TARGET" value="{{data.target}}"/>
        <metric label="CATEGORY" value="{{data.category}}"/>
        <metric label="STATUS" value="{{data.status}}"/>
        <metric label="SERVICE" value="{{data.service}}"/>
        <metric label="RECORDS" value="{{data.records}}"/>
      </grid>
      <divider/>
      <text>{{data.message}}</text>
    </panel>
  </column>
</screen>
