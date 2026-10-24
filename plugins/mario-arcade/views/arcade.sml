<screen name="arcade" version="3">
  <column>
    <panel title="SENTINEL JUMP / TERMINAL ARCADE" border="round" padding="1">
      <badge tone="info" variant="outline">ORIGINAL RETRO PLATFORMER / SSH</badge>
      <field label="WORLD" key="data.level"/>
      <metric label="LIVES" value="{{data.lives}}"/>
      <metric label="SCORE" value="{{data.score}}"/>
      <field label="TURNS" key="data.turns"/>
      <field label="CAMERA" key="data.camera"/>
      <divider variant="dotted"/>
      <text>{{data.row0}}</text>
      <text>{{data.row1}}</text>
      <text>{{data.row2}}</text>
      <text>{{data.row3}}</text>
      <text>{{data.row4}}</text>
      <text>{{data.row5}}</text>
      <text>{{data.row6}}</text>
      <text>{{data.row7}}</text>
      <text>{{data.row8}}</text>
      <divider variant="dotted"/>
      <field label="EVENT" key="data.message"/>
      <text>@ PLAYER   $ COIN   X ENEMY   # PLATFORM   F FINISH</text>
      <text>TYPE mario-arcade right / jump-right / wait / show / new</text>
      <text>Shared arcade state / one SSH command = one game tick.</text>
    </panel>
  </column>
</screen>
